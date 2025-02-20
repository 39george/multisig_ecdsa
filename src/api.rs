use std::collections::HashMap;

use anyhow::{anyhow, Context};
use axum::body::Body;
use axum::extract::{Path, Query, State};
use axum::response::{IntoResponse, Response};
use axum::Router;
use axum::{routing, Json};
use http::StatusCode;
use secp256k1::hashes::{hash160, Hash};
use secp256k1::Keypair;

use crate::crypto;
use crate::domain::message::Message;
use crate::startup::api_doc::{self, PostMsgRequest, SignMsgRequest};
use crate::{domain::user::User, startup::AppState};

#[derive(thiserror::Error)]
pub enum ErrorResponse {
    #[error(transparent)]
    UnexpectedError(#[from] anyhow::Error),
    #[error("Internal error")]
    InternalError(#[source] anyhow::Error),
    #[error("Bad request")]
    BadRequest(#[source] anyhow::Error),
    #[error("Not found error")]
    NotFoundError(#[source] anyhow::Error),
    #[error("Conflict error")]
    ConflictError(#[source] anyhow::Error),
}

crate::impl_debug!(ErrorResponse);

impl IntoResponse for ErrorResponse {
    fn into_response(self) -> Response {
        tracing::error!("{:?}", self);
        match self {
            ErrorResponse::UnexpectedError(_)
            | ErrorResponse::InternalError(_) => {
                StatusCode::INTERNAL_SERVER_ERROR.into_response()
            }
            // We use middleware to make json response from BadRequest
            ErrorResponse::BadRequest(e) => Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(Body::from(e.to_string()))
                .unwrap_or(StatusCode::BAD_REQUEST.into_response()),
            ErrorResponse::NotFoundError(param) => Response::builder()
                .status(StatusCode::NOT_FOUND)
                .header("Content-Type", "application/json")
                .body(Body::from(format!("{{\"param\":\"{}\"}}", param)))
                .unwrap_or(StatusCode::NOT_FOUND.into_response()),
            ErrorResponse::ConflictError(_) => {
                StatusCode::CONFLICT.into_response()
            }
        }
    }
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/user", routing::post(new_user))
        .route("/user/{username}", routing::get(get_user))
        .route("/users", routing::get(list_users))
        .route("/user/{username}/keypair", routing::post(new_keypair))
        .route("/msg", routing::post(new_msg))
        .route("/msg/{msg_id}", routing::post(sign_msg))
        .route("/msg/{msg_id}", routing::get(verify_msg_signature))
}

async fn new_user(
    State(state): State<AppState>,
    Query(api_doc::Username { name }): Query<api_doc::Username>,
) -> Result<StatusCode, ErrorResponse> {
    let user = name
        .map(|n| User {
            name: n,
            ..Default::default()
        })
        .unwrap_or_default();
    state.storage.store_user(user).await?;
    Ok(StatusCode::OK)
}

async fn get_user(
    State(state): State<AppState>,
    Path(username): Path<String>,
) -> Result<Json<Option<api_doc::User>>, ErrorResponse> {
    let user =
        state
            .storage
            .get_user(&username)
            .await?
            .map(|u| api_doc::User {
                id: u.id,
                name: u.name,
                keys: u
                    .keys
                    .values()
                    .map(|k| crypto::bt_addr_from_pk(&k.public_key()))
                    .collect(),
            });
    Ok(Json(user))
}

async fn list_users(
    State(state): State<AppState>,
) -> Result<Json<Vec<api_doc::User>>, ErrorResponse> {
    let users = state
        .storage
        .all_users()
        .await?
        .into_iter()
        .map(|u| api_doc::User {
            id: u.id,
            name: u.name,
            keys: u
                .keys
                .values()
                .map(|k| crypto::bt_addr_from_pk(&k.public_key()))
                .collect(),
        })
        .collect();
    Ok(Json(users))
}

async fn new_keypair(
    State(state): State<AppState>,
    Path(username): Path<String>,
) -> Result<StatusCode, ErrorResponse> {
    let mut user = state
        .storage
        .get_user(&username)
        .await?
        .ok_or(ErrorResponse::NotFoundError(anyhow!("user not found")))?;
    let keypair = crypto::new_keypair(&state.secp)
        .context("failed to generate keypair")?;
    user.add_keypair(keypair);
    state.storage.update_user(user).await?;
    Ok(StatusCode::OK)
}

async fn new_msg(
    State(state): State<AppState>,
    Json(req): Json<PostMsgRequest>,
) -> Result<String, ErrorResponse> {
    let selected_pubkeys = extract_selected_keypairs(&state, req.keys)
        .await?
        .into_iter()
        .map(|k| k.public_key())
        .collect();
    let msg = Message::new(
        req.content.as_bytes(),
        selected_pubkeys,
        req.required_signature_count,
    );
    let msg_id = msg.id.to_string();
    state.storage.store_msg(msg).await?;
    Ok(msg_id)
}

async fn sign_msg(
    State(state): State<AppState>,
    Path(msg_id): Path<uuid::Uuid>,
    Json(req): Json<SignMsgRequest>,
) -> Result<String, ErrorResponse> {
    let selected_keypairs = extract_selected_keypairs(&state, req.keys).await?;
    for keypair in selected_keypairs {
        let secp = state.secp.clone();
        state
            .storage
            .update_msg(
                &msg_id,
                Box::new(move |msg| {
                    msg.signature.sign(&secp, &msg.content, &keypair)?;
                    Ok(())
                }),
            )
            .await?;
    }
    Ok(String::new())
}

async fn verify_msg_signature(
    State(state): State<AppState>,
    Path(msg_id): Path<uuid::Uuid>,
) -> Result<String, ErrorResponse> {
    let msg = state
        .storage
        .get_msg(&msg_id)
        .await?
        .ok_or(ErrorResponse::NotFoundError(anyhow!("no message found")))?;
    let secp = secp256k1::Secp256k1::verification_only();
    match msg
        .signature
        .verify(&secp, &msg.content, msg.count_required)
    {
        Ok(()) => Ok("success".to_string()),
        Err(e) => Ok(format!("{e}")),
    }
}

// ───── Helpers ──────────────────────────────────────────────────────────── //

async fn extract_selected_keypairs(
    state: &AppState,
    keys: Vec<String>,
) -> Result<Vec<Keypair>, ErrorResponse> {
    let mut all_keypairs = state
        .storage
        .all_users()
        .await?
        .into_iter()
        .flat_map(|u| u.keys.into_values())
        .map(|k| (hash160::Hash::hash(&k.public_key().serialize()), k))
        .collect::<HashMap<_, _>>();
    let selected_keypairs = keys
        .into_iter()
        .map(|key| {
            let pkh = crypto::pkh_from_bt_addr(&key).map_err(|e| {
                ErrorResponse::BadRequest(anyhow!("invalid key: {}", e))
            })?;
            let keypair = all_keypairs.remove(&pkh).ok_or(
                ErrorResponse::NotFoundError(anyhow!("key not found: {}", key)),
            )?;
            Ok::<Keypair, ErrorResponse>(keypair)
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(selected_keypairs)
}

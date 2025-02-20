use std::collections::HashMap;

use anyhow::anyhow;
use axum::body::Body;
use axum::extract::{Path, Query, State};
use axum::response::{IntoResponse, Response};
use axum::Router;
use axum::{routing, Json};
use http::StatusCode;
use secp256k1::hashes::{hash160, Hash};
use secp256k1::PublicKey;

use crate::crypto;
use crate::domain::message::Message;
use crate::startup::api_doc::{self, PostMsgRequest};
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
        .route("/msg/{msg}", routing::post(new_msg))
        .route("/keypair", routing::post(new_keypair))
}

async fn new_user(
    State(state): State<AppState>,
    Query(user_name): Query<Option<String>>,
) -> Result<StatusCode, ErrorResponse> {
    let user = user_name
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

async fn new_msg(
    State(state): State<AppState>,
    Json(req): Json<PostMsgRequest>,
) -> Result<String, ErrorResponse> {
    let mut all_pubkeys = state
        .storage
        .all_users()
        .await?
        .into_iter()
        .map(|u| u.keys.into_iter().map(|(_, k)| k.public_key()))
        .flatten()
        .map(|pk| (hash160::Hash::hash(&pk.serialize()), pk))
        .collect::<HashMap<_, _>>();
    let selected_pubkeys = req
        .keys
        .into_iter()
        .map(|key| {
            let pkh = crypto::pkh_from_bt_addr(&key).map_err(|e| {
                ErrorResponse::BadRequest(anyhow!("invalid key: {}", e))
            })?;
            let pubkey = all_pubkeys.remove(&pkh).ok_or(
                ErrorResponse::NotFoundError(anyhow!("key not found: {}", key)),
            )?;
            Ok::<PublicKey, ErrorResponse>(pubkey)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let msg = Message::new(
        req.content.as_bytes(),
        selected_pubkeys,
        req.required_signature_count,
    );
    let msg_id = msg.id.to_string();
    state.storage.store_msg(msg)?;
    Ok(msg_id)
}

async fn new_keypair() -> StatusCode {
    StatusCode::OK
}

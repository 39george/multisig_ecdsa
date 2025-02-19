use axum::{routing, Router};
use http::StatusCode;

use crate::startup::AppState;

pub fn router() -> Router<AppState> {
    Router::new().route("/keypair", routing::post(new_keypair))
}

async fn new_keypair() -> StatusCode {
    StatusCode::OK
}

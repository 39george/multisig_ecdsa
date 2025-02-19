//! We derive ToSchema to all types need to show their fields to frontend,
//! and derive ToResponse to all types we bind as `response = Type`.
//! We only need ToSchema derived if we set response as `body = Type`.

use utoipa::{OpenApi, ToResponse};
use utoipauto::utoipauto;

// ───── ErrorResponses ───────────────────────────────────────────────────── //

#[derive(ToResponse)]
#[response(description = "Something happened on the server")]
pub struct InternalErrorResponse;

#[derive(ToResponse)]
#[response(description = "You not allowed to access this method")]
pub struct ForbiddenResponse;

// We use middleware to make json response from BadRequest
#[allow(dead_code)]
#[derive(ToResponse)]
#[response(
    description = "Request was formed erroneously",
    content_type = "application/json",
    example = json!({
        "caused_by":
        "Here will be the reason of a rejection"
    }),
)]
pub struct BadRequestResponse(String);

#[derive(ToResponse)]
#[response(description = "Not acceptable error")]
pub struct NotAcceptableErrorResponse;

#[derive(ToResponse)]
#[response(description = "Unauthorized error")]
pub struct UnauthorizedErrorResponse;

#[derive(ToResponse)]
#[response(description = "Too many uploads error")]
pub struct TooManyUploadsErrorResponse;

#[derive(ToResponse)]
#[response(description = "Conflict error")]
pub struct ConflictErrorResponse;

#[allow(dead_code)]
#[derive(ToResponse)]
#[response(
    description = "Unsupported mediatype error",
    content_type = "application/json",
    example = json!({
        "allowed_mediatypes": ["image/png"]
    }),
)]
pub struct UnsupportedMediaTypeErrorResponse(String);

// We use ToSchema here, because we write manually in every case,
// inlined, description, examples etc.
#[allow(dead_code)]
#[derive(ToResponse)]
#[response(
    description = "Not found some data (param name passed)",
    content_type = "application/json",
    example = json!({
        "param": "param_name" }),
)]
pub struct NotFoundResponse {
    param: String,
}

// ───── Api ──────────────────────────────────────────────────────────────── //

#[utoipauto]
#[derive(OpenApi)]
#[openapi(
        tags(
            (name = "open", description = "Open routes (no authorization)"),
        ),
        info(
            title = "Multisig - OpenAPI 3.0",
            version = "0.1.0",
            description = "This is a swagger documentation for simple multisig service.",
        )
    )]
pub(super) struct ApiDoc;

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use thiserror::Error;

/// Top-level application error. Produces structured JSON. Internal details are logged securely.
#[derive(Debug, Error)]
pub enum AppError {
    #[error("Authentication required")]
    Unauthorized,

    #[error("Forbidden")]
    Forbidden,

    #[error("Not found")]
    NotFound,

    #[error("Bad request: {0}")]
    BadRequest(String),

    #[error("Conflict: {0}")]
    Conflict(String),



    #[error("Internal server error")]
    Internal(#[from] anyhow::Error),

    #[error("Database error")]
    Database(#[from] sqlx::Error),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, message) = match &self {
            AppError::Unauthorized => (StatusCode::UNAUTHORIZED, self.to_string()),
            AppError::Forbidden => (StatusCode::FORBIDDEN, self.to_string()),
            AppError::NotFound => (StatusCode::NOT_FOUND, self.to_string()),
            AppError::BadRequest(msg) => (StatusCode::BAD_REQUEST, msg.clone()),
            AppError::Conflict(_) => (StatusCode::CONFLICT, self.to_string()),

            AppError::Internal(e) => {
                tracing::error!(error = %e, "Internal server error");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "An internal error occurred".to_string(),
                )
            }
            AppError::Database(e) => {
                tracing::error!(error = %e, "Database error");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "An internal error occurred".to_string(),
                )
            }
        };

        (status, Json(json!({ "error": message }))).into_response()
    }
}

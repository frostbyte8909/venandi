use axum::{Json, extract::State, response::IntoResponse};

use crate::{
    api::extractors::AuthUser,
    db::queries::get_suspicious_ips,
    error::AppError,
    state::AppState,
};

/// Returns IP correlation rows where multiple teams submitted from the same IP
/// within a 15-minute window. Restricted to admins.
pub async fn audit_ips(
    State(state): State<AppState>,
    AuthUser(claims): AuthUser,
) -> Result<impl IntoResponse, AppError> {
    if claims.role != "admin" {
        return Err(AppError::Forbidden);
    }
    let rows = get_suspicious_ips(&state.read_pool).await?;
    Ok(Json(rows))
}

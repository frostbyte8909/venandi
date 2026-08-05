use axum::{
    async_trait,
    extract::FromRequestParts,
    http::request::Parts,
};
use axum_extra::extract::CookieJar;
use jsonwebtoken::{DecodingKey, Validation, decode};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{error::AppError, state::AppState};

/// JWT claims payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    pub user_id: Uuid,
    pub team_id: Option<Uuid>,
    pub role: String,
    pub token_version: i64,
    pub exp: usize,
}

/// Requires authenticated JWT cookie. Validates signature, expiration, and revocation status.
pub struct AuthUser(pub Claims);

#[async_trait]
impl FromRequestParts<AppState> for AuthUser {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let jar = CookieJar::from_headers(&parts.headers);

        let token = jar
            .get("venandi_token")
            .map(|c| c.value().to_owned())
            .ok_or(AppError::Unauthorized)?;

        let key = DecodingKey::from_secret(state.jwt_secret.as_bytes());
        let token_data = decode::<Claims>(&token, &key, &Validation::default())
            .map_err(|_| AppError::Unauthorized)?;

        let claims = token_data.claims;

        // Verify token_version against database
        let user_id_str = claims.user_id.to_string();
        let current_version = sqlx::query!(
            r#"SELECT token_version as "token_version!" FROM users WHERE id = ?1"#,
            user_id_str
        )
        .fetch_optional(&state.read_pool)
        .await
        .map_err(|e| AppError::Internal(e.into()))?
        .map(|r| r.token_version)
        .unwrap_or(1);

        if current_version != claims.token_version {
            return Err(AppError::Unauthorized);
        }

        Ok(AuthUser(claims))
    }
}

/// Requires authenticated JWT cookie with 'admin' role.
pub struct AdminUser(pub Claims);

#[async_trait]
impl FromRequestParts<AppState> for AdminUser {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let AuthUser(claims) = AuthUser::from_request_parts(parts, state).await?;
        if claims.role != "admin" {
            return Err(AppError::Forbidden);
        }
        Ok(AdminUser(claims))
    }
}

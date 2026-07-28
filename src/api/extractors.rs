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

/// JWT claims embedded in the HttpOnly cookie.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    pub user_id: Uuid,
    pub team_id: Option<Uuid>,
    pub role: String,
    pub exp: usize,
}

/// Authenticated user, extracted from the HttpOnly JWT cookie.
/// Use this extractor in handlers that require authentication.
///
/// Fails with `AppError::Unauthorized` if:
/// - The cookie is absent.
/// - The JWT is expired or has an invalid signature.
/// - The team is on the revocation blacklist.
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

        // Check team revocation blacklist.
        if let Some(team_id) = &claims.team_id {
            let blacklisted = state
                .revoked_teams
                .read()
                .map_err(|_| AppError::Internal(anyhow::anyhow!("RwLock poisoned")))?
                .contains(&team_id.to_string());

            if blacklisted {
                return Err(AppError::Unauthorized);
            }
        }

        Ok(AuthUser(claims))
    }
}

/// Admin-only authenticated user.
/// Rejects with `AppError::Forbidden` if the role is not `"admin"`.
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

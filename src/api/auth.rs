use argon2::{
    Argon2,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString, rand_core::OsRng},
};
use axum::{Json, extract::State, response::IntoResponse};
use axum_extra::extract::CookieJar;
use axum_extra::extract::cookie::{Cookie, SameSite};
use chrono::{Duration, Utc};
use jsonwebtoken::{EncodingKey, Header, encode};
use serde::{Deserialize, Serialize};
use time::Duration as TimeDuration;
use uuid::Uuid;

use crate::{
    api::extractors::Claims,
    db::{
        actor::DbCommand,
        queries::{get_user_by_email},
    },
    error::AppError,
    state::AppState,
};

// ─── Request / Response Bodies ────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct RegisterRequest {
    pub email: String,
    pub password: String,
}

#[derive(Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

#[derive(Serialize)]
pub struct AuthResponse {
    pub user_id: String,
    pub role: String,
    pub team_id: Option<String>,
}

// ─── Handlers ────────────────────────────────────────────────────────────────

/// POST /api/auth/register
/// Creates a new user account. Hashing is offloaded to a blocking thread.
pub async fn register(
    State(state): State<AppState>,
    Json(body): Json<RegisterRequest>,
) -> Result<impl IntoResponse, AppError> {
    // Validate email format (basic check).
    if body.email.is_empty() || !body.email.contains('@') {
        return Err(AppError::BadRequest("Invalid email address.".into()));
    }
    if body.password.len() < 8 {
        return Err(AppError::BadRequest(
            "Password must be at least 8 characters.".into(),
        ));
    }

    // Check for existing account.
    if get_user_by_email(&state.read_pool, &body.email)
        .await?
        .is_some()
    {
        return Err(AppError::Conflict("Email already registered.".into()));
    }

    // Hash the password on a blocking thread — Argon2id is CPU-bound.
    let password_hash = tokio::task::spawn_blocking(move || {
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        argon2
            .hash_password(body.password.as_bytes(), &salt)
            .map(|h| h.to_string())
    })
    .await
    .map_err(|e| AppError::Internal(e.into()))?
    .map_err(|e| AppError::Internal(anyhow::anyhow!("Hashing error: {e}")))?;

    let user_id = Uuid::new_v4();

    state
        .db_tx
        .send(DbCommand::CreateUser {
            id: user_id,
            email: body.email,
            password_hash,
            role: "player".into(),
        })
        .await
        .map_err(|e| AppError::Internal(e.into()))?;

    Ok((
        axum::http::StatusCode::CREATED,
        Json(serde_json::json!({ "user_id": user_id, "message": "Account created." })),
    ))
}

/// POST /api/auth/login
/// Verifies credentials and issues an HttpOnly JWT cookie.
pub async fn login(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(body): Json<LoginRequest>,
) -> Result<(CookieJar, impl IntoResponse), AppError> {
    let user = get_user_by_email(&state.read_pool, &body.email)
        .await?
        .ok_or(AppError::Unauthorized)?;

    let password_hash = user.password_hash.clone();
    let password = body.password.clone();

    // Verify on a blocking thread to avoid starving Tokio workers.
    let valid = tokio::task::spawn_blocking(move || {
        let parsed = PasswordHash::new(&password_hash)
            .map_err(|e| anyhow::anyhow!("Hash parse: {e}"))?;
        let ok = Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .is_ok();
        Ok::<bool, anyhow::Error>(ok)
    })
    .await
    .map_err(|e| AppError::Internal(e.into()))?
    .map_err(|e| AppError::Internal(e))?;

    if !valid {
        return Err(AppError::Unauthorized);
    }

    let user_id = Uuid::parse_str(&user.id)
        .map_err(|e| AppError::Internal(anyhow::anyhow!("UUID parse: {e}")))?;
    let team_id = user
        .team_id
        .as_deref()
        .map(Uuid::parse_str)
        .transpose()
        .map_err(|e| AppError::Internal(anyhow::anyhow!("UUID parse: {e}")))?;

    // Build JWT (12-hour expiry).
    let exp = (Utc::now() + Duration::hours(12)).timestamp() as usize;
    let claims = Claims {
        user_id,
        team_id,
        role: user.role.clone(),
        exp,
    };

    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(state.jwt_secret.as_bytes()),
    )
    .map_err(|e| AppError::Internal(anyhow::anyhow!("JWT encode: {e}")))?;

    // Attach HttpOnly, SameSite=Strict, Secure cookie.
    let cookie = Cookie::build(("venandi_token", token))
        .http_only(true)
        .same_site(SameSite::Strict)
        .secure(true)
        .path("/")
        .max_age(TimeDuration::hours(12))
        .build();

    Ok((
        jar.add(cookie),
        Json(AuthResponse {
            user_id: user_id.to_string(),
            role: user.role,
            team_id: team_id.map(|t| t.to_string()),
        }),
    ))
}

/// POST /api/auth/logout
/// Clears the JWT cookie.
pub async fn logout(jar: CookieJar) -> (CookieJar, axum::http::StatusCode) {
    let cleared = Cookie::build(("venandi_token", ""))
        .http_only(true)
        .same_site(SameSite::Strict)
        .secure(true)
        .path("/")
        .max_age(TimeDuration::seconds(0))
        .build();
    (jar.add(cleared), axum::http::StatusCode::OK)
}

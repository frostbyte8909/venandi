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
use sha1_smol::Sha1;
use time::Duration as TimeDuration;
use tokio::sync::oneshot;
use uuid::Uuid;

use crate::{
    api::extractors::Claims,
    db::{
        actor::DbCommand,
        queries::get_user_by_email,
    },
    error::AppError,
    state::AppState,
};

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

pub async fn register(
    State(state): State<AppState>,
    Json(body): Json<RegisterRequest>,
) -> Result<impl IntoResponse, AppError> {
    if body.email.is_empty() || !body.email.contains('@') {
        return Err(AppError::BadRequest("Invalid email address.".into()));
    }
    if body.email.len() > 320 {
        return Err(AppError::BadRequest("Email too long.".into()));
    }
    if body.password.len() < 8 || body.password.len() > 128 {
        return Err(AppError::BadRequest(
            "Password must be between 8 and 128 characters.".into(),
        ));
    }

    if get_user_by_email(&state.read_pool, &body.email)
        .await?
        .is_some()
    {
        return Err(AppError::Conflict("Email already registered.".into()));
    }

    // HIBP k-anonymity: SHA-1 prefix of password is sent; suffix compared locally.
    if hibp_is_breached(&body.password).await {
        return Err(AppError::BadRequest(
            "This password has appeared in a known data breach. Choose a different one.".into(),
        ));
    }

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
    let (result_tx, result_rx) = oneshot::channel();

    state
        .db_tx
        .send(DbCommand::CreateUser {
            id: user_id,
            email: body.email,
            password_hash,
            role: "player".into(),
            result_tx,
        })
        .await
        .map_err(|e| AppError::Internal(e.into()))?;

    match result_rx.await {
        Ok(Ok(())) => {
            Ok((
                axum::http::StatusCode::CREATED,
                Json(serde_json::json!({ "user_id": user_id, "message": "Account created." })),
            ))
        }
        Ok(Err(e)) => Err(e),
        Err(_) => Err(AppError::Internal(anyhow::anyhow!("DB actor dropped"))),
    }
}

pub async fn login(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(body): Json<LoginRequest>,
) -> Result<(CookieJar, impl IntoResponse), AppError> {
    if body.email.len() > 320 || body.password.len() > 128 {
        return Err(AppError::Unauthorized);
    }

    let user = get_user_by_email(&state.read_pool, &body.email)
        .await?
        .ok_or(AppError::Unauthorized)?;

    let password_hash = user.password_hash.clone();
    let password = body.password.clone();

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
    .map_err(AppError::Internal)?;

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

    let exp = (Utc::now() + Duration::hours(12)).timestamp() as usize;
    let claims = Claims {
        user_id,
        team_id,
        role: user.role.clone(),
        token_version: user.token_version,
        exp,
    };

    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(state.jwt_secret.as_bytes()),
    )
    .map_err(|e| AppError::Internal(anyhow::anyhow!("JWT encode: {e}")))?;

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

/// k-Anonymity HIBP check. Only the first 5 hex chars of the SHA-1 hash leave the server.
/// Returns `true` if the password suffix is found in the breach list (breach count > 0).
async fn hibp_is_breached(password: &str) -> bool {
    let hash = format!("{}", Sha1::from(password).digest()).to_uppercase();
    let (prefix, suffix) = hash.split_at(5);

    let url = format!("https://api.pwnedpasswords.com/range/{prefix}");
    let Ok(resp) = reqwest::Client::new()
        .get(&url)
        .header("Add-Padding", "true")
        .send()
        .await
    else {
        // If the HIBP API is unreachable, fail open to avoid blocking registration.
        tracing::warn!("HIBP API unreachable; skipping breach check");
        return false;
    };

    let Ok(body) = resp.text().await else { return false };

    body.lines().any(|line| {
        line.split_once(':')
            .map(|(h, count)| h == suffix && count.trim().parse::<u64>().unwrap_or(0) > 0)
            .unwrap_or(false)
    })
}

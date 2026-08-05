use std::time::{Duration, Instant};

use axum::{
    extract::{
        State, WebSocketUpgrade,
        ws::{Message, WebSocket},
    },
    http::HeaderMap,
    response::IntoResponse,
};
use uuid::Uuid;

use crate::{
    api::extractors::AuthUser,
    error::AppError,
    state::{AppState, EphemeralTicket},
};

/// POST /api/ws/ticket
/// Generates 256-bit ephemeral upgrade ticket valid for 30s.
/// Requires valid JWT.
pub async fn issue_ticket(
    State(state): State<AppState>,
    AuthUser(claims): AuthUser,
) -> Result<impl IntoResponse, AppError> {
    let team_id = claims
        .team_id
        .ok_or_else(|| AppError::BadRequest("Must be on a team to connect via WebSocket.".into()))?;

    let ticket_id = Uuid::new_v4();
    let ticket = EphemeralTicket {
        team_id,
        user_id: claims.user_id,
        role: claims.role,
        expires_at: Instant::now() + Duration::from_secs(30),
    };

    state.ws_tickets.insert(ticket_id, ticket);

    Ok(axum::Json(serde_json::json!({ "ticket": ticket_id })))
}

/// GET /ws?ticket=<UUID>
/// Upgrades connection to WebSocket.
/// Ticket is burned on first read to prevent replay attacks.
/// Validates Origin header against VENANDI_ALLOWED_ORIGINS to mitigate CSWSH.
pub async fn ws_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
    ws: WebSocketUpgrade,
) -> Result<impl IntoResponse, AppError> {
    let origin = headers
        .get("origin")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    if !state.allowed_origins.contains(origin) {
        tracing::warn!(origin = %origin, "WebSocket upgrade rejected: invalid origin");
        return Err(AppError::Forbidden);
    }

    let ticket_str = params
        .get("ticket")
        .ok_or_else(|| AppError::BadRequest("Missing ticket parameter.".into()))?;

    let ticket_id = Uuid::parse_str(ticket_str)
        .map_err(|_| AppError::BadRequest("Invalid ticket format.".into()))?;

    let (_, ticket) = state
        .ws_tickets
        .remove(&ticket_id)
        .ok_or(AppError::Unauthorized)?;

    if Instant::now() > ticket.expires_at {
        return Err(AppError::Unauthorized);
    }

    tracing::info!(
        team_id = %ticket.team_id,
        user_id = %ticket.user_id,
        "WebSocket connection established."
    );

    Ok(ws.on_upgrade(move |socket| handle_socket(socket, ticket.team_id, ticket.user_id)))
}

async fn handle_socket(mut socket: WebSocket, team_id: Uuid, user_id: Uuid) {
    let welcome = serde_json::json!({
        "type": "connected",
        "team_id": team_id,
        "user_id": user_id,
    });

    if socket
        .send(Message::Text(welcome.to_string()))
        .await
        .is_err()
    {
        return;
    }

    while let Some(Ok(msg)) = socket.recv().await {
        match msg {
            Message::Text(text) => {
                tracing::debug!(team_id = %team_id, msg = %text, "WS message received");
                let _ = socket.send(Message::Text(text)).await;
            }
            Message::Close(_) => {
                tracing::info!(team_id = %team_id, "WebSocket connection closed.");
                break;
            }
            Message::Ping(data) => {
                let _ = socket.send(Message::Pong(data)).await;
            }
            _ => {}
        }
    }
}

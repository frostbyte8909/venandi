use std::{
    collections::HashSet,
    sync::Arc,
    time::Instant,
};

use dashmap::DashMap;
use sqlx::SqlitePool;
use tokio::sync::mpsc;
use uuid::Uuid;

use crate::{bot::event_bus::DiscordEvent, config::HuntConfig, db::actor::DbCommand, toasts::ToastRegistry};

/// Ephemeral WebSocket upgrade ticket. Valid for 30s.
#[derive(Debug, Clone)]
pub struct EphemeralTicket {
    pub team_id: Uuid,
    pub user_id: Uuid,
    pub role: String,
    pub expires_at: Instant,
}

/// Global application state.
#[derive(Clone)]
pub struct AppState {
    /// Read-only SQLite pool.
    pub read_pool: SqlitePool,

    /// Single-writer DB mutation channel.
    pub db_tx: mpsc::Sender<DbCommand>,

    /// Discord event bus channel.
    pub discord_tx: mpsc::Sender<DiscordEvent>,

    /// Pending WebSocket tickets.
    pub ws_tickets: Arc<DashMap<Uuid, EphemeralTicket>>,



    /// Immutable hunt configuration.
    pub hunt: Arc<HuntConfig>,

    /// HMAC key for dynamic flags.
    pub server_secret: Arc<Vec<u8>>,

    /// JWT signing secret.
    pub jwt_secret: Arc<String>,

    /// Allowed WebSocket origins.
    pub allowed_origins: Arc<HashSet<String>>,

    /// Randomised response variants, reloadable at runtime.
    pub toasts: Arc<ToastRegistry>,
}

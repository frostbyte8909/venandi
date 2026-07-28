use std::{
    collections::HashSet,
    sync::{Arc, RwLock},
    time::Instant,
};

use dashmap::DashMap;
use sqlx::SqlitePool;
use tokio::sync::mpsc;
use uuid::Uuid;

use crate::{bot::event_bus::DiscordEvent, config::HuntConfig, db::actor::DbCommand};

/// An ephemeral WebSocket upgrade ticket.
/// Lives in memory for at most 30 seconds before it is considered expired.
#[derive(Debug, Clone)]
pub struct EphemeralTicket {
    pub team_id: Uuid,
    pub user_id: Uuid,
    pub role: String,
    pub expires_at: Instant,
}

/// Global application state shared across all Axum handlers via `Arc`.
/// All fields are `Clone` or wrapped in interior-mutability primitives for
/// safe concurrent access.
#[derive(Clone)]
pub struct AppState {
    /// SQLite connection pool for concurrent reads (WAL mode).
    pub read_pool: SqlitePool,

    /// Channel sender to the single-writer DB mutation actor.
    pub db_tx: mpsc::Sender<DbCommand>,

    /// Channel sender to the async Discord event bus worker.
    pub discord_tx: mpsc::Sender<DiscordEvent>,

    /// In-memory DashMap of ephemeral WebSocket upgrade tickets.
    /// O(1) sharded concurrent access; zero disk I/O.
    pub ws_tickets: Arc<DashMap<Uuid, EphemeralTicket>>,

    /// In-memory blacklist of revoked team IDs (e.g., after a ban).
    /// Checked on every authenticated request before JWT claims are trusted.
    pub revoked_teams: Arc<RwLock<HashSet<String>>>,

    /// The fully-parsed and validated hunt configuration (immutable after boot).
    pub hunt: Arc<HuntConfig>,

    /// HMAC key for dynamic flag generation (from VENANDI_SERVER_SECRET).
    pub server_secret: Arc<Vec<u8>>,

    /// JWT signing secret (from VENANDI_JWT_SECRET).
    pub jwt_secret: Arc<String>,

    /// Allowed WebSocket origins parsed from VENANDI_ALLOWED_ORIGINS at boot.
    pub allowed_origins: Arc<HashSet<String>>,
}

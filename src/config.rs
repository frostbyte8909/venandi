use serde::{Deserialize, Serialize};

/// Root configuration loaded from `config/hunt.json` once at startup.
/// This is the single source of truth for event layout. Never persisted to DB.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct HuntConfig {
    pub event: EventMeta,
    pub levels: Vec<LevelConfig>,
}

/// Top-level event metadata.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct EventMeta {
    pub name: String,
    /// When `true`, static flags are accepted verbatim.
    /// When `false` (Cryptic Hunt mode), answers are normalised before matching.
    pub ctf_mode: bool,
}

/// Configuration for a single level, parsed from `hunt.json`.
/// Levels are NEVER stored in the database; this struct lives in memory only.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct LevelConfig {
    pub id: String,
    pub points: u32,
    /// Boolean expression string that must evaluate to `true` before this level
    /// becomes available to a team.
    /// Special value `"START"` means the level is always unlocked.
    pub unlock_condition: String,
    /// Accepted plaintext answers (only used when `dynamic_flag = false`).
    pub answers: Vec<String>,
    /// When `true`, the expected answer is generated as
    /// `HMAC-SHA256(SERVER_SECRET, level_id + ":" + team_id)` and no static
    /// answers are consulted.
    pub dynamic_flag: bool,
}

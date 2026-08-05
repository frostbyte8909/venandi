use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Root configuration loaded from `config/hunt.json` once at startup.
/// Single source of truth for event layout. Never persisted to DB.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct HuntConfig {
    pub event: EventMeta,
    pub levels: Vec<LevelConfig>,
    /// Known canary flag strings. Any submission matching one triggers an anti-cheat alert.
    #[serde(default)]
    pub canary_flags: Vec<String>,
}

/// Top-level event metadata.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct EventMeta {
    pub name: String,
    /// When `true`, static flags are accepted verbatim.
    /// When `false` (Cryptic Hunt mode), answers are normalised before matching.
    pub ctf_mode: bool,
    /// When set, public leaderboard order and solve counts freeze at this UTC instant.
    /// Solves continue to register internally after this time.
    pub freeze_time: Option<DateTime<Utc>>,
}

/// Configuration for a single level, parsed from `hunt.json`.
/// Levels are NEVER stored in the database; this struct lives in memory only.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct LevelConfig {
    pub id: String,
    /// Initial point value before any solves. Used as S_max in decay formula.
    pub points: u32,
    /// Minimum points awarded regardless of solve count. S_min in decay formula.
    #[serde(default = "default_points_min")]
    pub points_min: u32,
    /// Number of solves at which the challenge hits points_min. decay_threshold in decay formula.
    #[serde(default = "default_decay_threshold")]
    pub decay_threshold: u32,
    /// Boolean expression string that must evaluate to `true` before this level
    /// becomes available to a team. Special value `"START"` means always unlocked.
    pub unlock_condition: String,
    /// Accepted plaintext answers (only used when `dynamic_flag = false`).
    pub answers: Vec<String>,
    /// When `true`, the expected answer is generated as
    /// `HMAC-SHA256(SERVER_SECRET, level_id + ":" + team_id)`.
    pub dynamic_flag: bool,
}

fn default_points_min() -> u32 { 100 }
fn default_decay_threshold() -> u32 { 50 }

/// Compute the decayed point value for a challenge given the current solve count.
/// S = S_min + (S_max - S_min) * (1 - solves / decay_threshold)^2
pub fn compute_decayed_points(level: &LevelConfig, solve_count: u32) -> u32 {
    if solve_count >= level.decay_threshold {
        return level.points_min;
    }
    let ratio = 1.0 - (solve_count as f64 / level.decay_threshold as f64);
    let decayed = level.points_min as f64
        + (level.points as f64 - level.points_min as f64) * ratio * ratio;
    decayed.round() as u32
}

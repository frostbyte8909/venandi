
use chrono::{DateTime, Utc};
use serde::Serialize;
use sqlx::SqlitePool;
use uuid::Uuid;

use crate::error::AppError;

/// Team leaderboard record. Score is computed from `team_scores_view` SQL view.
#[derive(Debug, Serialize)]
pub struct TeamRow {
    pub id: String,
    pub name: String,
    pub score: i64,
    pub canary_triggered: bool,
}

/// User authentication record.
#[derive(Debug)]
pub struct UserRow {
    pub id: String,
    pub team_id: Option<String>,
    pub email: String,
    pub password_hash: String,
    pub role: String,
    pub token_version: i64,
}

/// Team solve record.
#[derive(Debug, Serialize)]
pub struct SolveRow {
    pub level_id: String,
    pub timestamp: String,
}

/// IP correlation row for anti-cheat auditing.
#[derive(Debug, Serialize)]
pub struct IpCorrelationRow {
    pub ip_address: String,
    pub team_ids: String,
    pub earliest_solve: String,
    pub latest_solve: String,
}

/// Returns top N teams by decayed score descending.
/// When `freeze_time` is set, order is locked to solves recorded before that instant.
pub async fn get_leaderboard(
    pool: &SqlitePool,
    limit: i64,
    freeze_time: Option<DateTime<Utc>>,
) -> Result<Vec<TeamRow>, AppError> {
    // CAST is required because COALESCE over a view column appears as NULL type to sqlx.
    let rows = if let Some(freeze) = freeze_time {
        let freeze_str = freeze.to_rfc3339();
        sqlx::query!(
            r#"SELECT t.id as "id!", t.name as "name!",
                      t.canary_triggered as "canary_triggered!: i64",
                      CAST(COALESCE(SUM(s.points_at_solve), 0) AS INTEGER) as "score!: i64"
               FROM teams t
               LEFT JOIN solves s ON s.team_id = t.id AND s.timestamp <= ?2
               GROUP BY t.id
               ORDER BY 4 DESC
               LIMIT ?1"#,
            limit, freeze_str
        )
        .fetch_all(pool)
        .await?
        .into_iter()
        .map(|r| TeamRow {
            id: r.id,
            name: r.name,
            score: r.score,
            canary_triggered: r.canary_triggered != 0,
        })
        .collect()
    } else {
        sqlx::query!(
            r#"SELECT t.id as "id!", t.name as "name!",
                      t.canary_triggered as "canary_triggered!: i64",
                      CAST(COALESCE(SUM(s.points_at_solve), 0) AS INTEGER) as "score!: i64"
               FROM teams t
               LEFT JOIN solves s ON s.team_id = t.id
               GROUP BY t.id
               ORDER BY 4 DESC
               LIMIT ?1"#,
            limit
        )
        .fetch_all(pool)
        .await?
        .into_iter()
        .map(|r| TeamRow {
            id: r.id,
            name: r.name,
            score: r.score,
            canary_triggered: r.canary_triggered != 0,
        })
        .collect()
    };

    Ok(rows)
}

pub async fn get_team_by_id(pool: &SqlitePool, team_id: Uuid) -> Result<Option<TeamRow>, AppError> {
    let team_id_str = team_id.to_string();
    let row = sqlx::query!(
        r#"SELECT t.id as "id!", t.name as "name!",
                  t.canary_triggered as "canary_triggered!: i64",
                  CAST(COALESCE(SUM(s.points_at_solve), 0) AS INTEGER) as "score!: i64"
           FROM teams t
           LEFT JOIN solves s ON s.team_id = t.id
           WHERE t.id = ?1
           GROUP BY t.id"#,
        team_id_str
    )
    .fetch_optional(pool)
    .await?
    .map(|r| TeamRow {
        id: r.id,
        name: r.name,
        score: r.score,
        canary_triggered: r.canary_triggered != 0,
    });
    Ok(row)
}

pub async fn get_user_by_email(
    pool: &SqlitePool,
    email: &str,
) -> Result<Option<UserRow>, AppError> {
    let row = sqlx::query!(
        r#"SELECT id as "id!", team_id, email as "email!", password_hash as "password_hash!", role as "role!", token_version as "token_version!"
           FROM users WHERE email = ?1"#,
        email
    )
    .fetch_optional(pool)
    .await?
    .map(|r| UserRow {
        id: r.id,
        team_id: r.team_id,
        email: r.email,
        password_hash: r.password_hash,
        role: r.role,
        token_version: r.token_version,
    });
    Ok(row)
}

pub async fn team_has_solved(
    pool: &SqlitePool,
    team_id: Uuid,
    level_id: &str,
) -> Result<bool, AppError> {
    let team_id_str = team_id.to_string();
    let row = sqlx::query!(
        r#"SELECT COUNT(*) as cnt FROM solves WHERE team_id = ?1 AND level_id = ?2"#,
        team_id_str,
        level_id
    )
    .fetch_one(pool)
    .await?;
    Ok(row.cnt > 0)
}

pub async fn get_team_solves(
    pool: &SqlitePool,
    team_id: Uuid,
) -> Result<Vec<SolveRow>, AppError> {
    let team_id_str = team_id.to_string();
    let rows = sqlx::query!(
        r#"SELECT level_id as "level_id!", timestamp as "timestamp!" FROM solves WHERE team_id = ?1 ORDER BY timestamp ASC"#,
        team_id_str
    )
    .fetch_all(pool)
    .await?
    .into_iter()
    .map(|r| SolveRow { level_id: r.level_id, timestamp: r.timestamp })
    .collect();
    Ok(rows)
}

/// Returns the current solve count for a given challenge. Used to compute decayed score.
pub async fn get_solve_count_for_level(
    pool: &SqlitePool,
    level_id: &str,
) -> Result<u32, AppError> {
    let row = sqlx::query!(
        "SELECT COUNT(*) as cnt FROM solves WHERE level_id = ?1",
        level_id
    )
    .fetch_one(pool)
    .await?;
    Ok(row.cnt as u32)
}

/// Returns IP correlation data: IPs associated with >1 distinct team within a 15-min window.
pub async fn get_suspicious_ips(pool: &SqlitePool) -> Result<Vec<IpCorrelationRow>, AppError> {
    // ORDER BY alias requires a subquery in standard SQL; we wrap to avoid the alias issue.
    let rows = sqlx::query!(
        r#"SELECT ip_address as "ip_address!", team_ids as "team_ids!",
                  earliest_solve as "earliest_solve!", latest_solve as "latest_solve!"
           FROM (
               SELECT
                   ip_address,
                   GROUP_CONCAT(DISTINCT team_id) as team_ids,
                   MIN(timestamp) as earliest_solve,
                   MAX(timestamp) as latest_solve
               FROM solves
               WHERE ip_address IS NOT NULL
               GROUP BY ip_address
               HAVING COUNT(DISTINCT team_id) > 1
                  AND (JULIANDAY(MAX(timestamp)) - JULIANDAY(MIN(timestamp))) * 1440 <= 15
           ) sub
           ORDER BY earliest_solve DESC"#
    )
    .fetch_all(pool)
    .await?
    .into_iter()
    .map(|r| IpCorrelationRow {
        ip_address: r.ip_address,
        team_ids: r.team_ids,
        earliest_solve: r.earliest_solve,
        latest_solve: r.latest_solve,
    })
    .collect();
    Ok(rows)
}

/// Returns 1-indexed team rank based on live aggregated score.
pub async fn get_team_rank(pool: &SqlitePool, team_id: Uuid) -> Result<i64, AppError> {
    let team_id_str = team_id.to_string();
    let row = sqlx::query!(
        r#"SELECT CAST(COUNT(*) + 1 AS INTEGER) as "rank!: i64"
           FROM (
               SELECT team_id, SUM(points_at_solve) as total
               FROM solves GROUP BY team_id
           ) scores
           WHERE total > (
               SELECT COALESCE(SUM(points_at_solve), 0)
               FROM solves WHERE team_id = ?1
           )"#,
        team_id_str
    )
    .fetch_one(pool)
    .await?;
    Ok(row.rank)
}

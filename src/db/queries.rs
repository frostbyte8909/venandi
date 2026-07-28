
use serde::Serialize;
use sqlx::SqlitePool;
use uuid::Uuid;

use crate::error::AppError;

/// Lightweight team record returned for leaderboard and status queries.
#[derive(Debug, Serialize)]
pub struct TeamRow {
    pub id: String,
    pub name: String,
    pub score: i64,
}

/// User record for authentication lookups.
#[derive(Debug)]
pub struct UserRow {
    pub id: String,
    pub team_id: Option<String>,
    pub email: String,
    pub password_hash: String,
    pub role: String,
}

/// Solve record.
#[derive(Debug, Serialize)]
pub struct SolveRow {
    pub level_id: String,
    pub timestamp: String,
}

/// Fetches top N teams ordered by score descending (for leaderboard).
pub async fn get_leaderboard(pool: &SqlitePool, limit: i64) -> Result<Vec<TeamRow>, AppError> {
    let rows = sqlx::query!(
        r#"SELECT id as "id!", name as "name!", score as "score!" FROM teams ORDER BY score DESC LIMIT ?1"#,
        limit
    )
    .fetch_all(pool)
    .await?
    .into_iter()
    .map(|r| TeamRow { id: r.id, name: r.name, score: r.score })
    .collect();
    Ok(rows)
}

/// Fetches a team by its ID.
pub async fn get_team_by_id(pool: &SqlitePool, team_id: Uuid) -> Result<Option<TeamRow>, AppError> {
    let team_id_str = team_id.to_string();
    let row = sqlx::query!(
        r#"SELECT id as "id!", name as "name!", score as "score!" FROM teams WHERE id = ?1"#,
        team_id_str
    )
    .fetch_optional(pool)
    .await?
    .map(|r| TeamRow { id: r.id, name: r.name, score: r.score });
    Ok(row)
}

/// Fetches a user by their email address.
pub async fn get_user_by_email(
    pool: &SqlitePool,
    email: &str,
) -> Result<Option<UserRow>, AppError> {
    let row = sqlx::query!(
        r#"SELECT id as "id!", team_id, email as "email!", password_hash as "password_hash!", role as "role!"
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
    });
    Ok(row)
}

/// Checks whether a team has already solved a given level.
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

/// Returns all level IDs solved by a given team.
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

/// Returns the rank of a team (1-indexed, lower is better).
pub async fn get_team_rank(pool: &SqlitePool, team_id: Uuid) -> Result<i64, AppError> {
    let team_id_str = team_id.to_string();
    let row = sqlx::query!(
        r#"SELECT COUNT(*) + 1 as "rank!" FROM teams
           WHERE score > (SELECT score FROM teams WHERE id = ?1)"#,
        team_id_str
    )
    .fetch_one(pool)
    .await?;
    Ok(row.rank)
}

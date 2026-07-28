use anyhow::Result;
use chrono::Utc;
use sqlx::SqlitePool;
use tokio::sync::mpsc;
use tracing::{error, warn};
use uuid::Uuid;

/// Commands that can be sent to the single-writer SQLite actor.
/// Each variant carries all data needed to perform the mutation.
/// The actor owns the write connection and processes commands sequentially,
/// ensuring SQLite never sees concurrent writers.
#[derive(Debug)]
pub enum DbCommand {
    CreateUser {
        id: Uuid,
        email: String,
        password_hash: String,
        role: String,
    },
    SetUserTeam {
        user_id: Uuid,
        team_id: Uuid,
    },
    CreateTeam {
        id: Uuid,
        name: String,
        join_code: String,
        password_hash: String,
    },
    RecordSolve {
        team_id: Uuid,
        level_id: String,
        points: u32,
    },
    WriteAuditLog {
        team_id: Option<Uuid>,
        user_id: Option<Uuid>,
        action: String,
    },
    UpsertAdmin {
        id: Uuid,
        email: String,
        password_hash: String,
    },
}

/// Spawns the single-writer SQLite actor as a background Tokio task.
/// Returns an `mpsc::Sender` that callers use to enqueue mutations.
///
/// The actor processes one command at a time, preventing `SQLITE_BUSY` errors
/// under high write concurrency.
pub fn spawn_db_actor(pool: SqlitePool) -> mpsc::Sender<DbCommand> {
    let (tx, mut rx) = mpsc::channel::<DbCommand>(512);

    tokio::spawn(async move {
        while let Some(cmd) = rx.recv().await {
            if let Err(e) = handle_command(&pool, cmd).await {
                error!(error = %e, "DB actor command failed");
            }
        }
        warn!("DB actor channel closed — shutting down.");
    });

    tx
}

async fn handle_command(pool: &SqlitePool, cmd: DbCommand) -> Result<()> {
    let now = Utc::now().to_rfc3339();

    match cmd {
        DbCommand::CreateUser {
            id,
            email,
            password_hash,
            role,
        } => {
            let id_str = id.to_string();
            sqlx::query!(
                r#"INSERT INTO users (id, email, password_hash, role, created_at)
                   VALUES (?1, ?2, ?3, ?4, ?5)"#,
                id_str,
                email,
                password_hash,
                role,
                now
            )
            .execute(pool)
            .await?;
        }

        DbCommand::SetUserTeam { user_id, team_id } => {
            let user_id_str = user_id.to_string();
            let team_id_str = team_id.to_string();
            sqlx::query!(
                "UPDATE users SET team_id = ?1 WHERE id = ?2",
                team_id_str,
                user_id_str
            )
            .execute(pool)
            .await?;
        }

        DbCommand::CreateTeam {
            id,
            name,
            join_code,
            password_hash,
        } => {
            let id_str = id.to_string();
            sqlx::query!(
                r#"INSERT INTO teams (id, name, join_code, password_hash, created_at)
                   VALUES (?1, ?2, ?3, ?4, ?5)"#,
                id_str,
                name,
                join_code,
                password_hash,
                now
            )
            .execute(pool)
            .await?;
        }

        DbCommand::RecordSolve {
            team_id,
            level_id,
            points,
        } => {
            let team_id_str = team_id.to_string();
            let points_i64 = points as i64;

            // Insert the solve record and atomically update team score.
            sqlx::query!(
                r#"INSERT OR IGNORE INTO solves (team_id, level_id, timestamp)
                   VALUES (?1, ?2, ?3)"#,
                team_id_str,
                level_id,
                now
            )
            .execute(pool)
            .await?;

            // Update score only if the row was newly inserted.
            // We check by looking up the specific solve with this exact timestamp.
            sqlx::query!(
                "UPDATE teams SET score = score + ?1 WHERE id = ?2 AND \
                 EXISTS (SELECT 1 FROM solves WHERE team_id = ?2 AND level_id = ?3 AND timestamp = ?4)",
                points_i64,
                team_id_str,
                level_id,
                now
            )
            .execute(pool)
            .await?;
        }

        DbCommand::WriteAuditLog {
            team_id,
            user_id,
            action,
        } => {
            let team_id_str = team_id.map(|u| u.to_string());
            let user_id_str = user_id.map(|u| u.to_string());
            sqlx::query!(
                r#"INSERT INTO audit_log (team_id, user_id, action, timestamp)
                   VALUES (?1, ?2, ?3, ?4)"#,
                team_id_str,
                user_id_str,
                action,
                now
            )
            .execute(pool)
            .await?;
        }

        DbCommand::UpsertAdmin {
            id,
            email,
            password_hash,
        } => {
            let id_str = id.to_string();
            sqlx::query!(
                r#"INSERT INTO users (id, email, password_hash, role, created_at)
                   VALUES (?1, ?2, ?3, 'admin', ?4)
                   ON CONFLICT(email) DO UPDATE SET role = 'admin', password_hash = ?3"#,
                id_str,
                email,
                password_hash,
                now
            )
            .execute(pool)
            .await?;
        }
    }

    Ok(())
}

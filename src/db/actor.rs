use anyhow::Result;
use chrono::Utc;
use sqlx::SqlitePool;
use tokio::sync::{mpsc, oneshot};
use tracing::{error, warn};
use uuid::Uuid;

use crate::error::AppError;

pub enum DbCommand {
    CreateUser {
        id: Uuid,
        email: String,
        password_hash: String,
        role: String,
        result_tx: oneshot::Sender<Result<(), AppError>>,
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
        first_blood_tx: oneshot::Sender<Result<bool, AppError>>,
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
            result_tx,
        } => {
            let id_str = id.to_string();
            let res = sqlx::query!(
                r#"INSERT INTO users (id, email, password_hash, role, created_at)
                   VALUES (?1, ?2, ?3, ?4, ?5)"#,
                id_str,
                email,
                password_hash,
                role,
                now
            )
            .execute(pool)
            .await;

            let final_res = match res {
                Ok(_) => Ok(()),
                Err(e) => {
                    if e.to_string().contains("UNIQUE constraint failed") {
                        Err(AppError::Conflict("Email already registered.".into()))
                    } else {
                        Err(AppError::Database(e))
                    }
                }
            };
            let _ = result_tx.send(final_res);
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
            first_blood_tx,
        } => {
            let team_id_str = team_id.to_string();
            let points_i64 = points as i64;

            let existing = sqlx::query!(
                "SELECT 1 as e FROM solves WHERE team_id = ?1 AND level_id = ?2",
                team_id_str, level_id
            ).fetch_optional(pool).await;

            match existing {
                Ok(Some(_)) => {
                    let _ = first_blood_tx.send(Ok(false));
                }
                Err(e) => {
                    let _ = first_blood_tx.send(Err(AppError::Database(e)));
                }
                Ok(None) => {
                    let prior = sqlx::query!(
                        "SELECT COUNT(*) as cnt FROM solves WHERE level_id = ?1",
                        level_id
                    ).fetch_one(pool).await;

                    match prior {
                        Ok(prior_row) => {
                            let insert_res = sqlx::query!(
                                "INSERT INTO solves (team_id, level_id, timestamp) VALUES (?1, ?2, ?3)",
                                team_id_str, level_id, now
                            ).execute(pool).await;

                            match insert_res {
                                Ok(_) => {
                                    let update_res = sqlx::query!(
                                        "UPDATE teams SET score = score + ?1 WHERE id = ?2",
                                        points_i64, team_id_str
                                    ).execute(pool).await;

                                    if let Err(e) = update_res {
                                        let _ = first_blood_tx.send(Err(AppError::Database(e)));
                                    } else {
                                        let _ = first_blood_tx.send(Ok(prior_row.cnt == 0));
                                    }
                                }
                                Err(e) => {
                                    let _ = first_blood_tx.send(Err(AppError::Database(e)));
                                }
                            }
                        }
                        Err(e) => {
                            let _ = first_blood_tx.send(Err(AppError::Database(e)));
                        }
                    }
                }
            }
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

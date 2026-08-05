use axum::{Json, extract::State, response::IntoResponse};
use serde::{Deserialize, Serialize};
use tokio::sync::oneshot;
use uuid::Uuid;

use crate::{
    api::extractors::AuthUser,
    bot::event_bus::DiscordEvent,
    config::LevelConfig,
    db::{
        actor::DbCommand,
        queries::get_team_solves,
    },
    domain::{
        dag::{EvalContext, evaluate_condition},
        dynamic_flag::verify_dynamic_flag,
        normalization::normalize_answer,
    },
    error::AppError,
    state::AppState,
};

#[derive(Deserialize)]
pub struct SubmitRequest {
    pub level_id: String,
    pub answer: String,
}

#[derive(Serialize)]
pub struct SubmitResponse {
    pub correct: bool,
    pub first_blood: bool,
    pub points_awarded: u32,
    pub message: String,
}

pub async fn submit(
    State(state): State<AppState>,
    AuthUser(claims): AuthUser,
    Json(body): Json<SubmitRequest>,
) -> Result<impl IntoResponse, AppError> {
    if body.answer.len() > 1024 || body.level_id.len() > 128 {
        return Err(AppError::BadRequest("Payload too large".into()));
    }

    let team_id = claims
        .team_id
        .ok_or_else(|| AppError::BadRequest("You must join a team before submitting.".into()))?;

    let level = state
        .hunt
        .levels
        .iter()
        .find(|l| l.id == body.level_id)
        .ok_or(AppError::NotFound)?
        .clone();

    let solved_rows = get_team_solves(&state.read_pool, team_id).await?;
    let solved_ids: std::collections::HashSet<String> =
        solved_rows.iter().map(|r| r.level_id.clone()).collect();

    let team_id_str = team_id.to_string();
    let team_score = {
        let row = sqlx::query!("SELECT score FROM teams WHERE id = ?1", team_id_str)
            .fetch_optional(&state.read_pool)
            .await?;
        row.map(|r| r.score as u64).unwrap_or(0)
    };

    let ctx = EvalContext {
        solved: solved_ids.clone(),
        score: team_score,
    };

    if !evaluate_condition(&level.unlock_condition, &ctx) {
        return Err(AppError::Forbidden);
    }

    if solved_ids.contains(&level.id) {
        return Ok(Json(SubmitResponse {
            correct: false,
            first_blood: false,
            points_awarded: 0,
            message: "Your team has already solved this level.".into(),
        }));
    }

    let correct = check_answer(&level, team_id, &body.answer, &state.server_secret);

    if !correct {
        let _ = state
            .db_tx
            .send(DbCommand::WriteAuditLog {
                team_id: Some(team_id),
                user_id: Some(claims.user_id),
                action: format!("invalid_flag_submission:{}", body.level_id),
            })
            .await;

        return Ok(Json(SubmitResponse {
            correct: false,
            first_blood: false,
            points_awarded: 0,
            message: "Incorrect answer. Try again.".into(),
        }));
    }

    let (first_blood_tx, first_blood_rx) = oneshot::channel();
    
    state
        .db_tx
        .send(DbCommand::RecordSolve {
            team_id,
            level_id: level.id.clone(),
            points: level.points,
            first_blood_tx,
        })
        .await
        .map_err(|e| AppError::Internal(e.into()))?;

    let first_blood = match first_blood_rx.await {
        Ok(Ok(fb)) => fb,
        Ok(Err(e)) => return Err(e),
        Err(_) => return Err(AppError::Internal(anyhow::anyhow!("DB actor dropped"))),
    };

    if first_blood {
        let _ = state
            .discord_tx
            .send(DiscordEvent::FirstBlood {
                team_id,
                level_id: level.id.clone(),
                points: level.points,
            })
            .await;
    }

    Ok(Json(SubmitResponse {
        correct: true,
        first_blood,
        points_awarded: level.points,
        message: format!("Correct! +{} points.", level.points),
    }))
}

fn check_answer(level: &LevelConfig, team_id: Uuid, submission: &str, secret: &[u8]) -> bool {
    if level.dynamic_flag {
        return verify_dynamic_flag(secret, &level.id, team_id, submission.trim());
    }

    let normalized_submission = normalize_answer(submission);
    level
        .answers
        .iter()
        .any(|a| normalize_answer(a) == normalized_submission)
}

use axum::{Json, extract::{ConnectInfo, State}, response::IntoResponse};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use subtle::ConstantTimeEq;
use tokio::sync::oneshot;
use uuid::Uuid;

use crate::{
    api::extractors::AuthUser,
    bot::event_bus::DiscordEvent,
    config::{LevelConfig, compute_decayed_points},
    db::{
        actor::DbCommand,
        queries::{get_team_solves, get_solve_count_for_level},
    },
    domain::{
        dag::{EvalContext, evaluate_condition},
        dynamic_flag::verify_dynamic_flag,
        normalization::normalize_answer,
    },
    error::AppError,
    state::AppState,
    toasts::ToastTrigger,
};

/// Canary strings: any submission matching these triggers an anti-cheat flag.
/// These values are intentionally visible at binary analysis level as decoys.
const CANARY_FLAGS: &[&str] = &[
    "flag{unintended_ai_hallucination}",
    "flag{lfi_honeypot_triggered}",
    "flag{canary_do_not_submit}",
];

#[derive(Deserialize)]
pub struct SubmitRequest {
    pub level_id: String,
    pub answer: String,
}

#[derive(Serialize)]
pub struct SubmitResponse {
    pub status: String,
    pub message: String,
}

pub async fn submit(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
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

    // Canary check before any other logic; queues a background flag write.
    let normalized_submission = normalize_answer(&body.answer);
    for canary in CANARY_FLAGS {
        let canary_norm = normalize_answer(canary);
        if bool::from(normalized_submission.as_bytes().ct_eq(canary_norm.as_bytes()))
            || body.answer.trim().eq_ignore_ascii_case(canary)
        {
            let canary_tx = state.db_tx.clone();
            tokio::spawn(async move {
                let _ = canary_tx.send(DbCommand::FlagCanary { team_id }).await;
            });
            return Ok(Json(SubmitResponse {
                status: "canary_triggered".into(),
                message: state.toasts.get(ToastTrigger::CanaryTriggered),
            }));
        }
    }

    // Also check hunt.json-configured canary flags.
    for canary in &state.hunt.canary_flags {
        if body.answer.trim().eq_ignore_ascii_case(canary) {
            let canary_tx = state.db_tx.clone();
            tokio::spawn(async move {
                let _ = canary_tx.send(DbCommand::FlagCanary { team_id }).await;
            });
            return Ok(Json(SubmitResponse {
                status: "canary_triggered".into(),
                message: state.toasts.get(ToastTrigger::CanaryTriggered),
            }));
        }
    }

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

    // Score for DAG condition evaluation. Inline aggregate avoids sqlx nullability issues with views.
    let team_id_str = team_id.to_string();
    let team_score = sqlx::query!(
        r#"SELECT CAST(COALESCE(SUM(points_at_solve), 0) AS INTEGER) as "score!: i64"
           FROM solves WHERE team_id = ?1"#,
        team_id_str
    )
    .fetch_one(&state.read_pool)
    .await?
    .score as u64;

    let ctx = EvalContext {
        solved: solved_ids.clone(),
        score: team_score,
    };

    if !evaluate_condition(&level.unlock_condition, &ctx) {
        return Err(AppError::Forbidden);
    }

    if solved_ids.contains(&level.id) {
        return Ok(Json(SubmitResponse {
            status: "already_solved".into(),
            message: "Your team has already solved this level.".into(),
        }));
    }

    // Compute decayed point value before any I/O commits.
    let solve_count = get_solve_count_for_level(&state.read_pool, &level.id).await?;
    let decayed_points = compute_decayed_points(&level, solve_count);

    let answer_result = check_answer(&level, team_id, &body.answer, &state.server_secret);

    match answer_result {
        AnswerResult::Correct => {}
        AnswerResult::NearMiss => {
            let _ = state
                .db_tx
                .send(DbCommand::WriteAuditLog {
                    team_id: Some(team_id),
                    user_id: Some(claims.user_id),
                    action: format!("near_miss:{}", body.level_id),
                })
                .await;
            return Ok(Json(SubmitResponse {
                status: "near_miss".into(),
                message: state.toasts.get(ToastTrigger::NearMiss),
            }));
        }
        AnswerResult::Incorrect => {
            let _ = state
                .db_tx
                .send(DbCommand::WriteAuditLog {
                    team_id: Some(team_id),
                    user_id: Some(claims.user_id),
                    action: format!("invalid_flag_submission:{}", body.level_id),
                })
                .await;
            return Ok(Json(SubmitResponse {
                status: "incorrect".into(),
                message: state.toasts.get(ToastTrigger::WrongFlag),
            }));
        }
    }

    let (first_blood_tx, first_blood_rx) = oneshot::channel();
    let ip_address = Some(addr.ip().to_string());
    let correct_message = state.toasts.get(ToastTrigger::CorrectFlag);

    tokio::spawn(async move {
        if let Err(e) = state.db_tx.send(DbCommand::RecordSolve {
            team_id,
            level_id: level.id.clone(),
            points: decayed_points,
            ip_address,
            first_blood_tx,
        }).await {
            tracing::error!("Failed to record solve: {}", e);
            return;
        }

        match first_blood_rx.await {
            Ok(Ok(true)) => {
                let _ = state.discord_tx.send(DiscordEvent::FirstBlood {
                    team_id,
                    level_id: level.id.clone(),
                    points: decayed_points,
                }).await;
            }
            Ok(Err(e)) => tracing::error!("Database error during solve: {}", e),
            Err(e) => tracing::error!("First blood channel dropped: {}", e),
            _ => {}
        }
    });

    Ok(Json(SubmitResponse {
        status: "correct".into(),
        message: correct_message,
    }))
}

enum AnswerResult {
    Correct,
    NearMiss,
    Incorrect,
}

fn check_answer(level: &LevelConfig, team_id: Uuid, submission: &str, secret: &[u8]) -> AnswerResult {
    if level.dynamic_flag {
        return if verify_dynamic_flag(secret, &level.id, team_id, submission.trim()) {
            AnswerResult::Correct
        } else {
            // Near-miss is not applicable to HMAC-derived dynamic flags.
            AnswerResult::Incorrect
        };
    }

    let norm_sub = normalize_answer(submission);

    for answer in &level.answers {
        let norm_ans = normalize_answer(answer);

        // Constant-time exact match.
        if bool::from(norm_sub.as_bytes().ct_eq(norm_ans.as_bytes())) {
            return AnswerResult::Correct;
        }

        // Case-insensitive match (e.g., "FLAG" vs "flag").
        if norm_sub.eq_ignore_ascii_case(&norm_ans) {
            return AnswerResult::NearMiss;
        }

        // Damerau-Levenshtein: threshold scales with flag length.
        let threshold = if norm_ans.len() > 20 { 2 } else { 1 };
        let dist = strsim::damerau_levenshtein(&norm_sub, &norm_ans);
        if dist <= threshold {
            return AnswerResult::NearMiss;
        }
    }

    AnswerResult::Incorrect
}

use std::time::Duration;

use tokio::sync::mpsc;
use tracing::{error, info, warn};
use uuid::Uuid;

/// Events that can be pushed onto the Discord event bus.
/// Each variant contains all data needed to compose and send the notification.
#[derive(Debug, Clone)]
pub enum DiscordEvent {
    FirstBlood {
        team_id: Uuid,
        level_id: String,
        points: u32,
    },
    HintDropped {
        level_id: String,
        hint_text: String,
    },
    TeamRegistered {
        team_name: String,
    },
}

/// Spawns the async Discord event bus worker as a background Tokio task.
///
/// Returns an `mpsc::Sender` for pushing events from API handlers.
/// The API handler returns an instant HTTP 200; this worker processes
/// the event in the background with exponential retry backoff.
pub fn spawn_event_bus(
    http: std::sync::Arc<serenity::http::Http>,
    channel_id: u64,
) -> mpsc::Sender<DiscordEvent> {
    let (tx, mut rx) = mpsc::channel::<DiscordEvent>(1000);

    tokio::spawn(async move {
        while let Some(event) = rx.recv().await {
            let message = format_event(&event);
            send_with_retry(&http, channel_id, &message).await;
        }
        warn!("Discord event bus channel closed.");
    });

    tx
}

fn format_event(event: &DiscordEvent) -> String {
    match event {
        DiscordEvent::FirstBlood {
            team_id,
            level_id,
            points,
        } => format!(
            "🩸 **First Blood!** Team `{}` just solved **{}** for **{}** points!",
            team_id, level_id, points
        ),
        DiscordEvent::HintDropped {
            level_id,
            hint_text,
        } => format!("💡 **Hint for {}:** {}", level_id, hint_text),
        DiscordEvent::TeamRegistered { team_name } => {
            format!("🎉 New team registered: **{}**", team_name)
        }
    }
}

/// Sends a message to a Discord channel with exponential retry backoff.
/// Backs off on HTTP 429 (rate limit) or transient network errors.
/// Gives up after 5 attempts.
async fn send_with_retry(http: &serenity::http::Http, channel_id: u64, message: &str) {
    let channel = serenity::model::id::ChannelId::new(channel_id);
    let mut delay = Duration::from_millis(500);
    const MAX_RETRIES: u32 = 5;

    for attempt in 1..=MAX_RETRIES {
        match channel
            .say(http, message)
            .await
        {
            Ok(_) => {
                info!("Discord event sent successfully on attempt {attempt}.");
                return;
            }
            Err(e) => {
                error!(
                    attempt,
                    error = %e,
                    "Failed to send Discord event. Retrying in {:?}...", delay
                );
                tokio::time::sleep(delay).await;
                delay *= 2; // Exponential backoff
            }
        }
    }

    error!("Discord event dropped after {MAX_RETRIES} failed attempts.");
}

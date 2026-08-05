pub mod event_bus;

use poise::serenity_prelude as serenity;
use sqlx::SqlitePool;

use crate::db::queries::get_leaderboard;


/// Data shared with every poise command context.
pub struct BotData {
    pub read_pool: SqlitePool,
}

type Error = Box<dyn std::error::Error + Send + Sync>;
type Context<'a> = poise::Context<'a, BotData, Error>;

// ─── Slash Commands ───────────────────────────────────────────────────────────

/// Shows the top 10 teams and their scores.
#[poise::command(slash_command)]
pub async fn leaderboard(ctx: Context<'_>) -> Result<(), Error> {
    let teams = get_leaderboard(&ctx.data().read_pool, 10, None).await?;

    if teams.is_empty() {
        ctx.say("No teams have scored yet!").await?;
        return Ok(());
    }

    let mut board = String::from("🏆 **Leaderboard** (Top 10)\n```\n");
    for (i, team) in teams.iter().enumerate() {
        board.push_str(&format!("{:>2}. {:20} {:>6} pts\n", i + 1, team.name, team.score));
    }
    board.push_str("```");

    ctx.say(board).await?;
    Ok(())
}

/// Shows the calling user's team rank and solved levels.
#[poise::command(slash_command)]
pub async fn status(ctx: Context<'_>) -> Result<(), Error> {
    // In a real deployment, you'd map the Discord user ID to a Venandi team ID
    // via a stored mapping. This is a placeholder that prompts the user.
    ctx.say(
        "ℹ️ Use the `/status` command after linking your Discord account to a Venandi team \
         via the event portal.",
    )
    .await?;
    Ok(())
}

/// Returns globally available hints for a specific level.
#[poise::command(slash_command)]
pub async fn hint(
    ctx: Context<'_>,
    #[description = "The level ID to check for hints (e.g., lvl_1)"] level_id: String,
) -> Result<(), Error> {
    // Hints are not yet modelled in the schema — this returns a friendly placeholder.
    // Extend by adding a `hints` table and populating it from hunt.json.
    ctx.say(format!(
        "💡 No globally unlocked hints for **{}** yet. Keep trying!",
        level_id
    ))
    .await?;
    Ok(())
}

// ─── Bot Initializer ──────────────────────────────────────────────────────────

/// Builds and starts the Poise Discord bot.
/// This runs indefinitely as a concurrent Tokio task alongside the Axum server.
pub async fn start_bot(token: String, read_pool: SqlitePool) -> Result<(), Error> {
    let framework = poise::Framework::builder()
        .options(poise::FrameworkOptions {
            commands: vec![leaderboard(), status(), hint()],
            ..Default::default()
        })
        .setup(|ctx, _ready, framework| {
            Box::pin(async move {
                poise::builtins::register_globally(ctx, &framework.options().commands).await?;
                tracing::info!("Discord bot ready and slash commands registered.");
                Ok(BotData { read_pool })
            })
        })
        .build();

    let intents = serenity::GatewayIntents::non_privileged();
    let mut client = serenity::ClientBuilder::new(&token, intents)
        .framework(framework)
        .await?;

    client.start().await?;
    Ok(())
}

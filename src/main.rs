mod api;
mod bot;
mod config;
mod db;
mod domain;
mod error;
mod state;

use std::{
    collections::HashSet,
    net::SocketAddr,
    sync::{Arc, RwLock},
};

use argon2::{
    Argon2,
    password_hash::{PasswordHasher, SaltString, rand_core::OsRng},
};
use axum::{
    Router,
    routing::{get, post},
};
use dashmap::DashMap;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use tower_http::trace::TraceLayer;
use tracing::info;
use tracing_subscriber::EnvFilter;
use uuid::Uuid;

use crate::{
    api::{auth, submit, ws},
    bot::{event_bus::spawn_event_bus, start_bot},
    config::HuntConfig,
    db::actor::spawn_db_actor,
    domain::dag::validate_dag_or_panic,
    state::AppState,
};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // ── 1. Load .env ──────────────────────────────────────────────────────────
    dotenvy::dotenv().ok();

    // ── 2. Initialize structured logging ─────────────────────────────────────
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("venandi=info".parse()?))
        .init();

    info!("╔════════════════════════════════════╗");
    info!("║      Venandi v3.1 Booting...       ║");
    info!("╚════════════════════════════════════╝");

    // ── 3. Parse hunt.json ────────────────────────────────────────────────────
    let hunt_json = std::fs::read_to_string("config/hunt.json")
        .expect("Failed to read config/hunt.json");
    let hunt: HuntConfig =
        serde_json::from_str(&hunt_json).expect("Failed to parse config/hunt.json");

    info!("Hunt config loaded: '{}' ({} levels)", hunt.event.name, hunt.levels.len());

    // ── 4. DAG Validation — panics and halts boot if a cycle is detected ──────
    validate_dag_or_panic(&hunt.levels);

    // ── 5. Open SQLite pool (WAL mode, busy_timeout = 5000ms) ────────────────
    let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");

    let pool_options = SqlitePoolOptions::new().max_connections(16);
    let connect_options: SqliteConnectOptions = database_url
        .parse::<SqliteConnectOptions>()?
        .create_if_missing(true)
        .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal)
        .busy_timeout(std::time::Duration::from_millis(5000));

    let pool = pool_options.connect_with(connect_options).await?;

    // ── 6. Apply migrations ───────────────────────────────────────────────────
    sqlx::migrate!("./migrations").run(&pool).await?;
    info!("Database migrations applied.");

    // ── 7. Admin bootstrap upsert ─────────────────────────────────────────────
    if let (Ok(admin_email), Ok(admin_password)) = (
        std::env::var("VENANDI_INITIAL_ADMIN_EMAIL"),
        std::env::var("VENANDI_INITIAL_ADMIN_PASSWORD"),
    ) {
        info!("Bootstrapping admin account for: {}", admin_email);

        let password_hash = tokio::task::spawn_blocking(move || {
            let salt = SaltString::generate(&mut OsRng);
            Argon2::default()
                .hash_password(admin_password.as_bytes(), &salt)
                .map(|h| h.to_string())
        })
        .await
        .map_err(|e| anyhow::anyhow!("spawn_blocking join error: {e}"))?
        .map_err(|e| anyhow::anyhow!("Argon2 hashing error: {e}"))?;

        let admin_id = Uuid::new_v4().to_string();
        sqlx::query!(
            r#"INSERT INTO users (id, email, password_hash, role, created_at)
               VALUES (?1, ?2, ?3, 'admin', datetime('now'))
               ON CONFLICT(email) DO UPDATE SET role = 'admin', password_hash = ?3"#,
            admin_id,
            admin_email,
            password_hash
        )
        .execute(&pool)
        .await?;

        info!("Admin account provisioned.");
    }

    // ── 8. Spawn single-writer DB actor ───────────────────────────────────────
    let db_tx = spawn_db_actor(pool.clone());

    // ── 9. Build AppState ─────────────────────────────────────────────────────
    let jwt_secret = std::env::var("VENANDI_JWT_SECRET").expect("VENANDI_JWT_SECRET must be set");
    let server_secret = std::env::var("VENANDI_SERVER_SECRET")
        .expect("VENANDI_SERVER_SECRET must be set");

    let allowed_origins: HashSet<String> = std::env::var("VENANDI_ALLOWED_ORIGINS")
        .unwrap_or_default()
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    info!("Allowed WebSocket origins: {:?}", allowed_origins);

    // ── 10. Spawn Discord event bus ───────────────────────────────────────────
    let discord_token = std::env::var("VENANDI_DISCORD_TOKEN")
        .expect("VENANDI_DISCORD_TOKEN must be set");

    // Build a Serenity HTTP client for outbound messages (event bus).
    let http = Arc::new(serenity::http::Http::new(&discord_token));

    // Use a placeholder channel ID — extend via env var as needed.
    let discord_channel_id: u64 = std::env::var("VENANDI_DISCORD_CHANNEL_ID")
        .unwrap_or_default()
        .parse()
        .unwrap_or(0);

    let discord_tx = spawn_event_bus(http, discord_channel_id);

    let state = AppState {
        read_pool: pool.clone(),
        db_tx,
        discord_tx,
        ws_tickets: Arc::new(DashMap::new()),
        revoked_teams: Arc::new(RwLock::new(HashSet::new())),
        hunt: Arc::new(hunt),
        server_secret: Arc::new(server_secret.into_bytes()),
        jwt_secret: Arc::new(jwt_secret),
        allowed_origins: Arc::new(allowed_origins),
    };

    // ── 11. Build Axum router ─────────────────────────────────────────────────
    let app = Router::new()
        // Auth routes (IP-based rate limiting applied via middleware)
        .route("/api/auth/register", post(auth::register))
        .route("/api/auth/login", post(auth::login))
        .route("/api/auth/logout", post(auth::logout))
        // Submission (TeamId-based rate limiting)
        .route("/api/submit", post(submit::submit))
        // WebSocket
        .route("/api/ws/ticket", post(ws::issue_ticket))
        .route("/ws", get(ws::ws_handler))
        // Static file server
        .nest_service("/static", tower_http::services::ServeDir::new("static"))
        .layer(TraceLayer::new_for_http())
        .with_state(state.clone());

    // ── 12. Concurrently start Axum + Discord bot ─────────────────────────────
    let bind_addr: SocketAddr = std::env::var("VENANDI_BIND_ADDR")
        .unwrap_or_else(|_| "0.0.0.0:3000".into())
        .parse()?;

    info!("Axum listening on {}", bind_addr);

    let axum_task = async {
        let listener = tokio::net::TcpListener::bind(bind_addr).await?;
        axum::serve(listener, app).await?;
        Ok::<_, anyhow::Error>(())
    };

    let bot_task = async {
        start_bot(discord_token, pool)
            .await
            .map_err(|e| anyhow::anyhow!("Discord bot error: {e}"))?;
        Ok::<_, anyhow::Error>(())
    };

    tokio::try_join!(axum_task, bot_task)?;

    Ok(())
}

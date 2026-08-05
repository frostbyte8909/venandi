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
    num::NonZeroU32,
    time::Duration,
};

use argon2::{
    Argon2,
    password_hash::{PasswordHasher, SaltString, rand_core::OsRng},
};
use axum::{
    Router,
    extract::DefaultBodyLimit,
    routing::{get, post},
};
use axum_governor::{GovernorConfigBuilder, GovernorLayer, extractor::PeerIp, Quota};
use dashmap::DashMap;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use tokio::time;
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
    dotenvy::dotenv().ok();

    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("venandi=info".parse()?))
        .init();

    info!("╔════════════════════════════════════╗");
    let version = env!("CARGO_PKG_VERSION");
    info!("║      Venandi v{:<19}║", version);
    info!("╚════════════════════════════════════╝");

    let hunt_json = std::fs::read_to_string("config/hunt.json")
        .expect("Failed to read config/hunt.json");
    let hunt: HuntConfig =
        serde_json::from_str(&hunt_json).expect("Failed to parse config/hunt.json");

    info!("Hunt config loaded: '{}' ({} levels)", hunt.event.name, hunt.levels.len());

    validate_dag_or_panic(&hunt.levels);

    let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");

    let pool_options = SqlitePoolOptions::new().max_connections(16);
    let connect_options: SqliteConnectOptions = database_url
        .parse::<SqliteConnectOptions>()?
        .create_if_missing(true)
        .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal)
        .busy_timeout(Duration::from_millis(5000));

    let pool = pool_options.connect_with(connect_options).await?;

    sqlx::migrate!("./migrations").run(&pool).await?;
    info!("Database migrations applied.");

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

    let db_tx = spawn_db_actor(pool.clone());

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

    let discord_token = std::env::var("VENANDI_DISCORD_TOKEN")
        .expect("VENANDI_DISCORD_TOKEN must be set");

    let http = Arc::new(serenity::http::Http::new(&discord_token));
    let discord_channel_id: u64 = std::env::var("VENANDI_DISCORD_CHANNEL_ID")
        .unwrap_or_default()
        .parse()
        .unwrap_or(0);

    let discord_tx = spawn_event_bus(http, discord_channel_id);

    let pool_clone = pool.clone();
    tokio::spawn(async move {
        if let Err(e) = start_bot(discord_token, pool_clone).await {
            tracing::error!("Discord bot crashed: {e}");
        }
    });

    let ws_tickets = Arc::new(DashMap::new());

    let state = AppState {
        read_pool: pool,
        db_tx,
        discord_tx,
        ws_tickets: ws_tickets.clone(),
        revoked_teams: Arc::new(RwLock::new(HashSet::new())),
        hunt: Arc::new(hunt),
        server_secret: Arc::new(server_secret.into_bytes()),
        jwt_secret: Arc::new(jwt_secret),
        allowed_origins: Arc::new(allowed_origins),
    };

    tokio::spawn(async move {
        let mut interval = time::interval(Duration::from_secs(10));
        loop {
            interval.tick().await;
            let now = std::time::Instant::now();
            ws_tickets.retain(|_, ticket| ticket.expires_at > now);
        }
    });

    let auth_quota = Quota::per_minute(NonZeroU32::new(5).unwrap());
    let auth_governor_conf = GovernorConfigBuilder::default()
        .with_extractor(PeerIp::default())
        .expect_connect_info()
        .quota_default(auth_quota)
        .finish()
        .unwrap();

    let submit_quota = Quota::per_second(NonZeroU32::new(1).unwrap())
        .allow_burst(NonZeroU32::new(10).unwrap());
    let submit_governor_conf = GovernorConfigBuilder::default()
        .with_extractor(PeerIp::default())
        .expect_connect_info()
        .quota_default(submit_quota)
        .finish()
        .unwrap();

    let auth_routes = Router::new()
        .route("/register", post(auth::register))
        .route("/login", post(auth::login))
        .route("/logout", post(auth::logout))
        .layer(GovernorLayer::new(auth_governor_conf));

    let submit_routes = Router::new()
        .route("/", post(submit::submit))
        .layer(GovernorLayer::new(submit_governor_conf));

    let api_routes = Router::new()
        .nest("/auth", auth_routes)
        .nest("/submit", submit_routes)
        .route("/ws/ticket", post(ws::request_ticket))
        .route("/ws", get(ws::ws_handler));

    let app = Router::new()
        .nest("/api", api_routes)
        .layer(DefaultBodyLimit::max(16_384))
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    let port = std::env::var("PORT").unwrap_or_else(|_| "8080".to_string());
    let addr = format!("0.0.0.0:{}", port)
        .parse::<SocketAddr>()
        .expect("Invalid PORT or bind address");

    info!("Starting server on {}", addr);
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>()
    )
    .await?;

    Ok(())
}

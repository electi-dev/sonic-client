mod config;
mod decryption;
mod encryption;
mod error;
mod external;
mod jobs;
mod kms_decrypt;
mod routes;
mod session;
mod state;

use axum::{
    routing::{get, post},
    Router,
};
use tower_http::cors::{Any, CorsLayer};
use tower_http::trace::TraceLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use crate::{config::AppConfig, state::AppState};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "info".into()),
        ))
        .with(tracing_subscriber::fmt::layer())
        .init();

    let config_path = std::env::var("CONFIG_PATH").unwrap_or_else(|_| "config.toml".into());
    let config: AppConfig = {
        let s = std::fs::read_to_string(&config_path)
            .unwrap_or_else(|_| panic!("cannot read config file: {config_path}"));
        toml::from_str(&s)?
    };

    std::fs::create_dir_all(&config.data_dir)?;
    let bind_addr = config.bind_addr.clone();
    let state = AppState::new(config);

    let app = Router::new()
        .route("/api/auth/register", post(routes::auth::register))
        .route("/api/auth/login", post(routes::auth::login))
        .route("/api/auth/logout", post(routes::auth::logout))
        .route("/api/jobs/usecase1", post(routes::jobs::submit_usecase1))
        .route("/api/jobs/usecase2", post(routes::jobs::submit_usecase2))
        .route("/api/jobs/usecase3", post(routes::jobs::submit_usecase3))
        .route("/api/jobs/usecase4", post(routes::jobs::submit_usecase4))
        .route("/api/jobs/{job_id}", get(routes::jobs::get_job))
        .layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_headers(Any)
                .allow_methods(Any),
        )
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    tracing::info!("Backend listening on {bind_addr}");
    let listener = tokio::net::TcpListener::bind(&bind_addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

use std::sync::Arc;

use axum::http::HeaderMap;
use dashmap::DashMap;
use uuid::Uuid;

use crate::{
    config::AppConfig, error::AppError, external::ExternalClient, jobs::JobEntry, session::Session,
};

#[derive(Clone)]
pub struct AppState {
    pub config: AppConfig,
    pub sessions: Arc<DashMap<Uuid, Session>>,
    pub jobs: Arc<DashMap<Uuid, JobEntry>>,
    pub http: reqwest::Client,
}

impl AppState {
    pub fn new(config: AppConfig) -> Self {
        Self {
            config,
            sessions: Arc::new(DashMap::new()),
            jobs: Arc::new(DashMap::new()),
            http: reqwest::Client::new(),
        }
    }

    pub fn external(&self) -> ExternalClient {
        ExternalClient::new(self.config.external_service_url.clone(), self.http.clone())
    }

    /// Returns (and creates) the user's data directory.
    pub fn user_dir(&self, username: &str) -> anyhow::Result<std::path::PathBuf> {
        let dir = self.config.data_dir.join(username);
        std::fs::create_dir_all(&dir)?;
        Ok(dir)
    }

    pub fn client_key_path(&self, username: &str) -> anyhow::Result<std::path::PathBuf> {
        Ok(self.user_dir(username)?.join("client_key.bin"))
    }

    pub fn server_key_path(&self, username: &str) -> anyhow::Result<std::path::PathBuf> {
        Ok(self.user_dir(username)?.join("server_key.bin"))
    }

    /// Extracts and validates the session from the `X-Session-Id` header.
    pub fn session_from_headers(&self, headers: &HeaderMap) -> Result<Session, AppError> {
        let id = headers
            .get("x-session-id")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<Uuid>().ok())
            .ok_or(AppError::Unauthorized)?;
        self.sessions
            .get(&id)
            .map(|s| s.clone())
            .ok_or(AppError::Unauthorized)
    }
}

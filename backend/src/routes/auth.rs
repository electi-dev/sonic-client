use axum::{extract::State, http::HeaderMap, Json};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{encryption, error::AppError, session::Session, state::AppState};

#[derive(Deserialize)]
pub struct AuthBody {
    username: String,
    password: String,
}

#[derive(Serialize)]
pub struct SessionResponse {
    session_id: Uuid,
}

/// Registers with the external service, generates FHE keypair, uploads server key, creates session.
/// The FHE key generation step is CPU-heavy and may take 30–120 seconds with default params.
pub async fn register(
    State(state): State<AppState>,
    Json(body): Json<AuthBody>,
) -> Result<Json<SessionResponse>, AppError> {
    let ext = state.external();

    ext.register(&body.username, &body.password)
        .await
        .map_err(|e| AppError::BadRequest(e.to_string()))?;

    // Immediately login to get the JWT we need for server-key upload
    let jwt = ext
        .login(&body.username, &body.password)
        .await
        .map_err(|e| AppError::BadRequest(e.to_string()))?;

    // Generate FHE keypair on a blocking thread
    let (client_key, server_key_bytes) = tokio::task::spawn_blocking(encryption::generate_fhe_keys)
        .await
        .map_err(|e| anyhow::anyhow!(e))??;

    // Persist client key in the user's folder
    let key_path = state.client_key_path(&body.username)?;
    encryption::save_client_key(&key_path, &client_key)?;

    let key_path = state.server_key_path(&body.username)?;
    std::fs::write(key_path, &server_key_bytes).map_err(|e| {
        tracing::error!("{:?}", e);
        anyhow::anyhow!(e)
    })?;

    // Upload server key to external service
    ext.upload_server_key(&jwt, server_key_bytes)
        .await
        .map_err(|e| AppError::BadRequest(e.to_string()))?;

    let session_id = Uuid::new_v4();
    state.sessions.insert(
        session_id,
        Session {
            username: body.username,
            jwt,
        },
    );

    Ok(Json(SessionResponse { session_id }))
}

pub async fn login(
    State(state): State<AppState>,
    Json(body): Json<AuthBody>,
) -> Result<Json<SessionResponse>, AppError> {
    let jwt = state
        .external()
        .login(&body.username, &body.password)
        .await
        .map_err(|_| AppError::Unauthorized)?;

    // Require that the client key already exists (i.e. user has registered via this backend)
    let key_path = state.client_key_path(&body.username)?;
    if !key_path.exists() {
        return Err(AppError::BadRequest(
            "No local FHE key found. Register via this backend first.".into(),
        ));
    }

    let session_id = Uuid::new_v4();
    state.sessions.insert(
        session_id,
        Session {
            username: body.username,
            jwt,
        },
    );

    Ok(Json(SessionResponse { session_id }))
}

pub async fn logout(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, AppError> {
    let id = headers
        .get("x-session-id")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<Uuid>().ok())
        .ok_or(AppError::Unauthorized)?;
    state.sessions.remove(&id);
    Ok(Json(serde_json::json!({ "message": "logged out" })))
}

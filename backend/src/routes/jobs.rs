use std::{net::Ipv4Addr, str::FromStr};

use axum::{
    extract::{Path, State},
    http::HeaderMap,
    Json,
};
use kms_grpc::KeyId;
use serde::Deserialize;
use tfhe::set_server_key;
use uuid::Uuid;

use crate::{
    decryption, encryption,
    error::AppError,
    jobs::{to_response, JobEntry, JobKind, JobResult, JobStatus, JobStatusResponse},
    state::AppState,
};

// ── Request bodies ────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct Usecase1Body {
    /// IPv4 addresses as strings, max 256
    ips: Vec<String>,
}

#[derive(Deserialize)]
pub struct Usecase2Body {
    /// 32-byte file hash as hex (with or without 0x prefix)
    hash: String,
}

#[derive(serde::Serialize)]
pub struct SubmitResponse {
    job_id: Uuid,
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn save_job_ips(state: &AppState, job_id: Uuid, ips: &[String]) -> anyhow::Result<()> {
    let path = state.config.data_dir.join(format!("job_{job_id}.ips.json"));
    std::fs::write(path, serde_json::to_vec(ips)?)?;
    Ok(())
}

fn load_job_ips(state: &AppState, job_id: Uuid) -> Vec<String> {
    let path = state.config.data_dir.join(format!("job_{job_id}.ips.json"));
    std::fs::read(path)
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default()
}

// ── Handlers ──────────────────────────────────────────────────────────────────

pub async fn submit_usecase1(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<Usecase1Body>,
) -> Result<Json<SubmitResponse>, AppError> {
    let session = state.session_from_headers(&headers)?;

    if body.ips.is_empty() || body.ips.len() > 256 {
        return Err(AppError::BadRequest(
            "ips must contain 1..=256 entries".into(),
        ));
    }

    let ip_u32s: Vec<u32> = body
        .ips
        .iter()
        .map(|ip| {
            Ipv4Addr::from_str(ip.trim())
                .map(u32::from)
                .map_err(|_| AppError::BadRequest(format!("invalid IP: {ip}")))
        })
        .collect::<Result<_, _>>()?;

    let public_key_bytes =
        std::fs::read("../keys.bin").map_err(|e| AppError::Internal(anyhow::anyhow!(e)))?;
    let public_key: tfhe::xof_key_set::CompressedXofKeySet =
        tfhe::safe_serialization::safe_deserialize(public_key_bytes.as_slice(), 1 << 30).unwrap();
    tracing::info!("deserialized server_key");
    let public_key = public_key.decompress().map_err(|e| {
        tracing::error!("decompressing keys.bin: {:?}", e);
        anyhow::anyhow!(e)
    })?;

    let (public_key, server_key) = {
        let parts = public_key.into_raw_parts();
        (parts.0, parts.1)
    };

    let encrypted = tokio::task::spawn_blocking({
        set_server_key(server_key);
        let ip_u32s = ip_u32s.clone();
        move || encryption::encrypt_ips(&ip_u32s, &public_key)
    })
    .await
    .map_err(|e| anyhow::anyhow!(e))??;

    let ext = state.external();
    let ext_job_id = ext.post_job(&session.jwt, "usecase1").await?;
    ext.upload_job_data(&session.jwt, ext_job_id, encrypted)
        .await?;

    let local_job_id = Uuid::new_v4();
    save_job_ips(&state, local_job_id, &body.ips)?;
    state.jobs.insert(
        local_job_id,
        JobEntry {
            username: session.username,
            external_job_id: ext_job_id,
            kind: JobKind::Usecase1 {
                ip_count: body.ips.len(),
            },
            status: JobStatus::Pending,
        },
    );

    Ok(Json(SubmitResponse {
        job_id: local_job_id,
    }))
}

pub async fn submit_usecase2(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<Usecase2Body>,
) -> Result<Json<SubmitResponse>, AppError> {
    let session = state.session_from_headers(&headers)?;

    let hash_str = body.hash.trim().trim_start_matches("0x");
    let hash_bytes =
        hex::decode(hash_str).map_err(|_| AppError::BadRequest("invalid hex hash".into()))?;
    if hash_bytes.len() != 32 {
        return Err(AppError::BadRequest(
            "hash must be exactly 32 bytes (64 hex chars)".into(),
        ));
    }
    let hash_arr: [u8; 32] = hash_bytes.try_into().unwrap();

    let key_path = state.client_key_path(&session.username)?;
    let server_key_path = state.server_key_path(&session.username)?;
    let encrypted = tokio::task::spawn_blocking(move || {
        let ck = encryption::load_client_key(&key_path)?;
        let sk = encryption::load_server_key(&server_key_path)?;
        set_server_key(sk);
        encryption::encrypt_hash(&hash_arr, &ck)
    })
    .await
    .map_err(|e| anyhow::anyhow!(e))??;

    let ext = state.external();
    let ext_job_id = ext.post_job(&session.jwt, "usecase2").await?;
    ext.upload_job_data(&session.jwt, ext_job_id, encrypted)
        .await?;

    let local_job_id = Uuid::new_v4();
    state.jobs.insert(
        local_job_id,
        JobEntry {
            username: session.username,
            external_job_id: ext_job_id,
            kind: JobKind::Usecase2,
            status: JobStatus::Pending,
        },
    );

    Ok(Json(SubmitResponse {
        job_id: local_job_id,
    }))
}

pub fn decode_hex(s: &str) -> Result<Vec<u8>, std::num::ParseIntError> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16))
        .collect()
}
fn parse_key_id(hex: &str) -> anyhow::Result<KeyId> {
    let bytes = decode_hex(hex).map_err(|e| anyhow::anyhow!("invalid key_id hex: {e}"))?;
    anyhow::ensure!(bytes.len() == 32, "key_id must be exactly 32 bytes");
    let arr: [u8; 32] = bytes.try_into().unwrap();
    Ok(KeyId::from_bytes(arr))
}

pub async fn get_job(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(job_id): Path<Uuid>,
) -> Result<Json<JobStatusResponse>, AppError> {
    let session = state.session_from_headers(&headers)?;

    // Fast-path: return cached status for non-pending jobs.
    {
        let entry = state.jobs.get(&job_id).ok_or(AppError::NotFound)?;
        if entry.username != session.username {
            return Err(AppError::Unauthorized);
        }
        match &entry.status {
            JobStatus::Done(r) => {
                return Ok(Json(to_response(job_id, "done", Some(r.clone()), None)))
            }
            JobStatus::Error(e) => {
                return Ok(Json(to_response(job_id, "error", None, Some(e.clone()))))
            }
            JobStatus::Processing => {
                return Ok(Json(to_response(job_id, "processing", None, None)))
            }
            JobStatus::Pending => {}
        }
    }

    // Job is pending — check external service.
    let (ext_job_id, kind) = {
        let e = state.jobs.get(&job_id).ok_or(AppError::NotFound)?;
        (e.external_job_id, e.kind.clone())
    };

    let result_bytes = state
        .external()
        .get_job_result(&session.jwt, ext_job_id)
        .await?;

    let Some(ct_bytes) = result_bytes else {
        return Ok(Json(to_response(job_id, "pending", None, None)));
    };

    // Atomically transition Pending → Processing to prevent duplicate decrypt tasks.
    {
        let mut entry = state.jobs.get_mut(&job_id).ok_or(AppError::NotFound)?;
        entry.status = JobStatus::Processing;
    }

    // Spawn background decryption; update job store when done.
    let state_clone = state.clone();
    let username = session.username.clone();
    let kms_cfg = state.config.kms_config_path.clone();
    let key_id_str = state.config.key_id.clone();

    tokio::spawn(async move {
        let result: anyhow::Result<JobResult> = match kind {
            JobKind::Usecase1 { .. } => {
                let ips = load_job_ips(&state_clone, job_id);
                let Ok(user_dir) = state_clone
                    .user_dir(&username)
                    .inspect_err(|e| tracing::error!("getting user dir: {:?}", e))
                else {
                    return;
                };

                let Ok(key_id) = parse_key_id(key_id_str.as_str())
                    .inspect_err(|e| tracing::error!("parsing key id: {:?}", e))
                else {
                    return;
                };
                decryption::decrypt_usecase1(ct_bytes, kms_cfg, &user_dir, key_id, &ips)
                    .await
                    .map(JobResult::Usecase1)
            }
            JobKind::Usecase2 => {
                let Ok(key_path) = state_clone
                    .client_key_path(&username)
                    .inspect_err(|e| tracing::error!("getting key path: {:?}", e))
                else {
                    return;
                };
                let Ok(server_key_path) = state_clone
                    .server_key_path(&username)
                    .inspect_err(|e| tracing::error!("getting key path: {:?}", e))
                else {
                    return;
                };
                let Ok(result) = tokio::task::spawn_blocking(move || {
                    let ck = encryption::load_client_key(&key_path)?;
                    let sk = encryption::load_server_key(&server_key_path)?;
                    set_server_key(sk);
                    decryption::decrypt_usecase2(&ct_bytes, &ck)
                })
                .await
                .inspect_err(|e| tracing::error!("decrypting spawn: {:?}", e)) else {
                    return;
                };
                let Ok(result) = result.inspect_err(|e| tracing::error!("decrypt: {:?}", e)) else {
                    return;
                };
                Ok(JobResult::Usecase2(result))
            }
        };

        if let Some(mut entry) = state_clone.jobs.get_mut(&job_id) {
            entry.status = match result {
                Ok(r) => JobStatus::Done(r),
                Err(e) => JobStatus::Error(e.to_string()),
            };
        }
    });

    Ok(Json(to_response(job_id, "processing", None, None)))
}

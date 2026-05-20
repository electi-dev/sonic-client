use std::path::PathBuf;
use serde::Deserialize;

#[derive(Deserialize, Clone, Debug)]
pub struct AppConfig {
    pub bind_addr: String,
    pub data_dir: PathBuf,
    pub external_service_url: String,
    /// Path to CoreClientConfig TOML consumed by kms_decrypt::user_decrypt
    pub kms_config_path: String,
    /// Static KMS key ID for usecase1 UserDecrypt
    pub key_id: String,
}

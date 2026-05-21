use tfhe::{prelude::FheDecrypt as _, ClientKey, CompressedFheInt64};

use crate::{encryption, jobs::IpResult};

pub async fn decrypt_usecase1(
    ct_bytes: Vec<u8>,
    kms_config_path: String,
    destination_prefix: &std::path::Path,
    key_id: kms_grpc::KeyId,
    ip_list: &[String],
) -> anyhow::Result<Vec<IpResult>> {
    let plaintext_bytes =
        crate::kms_decrypt::user_decrypt(kms_config_path, destination_prefix, ct_bytes, key_id)
            .await?;

    let results = ip_list
        .iter()
        .enumerate()
        .map(|(i, ip)| {
            let matched = plaintext_bytes
                .get(i / 8)
                .map(|b| (b >> (i % 8)) & 1 == 1)
                .unwrap_or(false);
            IpResult {
                ip: ip.clone(),
                matched,
            }
        })
        .collect();

    Ok(results)
}

/// Usecase2: decrypts the job result with the user's local FHE client key.
/// `ct_bytes` — raw binary returned by the external service (FheBool ciphertext).
pub fn decrypt_usecase2(ct_bytes: &[u8], client_key: &ClientKey) -> anyhow::Result<bool> {
    encryption::decrypt_bool(ct_bytes, client_key)
}

/// Usecase4: decompress and decrypt a CompressedFheUint64 result with the user's client key.
/// Returns the raw u64 value; the caller converts to float for display.
pub fn decrypt_usecase4(ct_bytes: &[u8], client_key: &ClientKey) -> anyhow::Result<i64> {
    let compressed: CompressedFheInt64 =
        tfhe::safe_serialization::safe_deserialize(ct_bytes, 1 << 30).map_err(|e| {
            tracing::error!("error deserilizing: {:?}", e);
            anyhow::anyhow!(e)
        })?;
    let ct = compressed.decompress();
    let value: i64 = ct.decrypt(client_key);
    Ok(value)
}

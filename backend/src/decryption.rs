use tfhe::{
    safe_serialization, set_server_key, ClientKey, CompressedCiphertextListBuilder,
    CompressedFheUint256,
};

use crate::{encryption, jobs::IpResult};

/// Usecase1: decrypts the job result via KMS UserDecrypt.
/// `ct_bytes`  — raw binary returned by the external service (already encrypted under KMS key).
/// `ip_list`   — original IP strings in submission order; used to label the Uint256 bitfield bits.
pub async fn decrypt_usecase1(
    ct_bytes: Vec<u8>,
    kms_config_path: String,
    destination_prefix: &std::path::Path,
    key_id: kms_grpc::KeyId,
    ip_list: &[String],
) -> anyhow::Result<Vec<IpResult>> {
    let public_key_bytes = std::fs::read("../keys.bin").map_err(|e| anyhow::anyhow!(e))?;
    let public_key: tfhe::xof_key_set::CompressedXofKeySet =
        tfhe::safe_serialization::safe_deserialize(public_key_bytes.as_slice(), 1 << 30).unwrap();
    tracing::info!("deserialized server_key");
    let public_key = public_key.decompress().map_err(|e| {
        tracing::error!("decompressing keys.bin: {:?}", e);
        anyhow::anyhow!(e)
    })?;

    let (_, server_key) = {
        let parts = public_key.into_raw_parts();
        (parts.0, parts.1)
    };
    set_server_key(server_key);

    let ct: CompressedFheUint256 =
        safe_serialization::safe_deserialize(ct_bytes.to_vec().as_slice(), 1 << 30)
            .map_err(|e| anyhow::anyhow!(format!("deserializing result: {}", e)))?;
    let ct = ct.decompress();
    let mut builder = CompressedCiphertextListBuilder::new();
    builder.push(ct);
    let compact_list = builder
        .build()
        .expect("Could not build CompressedCiphertextList");

    let mut serialized_ct = Vec::new();
    safe_serialization::safe_serialize(&compact_list, &mut serialized_ct, 1024 * 1024 * 1024)
        .map_err(|e| anyhow::anyhow!(format!("Serializing list: {:?}", e)))?;

    let plaintext_bytes = crate::kms_decrypt::user_decrypt(
        kms_config_path,
        destination_prefix,
        serialized_ct,
        key_id,
    )
    .await?;

    // Interpret the 32-byte (256-bit) little-endian bitfield:
    // bit i == 1  →  IP[i] matched
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

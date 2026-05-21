use anyhow::Context;
use tfhe::{
    generate_keys, ClientKey, CompactCiphertextListBuilder, CompactPublicKey, CompressedFheBool,
    ConfigBuilder, FheBool, FheInt64, FheUint256, FheUint32,
};
use tfhe::{prelude::*, ServerKey};

pub fn generate_fhe_keys() -> anyhow::Result<(ClientKey, Vec<u8>)> {
    let config = ConfigBuilder::default().build();
    let (client_key, server_key) = generate_keys(config);
    let mut server_key_bytes = Vec::new();
    tfhe::safe_serialization::safe_serialize(&server_key, &mut server_key_bytes, 1 << 30)
        .context("serialize client key")?;
    Ok((client_key, server_key_bytes))
}

pub fn save_client_key(path: &std::path::Path, key: &ClientKey) -> anyhow::Result<()> {
    let mut bytes = Vec::new();
    tfhe::safe_serialization::safe_serialize(key, &mut bytes, 1 << 30)
        .context("serialize client key")?;
    std::fs::write(path, bytes)?;
    Ok(())
}

pub fn load_client_key(path: &std::path::Path) -> anyhow::Result<ClientKey> {
    let bytes = std::fs::read(path)?;
    tfhe::safe_serialization::safe_deserialize(bytes.as_slice(), 1 << 30)
        .map_err(|e| anyhow::anyhow!("deserialize client key: {:?}", e))
}

pub fn load_server_key(path: &std::path::Path) -> anyhow::Result<ServerKey> {
    let bytes = std::fs::read(path)?;
    tfhe::safe_serialization::safe_deserialize(bytes.as_slice(), 1 << 30)
        .map_err(|e| anyhow::anyhow!("deserialize server key: {:?}", e))
}

pub fn encrypt_ips(ips: &[u32], public_key: &CompactPublicKey) -> anyhow::Result<Vec<u8>> {
    let mut builder = CompactCiphertextListBuilder::new(&public_key);
    for ip in ips.into_iter() {
        builder
            .push_with_num_bits(*ip, FheUint32::num_bits())
            .unwrap();
    }
    let compact_list = builder.build();

    let mut serialized_ct = Vec::new();
    tfhe::safe_serialization::safe_serialize(
        &compact_list,
        &mut serialized_ct,
        1024 * 1024 * 1024,
    )?;
    Ok(serialized_ct)
}

/// Encrypts a 32-byte file hash as a single FheUint256 ciphertext.
pub fn encrypt_hash(hash_bytes: &[u8; 32], client_key: &ClientKey) -> anyhow::Result<Vec<u8>> {
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&hash_bytes[0..16]);
    let first = u128::from_be_bytes(bytes);
    bytes.copy_from_slice(&hash_bytes[16..]);
    let second = u128::from_be_bytes(bytes);
    // tfhe::integer::U256::from accepts [u64; 4] in tfhe 0.7+
    let value = tfhe::integer::U256::from((second.to_le(), first.to_le()));
    let ct = FheUint256::encrypt(value, client_key);
    let mut serialized_ct = Vec::new();
    tfhe::safe_serialization::safe_serialize(&ct.compress(), &mut serialized_ct, 1 << 30)?;

    Ok(serialized_ct)
}

/// Decrypts a serialised FheBool ciphertext with the user's local client key.
pub fn decrypt_bool(ct_bytes: &[u8], client_key: &ClientKey) -> anyhow::Result<bool> {
    let ct: CompressedFheBool = tfhe::safe_serialization::safe_deserialize(ct_bytes, 1 << 30)
        .map_err(|e| {
            tracing::error!(e);
            anyhow::anyhow!(e)
        })?;
    Ok(ct.decompress().decrypt(client_key))
}

/// Encrypts a list of u64 values as a CompactCiphertextList using a PublicKey
/// derived from the client key (matches the server-side CompactCiphertextListBuilder pattern).
pub fn encrypt_i64_list(values: &[i64], client_key: &ClientKey) -> anyhow::Result<Vec<u8>> {
    use tfhe::{CompactCiphertextListBuilder, CompactPublicKey};

    let public_key = CompactPublicKey::new(client_key);
    let mut builder = CompactCiphertextListBuilder::new(&public_key);
    for &val in values {
        builder
            .push_with_num_bits(val, FheInt64::num_bits())
            .unwrap();
    }
    let compact_list = builder.build();
    let mut buf = Vec::new();
    tfhe::safe_serialization::safe_serialize(&compact_list, &mut buf, 1 << 30)
        .context("serialize CompactCiphertextList")?;
    Ok(buf)
}

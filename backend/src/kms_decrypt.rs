use std::{
    collections::{HashMap, HashSet},
    ops::Deref as _,
    path::Path,
    sync::Arc,
};

use aes_gcm::aead::rand_core::SeedableRng as _;
use aes_prng::AesRng;
use kms_core_client::s3_operations::fetch_global_pub_element_and_write_to_file;
use kms_grpc::{
    kms::v1::{CiphertextFormat, FheParameter, TypedCiphertext, UserDecryptionResponse},
    kms_service::v1::core_service_endpoint_client::CoreServiceEndpointClient,
    rpc_types::{protobuf_to_alloy_domain, PubDataType},
    KeyId, RequestId,
};
use kms_lib::{
    client::{client_wasm::Client, user_decryption_wasm::ParsedUserDecryptionRequest},
    consts::{DEFAULT_PARAM, SIGNING_KEY_ID, TEST_PARAM},
    testing::prelude::FileStorage,
    vault::storage::StorageType,
    DecryptionMode,
};
use observability::conf::Settings;
use serde::{Deserialize, Serialize};
use strum::{Display, EnumString};
use tokio::sync::RwLock;

pub async fn user_decrypt(
    file_conf: String,
    destination_prefix: &Path,
    to_decrypt: Vec<u8>,
    key_id: KeyId,
) -> Result<Vec<u8>, anyhow::Error> {
    let max_iter = 100;

    let mut cc_conf: CoreClientConfig = Settings::builder()
        .path(&file_conf)
        .env_prefix("CORE_CLIENT")
        .build()
        .init_conf()
        .unwrap();

    let known_addresses = cc_conf
        .cores
        .iter()
        .map(|core| core.address.clone())
        .collect::<Vec<String>>();

    let mut inner_cc_conf: CoreClientConfig = Settings::builder()
        .path(&file_conf)
        .env_prefix("CORE_CLIENT")
        .build()
        .init_conf()
        .unwrap();

    inner_cc_conf
        .cores
        .retain(|core| !known_addresses.contains(&core.address));
    cc_conf.cores.extend(inner_cc_conf.cores);

    let mut rng = AesRng::from_entropy();
    let num_parties = cc_conf.cores.len();

    if kms_lib::util::key_setup::ensure_client_keys_exist(
        Some(destination_prefix),
        &SIGNING_KEY_ID,
        true,
    )
    .await
    {
        tracing::info!("Signing keys were cerated at {:?}", destination_prefix);
    }

    let mut pub_storage: HashMap<u32, FileStorage> = HashMap::with_capacity(num_parties);
    let client_storage: FileStorage =
        FileStorage::new(Some(destination_prefix), StorageType::CLIENT, None).unwrap();
    println!("{:?}", client_storage.root_dir());
    let mut internal_client: Option<Client> = None;
    let mut core_endpoints_req = HashMap::with_capacity(num_parties);
    let mut core_endpoints_resp = HashMap::with_capacity(num_parties);

    // use secure default params if nothing is set
    let fhe_params = cc_conf.fhe_params.unwrap_or(FheParameter::Default);
    let client_param = match fhe_params {
        FheParameter::Test => TEST_PARAM,
        _ => DEFAULT_PARAM,
    };

    let public_verf_types = vec![PubDataType::VerfAddress, PubDataType::VerfKey];
    let _ = fetch_public_elements(
        &SIGNING_KEY_ID.to_string(),
        &public_verf_types,
        &cc_conf,
        destination_prefix,
        true, // we always need to download all verification keys
    )
    .await
    .unwrap();

    for cur_core in &cc_conf.cores {
        // make sure address starts with http://
        let url = if cur_core.address.starts_with("http://") {
            cur_core.address.clone()
        } else {
            "http://".to_string() + cur_core.address.as_str()
        };

        let core_endpoint_req = CoreServiceEndpointClient::connect(url.clone())
            .await
            .unwrap();

        // NOTE CANT USE PARTY ID AS KEY CAUSE WE MAY HAVE SEVERAL CORES WITH SAME ID
        // WHEN HAVING MULTIPLE CONTEXTS
        core_endpoints_req.insert(cur_core.clone(), core_endpoint_req);

        let core_endpoint_resp = CoreServiceEndpointClient::connect(url.clone())
            .await
            .unwrap();
        core_endpoints_resp.insert(cur_core.clone(), core_endpoint_resp);

        pub_storage.insert(
            cur_core.party_id as u32,
            FileStorage::new(
                Some(destination_prefix),
                StorageType::PUB,
                Some(cur_core.object_folder.as_str()),
            )
            .unwrap(),
        );
    }
    internal_client = Some(
        Client::new_client(
            client_storage,
            pub_storage,
            &client_param,
            cc_conf.decryption_mode,
        )
        .await
        .unwrap(),
    );

    let internal_client = Arc::new(RwLock::new(
        internal_client.expect("UserDecrypt requires a KMS client"),
    ));

    let ct_batch = vec![
        TypedCiphertext {
            ciphertext: to_decrypt,
            fhe_type: 8, // FheType::Euint256
            external_handle: vec![23_u8; 32],
            ciphertext_format: CiphertextFormat::SmallCompressed.into(),
        };
        1
    ];
    let req_id = RequestId::new_random(&mut rng);
    let user_decrypt_req_tuple = internal_client.write().await.user_decryption_request(
                &alloy_sol_types::eip712_domain!(
                    name: "Authorization token",
                    version: "1",
                    chain_id: 8006,
                    verifying_contract: alloy_primitives::address!("66f9664f97F2b50F62D13eA064982f936dE76657"),
                ),
                ct_batch,
                &req_id,
                &key_id.into(),
                None,
                None,
                &vec![],
            ).unwrap();

    let (user_decrypt_req, enc_pk, enc_sk) = user_decrypt_req_tuple;

    for (core, req_client) in core_endpoints_req.iter_mut() {
        req_client
            .user_decrypt(tonic::Request::new(user_decrypt_req.clone()))
            .await
            .unwrap();
    }
    let threshold = (num_parties - 1) / 3; // mirrors the library's own formula
    let min_responses_needed = num_parties - threshold;
    // Collect responses from all cores up to num_expected_responses
    let mut messages: Vec<UserDecryptionResponse> = Vec::new();

    for (core, resp_client) in core_endpoints_resp.iter_mut() {
        let mut response = resp_client
            .get_user_decryption_result(tonic::Request::new(req_id.into()))
            .await;
        let mut ctr = 0_usize;
        while response.is_err() && response.as_ref().unwrap_err().code() == tonic::Code::Unavailable
        {
            tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;
            if ctr >= max_iter {
                panic!("timeout after {max_iter} retries");
            }
            ctr += 1;
            response = resp_client
                .get_user_decryption_result(tonic::Request::new(req_id.into()))
                .await;
        }

        let resp = response
            .map_err(|e| anyhow::anyhow!("user decryption response failed: {e}"))
            .unwrap();
        messages.push(resp.into_inner());

        if messages.len() >= min_responses_needed {
            break;
        }
    }

    let client_request = ParsedUserDecryptionRequest::try_from(&user_decrypt_req)
        .map_err(|e| anyhow::anyhow!("failed to parse user decryption request: {e}"))
        .unwrap();
    let eip712_domain = protobuf_to_alloy_domain(
        user_decrypt_req
            .domain
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("domain not set in user decrypt request"))
            .unwrap(),
    )
    .unwrap();
    let plaintexts = internal_client
        .read()
        .await
        .process_user_decryption_resp(
            &client_request,
            &eip712_domain,
            &enc_pk,
            &enc_sk,
            Some(threshold),
            &messages,
        )
        .inspect_err(|e| {
            tracing::error!(
                "Error: User decryption response is NOT valid! Reason: {}",
                e
            )
        })
        .unwrap();
    let plaintext = plaintexts
        .into_iter()
        .next()
        .ok_or(anyhow::anyhow!("plaintexts response is empty"))?;

    let bytes = plaintext.bytes;

    Ok(bytes)
}

pub async fn fetch_public_elements(
    element_id: &str,
    element_types: &[PubDataType],
    sim_conf: &CoreClientConfig,
    destination_prefix: &Path,
    download_all: bool,
) -> anyhow::Result<Vec<CoreConf>> {
    // set of core ids, to track which cores we successfully contacted
    let mut successful_core_ids: HashSet<CoreConf> = HashSet::new();

    // go over list of cores to retrieve the public elements from
    'cores: for cur_core in &sim_conf.cores {
        let mut all_elements = true;
        // try to fetch all elements from this core
        'elements: for element_name in element_types {
            if fetch_global_pub_element_and_write_to_file(
                destination_prefix,
                cur_core.s3_endpoint.as_str(),
                element_id,
                &element_name.to_string(),
                &cur_core.object_folder,
            )
            .await
            .is_err()
            {
                tracing::warn!(
                    "Could not fetch element {element_name} with id {element_id} from core at endpoint {}. At least one core is required to proceed.",
                    cur_core.s3_endpoint
                );
                all_elements = false;
                break 'elements;
            }
        }
        // if we were able to retrieve all elements, add the core id to the set of successful nodes
        if all_elements {
            successful_core_ids.insert(cur_core.clone());
            // if we only want to download from one core, break here
            if !download_all {
                break 'cores;
            }
        }
    }

    if successful_core_ids.is_empty() {
        Err(anyhow::anyhow!(
            "Could not fetch all of [{element_types:?}] with id {element_id} from any core. At least one core is required to proceed."
        ))
    } else {
        Ok(successful_core_ids.into_iter().collect())
    }
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq, EnumString, Display)]
pub enum KmsType {
    #[strum(serialize = "centralized")]
    #[serde(rename = "centralized")]
    Centralized,
    #[strum(serialize = "threshold")]
    #[serde(rename = "threshold")]
    Threshold,
}
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct CoreClientConfig {
    // The mode of the KMS ("centralized" or "threshold"). Threshold by default.
    pub kms_type: KmsType,
    // List of configurations for the cores
    pub cores: Vec<CoreConf>,
    pub decryption_mode: Option<DecryptionMode>,
    pub num_majority: usize,
    pub num_reconstruct: usize,
    pub fhe_params: Option<FheParameter>,
}

#[derive(Deserialize, Serialize, Clone, Default, Debug, Hash, PartialEq, Eq)]
pub struct CoreConf {
    /// The ID of the given KMS server (monotonically increasing positive integer starting at 1)
    pub party_id: usize,

    /// The address of the given KMS server, including the port
    pub address: String,

    /// The S3 endpoint where the public material of the given server can be reached
    pub s3_endpoint: String,

    /// The folder at the S3 endpoint where the data is stored.
    pub object_folder: String,
}

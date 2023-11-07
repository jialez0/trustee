//! Attestation Service
//!
//! # Features
//! - `rvps-grpc`: The AS will connect a remote RVPS.
//! - `rvps-native`: The AS will integrate RVPS functionalities itself.

extern crate serde;

#[macro_use]
extern crate log;

pub mod config;
pub mod policy_engine;
mod rvps;
mod token;
mod utils;

use crate::token::AttestationTokenBroker;

use anyhow::{anyhow, Context, Result};
use config::Config;
pub use kbs_types::{Attestation, Tee};
use policy_engine::{PolicyEngine, PolicyEngineType, SetPolicyInput};
use rvps::RVPSAPI;
use serde_json::json;
use std::{collections::HashMap, str::FromStr};
use tokio::fs;

use crate::utils::flatten_claims;

pub struct AttestationService {
    _config: Config,
    policy_engine: Box<dyn PolicyEngine + Send + Sync>,
    rvps: Box<dyn RVPSAPI + Send + Sync>,
    token_broker: Box<dyn AttestationTokenBroker + Send + Sync>,
}

impl AttestationService {
    /// Create a new Attestation Service instance.
    pub async fn new(config: Config) -> Result<Self> {
        if !config.work_dir.as_path().exists() {
            fs::create_dir_all(&config.work_dir)
                .await
                .context("Create AS work dir failed: {:?}")?;
        }

        let policy_engine = PolicyEngineType::from_str(&config.policy_engine)
            .map_err(|_| anyhow!("Policy Engine {} is not supported", &config.policy_engine))?
            .to_policy_engine(config.work_dir.as_path())?;

        let rvps = config
            .rvps_config
            .into_rvps()
            .await
            .context("create rvps failed.")?;

        let token_broker = config
            .attestation_token_broker
            .to_token_broker(config.attestation_token_config.clone())?;

        Ok(Self {
            _config: config,
            policy_engine,
            rvps,
            token_broker,
        })
    }

    /// Set Attestation Verification Policy.
    pub async fn set_policy(&mut self, input: SetPolicyInput) -> Result<()> {
        self.policy_engine
            .set_policy(input)
            .await
            .map_err(|e| anyhow!("Cannot Set Policy: {:?}", e))
    }

    /// Evaluate Attestation Evidence.
    /// Issue an attestation results token which contain TCB status and TEE public key.
    pub async fn evaluate(&self, tee: Tee, nonce: &str, attestation: &str) -> Result<String> {
        let attestation = serde_json::from_str::<Attestation>(attestation)
            .context("Failed to deserialize Attestation")?;
        let verifier = verifier::to_verifier(&tee)?;

        let claims_from_tee_evidence = verifier
            .evaluate(nonce.to_string(), &attestation)
            .await
            .map_err(|e| anyhow!("Verifier evaluate failed: {e:?}"))?;

        let flattened_claims = flatten_claims(tee.clone(), &claims_from_tee_evidence)?;

        let tcb_json = serde_json::to_string(&flattened_claims)?;

        let reference_data_map = self
            .get_reference_data(flattened_claims.keys())
            .await
            .map_err(|e| anyhow!("Generate reference data failed{:?}", e))?;

        // Now only support using default policy to evaluate
        let evaluation_report = self
            .policy_engine
            .evaluate(reference_data_map, tcb.clone(), None)
            .await
            .map_err(|e| anyhow!("Policy Engine evaluation failed: {e}"))?;

        let token_claims = json!({
            "tee-pubkey": attestation.tee_pubkey.clone(),
            "tcb-status": flattened_claims,
            "evaluation-report": evaluation_report,
        });
        let attestation_results_token = self.token_broker.issue(token_claims)?;

        Ok(attestation_results_token)
    }

    async fn get_reference_data<'a, I>(&self, tcb_claims: I) -> Result<HashMap<String, Vec<String>>>
    where
        I: Iterator<Item = &'a String>,
    {
        let mut data = HashMap::new();
        for key in tcb_claims {
            let reference_value = self.rvps.get_digests(key).await?;
            if !reference_value.is_empty() {
                debug!("Successfully get reference values of {key} from RVPS.");
            }
            data.insert(key.to_string(), reference_value);
        }
        Ok(data)
    }

    /// Registry a new reference value
    pub async fn registry_reference_value(&mut self, message: &str) -> Result<()> {
        self.rvps.verify_and_extract(message).await
    }
}

use anyhow::Result;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use strum::EnumString;

pub mod opa;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SetPolicyInput {
    pub r#type: String,
    pub policy_id: String,
    pub policy: String,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct PolicyListEntry {
    pub id: String,
    pub digest: String,
    pub content: String,
}

#[derive(Debug, EnumString, Deserialize)]
#[strum(ascii_case_insensitive)]
pub enum PolicyEngineType {
    OPA,
}

#[derive(Debug, EnumString, Deserialize, PartialEq)]
#[strum(ascii_case_insensitive)]
pub enum PolicyType {
    Rego,
}

impl PolicyEngineType {
    #[allow(dead_code)]
    pub fn to_policy_engine(&self) -> Result<Box<dyn PolicyEngine + Send + Sync>> {
        match self {
            PolicyEngineType::OPA => {
                Ok(Box::new(opa::OPA::new()?) as Box<dyn PolicyEngine + Send + Sync>)
            }
        }
    }
}

#[async_trait]
pub trait PolicyEngine {
    /// The result is a key-value map.
    /// - `key`: the policy id
    /// - `value`: (whether the policy passes, the outputs about the policy)
    async fn evaluate(
        &self,
        reference_data_map: HashMap<String, Vec<String>>,
        input: String,
        policy_ids: Vec<String>,
    ) -> Result<HashMap<String, (bool, String)>>;

    async fn set_policy(&mut self, input: SetPolicyInput) -> Result<()>;

    async fn remove_policy(&mut self, policy_id: String) -> Result<()>;

    async fn list_policy(&self) -> Result<Vec<PolicyListEntry>>;
}

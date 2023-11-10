// Copyright (c) 2023 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use crate::attestation::Attest;
use anyhow::*;
use async_trait::async_trait;
use attestation_service::{
    config::Config as AsConfig, policy_engine::SetPolicyInput, AttestationService,
};
use kbs_types::{Attestation, Tee};

pub struct Native {
    inner: AttestationService,
}

#[async_trait]
impl Attest for Native {
    async fn set_policy(&mut self, input: &str) -> Result<()> {
        let req: SetPolicyInput =
            serde_json::from_str(input).context("parse set policy request")?;
        self.inner.set_policy(req).await
    }

    async fn verify(&mut self, tee: Tee, nonce: &str, attestation: &str) -> Result<String> {
        let attestation: Attestation =
            serde_json::from_str(attestation).context("parse Attestation")?;
        let runtime_data = vec![
            nonce.as_bytes().to_vec(),
            attestation.tee_pubkey.k_mod.as_bytes().to_vec(),
            attestation.tee_pubkey.k_exp.as_bytes().to_vec(),
        ];

        // TODO: configure policy used in AS
        // here we specify the policy as `default`.
        self.inner
            .evaluate(
                attestation.tee_evidence.as_bytes().to_vec(),
                tee,
                runtime_data,
                vec![],
                vec!["default".to_string()],
            )
            .await
    }
}

impl Native {
    pub async fn new(config: &AsConfig) -> Result<Self> {
        Ok(Self {
            inner: AttestationService::new(config.clone()).await?,
        })
    }
}

// Copyright (c) 2023 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use anyhow::*;
use jwt_simple::algorithms::{ECDSAP256KeyPairLike, ECDSAP256PublicKeyLike};
use jwt_simple::prelude::{Claims, Duration, ES256KeyPair};
use rcgen::{Certificate, CertificateParams};
use serde_json::Value;

use crate::token::AttestationTokenBroker;

pub struct SimpleAttestationTokenBroker {
    key_pair: ES256KeyPair,
    cert: Vec<u8>,
}

impl SimpleAttestationTokenBroker {
    pub fn new() -> Result<Self> {
        let key_pair = ES256KeyPair::generate();

        let rcgen_key_pair = rcgen::KeyPair::from_pem(&key_pair.to_pem()?)?;
        let mut cert_params = CertificateParams::new(vec!["CoCo-Attestation-Service".to_string()]);
        cert_params.key_pair = Some(rcgen_key_pair);
        let cert = Certificate::from_params(cert_params)?.serialize_der()?;

        Ok(Self { key_pair, cert })
    }
}

impl AttestationTokenBroker for SimpleAttestationTokenBroker {
    fn issue(&self, custom_claims: Value) -> Result<String> {
        let claims = Claims::with_custom_claims(custom_claims, Duration::from_mins(20));
        let token = self.key_pair.sign(claims)?;
        Ok(token)
    }

    fn verify(&self, token: String) -> Result<()> {
        let _ = self
            .key_pair
            .public_key()
            .verify_token::<Value>(&token, None)?;
        Ok(())
    }

    fn x509_certificate_chain(&self) -> Result<Vec<u8>> {
        Ok(self.cert.clone())
    }
}

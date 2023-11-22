// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::*;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use openssl::rsa::Rsa;
use openssl::sign::Signer;
use openssl::{
    hash::MessageDigest,
    pkey::{PKey, Private},
};
use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};
use serde_json::{json, Value};

use crate::token::{AttestationTokenBroker, AttestationTokenConfig};

const ISSUER_NAME: &str = "OpenAnolis-Attestation-Service";
const RSA_KEY_BITS: u32 = 2048;
const SIMPLE_TOKEN_ALG: &str = "RS384";

pub struct OaasAttestationTokenBroker {
    private_key: Rsa<Private>,
    config: AttestationTokenConfig,
}

impl OaasAttestationTokenBroker {
    pub fn new(config: AttestationTokenConfig) -> Result<Self> {
        let private_key = match config.signer.clone() {
            Some(signer) => {
                let pem_data = std::fs::read(&signer.key_path)
                    .map_err(|e| anyhow!("Read Token Signer private key failed: {:?}", e))?;
                Rsa::private_key_from_pem(&pem_data)?
            }
            None => Rsa::generate(RSA_KEY_BITS)?,
        };

        Ok(Self {
            private_key,
            config,
        })
    }
}

impl OaasAttestationTokenBroker {
    fn rs384_sign(&self, payload: &[u8]) -> Result<Vec<u8>> {
        let rsa_pkey = PKey::from_rsa(self.private_key.clone())?;
        let mut signer = Signer::new(MessageDigest::sha384(), &rsa_pkey)?;
        signer.update(payload)?;
        let signature = signer.sign_to_vec()?;

        Ok(signature)
    }
}

impl AttestationTokenBroker for OaasAttestationTokenBroker {
    fn issue(&self, custom_claims: Value) -> Result<String> {
        let header_value = json!({
            "typ": "JWT",
            "alg": SIMPLE_TOKEN_ALG,
        });
        let header_string = serde_json::to_string(&header_value)?;
        let header_b64 = URL_SAFE_NO_PAD.encode(header_string.as_bytes());

        let now = time::OffsetDateTime::now_utc();
        let exp = now + time::Duration::minutes(self.config.duration_min);

        let id: String = thread_rng()
            .sample_iter(&Alphanumeric)
            .take(10)
            .map(char::from)
            .collect();

        let mut claims = json!({
            "iss": self.config.clone().issuer_name.unwrap_or(ISSUER_NAME.to_string()),
            "iat": now.unix_timestamp(),
            "jti": id,
            "jwk": serde_json::from_str::<Value>(&self.pubkey_jwks()?)?["keys"][0].clone(),
            "nbf": now.unix_timestamp(),
            "exp": exp.unix_timestamp(),
        })
        .as_object()
        .ok_or_else(|| anyhow!("Internal Error: generate claims failed"))?
        .clone();

        claims.extend(
            custom_claims
                .as_object()
                .ok_or_else(|| anyhow!("Illegal token custom claims"))?
                .to_owned(),
        );

        let claims_value = Value::Object(claims);
        let claims_string = serde_json::to_string(&claims_value)?;
        let claims_b64 = URL_SAFE_NO_PAD.encode(claims_string.as_bytes());

        let signature_payload = format!("{header_b64}.{claims_b64}");
        let signature = self.rs384_sign(signature_payload.as_bytes())?;
        let signature_b64 = URL_SAFE_NO_PAD.encode(signature);

        let token = format!("{signature_payload}.{signature_b64}");

        Ok(token)
    }

    fn pubkey_jwks(&self) -> Result<String> {
        let n = self.private_key.n().to_vec();
        let e = self.private_key.e().to_vec();

        let mut jwk = Jwk {
            kty: "RSA".to_string(),
            alg: SIMPLE_TOKEN_ALG.to_string(),
            n: URL_SAFE_NO_PAD.encode(n),
            e: URL_SAFE_NO_PAD.encode(e),
            x5u: None,
            x5c: vec![],
        };

        if let Some(signer) = &self.config.signer {
            if let Some(cert_url) = signer.cert_url.clone() {
                jwk.x5u = Some(cert_url);
            }
            if let Some(cert_path) = signer.cert_path.clone() {
                let der_cert = std::fs::read(&cert_path)
                    .map_err(|e| anyhow!("Read Token Signer cert file failed: {:?}", e))?;
                jwk.x5c = vec![URL_SAFE_NO_PAD.encode(&der_cert)];
            }
        }

        let jwks = json!({
            "keys": vec![jwk],
        });

        Ok(serde_json::to_string(&jwks)?)
    }
}

#[derive(serde::Serialize, Debug, Clone)]
struct Jwk {
    kty: String,
    alg: String,
    n: String,
    e: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x5u: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub x5c: Vec<String>,
}

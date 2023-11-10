// Copyright (c) 2023 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use super::*;

use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};

#[cfg(feature = "as")]
/// GET /new-api-key
pub(crate) async fn new_api_key(
    request: HttpRequest,
    user_pub_key: web::Data<Option<Ed25519PublicKey>>,
    insecure: web::Data<bool>,
    api_key_list: web::Data<Arc<Mutex<Vec<String>>>>,
) -> Result<HttpResponse> {
    if !insecure.get_ref() {
        let user_pub_key = user_pub_key
            .as_ref()
            .as_ref()
            .ok_or(Error::UserPublicKeyNotProvided)?;

        validate_auth(&request, user_pub_key).map_err(|e| {
            Error::FailedAuthentication(format!("Requester is not an authorized user: {e}"))
        })?;
    }

    let api_key: String = thread_rng()
        .sample_iter(&Alphanumeric)
        .take(10)
        .map(char::from)
        .collect();

    api_key_list.clone().lock().await.push(api_key.clone());

    let body = serde_json::to_string(&serde_json::json!({
        "api-key": api_key,
    }))
    .map_err(|e| Error::PolicyEndpoint(format!("Serialize API Key failed {e}")))?;

    Ok(HttpResponse::Ok()
        .content_type("application/json")
        .body(body))
}

#[cfg(feature = "as")]
/// GET /api-key
pub(crate) async fn list_api_key(
    request: HttpRequest,
    user_pub_key: web::Data<Option<Ed25519PublicKey>>,
    insecure: web::Data<bool>,
    api_key_list: web::Data<Arc<Mutex<Vec<String>>>>,
) -> Result<HttpResponse> {
    if !insecure.get_ref() {
        let user_pub_key = user_pub_key
            .as_ref()
            .as_ref()
            .ok_or(Error::UserPublicKeyNotProvided)?;

        validate_auth(&request, user_pub_key).map_err(|e| {
            Error::FailedAuthentication(format!("Requester is not an authorized user: {e}"))
        })?;
    }

    let body = serde_json::to_string(&serde_json::json!({
        "api-keys": api_key_list.clone().lock().await.clone(),
    }))
    .map_err(|e| Error::PolicyEndpoint(format!("Serialize API Key failed {e}")))?;

    Ok(HttpResponse::Ok()
        .content_type("application/json")
        .body(body))
}

#[cfg(feature = "as")]
/// DELETE /api-key
pub(crate) async fn delete_api_key(
    request: HttpRequest,
    input: web::Data<String>,
    user_pub_key: web::Data<Option<Ed25519PublicKey>>,
    insecure: web::Data<bool>,
    api_key_list: web::Data<Arc<Mutex<Vec<String>>>>,
) -> Result<HttpResponse> {
    if !insecure.get_ref() {
        let user_pub_key = user_pub_key
            .as_ref()
            .as_ref()
            .ok_or(Error::UserPublicKeyNotProvided)?;

        validate_auth(&request, user_pub_key).map_err(|e| {
            Error::FailedAuthentication(format!("Requester is not an authorized user: {e}"))
        })?;
    }

    let target_api_key = input.into_inner().to_string();

    api_key_list
        .clone()
        .lock()
        .await
        .retain(|item| item != &target_api_key);

    Ok(HttpResponse::Ok().finish())
}

#[cfg(feature = "as")]
/// POST /attestation-policy
pub(crate) async fn set_attestation_policy(
    request: HttpRequest,
    input: web::Json<as_types::SetPolicyInput>,
    user_pub_key: web::Data<Option<Ed25519PublicKey>>,
    insecure: web::Data<bool>,
    attestation_service: web::Data<AttestationService>,
) -> Result<HttpResponse> {
    if !insecure.get_ref() {
        let user_pub_key = user_pub_key
            .as_ref()
            .as_ref()
            .ok_or(Error::UserPublicKeyNotProvided)?;

        validate_auth(&request, user_pub_key).map_err(|e| {
            Error::FailedAuthentication(format!("Requester is not an authorized user: {e}"))
        })?;
    }

    attestation_service
        .0
        .lock()
        .await
        .set_policy(input.into_inner())
        .await
        .map_err(|e| Error::PolicyEndpoint(format!("Set policy error {e}")))?;

    Ok(HttpResponse::Ok().finish())
}

#[cfg(feature = "as")]
/// DELETE /attestation-policy
pub(crate) async fn delete_attestation_policy(
    request: HttpRequest,
    input: web::Data<String>,
    user_pub_key: web::Data<Option<Ed25519PublicKey>>,
    insecure: web::Data<bool>,
    attestation_service: web::Data<AttestationService>,
) -> Result<HttpResponse> {
    if !insecure.get_ref() {
        let user_pub_key = user_pub_key
            .as_ref()
            .as_ref()
            .ok_or(Error::UserPublicKeyNotProvided)?;

        validate_auth(&request, user_pub_key).map_err(|e| {
            Error::FailedAuthentication(format!("Requester is not an authorized user: {e}"))
        })?;
    }

    attestation_service
        .0
        .lock()
        .await
        .remove_policy(input.into_inner().to_string())
        .await
        .map_err(|e| Error::PolicyEndpoint(format!("Remove policy error {e}")))?;

    Ok(HttpResponse::Ok().finish())
}

#[cfg(feature = "as")]
/// GET /attestation-policy
pub(crate) async fn get_attestation_policy(
    request: HttpRequest,
    user_pub_key: web::Data<Option<Ed25519PublicKey>>,
    insecure: web::Data<bool>,
    attestation_service: web::Data<AttestationService>,
) -> Result<HttpResponse> {
    if !insecure.get_ref() {
        let user_pub_key = user_pub_key
            .as_ref()
            .as_ref()
            .ok_or(Error::UserPublicKeyNotProvided)?;

        validate_auth(&request, user_pub_key).map_err(|e| {
            Error::FailedAuthentication(format!("Requester is not an authorized user: {e}"))
        })?;
    }

    let policy_list = attestation_service
        .0
        .lock()
        .await
        .list_policy()
        .await
        .map_err(|e| Error::PolicyEndpoint(format!("Set policy error {e}")))?;

    let body = serde_json::to_string(&serde_json::json!({
        "policys": policy_list,
    }))
    .map_err(|e| Error::PolicyEndpoint(format!("Serialize Policy List failed {e}")))?;

    Ok(HttpResponse::Ok()
        .content_type("application/json")
        .body(body))
}

#[cfg(feature = "policy")]
/// POST /resource-policy
pub(crate) async fn resource_policy(
    request: HttpRequest,
    input: web::Json<serde_json::Value>,
    user_pub_key: web::Data<Option<Ed25519PublicKey>>,
    insecure: web::Data<bool>,
    policy_engine: web::Data<PolicyEngine>,
) -> Result<HttpResponse> {
    if !insecure.get_ref() {
        let user_pub_key = user_pub_key
            .as_ref()
            .as_ref()
            .ok_or(Error::UserPublicKeyNotProvided)?;

        validate_auth(&request, user_pub_key).map_err(|e| {
            Error::FailedAuthentication(format!("Requester is not an authorized user: {e}"))
        })?;
    }

    policy_engine
        .0
        .lock()
        .await
        .set_policy(
            input.into_inner()["policy"]
                .as_str()
                .ok_or(Error::PolicyEndpoint(
                    "Get policy from request failed".to_string(),
                ))?
                .to_string(),
        )
        .await
        .map_err(|e| Error::PolicyEndpoint(format!("Set policy error {e}")))?;

    Ok(HttpResponse::Ok().finish())
}

#[cfg(feature = "resource")]
/// POST /resource/{repository}/{type}/{tag}
/// POST /resource/{type}/{tag}
///
/// TODO: Although this endpoint is authenticated through a JSON Web Token (JWT),
/// only identified users should be able to get a JWT and access it.
/// At the moment user identification is not supported, and the KBS CLI
/// `--user-public-key` defines the authorized user for that endpoint. In other words,
/// any JWT signed with the user's private key will be authenticated.
/// JWT generation and user identification is unimplemented for now, and thus this
/// endpoint is insecure and is only meant for testing purposes.
pub(crate) async fn set_resource(
    request: HttpRequest,
    data: web::Bytes,
    user_pub_key: web::Data<Option<Ed25519PublicKey>>,
    insecure: web::Data<bool>,
    repository: web::Data<Arc<RwLock<dyn Repository + Send + Sync>>>,
) -> Result<HttpResponse> {
    if !insecure.get_ref() {
        let user_pub_key = user_pub_key
            .as_ref()
            .as_ref()
            .ok_or(Error::UserPublicKeyNotProvided)?;

        validate_auth(&request, user_pub_key).map_err(|e| {
            Error::FailedAuthentication(format!("Requester is not an authorized user: {e}"))
        })?;
    }

    let resource_description = ResourceDesc {
        repository_name: request
            .match_info()
            .get("repository")
            .unwrap_or("default")
            .to_string(),
        resource_type: request
            .match_info()
            .get("type")
            .ok_or_else(|| Error::InvalidRequest(String::from("no `type` in url")))?
            .to_string(),
        resource_tag: request
            .match_info()
            .get("tag")
            .ok_or_else(|| Error::InvalidRequest(String::from("no `tag` in url")))?
            .to_string(),
    };

    set_secret_resource(&repository, resource_description, data.as_ref())
        .await
        .map_err(|e| Error::SetSecretFailed(format!("{e}")))?;
    Ok(HttpResponse::Ok().content_type("application/json").body(""))
}

// Copyright (c) 2022 by Rivos Inc.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use actix_web::{body::BoxBody, web, HttpRequest, HttpResponse};
use jwt_simple::prelude::Ed25519PublicKey;
use kbs_types::{Attestation, Challenge, ErrorInformation, Request};
use std::sync::Arc;
use strum_macros::EnumString;
use tokio::sync::{Mutex, RwLock};

use crate::attest::AttestVerifier;
use crate::auth::validate_auth;
use crate::resource::{set_secret_resource, Repository, ResourceDesc};
use crate::session::{Session, SessionMap, KBS_SESSION_ID};
use crate::token::AttestationTokenBroker;

mod attestation;
mod config;
mod core;
mod public;

/// RESTful APIs that related to KBS attestation protocol
pub use self::core::*;

/// RESTful APIs that need attestation verification
pub use attestation::*;

/// RESTful APIs that configure KBS and AS, require user authentication
pub use config::*;

/// RESTful APIs that is public
pub use public::*;

const ERROR_TYPE_PREFIX: &str = "https://github.com/confidential-containers/kbs/errors/";

#[derive(Debug, EnumString)]
pub enum ErrorInformationType {
    ExpiredCookie,
    FailedAuthentication,
    InvalidCookie,
    MissingCookie,
    UnAuthenticatedCookie,
    VerificationFailed,
    JWTVerificationFailed,
}

pub(crate) fn kbs_error_info(error_type: ErrorInformationType, detail: &str) -> ErrorInformation {
    ErrorInformation {
        error_type: format!("{ERROR_TYPE_PREFIX}{error_type:?}"),
        detail: detail.to_string(),
    }
}

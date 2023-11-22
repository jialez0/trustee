use std::{net::SocketAddr, sync::Arc};

use actix_web::{body::BoxBody, dev::Server, web, App, HttpResponse, HttpServer, ResponseError};
use anyhow::{bail, Context};
use attestation_service::{policy_engine::SetPolicyInput, AttestationService};
use base64::{engine::general_purpose::STANDARD, Engine};
use kbs_types::Tee;
use log::{debug, info};
use serde::{Deserialize, Serialize};
use strum::AsRefStr;
use thiserror::Error;
use tokio::sync::Mutex;

#[derive(Error, Debug, AsRefStr)]
pub enum Error {
    #[error("An internal error occured: {0}")]
    InternalError(#[from] anyhow::Error),
}

impl ResponseError for Error {
    fn error_response(&self) -> HttpResponse {
        let body = format!("{self:#?}");

        let mut res = match self {
            Error::InternalError(_) => HttpResponse::InternalServerError(),
            // _ => HttpResponse::NotImplemented(),
        };

        res.body(BoxBody::new(body))
    }
}

type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Serialize, Deserialize)]
struct AttestationRequest {
    tee: String,
    evidence: String,
    #[serde(default = "Vec::default")]
    runtime_data: Vec<String>,
    #[serde(default = "Vec::default")]
    init_data: Vec<String>,
    #[serde(default = "Vec::default")]
    policy_ids: Vec<String>,
}

fn to_tee(tee: &str) -> anyhow::Result<Tee> {
    let res = match tee {
        "azsnpvtpm" => Tee::AzSnpVtpm,
        "sev" => Tee::Sev,
        "sgx" => Tee::Sgx,
        "snp" => Tee::Snp,
        "tdx" => Tee::Tdx,
        "cca" => Tee::Cca,
        "csv" => Tee::Csv,
        "sample" => Tee::Sample,
        other => bail!("tee `{other} not supported`"),
    };

    Ok(res)
}

/// This handler uses json extractor
async fn attestation(
    request: web::Json<AttestationRequest>,
    cocoas: web::Data<Arc<Mutex<AttestationService>>>,
) -> Result<HttpResponse> {
    info!("new attestation request.");

    let request = request.into_inner();
    debug!("attestation: {request:#?}");

    let evidence = STANDARD
        .decode(&request.evidence)
        .context("base64 decode evidence")?;
    let tee = to_tee(&request.tee)?;
    let runtime_data = request
        .runtime_data
        .iter()
        .map(|data_item| {
            STANDARD
                .decode(data_item)
                .context("base64 decode runtime data")
        })
        .collect::<anyhow::Result<Vec<Vec<u8>>>>()?;
    let init_data: Vec<Vec<u8>> = request
        .init_data
        .iter()
        .map(|data_item| {
            STANDARD
                .decode(data_item)
                .context("base64 decode init data")
        })
        .collect::<anyhow::Result<Vec<Vec<u8>>>>()?;
    let policy_ids = if request.policy_ids.is_empty() {
        info!("no policy specified, use `default`");
        vec!["default".into()]
    } else {
        request.policy_ids
    };

    let token = cocoas
        .lock()
        .await
        .evaluate(evidence, tee, runtime_data, init_data, policy_ids)
        .await
        .context("attestation report evaluate")?;
    Ok(HttpResponse::Ok().body(token))
}

/// This handler uses json extractor with limit
async fn set_policy(
    input: web::Json<SetPolicyInput>,
    cocoas: web::Data<Arc<Mutex<AttestationService>>>,
) -> Result<HttpResponse> {
    info!("set policy.");
    let input = input.into_inner();

    debug!("set policy: {input:#?}");
    cocoas
        .lock()
        .await
        .set_policy(input)
        .await
        .context("set policy")?;

    Ok(HttpResponse::Ok().body(""))
}

async fn list_policy(cocoas: web::Data<Arc<Mutex<AttestationService>>>) -> Result<HttpResponse> {
    info!("get policy.");

    let policy_list = cocoas
        .lock()
        .await
        .list_policy()
        .await
        .context("get policys")?;

    let body = serde_json::to_string(&serde_json::json!({
        "policys": policy_list,
    }))
    .context("serialize response body")?;

    Ok(HttpResponse::Ok()
        .content_type("application/json")
        .body(body))
}

#[derive(Debug, Serialize, Deserialize)]
struct RemovePolicyRequest {
    pub policy_ids: Vec<String>,
}

async fn remove_policy(
    input: web::Json<RemovePolicyRequest>,
    cocoas: web::Data<Arc<Mutex<AttestationService>>>,
) -> Result<HttpResponse> {
    info!("set policy.");

    for id in input.into_inner().policy_ids {
        cocoas
            .lock()
            .await
            .remove_policy(id)
            .await
            .context("remove policy")?;
    }

    Ok(HttpResponse::Ok().body(""))
}

pub fn start_server(
    attestation_service: AttestationService,
    socket: SocketAddr,
) -> anyhow::Result<Server> {
    log::info!("starting HTTP server at http://{socket}");

    let attestation_service = web::Data::new(Arc::new(Mutex::new(attestation_service)));
    let server = HttpServer::new(move || {
        App::new()
            .service(web::resource("/attestation").route(web::post().to(attestation)))
            .service(
                web::resource("/policy")
                    .route(web::post().to(set_policy))
                    .route(web::get().to(list_policy))
                    .route(web::delete().to(remove_policy)),
            )
            .app_data(web::Data::clone(&attestation_service))
    })
    .bind((socket.ip().to_string(), socket.port()))?
    .run();

    Ok(server)
}

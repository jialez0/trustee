use std::{net::SocketAddr, path::Path};

use anyhow::{Context, Result};
use attestation_service::{config::Config, AttestationService};
use clap::{arg, command, Parser};
use log::info;

use crate::web::start_server;

mod web;

/// RESTful-AS command-line arguments.
#[derive(Debug, Parser)]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    /// Path to a CoCo-AS config file.
    #[arg(short, long)]
    pub config_file: String,

    /// Socket addresses (IP:port) to listen on, e.g. 127.0.0.1:8080.
    #[arg(short, long)]
    pub socket: SocketAddr,
}

#[actix_web::main]
async fn main() -> Result<()> {
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));

    let cli = Cli::parse();

    info!("Using config file {}", cli.config_file);

    let config_path = Path::new(&cli.config_file);
    let config = Config::try_from(config_path).context("read config file")?;

    let attestation_service = AttestationService::new(config).await?;

    let server = start_server(attestation_service, cli.socket)?;
    server.await?;

    Ok(())
}

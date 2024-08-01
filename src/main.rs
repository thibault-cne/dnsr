//! Loads a zone file and serves it over localhost UDP and TCP.
//!
//! Try queries such as:
//!
//!   dig @127.0.0.1 -p 8053 NS example.com
//!   dig @127.0.0.1 -p 8053 A example.com
//!   dig @127.0.0.1 -p 8053 AAAA example.com
//!   dig @127.0.0.1 -p 8053 CNAME example.com
//!
//! Also try with TCP, e.g.:
//!
//!   dig @127.0.0.1 -p 8053 +tcp A example.com
//!
//! Also try AXFR, e.g.:
//!
//!   dig @127.0.0.1 -p 8053 AXFR example.com

use core::future::pending;
use core::time::Duration;

use std::process::exit;
use std::sync::Arc;

use domain::net::server::buf::VecBufSource;
use domain::net::server::dgram::DgramServer;
use domain::net::server::middleware::edns::EdnsMiddlewareSvc;
use domain::net::server::middleware::mandatory::MandatoryMiddlewareSvc;
use domain::net::server::stream::StreamServer;
use tokio::net::{TcpListener, UdpSocket};

use crate::service::middleware::{MetricsMiddlewareSvc, Stats, TsigMiddlewareSvc};
use crate::service::Watcher;

mod config;
mod error;
mod key;
mod logger;
mod service;
mod tsig;
// mod watcher;
mod zone;

#[tokio::main()]
async fn main() {
    // Fetch the configuration
    let config_path = std::env::var("DNSR_CONFIG").unwrap_or(config::BASE_CONFIG_FILE.into());
    let bytes = match std::fs::read(&config_path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("Failed to read config file at path {}: {}", config_path, e);
            exit(1);
        }
    };
    let config = match config::Config::try_from(&bytes) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Failed to parse config file at path {}: {}", config_path, e);
            exit(1);
        }
    };

    // Initialize the custom logger
    logger::Logger::new()
        .with_level(config.log.level)
        .with_metrics(config.log.enable_metrics)
        .init()
        .expect("Failed to initialize custom logger");

    // Create the DNSR service
    let config = Arc::new(config);
    let dnsr = service::Dnsr::from(config.clone());
    let stats = Stats::new_shared();

    let dnsr = Arc::new(dnsr);
    let dnsr_svc = EdnsMiddlewareSvc::new(dnsr.clone());
    let dnsr_svc = MandatoryMiddlewareSvc::new(dnsr_svc);
    let dnsr_svc = TsigMiddlewareSvc::new(dnsr.clone(), dnsr_svc);
    let dnsr_svc = MetricsMiddlewareSvc::new(dnsr_svc, stats.clone());

    let addr = "0.0.0.0:53";

    // Start the UDP and TCP servers
    let sock = UdpSocket::bind(addr).await.unwrap();
    let sock = Arc::new(sock);
    let num_cores = std::thread::available_parallelism().unwrap().get();
    for _i in 0..num_cores {
        let udp_srv = DgramServer::new(sock.clone(), VecBufSource, dnsr_svc.clone());
        tokio::spawn(async move { udp_srv.run().await });
    }

    let sock = TcpListener::bind(addr).await.unwrap();
    let tcp_srv = StreamServer::new(sock, VecBufSource, dnsr_svc.clone());

    tokio::spawn(async move { tcp_srv.run().await });

    tokio::spawn(async move {
        match dnsr.watch_lock() {
            Ok(_) => (),
            Err(e) => {
                log::error!(target: "watcher", "failed to watch lock: {}", e);
                exit(1);
            }
        }
    });

    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(5));
        loop {
            interval.tick().await;
            log::info!(target: "metrics", "metrics report: {}", stats.read().unwrap());
        }
    });

    pending::<()>().await;
}

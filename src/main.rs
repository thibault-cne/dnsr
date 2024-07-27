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

use std::future::pending;
use std::process::exit;
use std::sync::Arc;

use domain::net::server::buf::VecBufSource;
use domain::net::server::dgram::DgramServer;
use domain::net::server::stream::StreamServer;
use domain::net::server::util::service_fn;
use tokio::net::{TcpListener, UdpSocket};

use crate::fs::Watcher;

mod config;
mod dns;
mod error;
mod fs;
mod logger;
mod metric;
mod tsig;

#[tokio::main()]
async fn main() {
    // Initialize the default logger
    logger::Logger::new()
        .init()
        .expect("Failed to initialize logger");

    // Fetch the configuration
    let config_path = std::env::var("DNSR_CONFIG").unwrap_or("config.yml".to_string());
    let bytes = match std::fs::read(&config_path) {
        Ok(b) => b,
        Err(e) => {
            log::error!("Failed to read config file at path {}: {}", config_path, e);
            exit(1);
        }
    };
    let config = match config::Config::try_from(&bytes) {
        Ok(c) => c,
        Err(e) => {
            log::error!("Failed to parse config file at path {}: {}", config_path, e);
            exit(1);
        }
    };

    // Initialize the custom logger
    logger::Logger::new()
        .with_level(config.log.level)
        .init()
        .expect("Failed to initialize custom logger");

    // Populate a zone tree with test data
    let state = Arc::new(dns::State::from(config.clone()));

    let addr = "127.0.0.1:8053";
    let svc = Arc::new(service_fn(dns::dns, state.clone()));

    let sock = UdpSocket::bind(addr).await.unwrap();
    let sock = Arc::new(sock);
    let mut udp_metrics = vec![];
    let num_cores = std::thread::available_parallelism().unwrap().get();
    for _i in 0..num_cores {
        let udp_srv = DgramServer::new(sock.clone(), VecBufSource, svc.clone());
        let metrics = udp_srv.metrics();
        udp_metrics.push(metrics);
        tokio::spawn(async move { udp_srv.run().await });
    }

    let sock = TcpListener::bind(addr).await.unwrap();
    let tcp_srv = StreamServer::new(sock, VecBufSource, svc);
    let tcp_metrics = tcp_srv.metrics();

    tokio::spawn(async move { tcp_srv.run().await });

    tokio::spawn(async move { Watcher::watch_lock(state).unwrap() });

    tokio::spawn(async move { metric::log_svc(config, udp_metrics, tcp_metrics).await });

    pending::<()>().await;
}

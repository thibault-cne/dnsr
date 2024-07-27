use std::sync::Arc;
use std::time::Duration;

use domain::net::server::metrics::ServerMetrics;

use crate::config::Config;

type UdpMetric = Vec<Arc<ServerMetrics>>;
type TcpMetric = Arc<ServerMetrics>;

pub async fn log_svc(config: Config, udp_metrics: UdpMetric, tcp_metrics: TcpMetric) {
    loop {
        tokio::time::sleep(Duration::from_millis(5000)).await;

        if config.log.enable_udp_metrics {
            udp_metrics.log();
        }
        if config.log.enable_tcp_metrics {
            tcp_metrics.log();
        }
    }
}

trait Metric {
    fn log(&self);
}

impl Metric for UdpMetric {
    fn log(&self) {
        for (i, metrics) in self.iter().enumerate() {
            log::info!(target: "metrics",
                "Server status: UDP[{i}]: #conn={:?}, #in-flight={}, #pending-writes={}, #msgs-recvd={}, #msgs-sent={}",
                metrics.num_connections(),
                metrics.num_inflight_requests(),
                metrics.num_pending_writes(),
                metrics.num_received_requests(),
                metrics.num_sent_responses(),
            );
        }
    }
}

impl Metric for TcpMetric {
    fn log(&self) {
        log::info!(target: "metrics",
            "Server status: TCP: #conn={:?}, #in-flight={}, #pending-writes={}, #msgs-recvd={}, #msgs-sent={}",
            self.num_connections(),
            self.num_inflight_requests(),
            self.num_pending_writes(),
            self.num_received_requests(),
            self.num_sent_responses(),
        );
    }
}

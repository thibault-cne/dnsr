use std::sync::Arc;
use std::time::Duration;

use domain::net::server::metrics::ServerMetrics;

use crate::config::Config;

type UdpMetric = Vec<Arc<ServerMetrics>>;
type TcpMetric = Arc<ServerMetrics>;

pub async fn log_svc(config: Config, udp_metrics: UdpMetric, tcp_metrics: TcpMetric) {
    let udp_metrics = ("UDP", udp_metrics);
    let tcp_metrics = ("TCP", tcp_metrics);

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

impl<S> Metric for (S, Arc<ServerMetrics>)
where
    S: AsRef<str>,
{
    fn log(&self) {
        let (name, metrics) = self;

        log::info!(target: "metrics",
            "Server status: {}: #conn={:?}, #in-flight={}, #pending-writes={}, #msgs-recvd={}, #msgs-sent={}",
            name.as_ref(),
            metrics.num_connections(),
            metrics.num_inflight_requests(),
            metrics.num_pending_writes(),
            metrics.num_received_requests(),
            metrics.num_sent_responses(),
        );
    }
}

impl<S> Metric for (S, Vec<Arc<ServerMetrics>>)
where
    S: AsRef<str>,
{
    fn log(&self) {
        let (name, metrics) = self;

        for (i, m) in metrics.iter().enumerate() {
            let metric = (format!("{}[{i}]", name.as_ref()), m.clone());
            metric.log();
        }
    }
}

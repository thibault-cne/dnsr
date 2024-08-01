use core::fmt;
use core::future::{ready, Ready};
use core::time::Duration;

use std::sync::{Arc, RwLock};

use domain::base::message_builder::AdditionalBuilder;
use domain::base::StreamTarget;
use domain::dep::octseq::Octets;
use domain::net::server::message::Request;
use domain::net::server::middleware::stream::{MiddlewareStream, PostprocessingStream};
use domain::net::server::service::{Service, ServiceResult};
use futures::stream::Empty;
use tokio::time::Instant;

#[derive(Default)]
pub struct Stats {
    slowest_req: Option<Duration>,
    fastest_req: Option<Duration>,
    num_req_bytes: u32,
    num_resp_bytes: u32,
    num_reqs: u32,
    num_ipv4: u32,
    num_ipv6: u32,
    num_udp: u32,
}

impl Stats {
    pub fn new_shared() -> Arc<RwLock<Self>> {
        Arc::new(RwLock::new(Self::default()))
    }
}

impl std::fmt::Display for Stats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "# Reqs={} [UDP={}, IPv4={}, IPv6={}] Bytes [rx={}, tx={}] Speed [fastest={}, slowest={}]",
            self.num_reqs,
            self.num_udp,
            self.num_ipv4,
            self.num_ipv6,
            self.num_req_bytes,
            self.num_resp_bytes,
            self.fastest_req.map(|v| format!("{}μs", v.as_micros())).unwrap_or_else(|| "-".to_string()),
            self.slowest_req.map(|v| format!("{}ms", v.as_millis())).unwrap_or_else(|| "-".to_string()),
    )
    }
}

#[derive(Clone)]
pub struct MetricsMiddlewareSvc<Svc> {
    stats: Arc<RwLock<Stats>>,
    svc: Svc,
}

impl<Svc> MetricsMiddlewareSvc<Svc> {
    /// Creates an instance of this processor.
    #[must_use]
    pub fn new(svc: Svc, stats: Arc<RwLock<Stats>>) -> Self {
        Self { svc, stats }
    }

    fn preprocess<RequestOctets>(&self, request: &Request<RequestOctets>)
    where
        RequestOctets: Octets + Send + Sync + Unpin,
    {
        let mut stats = self.stats.write().unwrap();

        stats.num_reqs += 1;
        stats.num_req_bytes += request.message().as_slice().len() as u32;

        if request.transport_ctx().is_udp() {
            stats.num_udp += 1;
        }

        if request.client_addr().is_ipv4() {
            stats.num_ipv4 += 1;
        } else {
            stats.num_ipv6 += 1;
        }
    }

    fn postprocess<RequestOctets>(
        request: &Request<RequestOctets>,
        response: &AdditionalBuilder<StreamTarget<Svc::Target>>,
        stats: Arc<RwLock<Stats>>,
    ) where
        RequestOctets: Octets + Send + Sync + Unpin,
        Svc: Service<RequestOctets>,
        Svc::Target: AsRef<[u8]>,
    {
        let duration = Instant::now().duration_since(request.received_at());
        let mut stats = stats.write().unwrap();

        stats.num_resp_bytes += response.as_slice().len() as u32;

        if duration < stats.fastest_req.unwrap_or(Duration::MAX) {
            stats.fastest_req = Some(duration);
        }
        if duration > stats.slowest_req.unwrap_or(Duration::ZERO) {
            stats.slowest_req = Some(duration);
        }
    }

    fn map_stream_item<RequestOctets>(
        request: Request<RequestOctets>,
        stream_item: ServiceResult<Svc::Target>,
        stats: Arc<RwLock<Stats>>,
    ) -> ServiceResult<Svc::Target>
    where
        RequestOctets: Octets + Send + Sync + Unpin,
        Svc: Service<RequestOctets>,
        Svc::Target: AsRef<[u8]>,
    {
        if let Ok(cr) = &stream_item {
            if let Some(response) = cr.response() {
                Self::postprocess(&request, response, stats);
            }
        }
        stream_item
    }
}

impl<RequestOctets, Svc> Service<RequestOctets> for MetricsMiddlewareSvc<Svc>
where
    RequestOctets: Octets + Send + Sync + 'static + Unpin,
    Svc: Service<RequestOctets>,
    Svc::Target: AsRef<[u8]>,
    Svc::Future: Unpin,
{
    type Target = Svc::Target;
    type Stream = MiddlewareStream<
        Svc::Future,
        Svc::Stream,
        PostprocessingStream<RequestOctets, Svc::Future, Svc::Stream, Arc<RwLock<Stats>>>,
        Empty<ServiceResult<Self::Target>>,
        ServiceResult<Self::Target>,
    >;
    type Future = Ready<Self::Stream>;

    fn call(&self, request: Request<RequestOctets>) -> Self::Future {
        self.preprocess(&request);
        let svc_call_fut = self.svc.call(request.clone());
        let map = PostprocessingStream::new(
            svc_call_fut,
            request,
            self.stats.clone(),
            Self::map_stream_item,
        );
        ready(MiddlewareStream::Map(map))
    }
}

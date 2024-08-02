use domain::net::server::message::Request;
use domain::net::server::service::{CallResult, ServiceError};
use futures::channel::mpsc::UnboundedSender;

pub type HandlerResult<T> = Result<T, ServiceError>;

pub trait HandleDNS {
    fn handle_non_axfr(&self, request: Request<Vec<u8>>) -> HandlerResult<CallResult<Vec<u8>>>;
    fn handle_axfr(
        &self,
        request: Request<Vec<u8>>,
        sender: UnboundedSender<HandlerResult<CallResult<Vec<u8>>>>,
    ) -> HandlerResult<()>;
}

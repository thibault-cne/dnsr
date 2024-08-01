use core::future::{ready, Ready};

use std::marker::PhantomData;
use std::ops::ControlFlow;
use std::sync::Arc;

use domain::base::message_builder::AdditionalBuilder;
use domain::base::wire::Composer;
use domain::base::{Message, Rtype, StreamTarget};
use domain::dep::octseq::Octets;
use domain::net::server::message::Request;
use domain::net::server::middleware::stream::{MiddlewareStream, PostprocessingStream};
use domain::net::server::service::{Service, ServiceResult};
use domain::rdata::tsig::Time48;
use domain::tsig::{ServerSequence, ServerTransaction};
use futures::stream::Once;

use crate::key::KeyStore;

#[derive(Clone, Debug)]
pub struct TsigMiddlewareSvc<Octets, Svc> {
    dnsr: Arc<crate::service::Dnsr>,
    svc: Svc,
    _octets: PhantomData<Octets>,
}

impl<RequestOctets, Svc> TsigMiddlewareSvc<RequestOctets, Svc>
where
    RequestOctets: Octets + Send + Sync + Unpin + Clone,
    Svc: Service<RequestOctets>,
    Svc::Target: Composer + Default,
{
    pub fn new(dnsr: Arc<crate::service::Dnsr>, svc: Svc) -> Self {
        Self {
            dnsr,
            svc,
            _octets: PhantomData,
        }
    }

    fn preprocess(
        &self,
        _request: &Request<RequestOctets>,
    ) -> ControlFlow<AdditionalBuilder<StreamTarget<Svc::Target>>> {
        ControlFlow::Continue(())
    }

    fn postprocess_non_axfr(
        keystore: &KeyStore,
        message: &mut Message<Vec<u8>>,
        response: &mut AdditionalBuilder<StreamTarget<Svc::Target>>,
    ) {
        match ServerTransaction::request::<KeyStore, Vec<u8>>(keystore, message, Time48::now()) {
            Ok(None) => (),
            Ok(Some(transaction)) => {
                log::info!(target: "svc", "found tsig key for transaction");
                transaction.answer(response, Time48::now()).unwrap()
            }
            Err(e) => log::error!(target: "svc", "tsig transaction error: {}", e),
        }
    }

    fn postprocess_axfr(
        keystore: &KeyStore,
        message: &mut Message<Vec<u8>>,
        response: &mut AdditionalBuilder<StreamTarget<Svc::Target>>,
    ) {
        match ServerSequence::request::<KeyStore, Vec<u8>>(keystore, message, Time48::now()) {
            Ok(None) => (),
            Ok(Some(mut sequence)) => {
                log::info!(target: "svc", "found tsig key for transaction");
                sequence.answer(response, Time48::now()).unwrap()
            }
            Err(e) => log::error!(target: "svc", "tsig transaction error: {}", e),
        }
    }

    fn postprocess(
        dnsr: Arc<crate::service::Dnsr>,
        request: &Request<RequestOctets>,
        response: &mut AdditionalBuilder<StreamTarget<Svc::Target>>,
    ) {
        let keystore = dnsr.keystore.read().unwrap();
        let bytes = request.message().as_slice();
        let mut message = Message::from_octets(bytes.to_vec()).unwrap();

        if !matches!(
            request
                .message()
                .sole_question()
                .map(|q| q.qtype() == Rtype::AXFR),
            Ok(true)
        ) {
            Self::postprocess_non_axfr(&keystore, &mut message, response)
        } else {
            Self::postprocess_axfr(&keystore, &mut message, response)
        }
    }

    fn map_stream_item(
        request: Request<RequestOctets>,
        mut stream_item: ServiceResult<Svc::Target>,
        metadata: Arc<crate::service::Dnsr>,
    ) -> ServiceResult<Svc::Target> {
        if let Ok(cr) = &mut stream_item {
            if let Some(response) = cr.response_mut() {
                Self::postprocess(metadata, &request, response);
            }
        }
        stream_item
    }
}

impl<RequestOctets, Svc> Service<RequestOctets> for TsigMiddlewareSvc<RequestOctets, Svc>
where
    RequestOctets: Octets + Send + Sync + 'static + Unpin + Clone,
    Svc: Service<RequestOctets>,
    Svc::Future: core::future::Future + Unpin,
    <Svc::Future as core::future::Future>::Output: Unpin,
    Svc::Target: Composer + Default,
{
    type Target = Svc::Target;
    type Stream = MiddlewareStream<
        Svc::Future,
        Svc::Stream,
        PostprocessingStream<RequestOctets, Svc::Future, Svc::Stream, Arc<crate::service::Dnsr>>,
        Once<Ready<<Svc::Stream as futures::stream::Stream>::Item>>,
        <Svc::Stream as futures::stream::Stream>::Item,
    >;
    type Future = core::future::Ready<Self::Stream>;

    fn call(&self, request: Request<RequestOctets>) -> Self::Future {
        match self.preprocess(&request) {
            ControlFlow::Break(_) => todo!(),
            ControlFlow::Continue(()) => {
                let svc_call_fut = self.svc.call(request.clone());
                let map = PostprocessingStream::new(
                    svc_call_fut,
                    request,
                    self.dnsr.clone(),
                    Self::map_stream_item,
                );
                ready(MiddlewareStream::Map(map))
            }
        }
    }
}

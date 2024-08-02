use core::future::{ready, Ready};

use std::marker::PhantomData;
use std::sync::Arc;

use bytes::Bytes;
use domain::base::iana::Rcode;
use domain::base::message_builder::AdditionalBuilder;
use domain::base::wire::Composer;
use domain::base::{Message, Name, Rtype, StreamTarget, ToName};
use domain::dep::octseq::Octets;
use domain::net::server::message::Request;
use domain::net::server::middleware::stream::{MiddlewareStream, PostprocessingStream};
use domain::net::server::service::{Service, ServiceResult};
use domain::net::server::util::mk_builder_for_target;
use domain::rdata::tsig::Time48;
use domain::tsig::{Key, ServerSequence, ServerTransaction};
use domain::zonetree::Answer;
use futures::stream::Once;

use crate::key::{DomainName, KeyStore, Keys};

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

    fn postprocess_non_axfr(
        keystore: &KeyStore,
        keys: &Keys,
        qname: &Name<Bytes>,
        message: &mut Message<Vec<u8>>,
        response: &mut AdditionalBuilder<StreamTarget<Svc::Target>>,
    ) -> Result<(), AdditionalBuilder<StreamTarget<<Svc as Service<RequestOctets>>::Target>>> {
        match ServerTransaction::request::<KeyStore, Vec<u8>>(keystore, message, Time48::now()) {
            Ok(None) => Ok(()),
            Ok(Some(transaction)) if validate_key_scope(keys, transaction.key(), qname) => {
                log::info!(target: "svc", "found tsig key for transaction");
                transaction.answer(response, Time48::now()).unwrap();
                Ok(())
            }
            Ok(_) => {
                log::error!(target: "tsig", "tsig used is not in the valid scope");
                let answer = Answer::new(Rcode::REFUSED);
                let builder = mk_builder_for_target();
                Err(answer.to_message(message, builder))
            }
            Err(e) => {
                log::error!(target: "tsig", "tsig transaction error: {}", e);
                let answer = Answer::new(Rcode::REFUSED);
                let builder = mk_builder_for_target();
                Err(answer.to_message(message, builder))
            }
        }
    }

    fn postprocess_axfr(
        keystore: &KeyStore,
        keys: &Keys,
        qname: &Name<Bytes>,
        message: &mut Message<Vec<u8>>,
        response: &mut AdditionalBuilder<StreamTarget<Svc::Target>>,
    ) -> Result<(), AdditionalBuilder<StreamTarget<<Svc as Service<RequestOctets>>::Target>>> {
        match ServerSequence::request::<KeyStore, Vec<u8>>(keystore, message, Time48::now()) {
            Ok(None) => Ok(()),
            Ok(Some(mut sequence)) if validate_key_scope(keys, sequence.key(), qname) => {
                log::info!(target: "svc", "found tsig key for transaction");
                sequence.answer(response, Time48::now()).unwrap();
                Ok(())
            }
            Ok(_) => {
                log::error!(target: "tsig", "tsig used is not in the valid scope");
                let answer = Answer::new(Rcode::REFUSED);
                let builder = mk_builder_for_target();
                Err(answer.to_message(message, builder))
            }
            Err(e) => {
                log::error!(target: "tsig", "tsig transaction error: {}", e);
                let answer = Answer::new(Rcode::REFUSED);
                let builder = mk_builder_for_target();
                Err(answer.to_message(message, builder))
            }
        }
    }

    fn postprocess(
        dnsr: Arc<crate::service::Dnsr>,
        request: &Request<RequestOctets>,
        response: &mut AdditionalBuilder<StreamTarget<Svc::Target>>,
    ) -> Result<(), AdditionalBuilder<StreamTarget<<Svc as Service<RequestOctets>>::Target>>> {
        let keystore = dnsr.keystore.read().unwrap();
        let keys = &dnsr.config.keys;
        let bytes = request.message().as_slice();
        let mut message = Message::from_octets(bytes.to_vec()).unwrap();
        let qname = request
            .message()
            .sole_question()
            .unwrap()
            .qname()
            .to_bytes();

        if !matches!(
            request
                .message()
                .sole_question()
                .map(|q| q.qtype() == Rtype::AXFR),
            Ok(true)
        ) {
            Self::postprocess_non_axfr(&keystore, keys, &qname, &mut message, response)
        } else {
            Self::postprocess_axfr(&keystore, keys, &qname, &mut message, response)
        }
    }

    fn map_stream_item(
        request: Request<RequestOctets>,
        mut stream_item: ServiceResult<Svc::Target>,
        metadata: Arc<crate::service::Dnsr>,
    ) -> ServiceResult<Svc::Target> {
        if let Ok(cr) = &mut stream_item {
            if let Some(response) = cr.response_mut() {
                if let Err(additional) = Self::postprocess(metadata, &request, response) {
                    *response = additional;
                }
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

fn validate_key_scope(keys: &Keys, key: &Key, dname: &Name<Bytes>) -> bool {
    let key_file = dbg!(key.name().into());
    let dname = Into::<DomainName>::into(dname).strip_prefix();

    dbg!(keys
        .get(&key_file)
        .map(|d| d.contains_key(&dname))
        .unwrap_or(false))
}

use core::future::{ready, Ready};

use std::collections::HashMap;
use std::marker::PhantomData;
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use domain::base::iana::Rcode;
use domain::base::message_builder::AdditionalBuilder;
use domain::base::wire::Composer;
use domain::base::{Message, Name, ParsedName, Rtype, StreamTarget, ToName, Ttl};
use domain::dep::octseq::Octets;
use domain::net::server::message::Request;
use domain::net::server::middleware::stream::{MiddlewareStream, PostprocessingStream};
use domain::net::server::service::{Service, ServiceResult};
use domain::net::server::util::mk_builder_for_target;
use domain::rdata::tsig::Time48;
use domain::rdata::{AllRecordData, ZoneRecordData};
use domain::tsig::{Key, ServerSequence, ServerTransaction};
use domain::zonetree::types::{StoredRecord, StoredRecordData};
use domain::zonetree::{Answer, Rrset};
use futures::stream::Once;
use futures::FutureExt;

use crate::key::{DomainName, KeyStore, Keys};
use crate::service::handler::HandlerResult;

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
        dnsr: Arc<crate::service::Dnsr>,
        qname: &Name<Bytes>,
        message: &mut Message<Vec<u8>>,
        response: &mut AdditionalBuilder<StreamTarget<Svc::Target>>,
    ) -> Result<(), AdditionalBuilder<StreamTarget<<Svc as Service<RequestOctets>>::Target>>> {
        let keystore = dnsr.keystore.read().unwrap();
        let keys = &dnsr.config.keys;
        let cloned_message = message.clone();
        let bytes = cloned_message.as_slice();
        let message_bytes = Message::from_octets(Bytes::copy_from_slice(bytes)).unwrap();

        match ServerTransaction::request::<KeyStore, Vec<u8>>(&keystore, message, Time48::now()) {
            Ok(None) => Ok(()),
            Ok(Some(transaction)) if validate_key_scope(keys, transaction.key(), qname) => {
                log::info!(target: "svc", "found tsig key for transaction");

                match handle_update_query(dnsr.clone(), message_bytes) {
                    Ok(_) => {
                        log::info!(target: "update", "successfully updated the zone");
                        log::debug!("{:?}", dnsr.zones);
                        transaction.answer(response, Time48::now()).unwrap();
                        Ok(())
                    }
                    Err(e) => {
                        log::error!(target: "update", "error while updating the dnsr zones: {}", e);
                        let answer = Answer::new(Rcode::SERVFAIL);
                        let builder = mk_builder_for_target();
                        Err(answer.to_message(message, builder))
                    }
                }
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
        dnsr: Arc<crate::service::Dnsr>,
        qname: &Name<Bytes>,
        message: &mut Message<Vec<u8>>,
        response: &mut AdditionalBuilder<StreamTarget<Svc::Target>>,
    ) -> Result<(), AdditionalBuilder<StreamTarget<<Svc as Service<RequestOctets>>::Target>>> {
        let keystore = dnsr.keystore.read().unwrap();
        let keys = &dnsr.config.keys;
        let cloned_message = message.clone();
        let bytes = cloned_message.as_slice();
        let message_bytes = Message::from_octets(Bytes::copy_from_slice(bytes)).unwrap();

        match ServerSequence::request::<KeyStore, Vec<u8>>(&keystore, message, Time48::now()) {
            Ok(None) => Ok(()),
            Ok(Some(mut sequence)) if validate_key_scope(keys, sequence.key(), qname) => {
                log::info!(target: "svc", "found tsig key for transaction");

                match handle_update_query(dnsr.clone(), message_bytes) {
                    Ok(_) => {
                        log::info!(target: "update", "successfully updated the zone");
                        log::debug!("{:?}", dnsr.zones);
                        sequence.answer(response, Time48::now()).unwrap();
                        Ok(())
                    }
                    Err(e) => {
                        log::error!(target: "update", "error while updating the dnsr zones: {}", e);
                        let answer = Answer::new(Rcode::SERVFAIL);
                        let builder = mk_builder_for_target();
                        Err(answer.to_message(message, builder))
                    }
                }
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
            Self::postprocess_non_axfr(dnsr, &qname, &mut message, response)
        } else {
            Self::postprocess_axfr(dnsr, &qname, &mut message, response)
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
    let key_file = key.name().into();
    let dname = Into::<DomainName>::into(dname).strip_prefix();

    keys.get(&key_file)
        .map(|d| d.contains_key(&dname))
        .unwrap_or(false)
}

fn handle_update_query(
    dnsr: Arc<crate::service::Dnsr>,
    message: Message<Bytes>,
) -> HandlerResult<()> {
    log::debug!("handle_update_query");
    let authority = message.authority()?;
    let mut records: HashMap<(Rtype, Ttl), Vec<StoredRecordData>> = HashMap::new();

    for a in authority {
        let a = a?.to_record::<AllRecordData<Bytes, ParsedName<Bytes>>>()?;

        if let Some(record) = a {
            let data: ZoneRecordData<Bytes, Name<Bytes>> = match record.data() {
                AllRecordData::Txt(txt) => txt.clone().into(),
                _ => unimplemented!(),
            };

            let record = StoredRecord::new(
                record.owner().to_bytes(),
                record.class(),
                record.ttl(),
                data,
            );
            records
                .entry((record.rtype(), record.ttl()))
                .or_default()
                .push(record.data().to_owned());
        }
    }

    let question = message.sole_question().unwrap();
    let qtype = question.qtype();
    let qname = question.qname().clone();
    let records = Arc::new(Mutex::new(records));
    let cloned_records = records.clone();

    let op = Box::new(move |owner: Name<Bytes>, rrset: &Rrset| {
        if rrset.rtype() == qtype && owner == qname {
            let mut records = cloned_records.lock().unwrap();
            records
                .entry((rrset.rtype(), rrset.ttl()))
                .or_default()
                .extend(rrset.data().to_vec());
        }
    });

    dnsr.zones.find_zone_walk(question.qname(), |zone| {
        if let Some(zone) = zone {
            zone.walk(op);
        }
    });

    let mutex = Arc::try_unwrap(records).unwrap();
    let records = mutex.into_inner().unwrap();

    // TODO: handle this lot of unwraps
    if let Some(zone) = dnsr.zones.find_zone(&question.qname()) {
        let mut writer = zone.write().now_or_never().unwrap();
        let open = writer.open().now_or_never().unwrap().unwrap();

        records.into_iter().for_each(|((rtype, ttl), data)| {
            let mut rset = Rrset::new(rtype, ttl);
            data.into_iter().for_each(|data| rset.push_data(data));
            open.update_rrset(rset.into_shared())
                .now_or_never()
                .unwrap()
                .unwrap();
        });
        writer.commit().now_or_never().unwrap().unwrap();
    }

    Ok(())
}

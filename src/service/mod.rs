use core::future::{ready, Future};

use std::pin::Pin;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::RwLock;

use domain::base::iana::Opcode;
use domain::base::iana::{Class, Rcode};
use domain::base::message_builder::AdditionalBuilder;
use domain::base::Message;
use domain::base::Name;
use domain::base::{Rtype, ToName};
use domain::dep::octseq::OctetsBuilder;
use domain::net::server::message::Request;
use domain::net::server::service::CallResult;
use domain::net::server::service::{Service, ServiceResult};
use domain::net::server::util::mk_builder_for_target;
use domain::zonetree::Rrset;
use domain::zonetree::{Answer, ReadableZone, Zone};
use futures::channel::mpsc::unbounded;
use futures::channel::mpsc::UnboundedSender;
use futures::stream::{once, Stream};

use crate::config::Config;
use crate::error::Error;
use crate::key;
use crate::zone::ZoneTree;

use self::handler::{HandleDNS, HandlerResult};
pub use self::watcher::Watcher;

mod handler;
pub mod middleware;
mod watcher;

pub type KeyStore = Arc<RwLock<key::KeyStore>>;

#[derive(Debug, Clone)]
pub struct Dnsr {
    pub config: Arc<Config>,
    pub zones: Arc<Zones>,
    pub keystore: KeyStore,
}

impl Service<Vec<u8>> for Dnsr {
    type Target = Vec<u8>;
    type Stream = Pin<Box<dyn Stream<Item = ServiceResult<Self::Target>> + Send>>;
    type Future = Pin<Box<dyn Future<Output = Self::Stream> + Send>>;

    fn call(&self, request: domain::net::server::message::Request<Vec<u8>>) -> Self::Future {
        let dnsr = self.clone();

        Box::pin(async move {
            if !matches!(
                request
                    .message()
                    .sole_question()
                    .map(|q| q.qtype() == Rtype::AXFR),
                Ok(true)
            ) {
                let transaction = dnsr.handle_non_axfr(request);
                let immediate_result = once(ready(transaction));
                return Box::pin(immediate_result) as Self::Stream;
            }

            let (sender, receiver) = unbounded();

            if let Err(e) = dnsr.handle_axfr(request, sender.clone()) {
                let _ = sender.unbounded_send(Err(e));
            }

            Box::pin(receiver) as Self::Stream
        })
    }
}

impl HandleDNS for Dnsr {
    fn handle_non_axfr(&self, request: Request<Vec<u8>>) -> HandlerResult<CallResult<Vec<u8>>> {
        let answer = {
            let question = request.message().sole_question().unwrap();
            self.zones
                .find_zone_read(question.qname(), |zone| match zone {
                    Some(zone) => {
                        let qname = question.qname().to_bytes();
                        let qtype = question.qtype();
                        zone.query(qname, qtype).unwrap()
                    }
                    None => Answer::new(Rcode::NXDOMAIN),
                })
        };

        let builder = mk_builder_for_target();
        let additional = answer.to_message(request.message(), builder);

        Ok(CallResult::new(additional))
    }

    fn handle_axfr(
        &self,
        request: Request<Vec<u8>>,
        sender: UnboundedSender<HandlerResult<CallResult<Vec<u8>>>>,
    ) -> HandlerResult<()> {
        let mut message = request.message().clone();
        let message = Arc::make_mut(&mut message);

        let request = Request::new(
            request.client_addr(),
            request.received_at(),
            message.to_owned(),
            request.transport_ctx().to_owned(),
        );

        // Look up the zone for the queried name.
        let question = request.message().sole_question().unwrap();

        if question.qclass() == Class::IN {
            let answer = Answer::new(Rcode::NXDOMAIN);
            add_to_stream(answer, request.message(), &sender);
            return Ok(());
        }

        let zone = self.zones.find_zone(question.qname());

        // If not found, return an NXDOMAIN error response.
        let Some(zone) = zone else {
            let answer = Answer::new(Rcode::NXDOMAIN);
            add_to_stream(answer, request.message(), &sender);
            return Ok(());
        };

        // https://datatracker.ietf.org/doc/html/rfc5936#section-2.2
        // 2.2: AXFR Response
        //
        // "An AXFR response that is transferring the zone's contents
        //  will consist of a series (which could be a series of
        //  length 1) of DNS messages.  In such a series, the first
        //  message MUST begin with the SOA resource record of the
        //  zone, and the last message MUST conclude with the same SOA
        //  resource record.  Intermediate messages MUST NOT contain
        //  the SOA resource record.  The AXFR server MUST copy the
        //  Question section from the corresponding AXFR query message
        //  into the first response message's Question section.  For
        //  subsequent messages, it MAY do the same or leave the
        //  Question section empty."

        // Get the SOA record as AXFR transfers must start and end with the SOA
        // record. If not found, return a SERVFAIL error response.
        let qname = question.qname().to_bytes();
        let zone = zone.read();
        let Ok(soa_answer) = zone.query(qname, Rtype::SOA) else {
            let answer = Answer::new(Rcode::SERVFAIL);
            add_to_stream(answer, request.message(), &sender);
            return Ok(());
        };

        // Push the begin SOA response message into the stream
        add_to_stream(soa_answer.clone(), request.message(), &sender);

        // "The AXFR protocol treats the zone contents as an unordered
        //  collection (or to use the mathematical term, a "set") of
        //  RRs.  Except for the requirement that the transfer must
        //  begin and end with the SOA RR, there is no requirement to
        //  send the RRs in any particular order or grouped into
        //  response messages in any particular way.  Although servers
        //  typically do attempt to send related RRs (such as the RRs
        //  forming an RRset, and the RRsets of a name) as a
        //  contiguous group or, when message space allows, in the
        //  same response message, they are not required to do so, and
        //  clients MUST accept any ordering and grouping of the
        //  non-SOA RRs.  Each RR SHOULD be transmitted only once, and
        //  AXFR clients MUST ignore any duplicate RRs received.
        //
        //  Each AXFR response message SHOULD contain a sufficient
        //  number of RRs to reasonably amortize the per-message
        //  overhead, up to the largest number that will fit within a
        //  DNS message (taking the required content of the other
        //  sections into account, as described below).
        //
        //  Some old AXFR clients expect each response message to
        //  contain only a single RR.  To interoperate with such
        //  clients, the server MAY restrict response messages to a
        //  single RR.  As there is no standard way to automatically
        //  detect such clients, this typically requires manual
        //  configuration at the server."

        let sender = Arc::new(Mutex::new(sender));
        let cloned_sender = sender.clone();
        let cloned_msg = request.message().clone();

        let op = Box::new(move |owner: Name<_>, rrset: &Rrset| {
            if rrset.rtype() != Rtype::SOA {
                let builder = mk_builder_for_target();
                let mut answer = builder.start_answer(&cloned_msg, Rcode::NOERROR).unwrap();
                for item in rrset.data() {
                    answer.push((owner.clone(), rrset.ttl(), item)).unwrap();
                }

                let additional = answer.additional();
                let sender = cloned_sender.lock().unwrap();
                add_additional_to_stream(additional, &cloned_msg, &sender);
            }
        });
        zone.walk(op);

        let mutex = Arc::try_unwrap(sender).unwrap();
        let sender = mutex.into_inner().unwrap();

        // Push the end SOA response message into the stream
        add_to_stream(soa_answer, request.message(), &sender);

        Ok(())
    }
}

fn add_to_stream(
    answer: Answer,
    msg: &Message<Vec<u8>>,
    sender: &UnboundedSender<HandlerResult<CallResult<Vec<u8>>>>,
) {
    let builder = mk_builder_for_target();
    let additional = answer.to_message(msg, builder);
    add_additional_to_stream(additional, msg, sender);
}

fn add_additional_to_stream(
    mut additional: AdditionalBuilder<domain::base::StreamTarget<Vec<u8>>>,
    msg: &Message<Vec<u8>>,
    sender: &UnboundedSender<HandlerResult<CallResult<Vec<u8>>>>,
) {
    set_axfr_header(msg, &mut additional);
    let item = Ok(CallResult::new(additional));
    sender.unbounded_send(item).unwrap();
}

fn set_axfr_header<Target>(msg: &Message<Vec<u8>>, additional: &mut AdditionalBuilder<Target>)
where
    Target: AsMut<[u8]>,
    Target: OctetsBuilder,
{
    // https://datatracker.ietf.org/doc/html/rfc5936#section-2.2.1
    // 2.2.1: Header Values
    //
    // "These are the DNS message header values for AXFR responses.
    //
    //     ID          MUST be copied from request -- see Note a)
    //
    //     QR          MUST be 1 (Response)
    //
    //     OPCODE      MUST be 0 (Standard Query)
    //
    //     Flags:
    //        AA       normally 1 -- see Note b)
    //        TC       MUST be 0 (Not truncated)
    //        RD       RECOMMENDED: copy request's value; MAY be set to 0
    //        RA       SHOULD be 0 -- see Note c)
    //        Z        "mbz" -- see Note d)
    //        AD       "mbz" -- see Note d)
    //        CD       "mbz" -- see Note d)"
    let header = additional.header_mut();
    header.set_id(msg.header().id());
    header.set_qr(true);
    header.set_opcode(Opcode::QUERY);
    header.set_aa(true);
    header.set_tc(false);
    header.set_rd(msg.header().rd());
    header.set_ra(false);
    header.set_z(false);
    header.set_ad(false);
    header.set_cd(false);
}

impl From<Arc<Config>> for Dnsr {
    fn from(config: Arc<Config>) -> Self {
        let zones = Arc::new(Arc::new(RwLock::new(ZoneTree::new())).into());
        let keystore = key::KeyStore::new_shared();

        Dnsr {
            config,
            zones,
            keystore,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Zones(Arc<RwLock<ZoneTree>>);

impl Zones {
    fn find_zone<N>(&self, qname: &N) -> Option<Zone>
    where
        N: ToName,
    {
        let zones = self.0.read().unwrap();
        zones.find_zone(qname).cloned()
    }

    fn find_zone_read<N, F>(&self, qname: &N, f: F) -> Answer
    where
        N: ToName,
        F: FnOnce(Option<Box<dyn ReadableZone>>) -> Answer,
    {
        let zones = self.0.read().unwrap();
        f(zones.find_zone(qname).map(|z| z.read()))
    }

    fn find_zone_walk<N, F>(&self, qname: &N, f: F)
    where
        N: ToName,
        F: FnOnce(Option<Box<dyn ReadableZone>>),
    {
        let zones = self.0.read().unwrap();
        f(zones.find_zone(qname).map(|z| z.read()))
    }

    fn has_zone<N>(&self, qname: &N, class: Class) -> bool
    where
        N: ToName,
    {
        if class != Class::IN {
            return false;
        }

        let zones = self.0.read().unwrap();
        zones.find_zone(qname).is_some()
    }

    pub fn insert_zone(&self, zone: Zone) -> Result<(), Error> {
        // Check if the zone already exists
        if self.has_zone(zone.apex_name(), zone.class()) {
            return Ok(());
        }

        log::info!(target: "zone_change", "adding zone {}", zone.apex_name());
        let mut zones = self.0.write().unwrap();
        zones.insert_zone(zone)
    }

    pub fn remove_zone<N>(&self, name: &N, class: Class) -> Result<(), Error>
    where
        N: ToName,
    {
        log::info!(target: "zone_change", "removing zone {} {}", name.to_bytes(), class);

        let mut zones = self.0.write().unwrap();

        for z in zones.iter_zones() {
            log::debug!(target: "zone_change", "zones present {} {}", z.apex_name(), z.class());
        }

        zones.remove_zone(name)?;

        for z in zones.iter_zones() {
            log::info!(target: "zone_change", "zones present {} {}", z.apex_name(), z.class());
        }

        Ok(())
    }
}

impl From<Arc<RwLock<ZoneTree>>> for Zones {
    fn from(value: Arc<RwLock<ZoneTree>>) -> Self {
        Zones(value)
    }
}

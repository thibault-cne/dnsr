use std::sync::{Arc, Mutex};

use domain::base::iana::{Class, Opcode, Rcode};
use domain::base::message_builder::AdditionalBuilder;
use domain::base::{Message, Name, Rtype, ToName};
use domain::dep::octseq::OctetsBuilder;
use domain::net::server::message::Request;
use domain::net::server::service::{CallResult, ServiceError};
use domain::net::server::util::mk_builder_for_target;
use domain::rdata::tsig::Time48;
use domain::tsig::{Key, ServerSequence, ServerTransaction};
use domain::zonetree::{Answer, Rrset};
use futures::channel::mpsc::UnboundedSender;

use crate::key::KeyStore;

type HandlerResult<T> = Result<T, ServiceError>;

pub trait HandleDNS {
    fn handle_non_axfr(&self, request: Request<Vec<u8>>) -> HandlerResult<CallResult<Vec<u8>>>;
    fn handle_axfr(
        &self,
        request: Request<Vec<u8>>,
        sender: UnboundedSender<HandlerResult<CallResult<Vec<u8>>>>,
    ) -> HandlerResult<()>;
}

impl HandleDNS for super::Dnsr {
    fn handle_non_axfr(&self, request: Request<Vec<u8>>) -> HandlerResult<CallResult<Vec<u8>>> {
        let answer = {
            let question = request.message().sole_question().unwrap();
            self.zones
                .find_zone_f(question.qname(), question.qclass(), |zone| match zone {
                    Some(zone) => {
                        let qname = question.qname().to_bytes();
                        let qtype = question.qtype();
                        zone.query(qname, qtype).unwrap()
                    }
                    None => Answer::new(Rcode::NXDOMAIN),
                })
        };

        let builder = mk_builder_for_target();
        let mut additional = answer.to_message(request.message(), builder);

        let keystore = self.keystore.read().unwrap();
        let mut message = request.message().clone();
        let message = Arc::make_mut(&mut message);

        match ServerTransaction::request::<KeyStore, Vec<u8>>(&keystore, message, Time48::now()) {
            Ok(None) => (),
            Ok(Some(transaction)) => {
                log::info!(target: "svc", "found tsig key for transaction");
                transaction.answer(&mut additional, Time48::now()).unwrap()
            }
            Err(e) => log::error!(target: "svc", "tsig transaction error: {}", e),
        }

        Ok(CallResult::new(additional))
    }

    fn handle_axfr(
        &self,
        request: Request<Vec<u8>>,
        sender: UnboundedSender<HandlerResult<CallResult<Vec<u8>>>>,
    ) -> HandlerResult<()> {
        let keystore = self.keystore.read().unwrap();
        let mut message = request.message().clone();
        let message = Arc::make_mut(&mut message);

        let mut server_sequence =
            match ServerSequence::request::<KeyStore, _>(&keystore, message, Time48::now()) {
                Ok(sequence) => sequence,
                _ => return Ok(()),
            };

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
            add_to_stream(server_sequence.as_mut(), answer, request.message(), &sender);
            return Ok(());
        }

        let zone = self.zones.find_zone(question.qname());

        // If not found, return an NXDOMAIN error response.
        let Some(zone) = zone else {
            let answer = Answer::new(Rcode::NXDOMAIN);
            add_to_stream(server_sequence.as_mut(), answer, request.message(), &sender);
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
            add_to_stream(server_sequence.as_mut(), answer, request.message(), &sender);
            return Ok(());
        };

        // Push the begin SOA response message into the stream
        add_to_stream(
            server_sequence.as_mut(),
            soa_answer.clone(),
            request.message(),
            &sender,
        );

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
        let server_sequence = Arc::new(Mutex::new(server_sequence));
        let cloned_server_sequence = server_sequence.clone();

        let op = Box::new(move |owner: Name<_>, rrset: &Rrset| {
            if rrset.rtype() != Rtype::SOA {
                let builder = mk_builder_for_target();
                let mut answer = builder.start_answer(&cloned_msg, Rcode::NOERROR).unwrap();
                for item in rrset.data() {
                    answer.push((owner.clone(), rrset.ttl(), item)).unwrap();
                }

                let additional = answer.additional();
                let sender = cloned_sender.lock().unwrap();
                let mut server_sequence = cloned_server_sequence.lock().unwrap();
                add_additional_to_stream(
                    server_sequence.as_mut(),
                    additional,
                    &cloned_msg,
                    &sender,
                );
            }
        });
        zone.walk(op);

        let mutex = Arc::try_unwrap(sender).unwrap();
        let sender = mutex.into_inner().unwrap();
        let mutex = Arc::try_unwrap(server_sequence).unwrap();
        let mut server_sequence = mutex.into_inner().unwrap();

        // Push the end SOA response message into the stream
        add_to_stream(
            server_sequence.as_mut(),
            soa_answer,
            request.message(),
            &sender,
        );

        Ok(())
    }
}

fn add_to_stream(
    sequence: Option<&mut ServerSequence<Arc<Key>>>,
    answer: Answer,
    msg: &Message<Vec<u8>>,
    sender: &UnboundedSender<HandlerResult<CallResult<Vec<u8>>>>,
) {
    let builder = mk_builder_for_target();
    let additional = answer.to_message(msg, builder);
    add_additional_to_stream(sequence, additional, msg, sender);
}

fn add_additional_to_stream(
    sequence: Option<&mut ServerSequence<Arc<Key>>>,
    mut additional: AdditionalBuilder<domain::base::StreamTarget<Vec<u8>>>,
    msg: &Message<Vec<u8>>,
    sender: &UnboundedSender<HandlerResult<CallResult<Vec<u8>>>>,
) {
    set_axfr_header(msg, &mut additional);
    sequence.map(|sequence| sequence.answer(&mut additional, Time48::now()));
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

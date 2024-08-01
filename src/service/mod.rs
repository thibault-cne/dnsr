use core::future::{ready, Future};

use std::pin::Pin;
use std::sync::Arc;
use std::sync::RwLock;

use domain::base::iana::{Class, Rcode};
use domain::base::{Rtype, ToName};
use domain::net::server::service::{Service, ServiceResult};
use domain::zonetree::{Answer, ReadableZone, Zone};
use futures::channel::mpsc::unbounded;
use futures::stream::{once, Stream};

use crate::config::Config;
use crate::error::Error;
use crate::key;
use crate::zone::ZoneTree;

use self::handler::HandleDNS;
pub use self::watcher::Watcher;

mod handler;
mod watcher;

pub type KeyStore = Arc<RwLock<key::KeyStore>>;

#[derive(Debug, Clone)]
pub struct Dnsr {
    pub config: Arc<Config>,
    pub zones: Zones,
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

impl From<Arc<Config>> for Dnsr {
    fn from(config: Arc<Config>) -> Self {
        let zones = Arc::new(RwLock::new(ZoneTree::new())).into();
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

    fn find_zone_f<N, F>(&self, qname: &N, class: Class, f: F) -> Answer
    where
        N: ToName,
        F: FnOnce(Option<Box<dyn ReadableZone>>) -> Answer,
    {
        if class != Class::IN {
            return Answer::new(Rcode::NXDOMAIN);
        }

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

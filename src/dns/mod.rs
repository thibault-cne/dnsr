use std::sync::{Arc, RwLock};

use domain::base::iana::{Class, Rcode};
use domain::base::ToName;

use domain::zonetree::{Answer, ReadableZone, Zone};

use crate::config::Config;
use crate::error::Error;
use crate::key::KeyStore;
use crate::zone::ZoneTree;

pub use service::dns;

mod service;

type Zones = Arc<RwLock<ZoneTree>>;

pub struct State {
    pub config: Config,
    pub zones: Zones,
    pub keystore: Arc<RwLock<KeyStore>>,
}

impl State {
    pub fn config(&self) -> &Config {
        &self.config
    }

    fn find_zone<N, F>(&self, qname: &N, class: Class, f: F) -> Answer
    where
        N: ToName,
        F: FnOnce(Option<Box<dyn ReadableZone>>) -> Answer,
    {
        if class != Class::IN {
            return Answer::new(Rcode::NXDOMAIN);
        }

        let zones = self.zones.read().unwrap();
        f(zones.find_zone(qname).map(|z| z.read()))
    }

    pub fn insert_zone(&self, zone: Zone) -> Result<(), Error> {
        log::info!(target: "zone_change", "adding zone {}", zone.apex_name());
        let mut zones = self.zones.write().unwrap();
        zones.insert_zone(zone)
    }

    pub fn remove_zone<N>(&self, name: &N, class: Class) -> Result<(), Error>
    where
        N: ToName,
    {
        log::info!(target: "zone_change", "removing zone {} {}", name.to_bytes(), class);

        let mut zones = self.zones.write().unwrap();

        for z in zones.iter_zones() {
            log::debug!(target: "zone", "zone {:?}", z);
        }

        zones.remove_zone(name)?;

        for z in zones.iter_zones() {
            log::debug!(target: "zone", "zone {}", z.apex_name());
        }

        Ok(())
    }
}

impl From<Config> for State {
    fn from(config: Config) -> Self {
        let zones = Arc::new(RwLock::new(ZoneTree::new()));
        State {
            config,
            zones,
            keystore: KeyStore::new_shared(),
        }
    }
}

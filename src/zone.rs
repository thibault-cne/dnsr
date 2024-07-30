use std::collections::HashMap;

use bytes::Bytes;
use domain::base::{name::Name, ToName};
use domain::zonetree::Zone;

use crate::error::Result;

#[derive(Debug, Default)]
pub struct ZoneTree {
    zones: HashMap<Name<Bytes>, Zone>,
}

impl ZoneTree {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn iter_zones(&self) -> impl Iterator<Item = &Zone> {
        self.zones.values()
    }

    pub fn find_zone<N>(&self, qname: &N) -> Option<&Zone>
    where
        N: ToName,
    {
        self.zones.get(&qname.to_name::<Bytes>())
    }

    pub fn insert_zone(&mut self, zone: Zone) -> Result<()> {
        match self.zones.insert(zone.apex_name().clone(), zone) {
            None => Ok(()),
            Some(_) => Err(domain::zonetree::error::ZoneTreeModificationError::ZoneExists.into()),
        }
    }

    pub fn remove_zone<N>(&mut self, name: &N) -> Result<()>
    where
        N: ToName,
    {
        match self.zones.remove(&name.to_name::<Bytes>()) {
            None => {
                Err(domain::zonetree::error::ZoneTreeModificationError::ZoneDoesNotExist.into())
            }
            Some(_) => Ok(()),
        }
    }
}

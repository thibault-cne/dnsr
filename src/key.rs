use std::collections::HashMap;
use std::ops::Deref;
use std::path::PathBuf;

use domain::base::iana::Class;
use domain::zonetree::types::StoredName;
use domain::zonetree::{Zone, ZoneBuilder};
use serde::Deserialize;

use crate::error::Result;

#[derive(Debug, Clone, Deserialize, Default)]
pub struct Keys(HashMap<KeyFile, Vec<Domain>>);

impl Deref for Keys {
    type Target = HashMap<KeyFile, Vec<Domain>>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum Domain {
    Unamed(String),
}

pub trait TryIntoZones {
    fn try_into_zones(self) -> Result<Vec<domain::zonetree::Zone>>;
}

impl TryIntoZones for &[Domain] {
    fn try_into_zones(self) -> Result<Vec<domain::zonetree::Zone>> {
        self.iter().map(|d| d.try_into()).collect()
    }
}

impl TryFrom<&Domain> for Zone {
    type Error = crate::error::Error;

    fn try_from(value: &Domain) -> Result<Self> {
        let apex_name = match value {
            Domain::Unamed(name) => StoredName::bytes_from_str(name)?,
        };
        Ok(ZoneBuilder::new(apex_name, Class::IN).build())
    }
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq, Hash)]
pub struct KeyFile(String);

impl KeyFile {
    pub fn as_pathbuf(&self) -> PathBuf {
        PathBuf::from(crate::config::TSIG_PATH).join(&self.0)
    }

    pub fn generate_key_file(&self) -> Result<()> {
        crate::tsig::generate_new_tsig(&self.as_pathbuf())
    }

    pub fn delete_key_file(&self) -> Result<()> {
        crate::tsig::delete_tsig(&self.as_pathbuf())
    }
}

impl std::fmt::Display for KeyFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

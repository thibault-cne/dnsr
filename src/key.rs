use std::collections::HashMap;
use std::ops::Deref;
use std::path::PathBuf;

use domain::base::iana::Class;
use domain::base::{Record, Serial, Ttl};
use domain::rdata::Soa;
use domain::zonetree::types::{StoredName, StoredRecord};
use domain::zonetree::{Rrset, SharedRrset, Zone, ZoneBuilder};
use serde::Deserialize;

use crate::error::Result;

#[derive(Debug, Clone, Deserialize, Default)]
pub struct Keys(HashMap<KeyFile, HashMap<String, DomainInfo>>);

impl Deref for Keys {
    type Target = HashMap<KeyFile, HashMap<String, DomainInfo>>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct DomainInfo {
    mname: String,
    rname: String,
}

pub trait TryIntoZone {
    fn try_into_zone(self) -> Result<Zone>;
}

pub trait TryIntoZones {
    fn try_into_zones(self) -> Result<Vec<domain::zonetree::Zone>>;
}

trait TryIntoStoredName {
    fn try_into_stored_name(self) -> Result<StoredName>;
}

impl TryIntoZones for &HashMap<String, DomainInfo> {
    fn try_into_zones(self) -> Result<Vec<domain::zonetree::Zone>> {
        self.iter().map(|d| d.try_into_zone()).collect()
    }
}

impl TryFrom<&DomainInfo> for SharedRrset {
    type Error = crate::error::Error;

    fn try_from(value: &DomainInfo) -> std::result::Result<Self, Self::Error> {
        let record: StoredRecord = Record::new(
            (&value.mname).try_into_stored_name()?,
            Class::IN,
            Ttl::HOUR,
            Soa::new(
                (&value.mname).try_into_stored_name()?,
                (&value.rname).try_into_stored_name()?,
                Serial::now(),
                Ttl::HOUR,
                Ttl::HOUR,
                Ttl::HOUR,
                Ttl::HOUR,
            )
            .into(),
        );
        let rset: Rrset = record.into();

        Ok(rset.into_shared())
    }
}

impl<S> TryIntoZone for (S, &DomainInfo)
where
    S: AsRef<str>,
{
    fn try_into_zone(self) -> Result<Zone> {
        let (name, info) = self;
        let mut builder = ZoneBuilder::new((&name).try_into_stored_name()?, Class::IN);
        builder.insert_rrset(&name.try_into_stored_name()?, info.try_into()?)?;
        Ok(builder.build())
    }
}

impl<S> TryIntoStoredName for S
where
    S: AsRef<str>,
{
    fn try_into_stored_name(self) -> Result<StoredName> {
        Ok(StoredName::bytes_from_str(self.as_ref())?)
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

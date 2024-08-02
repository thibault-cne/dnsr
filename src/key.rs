use core::str;
use std::collections::HashMap;
use std::ops::Deref;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::{Arc, RwLock};

use bytes::{Bytes, BytesMut};
use domain::base::iana::Class;
use domain::base::{Name, Record, Serial, ToName, Ttl};
use domain::rdata::Soa;
use domain::tsig::{Algorithm, Key, KeyName};
use domain::zonetree::types::{StoredName, StoredRecord};
use domain::zonetree::{Rrset, SharedRrset, Zone, ZoneBuilder};
use serde::Deserialize;

use crate::error::{ErrorKind, Result};

#[derive(Debug, Clone, Deserialize, Default)]
pub struct Keys(HashMap<KeyFile, HashMap<DomainName, DomainInfo>>);

impl Keys {
    pub fn keys(&self) -> Vec<&KeyFile> {
        self.0.keys().collect()
    }

    pub fn domains(&self) -> Vec<(&DomainName, &DomainInfo)> {
        let mut domains = Vec::new();
        self.0.iter().for_each(|(_, v)| {
            v.iter().for_each(|(k, v)| {
                domains.push((k, v));
            });
        });
        domains
    }
}

impl Deref for Keys {
    type Target = HashMap<KeyFile, HashMap<DomainName, DomainInfo>>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct DomainInfo {
    mname: String,
    rname: String,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq, Hash)]
pub struct DomainName(String);

impl DomainName {
    pub fn strip_prefix(self) -> Self {
        if let Some(dname) = self.0.strip_prefix("_acme-challenge.") {
            Self(dname.to_string())
        } else {
            self
        }
    }
}

pub trait TryInto<T> {
    fn try_into_t(self) -> Result<T>;
}

impl TryInto<Vec<domain::zonetree::Zone>> for &HashMap<DomainName, DomainInfo> {
    fn try_into_t(self) -> Result<Vec<domain::zonetree::Zone>> {
        self.iter().map(|d| d.try_into_t()).collect()
    }
}

impl TryFrom<&DomainInfo> for SharedRrset {
    type Error = crate::error::Error;

    fn try_from(value: &DomainInfo) -> std::result::Result<Self, Self::Error> {
        let mut owner = BytesMut::with_capacity(16 + value.mname.len());
        owner.extend_from_slice(b"_acme-challenge.");
        owner.extend_from_slice(value.mname.as_bytes());

        let record: StoredRecord = Record::new(
            owner.freeze().try_into_t()?,
            Class::IN,
            Ttl::HOUR,
            Soa::new(
                (&value.mname).try_into_t()?,
                (&value.rname).try_into_t()?,
                Serial::now(),
                Ttl::from_secs(10800),
                Ttl::HOUR,
                Ttl::from_secs(605800),
                Ttl::HOUR,
            )
            .into(),
        );
        log::debug!(target: "record", "new record created: {:?}", record);
        let rset: Rrset = record.into();

        Ok(rset.into_shared())
    }
}

impl TryInto<Zone> for (&DomainName, &DomainInfo) {
    fn try_into_t(self) -> Result<Zone> {
        let (name, info) = self;
        let mut builder = ZoneBuilder::new(name.try_into_t()?, Class::IN);
        builder.insert_rrset(&name.try_into_t()?, info.try_into()?)?;
        let zone = builder.build();
        log::debug!(target: "zone", "new zone created: {:?}", zone);
        Ok(zone)
    }
}

impl TryInto<StoredName> for &DomainName {
    fn try_into_t(self) -> Result<StoredName> {
        let mut owner = BytesMut::with_capacity(16 + self.0.len());
        owner.extend_from_slice(b"_acme-challenge.");
        owner.extend_from_slice(self.0.as_bytes());

        owner.freeze().try_into_t()
    }
}

impl From<&Name<Bytes>> for DomainName {
    fn from(value: &Name<Bytes>) -> Self {
        DomainName(value.to_string())
    }
}

impl<B> TryInto<StoredName> for B
where
    B: AsRef<[u8]>,
{
    fn try_into_t(self) -> Result<StoredName> {
        let str = str::from_utf8(self.as_ref())?;
        Ok(StoredName::bytes_from_str(str)?)
    }
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq, Hash)]
pub struct KeyFile(String);

impl KeyFile {
    pub fn as_pathbuf(&self) -> PathBuf {
        PathBuf::from(crate::config::TSIG_PATH).join(&self.0)
    }

    pub fn generate_key_file(&self) -> Result<Key> {
        crate::tsig::generate_new_tsig(&self.as_pathbuf(), self)
    }

    pub fn load_key(&self) -> Result<Key> {
        crate::tsig::load_tsig(&self.as_pathbuf(), self)
    }

    pub fn delete_key_file(&self) -> Result<()> {
        crate::tsig::delete_tsig(&self.as_pathbuf())
    }
}

impl TryFrom<&KeyFile> for KeyName {
    type Error = crate::error::Error;

    fn try_from(kf: &KeyFile) -> Result<Self> {
        Ok(KeyName::from_str(&kf.0)?)
    }
}

impl From<&KeyName> for KeyFile {
    fn from(kn: &KeyName) -> Self {
        Self(kn.to_string())
    }
}

impl TryFrom<&KeyFile> for (KeyName, Algorithm) {
    type Error = crate::error::Error;

    fn try_from(kf: &KeyFile) -> Result<Self> {
        Ok((kf.try_into()?, Algorithm::Sha512))
    }
}

impl std::fmt::Display for KeyFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Debug, Clone)]
pub struct KeyStore {
    keys: HashMap<(KeyName, Algorithm), Arc<Key>>,
}

impl KeyStore {
    pub fn new_shared() -> Arc<RwLock<Self>> {
        Arc::new(RwLock::new(Self {
            keys: HashMap::new(),
        }))
    }

    pub fn remove_key(&mut self, key: &KeyFile) -> Result<()> {
        if self.keys.remove(&key.try_into()?).is_some() {
            key.delete_key_file()?;
        }
        Ok(())
    }

    pub fn add_key(&mut self, key: &KeyFile) -> Result<()> {
        let k = match key.generate_key_file() {
            Ok(key) => key,
            Err(e) if e.kind == ErrorKind::TSIGFileAlreadyExist => {
                log::info!(target: "tsig_file", "tsig key {} already exists - skipping", key);
                key.load_key()?
            }
            Err(e) => return Err(e),
        };
        self.keys.insert(key.try_into()?, Arc::new(k));
        Ok(())
    }
}

impl domain::tsig::KeyStore for KeyStore {
    type Key = Arc<Key>;

    fn get_key<N>(&self, name: &N, algorithm: Algorithm) -> Option<Self::Key>
    where
        N: ToName,
    {
        self.keys.get_key(name, algorithm)
    }
}

impl Deref for KeyStore {
    type Target = HashMap<(KeyName, Algorithm), Arc<Key>>;

    fn deref(&self) -> &Self::Target {
        &self.keys
    }
}

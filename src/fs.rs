use std::fs::File;
use std::sync::mpsc::channel;
use std::sync::{Arc, RwLock};

use convert_case::Casing;
use domain::base::iana::Class;
use domain::zonetree::error::ZoneTreeModificationError;
use domain::zonetree::types::StoredName;
use domain::zonetree::{Zone, ZoneBuilder, ZoneTree};
use notify::{Config, RecommendedWatcher, RecursiveMode, Watcher as NotifyWatcher};
use serde::Deserialize;

use crate::error::{ErrorKind, Result};

pub struct Watcher;

impl Watcher {
    pub fn watch_lock(zones: Arc<RwLock<ZoneTree>>) -> Result<()> {
        // Retrieve path
        let fname = std::env::var("DOMAIN_FILE").unwrap_or("domains.yml".to_string());
        let path = std::path::Path::new(&fname).to_owned();

        // Initialize the watcher
        let (tx, rx) = channel();
        let mut watcher = Box::new(RecommendedWatcher::new(tx, Config::default())?);
        watcher.watch(&path, RecursiveMode::NonRecursive)?;

        // Initialize the dns zones
        let mut domains = initialize_dns_zones(&path, &zones)?;

        while rx.recv().is_ok() {
            let new_domains = serde_yaml::from_reader::<File, Domains>(File::open(&path)?)?;

            handle_file_change(&domains.domains, &new_domains.domains, &zones)?;

            domains = new_domains;
        }

        Ok(())
    }
}

fn initialize_dns_zones(
    domain_path: &std::path::Path,
    zones: &Arc<RwLock<ZoneTree>>,
) -> Result<Domains> {
    let key_folder = std::env::var("TSIG_KEY_FOLDER").unwrap_or("keys".to_string());
    let path = std::path::Path::new(&key_folder);

    // Create the key folder if it does not exist
    if !path.is_dir() {
        std::fs::create_dir(path)?;
    }

    let mut z = zones.write().unwrap();

    let domains = serde_yaml::from_reader::<File, Domains>(File::open(domain_path)?)?;
    domains.domains.iter().try_for_each(|d| -> Result<()> {
        let zone: Zone = d.try_into()?;
        z.insert_zone(zone)?;

        // If the TSIG key does not exist, create it
        match crate::tsig::generate_new_tsig(&format!("{}/{}", key_folder, d.file_name())) {
            Ok(()) => (),
            Err(e) if e.kind == ErrorKind::TSIGFileAlreadyExist => {
                log::info!(target: "tsig_file",
                    "TSIG key already exists for domain {} - skipping",
                    d.domain_name()
                );
            }
            Err(e) => return Err(e),
        }

        Ok(())
    })?;
    Ok(domains)
}

fn handle_file_change(
    old_domains: &[Domain],
    new_domains: &[Domain],
    zones: &Arc<RwLock<ZoneTree>>,
) -> Result<()> {
    let key_folder = std::env::var("TSIG_KEY_FOLDER").unwrap_or("keys".to_string());
    let deleted_domains = old_domains.iter().filter(|d| !new_domains.contains(d));
    let added_domains = new_domains.iter().filter(|d| !old_domains.contains(d));
    let mut z = zones.write().unwrap();

    for d in deleted_domains {
        let zone: Zone = d.try_into()?;
        match z.remove_zone(zone.apex_name(), zone.class()) {
            Ok(_) => (),
            Err(ZoneTreeModificationError::ZoneExists) => (),
            Err(e) => return Err(e.into()),
        }
        // # Try to delete the TSIG key
        crate::tsig::delete_tsig(&format!("{}/{}", key_folder, d.file_name()))?;
    }

    for d in added_domains {
        let zone: Zone = d.try_into()?;
        match z.insert_zone(zone) {
            Ok(_) => (),
            Err(ZoneTreeModificationError::ZoneExists) => (),
            Err(e) => return Err(e.into()),
        }
        // # Try to create the TSIG key
        crate::tsig::generate_new_tsig(&format!("{}/{}", key_folder, d.file_name()))?;
    }

    Ok(())
}

#[derive(Deserialize)]
pub struct Domains {
    domains: Vec<Domain>,
}

#[derive(Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum Domain {
    Unamed(String),
    Named { name: String },
}

impl Domain {
    fn domain_name(&self) -> &str {
        match self {
            Self::Unamed(name) => name,
            Self::Named { name } => name,
        }
    }

    fn file_name(&self) -> String {
        match self {
            Self::Unamed(name) => name.to_case(convert_case::Case::Snake),
            Self::Named { name } => name.to_case(convert_case::Case::Snake),
        }
    }
}

impl TryFrom<Domain> for Zone {
    type Error = crate::error::Error;

    fn try_from(value: Domain) -> Result<Self> {
        let apex_name = match value {
            Domain::Named { name } => StoredName::from_chars(name.chars())?,
            Domain::Unamed(name) => StoredName::from_chars(name.chars())?,
        };
        Ok(ZoneBuilder::new(apex_name, Class::IN).build())
    }
}

impl TryFrom<&Domain> for Zone {
    type Error = crate::error::Error;

    fn try_from(value: &Domain) -> Result<Self> {
        let apex_name = match value {
            Domain::Named { name } => StoredName::from_chars(name.chars())?,
            Domain::Unamed(name) => StoredName::from_chars(name.chars())?,
        };
        Ok(ZoneBuilder::new(apex_name, Class::IN).build())
    }
}

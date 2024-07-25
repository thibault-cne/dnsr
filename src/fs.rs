use std::fs::File;
use std::sync::mpsc::channel;
use std::sync::{Arc, RwLock};

use domain::base::iana::Class;
use domain::zonetree::error::ZoneTreeModificationError;
use domain::zonetree::types::StoredName;
use domain::zonetree::{Zone, ZoneBuilder, ZoneTree};
use notify::{Config, RecommendedWatcher, RecursiveMode, Watcher as NotifyWatcher};
use serde::Deserialize;

use crate::error::Result;

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
        let mut domains = {
            let mut z = zones.write().unwrap();

            let domains = serde_yaml::from_reader::<File, Domains>(File::open(&path)?)?;
            domains.domains.iter().try_for_each(|d| -> Result<()> {
                let zone: Zone = d.try_into()?;
                z.insert_zone(zone)?;
                Ok(())
            })?;
            domains
        };

        while rx.recv().is_ok() {
            let new_domains = serde_yaml::from_reader::<File, Domains>(File::open(&path)?)?;

            handle_file_change(&domains.domains, &new_domains.domains, &zones)?;

            domains = new_domains;
        }

        Ok(())
    }
}

fn handle_file_change(
    old_domains: &[Domain],
    new_domains: &[Domain],
    zones: &Arc<RwLock<ZoneTree>>,
) -> Result<()> {
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
    }

    for d in added_domains {
        let zone: Zone = d.try_into()?;
        match z.insert_zone(zone) {
            Ok(_) => (),
            Err(ZoneTreeModificationError::ZoneExists) => (),
            Err(e) => return Err(e.into()),
        }
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

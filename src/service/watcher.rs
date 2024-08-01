use std::fs::File;
use std::path::Path;
use std::sync::mpsc::channel;
use std::sync::Arc;

use notify::{Config, RecommendedWatcher, RecursiveMode, Watcher as NotifyWatcher};

use crate::error::Result;
use crate::key::{DomainInfo, DomainName, KeyFile, Keys, TryInto};

pub trait Watcher {
    fn watch_lock(&self) -> Result<()>;
}

impl Watcher for super::Dnsr {
    fn watch_lock(&self) -> Result<()> {
        // Retrieve path
        let file_path = crate::config::Config::config_file_path();
        let path = Path::new(&file_path);

        // Initialize the watcher
        let (tx, rx) = channel();
        let mut watcher = Box::new(RecommendedWatcher::new(tx, Config::default())?);
        watcher.watch(path, RecursiveMode::NonRecursive)?;

        // Initialize the dns zones
        initialize_dns_zones(&self.config, &self.zones, &self.keystore)?;
        let mut keys = self.config.keys.clone();

        while rx.recv().is_ok() {
            keys = handle_file_change(&keys, path, &self.keystore, &self.zones)?;
        }

        Ok(())
    }
}

fn initialize_dns_zones(
    config: &Arc<crate::config::Config>,
    zones: &super::Zones,
    keystore: &super::KeyStore,
) -> Result<()> {
    {
        // Create the key folder if it does not exist
        let path = config.tsig_path();
        if !path.is_dir() {
            std::fs::create_dir(path)?;
        }
    }

    for (k, v) in config.keys.iter() {
        v.try_into_t()?.into_iter().try_for_each(|z| {
            {
                let mut keystore = keystore.write().unwrap();
                keystore.add_key(k)?;
            }

            zones.insert_zone(z)
        })?;
    }

    Ok(())
}

fn handle_file_change(
    keys: &Keys,
    config_path: &Path,
    keystore: &super::KeyStore,
    zones: &super::Zones,
) -> Result<Keys> {
    let new_config =
        serde_yaml::from_reader::<File, crate::config::Config>(File::open(config_path)?)?;
    log::debug!(target: "config_file", "new config loaded {:?}", new_config);
    let loaded_keys = new_config.keys;

    let new_domains = loaded_keys.domains();
    let old_domains = keys.domains();
    let new_keys = loaded_keys.keys();
    let old_keys = keys.keys();

    handle_keys_change(keystore, &old_keys, &new_keys)?;
    handle_domains_change(zones, &old_domains, &new_domains)?;

    Ok(loaded_keys)
}

fn handle_keys_change(
    keystore: &super::KeyStore,
    old_keys: &[&KeyFile],
    new_keys: &[&KeyFile],
) -> Result<()> {
    let mut deleted_keys = old_keys.iter().filter(|k| !new_keys.contains(k));
    let mut added_keys = new_keys.iter().filter(|k| !old_keys.contains(k));

    deleted_keys.try_for_each(|&k| -> Result<()> {
        let mut keystore = keystore.write().unwrap();
        keystore.remove_key(k)?;

        Ok(())
    })?;

    added_keys.try_for_each(|&k| -> Result<()> {
        let mut keystore = keystore.write().unwrap();
        keystore.add_key(k)?;

        Ok(())
    })?;

    Ok(())
}

fn handle_domains_change(
    zones: &super::Zones,
    old_domains: &[(&DomainName, &DomainInfo)],
    new_domains: &[(&DomainName, &DomainInfo)],
) -> Result<()> {
    let mut deleted_domains = old_domains.iter().filter(|d| !new_domains.contains(d));
    let mut added_domains = new_domains.iter().filter(|d| !old_domains.contains(d));
    let mut modified_domains = new_domains
        .iter()
        .filter(|(n, _)| old_domains.iter().any(|(o, _)| n == o));

    deleted_domains.try_for_each(|d| -> Result<()> {
        let z = d.try_into_t()?;
        zones.remove_zone(z.apex_name(), z.class())?;
        Ok(())
    })?;

    added_domains.try_for_each(|d| -> Result<()> {
        let z = d.try_into_t()?;
        zones.insert_zone(z)?;
        Ok(())
    })?;

    modified_domains.try_for_each(|d| -> Result<()> {
        let z = d.try_into_t()?;
        zones.remove_zone(z.apex_name(), z.class())?;
        zones.insert_zone(z)?;
        Ok(())
    })?;

    Ok(())
}

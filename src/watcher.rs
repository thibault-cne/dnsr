use std::fs::File;
use std::path::Path;
use std::sync::mpsc::channel;
use std::sync::Arc;

use notify::{Config, RecommendedWatcher, RecursiveMode, Watcher as NotifyWatcher};

use crate::dns::State;
use crate::error::Result;
use crate::key::{DomainInfo, DomainName, KeyFile, Keys, TryInto};

#[derive(Debug, Clone)]
pub struct Watcher;

impl Watcher {
    pub fn watch_lock(mut keys: Keys, state: Arc<State>) -> Result<()> {
        // Retrieve path
        let file_path = crate::config::Config::config_file_path();
        let path = Path::new(&file_path);

        // Initialize the watcher
        let (tx, rx) = channel();
        let mut watcher = Box::new(RecommendedWatcher::new(tx, Config::default())?);
        watcher.watch(path, RecursiveMode::NonRecursive)?;

        // Initialize the dns zones
        initialize_dns_zones(&keys, &state)?;

        while rx.recv().is_ok() {
            keys = handle_file_change(&keys, path, &state)?;
        }

        Ok(())
    }
}

fn initialize_dns_zones(keys: &Keys, state: &Arc<State>) -> Result<()> {
    {
        // Create the key folder if it does not exist
        let path = state.config().tsig_path();
        if !path.is_dir() {
            std::fs::create_dir(path)?;
        }
    }

    for (k, v) in keys.iter() {
        v.try_into_t()?.into_iter().try_for_each(|z| {
            {
                let mut keystore = state.keystore.write().unwrap();
                keystore.add_key(k)?;
            }

            state.insert_zone(z)
        })?;
    }

    Ok(())
}

fn handle_file_change(keys: &Keys, config_path: &Path, state: &Arc<State>) -> Result<Keys> {
    let mut new_config =
        serde_yaml::from_reader::<File, crate::config::Config>(File::open(config_path)?)?;
    log::debug!(target: "config_file", "new config {:?}", new_config);
    let loaded_keys = new_config.take_keys().unwrap_or_default();

    let new_domains = loaded_keys.domains();
    let old_domains = keys.domains();
    let new_keys = loaded_keys.keys();
    let old_keys = keys.keys();

    handle_keys_change(state, &old_keys, &new_keys)?;
    handle_domains_change(state, &old_domains, &new_domains)?;

    Ok(loaded_keys)
}

fn handle_keys_change(
    state: &Arc<State>,
    old_keys: &[&KeyFile],
    new_keys: &[&KeyFile],
) -> Result<()> {
    let mut deleted_keys = old_keys.iter().filter(|k| !new_keys.contains(k));
    let mut added_keys = new_keys.iter().filter(|k| !old_keys.contains(k));

    deleted_keys.try_for_each(|&k| -> Result<()> {
        let mut keystore = state.keystore.write().unwrap();
        keystore.remove_key(k)?;

        Ok(())
    })?;

    added_keys.try_for_each(|&k| -> Result<()> {
        let mut keystore = state.keystore.write().unwrap();
        keystore.add_key(k)?;

        Ok(())
    })?;

    Ok(())
}

fn handle_domains_change(
    state: &Arc<State>,
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
        state.remove_zone(z.apex_name(), z.class())?;
        Ok(())
    })?;

    added_domains.try_for_each(|d| -> Result<()> {
        let z = d.try_into_t()?;
        state.insert_zone(z)?;
        Ok(())
    })?;

    modified_domains.try_for_each(|d| -> Result<()> {
        let z = d.try_into_t()?;
        state.remove_zone(z.apex_name(), z.class())?;
        state.insert_zone(z)?;
        Ok(())
    })?;

    Ok(())
}

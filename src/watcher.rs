use std::collections::HashMap;
use std::fs::File;
use std::path::Path;
use std::sync::mpsc::channel;
use std::sync::Arc;

use domain::zonetree::Zone;
use notify::{Config, RecommendedWatcher, RecursiveMode, Watcher as NotifyWatcher};

use crate::dns::State;
use crate::error::{ErrorKind, Result};
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
        v.try_into_t()?
            .into_iter()
            .try_for_each(|z| state.insert_zone(z))?;
        match k.generate_key_file() {
            Ok(()) => (),
            Err(e) if e.kind == ErrorKind::TSIGFileAlreadyExist => {
                log::info!(target: "tsig_file",
                    "TSIG key {} already exists - skipping",
                    k
                );
            }
            Err(e) => return Err(e),
        }
    }

    Ok(())
}

fn handle_file_change(keys: &Keys, config_path: &Path, state: &Arc<State>) -> Result<Keys> {
    let mut new_config =
        serde_yaml::from_reader::<File, crate::config::Config>(File::open(config_path)?)?;
    log::debug!(target: "config_file", "new config {:?}", new_config);
    let new_keys = new_config.take_keys().unwrap_or_default();

    let deleted_keys = keys.iter().filter(|(k, _)| !new_keys.contains_key(k));
    let added_keys = new_keys.iter().filter(|(k, _)| !keys.contains_key(k));
    let modified_keys = new_keys
        .iter()
        .filter(|(k, v)| keys.contains_key(k) && keys.get(k) != Some(v))
        .map(|(k, v)| (v, keys.get(k).unwrap()));

    handle_deleted_keys(state, deleted_keys)?;
    handle_added_keys(state, added_keys)?;
    handle_modified_keys(state, modified_keys)?;

    Ok(new_keys)
}

fn handle_deleted_keys<'i, I>(state: &Arc<State>, deleted_keys: I) -> Result<()>
where
    I: IntoIterator<Item = (&'i KeyFile, &'i HashMap<DomainName, DomainInfo>)>,
{
    for (k, v) in deleted_keys {
        v.try_into_t()?.into_iter().for_each(|z| {
            let _ = state.remove_zone(z.apex_name(), z.class());
        });

        // # Try to delete the TSIG key
        k.delete_key_file()?;
    }

    Ok(())
}

fn handle_added_keys<'i, I>(state: &Arc<State>, added_keys: I) -> Result<()>
where
    I: IntoIterator<Item = (&'i KeyFile, &'i HashMap<DomainName, DomainInfo>)>,
{
    for (k, v) in added_keys {
        v.try_into_t()?.into_iter().for_each(|z| {
            let _ = state.insert_zone(z);
        });

        // # Try to create the TSIG key
        k.generate_key_file()?;
    }

    Ok(())
}

fn handle_modified_keys<'i, I>(state: &Arc<State>, modified_keys: I) -> Result<()>
where
    I: IntoIterator<
        Item = (
            &'i HashMap<DomainName, DomainInfo>,
            &'i HashMap<DomainName, DomainInfo>,
        ),
    >,
{
    for (nv, ov) in modified_keys {
        ov.iter()
            .filter(|&(d, _)| nv.get(d).is_none())
            .try_for_each(|d| -> Result<()> {
                let zone: Zone = d.try_into_t()?;
                let _ = state.remove_zone(zone.apex_name(), zone.class());
                Ok(())
            })?;
        nv.iter()
            .filter(|&(d, _)| ov.get(d).is_none())
            .try_for_each(|d| -> Result<()> {
                let zone: Zone = d.try_into_t()?;
                let _ = state.insert_zone(zone);
                Ok(())
            })?;
    }

    Ok(())
}

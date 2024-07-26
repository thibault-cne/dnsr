use std::path::Path;

use serde::Deserialize;

use crate::error::Result;

#[derive(Deserialize, Clone)]
pub struct Config {
    pub tsig_folder: String,
    pub domain_file: String,
    pub log: LogConfig,
}

impl Config {
    pub fn domain_path(&self) -> &Path {
        Path::new(&self.domain_file)
    }

    pub fn tsig_folder(&self) -> &str {
        &self.tsig_folder
    }

    pub fn tsig_path(&self) -> &Path {
        Path::new(&self.tsig_folder)
    }
}

impl TryFrom<&Vec<u8>> for Config {
    type Error = crate::error::Error;

    fn try_from(value: &Vec<u8>) -> Result<Self> {
        Ok(serde_yaml::from_slice(value)?)
    }
}

#[derive(Deserialize, Clone, Copy)]
pub struct LogConfig {
    #[serde(deserialize_with = "de_level_filter")]
    pub level: log::LevelFilter,
}

fn de_level_filter<'de, D>(deserializer: D) -> std::result::Result<log::LevelFilter, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s: LevelFilter = Deserialize::deserialize(deserializer)?;
    match s {
        LevelFilter::Off => Ok(log::LevelFilter::Off),
        LevelFilter::Error => Ok(log::LevelFilter::Error),
        LevelFilter::Warn => Ok(log::LevelFilter::Warn),
        LevelFilter::Info => Ok(log::LevelFilter::Info),
        LevelFilter::Debug => Ok(log::LevelFilter::Debug),
        LevelFilter::Trace => Ok(log::LevelFilter::Trace),
    }
}

#[derive(Deserialize)]
enum LevelFilter {
    Off,
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

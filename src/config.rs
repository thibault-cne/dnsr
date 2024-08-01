use std::path::Path;

use serde::Deserialize;

use crate::error::Result;
use crate::key::Keys;

pub const TSIG_PATH: &str = "/etc/dnsr/keys";
pub const BASE_CONFIG_FILE: &str = "/etc/dnsr/config.yml";

#[derive(Deserialize, Clone, Debug)]
pub struct Config {
    pub log: LogConfig,
    pub keys: Keys,
}

impl Config {
    pub fn config_file_path() -> String {
        std::env::var("DNSR_CONFIG").unwrap_or(BASE_CONFIG_FILE.into())
    }

    pub fn tsig_path(&self) -> &Path {
        Path::new(TSIG_PATH)
    }
}

impl TryFrom<&Vec<u8>> for Config {
    type Error = crate::error::Error;

    fn try_from(value: &Vec<u8>) -> Result<Self> {
        Ok(serde_yaml::from_slice(value)?)
    }
}

#[derive(Deserialize, Clone, Copy, Debug)]
pub struct LogConfig {
    #[serde(deserialize_with = "de_level_filter")]
    pub level: log::LevelFilter,
    pub enable_udp_metrics: bool,
    pub enable_tcp_metrics: bool,
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
#[serde(rename_all = "lowercase")]
enum LevelFilter {
    Off,
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

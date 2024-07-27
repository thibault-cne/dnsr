use std::path::Path;

use serde::Deserialize;

use crate::error::Result;

pub const BASE_TSIG_PATH: &str = "/etc/dnsr/keys";
pub const BASE_CONFIG_FILE: &str = "/etc/dnsr/config.yml";
pub const BASE_DOMAIN_FILE: &str = "/etc/dnsr/domains.yml";

#[derive(Deserialize, Clone)]
pub struct Config {
    pub tsig_path: Option<String>,
    pub domain_path: Option<String>,
    pub log: LogConfig,
}

impl Config {
    pub fn tsig_folder(&self) -> &str {
        self.tsig_path.as_deref().unwrap_or(BASE_TSIG_PATH)
    }

    pub fn domain_folder(&self) -> &str {
        self.domain_path.as_deref().unwrap_or(BASE_DOMAIN_FILE)
    }

    pub fn domain_path(&self) -> &Path {
        Path::new(self.domain_folder())
    }

    pub fn tsig_path(&self) -> &Path {
        Path::new(self.tsig_folder())
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

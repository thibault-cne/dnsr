use std::path::Path;

use serde::Deserialize;

use crate::error::Result;
use crate::key::Keys;

pub const TSIG_PATH: &str = "/etc/dnsr/keys";
pub const BASE_CONFIG_FILE: &str = "/etc/dnsr/config.yml";

#[derive(Deserialize, Clone, Debug)]
pub struct Config {
    log: Option<LogConfig>,

    pub keys: Keys,
}

impl Config {
    pub fn config_file_path() -> String {
        std::env::var("DNSR_CONFIG").unwrap_or(BASE_CONFIG_FILE.into())
    }

    pub fn tsig_path(&self) -> &Path {
        Path::new(TSIG_PATH)
    }

    pub fn log_config(&self) -> LogConfig {
        self.log.unwrap_or_default()
    }
}

impl TryFrom<&Vec<u8>> for Config {
    type Error = crate::error::Error;

    fn try_from(value: &Vec<u8>) -> Result<Self> {
        Ok(serde_yaml::from_slice(value)?)
    }
}

#[derive(Deserialize, Default, Clone, Copy, Debug)]
pub struct LogConfig {
    #[serde(deserialize_with = "de_opt_level_filter")]
    level: Option<log::LevelFilter>,
    enable_metrics: Option<bool>,
    enable_thread_id: Option<bool>,
    stderr: Option<bool>,
}

impl LogConfig {
    pub fn level(&self) -> log::LevelFilter {
        self.level.unwrap_or(log::LevelFilter::Info)
    }

    pub fn enable_metrics(&self) -> bool {
        self.enable_metrics.unwrap_or(true)
    }

    pub fn enable_thread_id(&self) -> bool {
        self.enable_thread_id.unwrap_or(false)
    }

    pub fn stderr(&self) -> bool {
        self.stderr.unwrap_or(false)
    }
}

fn de_opt_level_filter<'de, D>(
    deserializer: D,
) -> std::result::Result<Option<log::LevelFilter>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s: Option<LevelFilter> = Deserialize::deserialize(deserializer)?;
    let Some(s) = s else {
        return Ok(None);
    };
    match s {
        LevelFilter::Off => Ok(Some(log::LevelFilter::Off)),
        LevelFilter::Error => Ok(Some(log::LevelFilter::Error)),
        LevelFilter::Warn => Ok(Some(log::LevelFilter::Warn)),
        LevelFilter::Info => Ok(Some(log::LevelFilter::Info)),
        LevelFilter::Debug => Ok(Some(log::LevelFilter::Debug)),
        LevelFilter::Trace => Ok(Some(log::LevelFilter::Trace)),
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

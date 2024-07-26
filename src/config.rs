use serde::Deserialize;

use crate::error;
use crate::error::Result;

#[derive(Deserialize, Clone, Copy)]
pub struct Config<'c> {
    pub tsig_folder: &'c str,
    pub domain_file: &'c str,
    pub log: LogConfig,
}

impl<'c> TryFrom<&'c Vec<u8>> for Config<'c> {
    type Error = crate::error::Error;

    fn try_from(value: &'c Vec<u8>) -> Result<Self> {
        Ok(serde_yaml::from_slice(value)?)
    }
}

#[derive(Deserialize, Clone, Copy)]
pub struct LogConfig {
    #[serde(deserialize_with = "de_level_filter")]
    pub level: log::LevelFilter,
    pub color: bool,
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

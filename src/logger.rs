//! This crate is strongly inspired by the [simple_logger](https://docs.rs/simple_logger/latest/simple_logger/) crate
//! This just uses less/other dependancies to keep the dependencies as low as possible on the project.

use log::{LevelFilter, Log, Metadata, Record, SetLoggerError};

pub struct Logger {
    /// The default logging level
    default_level: LevelFilter,

    /// The specific logging level for each module
    ///
    /// This is used to override the default value for some specific modules.
    module_levels: Vec<(String, LevelFilter)>,

    /// Whether to include thread names (and IDs) or not
    threads: bool,

    /// Whether to log on stderr or stdout
    stderr: bool,

    /// Whether to log metrics or not
    metrics: bool,
}

impl Logger {
    pub fn new() -> Logger {
        Logger {
            default_level: LevelFilter::Trace,
            module_levels: Vec::new(),
            threads: false,
            stderr: false,
            metrics: true,
        }
    }

    pub fn with_level(mut self, level: LevelFilter) -> Logger {
        self.default_level = level;
        self
    }

    pub fn with_metrics(mut self, metrics: bool) -> Logger {
        self.metrics = metrics;
        self
    }

    pub fn with_thread(mut self, threads: bool) -> Logger {
        self.threads = threads;
        self
    }

    pub fn with_stderr(mut self, stderr: bool) -> Logger {
        self.stderr = stderr;
        self
    }

    /// Configure the logger
    pub fn max_level(&self) -> LevelFilter {
        let max_level = self
            .module_levels
            .iter()
            .map(|(_name, level)| level)
            .copied()
            .max();
        max_level
            .map(|lvl| lvl.max(self.default_level))
            .unwrap_or(self.default_level)
    }

    /// 'Init' the actual logger and instantiate it,
    /// this method MUST be called in order for the logger to be effective.
    pub fn init(self) -> Result<(), SetLoggerError> {
        log::set_max_level(self.max_level());
        log::set_boxed_logger(Box::new(self))
    }
}

impl Default for Logger {
    fn default() -> Self {
        Logger::new()
    }
}

impl Log for Logger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        &metadata.level().to_level_filter()
            <= self
                .module_levels
                .iter()
                /* At this point the Vec is already sorted so that we can simply take
                 * the first match
                 */
                .find(|(name, _level)| metadata.target().starts_with(name))
                .map(|(_name, level)| level)
                .unwrap_or(&self.default_level)
            && (self.metrics || metadata.target() != "metrics")
    }

    fn log(&self, record: &Record) {
        if self.enabled(record.metadata()) {
            let level_string = format!("{:<5}", record.level().to_string());

            let target = if !record.target().is_empty() {
                record.target()
            } else {
                record.module_path().unwrap_or_default()
            };

            let thread = {
                if self.threads {
                    let thread = std::thread::current();

                    format!("@{}", { thread.name().unwrap_or("?") })
                } else {
                    "".to_string()
                }
            };

            let message = format!("{} [{}{}] {}", level_string, target, thread, record.args());

            if self.stderr {
                eprintln!("{}", message);
            } else {
                println!("{}", message);
            }
        }
    }

    fn flush(&self) {}
}

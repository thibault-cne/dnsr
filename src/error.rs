pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Clone)]
pub struct Error {
    pub kind: ErrorKind,
    pub message: Option<String>,
}

#[derive(Debug, Clone, Copy)]
pub enum ErrorKind {
    Notify,
    SerdeYaml,
    DomainStr,
    DomainZone,
    Io,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.message {
            Some(message) => write!(f, "{}", message),
            None => self.kind.fmt(f),
        }
    }
}

impl std::fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use ErrorKind::*;

        match self {
            Notify => write!(f, "notify error"),
            SerdeYaml => write!(f, "serde yaml error"),
            DomainStr => write!(f, "invalid domain name"),
            DomainZone => write!(f, "domain zone error"),
            Io => write!(f, "io error"),
        }
    }
}

impl From<notify::Error> for Error {
    fn from(value: notify::Error) -> Self {
        Self {
            kind: ErrorKind::Notify,
            message: Some(value.to_string()),
        }
    }
}

impl From<serde_yaml::Error> for Error {
    fn from(value: serde_yaml::Error) -> Self {
        Self {
            kind: ErrorKind::SerdeYaml,
            message: Some(value.to_string()),
        }
    }
}

impl From<domain::base::name::FromStrError> for Error {
    fn from(value: domain::base::name::FromStrError) -> Self {
        Self {
            kind: ErrorKind::DomainStr,
            message: Some(value.to_string()),
        }
    }
}

impl From<domain::zonetree::error::ZoneTreeModificationError> for Error {
    fn from(value: domain::zonetree::error::ZoneTreeModificationError) -> Self {
        Self {
            kind: ErrorKind::DomainZone,
            message: Some(value.to_string()),
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(value: std::io::Error) -> Self {
        Self {
            kind: ErrorKind::Io,
            message: Some(value.to_string()),
        }
    }
}

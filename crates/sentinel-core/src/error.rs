use std::path::PathBuf;

/// Project-wide result type.
pub type SentinelResult<T> = Result<T, SentinelError>;

/// Recoverable errors produced by collectors, detectors, storage, and CLI code.
#[derive(Debug, thiserror::Error)]
pub enum SentinelError {
    #[error("I/O error at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("configuration error: {0}")]
    Config(String),

    #[error("parse error: {0}")]
    Parse(String),

    #[error("storage error: {0}")]
    Storage(String),

    #[error("notification error: {0}")]
    Notify(String),

    #[error("permission denied: {0}")]
    Permission(String),

    #[error("unsupported feature: {0}")]
    Unsupported(String),

    #[error("external command failed: {0}")]
    Command(String),
}

impl SentinelError {
    /// Wrap an I/O error with the path that caused it.
    pub fn io(path: impl Into<PathBuf>, source: std::io::Error) -> Self {
        Self::Io {
            path: path.into(),
            source,
        }
    }
}

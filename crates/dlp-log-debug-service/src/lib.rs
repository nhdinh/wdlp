#![forbid(unsafe_code)]

use std::fmt;

pub mod config;
pub mod http;
pub mod paths;
pub mod tail;

pub use config::{
    AccessMode, ConfigError, DEFAULT_CONFIG_PATH, DEFAULT_MAX_RESPONSE_BYTES,
    DEFAULT_MAX_TAIL_LINES, DEFAULT_PORT, FileConfig, RuntimeConfig, load_runtime_config,
};
pub use http::{AppState, HttpError, LogQuery, authorize_peer, build_router, serve_http};
pub use paths::{
    AuthorizedFolders, PathAuthorizationError, authorize_canonical_target, authorize_requested_file,
};
pub use tail::{TailReadError, read_bounded_tail};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServiceError {
    ServeFailed,
}

impl ServiceError {
    pub const fn stable_code(self) -> &'static str {
        match self {
            Self::ServeFailed => "serve_failed",
        }
    }
}

impl fmt::Display for ServiceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.stable_code())
    }
}

impl std::error::Error for ServiceError {}

#[cfg(windows)]
pub fn run_windows_dispatcher() -> Result<(), ServiceError> {
    Ok(())
}

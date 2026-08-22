#![deny(unsafe_code)]

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
    AuthorizedFolders, PathAuthorizationError, authorize_canonical_target, open_authorized_file,
};
pub use tail::{TailReadError, read_bounded_tail, read_bounded_tail_file};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServiceError {
    ListenerBindFailed,
    ServeFailed,
    RuntimeFailed,
}

impl ServiceError {
    pub const fn stable_code(self) -> &'static str {
        match self {
            Self::ListenerBindFailed => "listener_bind_failed",
            Self::ServeFailed => "serve_failed",
            Self::RuntimeFailed => "runtime_failed",
        }
    }
}

impl fmt::Display for ServiceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.stable_code())
    }
}

impl std::error::Error for ServiceError {}

pub const fn service_exit_code(error: &ServiceError) -> u32 {
    match error {
        ServiceError::ListenerBindFailed => 1,
        ServiceError::ServeFailed => 2,
        ServiceError::RuntimeFailed => 3,
    }
}

#![forbid(unsafe_code)]

use std::{
    fmt,
    net::{IpAddr, SocketAddr},
    path::PathBuf,
};

use axum::{
    Router,
    extract::{ConnectInfo, Query, State, rejection::QueryRejection},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::get,
};
use serde::Deserialize;
use tokio::net::TcpListener;

pub mod config;
pub mod paths;
pub mod tail;

pub use config::{
    AccessMode, ConfigError, DEFAULT_CONFIG_PATH, DEFAULT_MAX_RESPONSE_BYTES,
    DEFAULT_MAX_TAIL_LINES, DEFAULT_PORT, FileConfig, RuntimeConfig, load_runtime_config,
};
pub use paths::{
    AuthorizedFolders, PathAuthorizationError, authorize_canonical_target, authorize_requested_file,
};
pub use tail::{TailReadError, read_bounded_tail};

#[derive(Clone, Debug)]
pub struct AppState {
    access_mode: AccessMode,
    authorized_folders: AuthorizedFolders,
    max_response_bytes: usize,
    max_tail_lines: usize,
}

impl AppState {
    pub fn from_runtime_config(config: RuntimeConfig) -> Self {
        Self {
            access_mode: config.access_mode,
            authorized_folders: config.authorized_folders,
            max_response_bytes: config.max_response_bytes,
            max_tail_lines: config.max_tail_lines,
        }
    }

    pub fn loopback_for_test(authorized_folder: PathBuf, max_response_bytes: usize) -> Self {
        Self::loopback_for_test_with_tail_limit(
            authorized_folder,
            max_response_bytes,
            DEFAULT_MAX_TAIL_LINES,
        )
    }

    pub fn loopback_for_test_with_tail_limit(
        authorized_folder: PathBuf,
        max_response_bytes: usize,
        max_tail_lines: usize,
    ) -> Self {
        let authorized_folders = AuthorizedFolders::from_configured_dirs([authorized_folder])
            .expect("test state must use an existing absolute authorized folder");
        assert!(max_response_bytes > 0, "test response cap must be positive");
        assert!(max_tail_lines > 0, "test tail limit must be positive");
        Self {
            access_mode: AccessMode::LocalhostOnly,
            authorized_folders,
            max_response_bytes,
            max_tail_lines,
        }
    }

    fn permits_peer(&self, peer: IpAddr) -> bool {
        peer.is_loopback()
            || matches!(&self.access_mode, AccessMode::RemoteAllowlist(allowed) if allowed.contains(&peer))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServiceError {
    ListenerFailed,
    ServeFailed,
}

impl ServiceError {
    pub const fn stable_code(self) -> &'static str {
        match self {
            Self::ListenerFailed => "listener_failed",
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

#[derive(Deserialize)]
struct LogQuery {
    path: Option<PathBuf>,
    tail: Option<String>,
}

pub fn build_router(state: AppState) -> Router {
    Router::new().route("/logs", get(get_log)).with_state(state)
}

pub async fn serve_http(listener: TcpListener, state: AppState) -> Result<(), ServiceError> {
    axum::serve(
        listener,
        build_router(state).into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .map_err(|_| ServiceError::ServeFailed)
}

async fn get_log(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    query: Result<Query<LogQuery>, QueryRejection>,
) -> Response {
    if !state.permits_peer(peer.ip()) {
        return error_response(StatusCode::FORBIDDEN, "untrusted_client");
    }
    let Ok(Query(query)) = query else {
        return error_response(StatusCode::BAD_REQUEST, "invalid_tail");
    };
    let Some(path) = query.path else {
        return error_response(StatusCode::BAD_REQUEST, "invalid_path");
    };
    // `tail` is optional by contract: omission is the configured maximum, not whole-file mode.
    let tail = match query.tail {
        None => state.max_tail_lines,
        Some(tail) => match tail.parse::<usize>() {
            Ok(value) if value > 0 && value <= state.max_tail_lines => value,
            _ => return error_response(StatusCode::BAD_REQUEST, "invalid_tail"),
        },
    };

    let path = match authorize_requested_file(&path, &state.authorized_folders) {
        Ok(path) => path,
        Err(PathAuthorizationError::InvalidPath) => {
            return error_response(StatusCode::BAD_REQUEST, "invalid_path");
        }
        Err(PathAuthorizationError::NotFound) => {
            return error_response(StatusCode::NOT_FOUND, "file_not_found");
        }
        Err(PathAuthorizationError::Denied) => {
            return error_response(StatusCode::FORBIDDEN, "forbidden_path");
        }
    };
    match read_bounded_tail(&path, tail, state.max_response_bytes) {
        Ok(content) => content.into_response(),
        Err(TailReadError::Io | TailReadError::InvalidText) => {
            error_response(StatusCode::INTERNAL_SERVER_ERROR, "read_failed")
        }
    }
}

fn error_response(status: StatusCode, code: &'static str) -> Response {
    (status, code).into_response()
}

#[cfg(windows)]
pub fn run_windows_dispatcher() -> Result<(), ServiceError> {
    Ok(())
}

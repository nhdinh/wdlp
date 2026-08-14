use std::{future::Future, net::SocketAddr, path::PathBuf};

use axum::{
    Router,
    extract::{ConnectInfo, Query, State, rejection::QueryRejection},
    http::{Method, StatusCode},
    response::{IntoResponse, Response},
    routing::any,
};
use serde::Deserialize;
use tokio::net::TcpListener;

use crate::{
    AccessMode, AuthorizedFolders, PathAuthorizationError, ServiceError, TailReadError,
    authorize_requested_file, read_bounded_tail,
};

#[derive(Clone, Debug)]
pub struct AppState {
    access_mode: AccessMode,
    authorized_folders: AuthorizedFolders,
    max_response_bytes: usize,
    max_tail_lines: usize,
}

impl AppState {
    pub fn from_runtime_config(config: crate::RuntimeConfig) -> Self {
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
            crate::DEFAULT_MAX_TAIL_LINES,
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
}

#[derive(Debug, Deserialize)]
pub struct LogQuery {
    path: Option<PathBuf>,
    tail: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HttpError {
    InvalidTail,
    InvalidPath,
    UntrustedClient,
    ForbiddenPath,
    FileNotFound,
    ReadFailed,
    RouteNotFound,
    MethodNotAllowed,
}

impl HttpError {
    pub const fn status(self) -> StatusCode {
        match self {
            Self::InvalidTail | Self::InvalidPath => StatusCode::BAD_REQUEST,
            Self::UntrustedClient | Self::ForbiddenPath => StatusCode::FORBIDDEN,
            Self::FileNotFound | Self::RouteNotFound => StatusCode::NOT_FOUND,
            Self::MethodNotAllowed => StatusCode::METHOD_NOT_ALLOWED,
            Self::ReadFailed => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    pub const fn stable_code(self) -> &'static str {
        match self {
            Self::InvalidTail => "invalid_tail",
            Self::InvalidPath => "invalid_path",
            Self::UntrustedClient => "untrusted_client",
            Self::ForbiddenPath => "forbidden_path",
            Self::FileNotFound => "file_not_found",
            Self::ReadFailed => "read_failed",
            Self::RouteNotFound => "route_not_found",
            Self::MethodNotAllowed => "method_not_allowed",
        }
    }
}

impl IntoResponse for HttpError {
    fn into_response(self) -> Response {
        (self.status(), self.stable_code()).into_response()
    }
}

/// Uses the accepted TCP peer only. HTTP headers are intentionally not an input to this check.
pub fn authorize_peer(access_mode: &AccessMode, peer: SocketAddr) -> Result<(), HttpError> {
    let peer_ip = peer.ip();
    if peer_ip.is_loopback()
        || matches!(access_mode, AccessMode::RemoteAllowlist(allowed) if allowed.contains(&peer_ip))
    {
        Ok(())
    } else {
        Err(HttpError::UntrustedClient)
    }
}

pub fn build_router(state: AppState) -> Router {
    Router::new()
        .route("/logs", any(log_endpoint))
        .fallback(any(route_not_found))
        .with_state(state)
}

pub async fn serve_http<F>(
    listener: TcpListener,
    state: AppState,
    shutdown: F,
) -> Result<(), ServiceError>
where
    F: Future<Output = ()> + Send + 'static,
{
    axum::serve(
        listener,
        build_router(state).into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown)
    .await
    .map_err(|_| ServiceError::ServeFailed)
}

async fn log_endpoint(
    method: Method,
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    query: Result<Query<LogQuery>, QueryRejection>,
) -> Response {
    let result = (|| {
        authorize_peer(&state.access_mode, peer)?;
        if method != Method::GET {
            return Err(HttpError::MethodNotAllowed);
        }
        let Query(query) = query.map_err(|_| HttpError::InvalidTail)?;
        let path = query.path.ok_or(HttpError::InvalidPath)?;
        let tail = match query.tail {
            None => state.max_tail_lines,
            Some(tail) => tail
                .parse::<usize>()
                .ok()
                .filter(|tail| *tail > 0 && *tail <= state.max_tail_lines)
                .ok_or(HttpError::InvalidTail)?,
        };
        let path =
            authorize_requested_file(&path, &state.authorized_folders).map_err(
                |error| match error {
                    PathAuthorizationError::InvalidPath => HttpError::InvalidPath,
                    PathAuthorizationError::NotFound => HttpError::FileNotFound,
                    PathAuthorizationError::Denied => HttpError::ForbiddenPath,
                },
            )?;
        read_bounded_tail(&path, tail, state.max_response_bytes).map_err(|error| match error {
            TailReadError::Io | TailReadError::InvalidText => HttpError::ReadFailed,
        })
    })();

    match result {
        Ok(content) => content.into_response(),
        Err(error) => error.into_response(),
    }
}

async fn route_not_found() -> HttpError {
    HttpError::RouteNotFound
}

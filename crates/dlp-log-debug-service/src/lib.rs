#![forbid(unsafe_code)]

use std::{
    fmt,
    fs::{self, File},
    io::{Read, Seek, SeekFrom},
    net::SocketAddr,
    path::{Path, PathBuf},
};

use axum::{
    Router,
    extract::{ConnectInfo, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::get,
};
use serde::Deserialize;
use tokio::net::TcpListener;

#[derive(Clone, Debug)]
pub struct AppState {
    authorized_folders: Vec<PathBuf>,
    max_response_bytes: usize,
}

impl AppState {
    pub fn new(
        authorized_folders: impl IntoIterator<Item = PathBuf>,
        max_response_bytes: usize,
    ) -> Result<Self, ServiceError> {
        if max_response_bytes == 0 {
            return Err(ServiceError::InvalidState);
        }

        let authorized_folders = authorized_folders
            .into_iter()
            .map(|folder| {
                let canonical = fs::canonicalize(folder).map_err(|_| ServiceError::InvalidState)?;
                if !canonical.is_dir() {
                    return Err(ServiceError::InvalidState);
                }
                Ok(canonical)
            })
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Self {
            authorized_folders,
            max_response_bytes,
        })
    }

    pub fn loopback_for_test(authorized_folder: PathBuf, max_response_bytes: usize) -> Self {
        Self::new([authorized_folder], max_response_bytes)
            .expect("test state must use an existing authorized folder")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServiceError {
    InvalidState,
    ListenerFailed,
    ServeFailed,
}

impl ServiceError {
    pub const fn stable_code(self) -> &'static str {
        match self {
            Self::InvalidState => "service_config_invalid",
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
    path: PathBuf,
    tail: usize,
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
    Query(query): Query<LogQuery>,
) -> Response {
    if !peer.ip().is_loopback() {
        return error_response(StatusCode::FORBIDDEN, "untrusted_client");
    }
    if query.tail == 0 {
        return error_response(StatusCode::BAD_REQUEST, "invalid_tail");
    }

    match authorize_requested_file(&query.path, &state.authorized_folders)
        .and_then(|path| read_bounded_tail(&path, query.tail, state.max_response_bytes))
    {
        Ok(content) => content.into_response(),
        Err(TracerError::Missing) => error_response(StatusCode::NOT_FOUND, "file_not_found"),
        Err(TracerError::Denied) => error_response(StatusCode::FORBIDDEN, "forbidden_path"),
        Err(TracerError::Read) => error_response(StatusCode::INTERNAL_SERVER_ERROR, "read_failed"),
    }
}

fn error_response(status: StatusCode, code: &'static str) -> Response {
    (status, code).into_response()
}

#[derive(Clone, Copy)]
enum TracerError {
    Missing,
    Denied,
    Read,
}

fn authorize_requested_file(
    path: &Path,
    authorized_folders: &[PathBuf],
) -> Result<PathBuf, TracerError> {
    if !path.is_absolute() {
        return Err(TracerError::Denied);
    }
    let canonical = fs::canonicalize(path).map_err(|_| TracerError::Missing)?;
    if !canonical.is_file() {
        return Err(TracerError::Denied);
    }
    if authorized_folders
        .iter()
        .any(|folder| canonical.parent() == Some(folder.as_path()))
    {
        Ok(canonical)
    } else {
        Err(TracerError::Denied)
    }
}

fn read_bounded_tail(
    path: &Path,
    requested_lines: usize,
    max_bytes: usize,
) -> Result<String, TracerError> {
    let mut file = File::open(path).map_err(|_| TracerError::Read)?;
    let length = file.metadata().map_err(|_| TracerError::Read)?.len();
    let read_start = length.saturating_sub(max_bytes as u64);

    let starts_at_line_boundary = if read_start == 0 {
        true
    } else {
        file.seek(SeekFrom::Start(read_start - 1))
            .map_err(|_| TracerError::Read)?;
        let mut preceding = [0_u8; 1];
        file.read_exact(&mut preceding)
            .map_err(|_| TracerError::Read)?;
        preceding[0] == b'\n'
    };

    file.seek(SeekFrom::Start(read_start))
        .map_err(|_| TracerError::Read)?;
    let mut bytes = Vec::with_capacity(max_bytes.min(length as usize));
    file.take(max_bytes as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| TracerError::Read)?;

    if !starts_at_line_boundary {
        let Some(first_newline) = bytes.iter().position(|byte| *byte == b'\n') else {
            return Ok(String::new());
        };
        bytes.drain(..=first_newline);
    }

    let Some(last_newline) = bytes.iter().rposition(|byte| *byte == b'\n') else {
        return Ok(String::new());
    };
    bytes.truncate(last_newline + 1);
    let text = String::from_utf8(bytes).map_err(|_| TracerError::Read)?;
    let line_count = text.bytes().filter(|byte| *byte == b'\n').count();
    if line_count <= requested_lines {
        return Ok(text);
    }
    let skipped_lines = line_count - requested_lines;
    let start = text
        .match_indices('\n')
        .nth(skipped_lines - 1)
        .map(|(index, _)| index + 1)
        .unwrap_or(0);
    Ok(text[start..].to_owned())
}

#[cfg(windows)]
pub fn run_windows_dispatcher() -> Result<(), ServiceError> {
    Ok(())
}

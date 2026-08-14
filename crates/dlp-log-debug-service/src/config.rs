use std::{
    fs,
    net::IpAddr,
    path::{Path, PathBuf},
};

use serde::Deserialize;

use crate::paths::AuthorizedFolders;

pub const DEFAULT_CONFIG_PATH: &str = r"C:\ProgramData\DlpLogDebugService\config.json";
pub const DEFAULT_PORT: u16 = 9191;
pub const DEFAULT_MAX_RESPONSE_BYTES: usize = 262_144;
pub const DEFAULT_MAX_TAIL_LINES: usize = 1_000;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileConfig {
    pub version: u8,
    pub trusted_client_ips: Vec<IpAddr>,
    pub allowed_folders: Vec<PathBuf>,
    pub port: u16,
    pub max_response_bytes: usize,
    /// Required maximum number of complete newest lines accepted by `GET /logs`.
    /// An omitted HTTP `tail` uses this value; a larger supplied value is rejected.
    pub max_tail_lines: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AccessMode {
    RemoteAllowlist(Vec<IpAddr>),
    LocalhostOnly,
}

#[derive(Clone, Debug)]
pub struct RuntimeConfig {
    pub access_mode: AccessMode,
    pub authorized_folders: AuthorizedFolders,
    pub port: u16,
    pub max_response_bytes: usize,
    pub max_tail_lines: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConfigError {
    Invalid,
}

pub fn load_runtime_config(path: &Path) -> RuntimeConfig {
    fs::read_to_string(path)
        .ok()
        .and_then(|contents| serde_json::from_str::<FileConfig>(&contents).ok())
        .and_then(|config| RuntimeConfig::try_from(config).ok())
        .unwrap_or_else(RuntimeConfig::localhost_only)
}

impl RuntimeConfig {
    pub fn localhost_only() -> Self {
        Self {
            access_mode: AccessMode::LocalhostOnly,
            authorized_folders: AuthorizedFolders::empty(),
            port: DEFAULT_PORT,
            max_response_bytes: DEFAULT_MAX_RESPONSE_BYTES,
            max_tail_lines: DEFAULT_MAX_TAIL_LINES,
        }
    }
}

impl TryFrom<FileConfig> for RuntimeConfig {
    type Error = ConfigError;

    fn try_from(config: FileConfig) -> Result<Self, Self::Error> {
        if config.version != 1
            || config.trusted_client_ips.is_empty()
            || config.port == 0
            || config.max_response_bytes == 0
            || config.max_tail_lines == 0
        {
            return Err(ConfigError::Invalid);
        }

        let authorized_folders = AuthorizedFolders::from_configured_dirs(config.allowed_folders)
            .map_err(|_| ConfigError::Invalid)?;
        if authorized_folders.is_empty() {
            return Err(ConfigError::Invalid);
        }

        Ok(Self {
            access_mode: AccessMode::RemoteAllowlist(config.trusted_client_ips),
            authorized_folders,
            port: config.port,
            max_response_bytes: config.max_response_bytes,
            max_tail_lines: config.max_tail_lines,
        })
    }
}

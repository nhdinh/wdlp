#![forbid(unsafe_code)]

use dlp_agent_core::{ActiveConfigurationSet, ConfigurationActivator};
use dlp_crypto::{ConfigurationSigner, ConfigurationVerifier};
use dlp_domain::{BundleVersion, DeviceId, FileId, StoreId, UserSid};
use dlp_protocol::{ConfigurationEnvelopeV1, SignedConfigurationV1};
use dlp_storage::{CapturedStoreIdentity, LocalEncryptedStore, StoreKey, VirtualPath};
use sqlx::{Row, SqlitePool, sqlite::SqlitePoolOptions};
use std::{
    fmt, fs,
    io::{Read, Write},
    net::{TcpStream, ToSocketAddrs},
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

pub const MIGRATION_VERSION: i64 = 202608070001;
const SQLITE_MIGRATION: &str =
    include_str!("../../../migrations-sqlite/202608070001_walking_skeleton.sql");

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SmokeReport {
    pub input_hash: u64,
    pub output_hash: u64,
    pub marker_scan_was_non_vacuous: bool,
    pub backing_scan_clean: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SmokeError {
    InvalidDatabaseUrl,
    DatabaseUnavailable,
    MigrationFailed,
    ServerUnavailable,
    EnrollmentRejected,
    ConfigurationRejected,
    StorageRejected,
    PlaintextLeak,
}

impl fmt::Display for SmokeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let code = match self {
            Self::InvalidDatabaseUrl => "smoke_database_url_invalid",
            Self::DatabaseUnavailable => "smoke_database_unavailable",
            Self::MigrationFailed => "smoke_migration_failed",
            Self::ServerUnavailable => "smoke_server_unavailable",
            Self::EnrollmentRejected => "smoke_enrollment_rejected",
            Self::ConfigurationRejected => "smoke_configuration_rejected",
            Self::StorageRejected => "smoke_storage_rejected",
            Self::PlaintextLeak => "smoke_plaintext_leak",
        };
        write!(formatter, "{code}")
    }
}

impl std::error::Error for SmokeError {}

/// Runs the portable tracer against the user-authorized SQLite ledger substitute.
/// PostgreSQL remains the production store and must be verified separately.
pub fn run_phase1_smoke(database_url: &str, root: &Path) -> Result<SmokeReport, SmokeError> {
    if !database_url.starts_with("sqlite:") {
        return Err(SmokeError::InvalidDatabaseUrl);
    }
    tokio::runtime::Runtime::new()
        .map_err(|_| SmokeError::ServerUnavailable)?
        .block_on(run_phase1_smoke_async(database_url, root))
}

async fn run_phase1_smoke_async(
    database_url: &str,
    root: &Path,
) -> Result<SmokeReport, SmokeError> {
    fs::create_dir_all(root).map_err(|_| SmokeError::StorageRejected)?;
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect(database_url)
        .await
        .map_err(|_| SmokeError::DatabaseUnavailable)?;
    initialize_sqlite_ledger(&pool).await?;
    verify_bound_router().await?;

    let device = DeviceId::parse("device-01").map_err(|_| SmokeError::EnrollmentRejected)?;
    enroll_once(&pool, &device).await?;

    let signer = ConfigurationSigner::from_seed("phase1-key", [9; 32]);
    let verifier =
        ConfigurationVerifier::from_public_key_bytes("phase1-key", signer.public_key_bytes())
            .map_err(|_| SmokeError::ConfigurationRejected)?;
    let first = signed_configuration(&signer, device.clone(), "1")?;
    let second = signed_configuration(&signer, device.clone(), "2")?;
    persist_configuration(&pool, &device, &first).await?;
    persist_configuration(&pool, &device, &second).await?;
    let mut active = ActiveConfigurationSet::default();
    active
        .activate(first, &verifier)
        .map_err(|_| SmokeError::ConfigurationRejected)?;
    active
        .activate(second, &verifier)
        .map_err(|_| SmokeError::ConfigurationRejected)?;
    if active.current().is_none() || active.last_known_good().is_none() {
        return Err(SmokeError::ConfigurationRejected);
    }

    let marker = format!(
        "phase1-marker-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| SmokeError::StorageRejected)?
            .as_nanos()
    );
    let source = format!("confidential:{marker}").into_bytes();
    let input_hash = stable_hash(&source);
    let backing = root.join("backing");
    let identity = CapturedStoreIdentity::new(
        UserSid::parse("S-1-5-21-1000").map_err(|_| SmokeError::StorageRejected)?,
        StoreId::parse("store-1000").map_err(|_| SmokeError::StorageRejected)?,
    );
    let file =
        FileId::parse("file-00000000000000000001").map_err(|_| SmokeError::StorageRejected)?;
    let mut store = LocalEncryptedStore::open(&backing, identity, StoreKey::from_bytes([7; 32]))
        .map_err(|_| SmokeError::StorageRejected)?;
    let path = VirtualPath::parse("protected.txt").map_err(|_| SmokeError::StorageRejected)?;
    let handle = store
        .create_or_open(&path, true, false)
        .map_err(|_| SmokeError::StorageRejected)?;
    store
        .write_handle(handle, 0, &source)
        .map_err(|_| SmokeError::StorageRejected)?;
    store
        .flush_handle(handle)
        .map_err(|_| SmokeError::StorageRejected)?;
    store
        .close_handle(handle)
        .map_err(|_| SmokeError::StorageRejected)?;
    let reopened = store.reopen().map_err(|_| SmokeError::StorageRejected)?;
    let output = reopened
        .read(&file)
        .map_err(|_| SmokeError::StorageRejected)?;
    let output_hash = stable_hash(&output);

    let control = root.join("control-marker.txt");
    fs::write(&control, marker.as_bytes()).map_err(|_| SmokeError::StorageRejected)?;
    let marker_scan_was_non_vacuous = contains_marker(&control, marker.as_bytes())?;
    let cache = root.join("cache");
    let logs = root.join("logs");
    let evidence = root.join("evidence");
    for directory in [&cache, &logs, &evidence] {
        fs::create_dir_all(directory).map_err(|_| SmokeError::StorageRejected)?;
    }
    fs::write(evidence.join("tracer.txt"), b"phase1 smoke complete")
        .map_err(|_| SmokeError::StorageRejected)?;
    let backing_scan_clean = marker_scan_was_non_vacuous
        && !tree_contains_marker(&backing, marker.as_bytes())?
        && !tree_contains_marker(&cache, marker.as_bytes())?
        && !tree_contains_marker(&logs, marker.as_bytes())?
        && !tree_contains_marker(&evidence, marker.as_bytes())?;
    if !backing_scan_clean {
        return Err(SmokeError::PlaintextLeak);
    }
    Ok(SmokeReport {
        input_hash,
        output_hash,
        marker_scan_was_non_vacuous,
        backing_scan_clean,
    })
}

async fn initialize_sqlite_ledger(pool: &SqlitePool) -> Result<(), SmokeError> {
    sqlx::raw_sql(SQLITE_MIGRATION)
        .execute(pool)
        .await
        .map_err(|_| SmokeError::MigrationFailed)?;
    sqlx::query("CREATE TABLE IF NOT EXISTS _sqlx_migrations (version BIGINT PRIMARY KEY)")
        .execute(pool)
        .await
        .map_err(|_| SmokeError::MigrationFailed)?;
    sqlx::query("INSERT OR IGNORE INTO _sqlx_migrations (version) VALUES (?)")
        .bind(MIGRATION_VERSION)
        .execute(pool)
        .await
        .map_err(|_| SmokeError::MigrationFailed)?;
    Ok(())
}

async fn enroll_once(pool: &SqlitePool, device: &DeviceId) -> Result<(), SmokeError> {
    sqlx::query("INSERT INTO device_allowlist (device_id, fingerprint_digest) VALUES (?, ?)")
        .bind(device.to_wire())
        .bind([1_u8; 32].as_slice())
        .execute(pool)
        .await
        .map_err(|_| SmokeError::EnrollmentRejected)?;
    sqlx::query("INSERT INTO enrollment_tokens (token_digest, device_id, expires_at) VALUES (?, ?, '2999-01-01T00:00:00Z')")
        .bind([2_u8; 32].as_slice())
        .bind(device.to_wire())
        .execute(pool)
        .await
        .map_err(|_| SmokeError::EnrollmentRejected)?;
    let result = sqlx::query("UPDATE enrollment_tokens SET consumed_at = CURRENT_TIMESTAMP WHERE token_digest = ? AND consumed_at IS NULL")
        .bind([2_u8; 32].as_slice())
        .execute(pool)
        .await
        .map_err(|_| SmokeError::EnrollmentRejected)?;
    if result.rows_affected() != 1 {
        return Err(SmokeError::EnrollmentRejected);
    }
    Ok(())
}

fn signed_configuration(
    signer: &ConfigurationSigner,
    device: DeviceId,
    version: &str,
) -> Result<SignedConfigurationV1, SmokeError> {
    let envelope = ConfigurationEnvelopeV1::new(
        1,
        device,
        BundleVersion::parse(version).map_err(|_| SmokeError::ConfigurationRejected)?,
        1_700_000_000,
        "encrypted-store-required",
    )
    .map_err(|_| SmokeError::ConfigurationRejected)?;
    let signature = signer.sign(&envelope.canonical_bytes());
    SignedConfigurationV1::new(envelope, signer.key_id(), signature)
        .map_err(|_| SmokeError::ConfigurationRejected)
}

async fn persist_configuration(
    pool: &SqlitePool,
    device: &DeviceId,
    configuration: &SignedConfigurationV1,
) -> Result<(), SmokeError> {
    let version: i64 = configuration
        .envelope()
        .bundle_version()
        .to_wire()
        .parse()
        .map_err(|_| SmokeError::ConfigurationRejected)?;
    sqlx::query("INSERT INTO signed_configurations (device_id, bundle_version, schema_version, key_id, canonical_bundle, signature) VALUES (?, ?, ?, ?, ?, ?)")
        .bind(device.to_wire())
        .bind(version)
        .bind(i64::from(configuration.envelope().schema_version()))
        .bind(configuration.key_id())
        .bind(configuration.envelope().canonical_bytes())
        .bind(configuration.signature())
        .execute(pool)
        .await
        .map_err(|_| SmokeError::ConfigurationRejected)?;
    let row = sqlx::query("SELECT COUNT(*) FROM signed_configurations WHERE device_id = ?")
        .bind(device.to_wire())
        .fetch_one(pool)
        .await
        .map_err(|_| SmokeError::ConfigurationRejected)?;
    let count: i64 = row
        .try_get(0)
        .map_err(|_| SmokeError::ConfigurationRejected)?;
    if count < 1 {
        return Err(SmokeError::ConfigurationRejected);
    }
    Ok(())
}

#[cfg(debug_assertions)]
async fn verify_bound_router() -> Result<(), SmokeError> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|_| SmokeError::ServerUnavailable)?;
    let address = listener
        .local_addr()
        .map_err(|_| SmokeError::ServerUnavailable)?;
    let server = tokio::spawn(async move {
        let _ = dlp_server::serve_tracer_listener(listener).await;
    });
    let response = std::thread::spawn(move || request_trace(address))
        .join()
        .map_err(|_| SmokeError::ServerUnavailable)??;
    server.abort();
    if response.starts_with("HTTP/1.1 204") {
        Ok(())
    } else {
        Err(SmokeError::ServerUnavailable)
    }
}

#[cfg(not(debug_assertions))]
async fn verify_bound_router() -> Result<(), SmokeError> {
    Err(SmokeError::ServerUnavailable)
}

fn request_trace(address: impl ToSocketAddrs) -> Result<String, SmokeError> {
    let mut stream = TcpStream::connect_timeout(
        &address
            .to_socket_addrs()
            .map_err(|_| SmokeError::ServerUnavailable)?
            .next()
            .ok_or(SmokeError::ServerUnavailable)?,
        Duration::from_secs(3),
    )
    .map_err(|_| SmokeError::ServerUnavailable)?;
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .map_err(|_| SmokeError::ServerUnavailable)?;
    stream
        .write_all(b"GET /api/v1/tracer HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .map_err(|_| SmokeError::ServerUnavailable)?;
    let mut response = String::new();
    stream
        .read_to_string(&mut response)
        .map_err(|_| SmokeError::ServerUnavailable)?;
    Ok(response)
}

fn contains_marker(path: &Path, marker: &[u8]) -> Result<bool, SmokeError> {
    let bytes = fs::read(path).map_err(|_| SmokeError::StorageRejected)?;
    Ok(bytes.windows(marker.len()).any(|window| window == marker))
}

fn tree_contains_marker(root: &Path, marker: &[u8]) -> Result<bool, SmokeError> {
    let mut pending = vec![PathBuf::from(root)];
    while let Some(path) = pending.pop() {
        for entry in fs::read_dir(&path).map_err(|_| SmokeError::StorageRejected)? {
            let entry = entry.map_err(|_| SmokeError::StorageRejected)?;
            let entry_path = entry.path();
            if entry
                .file_type()
                .map_err(|_| SmokeError::StorageRejected)?
                .is_dir()
            {
                pending.push(entry_path);
            } else if contains_marker(&entry_path, marker)? {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

fn stable_hash(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0xcbf2_9ce4_8422_2325_u64, |hash, byte| {
        (hash ^ u64::from(*byte)).wrapping_mul(0x1000_0000_01b3)
    })
}

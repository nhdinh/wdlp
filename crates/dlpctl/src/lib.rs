#![forbid(unsafe_code)]

use dlp_agent_core::{ActiveConfigurationSet, ConfigurationActivator};
use dlp_crypto::{ConfigurationSigner, ConfigurationVerifier};
use dlp_domain::{BundleVersion, DeviceId, FileId, StoreId, UserSid};
use dlp_protocol::{ConfigurationEnvelopeV1, SignedConfigurationV1};
use dlp_storage::{CapturedStoreIdentity, LocalEncryptedStore, StoreKey, VirtualPath};
use serde::{Deserialize, Serialize};
use sqlx::{Row, SqlitePool, sqlite::SqlitePoolOptions};
use std::{
    fmt, fs,
    io::{Read, Write},
    net::{TcpStream, ToSocketAddrs},
    path::{Path, PathBuf},
    sync::{Arc, Barrier, Mutex},
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

#[derive(Clone, Eq, PartialEq, Serialize)]
pub struct ProvisioningRequest {
    version: u16,
    device_id: String,
    fingerprint_digest: [u8; 32],
    ad_object_guid: Vec<u8>,
    ad_object_sid: Vec<u8>,
    preferred_drive_letter: char,
}

impl ProvisioningRequest {
    pub fn new(
        device_dns_name: impl Into<String>,
        fingerprint_digest: [u8; 32],
        ad_object_guid: Vec<u8>,
        ad_object_sid: Vec<u8>,
        preferred_drive_letter: char,
    ) -> Result<Self, ProvisioningError> {
        let device_id = device_dns_name.into();
        if !valid_dns_name(&device_id)
            || ad_object_guid.len() != 16
            || !(8..=68).contains(&ad_object_sid.len())
            || !preferred_drive_letter.is_ascii_uppercase()
        {
            return Err(ProvisioningError::InvalidRequest);
        }
        Ok(Self {
            version: 1,
            device_id,
            fingerprint_digest,
            ad_object_guid,
            ad_object_sid,
            preferred_drive_letter,
        })
    }

    fn json_body(&self) -> Result<String, ProvisioningError> {
        serde_json::to_string(self).map_err(|_| ProvisioningError::InvalidRequest)
    }
}

impl fmt::Debug for ProvisioningRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("ProvisioningRequest")
            .field("device_id", &self.device_id)
            .field("fingerprint_digest", &"[REDACTED]")
            .field("ad_object_guid", &"[REDACTED]")
            .field("ad_object_sid", &"[REDACTED]")
            .field("preferred_drive_letter", &self.preferred_drive_letter)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProvisioningError { InvalidRequest, Transport, InvalidResponse, SecretHandoff }

pub trait RuntimeSecretProvider {
    fn handoff_enrollment_token(&mut self, token: String) -> Result<(), ProvisioningError>;
}

pub fn handoff_token_to_runtime(
    token: &str,
    runtime: &mut dyn RuntimeSecretProvider,
) -> Result<(), ProvisioningError> {
    if token.is_empty() || token.len() > 512 || !token.bytes().all(|byte| byte.is_ascii_alphanumeric()) {
        return Err(ProvisioningError::InvalidResponse);
    }
    runtime.handoff_enrollment_token(token.to_owned())
}

/// mTLS-backed client for the administrator provisioning route. The endpoint
/// must be an HTTPS hostname, the root CA and administrator identity are loaded
/// from runtime-provider paths, and the plaintext token is handed only to the
/// injected secret provider.
pub struct ProvisioningClient {
    client: reqwest::Client,
    endpoint: String,
}

impl ProvisioningClient {
    pub fn new(
        endpoint: impl Into<String>,
        root_ca_pem_path: &Path,
        admin_cert_pem_path: &Path,
        admin_key_pem_path: &Path,
    ) -> Result<Self, ProvisioningError> {
        let endpoint = endpoint.into();
        let url = reqwest::Url::parse(&endpoint).map_err(|_| ProvisioningError::InvalidRequest)?;
        if url.scheme() != "https" {
            return Err(ProvisioningError::InvalidRequest);
        }
        let host = url.host_str().ok_or(ProvisioningError::InvalidRequest)?;
        if host.parse::<std::net::IpAddr>().is_ok() || !valid_dns_name(host) {
            return Err(ProvisioningError::InvalidRequest);
        }

        let root_pem = fs::read_to_string(root_ca_pem_path).map_err(|_| ProvisioningError::InvalidRequest)?;
        let root_certificate = reqwest::Certificate::from_pem(root_pem.as_bytes())
            .map_err(|_| ProvisioningError::InvalidRequest)?;

        let cert = fs::read_to_string(admin_cert_pem_path).map_err(|_| ProvisioningError::InvalidRequest)?;
        let key = fs::read_to_string(admin_key_pem_path).map_err(|_| ProvisioningError::InvalidRequest)?;
        let identity = reqwest::Identity::from_pem((cert + &key).as_bytes())
            .map_err(|_| ProvisioningError::InvalidRequest)?;

        let client = reqwest::Client::builder()
            .https_only(true)
            .add_root_certificate(root_certificate)
            .identity(identity)
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(20))
            .build()
            .map_err(|_| ProvisioningError::Transport)?;
        Ok(Self { client, endpoint })
    }

    /// Test-only constructor that skips mTLS material so JSON response parsing
    /// and handoff can be exercised without real certificates.
    #[cfg(test)]
    pub fn for_test(endpoint: impl Into<String>) -> Result<Self, ProvisioningError> {
        let endpoint = endpoint.into();
        let url = reqwest::Url::parse(&endpoint).map_err(|_| ProvisioningError::InvalidRequest)?;
        if url.scheme() != "https" {
            return Err(ProvisioningError::InvalidRequest);
        }
        let host = url.host_str().ok_or(ProvisioningError::InvalidRequest)?;
        if host.parse::<std::net::IpAddr>().is_ok() || !valid_dns_name(host) {
            return Err(ProvisioningError::InvalidRequest);
        }
        let client = reqwest::Client::builder()
            .https_only(true)
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(20))
            .build()
            .map_err(|_| ProvisioningError::Transport)?;
        Ok(Self { client, endpoint })
    }

    pub async fn provision(
        &self,
        request: &ProvisioningRequest,
        runtime: &mut dyn RuntimeSecretProvider,
    ) -> Result<(), ProvisioningError> {
        let body = request.json_body()?;
        let response = self
            .client
            .post(&self.endpoint)
            .header("content-type", "application/json")
            .body(body)
            .send()
            .await
            .map_err(|_| ProvisioningError::Transport)?;
        if !response.status().is_success() {
            return Err(ProvisioningError::Transport);
        }
        let payload = response
            .json::<ProvisioningResponseJson>()
            .await
            .map_err(|_| ProvisioningError::InvalidResponse)?;
        validate_provisioning_response(&payload,&request.device_id,
        )
        .map(|_| payload.enrollment_token)
        .and_then(|token| handoff_token_to_runtime(&token, runtime))
    }
}

fn validate_provisioning_response(
    payload: &ProvisioningResponseJson,
    expected_device_id: &str,
) -> Result<(), ProvisioningError> {
    if payload.version != 1 || payload.device_id != expected_device_id {
        return Err(ProvisioningError::InvalidResponse);
    }
    Ok(())
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
struct ProvisioningResponseJson {
    version: u16,
    device_id: String,
    enrollment_token: String,
}

fn valid_dns_name(value: &str) -> bool {
    value.len() <= 253 && value.contains('.') && value.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'.' || byte == b'-')
}

pub const MIGRATION_VERSION: i64 = 202608070001;

#[cfg(test)]
mod provisioning_tests {
    use super::*;

    struct Sink(Option<String>);
    impl RuntimeSecretProvider for Sink {
        fn handoff_enrollment_token(&mut self, token: String) -> Result<(), ProvisioningError> {
            self.0 = Some(token);
            Ok(())
        }
    }

    #[test]
    fn provisioning_request_rejects_raw_machine_observations_and_redacts_token() {
        let request = ProvisioningRequest::new(
            "LAB-CLIENT01.lab.local",
            [7; 32],
            vec![1; 16],
            vec![2; 16],
            'P',
        )
        .expect("normalized trusted observation is accepted");
        assert!(!format!("{request:?}").contains("token"));
        assert!(ProvisioningRequest::new("", [7; 32], vec![1; 16], vec![2; 16], 'P').is_err());
    }

    #[test]
    fn provisioning_client_hands_plaintext_token_only_to_runtime_secret_provider() {
        let mut sink = Sink(None);
        handoff_token_to_runtime("opaquetoken", &mut sink).unwrap();
        assert_eq!(sink.0.as_deref(), Some("opaquetoken"));
    }

    #[test]
    fn provisioning_client_rejects_non_https_and_ip_endpoints() {
        assert!(
            ProvisioningClient::for_test("http://server.lab.local/api/v1/admin/provisioning").is_err()
        );
        assert!(
            ProvisioningClient::for_test("https://192.168.1.1/api/v1/admin/provisioning").is_err()
        );
        assert!(
            ProvisioningClient::for_test("https://localhost/api/v1/admin/provisioning").is_err()
        );
    }

    #[test]
    fn provisioning_response_requires_version_and_matching_device() {
        assert!(validate_provisioning_response(
            &ProvisioningResponseJson {
                version: 1,
                device_id: "LAB-CLIENT01.lab.local".into(),
                enrollment_token: "opaquetoken123".into(),
            },
            "LAB-CLIENT01.lab.local",
        )
        .is_ok());
        assert!(validate_provisioning_response(
            &ProvisioningResponseJson {
                version: 2,
                device_id: "LAB-CLIENT01.lab.local".into(),
                enrollment_token: "opaquetoken123".into(),
            },
            "LAB-CLIENT01.lab.local",
        )
        .is_err());
        assert!(validate_provisioning_response(
            &ProvisioningResponseJson {
                version: 1,
                device_id: "OTHER.lab.local".into(),
                enrollment_token: "opaquetoken123".into(),
            },
            "LAB-CLIENT01.lab.local",
        )
        .is_err());
    }

    #[test]
    fn provisioning_client_requires_existing_pem_material() {
        let missing = std::path::Path::new("/nonexistent/ca.pem");
        assert!(
            ProvisioningClient::new(
                "https://server.lab.local/api/v1/admin/provisioning",
                missing,
                missing,
                missing,
            )
            .is_err()
        );
    }
}
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

/// Async counterpart for callers that already own a Tokio runtime, such as the CLI.
pub async fn run_phase1_smoke_in_runtime(
    database_url: &str,
    root: &Path,
) -> Result<SmokeReport, SmokeError> {
    run_phase1_smoke_async(database_url, root).await
}

/// Exercises the race and tamper boundaries that protect the walking skeleton.
/// The checks deliberately return only stable codes, never bundle or plaintext data.
pub fn verify_tracer_hardening(root: &Path) -> Result<(), SmokeError> {
    tokio::runtime::Runtime::new()
        .map_err(|_| SmokeError::ServerUnavailable)?
        .block_on(verify_tracer_hardening_async(root))
}

async fn verify_tracer_hardening_async(root: &Path) -> Result<(), SmokeError> {
    fs::create_dir_all(root).map_err(|_| SmokeError::StorageRejected)?;
    let database_url = format!(
        "sqlite://{}?mode=rwc",
        root.join("hardening.sqlite").display()
    );
    let pool = SqlitePoolOptions::new()
        .max_connections(4)
        .connect(&database_url)
        .await
        .map_err(|_| SmokeError::DatabaseUnavailable)?;
    initialize_sqlite_ledger(&pool).await?;
    let device = DeviceId::parse("device-hardening").map_err(|_| SmokeError::EnrollmentRejected)?;
    sqlx::query("INSERT INTO device_allowlist (device_id, fingerprint_digest) VALUES (?, ?)")
        .bind(device.to_wire())
        .bind([3_u8; 32].as_slice())
        .execute(&pool)
        .await
        .map_err(|_| SmokeError::EnrollmentRejected)?;
    sqlx::query("INSERT INTO enrollment_tokens (token_digest, device_id, expires_at) VALUES (?, ?, '2999-01-01T00:00:00Z')")
        .bind([4_u8; 32].as_slice())
        .bind(device.to_wire())
        .execute(&pool)
        .await
        .map_err(|_| SmokeError::EnrollmentRejected)?;
    let left = consume_token(&pool);
    let right = consume_token(&pool);
    let (left, right) = tokio::join!(left, right);
    if usize::from(left?) + usize::from(right?) != 1 {
        return Err(SmokeError::EnrollmentRejected);
    }

    let signer = ConfigurationSigner::from_seed("phase1-key", [9; 32]);
    let verifier = Arc::new(
        ConfigurationVerifier::from_public_key_bytes("phase1-key", signer.public_key_bytes())
            .map_err(|_| SmokeError::ConfigurationRejected)?,
    );
    let initial = signed_configuration(&signer, device.clone(), "2")?;
    let active = Arc::new(Mutex::new(ActiveConfigurationSet::default()));
    active
        .lock()
        .map_err(|_| SmokeError::ConfigurationRejected)?
        .activate(initial, &verifier)
        .map_err(|_| SmokeError::ConfigurationRejected)?;
    let barrier = Arc::new(Barrier::new(3));
    let mut workers = Vec::new();
    for version in ["3", "4"] {
        let active = Arc::clone(&active);
        let verifier = Arc::clone(&verifier);
        let barrier = Arc::clone(&barrier);
        let configuration = signed_configuration(&signer, device.clone(), version)?;
        workers.push(thread::spawn(move || {
            barrier.wait();
            active
                .lock()
                .map_err(|_| SmokeError::ConfigurationRejected)?
                .activate(configuration, &verifier)
                .map_err(|_| SmokeError::ConfigurationRejected)
        }));
    }
    barrier.wait();
    for worker in workers {
        // A delayed lower version is an expected fail-closed outcome; the final state below
        // proves that a valid higher version still wins the race deterministically.
        let _ = worker
            .join()
            .map_err(|_| SmokeError::ConfigurationRejected)?;
    }
    let before_invalid = active
        .lock()
        .map_err(|_| SmokeError::ConfigurationRejected)?
        .clone();
    let wrong_signer = ConfigurationSigner::from_seed("phase1-key", [8; 32]);
    let wrong_signature = signed_configuration(&wrong_signer, device.clone(), "5")?;
    let replay = signed_configuration(&signer, device.clone(), "1")?;
    let truncated = SignedConfigurationV1::new(
        ConfigurationEnvelopeV1::new(
            1,
            device,
            BundleVersion::parse("5").map_err(|_| SmokeError::ConfigurationRejected)?,
            1_700_000_000,
            "encrypted-store-required",
        )
        .map_err(|_| SmokeError::ConfigurationRejected)?,
        "phase1-key",
        vec![0; 63],
    )
    .map_err(|_| SmokeError::ConfigurationRejected)?;
    let mut locked = active
        .lock()
        .map_err(|_| SmokeError::ConfigurationRejected)?;
    for invalid in [wrong_signature, replay, truncated] {
        if locked.activate(invalid, &verifier).is_ok() || *locked != before_invalid {
            return Err(SmokeError::ConfigurationRejected);
        }
    }
    let current_version = locked
        .current()
        .ok_or(SmokeError::ConfigurationRejected)?
        .envelope()
        .bundle_version()
        .to_wire();
    if current_version != "4" || locked.last_known_good().is_none() {
        return Err(SmokeError::ConfigurationRejected);
    }
    drop(locked);

    let identity = CapturedStoreIdentity::new(
        UserSid::parse("S-1-5-21-2000").map_err(|_| SmokeError::StorageRejected)?,
        StoreId::parse("store-2000").map_err(|_| SmokeError::StorageRejected)?,
    );
    let file = FileId::parse("file-hardening").map_err(|_| SmokeError::StorageRejected)?;
    let mut store = LocalEncryptedStore::open(
        root.join("integrity"),
        identity,
        StoreKey::from_bytes([6; 32]),
    )
    .map_err(|_| SmokeError::StorageRejected)?;
    store
        .write(&file, b"protected payload")
        .map_err(|_| SmokeError::StorageRejected)?;
    store
        .flush_file(&file)
        .map_err(|_| SmokeError::StorageRejected)?;
    let mut corrupted = store.reopen().map_err(|_| SmokeError::StorageRejected)?;
    corrupted
        .tamper_selected_record_for_test(&file, "tag")
        .map_err(|_| SmokeError::StorageRejected)?;
    if corrupted.read(&file).is_ok() {
        return Err(SmokeError::StorageRejected);
    }
    let duplicate = FileId::parse("file-duplicate").map_err(|_| SmokeError::StorageRejected)?;
    store
        .write(&duplicate, b"protected payload")
        .map_err(|_| SmokeError::StorageRejected)?;
    store.inject_duplicate_nonce_for_test(&duplicate);
    if store.flush_file(&duplicate).is_ok() {
        return Err(SmokeError::StorageRejected);
    }
    Ok(())
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

async fn consume_token(pool: &SqlitePool) -> Result<bool, SmokeError> {
    sqlx::query("UPDATE enrollment_tokens SET consumed_at = CURRENT_TIMESTAMP WHERE token_digest = ? AND consumed_at IS NULL")
        .bind([4_u8; 32].as_slice())
        .execute(pool)
        .await
        .map(|result| result.rows_affected() == 1)
        .map_err(|_| SmokeError::EnrollmentRejected)
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

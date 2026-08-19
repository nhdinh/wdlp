//! SCM lifecycle and component composition.
//!
//! The service entry creates a Tokio runtime, reports accurate pending/running/stopped
//! states to the SCM, and loads the DPAPI credential and signed configuration cache
//! before any authenticated network activity. Session-change controls are registered
//! here for Plan 01-15; the session host itself is implemented separately.

use crate::credential::{CredentialStore, DpapiCredentialStore};
use crate::session::{
    DpapiStoreKeyProvider, MountAttempt, SessionConfig, SessionEvent, SessionMonitor, SystemClock,
    WtsSessionTokenProvider, active_session_ids,
};
use dlp_agent_core::{
    AgentConfigurationTransport, AgentHttpClient, ConfigurationCache, EnrollmentCoordinator,
    EnrollmentCredentialStore, EnrollmentMode, HealthSnapshot, RedactedDiagnostic,
};
use dlp_crypto::ConfigurationVerifier;
use dlp_domain::DeviceId;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, mpsc};
use std::time::Duration;

const SERVICE_LOG_PATH: &str = r"C:\dlp\agent\logs\dlp-windows-service.log";

/// Append a timestamped line to the service log file.
///
/// Logging is intentionally primitive: it must work before any runtime or
/// configuration is loaded so we can diagnose why the SCM start fails.
pub fn service_log(level: &str, message: impl AsRef<str>) {
    use std::fs::OpenOptions;
    use std::io::Write;

    let message = message.as_ref();
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| format!("{}.{:03}", d.as_secs(), d.subsec_millis()))
        .unwrap_or_else(|_| "0".to_string());
    let line = format!("[{timestamp}] [{level}] {message}\n");

    if let Some(parent) = std::path::Path::new(SERVICE_LOG_PATH).parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = OpenOptions::new()
        .create(true)
        .append(true)
        .open(SERVICE_LOG_PATH)
        .and_then(|mut file| file.write_all(line.as_bytes()));
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServiceState {
    Starting,
    Running,
    ReplacementEnrollmentRequired,
    Failed,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ServiceStartError {
    ConfigMissing,
    ConfigInvalid,
    CredentialLoadFailed,
    EnrollmentFailed,
    CacheLoadFailed,
    RuntimeFailed,
}

impl std::fmt::Display for ServiceStartError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let code = match self {
            Self::ConfigMissing => "service_config_missing",
            Self::ConfigInvalid => "service_config_invalid",
            Self::CredentialLoadFailed => "credential_load_failed",
            Self::EnrollmentFailed => "enrollment_failed",
            Self::CacheLoadFailed => "cache_load_failed",
            Self::RuntimeFailed => "service_runtime_failed",
        };
        formatter.write_str(code)
    }
}

impl std::error::Error for ServiceStartError {}

/// Secret-free service configuration. Runtime-sensitive material (enrollment token,
/// device identity, signing key bytes) is supplied by the endpoint runtime provider,
/// never committed to source control.
pub struct ServiceConfig {
    pub device_id: DeviceId,
    pub server_url: String,
    pub phase1_root_ca_pem: String,
    pub data_directory: PathBuf,
    pub cache_directory: PathBuf,
    pub enrollment_token: Option<String>,
    pub configuration_key_id: String,
    pub configuration_public_key: [u8; 32],
    pub poll_interval: Duration,
    pub health_interval: Duration,
    pub start_timeout: Duration,
    pub stop_timeout: Duration,
}

impl ServiceConfig {
    pub fn credential_store_path(&self) -> PathBuf {
        self.data_directory.join("credentials")
    }

    pub fn cache_root(&self) -> PathBuf {
        self.cache_directory.clone()
    }

    fn configuration_verifier(&self) -> Result<ConfigurationVerifier, ServiceStartError> {
        ConfigurationVerifier::from_public_key_bytes(
            &self.configuration_key_id,
            self.configuration_public_key,
        )
        .map_err(|_| ServiceStartError::ConfigInvalid)
    }
}

/// Composes the agent-core components that survive inside the SCM service entry.
pub struct ServiceContext {
    pub config: ServiceConfig,
    pub credential_store: DpapiCredentialStore,
    pub cache: ConfigurationCache,
    pub client: AgentHttpClient,
}

impl ServiceContext {
    /// Loads the DPAPI credential and cache, enrolling only when no usable credential
    /// exists and a runtime enrollment token is available.
    pub fn startup(config: ServiceConfig) -> Result<(Self, EnrollmentMode), ServiceStartError> {
        let credential_store = DpapiCredentialStore::new(config.credential_store_path())
            .map_err(|_| ServiceStartError::CredentialLoadFailed)?;
        let cache = ConfigurationCache::open(config.cache_root(), config.device_id.clone())
            .map_err(|_| ServiceStartError::CacheLoadFailed)?;
        cache
            .load_pointers()
            .map_err(|_| ServiceStartError::CacheLoadFailed)?;

        let bootstrap_client =
            AgentHttpClient::bootstrap(&config.server_url, &config.phase1_root_ca_pem)
                .map_err(|_| ServiceStartError::ConfigInvalid)?;

        let mode = match Self::ensure_credential(&config, &bootstrap_client, &credential_store) {
            Ok(mode) => mode,
            Err(error) => {
                service_log(
                    "ERROR",
                    format!("enrollment initialization failed: {error}"),
                );
                return Err(ServiceStartError::EnrollmentFailed);
            }
        };

        let client = Self::client_with_identity(&credential_store, bootstrap_client)
            .map_err(|_| ServiceStartError::CredentialLoadFailed)?;

        Ok((
            Self {
                config,
                credential_store,
                cache,
                client,
            },
            mode,
        ))
    }

    fn ensure_credential(
        config: &ServiceConfig,
        bootstrap_client: &AgentHttpClient,
        store: &DpapiCredentialStore,
    ) -> Result<EnrollmentMode, dlp_agent_core::EnrollmentError> {
        if store.validate_protection().unwrap_or(false) {
            return Ok(EnrollmentMode::Existing);
        }
        let Some(token) = config.enrollment_token.clone() else {
            return Err(dlp_agent_core::EnrollmentError::CredentialUnavailable);
        };
        // A damaged credential can still retain the serial that authorizes its
        // replacement. Passing that serial preserves the server's active-
        // credential check instead of making recovery impossible whenever the
        // local protection validation fails.
        let prior_serial = store
            .load()
            .ok()
            .map(|credential| credential.serial().to_vec());
        let mut coordinator =
            EnrollmentCoordinator::new((*bootstrap_client).clone(), store.clone());
        coordinator.startup(config.device_id.clone(), token, prior_serial.as_deref())
    }

    fn client_with_identity(
        store: &DpapiCredentialStore,
        bootstrap_client: AgentHttpClient,
    ) -> Result<AgentHttpClient, dlp_agent_core::EnrollmentError> {
        let credential = store.load_credential()?;
        let private_key = String::from_utf8(credential.private_key.clone())
            .map_err(|_| dlp_agent_core::EnrollmentError::CredentialUnavailable)?;
        bootstrap_client
            .with_device_identity(credential.certificate_chain.clone(), private_key)
            .map_err(|_| dlp_agent_core::EnrollmentError::CredentialUnavailable)
    }
}

pub fn startup_state(has_usable_credential: bool) -> ServiceState {
    if has_usable_credential {
        ServiceState::Running
    } else {
        ServiceState::ReplacementEnrollmentRequired
    }
}

/// Formats a redacted drive-state string from the session monitor snapshot.
/// Contains no SIDs, paths, keys, or content; only drive letter and state.
fn drive_state(mounts: &Arc<Mutex<Vec<MountAttempt>>>) -> String {
    let guard = mounts
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if guard.is_empty() {
        return "not_mounted".into();
    }
    guard
        .iter()
        .map(|m| {
            let letter = m.drive_letter.as_deref().unwrap_or("-");
            let state = match m.diagnostic {
                Some(d) => d.code(),
                None => "mounted",
            };
            format!("{letter}:{state}")
        })
        .collect::<Vec<_>>()
        .join(",")
}

/// Synchronous service loop that runs on a Tokio blocking task. It polls for signed
/// configuration and posts redacted health until the shutdown signal fires.
pub fn run_service_loop(
    context: ServiceContext,
    shutdown: mpsc::Receiver<()>,
    mounts: Arc<Mutex<Vec<MountAttempt>>>,
) {
    let verifier = match context.config.configuration_verifier() {
        Ok(v) => v,
        Err(_) => {
            post_health(&context, RedactedDiagnostic::ConfigurationRejected);
            return;
        }
    };

    let mut last_contact: Option<u64> = None;
    let mut transport = match AgentConfigurationTransport::new(&context.client) {
        Ok(t) => t,
        Err(_) => {
            post_health(&context, RedactedDiagnostic::CredentialUnavailable);
            return;
        }
    };

    let poll_interval = context.config.poll_interval;
    let health_interval = context.config.health_interval;
    let mut last_poll = std::time::Instant::now()
        .checked_sub(poll_interval)
        .unwrap_or_else(std::time::Instant::now);
    let mut last_health = std::time::Instant::now()
        .checked_sub(health_interval)
        .unwrap_or_else(std::time::Instant::now);

    loop {
        if shutdown.try_recv().is_ok() {
            break;
        }

        let now = std::time::Instant::now();
        if now.duration_since(last_poll) >= poll_interval {
            last_poll = now;
            match poll_and_activate(&context, &mut transport, &verifier) {
                Ok(_) => last_contact = Some(epoch_seconds()),
                Err(_) => {
                    post_health(&context, RedactedDiagnostic::ConfigurationRejected);
                }
            }
        }

        let now = std::time::Instant::now();
        if now.duration_since(last_health) >= health_interval {
            last_health = now;
            let snapshot = HealthSnapshot::from_cache(
                env!("CARGO_PKG_VERSION"),
                "running",
                drive_state(&mounts),
                &context.cache,
                last_contact,
                None,
            );
            let _ = context
                .client
                .post_health(&context.config.device_id, &snapshot.drive_state);
        }

        std::thread::sleep(Duration::from_millis(250));
    }
}

fn poll_and_activate(
    context: &ServiceContext,
    transport: &mut AgentConfigurationTransport,
    verifier: &ConfigurationVerifier,
) -> Result<(), dlp_agent_core::ClientError> {
    let bytes = context.client.poll_configuration(transport)?;
    let _ = context
        .cache
        .stage_verify_activate(&bytes, verifier)
        .map_err(|_| dlp_agent_core::ClientError::ConfigurationFetchFailed)?;
    Ok(())
}

fn post_health(context: &ServiceContext, diagnostic: RedactedDiagnostic) {
    let snapshot = HealthSnapshot::from_cache(
        env!("CARGO_PKG_VERSION"),
        "running",
        "not_mounted",
        &context.cache,
        None,
        Some(diagnostic),
    );
    let _ = context
        .client
        .post_health(&context.config.device_id, &snapshot.drive_state);
}

fn epoch_seconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(windows)]
pub fn run_scm_service() -> Result<(), windows_service::Error> {
    use windows_service::{
        define_windows_service,
        service::{
            ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState as ScmState,
            ServiceStatus, ServiceType,
        },
        service_control_handler::{self, ServiceControlHandlerResult},
        service_dispatcher,
    };

    define_windows_service!(ffi_service_main, service_main);

    fn service_main(_arguments: Vec<std::ffi::OsString>) {
        service_log("INFO", "service_main invoked");

        fn build_status(
            state: ScmState,
            checkpoint: u32,
            wait_hint: Duration,
            exit_code: ServiceExitCode,
        ) -> ServiceStatus {
            ServiceStatus {
                service_type: ServiceType::OWN_PROCESS,
                current_state: state,
                controls_accepted: ServiceControlAccept::STOP
                    | ServiceControlAccept::SHUTDOWN
                    | ServiceControlAccept::SESSION_CHANGE,
                exit_code,
                checkpoint,
                wait_hint,
                process_id: None,
            }
        }

        let (shutdown_tx, shutdown_rx) = mpsc::channel();
        let (session_tx, session_rx) = mpsc::channel::<SessionEvent>();
        let session_tx_handler = session_tx.clone();
        let handler =
            service_control_handler::register("DlpWindowsService", move |control| match control {
                ServiceControl::Stop | ServiceControl::Shutdown => {
                    let _ = session_tx_handler.send(SessionEvent::Stop);
                    let _ = shutdown_tx.send(());
                    ServiceControlHandlerResult::NoError
                }
                ServiceControl::SessionChange(session_change) => {
                    use windows_service::service::SessionChangeReason;
                    let event = match session_change.reason {
                        SessionChangeReason::SessionLogon => {
                            Some(SessionEvent::Logon(session_change.notification.session_id))
                        }
                        SessionChangeReason::SessionLogoff => {
                            Some(SessionEvent::Logoff(session_change.notification.session_id))
                        }
                        _ => None,
                    };
                    if let Some(event) = event {
                        let _ = session_tx_handler.send(event);
                    }
                    ServiceControlHandlerResult::NoError
                }
                _ => ServiceControlHandlerResult::NotImplemented,
            })
            .expect("register service control handler");
        service_log("INFO", "control handler registered");

        let _ = handler.set_service_status(build_status(
            ScmState::StartPending,
            0,
            Duration::from_secs(60),
            ServiceExitCode::Win32(0),
        ));

        let runtime = match tokio::runtime::Runtime::new() {
            Ok(rt) => rt,
            Err(error) => {
                service_log("ERROR", format!("failed to create tokio runtime: {error}"));
                let _ = handler.set_service_status(build_status(
                    ScmState::Stopped,
                    0,
                    Duration::default(),
                    ServiceExitCode::Win32(1),
                ));
                return;
            }
        };
        service_log("INFO", "tokio runtime created");

        let _ = handler.set_service_status(build_status(
            ScmState::StartPending,
            1,
            Duration::from_secs(60),
            ServiceExitCode::Win32(0),
        ));

        let config = match load_service_config() {
            Ok(c) => c,
            Err(error) => {
                service_log("ERROR", format!("failed to load service config: {error}"));
                let _ = handler.set_service_status(build_status(
                    ScmState::Stopped,
                    0,
                    Duration::default(),
                    ServiceExitCode::Win32(1),
                ));
                return;
            }
        };
        service_log("INFO", "service config loaded");

        let _ = handler.set_service_status(build_status(
            ScmState::StartPending,
            2,
            Duration::from_secs(60),
            ServiceExitCode::Win32(0),
        ));

        let (context, mode) = match ServiceContext::startup(config) {
            Ok(result) => result,
            Err(error) => {
                service_log("ERROR", format!("service startup failed: {error}"));
                let _ = handler.set_service_status(build_status(
                    ScmState::Stopped,
                    0,
                    Duration::default(),
                    ServiceExitCode::Win32(1),
                ));
                return;
            }
        };
        service_log("INFO", format!("service context initialized mode={mode:?}"));

        let _service_state = startup_state(matches!(mode, EnrollmentMode::Existing));

        let session_config = build_session_config(&context.config.data_directory);
        let key_provider = match DpapiStoreKeyProvider::new(
            context.config.data_directory.join("keys"),
        ) {
            Ok(p) => p,
            Err(error) => {
                service_log("ERROR", format!("store key provider creation failed: {error}"));
                let _ = handler.set_service_status(build_status(
                    ScmState::Stopped,
                    0,
                    Duration::default(),
                    ServiceExitCode::Win32(1),
                ));
                return;
            }
        };
        let mut monitor = match SessionMonitor::new(
            session_config,
            Box::new(SystemClock),
            Box::new(WtsSessionTokenProvider),
            Box::new(key_provider),
        ) {
            Ok(m) => m,
            Err(error) => {
                service_log("ERROR", format!("session monitor creation failed: {error}"));
                let _ = handler.set_service_status(build_status(
                    ScmState::Stopped,
                    0,
                    Duration::default(),
                    ServiceExitCode::Win32(1),
                ));
                return;
            }
        };

        // Spawn a dedicated thread to own the mutable monitor; the SCM handler is
        // synchronous and must not block on DPAPI or process operations.
        let mount_snapshot = Arc::new(Mutex::new(Vec::<MountAttempt>::new()));
        let mount_snapshot_thread = mount_snapshot.clone();
        let session_thread = std::thread::spawn(move || {
            for event in session_rx {
                match event {
                    SessionEvent::Logon(session_id) => {
                        service_log("INFO", format!("handling SessionEvent::Logon({session_id})"));
                        match monitor.session_logon(session_id) {
                            Ok(_) => service_log("INFO", format!("session_logon({session_id}) succeeded")),
                            Err(error) => service_log(
                                "WARN",
                                format!("session_logon({session_id}) failed: {error}"),
                            ),
                        }
                    }
                    SessionEvent::Logoff(session_id) => {
                        if let Err(error) = monitor.session_logoff(session_id) {
                            service_log(
                                "WARN",
                                format!("session_logoff({session_id}) failed: {error}"),
                            );
                        }
                    }
                    SessionEvent::Stop => break,
                }
                if let Ok(mut guard) = mount_snapshot_thread.lock() {
                    *guard = monitor.snapshot();
                }
            }
            monitor.stop_all();
            if let Ok(mut guard) = mount_snapshot_thread.lock() {
                *guard = monitor.snapshot();
            }
        });

        // Reconcile any interactive sessions that already existed before the service
        // started (e.g., service restart while a user is signed in).
        service_log("INFO", "enumerating active sessions for reconciliation");
        let active_sessions = active_session_ids();
        service_log("INFO", format!("found {} active session(s): {:?}", active_sessions.len(), active_sessions));
        for session_id in active_sessions {
            service_log("INFO", format!("sending SessionEvent::Logon({session_id})"));
            let _ = session_tx.send(SessionEvent::Logon(session_id));
        }

        let _ = handler.set_service_status(build_status(
            ScmState::Running,
            0,
            Duration::default(),
            ServiceExitCode::Win32(0),
        ));
        service_log("INFO", "service status set to Running");

        let handle =
            runtime.spawn_blocking(move || run_service_loop(context, shutdown_rx, mount_snapshot));
        let _ = runtime.block_on(handle);
        runtime.shutdown_timeout(Duration::from_secs(10));

        let _ = session_thread.join();

        service_log("INFO", "service loop ended");
        let _ = handler.set_service_status(build_status(
            ScmState::Stopped,
            0,
            Duration::default(),
            ServiceExitCode::Win32(0),
        ));
    }

    service_dispatcher::start("DlpWindowsService", ffi_service_main)
}

/// Builds the session-monitor configuration from runtime environment values.
#[cfg(windows)]
fn build_session_config(data_directory: &std::path::Path) -> SessionConfig {
    let preferred_drive_letter = std::env::var("DLP_PREFERRED_DRIVE_LETTER")
        .ok()
        .and_then(|v| v.chars().next())
        .unwrap_or('P')
        .to_ascii_uppercase();
    let sign_out_grace_seconds = std::env::var("DLP_SIGN_OUT_GRACE_SECONDS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(30);
    let host_binary_path = std::env::var("DLP_DRIVE_HOST_BINARY_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(r"C:\Program Files\DLP\dlp-drive-host.exe"));

    SessionConfig {
        data_directory: data_directory.to_path_buf(),
        preferred_drive_letter,
        sign_out_grace_seconds,
        host_binary_path,
    }
}

/// Loads service configuration from the runtime provider. The default implementation
/// resolves values from environment variables so the service can start without a
/// committed secret; callers may replace this for tests.
#[cfg(windows)]
fn load_service_config() -> Result<ServiceConfig, ServiceStartError> {
    use std::str::FromStr;

    let device_id = std::env::var("DLP_DEVICE_ID")
        .map_err(|_| ServiceStartError::ConfigMissing)
        .and_then(|v| DeviceId::parse(&v).map_err(|_| ServiceStartError::ConfigInvalid))?;
    let server_url =
        std::env::var("DLP_SERVER_URL").map_err(|_| ServiceStartError::ConfigMissing)?;
    let phase1_root_ca_value =
        std::env::var("DLP_ROOT_CA_PEM").map_err(|_| ServiceStartError::ConfigMissing)?;
    let phase1_root_ca_pem = if phase1_root_ca_value.contains("BEGIN CERTIFICATE") {
        phase1_root_ca_value
    } else {
        std::fs::read_to_string(&phase1_root_ca_value)
            .map_err(|_| ServiceStartError::ConfigInvalid)?
    };
    let data_directory = std::env::var("DLP_DATA_DIRECTORY")
        .map_err(|_| ServiceStartError::ConfigMissing)
        .map(PathBuf::from)?;
    let cache_directory = std::env::var("DLP_CACHE_DIRECTORY")
        .map_err(|_| ServiceStartError::ConfigMissing)
        .map(PathBuf::from)?;
    let configuration_key_id =
        std::env::var("DLP_CONFIGURATION_KEY_ID").unwrap_or_else(|_| "phase1-config-signer".into());
    let configuration_public_key = std::env::var("DLP_CONFIGURATION_PUBLIC_KEY_HEX")
        .map_err(|_| ServiceStartError::ConfigMissing)
        .and_then(|hex| hex::decode_to_array(&hex).ok_or(ServiceStartError::ConfigInvalid))?;

    let parse_duration = |key: &str, default_secs: u64| {
        std::env::var(key)
            .ok()
            .and_then(|v| u64::from_str(&v).ok())
            .map(Duration::from_secs)
            .unwrap_or_else(|| Duration::from_secs(default_secs))
    };

    Ok(ServiceConfig {
        device_id,
        server_url,
        phase1_root_ca_pem,
        data_directory,
        cache_directory,
        enrollment_token: std::env::var("DLP_AGENT_ENROLLMENT_TOKEN").ok(),
        configuration_key_id,
        configuration_public_key,
        poll_interval: parse_duration("DLP_POLL_INTERVAL_SECONDS", 300),
        health_interval: parse_duration("DLP_HEALTH_INTERVAL_SECONDS", 60),
        start_timeout: parse_duration("DLP_START_TIMEOUT_SECONDS", 60),
        stop_timeout: parse_duration("DLP_STOP_TIMEOUT_SECONDS", 10),
    })
}

#[cfg(windows)]
mod hex {
    pub fn decode_to_array(input: &str) -> Option<[u8; 32]> {
        if input.len() != 64 {
            return None;
        }
        let mut output = [0u8; 32];
        for (index, chunk) in input.as_bytes().chunks(2).enumerate() {
            let chunk = std::str::from_utf8(chunk).ok()?;
            output[index] = u8::from_str_radix(chunk, 16).ok()?;
        }
        Some(output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn startup_state_reflects_credential_availability() {
        assert_eq!(startup_state(true), ServiceState::Running);
        assert_eq!(
            startup_state(false),
            ServiceState::ReplacementEnrollmentRequired
        );
    }

    #[test]
    fn service_start_error_codes_are_stable() {
        assert_eq!(
            ServiceStartError::CredentialLoadFailed.to_string(),
            "credential_load_failed"
        );
    }
}

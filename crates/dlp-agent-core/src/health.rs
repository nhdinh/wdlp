//! Stable, redacted local health snapshots.

use crate::config_cache::{CacheError, ConfigurationCache};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HealthSnapshot {
    pub agent_version: String,
    pub service_state: String,
    pub config_state: String,
    pub drive_state: String,
    pub active_bundle_version: Option<String>,
    pub last_successful_contact: Option<u64>,
    pub diagnostic: Option<RedactedDiagnostic>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RedactedDiagnostic {
    EnrollmentDenied,
    CredentialUnavailable,
    ConfigurationRejected,
    NetworkUnavailable,
    CacheCorrupt,
    SessionHostLaunchFailed,
    DriveMountFailed,
    DriveLetterUnavailable,
    SessionDrainTimeout,
    StoreRecoveryFailed,
}
impl RedactedDiagnostic {
    pub const fn code(self) -> &'static str {
        match self {
            Self::EnrollmentDenied => "enrollment_denied",
            Self::CredentialUnavailable => "credential_unavailable",
            Self::ConfigurationRejected => "configuration_rejected",
            Self::NetworkUnavailable => "network_unavailable",
            Self::CacheCorrupt => "cache_corrupt",
            Self::SessionHostLaunchFailed => "session_host_launch_failed",
            Self::DriveMountFailed => "drive_mount_failed",
            Self::DriveLetterUnavailable => "drive_letter_unavailable",
            Self::SessionDrainTimeout => "session_drain_timeout",
            Self::StoreRecoveryFailed => "store_recovery_failed",
        }
    }
}
impl HealthSnapshot {
    pub fn not_mounted(agent_version: impl Into<String>) -> Self {
        Self {
            agent_version: agent_version.into(),
            service_state: "running".into(),
            config_state: "unconfigured".into(),
            drive_state: "not_mounted".into(),
            active_bundle_version: None,
            last_successful_contact: None,
            diagnostic: None,
        }
    }

    /// Builds a health snapshot from the durable cache state.
    ///
    /// Errors are converted to stable redacted codes; no secret or path data is
    /// included in the report.
    pub fn from_cache(
        agent_version: impl Into<String>,
        service_state: impl Into<String>,
        drive_state: impl Into<String>,
        cache: &ConfigurationCache,
        last_successful_contact: Option<u64>,
        diagnostic: Option<RedactedDiagnostic>,
    ) -> Self {
        let agent_version = agent_version.into();
        let service_state = service_state.into();
        let drive_state = drive_state.into();

        let (config_state, active_bundle_version) = match cache.load_pointers() {
            Ok(pointers) => {
                let state = if pointers.current_version.is_some() {
                    "active"
                } else {
                    "unconfigured"
                };
                let version = pointers.current_version.map(|v| v.to_string());
                (state.into(), version)
            }
            Err(CacheError::CorruptPointer | CacheError::MissingBundle) => {
                ("corrupt".into(), None)
            }
            Err(_) => ("error".into(), None),
        };

        Self {
            agent_version,
            service_state,
            config_state,
            drive_state,
            active_bundle_version,
            last_successful_contact,
            diagnostic,
        }
    }

    pub fn with_diagnostic(mut self, diagnostic: RedactedDiagnostic) -> Self {
        self.diagnostic = Some(diagnostic);
        self
    }
}

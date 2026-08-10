//! Stable, redacted local health snapshots.

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
}
impl RedactedDiagnostic {
    pub const fn code(self) -> &'static str {
        match self {
            Self::EnrollmentDenied => "enrollment_denied",
            Self::CredentialUnavailable => "credential_unavailable",
            Self::ConfigurationRejected => "configuration_rejected",
            Self::NetworkUnavailable => "network_unavailable",
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
}

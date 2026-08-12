#![forbid(unsafe_code)]

//! Portable enrollment, signed-configuration, and health-reporting ports.
//! Windows service and filesystem integration remain outside this crate.

use dlp_crypto::{ConfigurationVerifier, CryptoError};
use dlp_protocol::{
    EnrollmentRequestV1, EnrollmentResponseV1, HealthReportV1, SignedConfigurationV1,
};
use dlp_storage::StorageError;
use std::fmt;

pub mod client;
pub mod config_cache;
pub mod enrollment;
pub mod health;

pub use client::{AgentHttpClient, ClientError, ConfigurationTransport};
pub use config_cache::{
    ActivationOutcome, CacheError, CachePointers, ConfigurationCache,
    deserialize_signed_configuration, serialize_signed_configuration,
};
pub use enrollment::{
    EnrollmentCoordinator, EnrollmentCredential, EnrollmentCredentialStore, EnrollmentError,
    EnrollmentMode, EnrollmentTransport,
};
pub use health::{HealthSnapshot, RedactedDiagnostic};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AgentCoreError {
    EnrollmentRejected,
    ConfigurationRejected,
    HealthRejected,
    StorageUnavailable,
}

impl fmt::Display for AgentCoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::EnrollmentRejected => "enrollment was rejected",
            Self::ConfigurationRejected => "signed configuration was rejected",
            Self::HealthRejected => "health report was rejected",
            Self::StorageUnavailable => "agent storage is unavailable",
        };
        write!(formatter, "{message}")
    }
}

impl std::error::Error for AgentCoreError {}

impl From<CryptoError> for AgentCoreError {
    fn from(_: CryptoError) -> Self {
        Self::ConfigurationRejected
    }
}

impl From<StorageError> for AgentCoreError {
    fn from(_: StorageError) -> Self {
        Self::StorageUnavailable
    }
}

/// Transport port for the versioned enrollment DTOs.
pub trait EnrollmentPort {
    fn enroll(
        &mut self,
        request: EnrollmentRequestV1,
    ) -> Result<EnrollmentResponseV1, AgentCoreError>;
}

/// Records endpoint health through the versioned protocol boundary.
pub trait HealthReporter {
    fn report_health(&mut self, report: HealthReportV1) -> Result<(), AgentCoreError>;
}

/// Immutable current and last-known-good signed configurations.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ActiveConfigurationSet {
    current: Option<SignedConfigurationV1>,
    last_known_good: Option<SignedConfigurationV1>,
}

impl ActiveConfigurationSet {
    pub fn current(&self) -> Option<&SignedConfigurationV1> {
        self.current.as_ref()
    }

    pub fn last_known_good(&self) -> Option<&SignedConfigurationV1> {
        self.last_known_good.as_ref()
    }

    fn activate_verified(&mut self, configuration: SignedConfigurationV1) {
        self.last_known_good = self.current.replace(configuration);
    }

    fn version(configuration: &SignedConfigurationV1) -> Result<u64, AgentCoreError> {
        configuration
            .envelope()
            .bundle_version()
            .to_wire()
            .parse()
            .map_err(|_| AgentCoreError::ConfigurationRejected)
    }
}

/// Activates only a strictly verified, schema-compatible configuration.
pub trait ConfigurationActivator {
    fn activate(
        &mut self,
        configuration: SignedConfigurationV1,
        verifier: &ConfigurationVerifier,
    ) -> Result<(), AgentCoreError>;
}

impl ConfigurationActivator for ActiveConfigurationSet {
    fn activate(
        &mut self,
        configuration: SignedConfigurationV1,
        verifier: &ConfigurationVerifier,
    ) -> Result<(), AgentCoreError> {
        verifier.verify(
            configuration.envelope().schema_version(),
            configuration.key_id(),
            &configuration.envelope().canonical_bytes(),
            configuration.signature(),
        )?;
        let next_version = Self::version(&configuration)?;
        if self
            .current
            .as_ref()
            .is_some_and(|current| match Self::version(current) {
                Ok(current_version) => next_version <= current_version,
                Err(_) => true,
            })
        {
            return Err(AgentCoreError::ConfigurationRejected);
        }
        self.activate_verified(configuration);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{ActiveConfigurationSet, ConfigurationActivator, EnrollmentPort, HealthReporter};

    #[test]
    fn exposes_portable_enrollment_configuration_and_health_ports() {
        fn assert_enrollment<T: EnrollmentPort>() {}
        fn assert_activation<T: ConfigurationActivator>() {}
        fn assert_health<T: HealthReporter>() {}
        struct PortHost;
        impl EnrollmentPort for PortHost {
            fn enroll(
                &mut self,
                _request: dlp_protocol::EnrollmentRequestV1,
            ) -> Result<dlp_protocol::EnrollmentResponseV1, super::AgentCoreError> {
                Err(super::AgentCoreError::EnrollmentRejected)
            }
        }
        impl ConfigurationActivator for PortHost {
            fn activate(
                &mut self,
                _configuration: dlp_protocol::SignedConfigurationV1,
                _verifier: &dlp_crypto::ConfigurationVerifier,
            ) -> Result<(), super::AgentCoreError> {
                Err(super::AgentCoreError::ConfigurationRejected)
            }
        }
        impl HealthReporter for PortHost {
            fn report_health(
                &mut self,
                _report: dlp_protocol::HealthReportV1,
            ) -> Result<(), super::AgentCoreError> {
                Ok(())
            }
        }

        assert_enrollment::<PortHost>();
        assert_activation::<PortHost>();
        assert_health::<PortHost>();
        let _ = ActiveConfigurationSet::default();
    }
}

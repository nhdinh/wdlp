//! Noninteractive first-run and replacement enrollment state machine.
//!
//! The coordinator generates the endpoint ECDSA P-256 key and CSR locally,
//! sends only the CSR and one-time token to the server, validates the
//! constrained response, and commits the credential to the machine-DPAPI
//! store before any protected request is attempted.  There is no bearer
//! fallback and no transmission of the endpoint private key.

use crate::client::{AgentHttpClient, ClientError, ValidatedDeviceIdentity};
use dlp_domain::DeviceId;
use dlp_protocol::EnrollmentRequestV1;
use rcgen::{CertificateParams, KeyPair, PKCS_ECDSA_P256_SHA256};
use zeroize::Zeroize;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EnrollmentMode {
    Initial,
    Replacement,
    Existing,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EnrollmentError {
    CredentialUnavailable,
    TransportDenied,
    CsrGeneration,
    InvalidResponse,
    ProfileRejected,
}

impl std::fmt::Display for EnrollmentError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::CredentialUnavailable => "credential_unavailable",
            Self::TransportDenied => "enrollment_denied",
            Self::CsrGeneration => "csr_generation_failed",
            Self::InvalidResponse => "enrollment_response_invalid",
            Self::ProfileRejected => "enrollment_profile_rejected",
        })
    }
}
impl std::error::Error for EnrollmentError {}

impl From<ClientError> for EnrollmentError {
    fn from(error: ClientError) -> Self {
        match error {
            ClientError::InvalidServerUrl
            | ClientError::InvalidTrustAnchor
            | ClientError::TlsConfiguration
            | ClientError::NetworkUnavailable => Self::TransportDenied,
            ClientError::RequestDenied | ClientError::ConfigurationFetchFailed => Self::TransportDenied,
            ClientError::InvalidResponse => Self::InvalidResponse,
            ClientError::ProfileRejected => Self::ProfileRejected,
            ClientError::MissingDeviceCredential => Self::CredentialUnavailable,
        }
    }
}

/// In-memory credential view used between the coordinator and the store.
/// It is zeroized on drop and is never serialized to logs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnrollmentCredential {
    pub device_id: String,
    pub private_key: Vec<u8>,
    pub certificate_chain: String,
    pub serial: Vec<u8>,
    pub expires_after_days: u8,
}

impl EnrollmentCredential {
    pub fn new(
        device_id: impl Into<String>,
        private_key: Vec<u8>,
        certificate_chain: impl Into<String>,
        serial: Vec<u8>,
        expires_after_days: u8,
    ) -> Result<Self, EnrollmentError> {
        let credential = Self {
            device_id: device_id.into(),
            private_key,
            certificate_chain: certificate_chain.into(),
            serial,
            expires_after_days,
        };
        if credential.device_id.is_empty()
            || credential.private_key.is_empty()
            || credential.certificate_chain.is_empty()
            || credential.serial.is_empty()
            || credential.expires_after_days != 30
        {
            return Err(EnrollmentError::InvalidResponse);
        }
        Ok(credential)
    }
}

impl Zeroize for EnrollmentCredential {
    fn zeroize(&mut self) {
        self.device_id.zeroize();
        self.private_key.zeroize();
        self.certificate_chain.zeroize();
        self.serial.zeroize();
        self.expires_after_days.zeroize();
    }
}

impl Drop for EnrollmentCredential {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// The transport sees a signed CSR and one-time token, never a private key.
pub trait EnrollmentTransport {
    fn enroll(
        &mut self,
        request: EnrollmentRequestV1,
        csr_pem: &str,
        prior_serial: Option<&[u8]>,
    ) -> Result<ValidatedDeviceIdentity, EnrollmentError>;
}

pub trait EnrollmentCredentialStore {
    fn load_credential(
        &self) -> Result<EnrollmentCredential, EnrollmentError>;
    fn save_credential(
        &self,
        credential: &EnrollmentCredential,
    ) -> Result<(), EnrollmentError>;
}

pub struct EnrollmentCoordinator<T, S> {
    transport: T,
    store: S,
}

impl<T: EnrollmentTransport, S: EnrollmentCredentialStore> EnrollmentCoordinator<T, S> {
    pub fn new(transport: T, store: S) -> Self {
        Self { transport, store }
    }

    /// Returns `Existing` if the local credential loads successfully; otherwise
    /// performs a complete initial or replacement enrollment.
    pub fn startup(
        &mut self,
        device_id: DeviceId,
        token: String,
        prior_serial: Option<&[u8]>,
    ) -> Result<EnrollmentMode, EnrollmentError> {
        if self.store.load_credential().is_ok() {
            return Ok(EnrollmentMode::Existing);
        }

        let mode = if prior_serial.is_some() {
            EnrollmentMode::Replacement
        } else {
            EnrollmentMode::Initial
        };

        let mut token = token;
        let result = self.enroll_fresh(device_id, &token, prior_serial);
        // The token is single-use; clear it from memory regardless of outcome.
        token.zeroize();
        result?;
        Ok(mode)
    }

    fn enroll_fresh(
        &mut self,
        device_id: DeviceId,
        token: &str,
        prior_serial: Option<&[u8]>,
    ) -> Result<ValidatedDeviceIdentity, EnrollmentError> {
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256,
        )
        .map_err(|_| EnrollmentError::CsrGeneration)?;
        let params = CertificateParams::new(Vec::<String>::new())
            .map_err(|_| EnrollmentError::CsrGeneration)?;
        let mut csr = params
            .serialize_request(&key)
            .map_err(|_| EnrollmentError::CsrGeneration)?
            .pem()
            .map_err(|_| EnrollmentError::CsrGeneration)?;

        let request = EnrollmentRequestV1::new(1, device_id, token)
            .map_err(|_| EnrollmentError::TransportDenied)?;
        let identity = self.transport.enroll(request, &csr, prior_serial)?;

        let mut private_key = key.serialize_pem().into_bytes();
        let credential = EnrollmentCredential::new(
            identity.device_id.clone(),
            private_key.clone(),
            identity.certificate_chain_pem.clone(),
            identity.serial.clone(),
            30,
        )?;
        self.store.save_credential(&credential)?;

        private_key.zeroize();
        csr.zeroize();
        Ok(identity)
    }
}

impl EnrollmentTransport for AgentHttpClient {
    fn enroll(
        &mut self,
        request: EnrollmentRequestV1,
        csr_pem: &str,
        prior_serial: Option<&[u8]>,
    ) -> Result<ValidatedDeviceIdentity, EnrollmentError> {
        self.post_enrollment(
            request.device_id(),
            request.enrollment_token(),
            csr_pem,
            prior_serial,
        )
        .map_err(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Transport {
        saw_private_key: bool,
        saw_prior_serial: bool,
    }
    impl EnrollmentTransport for Transport {
        fn enroll(
            &mut self,
            _request: EnrollmentRequestV1,
            csr: &str,
            prior_serial: Option<&[u8]>,
        ) -> Result<ValidatedDeviceIdentity, EnrollmentError> {
            self.saw_private_key = csr.contains("PRIVATE KEY");
            self.saw_prior_serial = prior_serial.is_some();
            Ok(ValidatedDeviceIdentity {
                device_id: "device-01".into(),
                certificate_chain_pem: "chain".into(),
                serial: vec![1],
                expires_after_epoch_seconds: 1,
            })
        }
    }
    struct Store {
        usable: bool,
        saved: std::sync::Mutex<Option<EnrollmentCredential>>,
    }
    impl EnrollmentCredentialStore for Store {
        fn load_credential(
            &self,
        ) -> Result<EnrollmentCredential, EnrollmentError> {
            if self.usable {
                Ok(EnrollmentCredential::new(
                    "device-01",
                    vec![1],
                    "chain",
                    vec![1],
                    30,
                )
                .unwrap())
            } else {
                Err(EnrollmentError::CredentialUnavailable)
            }
        }
        fn save_credential(
            &self,
            credential: &EnrollmentCredential,
        ) -> Result<(), EnrollmentError> {
            *self.saved.lock().unwrap() = Some(credential.clone());
            Ok(())
        }
    }

    #[test]
    fn startup_generates_csr_without_sending_private_key() {
        let mut coordinator = EnrollmentCoordinator::new(
            Transport {
                saw_private_key: false,
                saw_prior_serial: false,
            },
            Store {
                usable: false,
                saved: std::sync::Mutex::new(None),
            },
        );
        assert_eq!(
            coordinator
                .startup(
                    DeviceId::parse("device-01").unwrap(),
                    "single-use".into(),
                    None
                )
                .unwrap(),
            EnrollmentMode::Initial
        );
        assert!(!coordinator.transport.saw_private_key);
    }

    #[test]
    fn startup_returns_existing_when_store_has_usable_credential() {
        let mut coordinator = EnrollmentCoordinator::new(
            Transport {
                saw_private_key: false,
                saw_prior_serial: false,
            },
            Store {
                usable: true,
                saved: std::sync::Mutex::new(None),
            },
        );
        assert_eq!(
            coordinator
                .startup(
                    DeviceId::parse("device-01").unwrap(),
                    "single-use".into(),
                    None
                )
            .unwrap(),
            EnrollmentMode::Existing
        );
    }

    #[test]
    fn replacement_includes_prior_serial_reference() {
        let mut coordinator = EnrollmentCoordinator::new(
            Transport {
                saw_private_key: false,
                saw_prior_serial: false,
            },
            Store {
                usable: false,
                saved: std::sync::Mutex::new(None),
            },
        );
        let _ = coordinator.startup(
            DeviceId::parse("device-01").unwrap(),
            "replacement-token".into(),
            Some(&[2, 3]),
        );
        assert!(coordinator.transport.saw_prior_serial);
    }
}

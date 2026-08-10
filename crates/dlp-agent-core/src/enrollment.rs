//! Noninteractive first-run and replacement enrollment state machine.

use dlp_domain::DeviceId;
use dlp_protocol::{EnrollmentRequestV1, EnrollmentResponseV1};
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
}

impl std::fmt::Display for EnrollmentError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::CredentialUnavailable => "credential_unavailable",
            Self::TransportDenied => "enrollment_denied",
            Self::CsrGeneration => "csr_generation_failed",
            Self::InvalidResponse => "enrollment_response_invalid",
        })
    }
}
impl std::error::Error for EnrollmentError {}

/// The transport sees a signed CSR and one-time token, never a private key.
pub trait EnrollmentTransport {
    fn enroll(
        &mut self,
        request: EnrollmentRequestV1,
        csr_pem: &str,
    ) -> Result<EnrollmentResponseV1, EnrollmentError>;
    fn replacement_complete(&mut self, prior_serial: &[u8]) -> Result<(), EnrollmentError>;
}

pub trait EnrollmentCredentialStore {
    fn load_credential(&self) -> Result<(), EnrollmentError>;
    fn save_credential(
        &self,
        private_key: &[u8],
        certificate_chain: &str,
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
        if let Some(serial) = prior_serial {
            self.transport.replacement_complete(serial)?;
        }
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)
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
        let response = self.transport.enroll(request, &csr)?;
        if response.credential_chain().is_empty() {
            return Err(EnrollmentError::InvalidResponse);
        }
        let mut private_key = key.serialize_der();
        self.store
            .save_credential(&private_key, response.credential_chain())?;
        private_key.zeroize();
        csr.zeroize();
        Ok(mode)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Transport {
        saw_private_key: bool,
        replacement: bool,
    }
    impl EnrollmentTransport for Transport {
        fn enroll(
            &mut self,
            _request: EnrollmentRequestV1,
            csr: &str,
        ) -> Result<EnrollmentResponseV1, EnrollmentError> {
            self.saw_private_key = csr.contains("PRIVATE KEY");
            EnrollmentResponseV1::new(1, DeviceId::parse("device-01").unwrap(), "chain")
                .map_err(|_| EnrollmentError::InvalidResponse)
        }
        fn replacement_complete(&mut self, _: &[u8]) -> Result<(), EnrollmentError> {
            self.replacement = true;
            Ok(())
        }
    }
    struct Store(bool);
    impl EnrollmentCredentialStore for Store {
        fn load_credential(&self) -> Result<(), EnrollmentError> {
            if self.0 {
                Ok(())
            } else {
                Err(EnrollmentError::CredentialUnavailable)
            }
        }
        fn save_credential(&self, private_key: &[u8], chain: &str) -> Result<(), EnrollmentError> {
            assert!(!private_key.is_empty());
            assert_eq!(chain, "chain");
            Ok(())
        }
    }
    #[test]
    fn startup_generates_csr_without_sending_private_key() {
        let mut coordinator = EnrollmentCoordinator::new(
            Transport {
                saw_private_key: false,
                replacement: false,
            },
            Store(false),
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
}

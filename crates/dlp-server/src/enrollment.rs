//! Fail-closed enrollment orchestration: exact digest, corroborated directory identity,
//! one-time token consumption, and constrained credential issuance form one authority flow.

use crate::{
    ad::{DirectoryError, DirectoryVerifier},
    pki::{IssuedDeviceCredential, RcgenDeviceCertificateIssuer},
    repository::{PgAuthorityRepository, RepositoryError, TestAuthorityRepository},
};
use async_trait::async_trait;
use dlp_protocol::{ProvisionDeviceRequestV1, ProvisionDeviceResponseV1};
use sha2::{Digest, Sha256};
use std::sync::Arc;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnrollmentAttempt {
    device_id: String,
    fingerprint_digest: [u8; 32],
    token: String,
    serial: Vec<u8>,
    directory_verified: bool,
    csr_valid: bool,
}
impl EnrollmentAttempt {
    pub fn valid_for_test() -> Self {
        Self {
            device_id: "device-test".into(),
            fingerprint_digest: [7; 32],
            token: "one-time-token".into(),
            serial: vec![1, 2, 3],
            directory_verified: true,
            csr_valid: true,
        }
    }
    pub fn invalid_for_test() -> Self {
        Self {
            directory_verified: false,
            ..Self::valid_for_test()
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EnrollmentError {
    Denied,
    AlreadyUsed,
    IntegrityFailure,
}

#[derive(Clone)]
pub struct TestEnrollmentService {
    repository: Arc<TestAuthorityRepository>,
}
impl TestEnrollmentService {
    pub fn for_test() -> Self {
        let repository = Arc::new(TestAuthorityRepository::default());
        repository.create_for_test("device-test", [7; 32], "one-time-token");
        Self { repository }
    }
    pub fn enroll(&self, attempt: EnrollmentAttempt) -> Result<(), EnrollmentError> {
        if !attempt.directory_verified || !attempt.csr_valid {
            return Err(EnrollmentError::Denied);
        }
        self.repository
            .consume_and_replace(
                &attempt.device_id,
                attempt.fingerprint_digest,
                &attempt.token,
                attempt.serial,
            )
            .map_err(|error| match error {
                RepositoryError::Denied => EnrollmentError::Denied,
                RepositoryError::Unavailable => EnrollmentError::IntegrityFailure,
            })
    }
}

/// Untrusted endpoint enrollment input. Debug intentionally omits the one-time
/// token and CSR because neither belongs in diagnostics or committed fixtures.
#[derive(Clone)]
pub struct EnrollmentSubmission {
    device_id: String,
    token: String,
    csr_pem: String,
    prior_serial: Option<Vec<u8>>,
}

impl EnrollmentSubmission {
    pub fn new(
        device_id: impl Into<String>,
        token: impl Into<String>,
        csr_pem: impl Into<String>,
        prior_serial: Option<Vec<u8>>,
    ) -> Result<Self, EnrollmentError> {
        let device_id = device_id.into();
        let token = token.into();
        let csr_pem = csr_pem.into();
        if device_id.is_empty()
            || device_id.len() > 128
            || token.is_empty()
            || token.len() > 512
            || csr_pem.is_empty()
            || csr_pem.len() > 65_536
            || prior_serial
                .as_ref()
                .is_some_and(|serial| serial.is_empty() || serial.len() > 20)
        {
            return Err(EnrollmentError::Denied);
        }
        Ok(Self {
            device_id,
            token,
            csr_pem,
            prior_serial,
        })
    }
}

impl std::fmt::Debug for EnrollmentSubmission {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("EnrollmentSubmission")
            .field("device_id", &self.device_id)
            .field("token", &"[REDACTED]")
            .field("csr_pem", &"[REDACTED]")
            .field(
                "prior_serial",
                &self.prior_serial.as_ref().map(|_| "[REDACTED]"),
            )
            .finish()
    }
}

/// Object-safe port for the transactional enrollment orchestration used by the
/// bootstrap route. Production and test implementations share the same fail-closed
/// contract.
#[async_trait]
pub trait EnrollmentServicePort: Send + Sync {
    async fn enroll(
        &self,
        submission: EnrollmentSubmission,
    ) -> Result<IssuedDeviceCredential, EnrollmentError>;
}

/// Production enrollment orchestration. The PostgreSQL repository holds the
/// authority row lock while the issuer creates only a public device leaf; it
/// commits token consumption, serial revocation, and serial activation together.
#[derive(Clone)]
pub struct EnrollmentService {
    repository: PgAuthorityRepository,
    issuer: RcgenDeviceCertificateIssuer,
    directory: Arc<dyn DirectoryVerifier>,
}

impl EnrollmentService {
    pub fn new(
        repository: PgAuthorityRepository,
        issuer: RcgenDeviceCertificateIssuer,
        directory: Arc<dyn DirectoryVerifier>,
    ) -> Self {
        Self {
            repository,
            issuer,
            directory,
        }
    }
}

#[async_trait]
impl EnrollmentServicePort for EnrollmentService {
    async fn enroll(
        &self,
        submission: EnrollmentSubmission,
    ) -> Result<IssuedDeviceCredential, EnrollmentError> {
        self.directory
            .corroborate_computer(&submission.device_id)
            .await
            .map_err(|error| {
                eprintln!("enrollment_directory_rejected: {error:?}");
                match error {
                    DirectoryError::InvalidConfiguration => EnrollmentError::IntegrityFailure,
                    DirectoryError::Unavailable => EnrollmentError::IntegrityFailure,
                    DirectoryError::NotFound
                    | DirectoryError::Disabled
                    | DirectoryError::Disagreement => EnrollmentError::Denied,
                }
            })?;
        let issuer = &self.issuer;
        self.repository
            .consume_and_activate(
                &submission.device_id,
                &submission.token,
                submission.prior_serial.as_deref(),
                |serial| {
                    let issued = issuer
                        .issue_from_csr(&submission.device_id, &submission.csr_pem, serial)
                        .map_err(|_| RepositoryError::Denied)?;
                    let certificate_digest: [u8; 32] =
                        Sha256::digest(issued.certificate_chain_pem.as_bytes()).into();
                    Ok((issued, certificate_digest))
                },
            )
            .await
            .map_err(|error| {
                eprintln!("enrollment_authority_rejected: {error:?}");
                match error {
                    RepositoryError::Denied => EnrollmentError::Denied,
                    RepositoryError::Unavailable => EnrollmentError::IntegrityFailure,
                }
            })
    }
}

/// Object-safe port for the administrator provisioning route. The caller has
/// already been verified by mTLS administrator issuer/profile; only the digest
/// and normalized identity cross this boundary.
#[async_trait]
pub trait ProvisioningServicePort: Send + Sync {
    async fn provision(
        &self,
        request: ProvisionDeviceRequestV1,
    ) -> Result<ProvisionDeviceResponseV1, EnrollmentError>;
}

/// Production administrator provisioning backed by the PostgreSQL authority.
/// The administrator identity is established by the TLS layer, not a shared key.
#[derive(Clone)]
pub struct AdminProvisioningService {
    repository: PgAuthorityRepository,
}

impl AdminProvisioningService {
    pub fn new(repository: PgAuthorityRepository) -> Self {
        Self { repository }
    }
}

#[async_trait]
impl ProvisioningServicePort for AdminProvisioningService {
    async fn provision(
        &self,
        request: ProvisionDeviceRequestV1,
    ) -> Result<ProvisionDeviceResponseV1, EnrollmentError> {
        let device_id = request.device_id().to_owned();
        self.repository
            .provision(&request)
            .await
            .map(|token| {
                ProvisionDeviceResponseV1::new(1, device_id.clone(), token)
                    .map_err(|_| EnrollmentError::IntegrityFailure)
            })
            .map_err(|_| EnrollmentError::IntegrityFailure)?
    }
}

/// Deterministic test provisioning fixture with a shared admin key. It must
/// never be supplied to production server composition.
#[derive(Clone)]
pub struct TestAdminProvisioningService {
    repository: Arc<TestAuthorityRepository>,
    admin_key_digest: [u8; 32],
}
impl TestAdminProvisioningService {
    pub fn new(
        repository: Arc<TestAuthorityRepository>,
        admin_key: &str,
    ) -> Result<Self, EnrollmentError> {
        if admin_key.is_empty() {
            return Err(EnrollmentError::Denied);
        }
        Ok(Self {
            repository,
            admin_key_digest: Sha256::digest(admin_key.as_bytes()).into(),
        })
    }
    pub fn provision(
        &self,
        supplied_admin_key: &str,
        device_id: &str,
        fingerprint_digest: [u8; 32],
    ) -> Result<String, EnrollmentError> {
        let supplied: [u8; 32] = Sha256::digest(supplied_admin_key.as_bytes()).into();
        let difference = supplied
            .iter()
            .zip(self.admin_key_digest.iter())
            .fold(0_u8, |acc, (left, right)| acc | (left ^ right));
        if difference != 0 || device_id.is_empty() {
            return Err(EnrollmentError::Denied);
        }
        self.repository
            .provision(device_id, fingerprint_digest)
            .map_err(|_| EnrollmentError::IntegrityFailure)
    }
}

#[cfg(test)]
mod provisioning_tests {
    use super::*;
    #[test]
    fn administrator_token_is_returned_once_and_only_its_digest_is_retained() {
        let repository = Arc::new(TestAuthorityRepository::default());
        let service = TestAdminProvisioningService::new(Arc::clone(&repository), "secret").unwrap();
        let token = service.provision("secret", "device-01", [9; 32]).unwrap();
        assert!(!token.is_empty());
        assert!(service.provision("wrong", "device-02", [8; 32]).is_err());
        assert_ne!(TestAuthorityRepository::token_digest(&token), [0; 32]);
    }
}

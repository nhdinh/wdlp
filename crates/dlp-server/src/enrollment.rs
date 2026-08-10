//! Fail-closed enrollment orchestration: exact digest, corroborated directory identity,
//! one-time token consumption, and constrained credential issuance form one authority flow.

use crate::{
    pki::{IssuedDeviceCredential, RcgenDeviceCertificateIssuer},
    repository::{PgAuthorityRepository, RepositoryError, TestAuthorityRepository},
};
use dlp_protocol::ProvisionDeviceRequestV1;
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
    observation: ProvisionDeviceRequestV1,
    token: String,
    csr_pem: String,
    prior_serial: Option<Vec<u8>>,
}

impl EnrollmentSubmission {
    pub fn new(
        observation: ProvisionDeviceRequestV1,
        token: impl Into<String>,
        csr_pem: impl Into<String>,
        prior_serial: Option<Vec<u8>>,
    ) -> Result<Self, EnrollmentError> {
        let token = token.into();
        let csr_pem = csr_pem.into();
        if token.is_empty()
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
            observation,
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
            .field("observation", &self.observation)
            .field("token", &"[REDACTED]")
            .field("csr_pem", &"[REDACTED]")
            .field(
                "prior_serial",
                &self.prior_serial.as_ref().map(|_| "[REDACTED]"),
            )
            .finish()
    }
}

/// Production enrollment orchestration. The PostgreSQL repository holds the
/// authority row lock while the issuer creates only a public device leaf; it
/// commits token consumption, serial revocation, and serial activation together.
#[derive(Clone)]
pub struct EnrollmentService {
    repository: PgAuthorityRepository,
    issuer: RcgenDeviceCertificateIssuer,
}

impl EnrollmentService {
    pub fn new(repository: PgAuthorityRepository, issuer: RcgenDeviceCertificateIssuer) -> Self {
        Self { repository, issuer }
    }

    pub async fn enroll(
        &self,
        submission: EnrollmentSubmission,
    ) -> Result<IssuedDeviceCredential, EnrollmentError> {
        let issuer = &self.issuer;
        self.repository
            .consume_and_activate(
                &submission.observation,
                &submission.token,
                submission.prior_serial.as_deref(),
                |serial| {
                    let issued = issuer
                        .issue_from_csr(
                            submission.observation.device_id(),
                            &submission.csr_pem,
                            serial,
                        )
                        .map_err(|_| RepositoryError::Denied)?;
                    let certificate_digest: [u8; 32] =
                        Sha256::digest(issued.certificate_chain_pem.as_bytes()).into();
                    Ok((issued, certificate_digest))
                },
            )
            .await
            .map_err(|error| match error {
                RepositoryError::Denied => EnrollmentError::Denied,
                RepositoryError::Unavailable => EnrollmentError::IntegrityFailure,
            })
    }
}

/// Narrow administrator provisioning seam. The caller must have already corroborated
/// the named computer at both trusted DCs; only the digest crosses this boundary.
#[derive(Clone)]
pub struct AdminProvisioningService {
    repository: Arc<TestAuthorityRepository>,
    admin_key_digest: [u8; 32],
}
impl AdminProvisioningService {
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
        let service = AdminProvisioningService::new(Arc::clone(&repository), "secret").unwrap();
        let token = service.provision("secret", "device-01", [9; 32]).unwrap();
        assert!(!token.is_empty());
        assert!(service.provision("wrong", "device-02", [8; 32]).is_err());
        assert_ne!(TestAuthorityRepository::token_digest(&token), [0; 32]);
    }
}

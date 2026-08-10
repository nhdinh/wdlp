//! Fail-closed enrollment orchestration: exact digest, corroborated directory identity,
//! one-time token consumption, and constrained credential issuance form one authority flow.

use crate::repository::{AuthorityRepository, RepositoryError};
use std::sync::Arc;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnrollmentAttempt { device_id: String, fingerprint_digest: [u8; 32], token: String, serial: Vec<u8>, directory_verified: bool, csr_valid: bool }
impl EnrollmentAttempt {
    pub fn valid_for_test() -> Self { Self { device_id: "device-test".into(), fingerprint_digest: [7; 32], token: "one-time-token".into(), serial: vec![1, 2, 3], directory_verified: true, csr_valid: true } }
    pub fn invalid_for_test() -> Self { Self { directory_verified: false, ..Self::valid_for_test() } }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EnrollmentError { Denied, AlreadyUsed, IntegrityFailure }

#[derive(Clone)]
pub struct EnrollmentService { repository: Arc<AuthorityRepository> }
impl EnrollmentService {
    pub fn for_test() -> Self { let repository = Arc::new(AuthorityRepository::default()); repository.create_for_test("device-test", [7; 32], "one-time-token"); Self { repository } }
    pub fn enroll(&self, attempt: EnrollmentAttempt) -> Result<(), EnrollmentError> {
        if !attempt.directory_verified || !attempt.csr_valid { return Err(EnrollmentError::Denied); }
        self.repository.consume_and_replace(&attempt.device_id, attempt.fingerprint_digest, &attempt.token, attempt.serial).map_err(|error| match error { RepositoryError::Denied => EnrollmentError::Denied, RepositoryError::Unavailable => EnrollmentError::IntegrityFailure })
    }
}

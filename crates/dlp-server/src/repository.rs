//! Transactional authority state.  Production adapters map these invariants to SQL locks.

use sha2::{Digest, Sha256};
use std::{collections::HashMap, sync::Mutex};
use uuid::Uuid;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnrollmentRecord {
    pub fingerprint_digest: [u8; 32],
    pub token_digest: [u8; 32],
    pub active_serial: Option<Vec<u8>>,
    pub revoked_serials: Vec<Vec<u8>>,
}

#[derive(Default)]
pub struct AuthorityRepository {
    records: Mutex<HashMap<String, EnrollmentRecord>>,
}

impl AuthorityRepository {
    pub fn token_digest(token: &str) -> [u8; 32] {
        Sha256::digest(token.as_bytes()).into()
    }
    pub fn create_for_test(&self, device_id: &str, fingerprint_digest: [u8; 32], token: &str) {
        self.records.lock().expect("authority lock").insert(
            device_id.into(),
            EnrollmentRecord {
                fingerprint_digest,
                token_digest: Self::token_digest(token),
                active_serial: None,
                revoked_serials: vec![],
            },
        );
    }
    /// Creates a server-owned, OS-random token. The caller receives plaintext once;
    /// state retains only its digest, never the value or raw hardware sources.
    pub fn provision(
        &self,
        device_id: &str,
        fingerprint_digest: [u8; 32],
    ) -> Result<String, RepositoryError> {
        let token = Uuid::new_v4().simple().to_string();
        let record = EnrollmentRecord {
            fingerprint_digest,
            token_digest: Self::token_digest(&token),
            active_serial: None,
            revoked_serials: vec![],
        };
        self.records
            .lock()
            .map_err(|_| RepositoryError::Unavailable)?
            .insert(device_id.to_owned(), record);
        Ok(token)
    }
    pub fn consume_and_replace(
        &self,
        device_id: &str,
        fingerprint_digest: [u8; 32],
        token: &str,
        serial: Vec<u8>,
    ) -> Result<(), RepositoryError> {
        let mut records = self
            .records
            .lock()
            .map_err(|_| RepositoryError::Unavailable)?;
        let record = records.get_mut(device_id).ok_or(RepositoryError::Denied)?;
        if record.fingerprint_digest != fingerprint_digest
            || record.token_digest != Self::token_digest(token)
            || serial.is_empty()
        {
            return Err(RepositoryError::Denied);
        }
        // Atomic under this repository lock: consume token and revoke predecessor before activation.
        record.token_digest = [0; 32];
        if let Some(old) = record.active_serial.replace(serial) {
            record.revoked_serials.push(old);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RepositoryError {
    Denied,
    Unavailable,
}

//! Transactional authority state.  Production adapters map these invariants to SQL locks.

use crate::tls::{AuthenticatedDevice, CredentialStatus};
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

/// Narrow persistence port for the post-enrollment tracer. The production
/// adapter replaces this mutex-backed implementation with the forward-only
/// PostgreSQL ledger; the authorization invariant remains the same.
#[derive(Default)]
pub struct RouteRepository {
    devices: Mutex<HashMap<String, DeviceRouteRecord>>,
}

#[derive(Default)]
struct DeviceRouteRecord {
    active_serial: Option<Vec<u8>>,
    revoked_serials: Vec<Vec<u8>>,
    health_reports: Vec<String>,
}

impl RouteRepository {
    pub fn activate_device(&self, device_id: &str, serial: &[u8]) {
        if let Ok(mut devices) = self.devices.lock() {
            let record = devices.entry(device_id.to_owned()).or_default();
            if let Some(previous) = record.active_serial.replace(serial.to_vec()) {
                record.revoked_serials.push(previous);
            }
        }
    }

    pub fn revoke_device(&self, device_id: &str, serial: &[u8]) {
        if let Ok(mut devices) = self.devices.lock()
            && let Some(record) = devices.get_mut(device_id)
        {
            if record.active_serial.as_deref() == Some(serial) {
                record.active_serial = None;
            }
            if !record
                .revoked_serials
                .iter()
                .any(|known| known.as_slice() == serial)
            {
                record.revoked_serials.push(serial.to_vec());
            }
        }
    }

    pub fn credential_status(&self, device_id: &str, serial: &[u8]) -> CredentialStatus {
        let Ok(devices) = self.devices.lock() else {
            return CredentialStatus::Expired;
        };
        let Some(record) = devices.get(device_id) else {
            return CredentialStatus::Expired;
        };
        if record
            .revoked_serials
            .iter()
            .any(|known| known.as_slice() == serial)
        {
            CredentialStatus::Revoked
        } else if record.active_serial.as_deref() == Some(serial) {
            CredentialStatus::Active
        } else {
            CredentialStatus::Expired
        }
    }

    pub fn authorize_device(
        &self,
        device: &AuthenticatedDevice,
    ) -> Result<(), RouteRepositoryError> {
        match self.credential_status(device.device_id(), device.credential_serial()) {
            CredentialStatus::Active => Ok(()),
            CredentialStatus::Revoked | CredentialStatus::Expired => {
                Err(RouteRepositoryError::Denied)
            }
        }
    }

    pub fn record_health(
        &self,
        device_id: &str,
        drive_state: &str,
    ) -> Result<(), RouteRepositoryError> {
        let mut devices = self
            .devices
            .lock()
            .map_err(|_| RouteRepositoryError::Unavailable)?;
        let record = devices
            .get_mut(device_id)
            .ok_or(RouteRepositoryError::Denied)?;
        record.health_reports.push(drive_state.to_owned());
        Ok(())
    }

    pub fn health_report_count(&self, device_id: &str) -> usize {
        self.devices
            .lock()
            .ok()
            .and_then(|records| {
                records
                    .get(device_id)
                    .map(|record| record.health_reports.len())
            })
            .unwrap_or_default()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RouteRepositoryError {
    Denied,
    Unavailable,
}

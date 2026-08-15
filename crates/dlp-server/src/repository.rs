//! Transactional authority state. Production adapters use PostgreSQL row locks;
//! mutex-backed stores below exist only as deterministic test fixtures.

use crate::tls::{AuthenticatedDevice, CredentialStatus};
use async_trait::async_trait;
use dlp_protocol::{ProvisionDeviceRequestV1, SignedConfigurationV1};
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Row};
use std::{
    collections::{BTreeMap, HashMap},
    sync::Mutex,
};
use uuid::Uuid;

/// PostgreSQL is the only authority adapter that may be selected for server
/// deployment. It is intentionally impossible to construct without a real pool.
#[derive(Clone)]
pub struct PgAuthorityRepository {
    pool: PgPool,
}

impl PgAuthorityRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// Issues a CSPRNG token, returns it to the trusted provisioning caller once,
    /// and persists only its SHA-256 digest with a database-owned expiry.
    pub async fn provision(
        &self,
        request: &ProvisionDeviceRequestV1,
    ) -> Result<String, RepositoryError> {
        let token = Uuid::new_v4().simple().to_string();
        let token_digest: [u8; 32] = Sha256::digest(token.as_bytes()).into();
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|_| RepositoryError::Unavailable)?;

        // Locking an existing device row makes duplicate provisioning serialize.
        // The unique constraints remain the final authority for a first insert race.
        sqlx::query("SELECT device_id FROM enrollment_authority WHERE device_id = $1 FOR UPDATE")
            .bind(request.device_id())
            .fetch_optional(&mut *transaction)
            .await
            .map_err(|_| RepositoryError::Unavailable)?;
        let result = sqlx::query(
            "INSERT INTO enrollment_authority (device_id, fingerprint_version, fingerprint_digest, ad_object_guid, ad_object_sid, ad_dns_name, ad_domain, preferred_drive_letter, token_digest, token_expires_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, CURRENT_TIMESTAMP + INTERVAL '10 minutes') ON CONFLICT (device_id) DO UPDATE SET fingerprint_version = EXCLUDED.fingerprint_version, fingerprint_digest = EXCLUDED.fingerprint_digest, ad_object_guid = EXCLUDED.ad_object_guid, ad_object_sid = EXCLUDED.ad_object_sid, ad_dns_name = EXCLUDED.ad_dns_name, ad_domain = EXCLUDED.ad_domain, preferred_drive_letter = EXCLUDED.preferred_drive_letter, token_digest = EXCLUDED.token_digest, token_expires_at = EXCLUDED.token_expires_at, token_consumed_at = NULL",
        )
        .bind(request.device_id())
        .bind(i32::from(request.fingerprint_version()))
        .bind(request.fingerprint_digest().as_slice())
        .bind(request.ad_object_guid())
        .bind(request.ad_object_sid())
        .bind(request.ad_dns_name())
        .bind(request.ad_domain())
        .bind(request.preferred_drive_letter().to_string())
        .bind(token_digest.as_slice())
        .execute(&mut *transaction)
        .await;
        if result.is_err() {
            return Err(RepositoryError::Denied);
        }
        transaction
            .commit()
            .await
            .map_err(|_| RepositoryError::Unavailable)?;
        Ok(token)
    }

    /// Consumes a token exactly once after locking its authority record. Later
    /// replacement activation reuses this transaction boundary.
    pub async fn consume_token(
        &self,
        device_id: &str,
        fingerprint_digest: &[u8; 32],
        token: &str,
    ) -> Result<(), RepositoryError> {
        let token_digest: [u8; 32] = Sha256::digest(token.as_bytes()).into();
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|_| RepositoryError::Unavailable)?;
        let row = sqlx::query(
            "SELECT fingerprint_digest, token_digest FROM enrollment_authority WHERE device_id = $1 AND token_consumed_at IS NULL AND token_expires_at > CURRENT_TIMESTAMP FOR UPDATE",
        )
        .bind(device_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| RepositoryError::Unavailable)?
        .ok_or(RepositoryError::Denied)?;
        let stored_fingerprint: Vec<u8> = row
            .try_get("fingerprint_digest")
            .map_err(|_| RepositoryError::Unavailable)?;
        let stored_token: Vec<u8> = row
            .try_get("token_digest")
            .map_err(|_| RepositoryError::Unavailable)?;
        if stored_fingerprint.as_slice() != fingerprint_digest
            || stored_token.as_slice() != token_digest
        {
            return Err(RepositoryError::Denied);
        }
        let consumed = sqlx::query(
            "UPDATE enrollment_authority SET token_consumed_at = CURRENT_TIMESTAMP WHERE device_id = $1 AND token_consumed_at IS NULL",
        )
        .bind(device_id)
        .execute(&mut *transaction)
        .await
        .map_err(|_| RepositoryError::Unavailable)?;
        if consumed.rows_affected() != 1 {
            return Err(RepositoryError::Denied);
        }
        transaction
            .commit()
            .await
            .map_err(|_| RepositoryError::Unavailable)
    }

    /// Locks the current authority row, validates its one-time token and active
    /// credential state, invokes the certificate callback, then consumes,
    /// revokes, and activates in one committed PostgreSQL transaction. The
    /// identity fields remain server-held authority data; bootstrap callers do
    /// not submit an observation to compare.
    pub async fn consume_and_activate<T, F>(
        &self,
        device_id: &str,
        token: &str,
        prior_serial: Option<&[u8]>,
        issue: F,
    ) -> Result<T, RepositoryError>
    where
        F: FnOnce(Vec<u8>) -> Result<(T, [u8; 32]), RepositoryError>,
    {
        let token_digest: [u8; 32] = Sha256::digest(token.as_bytes()).into();
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|_| RepositoryError::Unavailable)?;
        let row = sqlx::query(
            "SELECT fingerprint_digest, token_digest, ad_object_guid, ad_object_sid, ad_dns_name, ad_domain, active_serial FROM enrollment_authority WHERE device_id = $1 AND token_consumed_at IS NULL AND token_expires_at > CURRENT_TIMESTAMP FOR UPDATE",
        )
        .bind(device_id)
        .fetch_optional(&mut *transaction)
        .await
            .map_err(|_| RepositoryError::Unavailable)?
            .ok_or(RepositoryError::Denied)?;
        let stored_token: Vec<u8> = row
            .try_get("token_digest")
            .map_err(|_| RepositoryError::Unavailable)?;
        let active_serial: Option<Vec<u8>> = row
            .try_get("active_serial")
            .map_err(|_| RepositoryError::Unavailable)?;
        if stored_token.as_slice() != token_digest || active_serial.as_deref() != prior_serial {
            return Err(RepositoryError::Denied);
        }

        let new_serial = Uuid::new_v4().as_bytes().to_vec();
        let (result, public_certificate_digest) = issue(new_serial.clone())?;
        if let Some(previous) = active_serial {
            sqlx::query(
                "UPDATE device_route_credentials SET credential_status = 'revoked', revoked_at = CURRENT_TIMESTAMP WHERE device_id = $1 AND credential_serial = $2 AND credential_status = 'active'",
            )
            .bind(device_id)
            .bind(&previous)
            .execute(&mut *transaction)
            .await
            .map_err(|_| RepositoryError::Unavailable)?;
            sqlx::query(
                "INSERT INTO revoked_device_credentials (serial, device_id) VALUES ($1, $2)",
            )
            .bind(previous)
            .bind(device_id)
            .execute(&mut *transaction)
            .await
            .map_err(|_| RepositoryError::Unavailable)?;
        }
        let consumed = sqlx::query(
            "UPDATE enrollment_authority SET token_consumed_at = CURRENT_TIMESTAMP, active_serial = $2 WHERE device_id = $1 AND token_consumed_at IS NULL",
        )
        .bind(device_id)
        .bind(&new_serial)
        .execute(&mut *transaction)
        .await
        .map_err(|_| RepositoryError::Unavailable)?;
        if consumed.rows_affected() != 1 {
            return Err(RepositoryError::Denied);
        }
        sqlx::query(
            "INSERT INTO device_route_credentials (device_id, credential_serial, credential_status, public_certificate_digest, expires_at) VALUES ($1, $2, 'active', $3, CURRENT_TIMESTAMP + INTERVAL '30 days')",
        )
        .bind(device_id)
        .bind(new_serial)
        .bind(public_certificate_digest.as_slice())
        .execute(&mut *transaction)
        .await
        .map_err(|_| RepositoryError::Unavailable)?;
        transaction
            .commit()
            .await
            .map_err(|_| RepositoryError::Unavailable)?;
        Ok(result)
    }
}

/// PostgreSQL-backed protected-route credential lookup. Route wiring consumes
/// this adapter in Plan 01-23; this source slice establishes its fail-closed
/// database boundary without treating local tests as LAB-DC01 evidence.
#[derive(Clone)]
pub struct PgRouteRepository {
    pool: PgPool,
}

impl PgRouteRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl RouteRepositoryPort for PgRouteRepository {
    async fn activate_device(&self, device_id: &str, serial: &[u8]) {
        let _ = sqlx::query(
            "INSERT INTO device_route_credentials (device_id, credential_serial, credential_status, public_certificate_digest, expires_at) VALUES ($1, $2, 'active', $3, CURRENT_TIMESTAMP + INTERVAL '30 days') ON CONFLICT (credential_serial) DO UPDATE SET credential_status = 'active', revoked_at = NULL",
        )
        .bind(device_id)
        .bind(serial)
        .bind([0_u8; 32].as_slice())
        .execute(&self.pool)
        .await;
    }

    async fn revoke_device(&self, device_id: &str, serial: &[u8]) {
        let _ = sqlx::query(
            "UPDATE device_route_credentials SET credential_status = 'revoked', revoked_at = CURRENT_TIMESTAMP WHERE device_id = $1 AND credential_serial = $2",
        )
        .bind(device_id)
        .bind(serial)
        .execute(&self.pool)
        .await;
    }

    async fn credential_status(&self, device_id: &str, serial: &[u8]) -> CredentialStatus {
        let status = sqlx::query(
            "SELECT credential_status FROM device_route_credentials WHERE device_id = $1 AND credential_serial = $2",
        )
        .bind(device_id)
        .bind(serial)
        .fetch_optional(&self.pool)
        .await
        .ok()
        .flatten()
        .and_then(|row| row.try_get::<String, _>("credential_status").ok());
        match status.as_deref() {
            Some("active") => CredentialStatus::Active,
            Some("revoked") => CredentialStatus::Revoked,
            _ => CredentialStatus::Expired,
        }
    }

    async fn authorize_device(
        &self,
        device: &AuthenticatedDevice,
    ) -> Result<(), RouteRepositoryError> {
        match self
            .credential_status(device.device_id(), device.credential_serial())
            .await
        {
            CredentialStatus::Active => Ok(()),
            CredentialStatus::Revoked | CredentialStatus::Expired => {
                Err(RouteRepositoryError::Denied)
            }
        }
    }

    async fn record_health(
        &self,
        device_id: &str,
        drive_state: &str,
    ) -> Result<(), RouteRepositoryError> {
        sqlx::query("INSERT INTO health_reports (device_id, status) VALUES ($1, $2)")
            .bind(device_id)
            .bind(drive_state)
            .execute(&self.pool)
            .await
            .map_err(|_| RouteRepositoryError::Unavailable)?;
        Ok(())
    }

    async fn persist_configuration(
        &self,
        device_id: &str,
        configuration: SignedConfigurationV1,
    ) -> Result<(), RouteRepositoryError> {
        if configuration.audience().to_wire() != device_id {
            return Err(RouteRepositoryError::Denied);
        }
        let version = configuration
            .envelope()
            .bundle_version()
            .to_wire()
            .parse::<i64>()
            .map_err(|_| RouteRepositoryError::Denied)?;
        let existing = sqlx::query(
            "SELECT bundle_version FROM signed_configurations WHERE device_id = $1 ORDER BY bundle_version DESC LIMIT 1",
        )
        .bind(device_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|_| RouteRepositoryError::Unavailable)?;
        if let Some(row) = existing {
            let current: i64 = row
                .try_get("bundle_version")
                .map_err(|_| RouteRepositoryError::Unavailable)?;
            if version <= current {
                return Err(RouteRepositoryError::Replay);
            }
        }
        sqlx::query(
            "INSERT INTO signed_configurations (device_id, bundle_version, schema_version, key_id, canonical_bundle, signature, content_digest, audience) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
        )
        .bind(device_id)
        .bind(version)
        .bind(i16::try_from(configuration.envelope().schema_version()).map_err(|_| RouteRepositoryError::Denied)?)
        .bind(configuration.key_id())
        .bind(configuration.envelope().canonical_bytes())
        .bind(configuration.signature())
        .bind(configuration.content_digest())
        .bind(configuration.audience().to_wire())
        .execute(&self.pool)
        .await
        .map_err(|_| RouteRepositoryError::Unavailable)?;
        Ok(())
    }

    async fn selected_configuration(
        &self,
        device_id: &str,
    ) -> Result<Option<SignedConfigurationV1>, RouteRepositoryError> {
        let row = sqlx::query(
            "SELECT bundle_version, schema_version, key_id, canonical_bundle, signature, content_digest, audience FROM signed_configurations WHERE device_id = $1 ORDER BY bundle_version DESC LIMIT 1",
        )
        .bind(device_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|_| RouteRepositoryError::Unavailable)?;
        let Some(row) = row else {
            return Ok(None);
        };
        let bundle_version: i64 = row
            .try_get("bundle_version")
            .map_err(|_| RouteRepositoryError::Unavailable)?;
        let canonical_bundle: Vec<u8> = row
            .try_get("canonical_bundle")
            .map_err(|_| RouteRepositoryError::Unavailable)?;
        let envelope =
            dlp_protocol::ConfigurationEnvelopeV1::from_canonical_bytes(&canonical_bundle)
                .map_err(|_| RouteRepositoryError::Unavailable)?;
        if envelope.bundle_version().to_wire() != bundle_version.to_string()
            || envelope.device_id().to_wire() != device_id
        {
            return Err(RouteRepositoryError::Unavailable);
        }
        let key_id: String = row
            .try_get("key_id")
            .map_err(|_| RouteRepositoryError::Unavailable)?;
        let signature: Vec<u8> = row
            .try_get("signature")
            .map_err(|_| RouteRepositoryError::Unavailable)?;
        let signed = SignedConfigurationV1::new(envelope, &key_id, signature)
            .map_err(|_| RouteRepositoryError::Unavailable)?;
        let stored_digest: Vec<u8> = row
            .try_get("content_digest")
            .map_err(|_| RouteRepositoryError::Unavailable)?;
        let stored_audience: String = row
            .try_get("audience")
            .map_err(|_| RouteRepositoryError::Unavailable)?;
        if stored_digest.as_slice() != signed.content_digest()
            || stored_audience != device_id
            || signed.audience().to_wire() != stored_audience
        {
            return Err(RouteRepositoryError::Unavailable);
        }
        Ok(Some(signed))
    }

    async fn health_report_count(&self, device_id: &str) -> usize {
        let count: i64 =
            sqlx::query("SELECT COUNT(*) AS count FROM health_reports WHERE device_id = $1")
                .bind(device_id)
                .fetch_one(&self.pool)
                .await
                .ok()
                .and_then(|row| row.try_get::<i64, _>("count").ok())
                .unwrap_or(0);
        count as usize
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnrollmentRecord {
    pub fingerprint_digest: [u8; 32],
    pub token_digest: [u8; 32],
    pub active_serial: Option<Vec<u8>>,
    pub revoked_serials: Vec<Vec<u8>>,
}

/// Deterministic authority fixture. It is deliberately named for test use and
/// must never be supplied to production server composition.
#[derive(Default)]
pub struct TestAuthorityRepository {
    records: Mutex<HashMap<String, EnrollmentRecord>>,
}

impl TestAuthorityRepository {
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

/// Narrow persistence port for post-enrollment device routes. The production
/// adapter replaces the mutex-backed implementation with the forward-only
/// PostgreSQL ledger; the authorization invariant remains the same.
#[async_trait]
pub trait RouteRepositoryPort: Send + Sync {
    async fn activate_device(&self, device_id: &str, serial: &[u8]);
    async fn revoke_device(&self, device_id: &str, serial: &[u8]);
    async fn credential_status(&self, device_id: &str, serial: &[u8]) -> CredentialStatus;
    async fn authorize_device(
        &self,
        device: &AuthenticatedDevice,
    ) -> Result<(), RouteRepositoryError>;
    async fn record_health(
        &self,
        device_id: &str,
        drive_state: &str,
    ) -> Result<(), RouteRepositoryError>;
    async fn persist_configuration(
        &self,
        device_id: &str,
        configuration: SignedConfigurationV1,
    ) -> Result<(), RouteRepositoryError>;
    async fn selected_configuration(
        &self,
        device_id: &str,
    ) -> Result<Option<SignedConfigurationV1>, RouteRepositoryError>;
    async fn health_report_count(&self, device_id: &str) -> usize;
}

#[derive(Default)]
pub struct RouteRepository {
    devices: Mutex<HashMap<String, DeviceRouteRecord>>,
}

#[derive(Default)]
struct DeviceRouteRecord {
    active_serial: Option<Vec<u8>>,
    revoked_serials: Vec<Vec<u8>>,
    health_reports: Vec<String>,
    configurations: BTreeMap<u64, SignedConfigurationV1>,
}

#[async_trait]
impl RouteRepositoryPort for RouteRepository {
    async fn activate_device(&self, device_id: &str, serial: &[u8]) {
        if let Ok(mut devices) = self.devices.lock() {
            let record = devices.entry(device_id.to_owned()).or_default();
            if let Some(previous) = record.active_serial.replace(serial.to_vec()) {
                record.revoked_serials.push(previous);
            }
        }
    }

    async fn revoke_device(&self, device_id: &str, serial: &[u8]) {
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

    async fn credential_status(&self, device_id: &str, serial: &[u8]) -> CredentialStatus {
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

    async fn authorize_device(
        &self,
        device: &AuthenticatedDevice,
    ) -> Result<(), RouteRepositoryError> {
        match self
            .credential_status(device.device_id(), device.credential_serial())
            .await
        {
            CredentialStatus::Active => Ok(()),
            CredentialStatus::Revoked | CredentialStatus::Expired => {
                Err(RouteRepositoryError::Denied)
            }
        }
    }

    async fn record_health(
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

    async fn persist_configuration(
        &self,
        device_id: &str,
        configuration: SignedConfigurationV1,
    ) -> Result<(), RouteRepositoryError> {
        if configuration.audience().to_wire() != device_id {
            return Err(RouteRepositoryError::Denied);
        }
        let version = configuration
            .envelope()
            .bundle_version()
            .to_wire()
            .parse::<u64>()
            .map_err(|_| RouteRepositoryError::Denied)?;
        let mut devices = self
            .devices
            .lock()
            .map_err(|_| RouteRepositoryError::Unavailable)?;
        let record = devices
            .get_mut(device_id)
            .ok_or(RouteRepositoryError::Denied)?;
        if record
            .configurations
            .last_key_value()
            .is_some_and(|(current, _)| version <= *current)
        {
            return Err(RouteRepositoryError::Replay);
        }
        record.configurations.insert(version, configuration);
        Ok(())
    }

    async fn selected_configuration(
        &self,
        device_id: &str,
    ) -> Result<Option<SignedConfigurationV1>, RouteRepositoryError> {
        let devices = self
            .devices
            .lock()
            .map_err(|_| RouteRepositoryError::Unavailable)?;
        let record = devices.get(device_id).ok_or(RouteRepositoryError::Denied)?;
        Ok(record
            .configurations
            .last_key_value()
            .map(|(_, configuration)| configuration.clone()))
    }

    async fn health_report_count(&self, device_id: &str) -> usize {
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
    Replay,
    Unavailable,
}

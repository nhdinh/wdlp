//! Transactional authority state. Production adapters use PostgreSQL row locks;
//! mutex-backed stores below exist only as deterministic test fixtures.

use crate::tls::{
    AdministratorPrincipalV1, AuthenticatedAdmin, AuthenticatedDevice, CredentialStatus,
    canonical_serial_bytes,
};
use async_trait::async_trait;
use dlp_protocol::{ProvisionDeviceRequestV1, SignedConfigurationV1};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Row};
use std::{
    collections::{BTreeMap, HashMap},
    sync::Mutex,
};
use uuid::Uuid;

const POLICY_AUTHORITY_ADVISORY_LOCK: i64 = 0x0202_0001;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PrincipalRole {
    Administrator,
    Auditor,
}

impl PrincipalRole {
    const fn as_database_value(self) -> &'static str {
        match self {
            Self::Administrator => "administrator",
            Self::Auditor => "auditor",
        }
    }

    fn from_database_value(value: &str) -> Result<Self, RouteRepositoryError> {
        match value {
            "administrator" => Ok(Self::Administrator),
            "auditor" => Ok(Self::Auditor),
            _ => Err(RouteRepositoryError::Unavailable),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BootstrapOutcome {
    Created,
    Idempotent,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublishedPolicyVersion {
    policy_id: String,
    version: u64,
    schema_version: u16,
    source_json: Vec<u8>,
    content_digest: [u8; 32],
}

impl PublishedPolicyVersion {
    pub fn policy_id(&self) -> &str {
        &self.policy_id
    }

    pub const fn version(&self) -> u64 {
        self.version
    }

    pub const fn schema_version(&self) -> u16 {
        self.schema_version
    }

    pub fn source_json(&self) -> &[u8] {
        &self.source_json
    }

    pub const fn content_digest(&self) -> &[u8; 32] {
        &self.content_digest
    }
}

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
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|_| RepositoryError::Unavailable)?;

        sqlx::query(
            "INSERT INTO device_allowlist (device_id, fingerprint_digest) VALUES ($1, $2) ON CONFLICT (device_id) DO UPDATE SET fingerprint_digest = EXCLUDED.fingerprint_digest",
        )
        .bind(request.device_id())
        .bind(request.fingerprint_digest().as_slice())
        .execute(&mut *transaction)
        .await
        .map_err(|_| RepositoryError::Unavailable)?;

        // Locking an existing device row makes duplicate provisioning serialize.
        // The unique constraints remain the final authority for a first insert race.
        let existing = sqlx::query(
            "SELECT active_serial FROM enrollment_authority WHERE device_id = $1 FOR UPDATE",
        )
        .bind(request.device_id())
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| RepositoryError::Unavailable)?;
        let active_serial = existing
            .as_ref()
            .and_then(|row| row.try_get::<Option<Vec<u8>>, _>("active_serial").ok())
            .flatten();
        if !request.recovery() && active_serial.is_some() {
            transaction
                .rollback()
                .await
                .map_err(|_| RepositoryError::Unavailable)?;
            return Err(RepositoryError::Denied);
        }
        if request.recovery()
            && let Some(active_serial) = active_serial
        {
            sqlx::query(
                "UPDATE device_route_credentials SET credential_status = 'revoked', revoked_at = CURRENT_TIMESTAMP WHERE device_id = $1 AND credential_serial = $2 AND credential_status = 'active'",
            )
            .bind(request.device_id())
            .bind(&active_serial)
            .execute(&mut *transaction)
            .await
            .map_err(|_| RepositoryError::Unavailable)?;
            sqlx::query(
                "INSERT INTO revoked_device_credentials (serial, device_id) VALUES ($1, $2) ON CONFLICT (serial) DO NOTHING",
            )
            .bind(&active_serial)
            .bind(request.device_id())
            .execute(&mut *transaction)
            .await
            .map_err(|_| RepositoryError::Unavailable)?;
            sqlx::query(
                "UPDATE enrollment_authority SET active_serial = NULL WHERE device_id = $1 AND active_serial = $2",
            )
            .bind(request.device_id())
            .bind(&active_serial)
            .execute(&mut *transaction)
            .await
            .map_err(|_| RepositoryError::Unavailable)?;
        }
        let token = Uuid::new_v4().simple().to_string();
        let token_digest: [u8; 32] = Sha256::digest(token.as_bytes()).into();
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

        let new_serial = canonical_serial_bytes(Uuid::new_v4().as_bytes());
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
    async fn bootstrap_initial_administrator(
        &self,
        configured: Option<&AdministratorPrincipalV1>,
    ) -> Result<BootstrapOutcome, RouteRepositoryError> {
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|_| RouteRepositoryError::Unavailable)?;
        sqlx::query("SELECT pg_advisory_xact_lock($1)")
            .bind(POLICY_AUTHORITY_ADVISORY_LOCK)
            .execute(&mut *transaction)
            .await
            .map_err(|_| RouteRepositoryError::Unavailable)?;

        let marker = sqlx::query(
            "SELECT p.issuer_sha256, p.leaf_sha256, p.principal_role FROM initial_admin_bootstrap b JOIN administrator_principals p ON p.id = b.principal_id WHERE b.singleton = TRUE",
        )
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| RouteRepositoryError::Unavailable)?;
        if let Some(row) = marker {
            let issuer: Vec<u8> = row
                .try_get("issuer_sha256")
                .map_err(|_| RouteRepositoryError::Unavailable)?;
            let leaf: Vec<u8> = row
                .try_get("leaf_sha256")
                .map_err(|_| RouteRepositoryError::Unavailable)?;
            let role: String = row
                .try_get("principal_role")
                .map_err(|_| RouteRepositoryError::Unavailable)?;
            let matches = configured.is_none_or(|principal| {
                issuer.as_slice() == principal.issuer_sha256()
                    && leaf.as_slice() == principal.leaf_sha256()
            });
            let active_administrators: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM administrator_principals WHERE active = TRUE AND principal_role = 'administrator'",
            )
            .fetch_one(&mut *transaction)
            .await
            .map_err(|_| RouteRepositoryError::Unavailable)?;
            if !matches
                || active_administrators == 0
                || role != PrincipalRole::Administrator.as_database_value()
            {
                sqlx::query("INSERT INTO policy_audit_events (event_code) VALUES ('initial_admin_bootstrap_conflict')")
                    .execute(&mut *transaction)
                    .await
                    .map_err(|_| RouteRepositoryError::Unavailable)?;
                transaction
                    .commit()
                    .await
                    .map_err(|_| RouteRepositoryError::Unavailable)?;
                return Err(RouteRepositoryError::Conflict);
            }
            sqlx::query("INSERT INTO policy_audit_events (event_code) VALUES ('initial_admin_bootstrap_idempotent')")
                .execute(&mut *transaction)
                .await
                .map_err(|_| RouteRepositoryError::Unavailable)?;
            transaction
                .commit()
                .await
                .map_err(|_| RouteRepositoryError::Unavailable)?;
            return Ok(BootstrapOutcome::Idempotent);
        }

        let active_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM administrator_principals WHERE active = TRUE AND principal_role = 'administrator'",
        )
        .fetch_one(&mut *transaction)
        .await
        .map_err(|_| RouteRepositoryError::Unavailable)?;
        if active_count != 0 {
            return Err(RouteRepositoryError::Conflict);
        }
        let principal = configured.ok_or(RouteRepositoryError::MissingInitialAdministrator)?;
        let principal_id: i64 = sqlx::query_scalar(
            "INSERT INTO administrator_principals (issuer_sha256, leaf_sha256, principal_role) VALUES ($1, $2, 'administrator') RETURNING id",
        )
        .bind(principal.issuer_sha256().as_slice())
        .bind(principal.leaf_sha256().as_slice())
        .fetch_one(&mut *transaction)
        .await
        .map_err(|_| RouteRepositoryError::Unavailable)?;
        sqlx::query(
            "INSERT INTO initial_admin_bootstrap (singleton, principal_id) VALUES (TRUE, $1)",
        )
        .bind(principal_id)
        .execute(&mut *transaction)
        .await
        .map_err(|_| RouteRepositoryError::Unavailable)?;
        sqlx::query("INSERT INTO policy_audit_events (event_code) VALUES ('initial_admin_bootstrap_created')")
            .execute(&mut *transaction)
            .await
            .map_err(|_| RouteRepositoryError::Unavailable)?;
        transaction
            .commit()
            .await
            .map_err(|_| RouteRepositoryError::Unavailable)?;
        Ok(BootstrapOutcome::Created)
    }

    async fn resolve_principal_role(
        &self,
        principal: &AdministratorPrincipalV1,
    ) -> Result<PrincipalRole, RouteRepositoryError> {
        let role = sqlx::query_scalar::<_, String>(
            "SELECT principal_role FROM administrator_principals WHERE issuer_sha256 = $1 AND leaf_sha256 = $2 AND active = TRUE",
        )
        .bind(principal.issuer_sha256().as_slice())
        .bind(principal.leaf_sha256().as_slice())
        .fetch_optional(&self.pool)
        .await
        .map_err(|_| RouteRepositoryError::Unavailable)?
        .ok_or(RouteRepositoryError::Denied)?;
        PrincipalRole::from_database_value(&role)
    }

    async fn grant_principal(
        &self,
        actor: &AuthenticatedAdmin,
        principal: &AdministratorPrincipalV1,
        role: PrincipalRole,
    ) -> Result<(), RouteRepositoryError> {
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|_| RouteRepositoryError::Unavailable)?;
        sqlx::query("SELECT pg_advisory_xact_lock($1)")
            .bind(POLICY_AUTHORITY_ADVISORY_LOCK)
            .execute(&mut *transaction)
            .await
            .map_err(|_| RouteRepositoryError::Unavailable)?;
        let actor_role = sqlx::query_scalar::<_, String>(
            "SELECT principal_role FROM administrator_principals WHERE issuer_sha256 = $1 AND leaf_sha256 = $2 AND active = TRUE FOR UPDATE",
        )
        .bind(actor.principal().issuer_sha256().as_slice())
        .bind(actor.principal().leaf_sha256().as_slice())
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| RouteRepositoryError::Unavailable)?;
        if actor_role.as_deref() != Some(PrincipalRole::Administrator.as_database_value()) {
            return Err(RouteRepositoryError::Denied);
        }
        sqlx::query(
            "INSERT INTO administrator_principals (issuer_sha256, leaf_sha256, principal_role) VALUES ($1, $2, $3) ON CONFLICT (issuer_sha256, leaf_sha256) DO UPDATE SET principal_role = EXCLUDED.principal_role, active = TRUE, revoked_at = NULL",
        )
        .bind(principal.issuer_sha256().as_slice())
        .bind(principal.leaf_sha256().as_slice())
        .bind(role.as_database_value())
        .execute(&mut *transaction)
        .await
        .map_err(|_| RouteRepositoryError::Unavailable)?;
        sqlx::query("INSERT INTO policy_audit_events (event_code) VALUES ('administrator_principal_granted')")
            .execute(&mut *transaction)
            .await
            .map_err(|_| RouteRepositoryError::Unavailable)?;
        transaction
            .commit()
            .await
            .map_err(|_| RouteRepositoryError::Unavailable)
    }

    async fn revoke_principal(
        &self,
        actor: &AuthenticatedAdmin,
        principal: &AdministratorPrincipalV1,
    ) -> Result<(), RouteRepositoryError> {
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|_| RouteRepositoryError::Unavailable)?;
        sqlx::query("SELECT pg_advisory_xact_lock($1)")
            .bind(POLICY_AUTHORITY_ADVISORY_LOCK)
            .execute(&mut *transaction)
            .await
            .map_err(|_| RouteRepositoryError::Unavailable)?;
        let actor_role = sqlx::query_scalar::<_, String>(
            "SELECT principal_role FROM administrator_principals WHERE issuer_sha256 = $1 AND leaf_sha256 = $2 AND active = TRUE FOR UPDATE",
        )
        .bind(actor.principal().issuer_sha256().as_slice())
        .bind(actor.principal().leaf_sha256().as_slice())
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| RouteRepositoryError::Unavailable)?;
        if actor_role.as_deref() != Some(PrincipalRole::Administrator.as_database_value()) {
            return Err(RouteRepositoryError::Denied);
        }
        let target_role = sqlx::query_scalar::<_, String>(
            "SELECT principal_role FROM administrator_principals WHERE issuer_sha256 = $1 AND leaf_sha256 = $2 AND active = TRUE FOR UPDATE",
        )
        .bind(principal.issuer_sha256().as_slice())
        .bind(principal.leaf_sha256().as_slice())
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| RouteRepositoryError::Unavailable)?
        .ok_or(RouteRepositoryError::Denied)?;
        if target_role == PrincipalRole::Administrator.as_database_value() {
            let active_administrators: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM administrator_principals WHERE active = TRUE AND principal_role = 'administrator'",
            )
            .fetch_one(&mut *transaction)
            .await
            .map_err(|_| RouteRepositoryError::Unavailable)?;
            if active_administrators <= 1 {
                return Err(RouteRepositoryError::LastAdministrator);
            }
        }
        let result = sqlx::query(
            "UPDATE administrator_principals SET active = FALSE, revoked_at = CURRENT_TIMESTAMP WHERE issuer_sha256 = $1 AND leaf_sha256 = $2 AND active = TRUE",
        )
        .bind(principal.issuer_sha256().as_slice())
        .bind(principal.leaf_sha256().as_slice())
        .execute(&mut *transaction)
        .await
        .map_err(|_| RouteRepositoryError::Unavailable)?;
        if result.rows_affected() != 1 {
            return Err(RouteRepositoryError::Denied);
        }
        sqlx::query("INSERT INTO policy_audit_events (event_code) VALUES ('administrator_principal_revoked')")
            .execute(&mut *transaction)
            .await
            .map_err(|_| RouteRepositoryError::Unavailable)?;
        transaction
            .commit()
            .await
            .map_err(|_| RouteRepositoryError::Unavailable)
    }

    async fn save_policy_draft(
        &self,
        policy_id: &str,
        source_json: &[u8],
    ) -> Result<(), RouteRepositoryError> {
        if policy_id.is_empty()
            || policy_id.len() > 128
            || !(2..=1_048_576).contains(&source_json.len())
        {
            return Err(RouteRepositoryError::Denied);
        }
        sqlx::query(
            "INSERT INTO policy_drafts (policy_id, source_json) VALUES ($1, $2) ON CONFLICT (policy_id) DO UPDATE SET source_json = EXCLUDED.source_json, validated_digest = NULL, updated_at = CURRENT_TIMESTAMP",
        )
        .bind(policy_id)
        .bind(source_json)
        .execute(&self.pool)
        .await
        .map_err(|_| RouteRepositoryError::Unavailable)?;
        Ok(())
    }

    async fn policy_draft(&self, policy_id: &str) -> Result<Option<Vec<u8>>, RouteRepositoryError> {
        sqlx::query_scalar("SELECT source_json FROM policy_drafts WHERE policy_id = $1")
            .bind(policy_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(|_| RouteRepositoryError::Unavailable)
    }

    async fn record_policy_validation(
        &self,
        policy_id: &str,
        digest: &[u8; 32],
    ) -> Result<(), RouteRepositoryError> {
        let result = sqlx::query(
            "UPDATE policy_drafts SET validated_digest = $2, updated_at = CURRENT_TIMESTAMP WHERE policy_id = $1",
        )
        .bind(policy_id)
        .bind(digest.as_slice())
        .execute(&self.pool)
        .await
        .map_err(|_| RouteRepositoryError::Unavailable)?;
        if result.rows_affected() != 1 {
            return Err(RouteRepositoryError::NotFound);
        }
        Ok(())
    }

    async fn publish_policy(
        &self,
        policy_id: &str,
        version: u64,
        digest: &[u8; 32],
    ) -> Result<PublishedPolicyVersion, RouteRepositoryError> {
        let version = i64::try_from(version).map_err(|_| RouteRepositoryError::Denied)?;
        if version <= 0 {
            return Err(RouteRepositoryError::Denied);
        }
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|_| RouteRepositoryError::Unavailable)?;
        let source_json = sqlx::query_scalar::<_, Vec<u8>>(
            "SELECT source_json FROM policy_drafts WHERE policy_id = $1 FOR UPDATE",
        )
        .bind(policy_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| RouteRepositoryError::Unavailable)?
        .ok_or(RouteRepositoryError::NotFound)?;
        let inserted = sqlx::query(
            "INSERT INTO published_policy_versions (policy_id, policy_version, schema_version, source_json, content_digest) VALUES ($1, $2, 2, $3, $4)",
        )
        .bind(policy_id)
        .bind(version)
        .bind(&source_json)
        .bind(digest.as_slice())
        .execute(&mut *transaction)
        .await;
        if let Err(error) = inserted {
            if error
                .as_database_error()
                .and_then(|database| database.code())
                .as_deref()
                == Some("23505")
            {
                return Err(RouteRepositoryError::Conflict);
            }
            return Err(RouteRepositoryError::Unavailable);
        }
        sqlx::query(
            "INSERT INTO policy_audit_events (event_code) VALUES ('policy_version_published')",
        )
        .execute(&mut *transaction)
        .await
        .map_err(|_| RouteRepositoryError::Unavailable)?;
        transaction
            .commit()
            .await
            .map_err(|_| RouteRepositoryError::Unavailable)?;
        Ok(PublishedPolicyVersion {
            policy_id: policy_id.to_owned(),
            version: u64::try_from(version).map_err(|_| RouteRepositoryError::Unavailable)?,
            schema_version: 2,
            source_json,
            content_digest: *digest,
        })
    }

    async fn published_policy(
        &self,
        policy_id: &str,
        version: u64,
    ) -> Result<Option<PublishedPolicyVersion>, RouteRepositoryError> {
        let version = i64::try_from(version).map_err(|_| RouteRepositoryError::Denied)?;
        let row = sqlx::query(
            "SELECT schema_version, source_json, content_digest FROM published_policy_versions WHERE policy_id = $1 AND policy_version = $2",
        )
        .bind(policy_id)
        .bind(version)
        .fetch_optional(&self.pool)
        .await
        .map_err(|_| RouteRepositoryError::Unavailable)?;
        let Some(row) = row else {
            return Ok(None);
        };
        let schema_version: i16 = row
            .try_get("schema_version")
            .map_err(|_| RouteRepositoryError::Unavailable)?;
        let source_json: Vec<u8> = row
            .try_get("source_json")
            .map_err(|_| RouteRepositoryError::Unavailable)?;
        let content_digest: Vec<u8> = row
            .try_get("content_digest")
            .map_err(|_| RouteRepositoryError::Unavailable)?;
        Ok(Some(PublishedPolicyVersion {
            policy_id: policy_id.to_owned(),
            version: u64::try_from(version).map_err(|_| RouteRepositoryError::Unavailable)?,
            schema_version: u16::try_from(schema_version)
                .map_err(|_| RouteRepositoryError::Unavailable)?,
            source_json,
            content_digest: content_digest
                .try_into()
                .map_err(|_| RouteRepositoryError::Unavailable)?,
        }))
    }

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
    async fn bootstrap_initial_administrator(
        &self,
        configured: Option<&AdministratorPrincipalV1>,
    ) -> Result<BootstrapOutcome, RouteRepositoryError>;
    async fn resolve_principal_role(
        &self,
        principal: &AdministratorPrincipalV1,
    ) -> Result<PrincipalRole, RouteRepositoryError>;
    async fn grant_principal(
        &self,
        actor: &AuthenticatedAdmin,
        principal: &AdministratorPrincipalV1,
        role: PrincipalRole,
    ) -> Result<(), RouteRepositoryError>;
    async fn revoke_principal(
        &self,
        actor: &AuthenticatedAdmin,
        principal: &AdministratorPrincipalV1,
    ) -> Result<(), RouteRepositoryError>;
    async fn save_policy_draft(
        &self,
        policy_id: &str,
        source_json: &[u8],
    ) -> Result<(), RouteRepositoryError>;
    async fn policy_draft(&self, policy_id: &str) -> Result<Option<Vec<u8>>, RouteRepositoryError>;
    async fn record_policy_validation(
        &self,
        policy_id: &str,
        digest: &[u8; 32],
    ) -> Result<(), RouteRepositoryError>;
    async fn publish_policy(
        &self,
        policy_id: &str,
        version: u64,
        digest: &[u8; 32],
    ) -> Result<PublishedPolicyVersion, RouteRepositoryError>;
    async fn published_policy(
        &self,
        policy_id: &str,
        version: u64,
    ) -> Result<Option<PublishedPolicyVersion>, RouteRepositoryError>;
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

pub struct RouteRepository {
    devices: Mutex<HashMap<String, DeviceRouteRecord>>,
    principals: Mutex<BTreeMap<AdministratorPrincipalV1, PrincipalRole>>,
    bootstrap: Mutex<Option<AdministratorPrincipalV1>>,
    policy_drafts: Mutex<BTreeMap<String, PolicyDraftRecord>>,
    published_policies: Mutex<BTreeMap<(String, u64), PublishedPolicyVersion>>,
}

struct PolicyDraftRecord {
    source_json: Vec<u8>,
    validated_digest: Option<[u8; 32]>,
}

impl Default for RouteRepository {
    fn default() -> Self {
        let principal = AdministratorPrincipalV1::from_verified_der(
            b"dlp-test-administrator-issuer",
            b"admin-test",
        );
        Self {
            devices: Mutex::new(HashMap::new()),
            principals: Mutex::new(BTreeMap::from([(
                principal.clone(),
                PrincipalRole::Administrator,
            )])),
            bootstrap: Mutex::new(Some(principal)),
            policy_drafts: Mutex::new(BTreeMap::new()),
            published_policies: Mutex::new(BTreeMap::new()),
        }
    }
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
    async fn bootstrap_initial_administrator(
        &self,
        configured: Option<&AdministratorPrincipalV1>,
    ) -> Result<BootstrapOutcome, RouteRepositoryError> {
        let mut marker = self
            .bootstrap
            .lock()
            .map_err(|_| RouteRepositoryError::Unavailable)?;
        if let Some(existing) = marker.as_ref() {
            if configured.is_none_or(|principal| principal == existing) {
                return Ok(BootstrapOutcome::Idempotent);
            }
            return Err(RouteRepositoryError::Conflict);
        }
        let principal = configured.ok_or(RouteRepositoryError::MissingInitialAdministrator)?;
        self.principals
            .lock()
            .map_err(|_| RouteRepositoryError::Unavailable)?
            .insert(principal.clone(), PrincipalRole::Administrator);
        *marker = Some(principal.clone());
        Ok(BootstrapOutcome::Created)
    }

    async fn resolve_principal_role(
        &self,
        principal: &AdministratorPrincipalV1,
    ) -> Result<PrincipalRole, RouteRepositoryError> {
        self.principals
            .lock()
            .map_err(|_| RouteRepositoryError::Unavailable)?
            .get(principal)
            .copied()
            .ok_or(RouteRepositoryError::Denied)
    }

    async fn grant_principal(
        &self,
        actor: &AuthenticatedAdmin,
        principal: &AdministratorPrincipalV1,
        role: PrincipalRole,
    ) -> Result<(), RouteRepositoryError> {
        if self.resolve_principal_role(actor.principal()).await? != PrincipalRole::Administrator {
            return Err(RouteRepositoryError::Denied);
        }
        self.principals
            .lock()
            .map_err(|_| RouteRepositoryError::Unavailable)?
            .insert(principal.clone(), role);
        Ok(())
    }

    async fn revoke_principal(
        &self,
        actor: &AuthenticatedAdmin,
        principal: &AdministratorPrincipalV1,
    ) -> Result<(), RouteRepositoryError> {
        if self.resolve_principal_role(actor.principal()).await? != PrincipalRole::Administrator {
            return Err(RouteRepositoryError::Denied);
        }
        let mut principals = self
            .principals
            .lock()
            .map_err(|_| RouteRepositoryError::Unavailable)?;
        let role = principals
            .get(principal)
            .copied()
            .ok_or(RouteRepositoryError::Denied)?;
        if role == PrincipalRole::Administrator
            && principals
                .values()
                .filter(|candidate| **candidate == PrincipalRole::Administrator)
                .count()
                <= 1
        {
            return Err(RouteRepositoryError::LastAdministrator);
        }
        principals.remove(principal);
        Ok(())
    }

    async fn save_policy_draft(
        &self,
        policy_id: &str,
        source_json: &[u8],
    ) -> Result<(), RouteRepositoryError> {
        if policy_id.is_empty()
            || policy_id.len() > 128
            || !(2..=1_048_576).contains(&source_json.len())
        {
            return Err(RouteRepositoryError::Denied);
        }
        self.policy_drafts
            .lock()
            .map_err(|_| RouteRepositoryError::Unavailable)?
            .insert(
                policy_id.to_owned(),
                PolicyDraftRecord {
                    source_json: source_json.to_vec(),
                    validated_digest: None,
                },
            );
        Ok(())
    }

    async fn policy_draft(&self, policy_id: &str) -> Result<Option<Vec<u8>>, RouteRepositoryError> {
        Ok(self
            .policy_drafts
            .lock()
            .map_err(|_| RouteRepositoryError::Unavailable)?
            .get(policy_id)
            .map(|draft| draft.source_json.clone()))
    }

    async fn record_policy_validation(
        &self,
        policy_id: &str,
        digest: &[u8; 32],
    ) -> Result<(), RouteRepositoryError> {
        let mut drafts = self
            .policy_drafts
            .lock()
            .map_err(|_| RouteRepositoryError::Unavailable)?;
        let draft = drafts
            .get_mut(policy_id)
            .ok_or(RouteRepositoryError::NotFound)?;
        draft.validated_digest = Some(*digest);
        Ok(())
    }

    async fn publish_policy(
        &self,
        policy_id: &str,
        version: u64,
        digest: &[u8; 32],
    ) -> Result<PublishedPolicyVersion, RouteRepositoryError> {
        if version == 0 {
            return Err(RouteRepositoryError::Denied);
        }
        let source_json = self
            .policy_draft(policy_id)
            .await?
            .ok_or(RouteRepositoryError::NotFound)?;
        let published = PublishedPolicyVersion {
            policy_id: policy_id.to_owned(),
            version,
            schema_version: 2,
            source_json,
            content_digest: *digest,
        };
        let mut policies = self
            .published_policies
            .lock()
            .map_err(|_| RouteRepositoryError::Unavailable)?;
        if policies.contains_key(&(policy_id.to_owned(), version)) {
            return Err(RouteRepositoryError::Conflict);
        }
        policies.insert((policy_id.to_owned(), version), published.clone());
        Ok(published)
    }

    async fn published_policy(
        &self,
        policy_id: &str,
        version: u64,
    ) -> Result<Option<PublishedPolicyVersion>, RouteRepositoryError> {
        Ok(self
            .published_policies
            .lock()
            .map_err(|_| RouteRepositoryError::Unavailable)?
            .get(&(policy_id.to_owned(), version))
            .cloned())
    }

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
    Conflict,
    LastAdministrator,
    MissingInitialAdministrator,
    NotFound,
    Unavailable,
}

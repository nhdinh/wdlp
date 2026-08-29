//! Authenticated `/api/v1` route state and handlers.
//!
//! The TLS listener supplies a verified peer identity as connection metadata.
//! Route middleware converts that metadata into an authenticated extension only
//! after the active credential repository lookup succeeds.

use crate::{
    enrollment::{EnrollmentServicePort, EnrollmentSubmission, ProvisioningServicePort},
    repository::{
        PrincipalRole, PublishedPolicyVersion, RouteRepository, RouteRepositoryError,
        RouteRepositoryPort,
    },
    tls::{
        AdministratorPrincipalV1, AuthenticatedAdmin, AuthenticatedDevice, PeerIdentity,
        TlsConnectionInfo, TlsError,
    },
};
use axum::{
    Json, Router,
    extract::{ConnectInfo, DefaultBodyLimit, Extension, Path, State},
    http::{Request, StatusCode, header::CONTENT_TYPE},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post, put},
};
use dlp_agent_core::serialize_signed_configuration;
use dlp_crypto::ConfigurationSigner;
use dlp_domain::{BundleVersion, DeviceId};
use dlp_policy::{DetectorCeilings, PolicyDocumentV2};
use dlp_protocol::{
    ConfigurationEnvelopeV1, ProvisionDeviceRequestV1, ProvisionDeviceResponseV1,
    SignedConfigurationV1,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::Arc;

#[derive(Clone)]
pub struct RouteState {
    repository: Arc<dyn RouteRepositoryPort>,
    enrollment_service: Arc<dyn EnrollmentServicePort>,
    provisioning_service: Arc<dyn ProvisioningServicePort>,
    signer: Arc<ConfigurationSigner>,
}

impl RouteState {
    /// Test-only material is isolated to the deterministic route tracer. A
    /// production composition must inject a secret-backed signer.
    pub fn for_test() -> Self {
        Self::new(
            Arc::new(RouteRepository::default()),
            Arc::new(AlwaysOkEnrollmentService),
            Arc::new(AlwaysOkProvisioningService),
            Arc::new(ConfigurationSigner::from_seed(
                "phase1-test-key",
                [0xA5; 32],
            )),
        )
    }

    #[cfg(any(test, debug_assertions))]
    pub fn with_repository_for_test(repository: Arc<dyn RouteRepositoryPort>) -> Self {
        Self::new(
            repository,
            Arc::new(AlwaysOkEnrollmentService),
            Arc::new(AlwaysOkProvisioningService),
            Arc::new(ConfigurationSigner::from_seed(
                "phase1-test-key",
                [0xA5; 32],
            )),
        )
    }

    pub fn new(
        repository: Arc<dyn RouteRepositoryPort>,
        enrollment_service: Arc<dyn EnrollmentServicePort>,
        provisioning_service: Arc<dyn ProvisioningServicePort>,
        signer: Arc<ConfigurationSigner>,
    ) -> Self {
        Self {
            repository,
            enrollment_service,
            provisioning_service,
            signer,
        }
    }

    pub async fn activate_device_for_test(&self, device_id: &str, serial: &[u8]) {
        self.repository.activate_device(device_id, serial).await;
    }

    pub async fn revoke_device_for_test(&self, device_id: &str, serial: &[u8]) {
        self.repository.revoke_device(device_id, serial).await;
    }

    pub async fn health_report_count_for_test(&self, device_id: &str) -> usize {
        self.repository.health_report_count(device_id).await
    }

    pub async fn signed_configuration_for(
        &self,
        device: &AuthenticatedDevice,
    ) -> Result<SignedConfigurationV1, RouteError> {
        self.repository.authorize_device(device).await?;
        if let Some(configuration) = self
            .repository
            .selected_configuration(device.device_id())
            .await?
        {
            return Ok(configuration);
        }
        let configuration = self.make_configuration(device.device_id(), 1)?;
        self.repository
            .persist_configuration(device.device_id(), configuration.clone())
            .await?;
        Ok(configuration)
    }

    pub async fn stage_configuration_for_test(
        &self,
        device_id: &str,
        version: u64,
    ) -> Result<(), RouteError> {
        let configuration = self.make_configuration(device_id, version)?;
        self.repository
            .persist_configuration(device_id, configuration)
            .await
            .map_err(Into::into)
    }

    fn make_configuration(
        &self,
        device: &str,
        version: u64,
    ) -> Result<SignedConfigurationV1, RouteError> {
        let device_id = DeviceId::parse(device).map_err(|_| RouteError::Denied)?;
        let bundle_version =
            BundleVersion::parse(version.to_string()).map_err(|_| RouteError::Denied)?;
        let envelope = ConfigurationEnvelopeV1::new(
            1,
            device_id,
            bundle_version,
            1_754_568_000,
            "{\"preferred_drive_letter\":\"P\"}",
        )
        .map_err(|_| RouteError::Denied)?;
        let signature = self.signer.sign(&envelope.canonical_bytes());
        SignedConfigurationV1::new(envelope, self.signer.key_id(), signature)
            .map_err(|_| RouteError::Denied)
    }

    pub async fn record_health_for(
        &self,
        device: &AuthenticatedDevice,
        drive_state: &str,
    ) -> Result<(), RouteError> {
        if drive_state.is_empty() || drive_state.len() > 64 {
            return Err(RouteError::Denied);
        }
        self.repository.authorize_device(device).await?;
        self.repository
            .record_health(device.device_id(), drive_state)
            .await?;
        Ok(())
    }

    async fn principal_role(
        &self,
        administrator: &AuthenticatedAdmin,
    ) -> Result<PrincipalRole, RouteError> {
        self.repository
            .resolve_principal_role(administrator.principal())
            .await
            .map_err(Into::into)
    }

    async fn require_mutating_administrator(
        &self,
        administrator: &AuthenticatedAdmin,
    ) -> Result<(), RouteError> {
        match self.principal_role(administrator).await? {
            PrincipalRole::Administrator => Ok(()),
            PrincipalRole::Auditor => Err(RouteError::Forbidden),
        }
    }

    pub async fn grant_principal(
        &self,
        administrator: &AuthenticatedAdmin,
        principal: &AdministratorPrincipalV1,
        role: PrincipalRole,
    ) -> Result<(), RouteError> {
        self.require_mutating_administrator(administrator).await?;
        self.repository
            .grant_principal(administrator, principal, role)
            .await
            .map_err(Into::into)
    }

    pub async fn revoke_principal(
        &self,
        administrator: &AuthenticatedAdmin,
        principal: &AdministratorPrincipalV1,
    ) -> Result<(), RouteError> {
        self.require_mutating_administrator(administrator).await?;
        self.repository
            .revoke_principal(administrator, principal)
            .await
            .map_err(Into::into)
    }

    pub async fn save_policy_draft(
        &self,
        administrator: &AuthenticatedAdmin,
        policy_id: &str,
        source_json: &[u8],
    ) -> Result<(), RouteError> {
        self.require_mutating_administrator(administrator).await?;
        self.repository
            .save_policy_draft(policy_id, source_json)
            .await
            .map_err(Into::into)
    }

    pub async fn validate_policy_draft(
        &self,
        administrator: &AuthenticatedAdmin,
        policy_id: &str,
    ) -> Result<[u8; 32], RouteError> {
        self.require_mutating_administrator(administrator).await?;
        let source = self
            .repository
            .policy_draft(policy_id)
            .await?
            .ok_or(RouteError::NotFound)?;
        compile_policy(&source)?;
        let digest: [u8; 32] = Sha256::digest(&source).into();
        self.repository
            .record_policy_validation(policy_id, &digest)
            .await?;
        Ok(digest)
    }

    pub async fn publish_policy_draft(
        &self,
        administrator: &AuthenticatedAdmin,
        policy_id: &str,
        version: u64,
    ) -> Result<PublishedPolicyVersion, RouteError> {
        self.require_mutating_administrator(administrator).await?;
        let source = self
            .repository
            .policy_draft(policy_id)
            .await?
            .ok_or(RouteError::NotFound)?;
        compile_policy(&source)?;
        let digest: [u8; 32] = Sha256::digest(&source).into();
        self.repository
            .record_policy_validation(policy_id, &digest)
            .await?;
        self.repository
            .publish_policy(policy_id, version, &digest)
            .await
            .map_err(Into::into)
    }

    pub async fn inspect_policy_version(
        &self,
        administrator: &AuthenticatedAdmin,
        policy_id: &str,
        version: u64,
    ) -> Result<PublishedPolicyVersion, RouteError> {
        self.principal_role(administrator).await?;
        self.repository
            .published_policy(policy_id, version)
            .await?
            .ok_or(RouteError::NotFound)
    }
}

fn compile_policy(source: &[u8]) -> Result<(), RouteError> {
    PolicyDocumentV2::from_json_bytes(source)
        .and_then(|document| document.compile(DetectorCeilings::default()))
        .map(|_| ())
        .map_err(|_| RouteError::InvalidPolicy)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RouteError {
    Denied,
    Forbidden,
    Conflict,
    InvalidPolicy,
    NotFound,
    Unavailable,
}

impl From<RouteRepositoryError> for RouteError {
    fn from(value: RouteRepositoryError) -> Self {
        match value {
            RouteRepositoryError::Denied => Self::Denied,
            RouteRepositoryError::Replay => Self::Denied,
            RouteRepositoryError::Conflict | RouteRepositoryError::LastAdministrator => {
                Self::Conflict
            }
            RouteRepositoryError::MissingInitialAdministrator => Self::Unavailable,
            RouteRepositoryError::NotFound => Self::NotFound,
            RouteRepositoryError::Unavailable => Self::Unavailable,
        }
    }
}

impl IntoResponse for RouteError {
    fn into_response(self) -> Response {
        let (status, code) = match self {
            Self::Denied => (StatusCode::UNAUTHORIZED, "request_denied"),
            Self::Forbidden => (StatusCode::FORBIDDEN, "mutation_forbidden"),
            Self::Conflict => (StatusCode::CONFLICT, "authority_conflict"),
            Self::InvalidPolicy => (StatusCode::BAD_REQUEST, "policy_invalid"),
            Self::NotFound => (StatusCode::NOT_FOUND, "authority_not_found"),
            Self::Unavailable => (StatusCode::SERVICE_UNAVAILABLE, "authority_unavailable"),
        };
        (status, Json(serde_json::json!({ "error": code }))).into_response()
    }
}

/// Versioned API branches. Identity extraction is run before every protected
/// handler and does not accept any HTTP-provided certificate header.
pub fn api_v1_router(state: RouteState) -> Router {
    let administrator_mutation_routes = Router::new()
        .route(
            "/api/v1/admin/provisioning",
            post(admin_provisioning_contract),
        )
        .route("/api/v1/admin/principals/grant", post(grant_principal))
        .route("/api/v1/admin/principals/revoke", post(revoke_principal))
        .route(
            "/api/v1/admin/policies/{policy_id}/draft",
            put(save_policy_draft),
        )
        .route(
            "/api/v1/admin/policies/{policy_id}/validate",
            post(validate_policy_draft),
        )
        .route(
            "/api/v1/admin/policies/{policy_id}/publish",
            post(publish_policy_draft),
        )
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            require_mutating_administrator,
        ));
    let administrator_inspection_routes = Router::new()
        .route(
            "/api/v1/admin/policies/{policy_id}/versions/{version}",
            get(inspect_policy_version),
        )
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            require_registered_principal,
        ));
    let device_routes = Router::new()
        .route("/api/v1/device/configuration", get(fetch_configuration))
        .route("/api/v1/device/health", post(post_health))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            require_active_device,
        ));
    let bootstrap_routes = Router::new()
        .route("/api/v1/enrollment", post(bootstrap_enrollment_contract))
        .layer(DefaultBodyLimit::max(65_536));
    Router::new()
        .merge(bootstrap_routes)
        .merge(administrator_mutation_routes)
        .merge(administrator_inspection_routes)
        .merge(device_routes)
        .with_state(state)
}

fn tls_administrator(connection: &TlsConnectionInfo) -> Result<AuthenticatedAdmin, StatusCode> {
    connection
        .identity()
        .cloned()
        .ok_or(StatusCode::UNAUTHORIZED)
        .and_then(|peer| AuthenticatedAdmin::from_peer(peer).map_err(|_| StatusCode::UNAUTHORIZED))
}

async fn require_registered_principal(
    State(state): State<RouteState>,
    ConnectInfo(connection): ConnectInfo<TlsConnectionInfo>,
    mut request: Request<axum::body::Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    let administrator = tls_administrator(&connection)?;
    state
        .principal_role(&administrator)
        .await
        .map_err(|_| StatusCode::UNAUTHORIZED)?;
    request.extensions_mut().insert(administrator);
    Ok(next.run(request).await)
}

async fn require_mutating_administrator(
    State(state): State<RouteState>,
    ConnectInfo(connection): ConnectInfo<TlsConnectionInfo>,
    mut request: Request<axum::body::Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    let administrator = tls_administrator(&connection)?;
    match state.principal_role(&administrator).await {
        Ok(PrincipalRole::Administrator) => {
            request.extensions_mut().insert(administrator);
            Ok(next.run(request).await)
        }
        Ok(PrincipalRole::Auditor) => Err(StatusCode::FORBIDDEN),
        Err(_) => Err(StatusCode::UNAUTHORIZED),
    }
}

async fn require_active_device(
    State(state): State<RouteState>,
    ConnectInfo(connection): ConnectInfo<TlsConnectionInfo>,
    mut request: Request<axum::body::Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    let peer = connection.identity().cloned().ok_or_else(|| {
        eprintln!("device_route_rejected: peer_identity_missing");
        StatusCode::UNAUTHORIZED
    })?;
    let credential_status = state
        .repository
        .credential_status(peer.subject(), peer.serial())
        .await;
    let device = AuthenticatedDevice::from_peer(peer.clone(), credential_status).map_err(|_| {
        eprintln!("device_route_rejected: credential_not_active");
        StatusCode::UNAUTHORIZED
    })?;
    state
        .repository
        .authorize_device(&device)
        .await
        .map_err(|_| {
            eprintln!("device_route_rejected: repository_authorization_failed");
            StatusCode::UNAUTHORIZED
        })?;
    request.extensions_mut().insert(device);
    Ok(next.run(request).await)
}

/// The one bootstrap endpoint intentionally relies on ordinary server TLS only.
/// It has a fixed body ceiling and never treats an HTTP header as a peer identity.
async fn bootstrap_enrollment_contract(
    State(state): State<RouteState>,
    Json(request): Json<BootstrapEnrollmentRequest>,
) -> Result<Json<BootstrapEnrollmentResponse>, StatusCode> {
    if request.version != 1
        || request.device_id.is_empty()
        || request.device_id.len() > 128
        || request.token.is_empty()
        || request.token.len() > 512
        || request.csr_pem.is_empty()
        || request.csr_pem.len() > 65_536
    {
        return Err(StatusCode::BAD_REQUEST);
    }
    let prior_serial = decode_prior_serial(request.prior_serial.as_deref())?;
    let submission = EnrollmentSubmission::new(
        request.device_id,
        request.token,
        request.csr_pem,
        prior_serial,
    )
    .map_err(|_| StatusCode::BAD_REQUEST)?;
    let issued = state
        .enrollment_service
        .enroll(submission)
        .await
        .map_err(|_| StatusCode::UNAUTHORIZED)?;
    Ok(Json(BootstrapEnrollmentResponse {
        version: 1,
        credential_chain: issued.certificate_chain_pem,
    }))
}

async fn admin_provisioning_contract(
    State(state): State<RouteState>,
    Extension(_administrator): Extension<AuthenticatedAdmin>,
    Json(request): Json<AdministratorProvisioningRequest>,
) -> Result<Json<ProvisioningResponse>, StatusCode> {
    if request.version != 1
        || request.device_id.is_empty()
        || request.fingerprint_digest.len() != 32
        || request.ad_object_guid.len() != 16
        || !(8..=68).contains(&request.ad_object_sid.len())
        || !request.preferred_drive_letter.is_ascii_uppercase()
    {
        return Err(StatusCode::BAD_REQUEST);
    }
    let mut guid = [0_u8; 16];
    guid.copy_from_slice(&request.ad_object_guid);
    let mut provision_request = ProvisionDeviceRequestV1::new(
        1,
        request.device_id,
        1,
        request
            .fingerprint_digest
            .try_into()
            .map_err(|_| StatusCode::BAD_REQUEST)?,
        guid.to_vec(),
        request.ad_object_sid,
        "device.lab.local",
        "LAB",
        request.preferred_drive_letter,
    )
    .map_err(|_| StatusCode::BAD_REQUEST)?;
    if request.recovery {
        provision_request = provision_request.authorize_recovery();
    }
    let response = state
        .provisioning_service
        .provision(provision_request)
        .await
        .map_err(|_| StatusCode::UNAUTHORIZED)?;
    Ok(Json(ProvisioningResponse {
        version: response.version(),
        device_id: response.device_id().to_owned(),
        enrollment_token: response.enrollment_token().to_owned(),
    }))
}

async fn grant_principal(
    State(state): State<RouteState>,
    Extension(administrator): Extension<AuthenticatedAdmin>,
    Json(request): Json<PrincipalMutationRequest>,
) -> Result<StatusCode, RouteError> {
    if request.version != 1 {
        return Err(RouteError::InvalidPolicy);
    }
    let principal =
        AdministratorPrincipalV1::parse(&request.principal).map_err(|_| RouteError::Denied)?;
    state
        .grant_principal(&administrator, &principal, request.role)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn revoke_principal(
    State(state): State<RouteState>,
    Extension(administrator): Extension<AuthenticatedAdmin>,
    Json(request): Json<PrincipalRevocationRequest>,
) -> Result<StatusCode, RouteError> {
    if request.version != 1 {
        return Err(RouteError::InvalidPolicy);
    }
    let principal =
        AdministratorPrincipalV1::parse(&request.principal).map_err(|_| RouteError::Denied)?;
    state.revoke_principal(&administrator, &principal).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn save_policy_draft(
    State(state): State<RouteState>,
    Extension(administrator): Extension<AuthenticatedAdmin>,
    Path(policy_id): Path<String>,
    Json(request): Json<PolicyDraftRequest>,
) -> Result<StatusCode, RouteError> {
    if request.version != 2 {
        return Err(RouteError::InvalidPolicy);
    }
    let source_json =
        serde_json::to_vec(&request.document).map_err(|_| RouteError::InvalidPolicy)?;
    state
        .save_policy_draft(&administrator, &policy_id, &source_json)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn validate_policy_draft(
    State(state): State<RouteState>,
    Extension(administrator): Extension<AuthenticatedAdmin>,
    Path(policy_id): Path<String>,
) -> Result<Json<PolicyValidationResponse>, RouteError> {
    let digest = state
        .validate_policy_draft(&administrator, &policy_id)
        .await?;
    Ok(Json(PolicyValidationResponse {
        valid: true,
        content_digest: lower_hex(&digest),
    }))
}

async fn publish_policy_draft(
    State(state): State<RouteState>,
    Extension(administrator): Extension<AuthenticatedAdmin>,
    Path(policy_id): Path<String>,
    Json(request): Json<PolicyPublishRequest>,
) -> Result<Json<PolicyVersionResponse>, RouteError> {
    let published = state
        .publish_policy_draft(&administrator, &policy_id, request.version)
        .await?;
    policy_version_response(published).map(Json)
}

async fn inspect_policy_version(
    State(state): State<RouteState>,
    Extension(administrator): Extension<AuthenticatedAdmin>,
    Path((policy_id, version)): Path<(String, u64)>,
) -> Result<Json<PolicyVersionResponse>, RouteError> {
    let published = state
        .inspect_policy_version(&administrator, &policy_id, version)
        .await?;
    policy_version_response(published).map(Json)
}

fn policy_version_response(
    published: PublishedPolicyVersion,
) -> Result<PolicyVersionResponse, RouteError> {
    let document =
        serde_json::from_slice(published.source_json()).map_err(|_| RouteError::Unavailable)?;
    Ok(PolicyVersionResponse {
        policy_id: published.policy_id().to_owned(),
        version: published.version(),
        schema_version: published.schema_version(),
        content_digest: lower_hex(published.content_digest()),
        document,
    })
}

fn lower_hex(value: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(value.len() * 2);
    for byte in value {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

async fn fetch_configuration(
    State(state): State<RouteState>,
    Extension(device): Extension<AuthenticatedDevice>,
) -> Result<Response, StatusCode> {
    let configuration = state
        .signed_configuration_for(&device)
        .await
        .map_err(|error| {
            eprintln!("device_configuration_failed: {error:?}");
            route_error_status(error)
        })?;
    Ok((
        [(CONTENT_TYPE, "application/vnd.dlp.signed-configuration.v1")],
        serialize_signed_configuration(&configuration),
    )
        .into_response())
}

async fn post_health(
    State(state): State<RouteState>,
    Extension(device): Extension<AuthenticatedDevice>,
    Json(report): Json<HealthRequest>,
) -> Result<StatusCode, StatusCode> {
    if report.version != 1 {
        return Err(StatusCode::BAD_REQUEST);
    }
    state
        .record_health_for(&device, &report.drive_state)
        .await
        .map_err(route_error_status)?;
    Ok(StatusCode::NO_CONTENT)
}

fn route_error_status(error: RouteError) -> StatusCode {
    match error {
        RouteError::Denied => StatusCode::UNAUTHORIZED,
        RouteError::Forbidden => StatusCode::FORBIDDEN,
        RouteError::Conflict => StatusCode::CONFLICT,
        RouteError::InvalidPolicy => StatusCode::BAD_REQUEST,
        RouteError::NotFound => StatusCode::NOT_FOUND,
        RouteError::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
    }
}

#[derive(Serialize)]
struct ProvisioningResponse {
    version: u16,
    device_id: String,
    enrollment_token: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PrincipalMutationRequest {
    version: u16,
    principal: String,
    role: PrincipalRole,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PrincipalRevocationRequest {
    version: u16,
    principal: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyDraftRequest {
    version: u16,
    document: serde_json::Value,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyPublishRequest {
    version: u64,
}

#[derive(Serialize)]
struct PolicyValidationResponse {
    valid: bool,
    content_digest: String,
}

#[derive(Serialize)]
struct PolicyVersionResponse {
    policy_id: String,
    version: u64,
    schema_version: u16,
    content_digest: String,
    document: serde_json::Value,
}

#[derive(Deserialize)]
struct HealthRequest {
    version: u16,
    drive_state: String,
}

#[derive(Deserialize)]
struct BootstrapEnrollmentRequest {
    version: u16,
    device_id: String,
    token: String,
    csr_pem: String,
    #[serde(default)]
    prior_serial: Option<String>,
}

/// Public enrollment material only. The endpoint never returns a private key.
#[derive(Serialize)]
struct BootstrapEnrollmentResponse {
    version: u16,
    credential_chain: String,
}

/// Decodes the replacement credential serial without accepting an ambiguous or
/// silently truncated representation from the untrusted bootstrap request.
fn decode_prior_serial(value: Option<&str>) -> Result<Option<Vec<u8>>, StatusCode> {
    let Some(value) = value else {
        return Ok(None);
    };
    if value.len() < 2 || value.len() > 40 || value.len() % 2 != 0 {
        return Err(StatusCode::BAD_REQUEST);
    }
    let mut serial = Vec::with_capacity(value.len() / 2);
    for pair in value.as_bytes().chunks_exact(2) {
        let pair = std::str::from_utf8(pair).map_err(|_| StatusCode::BAD_REQUEST)?;
        serial.push(u8::from_str_radix(pair, 16).map_err(|_| StatusCode::BAD_REQUEST)?);
    }
    Ok(Some(serial))
}

#[derive(Deserialize)]
struct AdministratorProvisioningRequest {
    version: u16,
    device_id: String,
    fingerprint_digest: Vec<u8>,
    ad_object_guid: Vec<u8>,
    ad_object_sid: Vec<u8>,
    preferred_drive_letter: char,
    #[serde(default)]
    recovery: bool,
}

/// Test-only enrollment stub that always returns a deterministic credential so
/// route wiring can be exercised without a real database or PKI.
#[derive(Clone)]
struct AlwaysOkEnrollmentService;

#[async_trait::async_trait]
impl EnrollmentServicePort for AlwaysOkEnrollmentService {
    async fn enroll(
        &self,
        _submission: EnrollmentSubmission,
    ) -> Result<crate::pki::IssuedDeviceCredential, crate::enrollment::EnrollmentError> {
        Ok(crate::pki::IssuedDeviceCredential {
            certificate_chain_pem: "TEST CERTIFICATE".into(),
            serial: vec![1, 2, 3],
            expires_after_days: 30,
        })
    }
}

/// Test-only provisioning stub that always returns a deterministic token so
/// route wiring can be exercised without a real database.
#[derive(Clone)]
struct AlwaysOkProvisioningService;

#[async_trait::async_trait]
impl ProvisioningServicePort for AlwaysOkProvisioningService {
    async fn provision(
        &self,
        _request: ProvisionDeviceRequestV1,
    ) -> Result<ProvisionDeviceResponseV1, crate::enrollment::EnrollmentError> {
        ProvisionDeviceResponseV1::new(1, "device-01", "test-token")
            .map_err(|_| crate::enrollment::EnrollmentError::IntegrityFailure)
    }
}

#[allow(dead_code)]
fn _identity_is_tls_derived(identity: &PeerIdentity) -> Result<(), TlsError> {
    if identity.serial().is_empty() {
        Err(TlsError::Unauthorized)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod route_tests {
    use super::*;
    use crate::tls::{PeerIdentity, TlsConnectionInfo};
    use axum::body::Body;
    use tower::ServiceExt;

    fn json_request(method: &str, uri: &str, body: serde_json::Value) -> Request<Body> {
        Request::builder()
            .method(method)
            .uri(uri)
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap()
    }

    #[tokio::test]
    async fn bootstrap_enrollment_accepts_bounded_valid_input() {
        let state = RouteState::for_test();
        let app = api_v1_router(state);
        let mut request = json_request(
            "POST",
            "/api/v1/enrollment",
            serde_json::json!({
                "version": 1,
                "device_id": "device-01",
                "token": "one-time-token",
                "csr_pem": "-----BEGIN CERTIFICATE REQUEST-----\nMIIBkTCB+w==\n-----END CERTIFICATE REQUEST-----",
            }),
        );
        request
            .extensions_mut()
            .insert(ConnectInfo(TlsConnectionInfo::bootstrap_without_peer()));
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn bootstrap_enrollment_rejects_invalid_version() {
        let state = RouteState::for_test();
        let app = api_v1_router(state);
        let mut request = json_request(
            "POST",
            "/api/v1/enrollment",
            serde_json::json!({
                "version": 2,
                "device_id": "device-01",
                "token": "one-time-token",
                "csr_pem": "csr",
            }),
        );
        request
            .extensions_mut()
            .insert(ConnectInfo(TlsConnectionInfo::bootstrap_without_peer()));
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn admin_provisioning_accepts_bounded_valid_input() {
        let state = RouteState::for_test();
        let app = api_v1_router(state);
        let mut request = json_request(
            "POST",
            "/api/v1/admin/provisioning",
            serde_json::json!({
                "version": 1,
                "device_id": "device-01",
                "fingerprint_digest": vec![0; 32],
                "ad_object_guid": vec![0; 16],
                "ad_object_sid": vec![0; 16],
                "preferred_drive_letter": "P",
            }),
        );
        request
            .extensions_mut()
            .insert(ConnectInfo(TlsConnectionInfo::from_verified_peer(
                PeerIdentity::admin_for_test("admin-test"),
            )));
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn admin_provisioning_rejects_malformed_digest() {
        let state = RouteState::for_test();
        let app = api_v1_router(state);
        let mut request = json_request(
            "POST",
            "/api/v1/admin/provisioning",
            serde_json::json!({
                "version": 1,
                "device_id": "device-01",
                "fingerprint_digest": vec![0; 16],
                "ad_object_guid": vec![0; 16],
                "ad_object_sid": vec![0; 16],
                "preferred_drive_letter": "P",
            }),
        );
        request
            .extensions_mut()
            .insert(ConnectInfo(TlsConnectionInfo::from_verified_peer(
                PeerIdentity::admin_for_test("admin-test"),
            )));
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn device_configuration_requires_active_serial() {
        let state = RouteState::for_test();
        state
            .activate_device_for_test("device-test", &[1, 2, 3])
            .await;
        let app = api_v1_router(state);
        let mut request = Request::builder()
            .method("GET")
            .uri("/api/v1/device/configuration")
            .body(Body::empty())
            .unwrap();
        request
            .extensions_mut()
            .insert(ConnectInfo(TlsConnectionInfo::from_verified_peer(
                PeerIdentity::device_for_test("device-test", vec![1, 2, 3]),
            )));
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }
}

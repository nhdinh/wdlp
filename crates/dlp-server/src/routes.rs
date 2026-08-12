//! Authenticated `/api/v1` route state and handlers.
//!
//! The TLS listener supplies a verified peer identity as connection metadata.
//! Route middleware converts that metadata into an authenticated extension only
//! after the active credential repository lookup succeeds.

use crate::{
    enrollment::{EnrollmentServicePort, EnrollmentSubmission, ProvisioningServicePort},
    repository::{RouteRepository, RouteRepositoryError, RouteRepositoryPort},
    tls::{AuthenticatedAdmin, AuthenticatedDevice, PeerIdentity, TlsConnectionInfo, TlsError},
};
use axum::{
    Json, Router,
    extract::{ConnectInfo, DefaultBodyLimit, Extension, State},
    http::{Request, StatusCode},
    middleware::{self, Next},
    response::Response,
    routing::{get, post},
};
use dlp_crypto::ConfigurationSigner;
use dlp_domain::{BundleVersion, DeviceId};
use dlp_protocol::{ConfigurationEnvelopeV1, ProvisionDeviceRequestV1, SignedConfigurationV1};
use serde::{Deserialize, Serialize};
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
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RouteError {
    Denied,
    Unavailable,
}

impl From<RouteRepositoryError> for RouteError {
    fn from(value: RouteRepositoryError) -> Self {
        match value {
            RouteRepositoryError::Denied => Self::Denied,
            RouteRepositoryError::Replay => Self::Denied,
            RouteRepositoryError::Unavailable => Self::Unavailable,
        }
    }
}

/// Versioned API branches. Identity extraction is run before every protected
/// handler and does not accept any HTTP-provided certificate header.
pub fn api_v1_router(state: RouteState) -> Router {
    let admin_routes = Router::new()
        .route("/api/v1/admin/provisioning", post(admin_provisioning_contract))
        .route_layer(middleware::from_fn(require_administrator));
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
        .merge(admin_routes)
        .merge(device_routes)
        .with_state(state)
}

async fn require_administrator(
    ConnectInfo(connection): ConnectInfo<TlsConnectionInfo>,
    mut request: Request<axum::body::Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    let administrator = connection
        .identity()
        .cloned()
        .ok_or(StatusCode::UNAUTHORIZED)
        .and_then(|peer| AuthenticatedAdmin::from_peer(peer).map_err(|_| StatusCode::UNAUTHORIZED))
        .map_err(|_| StatusCode::UNAUTHORIZED)?;
    request.extensions_mut().insert(administrator);
    Ok(next.run(request).await)
}

async fn require_active_device(
    State(state): State<RouteState>,
    ConnectInfo(connection): ConnectInfo<TlsConnectionInfo>,
    mut request: Request<axum::body::Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    let peer = connection.identity().cloned().ok_or(StatusCode::UNAUTHORIZED)?;
    let credential_status = state
        .repository
        .credential_status(peer.subject(), peer.serial())
        .await;
    let device = AuthenticatedDevice::from_peer(peer.clone(), credential_status)
        .map_err(|_| StatusCode::UNAUTHORIZED)?;
    state
        .repository
        .authorize_device(&device)
        .await
        .map_err(|_| StatusCode::UNAUTHORIZED)?;
    request.extensions_mut().insert(device);
    Ok(next.run(request).await)
}

/// The one bootstrap endpoint intentionally relies on ordinary server TLS only.
/// It has a fixed body ceiling and never treats an HTTP header as a peer identity.
async fn bootstrap_enrollment_contract(
    State(state): State<RouteState>,
    Json(request): Json<BootstrapEnrollmentRequest>,
) -> Result<StatusCode, StatusCode> {
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
    let observation = ProvisionDeviceRequestV1::new(
        1,
        request.device_id,
        1,
        [0; 32],
        vec![0; 16],
        vec![0; 16],
        "device.lab.local",
        "LAB",
        'P',
    )
    .map_err(|_| StatusCode::BAD_REQUEST)?;
    let submission = EnrollmentSubmission::new(
        observation,
        request.token,
        request.csr_pem,
        None,
    )
    .map_err(|_| StatusCode::BAD_REQUEST)?;
    state
        .enrollment_service
        .enroll(submission)
        .await
        .map_err(|_| StatusCode::UNAUTHORIZED)?;
    Ok(StatusCode::OK)
}

async fn admin_provisioning_contract(
    State(state): State<RouteState>,
    Extension(_administrator): Extension<AuthenticatedAdmin>,
    Json(request): Json<AdministratorProvisioningRequest>,
) -> Result<StatusCode, StatusCode> {
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
    let provision_request = ProvisionDeviceRequestV1::new(
        1,
        request.device_id,
        1,
        request.fingerprint_digest.try_into().map_err(|_| StatusCode::BAD_REQUEST)?,
        guid.to_vec(),
        request.ad_object_sid,
        "device.lab.local",
        "LAB",
        request.preferred_drive_letter,
    )
    .map_err(|_| StatusCode::BAD_REQUEST)?;
    state
        .provisioning_service
        .provision(provision_request)
        .await
        .map_err(|_| StatusCode::UNAUTHORIZED)?;
    Ok(StatusCode::OK)
}

async fn fetch_configuration(
    State(state): State<RouteState>,
    Extension(device): Extension<AuthenticatedDevice>,
) -> Result<Json<ConfigurationResponse>, StatusCode> {
    let configuration = state
        .signed_configuration_for(&device)
        .await
        .map_err(route_error_status)?;
    Ok(Json(ConfigurationResponse::from(configuration)))
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
        RouteError::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
    }
}

#[derive(Serialize)]
struct ConfigurationResponse {
    version: u16,
    schema_version: u16,
    bundle_version: String,
    key_id: String,
    canonical_bytes: Vec<u8>,
    signature: Vec<u8>,
    content_digest: Vec<u8>,
    audience: String,
}

impl From<SignedConfigurationV1> for ConfigurationResponse {
    fn from(value: SignedConfigurationV1) -> Self {
        Self {
            version: value.version(),
            schema_version: value.envelope().schema_version(),
            bundle_version: value.envelope().bundle_version().to_wire().to_owned(),
            key_id: value.key_id().to_owned(),
            canonical_bytes: value.envelope().canonical_bytes(),
            signature: value.signature().to_vec(),
            content_digest: value.content_digest().to_vec(),
            audience: value.audience().to_wire().to_owned(),
        }
    }
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
}

#[derive(Deserialize)]
struct AdministratorProvisioningRequest {
    version: u16,
    device_id: String,
    fingerprint_digest: Vec<u8>,
    ad_object_guid: Vec<u8>,
    ad_object_sid: Vec<u8>,
    preferred_drive_letter: char,
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
    ) -> Result<String, crate::enrollment::EnrollmentError> {
        Ok("test-token".into())
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
        request.extensions_mut().insert(ConnectInfo(
            TlsConnectionInfo::from_verified_peer(PeerIdentity::admin_for_test("admin-test")),
        ));
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
        request.extensions_mut().insert(ConnectInfo(
            TlsConnectionInfo::from_verified_peer(PeerIdentity::admin_for_test("admin-test")),
        ));
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
        request.extensions_mut().insert(ConnectInfo(
            TlsConnectionInfo::from_verified_peer(PeerIdentity::device_for_test(
                "device-test",
                vec![1, 2, 3],
            )),
        ));
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }
}

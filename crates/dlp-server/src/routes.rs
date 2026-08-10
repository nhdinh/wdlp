//! Authenticated `/api/v1` route state and handlers.
//!
//! The TLS listener supplies a verified peer identity as connection metadata.
//! Route middleware converts that metadata into an authenticated extension only
//! after the active credential repository lookup succeeds.

use crate::{
    repository::{RouteRepository, RouteRepositoryError},
    tls::{AuthenticatedAdmin, AuthenticatedDevice, PeerIdentity, TlsConnectionInfo, TlsError},
};
use axum::{
    Json, Router,
    extract::{ConnectInfo, Extension, State},
    http::{Request, StatusCode},
    middleware::{self, Next},
    response::Response,
    routing::{get, post},
};
use dlp_crypto::ConfigurationSigner;
use dlp_domain::{BundleVersion, DeviceId};
use dlp_protocol::{ConfigurationEnvelopeV1, SignedConfigurationV1};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Clone)]
pub struct RouteState {
    repository: Arc<RouteRepository>,
    signer: Arc<ConfigurationSigner>,
}

impl RouteState {
    /// Test-only material is isolated to the deterministic route tracer. A
    /// production composition must inject a secret-backed signer.
    pub fn for_test() -> Self {
        Self::new(
            Arc::new(RouteRepository::default()),
            Arc::new(ConfigurationSigner::from_seed(
                "phase1-test-key",
                [0xA5; 32],
            )),
        )
    }

    pub fn new(repository: Arc<RouteRepository>, signer: Arc<ConfigurationSigner>) -> Self {
        Self { repository, signer }
    }

    pub fn activate_device_for_test(&self, device_id: &str, serial: &[u8]) {
        self.repository.activate_device(device_id, serial);
    }

    pub fn revoke_device_for_test(&self, device_id: &str, serial: &[u8]) {
        self.repository.revoke_device(device_id, serial);
    }

    pub fn health_report_count_for_test(&self, device_id: &str) -> usize {
        self.repository.health_report_count(device_id)
    }

    pub fn signed_configuration_for(
        &self,
        device: &AuthenticatedDevice,
    ) -> Result<SignedConfigurationV1, RouteError> {
        self.repository.authorize_device(device)?;
        let device_id = DeviceId::parse(device.device_id()).map_err(|_| RouteError::Denied)?;
        let bundle_version = BundleVersion::parse("1").expect("static bundle version is valid");
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

    pub fn record_health_for(
        &self,
        device: &AuthenticatedDevice,
        drive_state: &str,
    ) -> Result<(), RouteError> {
        if drive_state.is_empty() || drive_state.len() > 64 {
            return Err(RouteError::Denied);
        }
        self.repository.authorize_device(device)?;
        self.repository
            .record_health(device.device_id(), drive_state)?;
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
            RouteRepositoryError::Unavailable => Self::Unavailable,
        }
    }
}

/// Versioned API branches. Identity extraction is run before every protected
/// handler and does not accept any HTTP-provided certificate header.
pub fn api_v1_router(state: RouteState) -> Router {
    let admin_routes = Router::new()
        .route(
            "/api/v1/admin/provisioning",
            post(crate::admin_provisioning_contract),
        )
        .route_layer(middleware::from_fn(require_administrator));
    let device_routes = Router::new()
        .route("/api/v1/device/configuration", get(fetch_configuration))
        .route("/api/v1/device/health", post(post_health))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            require_active_device,
        ));
    Router::new()
        .merge(admin_routes)
        .merge(device_routes)
        .with_state(state)
}

async fn require_administrator(
    ConnectInfo(connection): ConnectInfo<TlsConnectionInfo>,
    mut request: Request<axum::body::Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    let administrator = AuthenticatedAdmin::from_peer(connection.identity().clone())
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
    let device = AuthenticatedDevice::from_peer(
        connection.identity().clone(),
        state.repository.credential_status(
            connection.identity().subject(),
            connection.identity().serial(),
        ),
    )
    .map_err(|_| StatusCode::UNAUTHORIZED)?;
    state
        .repository
        .authorize_device(&device)
        .map_err(|_| StatusCode::UNAUTHORIZED)?;
    request.extensions_mut().insert(device);
    Ok(next.run(request).await)
}

async fn fetch_configuration(
    State(state): State<RouteState>,
    Extension(device): Extension<AuthenticatedDevice>,
) -> Result<Json<ConfigurationResponse>, StatusCode> {
    let configuration = state
        .signed_configuration_for(&device)
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
        }
    }
}

#[derive(Deserialize)]
struct HealthRequest {
    version: u16,
    drive_state: String,
}

#[allow(dead_code)]
fn _identity_is_tls_derived(identity: &PeerIdentity) -> Result<(), TlsError> {
    if identity.serial().is_empty() {
        Err(TlsError::Unauthorized)
    } else {
        Ok(())
    }
}

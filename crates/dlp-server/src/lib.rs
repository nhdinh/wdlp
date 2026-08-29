#![forbid(unsafe_code)]

//! Fail-closed server composition. Route behavior and real provider adapters are
//! deliberately added by later plans; this seam owns process-only liveness and
//! migration-before-bind ordering now.

use crate::repository::RouteRepositoryPort;
use axum::{Json, Router, extract::Extension, http::StatusCode, routing::get};
use serde::Serialize;
use sqlx::{PgPool, migrate::Migrator, postgres::PgPoolOptions};
use std::{fmt, fs, net::SocketAddr, sync::Arc};

pub mod ad;
pub mod enrollment;
pub mod health;
pub mod pki;
pub mod repository;
pub mod routes;
pub mod tls;

pub use crate::ad::{
    DirectoryError, DirectoryVerifier, LdapDirectoryAdapter, LdapDirectoryVerifier,
    VerifiedComputerIdentity,
};

static MIGRATOR: Migrator = sqlx::migrate!("../../migrations");

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ServerError {
    MissingDatabaseUrl,
    MissingProvider { provider: &'static str },
    DatabaseUnavailable,
    MigrationFailed,
    ListenerFailed,
    ServeFailed,
    InvalidEnvironmentFile,
    InvalidInitialAdministrator,
    MissingInitialAdministrator,
    InitialAdministratorConflict,
}

impl fmt::Display for ServerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let code = match self {
            Self::MissingDatabaseUrl => "server_config_invalid",
            Self::MissingProvider { .. } => "server_provider_missing",
            Self::DatabaseUnavailable => "server_database_unavailable",
            Self::MigrationFailed => "server_migration_failed",
            Self::ListenerFailed => "server_listener_failed",
            Self::ServeFailed => "server_serve_failed",
            Self::InvalidEnvironmentFile => "server_environment_invalid",
            Self::InvalidInitialAdministrator => "initial_administrator_invalid",
            Self::MissingInitialAdministrator => "initial_administrator_required",
            Self::InitialAdministratorConflict => "initial_administrator_conflict",
        };
        write!(formatter, "{code}")
    }
}

/// Validates configuration shape without loading a secret, opening a socket, or
/// mutating a database. It is safe for deployment preflight and CI.
pub fn check_environment_file(path: impl AsRef<std::path::Path>) -> Result<(), ServerError> {
    let source = fs::read_to_string(path).map_err(|_| ServerError::InvalidEnvironmentFile)?;
    let required = [
        "DATABASE_URL",
        "DLP_AD_PRIMARY_LDAPS_URL",
        "DLP_AD_SECONDARY_LDAPS_URL",
        "DLP_AD_BASE_DN",
        "DLP_AD_BIND_DN",
        "DLP_AD_BIND_PASSWORD",
        "DLP_AD_DOMAIN",
        "DLP_AD_CA_CERT_PEM",
        "DLP_SERVER_CERT_PEM",
        "DLP_SERVER_KEY_PEM",
        "DLP_ADMIN_CA_CERT_PEM",
        "DLP_PHASE1_ROOT_CA_CERT_PEM",
        "DLP_DEVICE_ISSUING_CA_CERT_PEM",
        "DLP_DEVICE_ISSUING_CA_KEY_PEM",
        "DLP_CONFIGURATION_SIGNING_KEY_SEED_HEX",
    ];
    if required.iter().any(|key| {
        !source
            .lines()
            .any(|line| line.starts_with(&format!("{key}=")))
    }) || source.contains("DLP_PHASE1_ROOT_CA_KEY")
    {
        return Err(ServerError::InvalidEnvironmentFile);
    }
    Ok(())
}

impl std::error::Error for ServerError {}

#[derive(Clone, Debug)]
pub struct ServerConfig {
    listen_address: SocketAddr,
    database_url: String,
}

impl ServerConfig {
    pub fn from_environment() -> Result<Self, ServerError> {
        let database_url =
            std::env::var("DATABASE_URL").map_err(|_| ServerError::MissingDatabaseUrl)?;
        let listen_address = std::env::var("DLP_LISTEN_ADDRESS")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or_else(|| {
                "0.0.0.0:8080"
                    .parse()
                    .expect("static all-interfaces address is valid")
            });
        Ok(Self {
            listen_address,
            database_url,
        })
    }

    pub fn listen_address(&self) -> SocketAddr {
        self.listen_address
    }

    #[cfg(any(test, debug_assertions))]
    pub fn for_test() -> Self {
        Self {
            listen_address: "127.0.0.1:0"
                .parse()
                .expect("static loopback address is valid"),
            database_url: "postgresql://[REDACTED]".to_owned(),
        }
    }
}

impl ProductionProviders {
    /// Loads every production dependency from mounted runtime configuration.
    /// There is deliberately no `Default` startup path: any missing secret,
    /// directory endpoint, PostgreSQL URL, issuer, signer, clock, or TLS path
    /// fails before migrations or listener binding.
    pub fn from_environment(config: &ServerConfig) -> Result<Self, ServerError> {
        let directory: Arc<dyn DirectoryVerifier> =
            Arc::new(ad::LdapDirectoryAdapter::from_environment().map_err(|_| {
                ServerError::MissingProvider {
                    provider: "directory_verifier",
                }
            })?);
        let pool = PgPoolOptions::new()
            .connect_lazy(&config.database_url)
            .map_err(|_| ServerError::DatabaseUnavailable)?;
        let issuer = pki::RcgenDeviceCertificateIssuer::new(
            required_environment("DLP_PHASE1_ROOT_CA_CERT_PEM")?,
            required_environment("DLP_DEVICE_ISSUING_CA_CERT_PEM")?,
            required_environment("DLP_DEVICE_ISSUING_CA_KEY_PEM")?,
            None,
        )
        .map_err(|_| ServerError::MissingProvider {
            provider: "certificate_issuer",
        })?;
        let seed = decode_signing_seed(&required_environment(
            "DLP_CONFIGURATION_SIGNING_KEY_SEED_HEX",
        )?)?;
        let configuration_key_id = std::env::var("DLP_CONFIGURATION_KEY_ID")
            .unwrap_or_else(|_| "phase1-config-signing-key-v1".to_owned());
        // Validate TLS paths before a migration can mutate the authority ledger.
        tls::TlsPaths::from_environment().map_err(|_| ServerError::MissingProvider {
            provider: "tls_paths",
        })?;
        let authority_repository = repository::PgAuthorityRepository::new(pool.clone());
        let route_repository = Arc::new(repository::PgRouteRepository::new(pool));
        let enrollment_service = Arc::new(enrollment::EnrollmentService::new(
            authority_repository.clone(),
            issuer.clone(),
            Arc::clone(&directory),
        ));
        let provisioning_service = Arc::new(enrollment::AdminProvisioningService::new(
            authority_repository,
        ));
        Ok(Self {
            directory_verifier: Some(directory),
            certificate_issuer: Some(Arc::new(RuntimeIssuer(issuer))),
            configuration_signer: Some(Arc::new(RuntimeSigner(Arc::new(
                dlp_crypto::ConfigurationSigner::from_seed(configuration_key_id, seed),
            )))),
            repository: Some(Arc::new(RuntimeRepository { route_repository })),
            enrollment_service: Some(enrollment_service),
            provisioning_service: Some(provisioning_service),
            clock: Some(Arc::new(RuntimeClock)),
        })
    }
}

fn required_environment(name: &'static str) -> Result<String, ServerError> {
    std::env::var(name)
        .ok()
        .filter(|value| !value.is_empty())
        .ok_or(ServerError::MissingProvider { provider: name })
}

fn decode_signing_seed(value: &str) -> Result<[u8; 32], ServerError> {
    if value.len() != 64 {
        return Err(ServerError::MissingProvider {
            provider: "configuration_signer",
        });
    }
    let mut seed = [0_u8; 32];
    for (index, output) in seed.iter_mut().enumerate() {
        *output = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).map_err(|_| {
            ServerError::MissingProvider {
                provider: "configuration_signer",
            }
        })?;
    }
    Ok(seed)
}

#[allow(dead_code)]
struct RuntimeIssuer(pki::RcgenDeviceCertificateIssuer);
impl DeviceCertificateIssuer for RuntimeIssuer {}
struct RuntimeSigner(Arc<dlp_crypto::ConfigurationSigner>);
impl ConfigurationSigner for RuntimeSigner {
    fn route_signer(&self) -> Arc<dlp_crypto::ConfigurationSigner> {
        Arc::clone(&self.0)
    }
}
struct RuntimeRepository {
    route_repository: Arc<repository::PgRouteRepository>,
}
#[async_trait::async_trait]
impl ServerRepository for RuntimeRepository {
    fn route_repository(&self) -> Arc<dyn repository::RouteRepositoryPort> {
        self.route_repository.clone()
    }

    async fn bootstrap_initial_administrator(
        &self,
        configured: Option<&tls::AdministratorPrincipalV1>,
    ) -> Result<repository::BootstrapOutcome, repository::RouteRepositoryError> {
        self.route_repository
            .bootstrap_initial_administrator(configured)
            .await
    }
}
struct RuntimeClock;
impl Clock for RuntimeClock {}

pub trait DeviceCertificateIssuer: Send + Sync {}
pub trait ConfigurationSigner: Send + Sync {
    fn route_signer(&self) -> Arc<dlp_crypto::ConfigurationSigner>;
}
#[async_trait::async_trait]
pub trait ServerRepository: Send + Sync {
    fn route_repository(&self) -> Arc<dyn crate::repository::RouteRepositoryPort>;
    async fn bootstrap_initial_administrator(
        &self,
        configured: Option<&tls::AdministratorPrincipalV1>,
    ) -> Result<repository::BootstrapOutcome, repository::RouteRepositoryError>;
}
pub trait Clock: Send + Sync {}

#[derive(Clone, Default)]
pub struct ProductionProviders {
    pub directory_verifier: Option<Arc<dyn DirectoryVerifier>>,
    pub certificate_issuer: Option<Arc<dyn DeviceCertificateIssuer>>,
    pub configuration_signer: Option<Arc<dyn ConfigurationSigner>>,
    pub repository: Option<Arc<dyn ServerRepository>>,
    pub enrollment_service: Option<Arc<dyn enrollment::EnrollmentServicePort>>,
    pub provisioning_service: Option<Arc<dyn enrollment::ProvisioningServicePort>>,
    pub clock: Option<Arc<dyn Clock>>,
}

#[derive(Clone)]
pub struct ServerState {
    _config: ServerConfig,
    _providers: Option<ProductionProviders>,
    route_state: routes::RouteState,
    readiness: health::ReadinessDependencies,
}

impl ServerState {
    pub fn production(
        config: ServerConfig,
        providers: ProductionProviders,
    ) -> Result<Self, ServerError> {
        validate_providers(&providers)?;
        let signer = providers
            .configuration_signer
            .as_ref()
            .expect("validated signer provider")
            .route_signer();
        let repository = providers
            .repository
            .as_ref()
            .expect("validated repository provider")
            .route_repository();
        let enrollment_service = providers
            .enrollment_service
            .as_ref()
            .expect("validated enrollment service")
            .clone();
        let provisioning_service = providers
            .provisioning_service
            .as_ref()
            .expect("validated provisioning service")
            .clone();
        Ok(Self {
            _config: config,
            _providers: Some(providers),
            route_state: routes::RouteState::new(
                repository,
                enrollment_service,
                provisioning_service,
                signer,
            ),
            readiness: health::ReadinessDependencies::all_ready(),
        })
    }

    #[cfg(any(test, debug_assertions))]
    pub fn for_test() -> Self {
        Self {
            _config: ServerConfig::for_test(),
            _providers: None,
            route_state: routes::RouteState::for_test(),
            readiness: health::ReadinessDependencies::none_ready(),
        }
    }
}

fn validate_providers(providers: &ProductionProviders) -> Result<(), ServerError> {
    if providers.directory_verifier.is_none() {
        return Err(ServerError::MissingProvider {
            provider: "directory_verifier",
        });
    }
    if providers.certificate_issuer.is_none() {
        return Err(ServerError::MissingProvider {
            provider: "certificate_issuer",
        });
    }
    if providers.configuration_signer.is_none() {
        return Err(ServerError::MissingProvider {
            provider: "configuration_signer",
        });
    }
    if providers.repository.is_none() {
        return Err(ServerError::MissingProvider {
            provider: "repository",
        });
    }
    if providers.enrollment_service.is_none() {
        return Err(ServerError::MissingProvider {
            provider: "enrollment_service",
        });
    }
    if providers.provisioning_service.is_none() {
        return Err(ServerError::MissingProvider {
            provider: "provisioning_service",
        });
    }
    if providers.clock.is_none() {
        return Err(ServerError::MissingProvider { provider: "clock" });
    }
    Ok(())
}

#[derive(Serialize)]
pub struct HealthResponse {
    status: &'static str,
}

/// Builds the library-owned HTTP application. Liveness exposes process state only.
pub fn build_app(state: ServerState) -> Router {
    let readiness = state.readiness;
    Router::new()
        .route("/health/live", get(health_live))
        .route("/health/ready", get(health_ready))
        .route("/api/v1/tracer", get(tracer_contract))
        .merge(routes::api_v1_router(state.route_state))
        .layer(Extension(readiness))
}

pub async fn health_live() -> (StatusCode, Json<HealthResponse>) {
    (StatusCode::OK, Json(HealthResponse { status: "ok" }))
}

pub async fn health_ready(
    Extension(dependencies): Extension<health::ReadinessDependencies>,
) -> (StatusCode, Json<HealthResponse>) {
    let report = health::readiness(&dependencies);
    let status = if report.status == StatusCode::OK {
        "ok"
    } else {
        "not_ready"
    };
    (report.status, Json(HealthResponse { status }))
}

/// Confirms that a bound server exposes the final versioned tracer namespace.
/// Stateful enrollment/configuration work is deliberately supplied by the repository port.
pub async fn tracer_contract() -> StatusCode {
    StatusCode::NO_CONTENT
}

/// Development-only state used by the SQLite tracer. It is unavailable from a release build,
/// so fixture providers cannot be accidentally selected by production startup.
#[cfg(debug_assertions)]
pub fn tracer_state_for_development() -> ServerState {
    ServerState::for_test()
}

/// Runs only the development tracer app on a listener that the caller already bound.
/// Production startup remains `run_server`, which validates production providers and runs
/// PostgreSQL migrations before binding.
#[cfg(debug_assertions)]
pub async fn serve_tracer_listener(listener: tokio::net::TcpListener) -> Result<(), ServerError> {
    axum::serve(listener, build_app(tracer_state_for_development()))
        .await
        .map_err(|_| ServerError::ServeFailed)
}

/// Applies the embedded, forward-only SQLx ledger before any listener is bound.
pub async fn run_migrations(pool: &PgPool) -> Result<(), ServerError> {
    MIGRATOR
        .run(pool)
        .await
        .map_err(|_| ServerError::MigrationFailed)
}

/// Compose's one-shot migration service uses the same embedded ledger as
/// production startup and exits before any listener can be bound.
pub async fn run_migrations_from_environment() -> Result<(), ServerError> {
    let config = ServerConfig::from_environment()?;
    let pool = PgPoolOptions::new()
        .connect(&config.database_url)
        .await
        .map_err(|_| ServerError::DatabaseUnavailable)?;
    run_migrations(&pool).await
}

async fn run_migrations_for_startup(pool: Option<&PgPool>) -> Result<(), ServerError> {
    let pool = pool.ok_or(ServerError::MigrationFailed)?;
    run_migrations(pool).await
}

/// The sole production ordering seam: validate providers, migrate, then bind.
pub async fn run_server(
    config: ServerConfig,
    providers: ProductionProviders,
) -> Result<(), ServerError> {
    validate_providers(&providers)?;
    let pool = PgPoolOptions::new()
        .connect(&config.database_url)
        .await
        .map_err(|_| ServerError::DatabaseUnavailable)?;
    run_migrations_for_startup(Some(&pool)).await?;
    let initial_administrator = initial_administrator_from_environment()?;
    let repository = providers
        .repository
        .as_ref()
        .expect("validated repository provider");
    match repository
        .bootstrap_initial_administrator(initial_administrator.as_ref())
        .await
    {
        Ok(repository::BootstrapOutcome::Created) => {
            eprintln!("initial_admin_bootstrap_created");
        }
        Ok(repository::BootstrapOutcome::Idempotent) => {
            eprintln!("initial_admin_bootstrap_idempotent");
        }
        Err(repository::RouteRepositoryError::MissingInitialAdministrator) => {
            return Err(ServerError::MissingInitialAdministrator);
        }
        Err(repository::RouteRepositoryError::Conflict) => {
            eprintln!("initial_admin_bootstrap_conflict");
            return Err(ServerError::InitialAdministratorConflict);
        }
        Err(_) => return Err(ServerError::DatabaseUnavailable),
    }
    let state = ServerState::production(config.clone(), providers)?;
    let listener = tokio::net::TcpListener::bind(config.listen_address())
        .await
        .map_err(|_| ServerError::ListenerFailed)?;
    let tls_paths = tls::TlsPaths::from_environment().map_err(|_| ServerError::ListenerFailed)?;
    let tls_configuration = tls_paths
        .server_config()
        .map_err(|_| ServerError::ListenerFailed)?;
    let identity_roots = tls_paths
        .identity_roots()
        .map_err(|_| ServerError::ListenerFailed)?;
    tls::serve_tls_listener(
        listener,
        tls_configuration,
        identity_roots,
        build_app(state),
    )
    .await
    .map_err(|_| ServerError::ServeFailed)
}

fn initial_administrator_from_environment()
-> Result<Option<tls::AdministratorPrincipalV1>, ServerError> {
    match std::env::var("DLP_INITIAL_ADMIN_PRINCIPAL_SHA256") {
        Ok(value) => tls::AdministratorPrincipalV1::parse(&value)
            .map(Some)
            .map_err(|_| ServerError::InvalidInitialAdministrator),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(std::env::VarError::NotUnicode(_)) => Err(ServerError::InvalidInitialAdministrator),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        Clock, ConfigurationSigner, DeviceCertificateIssuer, DirectoryVerifier,
        ProductionProviders, ServerConfig, ServerError, ServerRepository, ServerState, build_app,
        health_live, run_migrations_for_startup,
    };
    use std::sync::Arc;

    #[test]
    fn production_state_rejects_missing_required_providers() {
        let config = ServerConfig::for_test();
        assert!(ServerState::production(config, Default::default()).is_err());

        struct Directory;
        #[async_trait::async_trait]
        impl DirectoryVerifier for Directory {
            async fn corroborate_computer(
                &self,
                _computer_dns_name: &str,
            ) -> Result<crate::VerifiedComputerIdentity, crate::DirectoryError> {
                Ok(crate::VerifiedComputerIdentity {
                    object_guid: vec![1; 16],
                    object_sid: vec![2; 16],
                    dns_name: "device.lab.local".into(),
                    domain: "LAB".into(),
                    enabled: true,
                })
            }
        }
        struct CertificateIssuer;
        impl DeviceCertificateIssuer for CertificateIssuer {}
        struct Signer;
        impl ConfigurationSigner for Signer {
            fn route_signer(&self) -> Arc<dlp_crypto::ConfigurationSigner> {
                Arc::new(dlp_crypto::ConfigurationSigner::from_seed("test", [5; 32]))
            }
        }
        struct Repository;
        #[async_trait::async_trait]
        impl ServerRepository for Repository {
            fn route_repository(&self) -> Arc<dyn crate::repository::RouteRepositoryPort> {
                Arc::new(crate::repository::RouteRepository::default())
            }

            async fn bootstrap_initial_administrator(
                &self,
                _configured: Option<&crate::tls::AdministratorPrincipalV1>,
            ) -> Result<crate::repository::BootstrapOutcome, crate::repository::RouteRepositoryError>
            {
                Ok(crate::repository::BootstrapOutcome::Idempotent)
            }
        }
        struct TestEnrollmentService;
        #[async_trait::async_trait]
        impl crate::enrollment::EnrollmentServicePort for TestEnrollmentService {
            async fn enroll(
                &self,
                _submission: crate::enrollment::EnrollmentSubmission,
            ) -> Result<crate::pki::IssuedDeviceCredential, crate::enrollment::EnrollmentError>
            {
                Ok(crate::pki::IssuedDeviceCredential {
                    certificate_chain_pem: String::new(),
                    serial: vec![],
                    expires_after_days: 30,
                })
            }
        }
        struct TestProvisioningService;
        #[async_trait::async_trait]
        impl crate::enrollment::ProvisioningServicePort for TestProvisioningService {
            async fn provision(
                &self,
                request: dlp_protocol::ProvisionDeviceRequestV1,
            ) -> Result<dlp_protocol::ProvisionDeviceResponseV1, crate::enrollment::EnrollmentError>
            {
                dlp_protocol::ProvisionDeviceResponseV1::new(1, request.device_id(), "token")
                    .map_err(|_| crate::enrollment::EnrollmentError::IntegrityFailure)
            }
        }
        struct TestClock;
        impl Clock for TestClock {}

        let providers = ProductionProviders {
            directory_verifier: Some(Arc::new(Directory)),
            certificate_issuer: Some(Arc::new(CertificateIssuer)),
            configuration_signer: Some(Arc::new(Signer)),
            repository: Some(Arc::new(Repository)),
            enrollment_service: Some(Arc::new(TestEnrollmentService)),
            provisioning_service: Some(Arc::new(TestProvisioningService)),
            clock: Some(Arc::new(TestClock)),
        };
        assert!(ServerState::production(ServerConfig::for_test(), providers).is_ok());
    }

    #[tokio::test]
    async fn liveness_is_process_only_and_migrations_gate_listener_startup() {
        let state = ServerState::for_test();
        let app = build_app(state);
        let (status, _) = health_live().await;
        assert_eq!(status, axum::http::StatusCode::OK);
        assert!(matches!(
            run_migrations_for_startup(None).await,
            Err(ServerError::MigrationFailed)
        ));
        let _ = app;
    }
}

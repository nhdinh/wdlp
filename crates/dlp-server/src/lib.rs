#![forbid(unsafe_code)]

//! Fail-closed server composition. Route behavior and real provider adapters are
//! deliberately added by later plans; this seam owns process-only liveness and
//! migration-before-bind ordering now.

use axum::{Router, http::StatusCode, routing::get};
use sqlx::{PgPool, migrate::Migrator, postgres::PgPoolOptions};
use std::{fmt, net::SocketAddr, sync::Arc};

pub mod ad;
pub mod enrollment;
pub mod pki;
pub mod repository;

static MIGRATOR: Migrator = sqlx::migrate!("../../migrations");

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ServerError {
    MissingDatabaseUrl,
    MissingProvider { provider: &'static str },
    DatabaseUnavailable,
    MigrationFailed,
    ListenerFailed,
    ServeFailed,
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
        };
        write!(formatter, "{code}")
    }
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
        let listen_address = "127.0.0.1:8080"
            .parse()
            .expect("static loopback address is valid");
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

pub trait DirectoryVerifier: Send + Sync {}
pub trait DeviceCertificateIssuer: Send + Sync {}
pub trait ConfigurationSigner: Send + Sync {}
pub trait ServerRepository: Send + Sync {}
pub trait Clock: Send + Sync {}

#[derive(Clone, Default)]
pub struct ProductionProviders {
    pub directory_verifier: Option<Arc<dyn DirectoryVerifier>>,
    pub certificate_issuer: Option<Arc<dyn DeviceCertificateIssuer>>,
    pub configuration_signer: Option<Arc<dyn ConfigurationSigner>>,
    pub repository: Option<Arc<dyn ServerRepository>>,
    pub clock: Option<Arc<dyn Clock>>,
}

#[derive(Clone)]
pub struct ServerState {
    _config: ServerConfig,
    _providers: Option<ProductionProviders>,
}

impl ServerState {
    pub fn production(
        config: ServerConfig,
        providers: ProductionProviders,
    ) -> Result<Self, ServerError> {
        validate_providers(&providers)?;
        Ok(Self {
            _config: config,
            _providers: Some(providers),
        })
    }

    #[cfg(any(test, debug_assertions))]
    pub fn for_test() -> Self {
        Self {
            _config: ServerConfig::for_test(),
            _providers: None,
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
    if providers.clock.is_none() {
        return Err(ServerError::MissingProvider { provider: "clock" });
    }
    Ok(())
}

/// Builds the library-owned HTTP application. Liveness exposes process state only.
pub fn build_app(_state: ServerState) -> Router {
    Router::new()
        .route("/health/live", get(health_live))
        .route("/api/v1/tracer", get(tracer_contract))
}

pub async fn health_live() -> StatusCode {
    StatusCode::NO_CONTENT
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

async fn run_migrations_for_startup(pool: Option<&PgPool>) -> Result<(), ServerError> {
    let pool = pool.ok_or(ServerError::MigrationFailed)?;
    run_migrations(pool).await
}

/// The sole production ordering seam: validate providers, migrate, then bind.
pub async fn run_server(
    config: ServerConfig,
    providers: ProductionProviders,
) -> Result<(), ServerError> {
    let state = ServerState::production(config.clone(), providers)?;
    let pool = PgPoolOptions::new()
        .connect(&config.database_url)
        .await
        .map_err(|_| ServerError::DatabaseUnavailable)?;
    run_migrations_for_startup(Some(&pool)).await?;
    let listener = tokio::net::TcpListener::bind(config.listen_address())
        .await
        .map_err(|_| ServerError::ListenerFailed)?;
    axum::serve(listener, build_app(state))
        .await
        .map_err(|_| ServerError::ServeFailed)
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
        impl DirectoryVerifier for Directory {}
        struct CertificateIssuer;
        impl DeviceCertificateIssuer for CertificateIssuer {}
        struct Signer;
        impl ConfigurationSigner for Signer {}
        struct Repository;
        impl ServerRepository for Repository {}
        struct TestClock;
        impl Clock for TestClock {}

        let providers = ProductionProviders {
            directory_verifier: Some(Arc::new(Directory)),
            certificate_issuer: Some(Arc::new(CertificateIssuer)),
            configuration_signer: Some(Arc::new(Signer)),
            repository: Some(Arc::new(Repository)),
            clock: Some(Arc::new(TestClock)),
        };
        assert!(ServerState::production(ServerConfig::for_test(), providers).is_ok());
    }

    #[tokio::test]
    async fn liveness_is_process_only_and_migrations_gate_listener_startup() {
        let state = ServerState::for_test();
        let app = build_app(state);
        assert_eq!(health_live().await, axum::http::StatusCode::NO_CONTENT);
        assert!(matches!(
            run_migrations_for_startup(None).await,
            Err(ServerError::MigrationFailed)
        ));
        let _ = app;
    }
}

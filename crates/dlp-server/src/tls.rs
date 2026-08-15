//! TLS material loading and request identity boundaries.
//!
//! TLS certificate material is loaded only from mounted paths.  The module never
//! accepts proxy-injected certificate headers: an identity must originate from a
//! completed rustls client-certificate handshake.

use axum::{
    extract::connect_info::Connected,
    serve::{IncomingStream, Listener},
};
use std::{env, fs, io, path::PathBuf, sync::Arc};
use tokio::{
    net::TcpListener,
    time::{Duration, sleep},
};
use tokio_rustls::rustls::{
    RootCertStore, ServerConfig,
    pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject},
    server::WebPkiClientVerifier,
};
use tokio_rustls::{TlsAcceptor, server::TlsStream};
use x509_parser::{extensions::GeneralName, parse_x509_certificate};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CredentialStatus {
    Active,
    Revoked,
    Expired,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum PeerRole {
    Administrator,
    Device,
}

/// An identity derived from the TLS peer certificate.  It deliberately has no
/// constructor from HTTP headers.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PeerIdentity {
    role: PeerRole,
    subject: String,
    serial: Vec<u8>,
}

impl PeerIdentity {
    /// Converts a certificate accepted by the rustls verifier into the only
    /// application identity representation. Device leaves must carry the fixed
    /// Phase 1 client profile; other verified leaves are administrator-only.
    pub fn from_verified_leaf(leaf_der: &[u8]) -> Result<Self, TlsError> {
        match Self::device_from_verified_leaf(leaf_der) {
            Ok(device) => Ok(device),
            Err(TlsError::Unauthorized) => {
                let (remainder, certificate) =
                    parse_x509_certificate(leaf_der).map_err(|_| TlsError::InvalidMaterial)?;
                if !remainder.is_empty()
                    || certificate.is_ca()
                    || !certificate.validity().is_valid()
                {
                    return Err(TlsError::Unauthorized);
                }
                let subject = certificate.subject().to_string();
                let serial = certificate.raw_serial().to_vec();
                if subject.is_empty() || serial.is_empty() {
                    return Err(TlsError::Unauthorized);
                }
                Ok(Self {
                    role: PeerRole::Administrator,
                    subject,
                    serial,
                })
            }
            Err(error) => Err(error),
        }
    }

    pub fn device_from_verified_leaf(leaf_der: &[u8]) -> Result<Self, TlsError> {
        let (remainder, certificate) =
            parse_x509_certificate(leaf_der).map_err(|_| TlsError::InvalidMaterial)?;
        if !remainder.is_empty() || certificate.is_ca() || !certificate.validity().is_valid() {
            return Err(TlsError::Unauthorized);
        }
        let key_usage = certificate
            .key_usage()
            .map_err(|_| TlsError::InvalidMaterial)?
            .ok_or(TlsError::Unauthorized)?;
        let extended_usage = certificate
            .extended_key_usage()
            .map_err(|_| TlsError::InvalidMaterial)?
            .ok_or(TlsError::Unauthorized)?;
        if !key_usage.value.digital_signature() || !extended_usage.value.client_auth {
            return Err(TlsError::Unauthorized);
        }
        let san = certificate
            .subject_alternative_name()
            .map_err(|_| TlsError::InvalidMaterial)?
            .ok_or(TlsError::Unauthorized)?;
        let device_id = san
            .value
            .general_names
            .iter()
            .find_map(|name| match name {
                GeneralName::URI(uri) => uri.strip_prefix("urn:dlp:device:"),
                _ => None,
            })
            .filter(|value| !value.is_empty())
            .ok_or(TlsError::Unauthorized)?;
        Ok(Self {
            role: PeerRole::Device,
            subject: device_id.to_owned(),
            serial: certificate.raw_serial().to_vec(),
        })
    }
    #[cfg(any(test, debug_assertions))]
    pub fn admin_for_test(subject: impl Into<String>) -> Self {
        Self {
            role: PeerRole::Administrator,
            subject: subject.into(),
            serial: vec![1],
        }
    }

    #[cfg(any(test, debug_assertions))]
    pub fn device_for_test(subject: impl Into<String>, serial: Vec<u8>) -> Self {
        Self {
            role: PeerRole::Device,
            subject: subject.into(),
            serial,
        }
    }

    pub fn subject(&self) -> &str {
        &self.subject
    }

    pub fn serial(&self) -> &[u8] {
        &self.serial
    }
}

/// Per-connection TLS metadata delivered by the rustls listener to Axum. It is
/// deliberately not constructible from request headers.
#[derive(Clone, Debug)]
pub struct TlsConnectionInfo {
    identity: Option<PeerIdentity>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IdentityRoots {
    administrator_issuer: String,
    device_issuer: String,
}

impl IdentityRoots {
    fn from_paths(paths: &TlsPaths) -> Result<Self, TlsError> {
        Ok(Self {
            administrator_issuer: certificate_subject(&paths.administrator_ca)?,
            device_issuer: certificate_subject(&paths.device_issuing_ca)?,
        })
    }

    fn peer_identity(&self, leaf_der: &[u8]) -> Result<PeerIdentity, TlsError> {
        let (remainder, certificate) =
            parse_x509_certificate(leaf_der).map_err(|_| TlsError::InvalidMaterial)?;
        if !remainder.is_empty() || certificate.is_ca() || !certificate.validity().is_valid() {
            return Err(TlsError::Unauthorized);
        }
        let issuer = certificate.issuer().to_string();
        if issuer == self.device_issuer {
            return PeerIdentity::device_from_verified_leaf(leaf_der);
        }
        if issuer != self.administrator_issuer {
            return Err(TlsError::Unauthorized);
        }
        let subject = certificate.subject().to_string();
        let serial = certificate.raw_serial().to_vec();
        if subject.is_empty() || serial.is_empty() {
            return Err(TlsError::Unauthorized);
        }
        Ok(PeerIdentity {
            role: PeerRole::Administrator,
            subject,
            serial,
        })
    }
}

impl TlsConnectionInfo {
    pub fn from_verified_peer(identity: PeerIdentity) -> Self {
        Self {
            identity: Some(identity),
        }
    }

    /// Bootstrap enrollment is the only route that may receive an ordinary
    /// server-authenticated TLS connection without a client certificate.
    pub fn bootstrap_without_peer() -> Self {
        Self { identity: None }
    }

    pub fn identity(&self) -> Option<&PeerIdentity> {
        self.identity.as_ref()
    }
}

/// An Axum listener that completes the required rustls handshake before an
/// HTTP connection exists. Invalid, expired, absent, or malformed client
/// certificates are dropped here; they never become HTTP requests.
pub struct RustlsListener {
    listener: TcpListener,
    acceptor: TlsAcceptor,
    identity_roots: IdentityRoots,
}

impl RustlsListener {
    pub fn new(
        listener: TcpListener,
        configuration: Arc<ServerConfig>,
        identity_roots: IdentityRoots,
    ) -> Self {
        Self {
            listener,
            acceptor: TlsAcceptor::from(configuration),
            identity_roots,
        }
    }
}

impl Listener for RustlsListener {
    type Io = TlsStream<tokio::net::TcpStream>;
    type Addr = TlsConnectionInfo;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            let Ok((stream, _)) = self.listener.accept().await else {
                sleep(Duration::from_millis(50)).await;
                continue;
            };
            let Ok(stream) = self.acceptor.accept(stream).await else {
                continue;
            };
            let identity = stream
                .get_ref()
                .1
                .peer_certificates()
                .and_then(|chain| chain.first())
                .map(|certificate| self.identity_roots.peer_identity(certificate.as_ref()))
                .transpose();
            let Ok(identity) = identity else {
                continue;
            };
            return (
                stream,
                match identity {
                    Some(identity) => TlsConnectionInfo::from_verified_peer(identity),
                    None => TlsConnectionInfo::bootstrap_without_peer(),
                },
            );
        }
    }

    fn local_addr(&self) -> io::Result<Self::Addr> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "TLS connection identity has no listener address",
        ))
    }
}

impl Connected<IncomingStream<'_, RustlsListener>> for TlsConnectionInfo {
    fn connect_info(stream: IncomingStream<'_, RustlsListener>) -> Self {
        stream.remote_addr().clone()
    }
}

pub async fn serve_tls_listener(
    listener: TcpListener,
    configuration: Arc<ServerConfig>,
    identity_roots: IdentityRoots,
    app: axum::Router,
) -> io::Result<()> {
    axum::serve(
        RustlsListener::new(listener, configuration, identity_roots),
        app.into_make_service_with_connect_info::<TlsConnectionInfo>(),
    )
    .await
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticatedAdmin {
    subject: String,
}

impl AuthenticatedAdmin {
    pub fn from_peer(peer: PeerIdentity) -> Result<Self, TlsError> {
        if peer.role != PeerRole::Administrator || peer.subject.is_empty() {
            return Err(TlsError::Unauthorized);
        }
        Ok(Self {
            subject: peer.subject,
        })
    }

    pub fn subject(&self) -> &str {
        &self.subject
    }

    /// Headers are never a TLS identity source, including in test/dev mode.
    pub fn from_forwarded_header(_header_name: &str) -> Result<Self, TlsError> {
        Err(TlsError::Unauthorized)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticatedDevice {
    device_id: String,
    credential_serial: Vec<u8>,
}

impl AuthenticatedDevice {
    pub fn from_peer(
        peer: PeerIdentity,
        credential_status: CredentialStatus,
    ) -> Result<Self, TlsError> {
        if peer.role != PeerRole::Device
            || peer.subject.is_empty()
            || peer.serial.is_empty()
            || credential_status != CredentialStatus::Active
        {
            return Err(TlsError::Unauthorized);
        }
        Ok(Self {
            device_id: peer.subject,
            credential_serial: peer.serial,
        })
    }

    pub fn device_id(&self) -> &str {
        &self.device_id
    }

    pub fn credential_serial(&self) -> &[u8] {
        &self.credential_serial
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TlsPaths {
    pub server_certificate: PathBuf,
    pub server_private_key: PathBuf,
    pub administrator_ca: PathBuf,
    pub phase1_root_ca: PathBuf,
    pub device_issuing_ca: PathBuf,
}

impl TlsPaths {
    pub fn from_environment() -> Result<Self, TlsError> {
        Ok(Self {
            server_certificate: required_path("DLP_SERVER_CERT_PEM")?,
            server_private_key: required_path("DLP_SERVER_KEY_PEM")?,
            administrator_ca: required_path("DLP_ADMIN_CA_CERT_PEM")?,
            phase1_root_ca: required_path("DLP_PHASE1_ROOT_CA_CERT_PEM")?,
            device_issuing_ca: required_path("DLP_DEVICE_ISSUING_CA_CERT_PEM")?,
        })
    }

    /// Builds a required-client-auth rustls configuration. Administrator and
    /// device CAs are trusted only for handshake authentication; route-level
    /// role and active-credential checks remain mandatory before handlers run.
    pub fn server_config(&self) -> Result<Arc<ServerConfig>, TlsError> {
        let certificates = load_certificates(&self.server_certificate)?;
        let private_key = load_private_key(&self.server_private_key)?;
        let mut client_roots = RootCertStore::empty();
        for certificate in load_certificates(&self.administrator_ca)?
            .into_iter()
            .chain(load_certificates(&self.device_issuing_ca)?)
        {
            client_roots
                .add(certificate)
                .map_err(|_| TlsError::InvalidMaterial)?;
        }
        // Read the public Phase 1 root now so a missing bootstrap anchor fails
        // closed before serving; no root private key is ever requested.
        let mut bootstrap_roots = RootCertStore::empty();
        for certificate in load_certificates(&self.phase1_root_ca)? {
            bootstrap_roots
                .add(certificate)
                .map_err(|_| TlsError::InvalidMaterial)?;
        }
        if bootstrap_roots.is_empty() {
            return Err(TlsError::InvalidMaterial);
        }

        let verifier = WebPkiClientVerifier::builder(Arc::new(client_roots))
            .allow_unauthenticated()
            .build()
            .map_err(|_| TlsError::InvalidMaterial)?;
        let mut configuration = ServerConfig::builder()
            .with_client_cert_verifier(verifier)
            .with_single_cert(certificates, private_key)
            .map_err(|_| TlsError::InvalidMaterial)?;
        configuration.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        Ok(Arc::new(configuration))
    }

    pub fn identity_roots(&self) -> Result<IdentityRoots, TlsError> {
        IdentityRoots::from_paths(self)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TlsError {
    MissingConfiguration,
    InvalidMaterial,
    Unauthorized,
}

fn required_path(variable: &str) -> Result<PathBuf, TlsError> {
    let value = env::var_os(variable).ok_or(TlsError::MissingConfiguration)?;
    if value.is_empty() {
        return Err(TlsError::MissingConfiguration);
    }
    let path = PathBuf::from(value);
    if !path.is_file() {
        return Err(TlsError::InvalidMaterial);
    }
    Ok(path)
}

fn load_certificates(path: &PathBuf) -> Result<Vec<CertificateDer<'static>>, TlsError> {
    let bytes = fs::read(path).map_err(|_| TlsError::InvalidMaterial)?;
    let certificates = CertificateDer::pem_slice_iter(&bytes)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| TlsError::InvalidMaterial)?;
    if certificates.is_empty() {
        return Err(TlsError::InvalidMaterial);
    }
    Ok(certificates)
}

fn load_private_key(path: &PathBuf) -> Result<PrivateKeyDer<'static>, TlsError> {
    let bytes = fs::read(path).map_err(|_| TlsError::InvalidMaterial)?;
    PrivateKeyDer::from_pem_slice(&bytes).map_err(|_| TlsError::InvalidMaterial)
}

fn certificate_subject(path: &PathBuf) -> Result<String, TlsError> {
    let certificates = load_certificates(path)?;
    let (_, certificate) =
        parse_x509_certificate(certificates[0].as_ref()).map_err(|_| TlsError::InvalidMaterial)?;
    Ok(certificate.subject().to_string())
}

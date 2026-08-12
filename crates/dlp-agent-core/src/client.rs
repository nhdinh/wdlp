//! Pinned-bootstrap and device-mTLS client configuration guard.
//!
//! The agent never sends its endpoint private key.  Bootstrap uses ordinary
//! server-authenticated TLS with the approved public root and hostname-only
//! validation.  After enrollment, every protected request requires the issued
//! device certificate as a TLS client identity; there is no bearer fallback.

use dlp_domain::DeviceId;
use dlp_protocol::HealthReportV1;
use x509_parser::{
    extensions::GeneralName,
    parse_x509_certificate,
};

const ENROLLMENT_URL_PATH: &str = "/api/v1/enrollment";
const HEALTH_URL_PATH: &str = "/api/v1/device/health";
const MAX_BODY_BYTES: usize = 256 * 1024;
const EXPECTED_DAYS: u64 = 30;
const EXPECTED_SECONDS: u64 = EXPECTED_DAYS * 24 * 60 * 60;

/// Transport port for fetching signed configuration bytes through device mTLS.
pub trait ConfigurationTransport {
    fn fetch_configuration(&mut self) -> Result<Vec<u8>, ClientError>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ClientError {
    InvalidServerUrl,
    InvalidTrustAnchor,
    MissingDeviceCredential,
    ConfigurationFetchFailed,
}

impl std::fmt::Display for ClientError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let code = match self {
            Self::InvalidServerUrl => "client_invalid_server_url",
            Self::InvalidTrustAnchor => "client_invalid_trust_anchor",
            Self::MissingDeviceCredential => "client_missing_device_credential",
            Self::TlsConfiguration => "client_tls_configuration",
            Self::RequestDenied => "client_request_denied",
            Self::InvalidResponse => "client_invalid_response",
            Self::ProfileRejected => "client_profile_rejected",
            Self::NetworkUnavailable => "client_network_unavailable",
        };
        formatter.write_str(code)
    }
}

impl std::error::Error for ClientError {}

/// Validated view of a returned device certificate chain.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedDeviceIdentity {
    pub device_id: String,
    pub certificate_chain_pem: String,
    pub serial: Vec<u8>,
    pub expires_after_epoch_seconds: u64,
}

pub struct AgentHttpClient {
    server_url: String,
    root_pem: String,
    certificate_chain_pem: Option<String>,
    private_key_pem: Option<String>,
    timeout_seconds: u64,
}

impl std::fmt::Debug for AgentHttpClient {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AgentHttpClient")
            .field("server_url", &self.server_url)
            .field("has_root", &!self.root_pem.is_empty())
            .field("has_device_identity", &self.uses_device_mtls())
            .field("timeout_seconds", &self.timeout_seconds)
            .finish()
    }
}

impl AgentHttpClient {
    pub fn bootstrap(
        server_url: impl Into<String>,
        root_pem: impl Into<String>,
    ) -> Result<Self, ClientError> {
        let server_url = server_url.into();
        let root_pem = root_pem.into();
        if !server_url.starts_with("https://") {
            return Err(ClientError::InvalidServerUrl);
        }
        if !root_pem.contains("BEGIN CERTIFICATE") {
            return Err(ClientError::InvalidTrustAnchor);
        }
        Ok(Self {
            server_url,
            root_pem,
            certificate_chain_pem: None,
            private_key_pem: None,
            timeout_seconds: 30,
        })
    }

    pub fn with_device_identity(
        mut self,
        certificate_chain_pem: impl Into<String>,
        private_key_pem: impl Into<String>,
    ) -> Result<Self, ClientError> {
        let certificate_chain_pem = certificate_chain_pem.into();
        let private_key_pem = private_key_pem.into();
        if certificate_chain_pem.is_empty() || private_key_pem.is_empty() {
            return Err(ClientError::MissingDeviceCredential);
        }
        if !certificate_chain_pem.contains("BEGIN CERTIFICATE")
            || !private_key_pem.contains("BEGIN PRIVATE KEY")
        {
            return Err(ClientError::MissingDeviceCredential);
        }
        self.certificate_chain_pem = Some(certificate_chain_pem);
        self.private_key_pem = Some(private_key_pem);
        Ok(self)
    }

    pub fn uses_device_mtls(&self) -> bool {
        self.certificate_chain_pem.is_some()
    }

    pub fn timeout_seconds(&self) -> u64 {
        self.timeout_seconds
    }

    /// Polls a signed configuration only when a device-mTLS identity is present.
    ///
    /// The transport implementation is responsible for TLS identity, server
    /// authentication, and exact-byte retrieval; this method is the guard that
    /// refuses to fetch without device credentials.
    pub fn poll_configuration<T: ConfigurationTransport>(
        &self,
        transport: &mut T,
    ) -> Result<Vec<u8>, ClientError> {
        if !self.device_mtls {
            return Err(ClientError::MissingDeviceCredential);
        }
        transport.fetch_configuration()
    }
}

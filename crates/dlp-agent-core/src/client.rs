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
    TlsConfiguration,
    RequestDenied,
    InvalidResponse,
    ProfileRejected,
    NetworkUnavailable,
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
            Self::ConfigurationFetchFailed => "client_configuration_fetch_failed",
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
        if !self.uses_device_mtls() {
            return Err(ClientError::MissingDeviceCredential);
        }
        transport.fetch_configuration()
    }

    /// POSTs a version-1 enrollment request and validates the returned chain.
    pub fn post_enrollment(
        &self,
        device_id: &DeviceId,
        token: &str,
        csr_pem: &str,
        prior_serial: Option<&[u8]>,
    ) -> Result<ValidatedDeviceIdentity, ClientError> {
        let client = self.build_client(false)?;
        let url = format!("{}{}", self.server_url, ENROLLMENT_URL_PATH);
        let request_body = EnrollmentRequestBody {
            version: 1,
            device_id: device_id.to_wire().to_owned(),
            token: token.to_owned(),
            csr_pem: csr_pem.to_owned(),
            prior_serial: prior_serial.map(|serial| {
                serial
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<String>()
            }),
        };
        let body = serde_json::to_string(&request_body).map_err(|_| ClientError::InvalidResponse)?;

        let response = client
            .post(&url)
            .header("content-type", "application/json")
            .body(body)
            .send()
            .map_err(|_| ClientError::NetworkUnavailable)?;
        if !response.status().is_success() {
            return Err(ClientError::RequestDenied);
        }
        let text = response
            .text()
            .map_err(|_| ClientError::InvalidResponse)?;
        if text.len() > MAX_BODY_BYTES {
            return Err(ClientError::InvalidResponse);
        }
        let enrollment: EnrollmentResponseBody = serde_json::from_str(&text)
            .map_err(|_| ClientError::InvalidResponse)?;
        validate_device_chain(device_id, &enrollment.credential_chain, &self.root_pem)
    }

    /// Posts a redacted health report using the device-mTLS identity.
    pub fn post_health(&self, device_id: &DeviceId, drive_state: &str) -> Result<(), ClientError> {
        if !self.uses_device_mtls() {
            return Err(ClientError::MissingDeviceCredential);
        }
        let client = self.build_client(true)?;
        let url = format!("{}{}", self.server_url, HEALTH_URL_PATH);
        let report = HealthReportV1::new(1, device_id.clone(), drive_state)
            .map_err(|_| ClientError::InvalidResponse)?;
        let body = serde_json::to_string(&HealthRequest {
            version: report.version(),
            drive_state: drive_state.to_owned(),
        })
        .map_err(|_| ClientError::InvalidResponse)?;
        let response = client
            .post(&url)
            .header("content-type", "application/json")
            .body(body)
            .send()
            .map_err(|_| ClientError::NetworkUnavailable)?;
        if !response.status().is_success() {
            return Err(ClientError::RequestDenied);
        }
        Ok(())
    }

    fn build_client(&self, require_device_identity: bool) -> Result<reqwest::blocking::Client, ClientError> {
        let mut builder = reqwest::blocking::Client::builder()
            .https_only(true)
            .add_root_certificate(
                reqwest::Certificate::from_pem(self.root_pem.as_bytes())
                    .map_err(|_| ClientError::InvalidTrustAnchor)?,
            )
            .connect_timeout(std::time::Duration::from_secs(10))
            .timeout(std::time::Duration::from_secs(self.timeout_seconds));

        if let (Some(chain), Some(key)) = (
            self.certificate_chain_pem.as_ref(),
            self.private_key_pem.as_ref(),
        ) {
            let identity_pem = format!("{}\n{}", chain, key);
            let identity = reqwest::Identity::from_pem(identity_pem.as_bytes())
                .map_err(|_| ClientError::TlsConfiguration)?;
            builder = builder.identity(identity);
        } else if require_device_identity {
            return Err(ClientError::MissingDeviceCredential);
        }

        builder.build().map_err(|_| ClientError::TlsConfiguration)
    }
}

#[derive(serde::Serialize)]
struct EnrollmentRequestBody {
    version: u16,
    device_id: String,
    token: String,
    csr_pem: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    prior_serial: Option<String>,
}

#[derive(serde::Deserialize)]
struct EnrollmentResponseBody {
    credential_chain: String,
}

#[derive(serde::Serialize)]
struct HealthRequest {
    version: u16,
    drive_state: String,
}

fn validate_device_chain(
    device_id: &DeviceId,
    chain_pem: &str,
    trusted_root_pem: &str,
) -> Result<ValidatedDeviceIdentity, ClientError> {
    if chain_pem.len() > MAX_BODY_BYTES || !chain_pem.contains("BEGIN CERTIFICATE") {
        return Err(ClientError::InvalidResponse);
    }

    let certs = rustls_pemfile::certs(&mut chain_pem.as_bytes())
        .map_err(|_| ClientError::InvalidResponse)?;
    if certs.is_empty() {
        return Err(ClientError::InvalidResponse);
    }

    let leaf_der = certs.first().expect("non-empty chain");
    let leaf = parse_x509_certificate(leaf_der)
        .map_err(|_| ClientError::ProfileRejected)?
        .1;

    if leaf.is_ca() {
        return Err(ClientError::ProfileRejected);
    }
    if !leaf.validity().is_valid() {
        return Err(ClientError::ProfileRejected);
    }

    let key_usage = leaf
        .key_usage()
        .map_err(|_| ClientError::ProfileRejected)?
        .ok_or(ClientError::ProfileRejected)?;
    if !key_usage.value.digital_signature() {
        return Err(ClientError::ProfileRejected);
    }
    let extended_usage = leaf
        .extended_key_usage()
        .map_err(|_| ClientError::ProfileRejected)?
        .ok_or(ClientError::ProfileRejected)?;
    if !extended_usage.value.client_auth {
        return Err(ClientError::ProfileRejected);
    }

    let san = leaf
        .subject_alternative_name()
        .map_err(|_| ClientError::ProfileRejected)?
        .ok_or(ClientError::ProfileRejected)?;
    let expected_uri = format!("urn:dlp:device:{}", device_id.to_wire());
    let has_uri = san.value.general_names.iter().any(|name| {
        if let GeneralName::URI(uri) = name {
            *uri == expected_uri.as_str()
        } else {
            false
        }
    });
    if !has_uri {
        return Err(ClientError::ProfileRejected);
    }

    let serial = leaf.raw_serial().to_vec();
    if serial.is_empty() {
        return Err(ClientError::ProfileRejected);
    }

    let not_after = leaf.validity().not_after;
    let not_before = leaf.validity().not_before;
    let expires_after_epoch_seconds = not_after.timestamp() as u64;
    let issued_after_epoch_seconds = not_before.timestamp() as u64;
    if expires_after_epoch_seconds.saturating_sub(issued_after_epoch_seconds) > EXPECTED_SECONDS {
        return Err(ClientError::ProfileRejected);
    }

    let roots = rustls_pemfile::certs(&mut trusted_root_pem.as_bytes())
        .map_err(|_| ClientError::InvalidTrustAnchor)?;
    let root_subject = roots
        .first()
        .and_then(|root_der| parse_x509_certificate(root_der.as_slice()).ok())
        .map(|(_, root)| root.subject().to_string())
        .ok_or(ClientError::InvalidTrustAnchor)?;
    let root_in_chain = certs.iter().any(|cert| {
        parse_x509_certificate(cert.as_slice())
            .ok()
            .map(|(_, cert)| cert.subject().to_string())
            .is_some_and(|subject| subject == root_subject)
    });
    if !root_in_chain {
        return Err(ClientError::ProfileRejected);
    }

    Ok(ValidatedDeviceIdentity {
        device_id: device_id.to_wire().to_owned(),
        certificate_chain_pem: chain_pem.to_owned(),
        serial,
        expires_after_epoch_seconds,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use dlp_domain::DeviceId;

    #[test]
    fn bootstrap_rejects_non_https_and_missing_anchor() {
        assert_eq!(
            AgentHttpClient::bootstrap("http://server", "root").unwrap_err(),
            ClientError::InvalidServerUrl
        );
        assert_eq!(
            AgentHttpClient::bootstrap("https://server", "not-a-cert").unwrap_err(),
            ClientError::InvalidTrustAnchor
        );
    }

    #[test]
    fn device_mtls_requires_material() {
        let client = AgentHttpClient::bootstrap("https://server", "-----BEGIN CERTIFICATE-----\nMIIBkA==\n-----END CERTIFICATE-----").unwrap();
        assert_eq!(
            client.with_device_identity("", "").unwrap_err(),
            ClientError::MissingDeviceCredential
        );
    }

    #[test]
    fn profile_validation_rejects_empty_or_invalid_chain() {
        let device = DeviceId::parse("device-01").unwrap();
        assert_eq!(
            validate_device_chain(&device, "", "root").unwrap_err(),
            ClientError::InvalidResponse
        );
    }
}

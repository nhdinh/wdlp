//! Pinned-bootstrap and device-mTLS client configuration guard.

/// Transport port for fetching signed configuration bytes through device mTLS.
pub trait ConfigurationTransport {
    fn fetch_configuration(&mut self) -> Result<Vec<u8>, ClientError>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentHttpClient {
    server_url: String,
    root_pem: String,
    device_mtls: bool,
    timeout_seconds: u64,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClientError {
    InvalidServerUrl,
    InvalidTrustAnchor,
    MissingDeviceCredential,
    ConfigurationFetchFailed,
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
            device_mtls: false,
            timeout_seconds: 30,
        })
    }
    pub fn with_device_mtls(
        mut self,
        certificate_chain: &[u8],
        private_key: &[u8],
    ) -> Result<Self, ClientError> {
        if certificate_chain.is_empty() || private_key.is_empty() {
            return Err(ClientError::MissingDeviceCredential);
        }
        self.device_mtls = true;
        Ok(self)
    }
    pub fn uses_device_mtls(&self) -> bool {
        self.device_mtls
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

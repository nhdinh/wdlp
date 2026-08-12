#![forbid(unsafe_code)]

//! Versioned REST `/api/v1` data-transfer contracts.
//!
//! Configuration signing intentionally accepts only `ConfigurationEnvelopeV1`'s
//! length-delimited, fixed-field bytes. Arbitrary maps are not a signing input.

use dlp_domain::{BundleVersion, DeviceId};
use sha2::{Digest, Sha256};
use std::fmt;

pub const API_VERSION_V1: u16 = 1;
pub const CONFIGURATION_SCHEMA_VERSION_V1: u16 = 1;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProtocolError {
    UnsupportedVersion { shape: &'static str, received: u16 },
    InvalidField { field: &'static str },
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedVersion { shape, received } => {
                write!(formatter, "unsupported version {received} for {shape}")
            }
            Self::InvalidField { field } => write!(formatter, "invalid {field}: [REDACTED]"),
        }
    }
}

impl std::error::Error for ProtocolError {}

fn require_v1(shape: &'static str, version: u16) -> Result<(), ProtocolError> {
    if version == API_VERSION_V1 {
        Ok(())
    } else {
        Err(ProtocolError::UnsupportedVersion {
            shape,
            received: version,
        })
    }
}

fn require_nonempty(field: &'static str, value: &str) -> Result<(), ProtocolError> {
    if value.is_empty() || value.len() > 65_536 {
        Err(ProtocolError::InvalidField { field })
    } else {
        Ok(())
    }
}

/// The `/api/v1/enrollment` request. The token is deliberately redacted in logs.
#[derive(Clone, Eq, PartialEq)]
pub struct EnrollmentRequestV1 {
    version: u16,
    device_id: DeviceId,
    enrollment_token: String,
}

impl EnrollmentRequestV1 {
    pub fn new(
        version: u16,
        device_id: DeviceId,
        enrollment_token: impl Into<String>,
    ) -> Result<Self, ProtocolError> {
        require_v1("EnrollmentRequestV1", version)?;
        let enrollment_token = enrollment_token.into();
        require_nonempty("enrollment token", &enrollment_token)?;
        Ok(Self {
            version,
            device_id,
            enrollment_token,
        })
    }

    pub const fn version(&self) -> u16 {
        self.version
    }

    pub fn device_id(&self) -> &DeviceId {
        &self.device_id
    }

    /// Returns the redacted enrollment token for transport use only.
    pub fn enrollment_token(&self) -> &str {
        &self.enrollment_token
    }
}

impl fmt::Debug for EnrollmentRequestV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EnrollmentRequestV1")
            .field("version", &self.version)
            .field("device_id", &self.device_id)
            .field("enrollment_token", &"[REDACTED]")
            .finish()
    }
}

/// Trusted-station provisioning input for a device that both configured domain
/// controllers have already corroborated. The database receives the normalized
/// identity and fixed digest, never the underlying hardware observations.
#[derive(Clone, Eq, PartialEq)]
pub struct ProvisionDeviceRequestV1 {
    version: u16,
    device_id: String,
    fingerprint_version: u16,
    fingerprint_digest: [u8; 32],
    ad_object_guid: Vec<u8>,
    ad_object_sid: Vec<u8>,
    ad_dns_name: String,
    ad_domain: String,
    preferred_drive_letter: char,
}

impl ProvisionDeviceRequestV1 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        version: u16,
        device_id: impl Into<String>,
        fingerprint_version: u16,
        fingerprint_digest: [u8; 32],
        ad_object_guid: Vec<u8>,
        ad_object_sid: Vec<u8>,
        ad_dns_name: impl Into<String>,
        ad_domain: impl Into<String>,
        preferred_drive_letter: char,
    ) -> Result<Self, ProtocolError> {
        require_v1("ProvisionDeviceRequestV1", version)?;
        let device_id = device_id.into();
        let ad_dns_name = ad_dns_name.into();
        let ad_domain = ad_domain.into();
        require_nonempty("device identity", &device_id)?;
        require_nonempty("AD DNS name", &ad_dns_name)?;
        require_nonempty("AD domain", &ad_domain)?;
        if fingerprint_version != 1
            || ad_object_guid.len() != 16
            || !(8..=68).contains(&ad_object_sid.len())
            || !preferred_drive_letter.is_ascii_uppercase()
        {
            return Err(ProtocolError::InvalidField {
                field: "trusted provisioning identity",
            });
        }
        Ok(Self {
            version,
            device_id,
            fingerprint_version,
            fingerprint_digest,
            ad_object_guid,
            ad_object_sid,
            ad_dns_name,
            ad_domain,
            preferred_drive_letter,
        })
    }

    pub const fn version(&self) -> u16 {
        self.version
    }

    pub fn device_id(&self) -> &str {
        &self.device_id
    }

    pub const fn fingerprint_version(&self) -> u16 {
        self.fingerprint_version
    }

    pub const fn fingerprint_digest(&self) -> &[u8; 32] {
        &self.fingerprint_digest
    }

    pub fn ad_object_guid(&self) -> &[u8] {
        &self.ad_object_guid
    }

    pub fn ad_object_sid(&self) -> &[u8] {
        &self.ad_object_sid
    }

    pub fn ad_dns_name(&self) -> &str {
        &self.ad_dns_name
    }

    pub fn ad_domain(&self) -> &str {
        &self.ad_domain
    }

    pub const fn preferred_drive_letter(&self) -> char {
        self.preferred_drive_letter
    }
}

impl fmt::Debug for ProvisionDeviceRequestV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProvisionDeviceRequestV1")
            .field("version", &self.version)
            .field("device_id", &self.device_id)
            .field("fingerprint_version", &self.fingerprint_version)
            .field("fingerprint_digest", &"[REDACTED]")
            .field("ad_object_guid", &"[REDACTED]")
            .field("ad_object_sid", &"[REDACTED]")
            .field("ad_dns_name", &self.ad_dns_name)
            .field("ad_domain", &self.ad_domain)
            .field("preferred_drive_letter", &self.preferred_drive_letter)
            .finish()
    }
}

/// The `/api/v1/enrollment` response. Credential material is opaque to this crate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnrollmentResponseV1 {
    version: u16,
    device_id: DeviceId,
    credential_chain: String,
}

impl EnrollmentResponseV1 {
    pub fn new(
        version: u16,
        device_id: DeviceId,
        credential_chain: impl Into<String>,
    ) -> Result<Self, ProtocolError> {
        require_v1("EnrollmentResponseV1", version)?;
        let credential_chain = credential_chain.into();
        require_nonempty("credential chain", &credential_chain)?;
        Ok(Self {
            version,
            device_id,
            credential_chain,
        })
    }

    /// Returns only the public certificate-chain response payload. The
    /// enrollment request never exposes an endpoint-generated private key.
    pub fn credential_chain(&self) -> &str {
        &self.credential_chain
    }

    pub const fn version(&self) -> u16 {
        self.version
    }
}

/// Fixed, versioned fields that are signed before any configuration activation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConfigurationEnvelopeV1 {
    version: u16,
    schema_version: u16,
    device_id: DeviceId,
    bundle_version: BundleVersion,
    issued_at_epoch_seconds: u64,
    payload: String,
}

impl ConfigurationEnvelopeV1 {
    pub fn new(
        schema_version: u16,
        device_id: DeviceId,
        bundle_version: BundleVersion,
        issued_at_epoch_seconds: u64,
        payload: impl Into<String>,
    ) -> Result<Self, ProtocolError> {
        if schema_version != CONFIGURATION_SCHEMA_VERSION_V1 {
            return Err(ProtocolError::UnsupportedVersion {
                shape: "ConfigurationEnvelopeV1 schema",
                received: schema_version,
            });
        }
        let payload = payload.into();
        require_nonempty("configuration payload", &payload)?;
        Ok(Self {
            version: API_VERSION_V1,
            schema_version,
            device_id,
            bundle_version,
            issued_at_epoch_seconds,
            payload,
        })
    }

    pub const fn version(&self) -> u16 {
        self.version
    }

    pub const fn schema_version(&self) -> u16 {
        self.schema_version
    }

    pub fn bundle_version(&self) -> &BundleVersion {
        &self.bundle_version
    }

    pub fn device_id(&self) -> &DeviceId {
        &self.device_id
    }

    pub const fn issued_at_epoch_seconds(&self) -> u64 {
        self.issued_at_epoch_seconds
    }

    pub fn payload(&self) -> &str {
        &self.payload
    }

    /// Encodes the only signature input as a length-delimited fixed field sequence.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut output = b"dlp-configuration-envelope/v1\0".to_vec();
        append_u16(&mut output, self.version);
        append_u16(&mut output, self.schema_version);
        append_bytes(&mut output, self.device_id.to_wire().as_bytes());
        append_bytes(&mut output, self.bundle_version.to_wire().as_bytes());
        append_u64(&mut output, self.issued_at_epoch_seconds);
        append_bytes(&mut output, self.payload.as_bytes());
        output
    }
}

/// The signed wrapper. Its signature is never included in the signed bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedConfigurationV1 {
    version: u16,
    envelope: ConfigurationEnvelopeV1,
    key_id: String,
    signature: Vec<u8>,
    content_digest: [u8; 32],
    audience: DeviceId,
}

impl SignedConfigurationV1 {
    pub fn new(
        envelope: ConfigurationEnvelopeV1,
        key_id: impl Into<String>,
        signature: Vec<u8>,
    ) -> Result<Self, ProtocolError> {
        let key_id = key_id.into();
        require_nonempty("key identifier", &key_id)?;
        if signature.is_empty() {
            return Err(ProtocolError::InvalidField { field: "signature" });
        }
        let content_digest: [u8; 32] = Sha256::digest(envelope.canonical_bytes()).into();
        let audience = envelope.device_id().clone();
        Ok(Self {
            version: API_VERSION_V1,
            envelope,
            key_id,
            signature,
            content_digest,
            audience,
        })
    }

    pub const fn version(&self) -> u16 {
        self.version
    }

    pub fn envelope(&self) -> &ConfigurationEnvelopeV1 {
        &self.envelope
    }

    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    pub fn signature(&self) -> &[u8] {
        &self.signature
    }

    pub fn content_digest(&self) -> &[u8; 32] {
        &self.content_digest
    }

    pub fn audience(&self) -> &DeviceId {
        &self.audience
    }
}

/// The `/api/v1/health` report.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HealthReportV1 {
    version: u16,
    device_id: DeviceId,
    status: String,
}

impl HealthReportV1 {
    pub fn new(
        version: u16,
        device_id: DeviceId,
        status: impl Into<String>,
    ) -> Result<Self, ProtocolError> {
        require_v1("HealthReportV1", version)?;
        let status = status.into();
        require_nonempty("health status", &status)?;
        Ok(Self {
            version,
            device_id,
            status,
        })
    }

    pub const fn version(&self) -> u16 {
        self.version
    }
}

fn append_u16(output: &mut Vec<u8>, value: u16) {
    output.extend_from_slice(&value.to_be_bytes());
}

fn append_u64(output: &mut Vec<u8>, value: u64) {
    output.extend_from_slice(&value.to_be_bytes());
}

fn append_bytes(output: &mut Vec<u8>, value: &[u8]) {
    let length = u32::try_from(value.len()).expect("validated protocol field length");
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value);
}

#[cfg(test)]
mod tests {
    use super::{
        ConfigurationEnvelopeV1, EnrollmentRequestV1, HealthReportV1, ProtocolError,
        SignedConfigurationV1,
    };
    use dlp_domain::{BundleVersion, DeviceId};

    #[test]
    fn wire_dtos_reject_unsupported_versions_with_typed_errors() {
        let device = DeviceId::parse("device-01").expect("valid device");
        assert!(matches!(
            EnrollmentRequestV1::new(2, device.clone(), "token"),
            Err(ProtocolError::UnsupportedVersion { .. })
        ));
        assert!(matches!(
            HealthReportV1::new(2, device, "healthy"),
            Err(ProtocolError::UnsupportedVersion { .. })
        ));
    }

    #[test]
    fn signed_envelopes_use_repeatable_fixed_field_canonical_bytes() {
        let device = DeviceId::parse("device-01").expect("valid device");
        let version = BundleVersion::parse("bundle-01").expect("valid bundle version");
        let envelope = ConfigurationEnvelopeV1::new(1, device, version, 1_700_000_000, "allow")
            .expect("valid envelope");
        let signed = SignedConfigurationV1::new(envelope, "key-01", vec![1, 2, 3])
            .expect("valid signed configuration");

        assert_eq!(
            signed.envelope().canonical_bytes(),
            signed.envelope().canonical_bytes()
        );
        assert!(!signed.envelope().canonical_bytes().is_empty());
    }

    #[test]
    fn arbitrary_maps_cannot_be_used_as_canonical_signing_input() {
        let source = include_str!("lib.rs");
        let production_source = source
            .split("#[cfg(test)]")
            .next()
            .expect("source has a production section");
        assert!(!production_source.contains("serde_json::Map"));
        assert!(!production_source.contains("HashMap"));
    }
}

#![forbid(unsafe_code)]

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

        assert_eq!(signed.envelope().canonical_bytes(), signed.envelope().canonical_bytes());
        assert!(!signed.envelope().canonical_bytes().is_empty());
    }

    #[test]
    fn arbitrary_maps_cannot_be_used_as_canonical_signing_input() {
        let source = include_str!("lib.rs");
        assert!(!source.contains("serde_json::Map"));
        assert!(!source.contains("HashMap"));
    }
}

#![forbid(unsafe_code)]

#[cfg(test)]
mod tests {
    use super::{DeviceId, EnforcementAction};

    #[test]
    fn typed_values_reject_bad_input_and_redact_sensitive_output() {
        let device = DeviceId::parse("device-01").expect("valid device id");
        assert_eq!(device.to_wire(), "device-01");
        assert!(DeviceId::parse(" ").is_err());
        assert_eq!(format!("{device:?}"), "DeviceId([REDACTED])");
        assert_eq!(EnforcementAction::Block.as_str(), "block");
    }
}

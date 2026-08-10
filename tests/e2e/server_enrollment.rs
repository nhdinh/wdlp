use dlp_server::enrollment::{EnrollmentAttempt, EnrollmentError, EnrollmentService};
use dlp_server::tls::{AuthenticatedAdmin, AuthenticatedDevice, CredentialStatus, PeerIdentity};

#[test]
fn authority_issues_one_credential_only_after_exact_identity_checks() {
    let service = EnrollmentService::for_test();
    let result = service.enroll(EnrollmentAttempt::valid_for_test());
    assert!(result.is_ok());
}

#[test]
fn authority_fails_closed_for_an_invalid_or_reused_attempt() {
    let service = EnrollmentService::for_test();
    let attempt = EnrollmentAttempt::invalid_for_test();
    assert_eq!(service.enroll(attempt), Err(EnrollmentError::Denied));
}

#[test]
fn mtls_routes_reject_cross_role_revoked_and_forwarded_identities() {
    let device = PeerIdentity::device_for_test("device-test", vec![1, 2, 3]);
    assert!(AuthenticatedDevice::from_peer(device, CredentialStatus::Active).is_ok());
    assert!(AuthenticatedDevice::from_peer(
        PeerIdentity::admin_for_test("admin-test"),
        CredentialStatus::Active,
    )
    .is_err());
    assert!(AuthenticatedDevice::from_peer(
        PeerIdentity::device_for_test("device-test", vec![1, 2, 3]),
        CredentialStatus::Revoked,
    )
    .is_err());
    assert!(AuthenticatedAdmin::from_forwarded_header("X-Forwarded-Client-Cert").is_err());
}

use dlp_server::enrollment::{EnrollmentAttempt, EnrollmentError, EnrollmentService};
use dlp_server::tls::{
    AuthenticatedAdmin, AuthenticatedDevice, CredentialStatus, PeerIdentity, TlsPaths,
};
use rustls::pki_types::pem::PemObject;

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
    assert!(
        AuthenticatedDevice::from_peer(
            PeerIdentity::admin_for_test("admin-test"),
            CredentialStatus::Active,
        )
        .is_err()
    );
    assert!(
        AuthenticatedDevice::from_peer(
            PeerIdentity::device_for_test("device-test", vec![1, 2, 3]),
            CredentialStatus::Revoked,
        )
        .is_err()
    );
    assert!(AuthenticatedAdmin::from_forwarded_header("X-Forwarded-Client-Cert").is_err());
}

#[test]
fn mtls_server_config_requires_the_mounted_phase1_material() {
    let configuration = TlsPaths::from_environment()
        .and_then(|paths| paths.server_config())
        .expect("test fixture paths must build a required-client-auth server config");
    assert_eq!(
        configuration.alpn_protocols,
        vec![b"h2".to_vec(), b"http/1.1".to_vec()]
    );
}

#[test]
fn device_leaf_requires_uri_san_serial_and_client_profile() {
    let issuer = std::env::var("DLP_DEVICE_ISSUING_CA_CERT_PEM").expect("fixture path");
    let leaf = std::path::Path::new(&issuer).with_file_name("device.cert.pem");
    let pem = std::fs::read(leaf).expect("fixture leaf");
    let leaf = rustls::pki_types::CertificateDer::pem_slice_iter(&pem)
        .next()
        .expect("fixture certificate")
        .expect("valid fixture certificate");
    let peer = PeerIdentity::device_from_verified_leaf(leaf.as_ref()).expect("valid device leaf");
    assert!(AuthenticatedDevice::from_peer(peer, CredentialStatus::Active).is_ok());
}

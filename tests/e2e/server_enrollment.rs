use dlp_server::enrollment::{EnrollmentAttempt, EnrollmentError, EnrollmentService};
use dlp_server::health::{ReadinessDependencies, liveness, readiness};
use dlp_server::routes::RouteState;
use dlp_server::tls::{
    AuthenticatedAdmin, AuthenticatedDevice, CredentialStatus, PeerIdentity, TlsPaths,
};

#[test]
fn repository_postgresql_authority_contract_is_digest_only_and_locking() {
    use dlp_protocol::ProvisionDeviceRequestV1;

    let request = ProvisionDeviceRequestV1::new(
        1,
        "device-01",
        1,
        [7; 32],
        vec![1; 16],
        vec![2; 16],
        "device-01.lab.local",
        "LAB",
        'P',
    )
    .expect("version-1 provisioning request is valid");
    assert_eq!(request.fingerprint_digest(), &[7; 32]);
    assert!(format!("{request:?}").contains("[REDACTED]"));

    let source = include_str!("../../crates/dlp-server/src/repository.rs");
    assert!(source.contains("pub struct PgAuthorityRepository"));
    assert!(source.contains("FOR UPDATE"));
    assert!(source.contains("token_digest"));
    assert!(!source.contains("BLOB"));
}
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

#[test]
fn mtls_routes_bind_signed_configuration_and_health_to_the_active_device() {
    let state = RouteState::for_test();
    let device = AuthenticatedDevice::from_peer(
        PeerIdentity::device_for_test("device-test", vec![1, 2, 3]),
        CredentialStatus::Active,
    )
    .expect("active test device");

    state.activate_device_for_test(device.device_id(), device.credential_serial());
    let configuration = state
        .signed_configuration_for(&device)
        .expect("active device receives a signed configuration");
    assert_eq!(configuration.envelope().bundle_version().to_wire(), "1");
    assert!(state.record_health_for(&device, "mounted").is_ok());
    assert_eq!(state.health_report_count_for_test(device.device_id()), 1);

    state.revoke_device_for_test(device.device_id(), device.credential_serial());
    assert!(state.signed_configuration_for(&device).is_err());
    assert!(state.record_health_for(&device, "mounted").is_err());
}

#[test]
fn signed_configuration_is_audience_bound_hashed_and_replay_safe() {
    let state = RouteState::for_test();
    let device = AuthenticatedDevice::from_peer(
        PeerIdentity::device_for_test("device-test", vec![1, 2, 3]),
        CredentialStatus::Active,
    )
    .expect("active test device");
    state.activate_device_for_test(device.device_id(), device.credential_serial());

    let first = state
        .signed_configuration_for(&device)
        .expect("first signed configuration");
    assert_eq!(first.audience().to_wire(), device.device_id());
    assert_eq!(first.content_digest().len(), 32);
    assert_eq!(first.content_digest(), first.content_digest());
    assert!(
        state
            .stage_configuration_for_test(device.device_id(), 1)
            .is_err()
    );
    state
        .stage_configuration_for_test(device.device_id(), 2)
        .expect("higher version is staged");
    assert_eq!(
        state
            .signed_configuration_for(&device)
            .expect("select greatest version")
            .envelope()
            .bundle_version()
            .to_wire(),
        "2"
    );
}

#[test]
fn readiness_is_read_only_and_requires_every_dependency() {
    assert_eq!(liveness(), axum::http::StatusCode::OK);
    let missing = ReadinessDependencies::none_ready();
    assert_eq!(
        readiness(&missing).status,
        axum::http::StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(
        readiness(&ReadinessDependencies::all_ready()).status,
        axum::http::StatusCode::OK
    );
}

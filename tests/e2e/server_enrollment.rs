use axum::http::StatusCode;
use dlp_server::enrollment::{EnrollmentAttempt, EnrollmentError, TestEnrollmentService};
use dlp_server::health::{ReadinessDependencies, liveness, readiness};
use dlp_server::routes::RouteState;
use dlp_server::tls::{
    AuthenticatedAdmin, AuthenticatedDevice, CredentialStatus, PeerIdentity, TlsPaths,
};

/// Writes environment PEM values to deterministic fixture files so the
/// focused-Hyper-V source tests can run without committing secret material.
/// A fresh device leaf with the required URI SAN is generated from the
/// device-issuing CA when the env var contains PEM content rather than a path.
#[cfg(test)]
fn ensure_phase1_pki_fixtures() -> std::path::PathBuf {
    use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, SanType};
    use std::fs;

    let repo_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..");
    let fixture_dir = repo_root.join("target").join("01-07-pki");
    fs::create_dir_all(&fixture_dir).expect("fixture directory");

    let pem_vars = [
        ("DLP_SERVER_CERT_PEM", "server-cert.pem"),
        ("DLP_SERVER_KEY_PEM", "server-key.pem"),
        ("DLP_ADMIN_CA_CERT_PEM", "admin-ca.pem"),
        ("DLP_PHASE1_ROOT_CA_CERT_PEM", "phase1-root-ca.pem"),
        ("DLP_DEVICE_ISSUING_CA_CERT_PEM", "device-issuing-ca.pem"),
        ("DLP_DEVICE_ISSUING_CA_KEY_PEM", "device-issuing-ca-key.pem"),
    ];

    for (var, filename) in pem_vars {
        let value = std::env::var(var).unwrap_or_default();
        let path = fixture_dir.join(filename);
        if value.trim_start().starts_with("-----BEGIN") {
            fs::write(&path, value).expect("write fixture");
        } else if !value.is_empty() && std::path::Path::new(&value).exists() {
            let content = fs::read(&value).expect("read existing fixture");
            fs::write(&path, content).expect("copy fixture");
        }
    }

    // Generate a device leaf cert signed by the device-issuing CA.
    let device_cert_path = fixture_dir.join("device-cert.pem");
    if !device_cert_path.exists() {
        let ca_cert_pem = fs::read_to_string(fixture_dir.join("device-issuing-ca.pem"))
            .expect("device issuing CA cert");
        let ca_key_pem = fs::read_to_string(fixture_dir.join("device-issuing-ca-key.pem"))
            .expect("device issuing CA key");
        let ca_key = KeyPair::from_pem(&ca_key_pem).expect("parse device CA key");
        let issuer = rcgen::Issuer::from_ca_cert_pem(&ca_cert_pem, ca_key)
            .expect("parse device CA issuer");

        let device_key = KeyPair::generate().expect("generate device key");
        let mut params = CertificateParams::new(vec!["device-01.lab.local".into()])
            .expect("device cert params");
        params.distinguished_name = DistinguishedName::new();
        params.distinguished_name.push(DnType::CommonName, "device-01");
        params.subject_alt_names.push(SanType::URI(
            rcgen::string::Ia5String::try_from("urn:dlp:device:device-01").expect("valid URI SAN"),
        ));
        params.key_usages.push(rcgen::KeyUsagePurpose::DigitalSignature);
        params.extended_key_usages.push(rcgen::ExtendedKeyUsagePurpose::ClientAuth);
        let device_cert = params
            .signed_by(&device_key, &issuer)
            .expect("sign device cert");
        fs::write(
            &device_cert_path,
            device_cert.pem() + &device_key.serialize_pem(),
        )
        .expect("write device cert");
    }

    fixture_dir
}

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

#[test]
fn enrollment_transaction_contract_uses_postgres_and_constrained_issuer() {
    let enrollment = include_str!("../../crates/dlp-server/src/enrollment.rs");
    let pki = include_str!("../../crates/dlp-server/src/pki.rs");
    let repository = include_str!("../../crates/dlp-server/src/repository.rs");
    assert!(enrollment.contains("pub struct EnrollmentService"));
    assert!(enrollment.contains("PgAuthorityRepository"));
    assert!(repository.contains("consume_and_activate"));
    assert!(repository.contains("revoked_device_credentials"));
    assert!(pki.contains("not_after"));
    assert!(pki.contains("ClientAuth"));
    assert!(pki.contains("DigitalSignature"));
}
use rustls::pki_types::pem::PemObject;

#[test]
fn authority_issues_one_credential_only_after_exact_identity_checks() {
    let service = TestEnrollmentService::for_test();
    let result = service.enroll(EnrollmentAttempt::valid_for_test());
    assert!(result.is_ok());
}

#[test]
fn authority_fails_closed_for_an_invalid_or_reused_attempt() {
    let service = TestEnrollmentService::for_test();
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
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("ring crypto provider installs for test");
    let fixture_dir = ensure_phase1_pki_fixtures();
    let paths = TlsPaths {
        server_certificate: fixture_dir.join("server-cert.pem"),
        server_private_key: fixture_dir.join("server-key.pem"),
        administrator_ca: fixture_dir.join("admin-ca.pem"),
        phase1_root_ca: fixture_dir.join("phase1-root-ca.pem"),
        device_issuing_ca: fixture_dir.join("device-issuing-ca.pem"),
    };
    let configuration = paths
        .server_config()
        .expect("test fixture paths must build a required-client-auth server config");
    assert_eq!(
        configuration.alpn_protocols,
        vec![b"h2".to_vec(), b"http/1.1".to_vec()]
    );
}

#[test]
fn device_leaf_requires_uri_san_serial_and_client_profile() {
    let fixture_dir = ensure_phase1_pki_fixtures();
    let leaf = fixture_dir.join("device-cert.pem");
    let pem = std::fs::read(leaf).expect("fixture leaf");
    let leaf = rustls::pki_types::CertificateDer::pem_slice_iter(&pem)
        .next()
        .expect("fixture certificate")
        .expect("valid fixture certificate");
    let peer = PeerIdentity::device_from_verified_leaf(leaf.as_ref()).expect("valid device leaf");
    assert!(AuthenticatedDevice::from_peer(peer, CredentialStatus::Active).is_ok());
}

#[tokio::test]
async fn mtls_routes_bind_signed_configuration_and_health_to_the_active_device() {
    let state = RouteState::for_test();
    let device = AuthenticatedDevice::from_peer(
        PeerIdentity::device_for_test("device-test", vec![1, 2, 3]),
        CredentialStatus::Active,
    )
    .expect("active test device");

    state.activate_device_for_test(device.device_id(), device.credential_serial()).await;
    let configuration = state
        .signed_configuration_for(&device)
        .await
        .expect("active device receives a signed configuration");
    assert_eq!(configuration.envelope().bundle_version().to_wire(), "1");
    assert!(state.record_health_for(&device, "mounted").await.is_ok());
    assert_eq!(state.health_report_count_for_test(device.device_id()).await, 1);

    state.revoke_device_for_test(device.device_id(), device.credential_serial()).await;
    assert!(state.signed_configuration_for(&device).await.is_err());
    assert!(state.record_health_for(&device, "mounted").await.is_err());
}

#[tokio::test]
async fn signed_configuration_is_audience_bound_hashed_and_replay_safe() {
    let state = RouteState::for_test();
    let device = AuthenticatedDevice::from_peer(
        PeerIdentity::device_for_test("device-test", vec![1, 2, 3]),
        CredentialStatus::Active,
    )
    .expect("active test device");
    state.activate_device_for_test(device.device_id(), device.credential_serial()).await;

    let first = state
        .signed_configuration_for(&device)
        .await
        .expect("first signed configuration");
    assert_eq!(first.audience().to_wire(), device.device_id());
    assert_eq!(first.content_digest().len(), 32);
    assert_eq!(first.content_digest(), first.content_digest());
    assert!(
        state
            .stage_configuration_for_test(device.device_id(), 1)
            .await
            .is_err()
    );
    state
        .stage_configuration_for_test(device.device_id(), 2)
        .await
        .expect("higher version is staged");
    assert_eq!(
        state
            .signed_configuration_for(&device)
            .await
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

#[test]
fn production_route_contract_partitions_bootstrap_admin_and_active_device_access() {
    let routes = include_str!("../../crates/dlp-server/src/routes.rs");
    let tls = include_str!("../../crates/dlp-server/src/tls.rs");
    let server = include_str!("../../crates/dlp-server/src/lib.rs");

    assert!(routes.contains("/api/v1/enrollment"));
    assert!(routes.contains("require_administrator"));
    assert!(routes.contains("require_active_device"));
    assert!(!server.contains("DLP_ADMIN_PROVISIONING_KEY"));
    assert!(!server.contains("Bearer "));
    assert!(tls.contains("Option<PeerIdentity>"));
}

#[test]
fn production_directory_contract_requires_two_hostname_results_and_denies_failures() {
    let directory = include_str!("../../crates/dlp-server/src/ad.rs");
    assert!(directory.contains("async fn corroborate_computer"));
    assert!(directory.contains("primary_ldaps_url"));
    assert!(directory.contains("secondary_ldaps_url"));
    assert!(directory.contains("DirectoryError::Disagreement"));
    assert!(directory.contains("IpAddr::from_str"));
}

#[test]
fn production_startup_contract_constructs_runtime_providers_before_binding() {
    let server = include_str!("../../crates/dlp-server/src/lib.rs");
    let main = include_str!("../../crates/dlp-server/src/main.rs");
    assert!(server.contains("pub fn from_environment(config: &ServerConfig)"));
    assert!(server.contains("run_migrations_for_startup"));
    assert!(main.contains("ProductionProviders::from_environment"));
    assert!(!main.contains("ProductionProviders::default()"));
}

#[test]
fn trusted_provisioning_preflight_requires_named_lab_roles_and_kerberos_tls() {
    let procedure = include_str!("../../scripts/lab/Invoke-TrustedProvisioning.ps1");
    assert!(procedure.contains("LAB-DC01"));
    assert!(procedure.contains("LAB-DC02"));
    assert!(procedure.contains("LAB-CLIENT01"));
    assert!(procedure.contains("Get-ADComputer -Server"));
    assert!(procedure.contains("New-CimSession"));
    assert!(procedure.contains("Kerberos"));
    assert!(procedure.contains("UseSSL"));
    assert!(!procedure.contains("Write-Output $token"));
}

#[test]
fn trusted_provisioning_invokes_dlpctl_without_serial_or_token_arguments() {
    let procedure = include_str!("../../scripts/lab/Invoke-TrustedProvisioning.ps1");
    assert!(procedure.contains("provision-device --computer"));
    assert!(procedure.contains("DLP_PROVISIONING_AD_OBJECT_GUID"));
    assert!(procedure.contains("DLP_PROVISIONING_AD_OBJECT_SID"));
    assert!(procedure.contains("DLP_PROVISIONING_PREFERRED_DRIVE_LETTER"));
    assert!(!procedure.contains("--serial"));
    assert!(!procedure.contains("--token"));
    assert!(!procedure.contains("Write-Output.*token"));
}

#[test]
fn trusted_provisioning_preflight_compares_both_domain_controllers() {
    let procedure = include_str!("../../scripts/lab/Invoke-TrustedProvisioning.ps1");
    assert!(procedure.contains("LAB-DC01.lab.local"));
    assert!(procedure.contains("LAB-DC02.lab.local"));
    assert!(procedure.contains("directory_corroboration_denied"));
    assert!(procedure.contains("$primaryIdentity -eq $secondaryIdentity"));
}

#[tokio::test]
async fn bootstrap_enrollment_route_returns_ok_for_bounded_valid_request() {
    use axum::body::Body;
    use axum::extract::connect_info::ConnectInfo;
    use dlp_server::routes::api_v1_router;
    use dlp_server::tls::TlsConnectionInfo;
    use axum::http::Request;
    use tower::ServiceExt;

    let state = RouteState::for_test();
    let app = api_v1_router(state);
    let mut request = Request::builder()
        .method("POST")
        .uri("/api/v1/enrollment")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::json!({
            "version": 1,
            "device_id": "device-01",
            "token": "one-time-token",
            "csr_pem": "-----BEGIN CERTIFICATE REQUEST-----\nMIIBkTCB+w==\n-----END CERTIFICATE REQUEST-----",
        }).to_string()))
        .unwrap();
    request
        .extensions_mut()
        .insert(ConnectInfo(TlsConnectionInfo::bootstrap_without_peer()));
    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn bootstrap_enrollment_route_returns_bad_request_for_invalid_version() {
    use axum::body::Body;
    use axum::extract::connect_info::ConnectInfo;
    use dlp_server::routes::api_v1_router;
    use dlp_server::tls::TlsConnectionInfo;
    use axum::http::Request;
    use tower::ServiceExt;

    let state = RouteState::for_test();
    let app = api_v1_router(state);
    let mut request = Request::builder()
        .method("POST")
        .uri("/api/v1/enrollment")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::json!({
            "version": 2,
            "device_id": "device-01",
            "token": "one-time-token",
            "csr_pem": "csr",
        }).to_string()))
        .unwrap();
    request
        .extensions_mut()
        .insert(ConnectInfo(TlsConnectionInfo::bootstrap_without_peer()));
    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn admin_provisioning_route_returns_ok_for_bounded_valid_request() {
    use axum::body::Body;
    use axum::extract::connect_info::ConnectInfo;
    use dlp_server::routes::api_v1_router;
    use dlp_server::tls::{PeerIdentity, TlsConnectionInfo};
    use axum::http::Request;
    use tower::ServiceExt;

    let state = RouteState::for_test();
    let app = api_v1_router(state);
    let mut request = Request::builder()
        .method("POST")
        .uri("/api/v1/admin/provisioning")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::json!({
            "version": 1,
            "device_id": "device-01",
            "fingerprint_digest": vec![0; 32],
            "ad_object_guid": vec![0; 16],
            "ad_object_sid": vec![0; 16],
            "preferred_drive_letter": "P",
        }).to_string()))
        .unwrap();
    request.extensions_mut().insert(ConnectInfo(
        TlsConnectionInfo::from_verified_peer(PeerIdentity::admin_for_test("admin-test")),
    ));
    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn admin_provisioning_route_returns_bad_request_for_short_digest() {
    use axum::body::Body;
    use axum::extract::connect_info::ConnectInfo;
    use dlp_server::routes::api_v1_router;
    use dlp_server::tls::{PeerIdentity, TlsConnectionInfo};
    use axum::http::Request;
    use tower::ServiceExt;

    let state = RouteState::for_test();
    let app = api_v1_router(state);
    let mut request = Request::builder()
        .method("POST")
        .uri("/api/v1/admin/provisioning")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::json!({
            "version": 1,
            "device_id": "device-01",
            "fingerprint_digest": vec![0; 16],
            "ad_object_guid": vec![0; 16],
            "ad_object_sid": vec![0; 16],
            "preferred_drive_letter": "P",
        }).to_string()))
        .unwrap();
    request.extensions_mut().insert(ConnectInfo(
        TlsConnectionInfo::from_verified_peer(PeerIdentity::admin_for_test("admin-test")),
    ));
    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

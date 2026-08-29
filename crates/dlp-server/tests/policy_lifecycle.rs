use axum::{
    body::Body,
    extract::{ConnectInfo, Request},
};
use dlp_server::{
    repository::{
        BootstrapOutcome, PgRouteRepository, PrincipalRole, RouteRepositoryError,
        RouteRepositoryPort,
    },
    routes::{PolicyDeploymentUpdate, RouteState, api_v1_router},
    run_migrations,
    tls::{
        AdministratorPrincipalV1, AuthenticatedAdmin, AuthenticatedDevice, CredentialStatus,
        PeerIdentity, TlsConnectionInfo,
    },
};
use serde_json::json;
use sqlx::{Connection, PgConnection, PgPool, postgres::PgPoolOptions};
use std::sync::Arc;
use tower::ServiceExt;

const POLICY_TEST_LOCK: i64 = 0x0202_00ff;

async fn policy_test_database() -> (PgConnection, PgPool) {
    let database_url = std::env::var("DATABASE_URL")
        .expect("DATABASE_URL must point to the dedicated PostgreSQL test database");
    let mut guard = PgConnection::connect(&database_url)
        .await
        .expect("connect PostgreSQL policy test guard");
    sqlx::query("SELECT pg_advisory_lock($1)")
        .bind(POLICY_TEST_LOCK)
        .execute(&mut guard)
        .await
        .expect("serialize policy lifecycle integration tests");
    let pool = PgPoolOptions::new()
        .max_connections(8)
        .connect(&database_url)
        .await
        .expect("connect PostgreSQL policy test pool");
    run_migrations(&pool)
        .await
        .expect("apply policy migrations");
    sqlx::query(
        "TRUNCATE policy_audit_events, published_policy_versions, policy_drafts, initial_admin_bootstrap, administrator_principals RESTART IDENTITY CASCADE",
    )
        .execute(&pool)
        .await
        .expect("reset policy lifecycle authority");
    (guard, pool)
}

fn admin(principal: AdministratorPrincipalV1) -> AuthenticatedAdmin {
    AuthenticatedAdmin::from_peer(PeerIdentity::admin_for_test_principal(principal))
        .expect("test administrator identity")
}

fn json_request(method: &str, uri: &str, body: serde_json::Value) -> Request {
    Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .expect("valid request")
}

fn attach_admin(request: &mut Request, principal: AdministratorPrincipalV1) {
    request
        .extensions_mut()
        .insert(ConnectInfo(TlsConnectionInfo::from_verified_peer(
            PeerIdentity::admin_for_test_principal(principal),
        )));
}

fn valid_policy(version: &str, action: &str) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "schema_version": 2,
        "policy_version": version,
        "default_action": action,
        "rules": []
    }))
    .expect("serialize policy fixture")
}

#[tokio::test]
async fn policy_roles_and_immutable_publish() {
    let (_guard, pool) = policy_test_database().await;
    let repository = Arc::new(PgRouteRepository::new(pool.clone()));

    let initial = AdministratorPrincipalV1::from_verified_der(b"issuer-a", b"leaf-a");
    let auditor_principal = AdministratorPrincipalV1::from_verified_der(b"issuer-a", b"leaf-b");
    let replacement = AdministratorPrincipalV1::from_verified_der(b"issuer-a", b"leaf-c");
    let changed_issuer = AdministratorPrincipalV1::from_verified_der(b"issuer-b", b"leaf-a");
    let changed_leaf = AdministratorPrincipalV1::from_verified_der(b"issuer-a", b"leaf-z");

    assert_ne!(
        initial, changed_issuer,
        "issuer substitution changes authority"
    );
    assert_ne!(initial, changed_leaf, "leaf substitution changes authority");
    assert_ne!(
        initial, auditor_principal,
        "equal-subject leaves remain distinct by DER"
    );
    let encoded = initial.to_wire();
    assert_eq!(
        AdministratorPrincipalV1::parse(&encoded),
        Ok(initial.clone())
    );
    assert!(AdministratorPrincipalV1::parse(&encoded.to_uppercase()).is_err());
    assert!(AdministratorPrincipalV1::parse(&format!(" {encoded}")).is_err());

    assert_eq!(
        repository.bootstrap_initial_administrator(None).await,
        Err(RouteRepositoryError::MissingInitialAdministrator)
    );
    assert_eq!(
        repository
            .bootstrap_initial_administrator(Some(&initial))
            .await,
        Ok(BootstrapOutcome::Created)
    );
    assert_eq!(
        repository
            .bootstrap_initial_administrator(Some(&initial))
            .await,
        Ok(BootstrapOutcome::Idempotent)
    );
    assert_eq!(
        repository
            .bootstrap_initial_administrator(Some(&changed_leaf))
            .await,
        Err(RouteRepositoryError::Conflict)
    );

    let initial_admin = admin(initial.clone());
    assert_eq!(
        repository.resolve_principal_role(&initial).await,
        Ok(PrincipalRole::Administrator)
    );
    assert_eq!(
        repository.resolve_principal_role(&changed_leaf).await,
        Err(RouteRepositoryError::Denied)
    );
    repository
        .grant_principal(&initial_admin, &auditor_principal, PrincipalRole::Auditor)
        .await
        .expect("administrator grants auditor");
    repository
        .grant_principal(&initial_admin, &replacement, PrincipalRole::Administrator)
        .await
        .expect("administrator grants replacement administrator");
    repository
        .revoke_principal(&admin(replacement.clone()), &initial)
        .await
        .expect("replacement administrator revokes predecessor");
    assert_eq!(
        repository
            .revoke_principal(&admin(replacement.clone()), &replacement)
            .await,
        Err(RouteRepositoryError::LastAdministrator)
    );

    let state = RouteState::with_repository_for_test(repository.clone());
    let policy_id = format!("policy-{}", uuid::Uuid::new_v4());
    let original = valid_policy("1", "allow");
    let revised = valid_policy("2", "block");
    state
        .save_policy_draft(&admin(replacement.clone()), &policy_id, &original)
        .await
        .expect("administrator saves draft");
    let digest = state
        .validate_policy_draft(&admin(replacement.clone()), &policy_id)
        .await
        .expect("administrator validates draft");
    let published = state
        .publish_policy_draft(&admin(replacement.clone()), &policy_id, 1)
        .await
        .expect("administrator publishes immutable version");
    assert_eq!(published.content_digest(), &digest);
    assert_eq!(published.source_json(), original.as_slice());

    let auditor = admin(auditor_principal.clone());
    assert_eq!(
        state
            .save_policy_draft(&auditor, &policy_id, &revised)
            .await,
        Err(dlp_server::routes::RouteError::Forbidden)
    );
    assert_eq!(
        state
            .inspect_policy_version(&auditor, &policy_id, 1)
            .await
            .expect("auditor may inspect")
            .source_json(),
        original.as_slice()
    );

    state
        .save_policy_draft(&admin(replacement.clone()), &policy_id, &revised)
        .await
        .expect("draft remains mutable after publication");
    assert_eq!(
        state
            .publish_policy_draft(&admin(replacement.clone()), &policy_id, 1)
            .await,
        Err(dlp_server::routes::RouteError::Conflict)
    );
    assert_eq!(
        state
            .inspect_policy_version(&auditor, &policy_id, 1)
            .await
            .expect("published version remains unchanged")
            .source_json(),
        original.as_slice()
    );

    let rejected_id = format!("rejected-{}", uuid::Uuid::new_v4());
    let unsupported = valid_policy("1", "require_justification");
    state
        .save_policy_draft(&admin(replacement.clone()), &rejected_id, &unsupported)
        .await
        .expect("store reviewable invalid draft");
    assert_eq!(
        state
            .validate_policy_draft(&admin(replacement.clone()), &rejected_id)
            .await,
        Err(dlp_server::routes::RouteError::InvalidPolicy)
    );
    assert_eq!(
        state
            .publish_policy_draft(&admin(replacement.clone()), &rejected_id, 1)
            .await,
        Err(dlp_server::routes::RouteError::InvalidPolicy)
    );
    assert!(
        repository
            .published_policy(&rejected_id, 1)
            .await
            .expect("query rejected policy authority")
            .is_none()
    );

    let app = api_v1_router(state);
    let mut auditor_mutation = json_request(
        "PUT",
        &format!("/api/v1/admin/policies/{policy_id}/draft?role=administrator"),
        json!({"version": 2, "document": serde_json::from_slice::<serde_json::Value>(&revised).unwrap()}),
    );
    auditor_mutation
        .headers_mut()
        .insert("x-dlp-role", "administrator".parse().unwrap());
    attach_admin(&mut auditor_mutation, auditor_principal.clone());
    assert_eq!(
        app.clone()
            .oneshot(auditor_mutation)
            .await
            .unwrap()
            .status(),
        axum::http::StatusCode::FORBIDDEN
    );

    let mut unregistered = json_request(
        "PUT",
        &format!("/api/v1/admin/policies/{policy_id}/draft"),
        json!({"version": 2, "document": serde_json::from_slice::<serde_json::Value>(&revised).unwrap(), "role": "administrator"}),
    );
    unregistered
        .headers_mut()
        .insert("x-dlp-role", "administrator".parse().unwrap());
    attach_admin(&mut unregistered, changed_leaf);
    assert_eq!(
        app.oneshot(unregistered).await.unwrap().status(),
        axum::http::StatusCode::UNAUTHORIZED
    );

    let audit_codes =
        sqlx::query_scalar::<_, String>("SELECT event_code FROM policy_audit_events ORDER BY id")
            .fetch_all(&pool)
            .await
            .expect("read metadata-only policy audit codes");
    assert!(
        audit_codes
            .iter()
            .any(|code| code == "initial_admin_bootstrap_created")
    );
    assert!(
        audit_codes
            .iter()
            .any(|code| code == "initial_admin_bootstrap_idempotent")
    );
    assert!(
        audit_codes
            .iter()
            .any(|code| code == "initial_admin_bootstrap_conflict")
    );
}

#[tokio::test]
async fn policy_bundle_contract() {
    let (_guard, pool) = policy_test_database().await;
    let repository = Arc::new(PgRouteRepository::new(pool.clone()));
    let administrator_principal =
        AdministratorPrincipalV1::from_verified_der(b"bundle-issuer", b"bundle-admin");
    repository
        .bootstrap_initial_administrator(Some(&administrator_principal))
        .await
        .expect("bootstrap bundle contract administrator");
    let administrator = admin(administrator_principal);
    let state = RouteState::with_repository_for_test(repository.clone());

    let device_id = format!("device-{}", uuid::Uuid::new_v4());
    let serial = uuid::Uuid::new_v4().as_bytes().to_vec();
    let first_random = *uuid::Uuid::new_v4().as_bytes();
    let second_random = *uuid::Uuid::new_v4().as_bytes();
    let mut fingerprint = [0_u8; 32];
    fingerprint[..16].copy_from_slice(&first_random);
    fingerprint[16..].copy_from_slice(&second_random);
    let mut token_digest = fingerprint;
    token_digest.reverse();
    sqlx::query("INSERT INTO device_allowlist (device_id, fingerprint_digest) VALUES ($1, $2)")
        .bind(&device_id)
        .bind(fingerprint.as_slice())
        .execute(&pool)
        .await
        .expect("allow bundle contract device");
    sqlx::query(
        "INSERT INTO enrollment_authority (device_id, fingerprint_version, fingerprint_digest, ad_object_guid, ad_object_sid, ad_dns_name, ad_domain, preferred_drive_letter, token_digest, token_expires_at) VALUES ($1, 1, $2, $3, $4, $5, 'LAB', 'P', $6, CURRENT_TIMESTAMP + INTERVAL '10 minutes')",
    )
    .bind(&device_id)
    .bind(fingerprint.as_slice())
    .bind(first_random.as_slice())
    .bind([1_u8; 8].as_slice())
    .bind(format!("{device_id}.lab.local"))
    .bind(token_digest.as_slice())
    .execute(&pool)
    .await
    .expect("create bundle contract enrollment authority");
    state.activate_device_for_test(&device_id, &serial).await;
    let device = AuthenticatedDevice::from_peer(
        PeerIdentity::device_for_test(&device_id, serial),
        CredentialStatus::Active,
    )
    .expect("authenticated bundle contract device");

    let default_policy_id = format!("default-{}", uuid::Uuid::new_v4());
    let first_override_id = format!("override-a-{}", uuid::Uuid::new_v4());
    let second_override_id = format!("override-b-{}", uuid::Uuid::new_v4());
    let default_source = valid_policy("default-1", "allow");
    let first_override_source = valid_policy("override-a-1", "block");
    let second_override_source = valid_policy("override-b-1", "allow");
    let mut published = Vec::new();
    for (policy_id, source) in [
        (&default_policy_id, &default_source),
        (&first_override_id, &first_override_source),
        (&second_override_id, &second_override_source),
    ] {
        state
            .save_policy_draft(&administrator, policy_id, source)
            .await
            .expect("save bundle policy draft");
        state
            .validate_policy_draft(&administrator, policy_id)
            .await
            .expect("validate bundle policy draft");
        published.push(
            state
                .publish_policy_draft(&administrator, policy_id, 1)
                .await
                .expect("publish bundle policy version"),
        );
    }

    assert_eq!(
        state.policy_bundle_for(&device).await,
        Err(dlp_server::routes::RouteError::NotFound),
        "publication alone must not deploy a policy"
    );

    state
        .assign_organization_policy(&administrator, &default_policy_id, 1)
        .await
        .expect("assign organization default");
    let default_bundle = state
        .policy_bundle_for(&device)
        .await
        .expect("select organization default");
    assert_eq!(default_bundle.schema_version(), 2);
    assert_eq!(default_bundle.policy_id(), default_policy_id);
    assert_eq!(default_bundle.policy_version(), 1);
    assert_eq!(
        default_bundle.policy_digest(),
        published[0].content_digest()
    );
    assert_eq!(
        default_bundle.agent_settings_json(),
        r#"{"preferred_drive_letter":"P"}"#
    );
    assert_eq!(default_bundle.effective_at_epoch_seconds(), 1_754_568_000);
    assert_eq!(default_bundle.offline_allowance_seconds(), 7 * 24 * 60 * 60);
    assert_eq!(default_bundle.device_audience(), device_id);
    assert_eq!(default_bundle.bundle_version(), 1);
    assert_eq!(default_bundle.signing_key_id(), "phase1-test-key");

    state
        .assign_organization_policy(&administrator, &default_policy_id, 1)
        .await
        .expect("repeat organization default idempotently");
    assert_eq!(
        state
            .policy_bundle_for(&device)
            .await
            .expect("reselect unchanged default")
            .bundle_version(),
        default_bundle.bundle_version(),
        "an identical desired policy must not advance the cursor"
    );

    let left_state = state.clone();
    let left_admin = administrator.clone();
    let left_device_id = device_id.clone();
    let left_policy_id = first_override_id.clone();
    let right_state = state.clone();
    let right_admin = administrator.clone();
    let right_device_id = device_id.clone();
    let right_policy_id = second_override_id.clone();
    let (left, right) = tokio::join!(
        async move {
            left_state
                .assign_device_policy(&left_admin, &left_device_id, &left_policy_id, 1)
                .await
        },
        async move {
            right_state
                .assign_device_policy(&right_admin, &right_device_id, &right_policy_id, 1)
                .await
        }
    );
    left.expect("serialize first concurrent override");
    right.expect("serialize second concurrent override");
    let override_bundle = state
        .policy_bundle_for(&device)
        .await
        .expect("select winning device override");
    assert!(
        [first_override_id.as_str(), second_override_id.as_str()]
            .contains(&override_bundle.policy_id()),
        "one complete concurrent assignment must win"
    );
    assert_eq!(
        override_bundle.bundle_version(),
        default_bundle.bundle_version() + 2,
        "each distinct serialized assignment advances the device cursor once"
    );
    let winning_policy_id = override_bundle.policy_id().to_owned();
    state
        .assign_device_policy(&administrator, &device_id, &winning_policy_id, 1)
        .await
        .expect("repeat winning override idempotently");
    assert_eq!(
        state
            .policy_bundle_for(&device)
            .await
            .expect("reselect unchanged override")
            .bundle_version(),
        override_bundle.bundle_version()
    );

    let desired_version = override_bundle.bundle_version();
    let initial_status = state
        .policy_distribution_status(&device)
        .await
        .expect("read initial distribution status");
    assert_eq!(initial_status.desired_bundle_version(), desired_version);
    assert_eq!(initial_status.issued_bundle_version(), None);
    assert_eq!(initial_status.activated_bundle_version(), None);
    assert_eq!(initial_status.last_error_code(), None);
    state
        .report_policy_deployment(
            &device,
            PolicyDeploymentUpdate::Issued {
                bundle_version: desired_version,
            },
        )
        .await
        .expect("report issued bundle");
    state
        .report_policy_deployment(
            &device,
            PolicyDeploymentUpdate::Error {
                bundle_version: desired_version,
                error_code: "apply_failed".to_owned(),
            },
        )
        .await
        .expect("report bounded deployment error");
    assert_eq!(
        state
            .policy_distribution_status(&device)
            .await
            .expect("read failed deployment status")
            .last_error_code(),
        Some("apply_failed")
    );
    state
        .report_policy_deployment(
            &device,
            PolicyDeploymentUpdate::Activated {
                bundle_version: desired_version,
            },
        )
        .await
        .expect("report activated bundle");
    assert_eq!(
        state
            .report_policy_deployment(
                &device,
                PolicyDeploymentUpdate::Issued {
                    bundle_version: desired_version - 1,
                },
            )
            .await,
        Err(dlp_server::routes::RouteError::Conflict),
        "deployment status cannot move backward"
    );
    let activated_status = state
        .policy_distribution_status(&device)
        .await
        .expect("read activated deployment status");
    assert_eq!(
        activated_status.issued_bundle_version(),
        Some(desired_version)
    );
    assert_eq!(
        activated_status.activated_bundle_version(),
        Some(desired_version)
    );
    assert_eq!(activated_status.last_error_code(), None);

    state
        .clear_device_policy(&administrator, &device_id)
        .await
        .expect("clear device override");
    let restored_default = state
        .policy_bundle_for(&device)
        .await
        .expect("fall back to organization default");
    assert_eq!(restored_default.policy_id(), default_policy_id);
    assert_eq!(
        restored_default.policy_digest(),
        published[0].content_digest()
    );
    assert_eq!(restored_default.bundle_version(), desired_version + 1);
}

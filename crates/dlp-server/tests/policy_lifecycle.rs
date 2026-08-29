use axum::{
    body::Body,
    extract::{ConnectInfo, Request},
};
use dlp_server::{
    repository::{
        BootstrapOutcome, PgRouteRepository, PrincipalRole, RouteRepositoryError,
        RouteRepositoryPort,
    },
    routes::{RouteState, api_v1_router},
    run_migrations,
    tls::{AdministratorPrincipalV1, AuthenticatedAdmin, PeerIdentity, TlsConnectionInfo},
};
use serde_json::json;
use sqlx::{Connection, PgConnection, PgPool, postgres::PgPoolOptions};
use std::sync::Arc;
use tower::ServiceExt;

const POLICY_TEST_LOCK: i64 = 0x0202_0001;

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
    sqlx::query("DELETE FROM policy_audit_events")
        .execute(&pool)
        .await
        .expect("reset policy audit events");
    sqlx::query("DELETE FROM published_policy_versions")
        .execute(&pool)
        .await
        .expect("reset published policies");
    sqlx::query("DELETE FROM policy_drafts")
        .execute(&pool)
        .await
        .expect("reset policy drafts");
    sqlx::query("DELETE FROM initial_admin_bootstrap")
        .execute(&pool)
        .await
        .expect("reset initial administrator bootstrap");
    sqlx::query("DELETE FROM administrator_principals")
        .execute(&pool)
        .await
        .expect("reset administrator principals");
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
    // Plan 02-02 Task 2 replaces this RED sentinel with the selected immutable
    // policy and monotonic distribution contract. Plan 02-04 then extends the
    // same top-level test with signed-byte assertions.
    panic!("Task 2 bundle contract is not implemented yet");
}

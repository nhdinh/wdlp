use std::fs;
use std::path::PathBuf;

fn repo_root() -> PathBuf {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.pop();
    path.pop();
    path
}

#[test]
fn compose_yaml_documents_native_postgresql_lab_deployment() {
    let compose_path = repo_root().join("deploy/compose.yaml");
    let content = fs::read_to_string(&compose_path).expect("compose.yaml must exist");
    assert!(
        content.contains("LAB-SERVER01"),
        "compose must document the native PostgreSQL host used by the lab"
    );
    assert!(
        content.contains("192.168.50.12"),
        "compose must document the native PostgreSQL IP"
    );
    assert!(
        content.contains("migrations service is intentionally omitted"),
        "compose must note that migrations are run directly against native PostgreSQL"
    );
}

#[test]
fn compose_yaml_secrets_are_not_hardcoded() {
    let compose_path = repo_root().join("deploy/compose.yaml");
    let content = fs::read_to_string(&compose_path).expect("compose.yaml must exist");
    assert!(
        content.contains("env_file:"),
        "sensitive env vars must be loaded from env_file"
    );
    // Ensure no literal secret values appear for common keys.
    for key in [
        "DATABASE_URL=",
        "DLP_AD_BIND_PASSWORD=",
        "DLP_SERVER_KEY_PEM=",
        "DLP_DEVICE_ISSUING_CA_KEY_PEM=",
        "DLP_CONFIGURATION_SIGNING_KEY_SEED_HEX=",
        "DLP_ADMIN_PROVISIONING_KEY=",
    ] {
        assert!(
            !content.contains(key),
            "compose must not hardcode {key}"
        );
    }
}

#[test]
fn migrations_are_ordered_and_forward_only() {
    let migrations_dir = repo_root().join("migrations");
    let mut entries: Vec<_> = fs::read_dir(&migrations_dir)
        .expect("migrations dir must exist")
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().map(|ext| ext == "sql").unwrap_or(false))
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    entries.sort();
    assert_eq!(
        entries,
        vec![
            "202608070001_walking_skeleton.sql",
            "202608070002_enrollment_authority.sql",
            "202608070003_authenticated_routes.sql",
        ],
        "migrations must be ordered forward-only"
    );
}

#[test]
fn migrations_do_not_seed_runtime_data() {
    for name in [
        "202608070001_walking_skeleton.sql",
        "202608070002_enrollment_authority.sql",
        "202608070003_authenticated_routes.sql",
    ] {
        let path = repo_root().join("migrations").join(name);
        let content = fs::read_to_string(&path).expect("migration must exist");
        assert!(
            !content.contains("INSERT INTO"),
            "migration {name} must not contain runtime seed rows"
        );
    }
}

#[test]
fn server_env_example_omits_secret_values() {
    let env_path = repo_root().join("config/server.env.example");
    let content = fs::read_to_string(&env_path).expect("server.env.example must exist");
    // Every line that names a secret key must end with '=' and no value.
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if trimmed.starts_with("DLP_") {
            let after_eq = trimmed.split_once('=').map(|(_, v)| v).unwrap_or("");
            assert!(
                after_eq.is_empty(),
                "{trimmed} must not contain a secret value in the example file"
            );
        }
    }
}

#[test]
fn lab_roles_example_has_five_machine_contract() {
    let path = repo_root().join("config/lab.roles.example.json");
    let content = fs::read_to_string(&path).expect("lab.roles.example.json must exist");
    assert!(content.contains("developer_orchestrator"));
    assert!(content.contains("database_server"));
    assert!(content.contains("primary_directory_server"));
    assert!(content.contains("secondary_ad_authority"));
    assert!(content.contains("endpoint_runtime"));
}

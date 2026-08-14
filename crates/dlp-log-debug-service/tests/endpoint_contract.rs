use std::{
    fs,
    io::{Read, Write},
    net::TcpStream,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

use dlp_log_debug_service::{
    AccessMode, AppState, AuthorizedFolders, DEFAULT_MAX_RESPONSE_BYTES, DEFAULT_MAX_TAIL_LINES,
    DEFAULT_PORT, authorize_canonical_target, authorize_requested_file, load_runtime_config,
    read_bounded_tail, serve_http,
};
use tokio::net::TcpListener;

fn percent_encode(value: &str) -> String {
    value
        .bytes()
        .flat_map(|byte| match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                format!("{}", char::from(byte)).bytes().collect::<Vec<_>>()
            }
            other => format!("%{other:02X}").bytes().collect::<Vec<_>>(),
        })
        .map(char::from)
        .collect()
}

fn unique_temp_dir() -> std::path::PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock should be after UNIX epoch")
        .as_nanos();
    std::env::temp_dir().join(format!("dlp-log-debug-service-{nanos}"))
}

fn request_log_tail(address: std::net::SocketAddr, path: &Path, tail: Option<&str>) -> String {
    let path = percent_encode(&path.display().to_string());
    let tail = tail
        .map(|value| format!("&tail={value}"))
        .unwrap_or_default();
    let mut stream = TcpStream::connect(address).expect("listener should accept TCP");
    stream
        .write_all(
            format!(
                "GET /logs?path={path}{tail} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
            )
            .as_bytes(),
        )
        .expect("request should be written");

    let mut response = String::new();
    stream
        .read_to_string(&mut response)
        .expect("response should be valid UTF-8 HTTP");
    response
}

#[tokio::test]
async fn tracer_serves_one_allowlisted_log_over_http() {
    let directory = unique_temp_dir();
    fs::create_dir_all(&directory).expect("test directory should be created");
    let log_path = directory.join("agent.log");
    fs::write(&log_path, "older\nselected-one\nselected-two\n").expect("log should be written");

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("ephemeral listener should bind");
    let address = listener
        .local_addr()
        .expect("listener should have an address");
    let server = tokio::spawn(serve_http(
        listener,
        AppState::loopback_for_test(directory.clone(), 1024),
    ));

    let response =
        tokio::task::spawn_blocking(move || request_log_tail(address, &log_path, Some("2")))
            .await
            .expect("request task should complete");
    server.abort();
    let _ = server.await;
    fs::remove_dir_all(directory).expect("test directory should be removed");

    let (headers, body) = response
        .split_once("\r\n\r\n")
        .expect("response should contain HTTP headers and a body");
    assert!(
        headers.starts_with("HTTP/1.1 200"),
        "unexpected response: {headers}"
    );
    assert_eq!(body, "selected-one\nselected-two\n");
    assert!(!body.contains('{'));
    assert!(!body.contains("truncated"));
}

#[test]
fn invalid_or_empty_config_falls_back_without_authorized_folders() {
    let directory = unique_temp_dir();
    fs::create_dir_all(&directory).expect("test directory should be created");
    let config_path = directory.join("config.json");

    let missing = load_runtime_config(&config_path);
    assert_eq!(missing.access_mode, AccessMode::LocalhostOnly);
    assert_eq!(missing.port, DEFAULT_PORT);
    assert_eq!(missing.max_response_bytes, DEFAULT_MAX_RESPONSE_BYTES);
    assert_eq!(missing.max_tail_lines, DEFAULT_MAX_TAIL_LINES);
    assert!(missing.authorized_folders.is_empty());

    fs::write(
        &config_path,
        r#"{"version":1,"trusted_client_ips":[],"allowed_folders":[],"port":9191,"max_response_bytes":1024,"max_tail_lines":10}"#,
    )
    .expect("config should be written");
    let empty_trust = load_runtime_config(&config_path);
    assert_eq!(empty_trust.access_mode, AccessMode::LocalhostOnly);
    assert!(empty_trust.authorized_folders.is_empty());
    fs::remove_dir_all(directory).expect("test directory should be removed");
}

#[test]
fn malformed_or_semantically_invalid_config_never_partially_activates() {
    let directory = unique_temp_dir();
    let allowed = directory.join("allowed");
    fs::create_dir_all(&allowed).expect("allowed directory should be created");
    let config_path = directory.join("config.json");
    let allowed = allowed.to_string_lossy().replace('\\', "\\\\");
    let cases = [
        "not json".to_owned(),
        format!(
            r#"{{"version":1,"trusted_client_ips":["192.0.2.10"],"allowed_folders":["{allowed}"],"port":9191,"max_response_bytes":1024,"max_tail_lines":1,"extra":true}}"#
        ),
        format!(
            r#"{{"version":2,"trusted_client_ips":["192.0.2.10"],"allowed_folders":["{allowed}"],"port":9191,"max_response_bytes":1024,"max_tail_lines":1}}"#
        ),
        format!(
            r#"{{"version":1,"trusted_client_ips":["not-an-ip"],"allowed_folders":["{allowed}"],"port":9191,"max_response_bytes":1024,"max_tail_lines":1}}"#
        ),
        format!(
            r#"{{"version":1,"trusted_client_ips":["192.0.2.10"],"allowed_folders":["{allowed}"],"port":0,"max_response_bytes":1024,"max_tail_lines":1}}"#
        ),
        format!(
            r#"{{"version":1,"trusted_client_ips":["192.0.2.10"],"allowed_folders":["{allowed}"],"port":9191,"max_response_bytes":0,"max_tail_lines":1}}"#
        ),
        format!(
            r#"{{"version":1,"trusted_client_ips":["192.0.2.10"],"allowed_folders":["{allowed}"],"port":9191,"max_response_bytes":1024,"max_tail_lines":0}}"#
        ),
    ];

    for case in cases {
        fs::write(&config_path, case).expect("config should be written");
        let config = load_runtime_config(&config_path);
        assert_eq!(config.access_mode, AccessMode::LocalhostOnly);
        assert_eq!(config.port, DEFAULT_PORT);
        assert_eq!(config.max_response_bytes, DEFAULT_MAX_RESPONSE_BYTES);
        assert_eq!(config.max_tail_lines, DEFAULT_MAX_TAIL_LINES);
        assert!(config.authorized_folders.is_empty());
    }
    fs::remove_dir_all(directory).expect("test directory should be removed");
}

#[test]
fn valid_config_activates_allowlist_and_configured_tail_limit() {
    let directory = unique_temp_dir();
    fs::create_dir_all(&directory).expect("test directory should be created");
    let config_path = directory.join("config.json");
    let allowed = directory.join("allowed");
    fs::create_dir_all(&allowed).expect("allowed directory should be created");
    let allowed = allowed.to_string_lossy().replace('\\', "\\\\");
    fs::write(
        &config_path,
        format!(
            r#"{{"version":1,"trusted_client_ips":["192.0.2.10"],"allowed_folders":["{allowed}"],"port":9192,"max_response_bytes":1024,"max_tail_lines":3}}"#
        ),
    )
    .expect("config should be written");

    let config = load_runtime_config(&config_path);
    assert_eq!(
        config.access_mode,
        AccessMode::RemoteAllowlist(vec!["192.0.2.10".parse().unwrap()])
    );
    assert_eq!(config.port, 9192);
    assert_eq!(config.max_response_bytes, 1024);
    assert_eq!(config.max_tail_lines, 3);
    assert_eq!(config.authorized_folders.len(), 1);
    fs::remove_dir_all(directory).expect("test directory should be removed");
}

#[test]
fn direct_child_authorization_requires_exact_canonical_parent() {
    let directory = unique_temp_dir();
    let allowed = directory.join("allowed");
    let nested = allowed.join("nested");
    let sibling = directory.join("allowed-other");
    fs::create_dir_all(&nested).expect("nested directory should be created");
    fs::create_dir_all(&sibling).expect("sibling directory should be created");
    let direct_file = allowed.join("direct.log");
    let nested_file = nested.join("nested.log");
    let sibling_file = sibling.join("sibling.log");
    fs::write(&direct_file, "direct\n").expect("direct file should be written");
    fs::write(&nested_file, "nested\n").expect("nested file should be written");
    fs::write(&sibling_file, "sibling\n").expect("sibling file should be written");

    let folders = AuthorizedFolders::from_configured_dirs([allowed.clone()])
        .expect("folders should authorize");
    assert_eq!(
        authorize_requested_file(&direct_file, &folders).unwrap(),
        fs::canonicalize(&direct_file).unwrap()
    );
    assert!(authorize_requested_file(&nested_file, &folders).is_err());
    assert!(authorize_requested_file(&sibling_file, &folders).is_err());
    assert!(
        authorize_requested_file(
            &allowed.join("..").join("allowed-other").join("sibling.log"),
            &folders
        )
        .is_err()
    );
    assert!(authorize_requested_file(Path::new("relative.log"), &folders).is_err());
    assert!(authorize_requested_file(&allowed, &folders).is_err());

    let escaped_target = fs::canonicalize(&sibling_file).expect("target should canonicalize");
    assert!(authorize_canonical_target(&escaped_target, &folders).is_err());
    fs::remove_dir_all(directory).expect("test directory should be removed");
}

#[test]
fn bounded_tail_keeps_only_complete_lines_within_byte_cap() {
    let directory = unique_temp_dir();
    fs::create_dir_all(&directory).expect("test directory should be created");
    let log_path = directory.join("agent.log");
    fs::write(&log_path, "first\r\nsecond\r\nthird\r\nunterminated")
        .expect("log should be written");

    assert_eq!(read_bounded_tail(&log_path, 10, 19).unwrap(), "third\r\n");
    assert_eq!(read_bounded_tail(&log_path, 1, 19).unwrap(), "third\r\n");
    fs::write(&log_path, "this-line-is-larger-than-the-cap\n")
        .expect("large line should be written");
    assert_eq!(read_bounded_tail(&log_path, 10, 8).unwrap(), "");
    fs::write(&log_path, [0xff, b'\n']).expect("invalid text should be written");
    assert_eq!(
        read_bounded_tail(&log_path, 1, 8),
        Err(dlp_log_debug_service::TailReadError::InvalidText)
    );
    fs::remove_dir_all(directory).expect("test directory should be removed");
}

#[tokio::test]
async fn omitted_tail_uses_configured_max_and_oversized_tail_is_rejected() {
    let directory = unique_temp_dir();
    fs::create_dir_all(&directory).expect("test directory should be created");
    let log_path = directory.join("agent.log");
    fs::write(&log_path, "one\ntwo\nthree\n").expect("log should be written");
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("listener should bind");
    let address = listener
        .local_addr()
        .expect("listener should have an address");
    let server = tokio::spawn(serve_http(
        listener,
        AppState::loopback_for_test_with_tail_limit(directory.clone(), 1024, 2),
    ));

    let default_response = tokio::task::spawn_blocking({
        let log_path = log_path.clone();
        move || request_log_tail(address, &log_path, None)
    })
    .await
    .expect("request task should complete");
    let oversized_response =
        tokio::task::spawn_blocking(move || request_log_tail(address, &log_path, Some("3")))
            .await
            .expect("request task should complete");
    server.abort();
    let _ = server.await;
    fs::remove_dir_all(directory).expect("test directory should be removed");

    assert!(default_response.starts_with("HTTP/1.1 200"));
    assert!(default_response.ends_with("two\nthree\n"));
    assert!(oversized_response.starts_with("HTTP/1.1 400"));
    assert!(oversized_response.ends_with("invalid_tail"));
}

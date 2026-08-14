use std::{
    fs,
    io::{Read, Write},
    net::TcpStream,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

use dlp_log_debug_service::{AppState, serve_http};
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

fn request_log_tail(address: std::net::SocketAddr, path: &Path) -> String {
    let path = percent_encode(&path.display().to_string());
    let mut stream = TcpStream::connect(address).expect("listener should accept TCP");
    stream
        .write_all(
            format!(
                "GET /logs?path={path}&tail=2 HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
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

    let response = tokio::task::spawn_blocking(move || request_log_tail(address, &log_path))
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

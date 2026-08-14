use std::{
    fs,
    time::{SystemTime, UNIX_EPOCH},
};

use dlp_log_debug_service::{
    AppState, ServiceError, service_exit_code, serve_http,
};
use tokio::{net::TcpListener, sync::oneshot};

fn unique_temp_dir() -> std::path::PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock should be after UNIX epoch")
        .as_nanos();
    std::env::temp_dir().join(format!("dlp-log-debug-service-lifecycle-{nanos}"))
}

#[test]
fn service_error_contract_is_portable_and_stable() {
    let cases = [
        (ServiceError::ListenerBindFailed, "listener_bind_failed"),
        (ServiceError::ServeFailed, "serve_failed"),
        (ServiceError::RuntimeFailed, "runtime_failed"),
    ];

    for (error, code) in cases {
        assert_eq!(error.stable_code(), code);
        assert_ne!(service_exit_code(&error), 0);
    }
}

#[tokio::test]
async fn graceful_shutdown_owns_prebound_listener() {
    let directory = unique_temp_dir();
    fs::create_dir_all(&directory).expect("test directory should be created");
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("test listener should bind");
    let address = listener.local_addr().expect("listener should have an address");
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let server = tokio::spawn(serve_http(
        listener,
        AppState::loopback_for_test(directory.clone(), 1024),
        async move {
            let _ = shutdown_rx.await;
        },
    ));

    assert!(TcpListener::bind(address).await.is_err());
    shutdown_tx.send(()).expect("server should still own the listener");
    assert_eq!(server.await.expect("server task should complete"), Ok(()));
    let released = TcpListener::bind(address)
        .await
        .expect("listener should release after graceful shutdown");
    drop(released);
    fs::remove_dir_all(directory).expect("test directory should be removed");
}

#[cfg(windows)]
use std::{net::SocketAddr, path::Path, time::Duration};

#[cfg(windows)]
use dlp_log_debug_service::{
    AppState, DEFAULT_CONFIG_PATH, ServiceError, load_runtime_config, serve_http, service_exit_code,
};

pub const SERVICE_NAME: &str = "DlpLogDebugService";

/// Records a lifecycle code without formatting peer, path, content, configuration, or OS details.
pub fn service_log(code: &str) {
    #[cfg(windows)]
    {
        use std::{fs::OpenOptions, io::Write};

        const SERVICE_LOG_PATH: &str = r"C:\ProgramData\DlpLogDebugService\service.log";
        if let Some(parent) = Path::new(SERVICE_LOG_PATH).parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let _ = OpenOptions::new()
            .create(true)
            .append(true)
            .open(SERVICE_LOG_PATH)
            .and_then(|mut file| writeln!(file, "{code}"));
    }

    #[cfg(not(windows))]
    let _ = code;
}

#[cfg(windows)]
windows_service::define_windows_service!(ffi_service_main, service_main);

#[cfg(windows)]
pub fn run_scm_service() -> Result<(), windows_service::Error> {
    windows_service::service_dispatcher::start(SERVICE_NAME, ffi_service_main)
}

#[cfg(windows)]
fn service_main(_: Vec<std::ffi::OsString>) {
    use windows_service::{
        service::{
            ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
            ServiceType,
        },
        service_control_handler::{self, ServiceControlHandlerResult},
    };

    fn status(state: ServiceState, exit_code: ServiceExitCode) -> ServiceStatus {
        ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: state,
            controls_accepted: ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
            exit_code,
            checkpoint: 0,
            wait_hint: Duration::from_secs(60),
            process_id: None,
        }
    }

    let (shutdown_tx, mut shutdown_rx) = tokio::sync::watch::channel(false);
    let handler =
        match service_control_handler::register(SERVICE_NAME, move |control| match control {
            ServiceControl::Stop | ServiceControl::Shutdown => {
                let _ = shutdown_tx.send(true);
                ServiceControlHandlerResult::NoError
            }
            _ => ServiceControlHandlerResult::NotImplemented,
        }) {
            Ok(handler) => handler,
            Err(_) => {
                service_log("runtime_failed");
                return;
            }
        };

    let _ = handler.set_service_status(status(
        ServiceState::StartPending,
        ServiceExitCode::Win32(0),
    ));
    let runtime = match tokio::runtime::Runtime::new() {
        Ok(runtime) => runtime,
        Err(_) => {
            stop_with_error(&handler, ServiceError::RuntimeFailed);
            return;
        }
    };

    let config = load_runtime_config(Path::new(DEFAULT_CONFIG_PATH));
    let state = AppState::from_runtime_config(config.clone());
    let listener = match runtime.block_on(tokio::net::TcpListener::bind(SocketAddr::from((
        [0, 0, 0, 0],
        config.port,
    )))) {
        Ok(listener) => listener,
        Err(_) => {
            stop_with_error(&handler, ServiceError::ListenerBindFailed);
            runtime.shutdown_timeout(Duration::from_secs(10));
            return;
        }
    };

    let _ = handler.set_service_status(status(ServiceState::Running, ServiceExitCode::Win32(0)));
    let result = runtime.block_on(serve_http(listener, state, async move {
        if !*shutdown_rx.borrow() {
            let _ = shutdown_rx.changed().await;
        }
    }));
    match result {
        Ok(()) => {
            service_log("stopped");
            let _ = handler
                .set_service_status(status(ServiceState::Stopped, ServiceExitCode::Win32(0)));
        }
        Err(error) => stop_with_error(&handler, error),
    }
    runtime.shutdown_timeout(Duration::from_secs(10));
}

#[cfg(windows)]
fn stop_with_error(
    handler: &windows_service::service_control_handler::ServiceStatusHandle,
    error: ServiceError,
) {
    use windows_service::service::{ServiceExitCode, ServiceState, ServiceStatus, ServiceType};

    service_log(error.stable_code());
    let _ = handler.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Stopped,
        controls_accepted: windows_service::service::ServiceControlAccept::empty(),
        exit_code: ServiceExitCode::ServiceSpecific(service_exit_code(&error)),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    });
}

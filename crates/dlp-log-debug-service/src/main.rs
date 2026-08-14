#[cfg(windows)]
windows_service::define_windows_service!(ffi_service_main, scm_service_main);

#[cfg(windows)]
fn scm_service_main(_: Vec<std::ffi::OsString>) {
    let _ = dlp_log_debug_service::run_windows_dispatcher();
}

#[cfg(windows)]
fn main() {
    if windows_service::service_dispatcher::start("DlpLogDebugService", ffi_service_main).is_err() {
        eprintln!("service_dispatcher_failed");
    }
}

#[cfg(not(windows))]
fn main() -> std::process::ExitCode {
    eprintln!("windows_only");
    std::process::ExitCode::FAILURE
}

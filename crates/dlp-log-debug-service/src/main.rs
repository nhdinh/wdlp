#[cfg(windows)]
mod service;

#[cfg(windows)]
fn main() {
    if service::run_scm_service().is_err() {
        eprintln!("service_dispatcher_failed");
    }
}

#[cfg(not(windows))]
fn main() -> std::process::ExitCode {
    eprintln!("windows_only");
    std::process::ExitCode::FAILURE
}

//! Windows Service Control Manager entry boundary.
//!
//! Later Win32/SCM integration belongs only in this crate. Any unavoidable
//! unsafe block must document its pointer, lifetime, and ownership invariant
//! locally; portable crates must never receive a raw Windows type.

/// The narrow composition seam implemented by future SCM adapters.
pub trait ServiceEntrypoint {
    fn run(&self) -> Result<(), ServiceEntrypointError>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServiceEntrypointError {
    DispatcherUnavailable,
}

impl std::fmt::Display for ServiceEntrypointError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "Windows service dispatcher is unavailable")
    }
}

impl std::error::Error for ServiceEntrypointError {}

#[cfg(windows)]
fn declare_scm_dependency() {
    let _ = std::any::TypeId::of::<windows_service::service::ServiceControl>();
}

#[cfg(windows)]
fn install_ring_provider() {
    if rustls::crypto::ring::default_provider()
        .install_default()
        .is_ok()
    {
        dlp_windows_service::service::service_log("INFO", "ring crypto provider installed");
    } else {
        dlp_windows_service::service::service_log(
            "WARN",
            "ring crypto provider installation failed or already installed",
        );
    }
}

fn main() -> std::process::ExitCode {
    #[cfg(windows)]
    {
        dlp_windows_service::service::service_log("INFO", "service process starting");
        declare_scm_dependency();
        install_ring_provider();
        dlp_windows_service::service::service_log("INFO", "entering service dispatcher");
        if let Err(error) = dlp_windows_service::service::run_scm_service() {
            dlp_windows_service::service::service_log(
                "ERROR",
                format!("service dispatcher failed: {error}"),
            );
            eprintln!("service_dispatcher_failed: {error}");
            return std::process::ExitCode::FAILURE;
        } else {
            dlp_windows_service::service::service_log("INFO", "service dispatcher exited cleanly");
        }
    }

    std::process::ExitCode::SUCCESS
}

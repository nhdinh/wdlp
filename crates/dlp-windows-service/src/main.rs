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

fn main() {
    #[cfg(windows)]
    declare_scm_dependency();
}

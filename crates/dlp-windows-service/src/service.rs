//! SCM composition seam. Startup remains noninteractive and fails closed when
//! credential custody or enrollment is unavailable.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServiceState {
    Starting,
    Running,
    ReplacementEnrollmentRequired,
    Failed,
}

pub fn startup_state(has_usable_credential: bool) -> ServiceState {
    if has_usable_credential {
        ServiceState::Running
    } else {
        ServiceState::ReplacementEnrollmentRequired
    }
}

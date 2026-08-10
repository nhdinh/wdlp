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

#[cfg(windows)]
pub fn run_scm_service() -> Result<(), windows_service::Error> {
    use std::sync::mpsc;
    use windows_service::{
        define_windows_service,
        service::{
            ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState as ScmState,
            ServiceStatus, ServiceType,
        },
        service_control_handler::{self, ServiceControlHandlerResult},
        service_dispatcher,
    };
    define_windows_service!(ffi_service_main, service_main);
    fn service_main(_arguments: Vec<std::ffi::OsString>) {
        let (sender, receiver) = mpsc::channel();
        let handler =
            service_control_handler::register("DlpWindowsService", move |control| match control {
                ServiceControl::Stop | ServiceControl::Shutdown => {
                    let _ = sender.send(());
                    ServiceControlHandlerResult::NoError
                }
                _ => ServiceControlHandlerResult::NotImplemented,
            })
            .expect("register service control handler");
        let status = |state| ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: state,
            controls_accepted: ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: std::time::Duration::default(),
            process_id: None,
        };
        let _ = handler.set_service_status(status(ScmState::Running));
        let _ = receiver.recv();
        let _ = handler.set_service_status(status(ScmState::Stopped));
    }
    service_dispatcher::start("DlpWindowsService", ffi_service_main)
}

use dlp_windows_drive::{DlpFileSystemContext, WinFspMountHost};

#[test]
fn sid_bound_context_and_host_are_available_for_the_real_runtime_smoke() {
    let _context = std::any::TypeId::of::<DlpFileSystemContext>();
    let _host = std::any::TypeId::of::<WinFspMountHost>();
}

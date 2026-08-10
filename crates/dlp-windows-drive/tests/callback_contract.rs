use dlp_storage::StorageError;
use dlp_windows_drive::status::{to_ntstatus, STATUS_DISK_FULL, STATUS_NOT_SUPPORTED};

#[test]
fn storage_failures_and_explicitly_unsupported_windows_features_have_stable_statuses() {
    assert_eq!(to_ntstatus(&StorageError::NoSpace), STATUS_DISK_FULL);
    assert_eq!(STATUS_NOT_SUPPORTED, 0xC000_0010u32 as i32);
}

#[test]
fn callback_adapter_declares_every_phase_one_operation_or_explicit_opt_out() {
    let source = include_str!("../src/filesystem.rs");
    for callback in [
        "fn cleanup", "fn close", "fn flush", "fn get_file_info", "fn set_basic_info",
        "fn set_file_size", "fn rename", "fn set_delete", "fn read_directory",
        "fn get_stream_info", "fn get_reparse_point", "fn get_extended_attributes",
    ] {
        assert!(source.contains(callback), "missing callback contract: {callback}");
    }
}

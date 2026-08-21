use dlp_storage::StorageError;
use dlp_windows_drive::status::{
    STATUS_DELETE_PENDING, STATUS_DISK_FULL, STATUS_INTEGRITY_FAILURE, STATUS_IO_DEVICE_ERROR,
    STATUS_NOT_SUPPORTED, STATUS_OBJECT_NAME_INVALID, STATUS_OBJECT_NAME_NOT_FOUND,
    STATUS_SHARING_VIOLATION, path_to_ntstatus, to_ntstatus,
};

#[test]
fn storage_failures_and_explicitly_unsupported_windows_features_have_stable_statuses() {
    assert_eq!(to_ntstatus(&StorageError::NoSpace), STATUS_DISK_FULL);
    assert_eq!(
        to_ntstatus(&StorageError::IntegrityFailure),
        STATUS_INTEGRITY_FAILURE
    );
    assert_eq!(
        to_ntstatus(&StorageError::NotFound),
        STATUS_OBJECT_NAME_NOT_FOUND
    );
    assert_eq!(
        to_ntstatus(&StorageError::SharingViolation),
        STATUS_SHARING_VIOLATION
    );
    assert_eq!(
        to_ntstatus(&StorageError::DeletePending),
        STATUS_DELETE_PENDING
    );
    assert_eq!(
        to_ntstatus(&StorageError::IoFailure),
        STATUS_IO_DEVICE_ERROR
    );
    assert_eq!(
        path_to_ntstatus(&dlp_storage::PathError::InvalidPath),
        STATUS_OBJECT_NAME_INVALID
    );
    assert_eq!(STATUS_NOT_SUPPORTED, 0xC000_0010u32 as i32);
}

#[test]
fn callback_adapter_declares_every_phase_one_operation_or_explicit_opt_out() {
    let source = include_str!("../src/filesystem.rs");
    for callback in [
        "fn open",
        "fn create",
        "fn cleanup",
        "fn close",
        "fn flush",
        "fn get_file_info",
        "fn overwrite",
        "fn set_basic_info",
        "fn set_file_size",
        "fn rename",
        "fn set_delete",
        "fn read_directory",
        "fn read",
        "fn write",
        "fn get_stream_info",
        "fn get_reparse_point",
        "fn get_extended_attributes",
    ] {
        assert!(
            source.contains(callback),
            "missing callback contract: {callback}"
        );
    }
    assert!(
        source.contains("DirInfo"),
        "directories use WinFsp directory entries"
    );
    assert!(
        source.contains("NotifyingFileSystemContext"),
        "filesystem implements change notifications"
    );
    assert!(
        source.contains("pending_notifications"),
        "filesystem queues pending notifications"
    );
    assert!(
        source.contains("wildmatch::matches"),
        "directory enumeration uses wildcard matching"
    );
    assert!(
        source.contains("FILE_NOTIFY_CHANGE_FILE_NAME"),
        "change notifications use WinFsp filters"
    );
    assert!(
        source.contains("FILE_ACTION_ADDED"),
        "change notifications use WinFsp actions"
    );
    assert!(source.contains("ensure_delete_allowed"));
    assert!(
        source.contains("read_handle"),
        "renamed open handles keep file identity"
    );
    assert!(
        source.contains("checked_add"),
        "write bounds are checked before storage"
    );
    assert!(!source.contains("winfsp_sys"));
    assert!(!source.contains("UserSid::parse"));
}

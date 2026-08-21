//! Stable, redacted translations between storage failures and WinFsp status values.

use dlp_storage::{PathError, StorageError};

/// `STATUS_DATA_ERROR`: encrypted bytes could not be authenticated.
pub const STATUS_INTEGRITY_FAILURE: i32 = 0xC000_003Eu32 as i32;
pub const STATUS_DISK_FULL: i32 = 0xC000_007Fu32 as i32;
pub const STATUS_OBJECT_NAME_INVALID: i32 = 0xC000_0033u32 as i32;
pub const STATUS_OBJECT_NAME_NOT_FOUND: i32 = 0xC000_0034u32 as i32;
pub const STATUS_OBJECT_NAME_COLLISION: i32 = 0xC000_0035u32 as i32;
pub const STATUS_SHARING_VIOLATION: i32 = 0xC000_0043u32 as i32;
pub const STATUS_DELETE_PENDING: i32 = 0xC000_0056u32 as i32;
pub const STATUS_IO_DEVICE_ERROR: i32 = 0xC000_0185u32 as i32;
/// Explicit Phase 1 opt-out for ADS, reparse points, and extended attributes.
pub const STATUS_NOT_SUPPORTED: i32 = 0xC000_0010u32 as i32;

/// WinFsp change-notification filters (Windows FILE_NOTIFY_CHANGE_* constants).
pub const FILE_NOTIFY_CHANGE_FILE_NAME: u32 = 0x0000_0001;
pub const FILE_NOTIFY_CHANGE_DIR_NAME: u32 = 0x0000_0002;
pub const FILE_NOTIFY_CHANGE_ATTRIBUTES: u32 = 0x0000_0004;
pub const FILE_NOTIFY_CHANGE_SIZE: u32 = 0x0000_0008;
pub const FILE_NOTIFY_CHANGE_LAST_WRITE: u32 = 0x0000_0010;
pub const FILE_NOTIFY_CHANGE_LAST_ACCESS: u32 = 0x0000_0020;
pub const FILE_NOTIFY_CHANGE_CREATION: u32 = 0x0000_0040;
pub const FILE_NOTIFY_CHANGE_EA: u32 = 0x0000_0080;
pub const FILE_NOTIFY_CHANGE_SECURITY: u32 = 0x0000_0100;
pub const FILE_NOTIFY_CHANGE_STREAM_NAME: u32 = 0x0000_0200;
pub const FILE_NOTIFY_CHANGE_STREAM_SIZE: u32 = 0x0000_0400;
pub const FILE_NOTIFY_CHANGE_STREAM_WRITE: u32 = 0x0000_0800;

/// WinFsp change-notification actions (Windows FILE_ACTION_* constants).
pub const FILE_ACTION_ADDED: u32 = 0x0000_0001;
pub const FILE_ACTION_REMOVED: u32 = 0x0000_0002;
pub const FILE_ACTION_MODIFIED: u32 = 0x0000_0003;
pub const FILE_ACTION_RENAMED_OLD_NAME: u32 = 0x0000_0004;
pub const FILE_ACTION_RENAMED_NEW_NAME: u32 = 0x0000_0005;

/// Maps portable errors without exposing a store path, SID, key, or buffer.
pub fn to_ntstatus(error: &StorageError) -> i32 {
    match error {
        StorageError::IntegrityFailure | StorageError::RecoveryRequired => STATUS_INTEGRITY_FAILURE,
        StorageError::NoSpace => STATUS_DISK_FULL,
        StorageError::NotFound => STATUS_OBJECT_NAME_NOT_FOUND,
        StorageError::AlreadyExists => STATUS_OBJECT_NAME_COLLISION,
        StorageError::SharingViolation => STATUS_SHARING_VIOLATION,
        StorageError::DeletePending => STATUS_DELETE_PENDING,
        StorageError::FlushNotDurable
        | StorageError::CloseNotDurable
        | StorageError::Unavailable
        | StorageError::IoFailure => STATUS_IO_DEVICE_ERROR,
    }
}

pub const fn path_to_ntstatus(_: &PathError) -> i32 {
    STATUS_OBJECT_NAME_INVALID
}

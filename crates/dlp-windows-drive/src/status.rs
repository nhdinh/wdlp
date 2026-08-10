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

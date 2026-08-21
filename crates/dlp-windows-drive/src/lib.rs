//! Replaceable Windows filesystem-host boundary.
//!
//! Future WinFsp and Win32 FFI belongs only in this crate. Each unavoidable
//! unsafe block must state local pointer, lifetime, and ownership invariants;
//! no raw operating-system type may cross into portable crates.

use dlp_storage::{CapturedStoreIdentity, ProtectedFileSystem, StorageError};
use std::fmt;

mod filesystem;
mod host;
pub mod status;
mod wildmatch;

pub use filesystem::DlpFileSystemContext;
pub use host::{WinFspMountHost, WinFspMountedVolume};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MountError {
    HostUnavailable,
    HostStatus(i32),
    StorageUnavailable,
}

impl From<StorageError> for MountError {
    fn from(_: StorageError) -> Self {
        Self::StorageUnavailable
    }
}

impl fmt::Display for MountError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::HostUnavailable => "Windows mount host is unavailable",
            Self::HostStatus(_) => "Windows mount host returned a stable status",
            Self::StorageUnavailable => "protected storage is unavailable",
        };
        write!(formatter, "{message}")
    }
}

impl std::error::Error for MountError {}

/// A mounted-volume lifecycle without exposing a Win32 or WinFsp handle.
pub trait MountedVolume {
    fn store_identity(&self) -> &CapturedStoreIdentity;
    fn unmount(self) -> Result<(), MountError>
    where
        Self: Sized;
}

/// Adapts the portable protected filesystem to a future Windows mount host.
pub trait MountHost {
    type Volume: MountedVolume;

    fn mount(
        &mut self,
        store: CapturedStoreIdentity,
        filesystem: &mut dyn ProtectedFileSystem,
    ) -> Result<Self::Volume, MountError>;
}

#[cfg(test)]
mod tests {
    use super::{MountError, MountHost, MountedVolume};
    use dlp_domain::{FileId, StoreId, UserSid};
    use dlp_storage::{
        CapturedStoreIdentity, ProtectedFileSystem, StorageError, StoreFileIdentity,
    };

    struct NoopVolume(CapturedStoreIdentity);

    impl MountedVolume for NoopVolume {
        fn store_identity(&self) -> &CapturedStoreIdentity {
            &self.0
        }

        fn unmount(self) -> Result<(), MountError> {
            Ok(())
        }
    }

    struct NoopHost;

    impl MountHost for NoopHost {
        type Volume = NoopVolume;

        fn mount(
            &mut self,
            store: CapturedStoreIdentity,
            _filesystem: &mut dyn ProtectedFileSystem,
        ) -> Result<Self::Volume, MountError> {
            Ok(NoopVolume(store))
        }
    }

    struct NoopFileSystem;

    impl ProtectedFileSystem for NoopFileSystem {
        fn flush_handle(&mut self, _file: &StoreFileIdentity) -> Result<(), StorageError> {
            Ok(())
        }

        fn close_handle(&mut self, _file: &StoreFileIdentity) -> Result<(), StorageError> {
            Ok(())
        }
    }

    #[test]
    fn mount_boundary_uses_captured_store_identity_only() {
        let store = CapturedStoreIdentity::new(
            UserSid::parse("S-1-5-21").expect("valid SID"),
            StoreId::parse("store-01").expect("valid store"),
        );
        let _file = FileId::parse("file-01").expect("valid file");
        let mut host = NoopHost;
        let mut filesystem = NoopFileSystem;
        let volume = host.mount(store, &mut filesystem).expect("mount boundary");
        volume.unmount().expect("unmount boundary");
    }
}

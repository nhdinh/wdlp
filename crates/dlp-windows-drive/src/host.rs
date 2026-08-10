//! Owned, user-session WinFsp host lifecycle.

use crate::{DlpFileSystemContext, MountError, MountedVolume};
use dlp_storage::CapturedStoreIdentity;
use std::path::PathBuf;
use winfsp::{
    host::{FileSystemHost, VolumeParams},
    winfsp_init,
};

/// A configured host for exactly one user-session drive letter or mount point.
pub struct WinFspMountHost {
    mount_point: PathBuf,
}

impl WinFspMountHost {
    pub fn new(mount_point: impl Into<PathBuf>) -> Result<Self, MountError> {
        let mount_point = mount_point.into();
        if mount_point.as_os_str().is_empty() {
            return Err(MountError::HostUnavailable);
        }
        Ok(Self { mount_point })
    }

    /// Creates, starts, and mounts the WinFsp host in the caller's Windows logon session.
    pub fn start(self, context: DlpFileSystemContext) -> Result<WinFspMountedVolume, MountError> {
        winfsp_init().map_err(|error| MountError::HostStatus(error.to_ntstatus()))?;
        let identity = context.store_identity().clone();
        let mut params = VolumeParams::default();
        params
            .filesystem_name("DLPDrive")
            .case_sensitive_search(false)
            .case_preserved_names(true)
            .unicode_on_disk(true)
            .reparse_points(false)
            .named_streams(false)
            .extended_attributes(false);
        let mut host: FileSystemHost<DlpFileSystemContext> =
            FileSystemHost::new(params, context).map_err(|_| MountError::HostUnavailable)?;
        host.start().map_err(|_| MountError::HostUnavailable)?;
        host.mount(self.mount_point)
            .map_err(|_| MountError::HostUnavailable)?;
        Ok(WinFspMountedVolume { identity, host })
    }
}

/// Owns the mounted host; dropping or explicitly unmounting removes the drive.
pub struct WinFspMountedVolume {
    identity: CapturedStoreIdentity,
    host: FileSystemHost<DlpFileSystemContext>,
}

impl MountedVolume for WinFspMountedVolume {
    fn store_identity(&self) -> &CapturedStoreIdentity {
        &self.identity
    }

    fn unmount(mut self) -> Result<(), MountError> {
        self.host.unmount();
        self.host.stop();
        Ok(())
    }
}

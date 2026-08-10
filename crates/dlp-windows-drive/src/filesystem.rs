//! SID-bound WinFsp callbacks over the portable encrypted store.

use crate::status::{path_to_ntstatus, to_ntstatus};
use dlp_storage::{
    CapturedStoreIdentity, FileHandle, LocalEncryptedStore, StorageError, VirtualPath,
};
use std::{ffi::c_void, sync::Mutex};
use winfsp::{
    FspError, Result, U16CStr,
    filesystem::{FileInfo, FileSecurity, FileSystemContext, OpenFileInfo, VolumeInfo},
};

/// A handle cannot replace the mount's captured identity; it only refers to a parsed virtual path.
#[derive(Clone)]
pub struct DlpFileHandle {
    path: Option<VirtualPath>,
    handle: Option<FileHandle>,
}

/// The callback context owns exactly one authenticated SID/store pair and encrypted store.
///
/// WinFsp invokes callbacks through shared references, so per-store state is protected by a
/// mutex. Independent file concurrency is supplied by WinFsp's fine operation guard; this
/// context never accepts a caller-provided SID, store identifier, or host path.
pub struct DlpFileSystemContext {
    identity: CapturedStoreIdentity,
    store: Mutex<LocalEncryptedStore>,
}

impl DlpFileSystemContext {
    pub fn new(identity: CapturedStoreIdentity, store: LocalEncryptedStore) -> Result<Self> {
        if store.identity() != &identity {
            return Err(FspError::NTSTATUS(
                crate::status::STATUS_OBJECT_NAME_INVALID,
            ));
        }
        Ok(Self {
            identity,
            store: Mutex::new(store),
        })
    }

    pub fn store_identity(&self) -> &CapturedStoreIdentity {
        &self.identity
    }

    fn storage_error(error: StorageError) -> FspError {
        FspError::NTSTATUS(to_ntstatus(&error))
    }

    fn virtual_path(file_name: &U16CStr) -> Result<Option<VirtualPath>> {
        let name = file_name.to_string_lossy();
        let normalized = name.trim_start_matches(['\\', '/']);
        if normalized.is_empty() {
            return Ok(None);
        }
        VirtualPath::parse(normalized)
            .map(Some)
            .map_err(|error| FspError::NTSTATUS(path_to_ntstatus(&error)))
    }

    fn file_info_for(&self, path: &VirtualPath, info: &mut FileInfo) -> Result<()> {
        let store = self
            .store
            .lock()
            .map_err(|_| FspError::NTSTATUS(crate::status::STATUS_IO_DEVICE_ERROR))?;
        let bytes = store.read_path(path).map_err(Self::storage_error)?;
        info.file_size = bytes.len() as u64;
        info.allocation_size = info.file_size;
        Ok(())
    }
}

impl FileSystemContext for DlpFileSystemContext {
    type FileContext = DlpFileHandle;

    fn get_security_by_name(
        &self,
        file_name: &U16CStr,
        _security_descriptor: Option<&mut [c_void]>,
        _reparse_point_resolver: impl FnOnce(&U16CStr) -> Option<FileSecurity>,
    ) -> Result<FileSecurity> {
        let attributes = if Self::virtual_path(file_name)?.is_none() {
            0x10
        } else {
            0x80
        };
        Ok(FileSecurity {
            reparse: false,
            sz_security_descriptor: 0,
            attributes,
        })
    }

    fn open(
        &self,
        file_name: &U16CStr,
        _create_options: u32,
        _granted_access: u32,
        file_info: &mut OpenFileInfo,
    ) -> Result<Self::FileContext> {
        let path = Self::virtual_path(file_name)?;
        let Some(path) = path else {
            file_info.as_mut().file_attributes = 0x10;
            return Ok(DlpFileHandle {
                path: None,
                handle: None,
            });
        };
        let mut store = self
            .store
            .lock()
            .map_err(|_| FspError::NTSTATUS(crate::status::STATUS_IO_DEVICE_ERROR))?;
        let handle = store
            .create_or_open(&path, false, false)
            .map_err(Self::storage_error)?;
        drop(store);
        self.file_info_for(&path, file_info.as_mut())?;
        Ok(DlpFileHandle {
            path: Some(path),
            handle: Some(handle),
        })
    }

    fn close(&self, context: Self::FileContext) {
        if let Some(handle) = context.handle {
            if let Ok(mut store) = self.store.lock() {
                let _ = store.close_handle(handle);
            }
        }
    }

    fn create(
        &self,
        file_name: &U16CStr,
        _create_options: u32,
        _granted_access: u32,
        _file_attributes: u32,
        _security_descriptor: Option<&[c_void]>,
        _allocation_size: u64,
        _extra_buffer: Option<&[u8]>,
        extra_buffer_is_reparse_point: bool,
        file_info: &mut OpenFileInfo,
    ) -> Result<Self::FileContext> {
        if extra_buffer_is_reparse_point {
            return Err(FspError::NTSTATUS(
                crate::status::STATUS_OBJECT_NAME_INVALID,
            ));
        }
        let path = Self::virtual_path(file_name)?.ok_or(FspError::NTSTATUS(
            crate::status::STATUS_OBJECT_NAME_INVALID,
        ))?;
        let mut store = self
            .store
            .lock()
            .map_err(|_| FspError::NTSTATUS(crate::status::STATUS_IO_DEVICE_ERROR))?;
        let handle = store
            .create_or_open(&path, true, false)
            .map_err(Self::storage_error)?;
        file_info.as_mut().file_attributes = 0x80;
        Ok(DlpFileHandle {
            path: Some(path),
            handle: Some(handle),
        })
    }

    fn flush(&self, context: Option<&Self::FileContext>, file_info: &mut FileInfo) -> Result<()> {
        let context = context.ok_or(FspError::NTSTATUS(crate::status::STATUS_IO_DEVICE_ERROR))?;
        let handle = context.handle.ok_or(FspError::NTSTATUS(
            crate::status::STATUS_OBJECT_NAME_INVALID,
        ))?;
        let mut store = self
            .store
            .lock()
            .map_err(|_| FspError::NTSTATUS(crate::status::STATUS_IO_DEVICE_ERROR))?;
        store.flush_handle(handle).map_err(Self::storage_error)?;
        if let Some(path) = &context.path {
            let bytes = store.read_path(path).map_err(Self::storage_error)?;
            file_info.file_size = bytes.len() as u64;
            file_info.allocation_size = file_info.file_size;
        }
        Ok(())
    }

    fn get_file_info(&self, context: &Self::FileContext, file_info: &mut FileInfo) -> Result<()> {
        if let Some(path) = &context.path {
            self.file_info_for(path, file_info)?;
        } else {
            file_info.file_attributes = 0x10;
        }
        Ok(())
    }

    fn get_volume_info(&self, volume_info: &mut VolumeInfo) -> Result<()> {
        volume_info.total_size = 16 * 1024 * 1024 * 1024;
        volume_info.free_size = volume_info.total_size;
        volume_info.set_volume_label("DLPDrive");
        Ok(())
    }

    fn read(&self, context: &Self::FileContext, buffer: &mut [u8], offset: u64) -> Result<u32> {
        let path = context.path.as_ref().ok_or(FspError::NTSTATUS(
            crate::status::STATUS_OBJECT_NAME_INVALID,
        ))?;
        let offset = usize::try_from(offset)
            .map_err(|_| FspError::NTSTATUS(crate::status::STATUS_OBJECT_NAME_INVALID))?;
        let store = self
            .store
            .lock()
            .map_err(|_| FspError::NTSTATUS(crate::status::STATUS_IO_DEVICE_ERROR))?;
        let bytes = store.read_path(path).map_err(Self::storage_error)?;
        let available = bytes.get(offset..).unwrap_or_default();
        let copied = available.len().min(buffer.len());
        // `read_path` authenticates the encrypted record before this copy.
        buffer[..copied].copy_from_slice(&available[..copied]);
        u32::try_from(copied).map_err(|_| FspError::NTSTATUS(crate::status::STATUS_IO_DEVICE_ERROR))
    }

    fn write(
        &self,
        context: &Self::FileContext,
        buffer: &[u8],
        offset: u64,
        _write_to_eof: bool,
        _constrained_io: bool,
        file_info: &mut FileInfo,
    ) -> Result<u32> {
        let handle = context.handle.ok_or(FspError::NTSTATUS(
            crate::status::STATUS_OBJECT_NAME_INVALID,
        ))?;
        let offset = usize::try_from(offset)
            .map_err(|_| FspError::NTSTATUS(crate::status::STATUS_OBJECT_NAME_INVALID))?;
        let _end = offset.checked_add(buffer.len()).ok_or(FspError::NTSTATUS(
            crate::status::STATUS_OBJECT_NAME_INVALID,
        ))?;
        let mut store = self
            .store
            .lock()
            .map_err(|_| FspError::NTSTATUS(crate::status::STATUS_IO_DEVICE_ERROR))?;
        store
            .write_handle(handle, offset, buffer)
            .map_err(Self::storage_error)?;
        // Close has no error return in the binding; publish here so every successful write and
        // any subsequent close are already durable.
        store.flush_handle(handle).map_err(Self::storage_error)?;
        if let Some(path) = &context.path {
            let bytes = store.read_path(path).map_err(Self::storage_error)?;
            file_info.file_size = bytes.len() as u64;
            file_info.allocation_size = file_info.file_size;
        }
        u32::try_from(buffer.len())
            .map_err(|_| FspError::NTSTATUS(crate::status::STATUS_IO_DEVICE_ERROR))
    }
}

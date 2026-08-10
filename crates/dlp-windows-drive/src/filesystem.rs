//! SID-bound WinFsp callbacks over the portable encrypted store.

use crate::status::{STATUS_NOT_SUPPORTED, path_to_ntstatus, to_ntstatus};
use dlp_storage::{
    CapturedStoreIdentity, FileHandle, LocalEncryptedStore, StorageError, VirtualPath,
};
use std::{ffi::c_void, sync::Mutex};
use winfsp::{
    FspError, Result, U16CStr,
    filesystem::{
        DirInfo, DirMarker, FileInfo, FileSecurity, FileSystemContext, OpenFileInfo, VolumeInfo,
        WideNameInfo,
    },
};

/// A handle cannot replace the mount's captured identity; it only refers to a parsed virtual path.
pub struct DlpFileHandle {
    path: Mutex<VirtualPath>,
    handle: Option<FileHandle>,
    directory: bool,
    delete_requested: Mutex<bool>,
}

impl DlpFileHandle {
    fn file(path: VirtualPath, handle: FileHandle) -> Self {
        Self {
            path: Mutex::new(path),
            handle: Some(handle),
            directory: false,
            delete_requested: Mutex::new(false),
        }
    }

    fn directory(path: VirtualPath) -> Self {
        Self {
            path: Mutex::new(path),
            handle: None,
            directory: true,
            delete_requested: Mutex::new(false),
        }
    }

    fn path(&self) -> Result<VirtualPath> {
        self.path
            .lock()
            .map(|path| path.clone())
            .map_err(|_| FspError::NTSTATUS(crate::status::STATUS_IO_DEVICE_ERROR))
    }

    fn replace_path(&self, replacement: VirtualPath) -> Result<()> {
        *self
            .path
            .lock()
            .map_err(|_| FspError::NTSTATUS(crate::status::STATUS_IO_DEVICE_ERROR))? = replacement;
        Ok(())
    }
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
        if store.is_directory_path(path) {
            info.file_attributes = 0x10;
        } else {
            let bytes = store.read_path(path).map_err(Self::storage_error)?;
            info.file_size = bytes.len() as u64;
            info.allocation_size = info.file_size;
            info.file_attributes = 0x80;
        }
        Ok(())
    }

    fn file_info_for_handle(&self, context: &DlpFileHandle, info: &mut FileInfo) -> Result<()> {
        if context.directory {
            info.file_attributes = 0x10;
            return Ok(());
        }
        let handle = context.handle.ok_or(FspError::NTSTATUS(
            crate::status::STATUS_OBJECT_NAME_INVALID,
        ))?;
        let store = self
            .store
            .lock()
            .map_err(|_| FspError::NTSTATUS(crate::status::STATUS_IO_DEVICE_ERROR))?;
        let bytes = store.read_handle(handle).map_err(Self::storage_error)?;
        info.file_size = bytes.len() as u64;
        info.allocation_size = info.file_size;
        info.file_attributes = 0x80;
        Ok(())
    }

    fn is_directory_create(create_options: u32) -> bool {
        // FILE_DIRECTORY_FILE. Kept local so the adapter does not depend on raw winfsp-sys.
        create_options & 0x0000_0001 != 0
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
        let attributes = match Self::virtual_path(file_name)? {
            None => 0x10,
            Some(path) => {
                if self
                    .store
                    .lock()
                    .map_err(|_| FspError::NTSTATUS(crate::status::STATUS_IO_DEVICE_ERROR))?
                    .is_directory_path(&path)
                {
                    0x10
                } else {
                    0x80
                }
            }
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
        let path = Self::virtual_path(file_name)?.unwrap_or_else(VirtualPath::root);
        if path.lookup_key().is_empty() {
            file_info.as_mut().file_attributes = 0x10;
            return Ok(DlpFileHandle::directory(path));
        }
        let mut store = self
            .store
            .lock()
            .map_err(|_| FspError::NTSTATUS(crate::status::STATUS_IO_DEVICE_ERROR))?;
        if store.is_directory_path(&path) {
            file_info.as_mut().file_attributes = 0x10;
            return Ok(DlpFileHandle::directory(path));
        }
        let handle = store
            .create_or_open(&path, false, true)
            .map_err(Self::storage_error)?;
        drop(store);
        self.file_info_for(&path, file_info.as_mut())?;
        Ok(DlpFileHandle::file(path, handle))
    }

    fn close(&self, context: Self::FileContext) {
        if let Some(handle) = context.handle
            && let Ok(mut store) = self.store.lock()
        {
            let _ = store.close_handle(handle);
        }
    }

    fn cleanup(&self, context: &Self::FileContext, _file_name: Option<&U16CStr>, _flags: u32) {
        let delete_requested = context
            .delete_requested
            .lock()
            .map(|requested| *requested)
            .unwrap_or(false);
        if delete_requested
            && let Ok(path) = context.path()
            && let Ok(mut store) = self.store.lock()
        {
            // WinFsp requires deletion to happen during cleanup, never in set_delete.
            let _ = store.delete(&path);
        }
    }

    fn create(
        &self,
        file_name: &U16CStr,
        create_options: u32,
        _granted_access: u32,
        file_attributes: u32,
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
        if Self::is_directory_create(create_options) || file_attributes & 0x10 != 0 {
            store.create_directory(&path).map_err(Self::storage_error)?;
            file_info.as_mut().file_attributes = 0x10;
            return Ok(DlpFileHandle::directory(path));
        }
        let handle = store
            .create_or_open(&path, true, true)
            .map_err(Self::storage_error)?;
        file_info.as_mut().file_attributes = 0x80;
        Ok(DlpFileHandle::file(path, handle))
    }

    fn flush(&self, context: Option<&Self::FileContext>, file_info: &mut FileInfo) -> Result<()> {
        let Some(context) = context else {
            return Ok(());
        };
        let Some(handle) = context.handle else {
            file_info.file_attributes = 0x10;
            return Ok(());
        };
        let mut store = self
            .store
            .lock()
            .map_err(|_| FspError::NTSTATUS(crate::status::STATUS_IO_DEVICE_ERROR))?;
        store.flush_handle(handle).map_err(Self::storage_error)?;
        if let Some(handle) = context.handle {
            let bytes = store.read_handle(handle).map_err(Self::storage_error)?;
            file_info.file_size = bytes.len() as u64;
            file_info.allocation_size = file_info.file_size;
        } else {
            file_info.file_attributes = 0x10;
        }
        Ok(())
    }

    fn overwrite(
        &self,
        context: &Self::FileContext,
        _file_attributes: u32,
        _replace_file_attributes: bool,
        allocation_size: u64,
        _extra_buffer: Option<&[u8]>,
        file_info: &mut FileInfo,
    ) -> Result<()> {
        let handle = context.handle.ok_or(FspError::NTSTATUS(
            crate::status::STATUS_OBJECT_NAME_INVALID,
        ))?;
        let length = usize::try_from(allocation_size)
            .map_err(|_| FspError::NTSTATUS(crate::status::STATUS_OBJECT_NAME_INVALID))?;
        let mut store = self
            .store
            .lock()
            .map_err(|_| FspError::NTSTATUS(crate::status::STATUS_IO_DEVICE_ERROR))?;
        store
            .truncate_handle(handle, length)
            .map_err(Self::storage_error)?;
        store.flush_handle(handle).map_err(Self::storage_error)?;
        drop(store);
        self.file_info_for_handle(context, file_info)
    }

    fn get_file_info(&self, context: &Self::FileContext, file_info: &mut FileInfo) -> Result<()> {
        self.file_info_for_handle(context, file_info)
    }

    fn set_basic_info(
        &self,
        context: &Self::FileContext,
        _attributes: u32,
        _created: u64,
        _accessed: u64,
        _written: u64,
        _changed: u64,
        file_info: &mut FileInfo,
    ) -> Result<()> {
        self.get_file_info(context, file_info)
    }

    fn set_file_size(
        &self,
        context: &Self::FileContext,
        new_size: u64,
        _allocation: bool,
        file_info: &mut FileInfo,
    ) -> Result<()> {
        let handle = context.handle.ok_or(FspError::NTSTATUS(
            crate::status::STATUS_OBJECT_NAME_INVALID,
        ))?;
        let length = usize::try_from(new_size)
            .map_err(|_| FspError::NTSTATUS(crate::status::STATUS_OBJECT_NAME_INVALID))?;
        let mut store = self
            .store
            .lock()
            .map_err(|_| FspError::NTSTATUS(crate::status::STATUS_IO_DEVICE_ERROR))?;
        store
            .truncate_handle(handle, length)
            .map_err(Self::storage_error)?;
        store.flush_handle(handle).map_err(Self::storage_error)?;
        file_info.file_size = new_size;
        file_info.allocation_size = new_size;
        Ok(())
    }

    fn rename(
        &self,
        context: &Self::FileContext,
        _file_name: &U16CStr,
        new_file_name: &U16CStr,
        replace: bool,
    ) -> Result<()> {
        let source = context.path()?;
        let destination = Self::virtual_path(new_file_name)?.ok_or(FspError::NTSTATUS(
            crate::status::STATUS_OBJECT_NAME_INVALID,
        ))?;
        self.store
            .lock()
            .map_err(|_| FspError::NTSTATUS(crate::status::STATUS_IO_DEVICE_ERROR))?
            .rename(&source, &destination, replace)
            .map_err(Self::storage_error)?;
        context.replace_path(destination)
    }

    fn set_delete(
        &self,
        context: &Self::FileContext,
        _file_name: &U16CStr,
        delete_file: bool,
    ) -> Result<()> {
        if delete_file {
            let path = context.path()?;
            self.store
                .lock()
                .map_err(|_| FspError::NTSTATUS(crate::status::STATUS_IO_DEVICE_ERROR))?
                .ensure_delete_allowed(&path)
                .map_err(Self::storage_error)?;
        }
        *context
            .delete_requested
            .lock()
            .map_err(|_| FspError::NTSTATUS(crate::status::STATUS_IO_DEVICE_ERROR))? = delete_file;
        Ok(())
    }

    fn read_directory(
        &self,
        context: &Self::FileContext,
        pattern: Option<&U16CStr>,
        marker: DirMarker,
        buffer: &mut [u8],
    ) -> Result<u32> {
        if !context.directory {
            return Err(FspError::NTSTATUS(STATUS_NOT_SUPPORTED));
        }
        if let Some(pattern) = pattern
            && pattern.to_string_lossy() != "*"
        {
            return Err(FspError::NTSTATUS(STATUS_NOT_SUPPORTED));
        }
        let path = context.path()?;
        let marker_name = marker
            .inner_as_cstr()
            .map(|marker| marker.to_string_lossy());
        let entries = self
            .store
            .lock()
            .map_err(|_| FspError::NTSTATUS(crate::status::STATUS_IO_DEVICE_ERROR))?
            .read_directory(&path)
            .map_err(Self::storage_error)?;
        let mut cursor = 0_u32;
        for entry in entries.into_iter().filter(|entry| {
            marker_name
                .as_ref()
                .is_none_or(|marker| entry.to_ascii_lowercase() > marker.to_ascii_lowercase())
        }) {
            let mut info: DirInfo = DirInfo::new();
            info.set_name(&entry)?;
            let child = if path.lookup_key().is_empty() {
                VirtualPath::parse(&entry)
            } else {
                VirtualPath::parse(&format!("{}\\{entry}", path.lookup_key()))
            }
            .map_err(|error| FspError::NTSTATUS(path_to_ntstatus(&error)))?;
            self.file_info_for(&child, info.file_info_mut())?;
            if !info.append_to_buffer(buffer, &mut cursor) {
                break;
            }
        }
        <DirInfo as WideNameInfo<255>>::finalize_buffer(buffer, &mut cursor);
        Ok(cursor)
    }

    fn get_stream_info(&self, _context: &Self::FileContext, _buffer: &mut [u8]) -> Result<u32> {
        Err(FspError::NTSTATUS(STATUS_NOT_SUPPORTED))
    }
    fn get_reparse_point(
        &self,
        _context: &Self::FileContext,
        _file_name: &U16CStr,
        _buffer: &mut [u8],
    ) -> Result<u64> {
        Err(FspError::NTSTATUS(STATUS_NOT_SUPPORTED))
    }
    fn get_extended_attributes(
        &self,
        _context: &Self::FileContext,
        _buffer: &mut [u8],
    ) -> Result<u32> {
        Err(FspError::NTSTATUS(STATUS_NOT_SUPPORTED))
    }

    fn get_volume_info(&self, volume_info: &mut VolumeInfo) -> Result<()> {
        volume_info.total_size = 16 * 1024 * 1024 * 1024;
        volume_info.free_size = volume_info.total_size;
        volume_info.set_volume_label("DLPDrive");
        Ok(())
    }

    fn read(&self, context: &Self::FileContext, buffer: &mut [u8], offset: u64) -> Result<u32> {
        let handle = context.handle.ok_or(FspError::NTSTATUS(
            crate::status::STATUS_OBJECT_NAME_INVALID,
        ))?;
        let offset = usize::try_from(offset)
            .map_err(|_| FspError::NTSTATUS(crate::status::STATUS_OBJECT_NAME_INVALID))?;
        let store = self
            .store
            .lock()
            .map_err(|_| FspError::NTSTATUS(crate::status::STATUS_IO_DEVICE_ERROR))?;
        let bytes = store.read_handle(handle).map_err(Self::storage_error)?;
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
        write_to_eof: bool,
        _constrained_io: bool,
        file_info: &mut FileInfo,
    ) -> Result<u32> {
        let handle = context.handle.ok_or(FspError::NTSTATUS(
            crate::status::STATUS_OBJECT_NAME_INVALID,
        ))?;
        let mut store = self
            .store
            .lock()
            .map_err(|_| FspError::NTSTATUS(crate::status::STATUS_IO_DEVICE_ERROR))?;
        let offset = if write_to_eof {
            store
                .read_handle(handle)
                .map_err(Self::storage_error)?
                .len()
        } else {
            usize::try_from(offset)
                .map_err(|_| FspError::NTSTATUS(crate::status::STATUS_OBJECT_NAME_INVALID))?
        };
        let _end = offset.checked_add(buffer.len()).ok_or(FspError::NTSTATUS(
            crate::status::STATUS_OBJECT_NAME_INVALID,
        ))?;
        store
            .write_handle(handle, offset, buffer)
            .map_err(Self::storage_error)?;
        // Close has no error return in the binding; publish here so every successful write and
        // any subsequent close are already durable.
        store.flush_handle(handle).map_err(Self::storage_error)?;
        if let Some(handle) = context.handle {
            let bytes = store.read_handle(handle).map_err(Self::storage_error)?;
            file_info.file_size = bytes.len() as u64;
            file_info.allocation_size = file_info.file_size;
        }
        u32::try_from(buffer.len())
            .map_err(|_| FspError::NTSTATUS(crate::status::STATUS_IO_DEVICE_ERROR))
    }
}

use std::{
    fs::{self, File, OpenOptions},
    path::{Path, PathBuf},
};

#[derive(Clone, Debug)]
pub struct AuthorizedFolders(Vec<PathBuf>);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PathAuthorizationError {
    InvalidPath,
    NotFound,
    Denied,
}

impl AuthorizedFolders {
    pub fn empty() -> Self {
        Self(Vec::new())
    }

    pub fn from_configured_dirs(
        folders: impl IntoIterator<Item = PathBuf>,
    ) -> Result<Self, PathAuthorizationError> {
        folders
            .into_iter()
            .map(|folder| {
                if !folder.is_absolute() {
                    return Err(PathAuthorizationError::InvalidPath);
                }
                let canonical =
                    fs::canonicalize(folder).map_err(|_| PathAuthorizationError::NotFound)?;
                if !canonical.is_dir() {
                    return Err(PathAuthorizationError::InvalidPath);
                }
                Ok(canonical)
            })
            .collect::<Result<Vec<_>, _>>()
            .map(Self)
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    fn contains_exact_parent(&self, target: &Path) -> bool {
        target
            .parent()
            .is_some_and(|parent| self.0.iter().any(|folder| parent == folder))
    }
}

pub fn open_authorized_file(
    path: &Path,
    authorized_folders: &AuthorizedFolders,
) -> Result<File, PathAuthorizationError> {
    if !path.is_absolute() {
        return Err(PathAuthorizationError::InvalidPath);
    }

    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let file = options.open(path).map_err(|error| match error.kind() {
        std::io::ErrorKind::NotFound => PathAuthorizationError::NotFound,
        _ => PathAuthorizationError::Denied,
    })?;
    #[cfg(windows)]
    let canonical = final_path_for_handle(&file)?;
    #[cfg(not(windows))]
    let canonical = fs::canonicalize(path).map_err(|_| PathAuthorizationError::NotFound)?;
    authorize_canonical_target(&canonical, authorized_folders)?;
    #[cfg(not(windows))]
    {
        let handle_metadata = file
            .metadata()
            .map_err(|_| PathAuthorizationError::Denied)?;
        let path_metadata = fs::metadata(&canonical).map_err(|_| PathAuthorizationError::Denied)?;
        if !same_file(&handle_metadata, &path_metadata) {
            return Err(PathAuthorizationError::Denied);
        }
    }
    Ok(file)
}

#[cfg(unix)]
fn same_file(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    left.dev() == right.dev() && left.ino() == right.ino()
}

#[cfg(windows)]
#[allow(unsafe_code)]
fn final_path_for_handle(file: &File) -> Result<PathBuf, PathAuthorizationError> {
    use std::os::windows::{ffi::OsStringExt, io::AsRawHandle};
    use windows_sys::Win32::Storage::FileSystem::GetFinalPathNameByHandleW;

    let handle = file.as_raw_handle();
    let required = unsafe { GetFinalPathNameByHandleW(handle, std::ptr::null_mut(), 0, 0) };
    if required == 0 {
        return Err(PathAuthorizationError::Denied);
    }
    let mut buffer = vec![0_u16; required as usize + 1];
    let written =
        unsafe { GetFinalPathNameByHandleW(handle, buffer.as_mut_ptr(), buffer.len() as u32, 0) };
    if written == 0 || written as usize >= buffer.len() {
        return Err(PathAuthorizationError::Denied);
    }
    buffer.truncate(written as usize);
    Ok(PathBuf::from(std::ffi::OsString::from_wide(&buffer)))
}

pub fn authorize_canonical_target(
    canonical_target: &Path,
    authorized_folders: &AuthorizedFolders,
) -> Result<(), PathAuthorizationError> {
    if !canonical_target.is_file() {
        return Err(PathAuthorizationError::Denied);
    }
    if authorized_folders.contains_exact_parent(canonical_target) {
        Ok(())
    } else {
        Err(PathAuthorizationError::Denied)
    }
}

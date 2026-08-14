use std::{
    fs,
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

pub fn authorize_requested_file(
    path: &Path,
    authorized_folders: &AuthorizedFolders,
) -> Result<PathBuf, PathAuthorizationError> {
    if !path.is_absolute() {
        return Err(PathAuthorizationError::InvalidPath);
    }
    let canonical = fs::canonicalize(path).map_err(|_| PathAuthorizationError::NotFound)?;
    authorize_canonical_target(&canonical, authorized_folders)?;
    Ok(canonical)
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

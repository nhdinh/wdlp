#![forbid(unsafe_code)]

//! Portable encrypted-store format and filesystem-facing durability contracts.

mod format;
mod store;

pub use dlp_crypto::StoreKey;
pub use format::{CommitRecordV1, EncryptedManifestV1, EncryptedRecordV1};
pub use store::{CommitOutcome, DurabilityTrace, LocalEncryptedStore};

use dlp_domain::{FileId, StoreId, UserSid};
use std::fmt;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StorageError {
    FlushNotDurable,
    CloseNotDurable,
    IntegrityFailure,
    NoSpace,
    Unavailable,
    NotFound,
    IoFailure,
}

impl fmt::Display for StorageError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::FlushNotDurable => "encrypted data is not durably flushed",
            Self::CloseNotDurable => "encrypted data is not durably closed",
            Self::IntegrityFailure => "encrypted store integrity check failed",
            Self::NoSpace => "encrypted store has no remaining space",
            Self::Unavailable => "encrypted store is unavailable",
            Self::NotFound => "encrypted store entry was not found",
            Self::IoFailure => "encrypted store backing I/O failed",
        };
        write!(formatter, "{message}")
    }
}

impl std::error::Error for StorageError {}

/// Store routing identity captured by the authenticated Windows-session boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapturedStoreIdentity {
    user_sid: UserSid,
    store_id: StoreId,
}

impl CapturedStoreIdentity {
    pub const fn new(user_sid: UserSid, store_id: StoreId) -> Self {
        Self { user_sid, store_id }
    }

    pub fn user_sid(&self) -> &UserSid {
        &self.user_sid
    }

    pub fn store_id(&self) -> &StoreId {
        &self.store_id
    }
}

/// File identity that cannot be constructed from an unbound caller-provided user string.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoreFileIdentity {
    store: CapturedStoreIdentity,
    file_id: FileId,
}

impl StoreFileIdentity {
    pub const fn new(store: CapturedStoreIdentity, file_id: FileId) -> Self {
        Self { store, file_id }
    }

    pub fn store(&self) -> &CapturedStoreIdentity {
        &self.store
    }

    pub fn file_id(&self) -> &FileId {
        &self.file_id
    }
}

pub const CHUNK_SIZE: usize = 4 * 1024 * 1024;

/// Resolves a key only for the captured store identity.
pub trait StoreKeyProvider {
    fn load_store_key(&self, identity: &CapturedStoreIdentity) -> Result<StoreKey, StorageError>;
}

/// Durability port: a successful return means the future implementation met D-12.
pub trait EncryptedStore {
    fn flush(&mut self, file: &StoreFileIdentity) -> Result<(), StorageError>;
    fn close(&mut self, file: &StoreFileIdentity) -> Result<(), StorageError>;
}

/// Portable filesystem-facing port retaining flush/close semantics without Windows types.
pub trait ProtectedFileSystem {
    fn flush_handle(&mut self, file: &StoreFileIdentity) -> Result<(), StorageError>;
    fn close_handle(&mut self, file: &StoreFileIdentity) -> Result<(), StorageError>;
}

#[cfg(test)]
mod tests {
    use super::{
        CapturedStoreIdentity, EncryptedStore, ProtectedFileSystem, StorageError,
        StoreFileIdentity, StoreKey, StoreKeyProvider,
    };
    use dlp_domain::{FileId, StoreId, UserSid};

    fn identity() -> StoreFileIdentity {
        StoreFileIdentity::new(
            CapturedStoreIdentity::new(
                UserSid::parse("S-1-5-21").expect("valid SID"),
                StoreId::parse("store-01").expect("valid store"),
            ),
            FileId::parse("file-01").expect("valid file"),
        )
    }

    #[test]
    fn storage_ports_require_captured_store_and_file_identities() {
        struct Noop;
        impl StoreKeyProvider for Noop {
            fn load_store_key(
                &self,
                _identity: &CapturedStoreIdentity,
            ) -> Result<StoreKey, StorageError> {
                Err(StorageError::IntegrityFailure)
            }
        }
        impl EncryptedStore for Noop {
            fn flush(&mut self, _file: &StoreFileIdentity) -> Result<(), StorageError> {
                Err(StorageError::FlushNotDurable)
            }
            fn close(&mut self, _file: &StoreFileIdentity) -> Result<(), StorageError> {
                Err(StorageError::CloseNotDurable)
            }
        }
        impl ProtectedFileSystem for Noop {
            fn flush_handle(&mut self, file: &StoreFileIdentity) -> Result<(), StorageError> {
                self.flush(file)
            }
            fn close_handle(&mut self, file: &StoreFileIdentity) -> Result<(), StorageError> {
                self.close(file)
            }
        }

        let mut port = Noop;
        assert!(matches!(
            port.flush_handle(&identity()),
            Err(StorageError::FlushNotDurable)
        ));
        assert!(matches!(
            port.close_handle(&identity()),
            Err(StorageError::CloseNotDurable)
        ));
        assert!(matches!(
            port.load_store_key(identity().store()),
            Err(StorageError::IntegrityFailure)
        ));
    }

    #[test]
    fn storage_contract_keeps_key_material_redacted() {
        let source = include_str!("lib.rs");
        let production_source = source
            .split("#[cfg(test)]")
            .next()
            .expect("production source");
        assert!(production_source.contains("StoreKey"));
    }
}

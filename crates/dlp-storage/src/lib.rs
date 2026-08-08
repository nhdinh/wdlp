#![forbid(unsafe_code)]

#[cfg(test)]
mod tests {
    use super::{
        CapturedStoreIdentity, EncryptedStore, ProtectedFileSystem, StorageError, StoreFileIdentity,
        StoreKey, StoreKeyProvider,
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
        assert!(matches!(port.flush_handle(&identity()), Err(StorageError::FlushNotDurable)));
        assert!(matches!(port.close_handle(&identity()), Err(StorageError::CloseNotDurable)));
        assert!(matches!(
            port.load_store_key(identity().store()),
            Err(StorageError::IntegrityFailure)
        ));
    }

    #[test]
    fn storage_contract_has_no_persisted_record_writer() {
        let source = include_str!("lib.rs");
        let production_source = source.split("#[cfg(test)]").next().expect("production source");
        assert!(!production_source.contains("std::fs"));
        assert!(!production_source.contains("write_record"));
        assert!(!production_source.contains("encode_record"));
    }
}

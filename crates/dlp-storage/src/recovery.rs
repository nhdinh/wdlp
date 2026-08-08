use crate::{LocalEncryptedStore, StorageError};
use dlp_domain::FileId;

/// Opaque forensic metadata for a retained encrypted artifact.
///
/// Evidence bytes are deliberately not exposed through this API.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvidenceRecord {
    pub opaque_id: String,
    pub record_type: &'static str,
    pub digest: String,
    pub code: StorageError,
}

/// Result of authenticating the selected committed generation during restart.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryReport {
    pub selected_generation: u64,
    pub recovered_from_prior_pointer: bool,
}

/// Reconstructs a file only after authenticating its pointer, commit, manifest, and chunks.
///
/// The only fallback is the separately persisted authenticated prior pointer; directory names,
/// timestamps, and unreferenced staging entries are never considered candidates.
pub fn recover_store(
    store: &mut LocalEncryptedStore,
    file: &FileId,
) -> Result<RecoveryReport, StorageError> {
    match store.recover_selected_from_prior(file) {
        Err(StorageError::IntegrityFailure) => {
            store.preserve_integrity_evidence(file)?;
            Err(StorageError::IntegrityFailure)
        }
        result => result,
    }
}

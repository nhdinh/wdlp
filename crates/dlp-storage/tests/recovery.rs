use dlp_storage::{
    recover_store, CapturedStoreIdentity, LocalEncryptedStore, StorageError, StoreKey,
};
use dlp_domain::{FileId, StoreId, UserSid};

fn fixture() -> (tempfile::TempDir, CapturedStoreIdentity, StoreKey, FileId) {
    let temp = tempfile::tempdir().expect("temporary backing directory");
    let identity = CapturedStoreIdentity::new(
        UserSid::parse("S-1-5-21-recovery").expect("valid SID"),
        StoreId::parse("recovery-store").expect("valid store ID"),
    );
    let key = StoreKey::from_bytes([7; 32]);
    let file = FileId::parse("recovery-file").expect("valid file ID");
    (temp, identity, key, file)
}

#[test]
fn recovers_the_prior_authenticated_commit_when_selected_pointer_is_lost() {
    let (temp, identity, key, file) = fixture();
    let mut store = LocalEncryptedStore::open(temp.path(), identity.clone(), key.clone())
        .expect("open store");
    store.write(&file, b"old committed bytes").expect("stage old");
    store.flush_file(&file).expect("commit old");
    store.write(&file, b"replacement that must not publish").expect("stage replacement");
    store.inject_write_failure_for_test();
    assert_eq!(store.flush_file(&file), Err(StorageError::IoFailure));

    let selected = temp
        .path()
        .join("stores")
        .join(identity.store_id().to_wire())
        .join("files")
        .join(file.to_wire())
        .join("selected.commit");
    std::fs::remove_file(selected).expect("simulate torn selected pointer");

    let mut restarted = LocalEncryptedStore::open(temp.path(), identity, key).expect("reopen");
    let report = recover_store(&mut restarted, &file).expect("recover prior commit");
    assert!(report.recovered_from_prior_pointer);
    assert_eq!(restarted.read(&file).expect("read recovered bytes"), b"old committed bytes");

    let second = recover_store(&mut restarted, &file).expect("idempotent recovery");
    assert_eq!(report.selected_generation, second.selected_generation);
}

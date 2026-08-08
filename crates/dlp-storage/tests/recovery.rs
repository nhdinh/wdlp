use dlp_domain::{FileId, StoreId, UserSid};
use dlp_storage::{
    CapturedStoreIdentity, DurabilityFaultPoint, LocalEncryptedStore, StoreKey, recover_store,
};

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
    let mut store =
        LocalEncryptedStore::open(temp.path(), identity.clone(), key.clone()).expect("open store");
    store
        .write(&file, b"old committed bytes")
        .expect("stage old");
    store.flush_file(&file).expect("commit old");
    store
        .write(&file, b"replacement that must not publish")
        .expect("stage replacement");
    store
        .flush_file(&file)
        .expect("prepare replacement pointer");

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
    assert_eq!(
        restarted.read(&file).expect("read recovered bytes"),
        b"old committed bytes"
    );

    let second = recover_store(&mut restarted, &file).expect("idempotent recovery");
    assert_eq!(report.selected_generation, second.selected_generation);
}

#[test]
fn every_durability_fault_recovers_one_complete_authenticated_generation() {
    let points = [
        DurabilityFaultPoint::BeforeRecordWrite,
        DurabilityFaultPoint::AfterRecordFlush,
        DurabilityFaultPoint::BeforeManifestWrite,
        DurabilityFaultPoint::AfterManifestFlush,
        DurabilityFaultPoint::BeforeCommitWrite,
        DurabilityFaultPoint::AfterCommitFlush,
        DurabilityFaultPoint::BeforePointerReplace,
        DurabilityFaultPoint::AfterPointerReplace,
        DurabilityFaultPoint::BeforeDirectoryFlush,
        DurabilityFaultPoint::AfterDirectoryFlush,
    ];
    for point in points {
        let (temp, identity, key, file) = fixture();
        let mut store = LocalEncryptedStore::open(temp.path(), identity.clone(), key.clone())
            .expect("open store");
        store.write(&file, b"old complete").expect("stage old");
        store.flush_file(&file).expect("commit old");
        store.write(&file, b"new complete").expect("stage new");
        store.inject_fault_at_for_test(point);
        assert!(
            store.flush_file(&file).is_err(),
            "fault {point:?} must interrupt"
        );

        let mut restarted = LocalEncryptedStore::open(temp.path(), identity, key).expect("restart");
        recover_store(&mut restarted, &file).expect("recovery selects authenticated commit");
        let bytes = restarted.read(&file).expect("authenticated readback");
        assert!(bytes == b"old complete" || bytes == b"new complete");
    }
}

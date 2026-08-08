use dlp_domain::{FileId, StoreId, UserSid};
use dlp_storage::{
    CapturedStoreIdentity, LocalEncryptedStore, StorageError, StoreKey, recover_store,
};
use std::{fs, path::Path};

fn contains_marker(root: &Path, marker: &[u8]) -> bool {
    for entry in fs::read_dir(root).expect("read scan root") {
        let path = entry.expect("directory entry").path();
        if path.is_dir() && contains_marker(&path, marker) {
            return true;
        }
        if path.is_file()
            && fs::read(&path)
                .expect("read artifact")
                .windows(marker.len())
                .any(|w| w == marker)
        {
            return true;
        }
    }
    false
}

#[test]
fn recursive_artifact_scan_is_non_vacuous_and_excludes_plaintext_and_key_markers() {
    let temp = tempfile::tempdir().expect("temporary root");
    let backing = temp.path().join("backing");
    let control = temp.path().join("control.bin");
    let plaintext = b"DLP-UNIQUE-PLAINTEXT-MARKER-98341";
    let key_marker = [0x91_u8; 32];
    fs::write(
        &control,
        [plaintext.as_slice(), key_marker.as_slice()].concat(),
    )
    .expect("control input");
    assert!(contains_marker(temp.path(), plaintext));
    assert!(contains_marker(temp.path(), &key_marker));

    let identity = CapturedStoreIdentity::new(
        UserSid::parse("S-1-5-21-leak-scan").expect("valid SID"),
        StoreId::parse("leak-scan-store").expect("valid store ID"),
    );
    let file = FileId::parse("leak-scan-file").expect("valid file ID");
    let mut store = LocalEncryptedStore::open(&backing, identity, StoreKey::from_bytes(key_marker))
        .expect("open store");
    store.write(&file, plaintext).expect("stage plaintext");
    store.flush_file(&file).expect("commit encrypted records");
    store
        .tamper_selected_record_for_test(&file, "tag")
        .expect("tamper selected pointer");
    assert_eq!(
        recover_store(&mut store, &file),
        Err(StorageError::IntegrityFailure)
    );

    assert!(!contains_marker(&backing, plaintext));
    assert!(!contains_marker(&backing, &key_marker));
}

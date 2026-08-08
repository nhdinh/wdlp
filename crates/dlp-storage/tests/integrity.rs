use dlp_domain::{FileId, StoreId, UserSid};
use dlp_storage::{CapturedStoreIdentity, LocalEncryptedStore, StorageError, StoreKey, recover_store};
use std::{fs, path::{Path, PathBuf}};

fn fixture() -> (tempfile::TempDir, CapturedStoreIdentity, StoreKey, FileId, FileId) {
    let temp = tempfile::tempdir().expect("temporary backing directory");
    let identity = CapturedStoreIdentity::new(
        UserSid::parse("S-1-5-21-integrity").expect("valid SID"),
        StoreId::parse("integrity-store").expect("valid store ID"),
    );
    (
        temp,
        identity,
        StoreKey::from_bytes([19; 32]),
        FileId::parse("integrity-file-a").expect("valid file ID"),
        FileId::parse("integrity-file-b").expect("valid file ID"),
    )
}

fn backing_file(root: &Path, identity: &CapturedStoreIdentity, file: &FileId, relative: &str) -> PathBuf {
    root.join("stores")
        .join(identity.store_id().to_wire())
        .join("files")
        .join(file.to_wire())
        .join(relative)
}

fn evidence_contains(root: &Path, expected: &[u8]) -> bool {
    fn visit(path: &Path, expected: &[u8]) -> bool {
        let entries = fs::read_dir(path).expect("read evidence directory");
        for entry in entries {
            let entry = entry.expect("directory entry");
            let path = entry.path();
            if path.is_dir() {
                if visit(&path, expected) { return true; }
            } else if fs::read(&path).expect("read evidence file") == expected {
                return true;
            }
        }
        false
    }
    let evidence = root.join("evidence");
    evidence.exists() && visit(&evidence, expected)
}

#[test]
fn tampered_pointer_commit_manifest_and_chunk_fail_closed_and_retain_bytes() {
    let targets = ["selected.commit", "generations/{generation}/commit.rec", "generations/{generation}/manifest.rec", "generations/{generation}/chunk-00000000.rec"];
    for target in targets {
        let (temp, identity, key, file, _) = fixture();
        let mut store = LocalEncryptedStore::open(temp.path(), identity.clone(), key.clone()).expect("open store");
        store.write(&file, b"protected marker: integrity fixture").expect("stage");
        let committed = store.flush_file(&file).expect("commit");
        let relative = target.replace("{generation}", &format!("g-{:020}", committed.generation));
        let path = backing_file(temp.path(), &identity, &file, &relative);
        let mut altered = fs::read(&path).expect("read encrypted artifact");
        *altered.last_mut().expect("non-empty encrypted artifact") ^= 1;
        fs::write(&path, &altered).expect("tamper artifact");

        let mut restarted = LocalEncryptedStore::open(temp.path(), identity, key).expect("restart");
        assert_eq!(recover_store(&mut restarted, &file), Err(StorageError::IntegrityFailure));
        assert_eq!(restarted.read(&file), Err(StorageError::IntegrityFailure));
        assert!(evidence_contains(temp.path(), &altered), "{target} evidence retained");
    }
}

#[test]
fn cross_file_chunk_substitution_returns_integrity_without_plaintext() {
    let (temp, identity, key, file_a, file_b) = fixture();
    let mut store = LocalEncryptedStore::open(temp.path(), identity.clone(), key.clone()).expect("open store");
    store.write(&file_a, b"first protected marker").expect("stage first");
    let first = store.flush_file(&file_a).expect("commit first");
    store.write(&file_b, b"second protected marker").expect("stage second");
    let second = store.flush_file(&file_b).expect("commit second");
    let target = backing_file(temp.path(), &identity, &file_a, &format!("generations/g-{:020}/chunk-00000000.rec", first.generation));
    let source = backing_file(temp.path(), &identity, &file_b, &format!("generations/g-{:020}/chunk-00000000.rec", second.generation));
    let substituted = fs::read(source).expect("read second encrypted chunk");
    fs::write(&target, &substituted).expect("substitute encrypted chunk");

    let mut restarted = LocalEncryptedStore::open(temp.path(), identity, key).expect("restart");
    assert_eq!(recover_store(&mut restarted, &file_a), Err(StorageError::IntegrityFailure));
    assert_eq!(restarted.read(&file_a), Err(StorageError::IntegrityFailure));
    assert!(evidence_contains(temp.path(), &substituted));
}

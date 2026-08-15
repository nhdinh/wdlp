use dlp_domain::{FileId, StoreId, UserSid};
use dlp_storage::{
    CapturedStoreIdentity, DurabilityFaultPoint, LocalEncryptedStore, StorageError, StoreKey,
    recover_store,
};
use sha2::{Digest, Sha256};
use std::{
    fs,
    path::{Path, PathBuf},
};

fn fixture() -> (
    tempfile::TempDir,
    CapturedStoreIdentity,
    StoreKey,
    FileId,
    FileId,
) {
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

fn backing_file(
    root: &Path,
    identity: &CapturedStoreIdentity,
    file: &FileId,
    relative: &str,
) -> PathBuf {
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
                if visit(&path, expected) {
                    return true;
                }
            } else if fs::read(&path).expect("read evidence file") == expected {
                return true;
            }
        }
        false
    }
    let evidence = root.join("evidence");
    evidence.exists() && visit(&evidence, expected)
}

fn contains_marker(root: &Path, marker: &[u8]) -> bool {
    fn visit(path: &Path, marker: &[u8]) -> bool {
        let entries = fs::read_dir(path).expect("read scan root");
        for entry in entries {
            let entry = entry.expect("directory entry");
            let path = entry.path();
            if path.is_dir() {
                if visit(&path, marker) {
                    return true;
                }
            } else if fs::read(&path)
                .expect("read artifact")
                .windows(marker.len())
                .any(|window| window == marker)
            {
                return true;
            }
        }
        false
    }
    visit(root, marker)
}

#[test]
fn tampered_pointer_commit_manifest_and_chunk_fail_closed_and_retain_bytes() {
    let targets = [
        "selected.commit",
        "generations/{generation}/commit.rec",
        "generations/{generation}/manifest.rec",
        "generations/{generation}/chunk-00000000.rec",
    ];
    for target in targets {
        let (temp, identity, key, file, _) = fixture();
        let mut store = LocalEncryptedStore::open(temp.path(), identity.clone(), key.clone())
            .expect("open store");
        store
            .write(&file, b"protected marker: integrity fixture")
            .expect("stage");
        let committed = store.flush_file(&file).expect("commit");
        let relative = target.replace("{generation}", &format!("g-{:020}", committed.generation));
        let path = backing_file(temp.path(), &identity, &file, &relative);
        let mut altered = fs::read(&path).expect("read encrypted artifact");
        *altered.last_mut().expect("non-empty encrypted artifact") ^= 1;
        fs::write(&path, &altered).expect("tamper artifact");

        let mut restarted = LocalEncryptedStore::open(temp.path(), identity, key).expect("restart");
        assert_eq!(
            recover_store(&mut restarted, &file),
            Err(StorageError::IntegrityFailure)
        );
        assert_eq!(restarted.read(&file), Err(StorageError::IntegrityFailure));
        assert!(
            evidence_contains(temp.path(), &altered),
            "{target} evidence retained"
        );
    }
}

#[test]
fn cross_file_chunk_substitution_returns_integrity_without_plaintext() {
    let (temp, identity, key, file_a, file_b) = fixture();
    let mut store =
        LocalEncryptedStore::open(temp.path(), identity.clone(), key.clone()).expect("open store");
    store
        .write(&file_a, b"first protected marker")
        .expect("stage first");
    let first = store.flush_file(&file_a).expect("commit first");
    store
        .write(&file_b, b"second protected marker")
        .expect("stage second");
    let second = store.flush_file(&file_b).expect("commit second");
    let target = backing_file(
        temp.path(),
        &identity,
        &file_a,
        &format!("generations/g-{:020}/chunk-00000000.rec", first.generation),
    );
    let source = backing_file(
        temp.path(),
        &identity,
        &file_b,
        &format!("generations/g-{:020}/chunk-00000000.rec", second.generation),
    );
    let substituted = fs::read(source).expect("read second encrypted chunk");
    fs::write(&target, &substituted).expect("substitute encrypted chunk");

    let mut restarted = LocalEncryptedStore::open(temp.path(), identity, key).expect("restart");
    assert_eq!(
        recover_store(&mut restarted, &file_a),
        Err(StorageError::IntegrityFailure)
    );
    assert_eq!(restarted.read(&file_a), Err(StorageError::IntegrityFailure));
    assert!(evidence_contains(temp.path(), &substituted));
}

#[test]
fn no_space_at_each_publication_boundary_preserves_a_complete_commit() {
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
        let (temp, identity, key, file, _) = fixture();
        let mut store = LocalEncryptedStore::open(temp.path(), identity.clone(), key.clone())
            .expect("open store");
        store.write(&file, b"old complete").expect("stage old");
        store.flush_file(&file).expect("commit old");
        store.write(&file, b"new complete").expect("stage new");
        store.inject_no_space_at_for_test(point);
        assert_eq!(store.flush_file(&file), Err(StorageError::NoSpace));

        let mut restarted = LocalEncryptedStore::open(temp.path(), identity, key).expect("restart");
        recover_store(&mut restarted, &file).expect("recover complete selected commit");
        let recovered = restarted.read(&file).expect("read complete generation");
        assert!(recovered == b"old complete" || recovered == b"new complete");
    }
}

#[test]
fn corrupt_authenticated_content_returns_integrity_failure_and_preserves_evidence() {
    let (temp, identity, key, file, _) = fixture();
    let mut store =
        LocalEncryptedStore::open(temp.path(), identity.clone(), key.clone()).expect("open store");
    let baseline = b"DLP-01-20-BASELINE";
    store.write(&file, baseline).expect("stage baseline");
    store.flush_file(&file).expect("commit baseline");

    store
        .write(&file, b"DLP-01-20-REPLACEMENT")
        .expect("stage replacement");
    let replacement = store.flush_file(&file).expect("commit replacement");
    let chunk = backing_file(
        temp.path(),
        &identity,
        &file,
        &format!(
            "generations/g-{:020}/chunk-00000000.rec",
            replacement.generation
        ),
    );
    let mut altered = fs::read(&chunk).expect("read encrypted chunk");
    *altered.last_mut().expect("non-empty encrypted chunk") ^= 1;
    fs::write(&chunk, &altered).expect("corrupt content record");

    let mut restarted = LocalEncryptedStore::open(temp.path(), identity, key).expect("restart");
    assert_eq!(
        recover_store(&mut restarted, &file),
        Err(StorageError::IntegrityFailure)
    );
    assert_eq!(restarted.read(&file), Err(StorageError::IntegrityFailure));
    assert!(
        evidence_contains(temp.path(), &altered),
        "corrupt content evidence is preserved"
    );
    assert!(
        !contains_marker(temp.path(), b"DLP-01-20-REPLACEMENT"),
        "replacement plaintext is not exposed"
    );
    assert!(
        !contains_marker(temp.path(), baseline),
        "baseline plaintext is not exposed in backing store"
    );
}

#[test]
fn corrupt_sensitive_metadata_returns_integrity_failure_and_preserves_evidence() {
    let (temp, identity, key, file, _) = fixture();
    let mut store =
        LocalEncryptedStore::open(temp.path(), identity.clone(), key.clone()).expect("open store");
    let documents = dlp_storage::VirtualPath::parse("Documents").expect("directory path");
    store
        .create_directory(&documents)
        .expect("create directory");
    store
        .write(&file, b"DLP-01-20-METADATA-BASELINE")
        .expect("stage baseline");
    store.flush_file(&file).expect("commit baseline");

    let namespace = temp
        .path()
        .join("stores")
        .join(identity.store_id().to_wire())
        .join("namespace.rec");
    let mut altered = fs::read(&namespace).expect("read encrypted namespace record");
    *altered.last_mut().expect("non-empty encrypted record") ^= 1;
    fs::write(&namespace, &altered).expect("corrupt sensitive metadata record");

    let restarted = LocalEncryptedStore::open(temp.path(), identity, key);
    assert!(
        matches!(restarted, Err(StorageError::IntegrityFailure)),
        "corrupt namespace metadata must deny store load"
    );
    assert!(
        evidence_contains(temp.path(), &altered),
        "corrupt metadata evidence is preserved"
    );
}

#[test]
fn backing_store_disk_full_returns_no_space_and_preserves_baseline_hash() {
    let (temp, identity, key, file, _) = fixture();
    let mut store =
        LocalEncryptedStore::open(temp.path(), identity.clone(), key.clone()).expect("open store");
    let baseline = b"DLP-01-20-DISK-FULL-BASELINE";
    store.write(&file, baseline).expect("stage baseline");
    store.flush_file(&file).expect("commit baseline");
    let baseline_hash = Sha256::digest(store.read(&file).expect("read baseline"));

    store
        .write(&file, b"DLP-01-20-DISK-FULL-REPLACEMENT")
        .expect("stage replacement");
    store.inject_no_space_at_for_test(DurabilityFaultPoint::BeforePointerReplace);
    assert_eq!(
        store.flush_file(&file),
        Err(StorageError::NoSpace),
        "NoSpace before pointer publication returns disk-full"
    );

    let mut restarted = LocalEncryptedStore::open(temp.path(), identity, key).expect("restart");
    recover_store(&mut restarted, &file).expect("recover baseline");
    let recovered = restarted.read(&file).expect("read baseline after NoSpace");
    assert_eq!(
        Sha256::digest(&recovered),
        baseline_hash,
        "baseline hash is preserved after disk-full"
    );
}

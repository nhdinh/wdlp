use dlp_domain::{FileId, StoreId, UserSid};
use dlp_storage::{CHUNK_SIZE, CapturedStoreIdentity, LocalEncryptedStore, StorageError, StoreKey};

fn identity() -> CapturedStoreIdentity {
    CapturedStoreIdentity::new(
        UserSid::parse("S-1-5-21-1000").expect("SID"),
        StoreId::parse("store-1000").expect("store ID"),
    )
}

fn store() -> LocalEncryptedStore {
    let root = tempfile::tempdir().expect("temporary root").keep();
    LocalEncryptedStore::open(root, identity(), StoreKey::from_bytes([9; 32])).expect("store opens")
}

#[test]
fn exact_four_mib_boundaries_and_sparse_writes_roundtrip_only_after_flush() {
    for length in [
        0,
        CHUNK_SIZE - 1,
        CHUNK_SIZE,
        CHUNK_SIZE + 1,
        CHUNK_SIZE * 2 + 37,
    ] {
        let mut encrypted = store();
        let file = FileId::parse("boundary-file").expect("file ID");
        let bytes = vec![length as u8; length];

        encrypted.write(&file, &bytes).expect("stages write");
        assert!(matches!(encrypted.read(&file), Err(StorageError::NotFound)));
        let outcome = encrypted.flush_file(&file).expect("durable flush");

        assert_eq!(outcome.chunk_count, bytes.len().div_ceil(CHUNK_SIZE));
        assert!(outcome.trace.is_durably_published());
        assert_eq!(encrypted.read(&file).expect("authenticated read"), bytes);
    }

    let mut encrypted = store();
    let file = FileId::parse("sparse-file").expect("file ID");
    encrypted
        .write_at(&file, CHUNK_SIZE + 3, b"tail")
        .expect("stages sparse write");
    encrypted.flush_file(&file).expect("durable flush");
    let roundtrip = encrypted.read(&file).expect("authenticated read");
    assert_eq!(roundtrip.len(), CHUNK_SIZE + 7);
    assert!(roundtrip[..CHUNK_SIZE + 3].iter().all(|byte| *byte == 0));
    assert_eq!(&roundtrip[CHUNK_SIZE + 3..], b"tail");
}

#[test]
fn persisted_nonces_are_unique_and_duplicate_injection_cannot_publish() {
    let mut encrypted = store();
    let file = FileId::parse("nonce-file").expect("file ID");
    encrypted
        .write(&file, &vec![7; CHUNK_SIZE + 1])
        .expect("stages write");
    let first = encrypted.flush_file(&file).expect("initial commit");
    assert!(first.nonces.windows(2).all(|pair| pair[0] != pair[1]));

    encrypted
        .write(&file, b"replacement")
        .expect("stages replacement");
    encrypted.inject_duplicate_nonce_for_test(&file);
    assert!(matches!(
        encrypted.flush_file(&file),
        Err(StorageError::IntegrityFailure)
    ));
    assert_eq!(
        encrypted
            .read(&file)
            .expect("prior commit remains readable"),
        vec![7; CHUNK_SIZE + 1]
    );
}

#[test]
fn tampered_authenticated_identity_or_tag_returns_no_plaintext() {
    let mut encrypted = store();
    let file = FileId::parse("tamper-file").expect("file ID");
    encrypted
        .write(&file, b"authenticated bytes")
        .expect("stages write");
    encrypted.flush_file(&file).expect("durable flush");

    for field in [
        "store",
        "file",
        "generation",
        "chunk",
        "length",
        "version",
        "tag",
    ] {
        let mut corrupted = encrypted.reopen().expect("reopen same store");
        corrupted
            .tamper_selected_record_for_test(&file, field)
            .expect("tamper fixture");
        assert!(matches!(
            corrupted.read(&file),
            Err(StorageError::IntegrityFailure)
        ));
    }
}

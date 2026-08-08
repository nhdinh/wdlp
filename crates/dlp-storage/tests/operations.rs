use dlp_domain::{StoreId, UserSid};
use dlp_storage::{CapturedStoreIdentity, LocalEncryptedStore, PathError, StorageError, StoreKey, VirtualPath};

fn store(sid: &str, store: &str) -> LocalEncryptedStore {
    LocalEncryptedStore::open(
        tempfile::tempdir().expect("temporary root").keep(),
        CapturedStoreIdentity::new(UserSid::parse(sid).expect("SID"), StoreId::parse(store).expect("store ID")),
        StoreKey::from_bytes([store.len() as u8; 32]),
    ).expect("encrypted store")
}

#[test]
fn paths_are_bounded_case_insensitive_and_cannot_escape_a_sid_store() {
    let valid = VirtualPath::parse(r"Documents\\Quarterly Report.txt").expect("valid path");
    assert_eq!(valid.lookup_key(), "documents/quarterly report.txt");
    assert_eq!(valid.display_name(), Some("Quarterly Report.txt"));
    assert_eq!(VirtualPath::parse(r"documents/QUARTERLY REPORT.TXT").expect("case fold").lookup_key(), valid.lookup_key());

    for invalid in ["", r"\\\\server\\share", r"C:\\escape", r"\\Device\\Harddisk", r"..\\secret", "dir/../secret", "name:stream", "CON", "nul.txt", "a\0b", &"x".repeat(129)] {
        assert!(matches!(VirtualPath::parse(invalid), Err(PathError::InvalidPath)));
    }
}

#[test]
fn file_directory_and_handle_operations_are_deterministic() {
    let mut encrypted = store("S-1-5-21-1000", "store-a");
    let documents = VirtualPath::parse("Documents").expect("directory");
    let report = VirtualPath::parse(r"Documents\\Quarterly Report.txt").expect("file");
    let renamed = VirtualPath::parse(r"Documents\\Final Report.txt").expect("renamed file");
    encrypted.create_directory(&documents).expect("create directory");
    let handle = encrypted.create_or_open(&report, true, true).expect("create file");
    encrypted.write_handle(handle, 0, b"draft").expect("write");
    encrypted.truncate_handle(handle, 3).expect("truncate");
    encrypted.flush_handle(handle).expect("flush");
    encrypted.close_handle(handle).expect("close");
    assert_eq!(encrypted.read_path(&VirtualPath::parse(r"documents\\QUARTERLY report.TXT").expect("case lookup")).expect("read"), b"dra");
    encrypted.rename(&report, &renamed, false).expect("rename");
    assert_eq!(encrypted.read_directory(&documents).expect("directory listing"), vec!["Final Report.txt"]);
    encrypted.delete(&renamed).expect("delete");
    assert!(matches!(encrypted.read_path(&renamed), Err(StorageError::NotFound)));
}

#[test]
fn sids_handles_and_failed_publication_remain_isolated() {
    let path = VirtualPath::parse("same.txt").expect("path");
    let mut first = store("S-1-5-21-1000", "store-a");
    let mut second = store("S-1-5-21-2000", "store-b");
    assert_ne!(first.identity(), second.identity());
    let first_handle = first.create_or_open(&path, true, false).expect("first open");
    let second_handle = second.create_or_open(&path, true, true).expect("second open");
    first.write_handle(first_handle, 0, b"first").expect("first write");
    first.flush_handle(first_handle).expect("first flush");
    second.write_handle(second_handle, 0, b"second").expect("second write");
    second.flush_handle(second_handle).expect("second flush");
    assert_eq!(first.read_path(&path).expect("first read"), b"first");
    assert_eq!(second.read_path(&path).expect("second read"), b"second");
    assert!(matches!(first.delete(&path), Err(StorageError::SharingViolation)));
    first.close_handle(first_handle).expect("first close");

    let replacement = first.create_or_open(&path, false, true).expect("reopen");
    first.write_handle(replacement, 0, b"replacement").expect("stage replacement");
    first.inject_write_failure_for_test();
    assert!(matches!(first.flush_handle(replacement), Err(StorageError::IoFailure | StorageError::NoSpace)));
    assert_eq!(first.read_path(&path).expect("prior generation stays readable"), b"first");
}

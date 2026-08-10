use dlp_windows_service::{CredentialStore, DeviceCredential, DpapiCredentialStore};
use std::fs;

#[test]
fn credential_store_keeps_private_key_in_one_protected_atomic_blob() {
    let directory =
        std::env::temp_dir().join(format!("dlp-credential-protection-{}", std::process::id()));
    let _ = fs::remove_dir_all(&directory);
    let store = DpapiCredentialStore::new(&directory).expect("secure store");
    let credential = DeviceCredential::for_test("device-01", b"private-key", b"certificate");

    store.protect(&credential).expect("protect credential");
    assert_eq!(store.load().expect("load credential"), credential);
    assert!(store.validate_protection().expect("validate ACL and blob"));

    let bytes = fs::read(store.path()).expect("read protected test blob");
    assert!(
        !bytes
            .windows(b"private-key".len())
            .any(|window| window == b"private-key")
    );
    let _ = fs::remove_dir_all(&directory);
}

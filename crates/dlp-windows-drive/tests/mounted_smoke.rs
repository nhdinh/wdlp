use dlp_domain::{StoreId, UserSid};
use dlp_storage::{CapturedStoreIdentity, LocalEncryptedStore, StoreKey};
use dlp_windows_drive::{DlpFileSystemContext, MountedVolume, WinFspMountHost};
use std::{
    fs,
    path::{Path, PathBuf},
    thread,
    time::Duration,
};

const MARKER: &[u8] = b"dlp-winfsp-mounted-smoke-marker";

fn test_root() -> PathBuf {
    std::env::temp_dir().join(format!("dlp-winfsp-smoke-{}", std::process::id()))
}

fn available_drive() -> String {
    (b'D'..=b'Z')
        .rev()
        .map(|letter| format!("{}:", letter as char))
        .find(|letter| !Path::new(&format!("{letter}\\")).exists())
        .expect("an unused drive letter")
}

fn contains_marker(root: &Path) -> bool {
    let mut pending = vec![root.to_path_buf()];
    while let Some(path) = pending.pop() {
        for entry in fs::read_dir(path).expect("read backing directory") {
            let path = entry.expect("directory entry").path();
            if path.is_dir() {
                pending.push(path);
            } else if fs::read(&path)
                .expect("read backing record")
                .windows(MARKER.len())
                .any(|window| window == MARKER)
            {
                return true;
            }
        }
    }
    false
}

fn wait_for_path(path: &str, present: bool) -> bool {
    for _ in 0..40 {
        if Path::new(path).exists() == present {
            return true;
        }
        thread::sleep(Duration::from_millis(50));
    }
    false
}

#[test]
fn sid_bound_context_mounts_roundtrips_denies_corruption_and_unmounts() {
    let root = test_root();
    let _ = fs::remove_dir_all(&root);
    let identity = CapturedStoreIdentity::new(
        UserSid::parse("S-1-5-21-1000").expect("test SID"),
        StoreId::parse("mounted-smoke-store").expect("test store"),
    );
    let store = LocalEncryptedStore::open(&root, identity.clone(), StoreKey::from_bytes([9; 32]))
        .expect("open encrypted backing store");
    let context =
        DlpFileSystemContext::new(identity, store).expect("capture matching store identity");
    let drive = std::env::var("DLP_WINFSP_SMOKE_LETTER").unwrap_or_else(|_| available_drive());
    let mounted_path = format!("{drive}\\");
    let volume = WinFspMountHost::new(&drive)
        .expect("valid requested drive")
        .start(context)
        .expect("start and mount real WinFsp host");

    assert!(
        wait_for_path(&mounted_path, true),
        "drive is visible in this Windows session"
    );
    let file = format!("{mounted_path}smoke.txt");
    fs::write(&file, MARKER).expect("Win32 write through mounted drive");
    assert_eq!(fs::read(&file).expect("read through mounted drive"), MARKER);
    assert!(
        !contains_marker(&root),
        "backing store must not contain plaintext marker"
    );

    let selected = root
        .join("stores")
        .join("mounted-smoke-store")
        .join("files");
    let record = fs::read_dir(&selected)
        .expect("encrypted file directory")
        .next()
        .expect("one encrypted record")
        .expect("record entry")
        .path()
        .join("selected.commit");
    let mut ciphertext = fs::read(&record).expect("selected encrypted record");
    *ciphertext.last_mut().expect("nonempty encrypted record") ^= 1;
    fs::write(&record, ciphertext).expect("corrupt only the test record");
    assert!(
        fs::read(&file).is_err(),
        "corruption returns no authenticated bytes"
    );

    if let Ok(milliseconds) = std::env::var("DLP_WINFSP_INTERACTIVE_HOLD_MS") {
        let milliseconds = milliseconds
            .parse::<u64>()
            .expect("interactive hold must be an integer number of milliseconds");
        assert!(
            milliseconds <= 60_000,
            "interactive hold is bounded to one minute"
        );
        eprintln!("mounted smoke is holding {drive} for visual verification");
        thread::sleep(Duration::from_millis(milliseconds));
    }

    volume.unmount().expect("clean unmount");
    assert!(
        wait_for_path(&mounted_path, false),
        "drive disappears after host stop"
    );
    let _ = fs::remove_dir_all(root);
}

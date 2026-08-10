use dlp_domain::{StoreId, UserSid};
use dlp_storage::{CapturedStoreIdentity, LocalEncryptedStore, StoreKey};
use dlp_windows_drive::{DlpFileSystemContext, MountedVolume, WinFspMountHost};
use std::{
    fs,
    io::{Read, Write},
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
    let context = DlpFileSystemContext::new(identity.clone(), store)
        .expect("capture matching store identity");
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
    let directory = format!("{mounted_path}Documents");
    fs::create_dir(&directory).expect("Win32 create directory through mounted drive");
    let file = format!("{directory}\\smoke.txt");
    fs::write(&file, MARKER).expect("Win32 write through mounted drive");
    let mut concurrent_reader = fs::File::open(&file).expect("second handle opens the same file");
    let mut roundtrip = Vec::new();
    concurrent_reader
        .read_to_end(&mut roundtrip)
        .expect("concurrent handle reads authenticated bytes");
    assert_eq!(roundtrip, MARKER);
    let renamed = format!("{directory}\\Final Report.txt");
    fs::rename(&file, &renamed).expect("Win32 rename keeps the open file identity");
    let mut append = fs::OpenOptions::new()
        .append(true)
        .open(&renamed)
        .expect("second writer opens renamed file");
    append.write_all(b"-extended").expect("write after rename");
    append.sync_all().expect("flush after rename");
    let expected = [MARKER, b"-extended"].concat();
    assert_eq!(
        fs::read(&renamed).expect("read through mounted drive"),
        expected
    );
    let entries = fs::read_dir(&directory)
        .expect("enumerate mounted directory")
        .map(|entry| entry.expect("directory entry").file_name())
        .collect::<Vec<_>>();
    assert_eq!(
        entries.len(),
        1,
        "directory enumeration returns one visible file"
    );
    let deleted = format!("{directory}\\delete-me.txt");
    fs::write(&deleted, b"delete-pending").expect("create deletion candidate");
    fs::remove_file(&deleted).expect("delete file through mounted drive");
    assert!(
        !Path::new(&deleted).exists(),
        "deleted path is no longer visible"
    );
    assert!(
        !contains_marker(&root),
        "backing store must not contain plaintext marker"
    );

    drop(append);
    drop(concurrent_reader);

    volume.unmount().expect("clean first unmount");
    assert!(
        wait_for_path(&mounted_path, false),
        "drive disappears after first host stop"
    );

    let restarted_store =
        LocalEncryptedStore::open(&root, identity.clone(), StoreKey::from_bytes([9; 32]))
            .expect("restart opens encrypted namespace index");
    let restarted_context = DlpFileSystemContext::new(identity, restarted_store)
        .expect("restart captures the same SID/store identity");
    let restarted = WinFspMountHost::new(&drive)
        .expect("same requested drive remains valid")
        .start(restarted_context)
        .expect("restart remounts the encrypted namespace");
    assert!(
        wait_for_path(&mounted_path, true),
        "restart drive is visible"
    );
    assert_eq!(
        fs::read(&renamed).expect("renamed file survives host restart"),
        [MARKER, b"-extended"].concat()
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
        fs::read(&renamed).is_err(),
        "corruption returns no authenticated bytes"
    );

    if let Ok(milliseconds) = std::env::var("DLP_WINFSP_INTERACTIVE_HOLD_MS") {
        let milliseconds = milliseconds
            .parse::<u64>()
            .expect("interactive hold must be an integer number of milliseconds");
        assert!(
            milliseconds <= 120_000,
            "interactive hold is bounded to two minutes"
        );
        eprintln!("mounted smoke is holding {drive} for visual verification");
        thread::sleep(Duration::from_millis(milliseconds));
    }

    restarted.unmount().expect("clean final unmount");
    assert!(
        wait_for_path(&mounted_path, false),
        "drive disappears after host stop"
    );
    let _ = fs::remove_dir_all(root);
}

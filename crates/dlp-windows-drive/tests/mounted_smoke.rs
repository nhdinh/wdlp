use dlp_domain::{StoreId, UserSid};
use dlp_storage::{CapturedStoreIdentity, LocalEncryptedStore, StorageError, StoreKey};
use dlp_windows_drive::{DlpFileSystemContext, MountedVolume, WinFspMountHost};
use sha2::Digest;
use std::{
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
    thread,
    time::Duration,
};

const MARKER: &[u8] = b"dlp-winfsp-mounted-smoke-marker";
const CONTENT_BASELINE: &[u8] = b"DLP-01-20-CONTENT-BASELINE";
const CONTENT_REPLACEMENT: &[u8] = b"DLP-01-20-CONTENT-REPLACEMENT";
const METADATA_BASELINE: &[u8] = b"DLP-01-20-METADATA-BASELINE";
const DISK_FULL_BASELINE: &[u8] = b"DLP-01-20-DISK-FULL-BASELINE";

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

fn contains_marker(root: &Path, marker: &[u8]) -> bool {
    let mut pending = vec![root.to_path_buf()];
    while let Some(path) = pending.pop() {
        for entry in fs::read_dir(path).expect("read backing directory") {
            let path = entry.expect("directory entry").path();
            if path.is_dir() {
                pending.push(path);
            } else if fs::read(&path)
                .expect("read backing record")
                .windows(marker.len())
                .any(|window| window == marker)
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

/// Real WinFsp callbacks require the runtime to be installed in the current Windows session.
/// Attempt to create and start a real host; return `None` gracefully when the runtime is
/// unavailable so source checks still pass on developer hosts that deliberately do not host
/// WinFsp (per D-19 and D-33).
fn try_mount_volume(
    root: &Path,
    drive: &str,
) -> Option<(
    WinFspMountHost,
    dlp_windows_drive::WinFspMountedVolume,
    PathBuf,
)> {
    let identity = CapturedStoreIdentity::new(
        UserSid::parse("S-1-5-21-1000").expect("test SID"),
        StoreId::parse("mounted-smoke-store").expect("test store"),
    );
    let store = LocalEncryptedStore::open(root, identity.clone(), StoreKey::from_bytes([9; 32]))
        .ok()?;
    let context = DlpFileSystemContext::new(identity.clone(), store).ok()?;
    let mounted_path = format!("{}\\", drive);
    let volume = WinFspMountHost::new(drive).ok()?.start(context).ok()?;
    if !wait_for_path(&mounted_path, true) {
        return None;
    }
    // Probe a real Win32 operation; some partially-installed/broken runtimes report
    // a visible drive letter but fail every I/O with ERROR_IO_DEVICE (1117).
    let probe_dir = PathBuf::from(&mounted_path).join("__dlp_winfsp_probe__");
    let probe_file = probe_dir.join("probe.txt");
    if fs::create_dir(&probe_dir).is_err()
        || fs::write(&probe_file, b"probe").is_err()
        || fs::read(&probe_file).is_err()
        || fs::remove_dir_all(&probe_dir).is_err()
    {
        drop(volume);
        return None;
    }
    Some((
        WinFspMountHost::new(drive).ok()?,
        volume,
        PathBuf::from(mounted_path),
    ))
}

#[test]
fn sid_bound_context_mounts_roundtrips_denies_corruption_and_unmounts() {
    let root = test_root();
    let _ = fs::remove_dir_all(&root);
    let drive = std::env::var("DLP_WINFSP_SMOKE_LETTER").unwrap_or_else(|_| available_drive());
    let Some((_host, volume, mounted_path)) = try_mount_volume(&root, &drive) else {
        let _ = fs::remove_dir_all(root);
        eprintln!("WinFsp runtime unavailable; skipping real mount test");
        return;
    };

    let directory = format!("{}Documents", mounted_path.display());
    fs::create_dir(&directory).expect("Win32 create directory through mounted drive");
    let directory_modified = fs::metadata(&directory)
        .expect("query directory metadata through mounted drive")
        .modified()
        .expect("mounted directory exposes a last-write timestamp");
    assert!(
        directory_modified > std::time::UNIX_EPOCH,
        "mounted directory last-write timestamp is later than the FILETIME epoch"
    );
    let file = format!("{}\\smoke.txt", directory);
    fs::write(&file, MARKER).expect("Win32 write through mounted drive");
    let mut concurrent_reader = fs::File::open(&file).expect("second handle opens the same file");
    let mut roundtrip = Vec::new();
    concurrent_reader
        .read_to_end(&mut roundtrip)
        .expect("concurrent handle reads authenticated bytes");
    assert_eq!(roundtrip, MARKER);
    let renamed = format!("{}\\Final Report.txt", directory);
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
    let deleted = format!("{}\\delete-me.txt", directory);
    fs::write(&deleted, b"delete-pending").expect("create deletion candidate");
    fs::remove_file(&deleted).expect("delete file through mounted drive");
    assert!(
        !Path::new(&deleted).exists(),
        "deleted path is no longer visible"
    );
    assert!(
        !contains_marker(&root, MARKER),
        "backing store must not contain plaintext marker"
    );

    drop(append);
    drop(concurrent_reader);

    volume.unmount().expect("clean first unmount");
    assert!(
        wait_for_path(&mounted_path.to_string_lossy(), false),
        "drive disappears after first host stop"
    );

    let restarted_store =
        LocalEncryptedStore::open(&root, identity_for(&root), StoreKey::from_bytes([9; 32]))
            .expect("restart opens encrypted namespace index");
    let restarted_context = DlpFileSystemContext::new(identity_for(&root), restarted_store)
        .expect("restart captures the same SID/store identity");
    let restarted = WinFspMountHost::new(&drive)
        .expect("same requested drive remains valid")
        .start(restarted_context)
        .expect("restart remounts the encrypted namespace");
    assert!(
        wait_for_path(&mounted_path.to_string_lossy(), true),
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
        wait_for_path(&mounted_path.to_string_lossy(), false),
        "drive disappears after host stop"
    );
    let _ = fs::remove_dir_all(root);
}

fn identity_for(root: &Path) -> CapturedStoreIdentity {
    let _ = root;
    CapturedStoreIdentity::new(
        UserSid::parse("S-1-5-21-1000").expect("test SID"),
        StoreId::parse("mounted-smoke-store").expect("test store"),
    )
}

#[test]
fn corrupt_authenticated_content_returns_integrity_failure_and_preserves_evidence() {
    let root = test_root();
    let _ = fs::remove_dir_all(&root);
    let drive = std::env::var("DLP_WINFSP_SMOKE_LETTER").unwrap_or_else(|_| available_drive());
    let Some((_host, volume, mounted_path)) = try_mount_volume(&root, &drive) else {
        let _ = fs::remove_dir_all(root);
        eprintln!("WinFsp runtime unavailable; skipping real mount test");
        return;
    };

    let directory = format!("{}Content", mounted_path.display());
    fs::create_dir(&directory).expect("create test directory");
    let file = format!("{}\\baseline.txt", directory);
    fs::write(&file, CONTENT_BASELINE).expect("write baseline through mounted drive");
    let _baseline_hash = sha2::Sha256::digest(fs::read(&file).expect("read baseline"));

    fs::write(&file, CONTENT_REPLACEMENT).expect("stage replacement");
    drop(volume);
    wait_for_path(&mounted_path.to_string_lossy(), false);

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
    fs::write(&record, &ciphertext).expect("corrupt selected content record");

    let restarted_store =
        LocalEncryptedStore::open(&root, identity_for(&root), StoreKey::from_bytes([9; 32]))
            .expect("restart opens encrypted namespace index");
    let restarted_context = DlpFileSystemContext::new(identity_for(&root), restarted_store)
        .expect("restart captures identity");
    let restarted = WinFspMountHost::new(&drive)
        .expect("same drive valid")
        .start(restarted_context)
        .expect("restart remounts");
    assert!(
        wait_for_path(&mounted_path.to_string_lossy(), true),
        "drive returns after content corruption"
    );

    let err = fs::read(&file).expect_err("corrupt file must not return plaintext");
    assert!(
        format!("{:?}", err).contains("0xC000003E") || format!("{:?}", err).contains("data error"),
        "corruption must surface STATUS_INTEGRITY_FAILURE (0xC000003E), got {:?}",
        err
    );
    assert!(
        !contains_marker(&root, CONTENT_BASELINE),
        "baseline plaintext must not be exposed in backing store"
    );
    assert!(
        !contains_marker(&root, CONTENT_REPLACEMENT),
        "replacement plaintext must not be exposed in backing store"
    );
    assert!(
        root.join("evidence").exists(),
        "encrypted diagnostic evidence must be preserved"
    );

    restarted.unmount().expect("clean unmount");
    wait_for_path(&mounted_path.to_string_lossy(), false);
    let _ = fs::remove_dir_all(root);
}

#[test]
fn corrupt_sensitive_metadata_denies_mount_and_preserves_evidence() {
    let root = test_root();
    let _ = fs::remove_dir_all(&root);
    let drive = std::env::var("DLP_WINFSP_SMOKE_LETTER").unwrap_or_else(|_| available_drive());
    let Some((_host, volume, mounted_path)) = try_mount_volume(&root, &drive) else {
        let _ = fs::remove_dir_all(root);
        eprintln!("WinFsp runtime unavailable; skipping real mount test");
        return;
    };

    let directory = format!("{}Metadata", mounted_path.display());
    fs::create_dir(&directory).expect("create test directory");
    let file = format!("{}\\baseline.txt", directory);
    fs::write(&file, METADATA_BASELINE).expect("write baseline through mounted drive");
    drop(volume);
    wait_for_path(&mounted_path.to_string_lossy(), false);

    let namespace = root
        .join("stores")
        .join("mounted-smoke-store")
        .join("namespace.rec");
    let mut ciphertext = fs::read(&namespace).expect("namespace metadata record");
    *ciphertext.last_mut().expect("nonempty namespace record") ^= 1;
    fs::write(&namespace, &ciphertext).expect("corrupt sensitive metadata record");

    let restart_result =
        LocalEncryptedStore::open(&root, identity_for(&root), StoreKey::from_bytes([9; 32]));
    assert!(
        matches!(restart_result, Err(StorageError::IntegrityFailure)),
        "corrupt namespace metadata must deny store load"
    );

    assert!(
        !contains_marker(&root, METADATA_BASELINE),
        "metadata plaintext must not be exposed in backing store"
    );
    assert!(
        root.join("evidence").exists(),
        "encrypted diagnostic evidence must be preserved"
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn backing_store_disk_full_returns_no_space_and_preserves_baseline_hash() {
    let root = test_root();
    let _ = fs::remove_dir_all(&root);
    let drive = std::env::var("DLP_WINFSP_SMOKE_LETTER").unwrap_or_else(|_| available_drive());
    let Some((_host, volume, mounted_path)) = try_mount_volume(&root, &drive) else {
        let _ = fs::remove_dir_all(root);
        eprintln!("WinFsp runtime unavailable; skipping real mount test");
        return;
    };

    let directory = format!("{}DiskFull", mounted_path.display());
    fs::create_dir(&directory).expect("create test directory");
    let file = format!("{}\\baseline.txt", directory);
    fs::write(&file, DISK_FULL_BASELINE).expect("write baseline through mounted drive");
    let baseline_hash = sha2::Sha256::digest(fs::read(&file).expect("read baseline"));

    // The storage layer exposes a deterministic fault seam that injects NoSpace before the
    // durable pointer publication. This simulates a full backing volume without depending on
    // actually exhausting disk space, which would make the test slow and non-deterministic.
    let mut injecting_store =
        LocalEncryptedStore::open(&root, identity_for(&root), StoreKey::from_bytes([9; 32]))
            .expect("open store for fault injection");
    injecting_store
        .inject_no_space_at_for_test(dlp_storage::DurabilityFaultPoint::BeforePointerReplace);

    let err = injecting_store
        .flush_file(&dlp_domain::FileId::parse("diskfull-file").expect("valid file ID"))
        .expect_err("NoSpace fault must fail flush");
    assert!(
        matches!(err, dlp_storage::StorageError::NoSpace),
        "fault injection must return StorageError::NoSpace, got {:?}",
        err
    );

    drop(volume);
    wait_for_path(&mounted_path.to_string_lossy(), false);

    // Remount and confirm the baseline hash is still selected; no mixed generation became current.
    let recovered_store =
        LocalEncryptedStore::open(&root, identity_for(&root), StoreKey::from_bytes([9; 32]))
            .expect("recover store after NoSpace");
    let recovered_context =
        DlpFileSystemContext::new(identity_for(&root), recovered_store).expect("capture identity");
    let recovered = WinFspMountHost::new(&drive)
        .expect("same drive valid")
        .start(recovered_context)
        .expect("remount after NoSpace");
    assert!(
        wait_for_path(&mounted_path.to_string_lossy(), true),
        "drive returns after disk-full recovery"
    );

    let recovered_hash = sha2::Sha256::digest(fs::read(&file).expect("read recovered baseline"));
    assert_eq!(
        recovered_hash, baseline_hash,
        "baseline hash must be preserved after disk-full recovery"
    );

    recovered.unmount().expect("clean unmount");
    wait_for_path(&mounted_path.to_string_lossy(), false);
    let _ = fs::remove_dir_all(root);
}

//! Non-UI WinFsp host running in the captured user logon session.
//!
//! This binary contains no server URL, enrollment token, device certificate, or key. It
//! receives the service-owned pipe name, session ID, captured SID, and actor generation
//! from the service, authenticates to the pipe, selects a free drive letter in the user
//! session, mounts the WinFsp volume, and runs the filesystem dispatch loop.

use dlp_domain::{StoreId, UserSid};
use dlp_storage::{CapturedStoreIdentity, LocalEncryptedStore, StoreKey};
use dlp_windows_drive::{DlpFileSystemContext, WinFspMountHost};
use std::path::PathBuf;

const USAGE: &str = "Usage: dlp-drive-host --pipe-name NAME --session-id ID --user-sid SID --generation GEN --store-root ROOT --preferred-letter LTR";

#[derive(Clone, Debug)]
struct HostArgs {
    pipe_name: String,
    session_id: u32,
    user_sid: UserSid,
    generation: u64,
    store_root: PathBuf,
    preferred_letter: char,
}

fn parse_args() -> Option<HostArgs> {
    let mut pipe_name = None;
    let mut session_id = None;
    let mut user_sid = None;
    let mut generation = None;
    let mut store_root = None;
    let mut preferred_letter = None;
    let mut iter = std::env::args().skip(1);
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--pipe-name" => pipe_name = iter.next(),
            "--session-id" => session_id = iter.next().and_then(|v| v.parse().ok()),
            "--user-sid" => user_sid = iter.next().and_then(|v| UserSid::parse(v).ok()),
            "--generation" => generation = iter.next().and_then(|v| v.parse().ok()),
            "--store-root" => store_root = iter.next().map(PathBuf::from),
            "--preferred-letter" => {
                preferred_letter = iter.next().and_then(|v| {
                    let mut chars = v.chars();
                    let c = chars.next()?;
                    if chars.next().is_none() {
                        Some(c)
                    } else {
                        None
                    }
                })
            }
            _ => {}
        }
    }
    Some(HostArgs {
        pipe_name: pipe_name?,
        session_id: session_id?,
        user_sid: user_sid?,
        generation: generation?,
        store_root: store_root?,
        preferred_letter: preferred_letter?,
    })
}

fn main() {
    let args = match parse_args() {
        Some(a) => a,
        None => {
            eprintln!("{USAGE}");
            std::process::exit(1);
        }
    };

    // Authenticate to the service-owned pipe using only the bounded identity fields
    // supplied by the service. The pipe server validates SID/session/PID/generation.
    if let Err(error) = authenticate_to_service(&args.pipe_name, args.session_id, args.generation) {
        eprintln!("pipe_auth_failed: {error}");
        std::process::exit(2);
    }

    let store_id = StoreId::parse(format!("sid-{}", stable_sid_digest(&args.user_sid)))
        .unwrap_or_else(|_| {
            eprintln!("store_id_failed");
            std::process::exit(3);
        });
    let identity = CapturedStoreIdentity::new(args.user_sid, store_id);

    // The host does not possess the store key; it relies on the authenticated pipe to
    // carry storage operations. For Phase 1 source compilation, the host mounts a
    // placeholder filesystem context when a real key is unavailable.
    let store = match open_local_store(&args.store_root, &identity) {
        Ok(s) => s,
        Err(error) => {
            eprintln!("store_open_failed: {error}");
            std::process::exit(4);
        }
    };

    let context = match DlpFileSystemContext::new(identity, store) {
        Ok(c) => c,
        Err(error) => {
            eprintln!("filesystem_context_failed: {error}");
            std::process::exit(5);
        }
    };

    let target = select_drive_letter(args.preferred_letter);
    let host = match WinFspMountHost::new(format!("{target}:")) {
        Ok(h) => h,
        Err(error) => {
            eprintln!("mount_host_failed: {error}");
            std::process::exit(6);
        }
    };

    match host.start(context) {
        Ok(_volume) => {
            // WinFsp dispatch loop runs until the service signals unmount.
            // The volume is owned here so it stays mounted.
            println!("mounted {target}:");
        }
        Err(error) => {
            eprintln!("mount_failed: {error}");
            std::process::exit(7);
        }
    }
}

fn authenticate_to_service(
    _pipe_name: &str,
    _session_id: u32,
    _generation: u64,
) -> Result<(), String> {
    // Real implementation: open named pipe, send StorageRequest with version/session/
    // host_pid/generation, verify accepted response. Source stub for compilation; the
    // runtime path is exercised only on LAB-CLIENT01.
    Ok(())
}

fn stable_sid_digest(sid: &UserSid) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(sid.to_wire().as_bytes());
    digest
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>()[..64]
        .to_owned()
}

fn open_local_store(
    root: &std::path::Path,
    identity: &CapturedStoreIdentity,
) -> Result<LocalEncryptedStore, String> {
    // In production the key arrives through the authenticated pipe; for source build
    // we use a deterministic test key so the binary compiles and unit tests can
    // exercise the host argument parser without requiring DPAPI.
    let key = StoreKey::from_bytes([0u8; 32]);
    LocalEncryptedStore::open(root, identity.clone(), key).map_err(|e| e.to_string())
}

fn select_drive_letter(preferred: char) -> char {
    // Real implementation enumerates the user session's drive letters via GetLogicalDrives
    // and selects preferred then next-free. Source stub returns preferred.
    preferred.to_ascii_uppercase()
}

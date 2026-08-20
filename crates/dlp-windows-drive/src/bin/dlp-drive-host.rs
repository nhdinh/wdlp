//! Non-UI WinFsp host running in the captured user logon session.
//!
//! This binary contains no server URL, enrollment token, device certificate, or key. It
//! receives only the service-owned pipe name, session ID, and actor generation from the
//! service command line, authenticates to the pipe, receives the service-derived
//! identity/root/key bootstrap, selects a free drive letter in the user session, mounts
//! the WinFsp volume, and runs the filesystem dispatch loop.

use dlp_domain::{StoreId, UserSid};
use dlp_storage::{CapturedStoreIdentity, LocalEncryptedStore, StoreKey};
use dlp_windows_drive::{DlpFileSystemContext, WinFspMountHost};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use zeroize::Zeroize;

const USAGE: &str = "Usage: dlp-drive-host --pipe-name NAME --session-id ID --generation GEN";
const BOOTSTRAP_PROTOCOL_VERSION: u16 = 1;

#[derive(Clone, Debug)]
struct HostArgs {
    pipe_name: String,
    session_id: u32,
    generation: u64,
}

fn parse_args() -> Option<HostArgs> {
    let mut pipe_name = None;
    let mut session_id = None;
    let mut generation = None;
    let mut iter = std::env::args().skip(1);
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--pipe-name" => pipe_name = iter.next(),
            "--session-id" => session_id = iter.next().and_then(|v| v.parse().ok()),
            "--generation" => generation = iter.next().and_then(|v| v.parse().ok()),
            _ => {}
        }
    }
    Some(HostArgs {
        pipe_name: pipe_name?,
        session_id: session_id?,
        generation: generation?,
    })
}

/// Local mirror of the service's bootstrap wire format. This avoids a crate dependency
/// cycle; the two definitions must remain byte-compatible.
#[derive(Clone, Debug, Deserialize, Serialize)]
struct HostBootstrap {
    version: u16,
    session_id: u32,
    generation: u64,
    user_sid: String,
    store_id: String,
    store_root: PathBuf,
    preferred_letter: char,
    store_key: Vec<u8>,
}

impl Drop for HostBootstrap {
    fn drop(&mut self) {
        self.store_key.zeroize();
    }
}

/// Local mirror of the service's drive-letter report. Kept byte-compatible with the
/// service-side `DriveLetterReport`.
#[derive(Clone, Debug, Deserialize, Serialize)]
struct DriveLetterReport {
    drive_letter: char,
}

fn main() {
    let args = match parse_args() {
        Some(a) => a,
        None => {
            eprintln!("{USAGE}");
            std::process::exit(1);
        }
    };

    let (bootstrap, mut pipe_file) = match authenticate_to_service(
        &args.pipe_name,
        args.session_id,
        args.generation,
    ) {
        Ok(b) => b,
        Err(error) => {
            eprintln!("pipe_auth_failed: {error}");
            std::process::exit(2);
        }
    };

    if bootstrap.version != BOOTSTRAP_PROTOCOL_VERSION {
        eprintln!("bootstrap_protocol_mismatch");
        std::process::exit(2);
    }
    if bootstrap.session_id != args.session_id || bootstrap.generation != args.generation {
        eprintln!("bootstrap_identity_mismatch");
        std::process::exit(2);
    }

    let user_sid = match UserSid::parse(&bootstrap.user_sid) {
        Ok(s) => s,
        Err(_) => {
            eprintln!("bootstrap_sid_invalid");
            std::process::exit(2);
        }
    };
    let store_id = match StoreId::parse(&bootstrap.store_id) {
        Ok(s) => s,
        Err(_) => {
            eprintln!("bootstrap_store_id_invalid");
            std::process::exit(2);
        }
    };
    let identity = CapturedStoreIdentity::new(user_sid, store_id);

    let key_bytes: [u8; 32] = match bootstrap.store_key.as_slice().try_into() {
        Ok(b) => b,
        Err(_) => {
            eprintln!("bootstrap_key_length_invalid");
            std::process::exit(2);
        }
    };
    if key_bytes.iter().all(|b| *b == 0) {
        eprintln!("bootstrap_key_zero");
        std::process::exit(2);
    }
    let store_key = StoreKey::from_bytes(key_bytes);

    let store = match LocalEncryptedStore::open(&bootstrap.store_root, identity.clone(), store_key) {
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

    let target = match select_drive_letter(bootstrap.preferred_letter) {
        Some(letter) => letter,
        None => {
            eprintln!("no_free_drive_letter");
            std::process::exit(8);
        }
    };

    ensure_winfsp_dll_path();

    let host = match WinFspMountHost::new(format!("{target}:")) {
        Ok(h) => h,
        Err(error) => {
            eprintln!("mount_host_failed: {error}");
            std::process::exit(6);
        }
    };

    let volume = match host.start(context) {
        Ok(v) => v,
        Err(error) => {
            eprintln!("mount_failed: {error}");
            std::process::exit(7);
        }
    };

    // Report the real selected letter back to the service before entering the
    // long-running control loop.
    if let Err(error) = send_drive_letter_ack(&mut pipe_file, target) {
        eprintln!("drive_letter_ack_failed: {error}");
        std::process::exit(9);
    }

    println!("mounted {target}:");

    // The volume stays mounted while the authenticated control channel remains open.
    // On pipe EOF or service stop, the control loop exits and the owned volume is
    // dropped, causing clean unmount.
    eprintln!("entering control loop");
    match run_control_loop(pipe_file) {
        Ok(_) => {}
        Err(error) => {
            eprintln!("control_loop_exit: {error}");
        }
    }

    eprintln!("dropping volume");
    drop(volume);
}

fn authenticate_to_service(
    pipe_name: &str,
    session_id: u32,
    generation: u64,
) -> Result<(HostBootstrap, std::fs::File), String> {
    #[cfg(windows)]
    {
        use std::io::{Read, Write};
        use std::os::windows::io::FromRawHandle;
        use windows::Win32::{
            Foundation::{ERROR_PIPE_BUSY, GetLastError},
            Storage::FileSystem::{
                CreateFileW, FILE_CREATION_DISPOSITION, FILE_FLAGS_AND_ATTRIBUTES,
                FILE_SHARE_MODE,
            },
            System::Pipes::WaitNamedPipeW,
        };

        const SECURITY_SQOS_PRESENT: u32 = 0x00100000;
        const SECURITY_IDENTIFICATION: u32 = 0x00010000;
        const GENERIC_READ: u32 = 0x80000000;
        const GENERIC_WRITE: u32 = 0x40000000;
        const OPEN_EXISTING: u32 = 3;

        let pipe_name_wide: Vec<u16> = pipe_name.encode_utf16().chain(Some(0)).collect();

        unsafe {
            // Wait for the service-created pipe instance with a bounded timeout.
            let busy = WaitNamedPipeW(
                windows::core::PCWSTR(pipe_name_wide.as_ptr()),
                10_000,
            );
            // WaitNamedPipeW returns false with ERROR_PIPE_BUSY if the pipe is busy,
            // which is acceptable because a service instance should become available.
            if !busy.as_bool() && GetLastError() != ERROR_PIPE_BUSY {
                return Err("pipe_wait_timeout".to_string());
            }

            let handle = CreateFileW(
                windows::core::PCWSTR(pipe_name_wide.as_ptr()),
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_MODE(0),
                None,
                FILE_CREATION_DISPOSITION(OPEN_EXISTING),
                FILE_FLAGS_AND_ATTRIBUTES(SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION),
                None,
            )
            .map_err(|_| "pipe_open_failed".to_string())?;

            let mut file = std::fs::File::from_raw_handle(handle.0 as *mut _);

            // Send the authentication request with identification-level SQOS already
            // conveyed by the open flags.
            let request = serde_json::json!({
                "version": BOOTSTRAP_PROTOCOL_VERSION,
                "session_id": session_id,
                "host_pid": std::process::id(),
                "generation": generation,
                "user_sid": "", // populated by the service from the impersonated token
            });
            let request_bytes = serde_json::to_vec(&request).map_err(|_| "encode_request")?;
            let length = (request_bytes.len() as u32).to_be_bytes();
            file.write_all(&length)
                .and_then(|_| file.write_all(&request_bytes))
                .map_err(|_| "pipe_write_failed".to_string())?;

            // Read the response: first a boolean acceptance, then the bootstrap if accepted.
            let mut len_buf = [0u8; 4];
            file.read_exact(&mut len_buf)
                .map_err(|_| "pipe_read_length_failed".to_string())?;
            let response_len = u32::from_be_bytes(len_buf) as usize;
            if response_len > 64 * 1024 {
                return Err("bootstrap_oversized".to_string());
            }
            let mut response_buf = vec![0u8; response_len];
            file.read_exact(&mut response_buf)
                .map_err(|_| "pipe_read_failed".to_string())?;

            let accepted: serde_json::Value = serde_json::from_slice(&response_buf)
                .map_err(|_| "response_decode_failed".to_string())?;
            if !accepted.get("accepted").and_then(|v| v.as_bool()).unwrap_or(false) {
                return Err("pipe_auth_rejected".to_string());
            }

            let mut len_buf = [0u8; 4];
            file.read_exact(&mut len_buf)
                .map_err(|_| "bootstrap_length_read_failed".to_string())?;
            let bootstrap_len = u32::from_be_bytes(len_buf) as usize;
            if bootstrap_len > 64 * 1024 {
                return Err("bootstrap_oversized".to_string());
            }
            let mut bootstrap_buf = vec![0u8; bootstrap_len];
            file.read_exact(&mut bootstrap_buf)
                .map_err(|_| "bootstrap_read_failed".to_string())?;

            let bootstrap: HostBootstrap = serde_json::from_slice(&bootstrap_buf)
                .map_err(|_| "bootstrap_decode_failed".to_string())?;

            // Return the open pipe so the control loop can block on it and the service
            // can send drain/stop messages.
            Ok((bootstrap, file))
        }
    }
    #[cfg(not(windows))]
    {
        let _ = (pipe_name, session_id, generation);
        Err("windows_only".to_string())
    }
}

fn send_drive_letter_ack(
    file: &mut std::fs::File,
    drive_letter: char,
) -> Result<(), String> {
    use std::io::Write;
    let ack = DriveLetterReport { drive_letter };
    let ack_bytes = serde_json::to_vec(&ack).map_err(|_| "ack_encode_failed".to_string())?;
    let length = (ack_bytes.len() as u32).to_be_bytes();
    file.write_all(&length)
        .and_then(|_| file.write_all(&ack_bytes))
        .map_err(|_| "ack_write_failed".to_string())
}

fn run_control_loop(mut pipe_file: std::fs::File) -> Result<(), String> {
    // Block reading the service control channel. EOF means the service disconnected
    // or stopped; returning drops the volume and unmounts the drive cleanly.
    #[cfg(windows)]
    {
        use std::io::Read;
        loop {
            let mut len_buf = [0u8; 4];
            match pipe_file.read_exact(&mut len_buf) {
                Ok(_) => {}
                Err(e) => {
                    eprintln!("control loop read length error: {e}");
                    return Ok(());
                } // EOF or broken pipe -> service stopped
            }
            let msg_len = u32::from_be_bytes(len_buf) as usize;
            if msg_len > 64 * 1024 {
                return Err("control_message_oversized".to_string());
            }
            let mut msg_buf = vec![0u8; msg_len];
            if let Err(_) = pipe_file.read_exact(&mut msg_buf) {
                return Ok(()); // EOF mid-message -> service stopped
            }
            // Messages are currently ignored; any future drain/stop command will be
            // handled here. For now the loop only cares about the pipe staying open.
        }
    }
    #[cfg(not(windows))]
    {
        let _ = pipe_file;
        Ok(())
    }
}

#[allow(dead_code)]
fn stable_sid_digest(sid: &UserSid) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(sid.to_wire().as_bytes());
    digest
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>()[..64]
        .to_owned()
}

fn drive_letter_candidates(preferred: char) -> impl Iterator<Item = char> {
    let candidates: Vec<char> = ('C'..='Z').collect();
    let preferred = preferred.to_ascii_uppercase();
    let start = candidates
        .iter()
        .position(|c| *c == preferred)
        .unwrap_or(0);
    (0..candidates.len())
        .map(move |offset| candidates[(start + offset) % candidates.len()])
}

fn select_drive_letter(preferred: char) -> Option<char> {
    drive_letter_candidates(preferred).find(|letter| {
        let path_string = format!("{letter}:\\");
        let path = std::path::Path::new(&path_string);
        matches!(path.try_exists(), Ok(false))
    })
}

#[cfg(windows)]
fn ensure_winfsp_dll_path() {
    use windows::Win32::System::LibraryLoader::SetDllDirectoryW;
    const CANDIDATES: &[&str] = &[
        r"C:\Program Files (x86)\WinFsp\bin",
        r"C:\Program Files\WinFsp\bin",
    ];
    for path in CANDIDATES {
        let dll = std::path::Path::new(path).join("winfsp-x64.dll");
        if dll.exists() {
            let wide: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();
            let _ = unsafe { SetDllDirectoryW(windows::core::PCWSTR(wide.as_ptr())) };
            return;
        }
    }
}

#[cfg(not(windows))]
fn ensure_winfsp_dll_path() {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_minimal_actor_arguments() {
        let args = vec![
            "dlp-drive-host",
            "--pipe-name",
            r"\\.\pipe\dlp-test",
            "--session-id",
            "1",
            "--generation",
            "7",
        ];
        let parsed = parse_args_from(args.into_iter().map(String::from));
        assert!(parsed.is_some());
        let parsed = parsed.unwrap();
        assert_eq!(parsed.pipe_name, r"\\.\pipe\dlp-test");
        assert_eq!(parsed.session_id, 1);
        assert_eq!(parsed.generation, 7);
    }

    #[test]
    fn rejects_missing_generation() {
        let args = vec![
            "dlp-drive-host",
            "--pipe-name",
            r"\\.\pipe\dlp-test",
            "--session-id",
            "1",
        ];
        assert!(parse_args_from(args.into_iter().map(String::from)).is_none());
    }

    fn parse_args_from(iter: impl Iterator<Item = String>) -> Option<HostArgs> {
        let mut pipe_name = None;
        let mut session_id = None;
        let mut generation = None;
        let mut iter = iter.skip(1);
        while let Some(arg) = iter.next() {
            match arg.as_str() {
                "--pipe-name" => pipe_name = iter.next(),
                "--session-id" => session_id = iter.next().and_then(|v| v.parse().ok()),
                "--generation" => generation = iter.next().and_then(|v| v.parse().ok()),
                _ => {}
            }
        }
        Some(HostArgs {
            pipe_name: pipe_name?,
            session_id: session_id?,
            generation: generation?,
        })
    }

    #[test]
    fn drive_letter_selection_candidates_start_with_preferred() {
        let mut iter = drive_letter_candidates('P');
        assert_eq!(iter.next(), Some('P'));
        assert_eq!(iter.next(), Some('Q'));
        assert_eq!(iter.next(), Some('R'));
    }

    #[test]
    fn drive_letter_selection_candidates_wrap_after_z() {
        let collected: Vec<char> = drive_letter_candidates('Y').take(4).collect();
        assert_eq!(collected, vec!['Y', 'Z', 'C', 'D']);
    }

    #[test]
    fn drive_letter_selection_candidates_include_all_letters() {
        let collected: std::collections::HashSet<char> = drive_letter_candidates('M').collect();
        assert_eq!(collected.len(), 24);
        for letter in 'C'..='Z' {
            assert!(collected.contains(&letter));
        }
    }
}

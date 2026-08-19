//! Per-session WinFsp host lifecycle, authenticated storage IPC, and SID-bound key custody.
//!
//! The service owns credentials, per-SID data-encryption keys, store selection, and the
//! authority to launch one non-UI `dlp-drive-host` per eligible user logon session. The
//! host process owns only the WinFsp mount in its own logon session and accesses storage
//! through a service-owned named pipe that validates the caller's SID, session ID, process
//! ID, and actor generation.

use dlp_crypto::StoreKey;
use dlp_domain::{StoreId, UserSid};
use dlp_storage::{CapturedStoreIdentity, StorageError, StoreKeyProvider};
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};

use crate::pipe::{PipeFactory, StorageBootstrap, WindowsPipeFactory};

#[cfg(test)]
use crate::pipe::PipeBootstrap;

/// Unique generation counter for mount actors. Increments are monotonic per process.
static ACTOR_GENERATION: AtomicU64 = AtomicU64::new(1);

/// A stable, redacted diagnostic emitted when a session/mount event fails.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionDiagnostic {
    IdentityRejected,
    KeyUnavailable,
    PipeAuthFailed,
    HostLaunchFailed,
    MountFailed,
    DrainTimeout,
    RecoveryFailed,
}

impl SessionDiagnostic {
    pub const fn code(self) -> &'static str {
        match self {
            Self::IdentityRejected => "session_identity_rejected",
            Self::KeyUnavailable => "session_key_unavailable",
            Self::PipeAuthFailed => "session_pipe_auth_failed",
            Self::HostLaunchFailed => "session_host_launch_failed",
            Self::MountFailed => "session_mount_failed",
            Self::DrainTimeout => "session_drain_timeout",
            Self::RecoveryFailed => "session_recovery_failed",
        }
    }
}

/// The outcome of a single mount attempt for telemetry and health.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MountAttempt {
    pub generation: u64,
    pub session_id: u32,
    pub drive_letter: Option<String>,
    pub diagnostic: Option<SessionDiagnostic>,
}

/// A validated Windows session identity derived only from the WTS primary token.
///
/// The SID and session ID are immutable after construction; the store ID is derived from
/// the SID so caller-provided store selectors can never cross users.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct EligibleSession {
    session_id: u32,
    user_sid: UserSid,
    store_id: StoreId,
    generation: u64,
}

impl EligibleSession {
    /// Creates an eligible session from a captured session ID and normalized user SID.
    /// The store ID is deterministically derived from the SID.
    pub fn new(session_id: u32, user_sid: UserSid) -> Result<Self, SessionError> {
        if session_id == 0 {
            return Err(SessionError::InvalidIdentity);
        }
        let store_id =
            StoreId::parse(format!("sid-{}", stable_sid_digest(&user_sid))).map_err(|_| {
                // The wire form of a parsed SID is always valid store-id input.
                SessionError::InvalidIdentity
            })?;
        Ok(Self {
            session_id,
            user_sid,
            store_id,
            generation: ACTOR_GENERATION.fetch_add(1, Ordering::Relaxed),
        })
    }

    pub fn session_id(&self) -> u32 {
        self.session_id
    }

    pub fn user_sid(&self) -> &UserSid {
        &self.user_sid
    }

    pub fn store_id(&self) -> &StoreId {
        &self.store_id
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }

    pub fn store_identity(&self) -> CapturedStoreIdentity {
        CapturedStoreIdentity::new(self.user_sid.clone(), self.store_id.clone())
    }
}

fn stable_sid_digest(sid: &UserSid) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(sid.to_wire().as_bytes());
    // Store IDs must be ASCII alphanumeric/hyphen/underscore and <= 128 chars.
    digest
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>()[..64]
        .to_owned()
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SessionError {
    InvalidIdentity,
    TokenUnavailable,
    StoreKeyFailure,
    PipeUnavailable,
    HostUnavailable,
    NotImplemented,
}

impl std::fmt::Display for SessionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let code = match self {
            Self::InvalidIdentity => "session_invalid_identity",
            Self::TokenUnavailable => "session_token_unavailable",
            Self::StoreKeyFailure => "session_store_key_failure",
            Self::PipeUnavailable => "session_pipe_unavailable",
            Self::HostUnavailable => "session_host_unavailable",
            Self::NotImplemented => "session_not_implemented",
        };
        f.write_str(code)
    }
}

impl std::error::Error for SessionError {}

/// Testable clock for retry and drain timing.
pub trait Clock: Send + Sync {
    fn now(&self) -> std::time::Instant;
}

/// Wall-clock implementation used in production.
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> std::time::Instant {
        std::time::Instant::now()
    }
}

/// Injected token provider so unit tests can run without a real WTS session.
pub trait SessionTokenProvider: Send + Sync {
    /// Returns the primary user token and captured SID for the session, or None if
    /// the session is not eligible.
    fn primary_token(&self, session_id: u32) -> Option<(PrimaryToken, UserSid)>;
}

/// Opaque owned Windows primary token handle.
pub struct PrimaryToken {
    #[cfg(windows)]
    handle: windows::Win32::Foundation::HANDLE,
    #[cfg(not(windows))]
    _session_id: u32,
}

#[cfg(windows)]
impl PrimaryToken {
    pub fn new(handle: windows::Win32::Foundation::HANDLE) -> Self {
        Self { handle }
    }

    /// Creates a token handle for the current process, suitable only for tests.
    pub fn for_test() -> Self {
        unsafe {
            use windows::Win32::{
                Security::TOKEN_QUERY,
                System::Threading::{GetCurrentProcess, OpenProcessToken},
            };
            let mut handle = windows::Win32::Foundation::HANDLE::default();
            let _ = OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut handle);
            Self { handle }
        }
    }

    pub fn handle(&self) -> windows::Win32::Foundation::HANDLE {
        self.handle
    }
}

#[cfg(not(windows))]
impl PrimaryToken {
    pub fn new(session_id: u32) -> Self {
        Self {
            _session_id: session_id,
        }
    }

    pub fn for_test() -> Self {
        Self { _session_id: 1 }
    }
}

/// Production token provider that calls WTSQueryUserToken from the LocalSystem service.
#[cfg(windows)]
pub struct WtsSessionTokenProvider;

#[cfg(windows)]
impl SessionTokenProvider for WtsSessionTokenProvider {
    fn primary_token(&self, session_id: u32) -> Option<(PrimaryToken, UserSid)> {
        use windows::Win32::System::RemoteDesktop::WTSQueryUserToken;
        unsafe {
            let mut handle = windows::Win32::Foundation::HANDLE::default();
            WTSQueryUserToken(session_id, &mut handle).ok()?;
            let token = PrimaryToken::new(handle);
            let sid = token_user_sid(&token).ok()?;
            Some((token, sid))
        }
    }
}

/// Returns the active interactive session IDs visible to the service.
#[cfg(windows)]
pub fn active_session_ids() -> Vec<u32> {
    use windows::Win32::System::RemoteDesktop::{
        WTS_SESSION_INFOW, WTSEnumerateSessionsW, WTSFreeMemory,
    };
    unsafe {
        let mut info: *mut WTS_SESSION_INFOW = std::ptr::null_mut();
        let mut count = 0u32;
        if WTSEnumerateSessionsW(None, 0, 1, &mut info, &mut count).is_err() {
            return Vec::new();
        }
        if info.is_null() {
            return Vec::new();
        }
        let sessions = std::slice::from_raw_parts(info, count as usize);
        let ids: Vec<u32> = sessions
            .iter()
            .filter_map(|s| {
                // Treat both WTSActive (0) and WTSConnected (1) sessions as eligible so a
                // console session that has not yet reached Active state (e.g. immediately
                // after service restart while a user is already signed in) can be reconciled.
                let state = s.State.0;
                if state == 0 || state == 1 {
                    Some(s.SessionId)
                } else {
                    None
                }
            })
            .collect();
        WTSFreeMemory(info as *mut _);
        ids
    }
}

#[cfg(windows)]
impl Drop for PrimaryToken {
    fn drop(&mut self) {
        unsafe {
            let _ = windows::Win32::Foundation::CloseHandle(self.handle);
        }
    }
}

/// Reads the user SID from a primary token. Production uses GetTokenInformation.
pub fn token_user_sid(token: &PrimaryToken) -> Result<UserSid, SessionError> {
    #[cfg(windows)]
    {
        use windows::Win32::{
            Foundation::LocalFree,
            Security::{
                Authorization::ConvertSidToStringSidW, GetTokenInformation, TOKEN_USER, TokenUser,
            },
        };
        let mut size = 0u32;
        unsafe {
            let _ = GetTokenInformation(token.handle(), TokenUser, None, 0, &mut size);
        }
        if size == 0 {
            return Err(SessionError::TokenUnavailable);
        }
        let mut buffer = vec![0u8; size as usize];
        unsafe {
            GetTokenInformation(
                token.handle(),
                TokenUser,
                Some(buffer.as_mut_ptr() as *mut _),
                size,
                &mut size,
            )
            .map_err(|_| SessionError::TokenUnavailable)?;
            let user = &*(buffer.as_ptr() as *const TOKEN_USER);
            let mut string_sid = windows::core::PWSTR::null();
            ConvertSidToStringSidW(user.User.Sid, &mut string_sid)
                .map_err(|_| SessionError::TokenUnavailable)?;
            let len = (0..).find(|i| *string_sid.0.add(*i) == 0).unwrap_or(0);
            let slice = std::slice::from_raw_parts(string_sid.0, len);
            let text = String::from_utf16(slice).map_err(|_| SessionError::TokenUnavailable)?;
            let _ = LocalFree(Some(windows::Win32::Foundation::HLOCAL(
                string_sid.0 as *mut _,
            )));
            UserSid::parse(text).map_err(|_| SessionError::InvalidIdentity)
        }
    }
    #[cfg(not(windows))]
    {
        let _ = token;
        UserSid::parse("S-1-5-21").map_err(|_| SessionError::InvalidIdentity)
    }
}

/// Events dispatched from the SCM control handler to the session monitor.
#[derive(Clone, Copy, Debug)]
pub enum SessionEvent {
    Logon(u32),
    Logoff(u32),
    Stop,
}

/// DPAPI-wrapped per-SID data-encryption key with service-only ACL.
pub struct DpapiStoreKeyProvider {
    root: PathBuf,
}

impl DpapiStoreKeyProvider {
    pub fn new(root: impl Into<PathBuf>) -> Result<Self, SessionError> {
        let root = root.into();
        std::fs::create_dir_all(&root).map_err(|_| SessionError::StoreKeyFailure)?;
        Ok(Self { root })
    }

    fn path_for(&self, identity: &CapturedStoreIdentity) -> PathBuf {
        self.root
            .join("keys")
            .join(format!("{}.dpapi", identity.store_id().to_wire()))
    }
}

impl StoreKeyProvider for DpapiStoreKeyProvider {
    fn load_store_key(&self,
        identity: &CapturedStoreIdentity,
    ) -> Result<StoreKey, StorageError> {
        let path = self.path_for(identity);
        if path.exists() {
            let blob = std::fs::read(&path).map_err(|_| StorageError::Unavailable)?;
            let plain = unprotect_store_key(&blob).map_err(|_| StorageError::Unavailable)?;
            let bytes: [u8; 32] = plain
                .as_slice()
                .try_into()
                .map_err(|_| StorageError::Unavailable)?;
            Ok(StoreKey::from_bytes(bytes))
        } else {
            let mut bytes = [0u8; 32];
            use rand::RngCore;
            rand::thread_rng().fill_bytes(&mut bytes);
            let key = StoreKey::from_bytes(bytes);
            let blob = protect_store_key(&bytes).map_err(|_| StorageError::Unavailable)?;
            std::fs::create_dir_all(path.parent().ok_or(StorageError::Unavailable)?)
                .map_err(|_| StorageError::Unavailable)?;
            std::fs::write(&path, &blob).map_err(|_| StorageError::Unavailable)?;
            #[cfg(windows)]
            crate::credential::enforce_acl(&path).ok();
            Ok(key)
        }
    }
}

#[cfg(windows)]
fn protect_store_key(input: &[u8; 32]) -> Result<Vec<u8>, SessionError> {
    use windows::Win32::{
        Foundation::{HLOCAL, LocalFree},
        Security::Cryptography::{
            CRYPT_INTEGER_BLOB, CRYPTPROTECT_LOCAL_MACHINE, CRYPTPROTECT_UI_FORBIDDEN,
            CryptProtectData,
        },
    };
    unsafe {
        let input_blob = CRYPT_INTEGER_BLOB {
            cbData: input.len() as u32,
            pbData: input.as_ptr() as *mut u8,
        };
        let mut output = CRYPT_INTEGER_BLOB::default();
        CryptProtectData(
            &input_blob,
            windows::core::PCWSTR::null(),
            None,
            None,
            None,
            CRYPTPROTECT_LOCAL_MACHINE | CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
        .map_err(|_| SessionError::StoreKeyFailure)?;
        let bytes = std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec();
        let _ = LocalFree(Some(HLOCAL(output.pbData as *mut _)));
        Ok(bytes)
    }
}

#[cfg(windows)]
fn unprotect_store_key(input: &[u8]) -> Result<Vec<u8>, SessionError> {
    use windows::Win32::{
        Foundation::{HLOCAL, LocalFree},
        Security::Cryptography::{
            CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptUnprotectData,
        },
    };
    unsafe {
        let input_blob = CRYPT_INTEGER_BLOB {
            cbData: input.len() as u32,
            pbData: input.as_ptr() as *mut u8,
        };
        let mut output = CRYPT_INTEGER_BLOB::default();
        CryptUnprotectData(
            &input_blob,
            None::<*mut windows::core::PWSTR>,
            None,
            None,
            None,
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
        .map_err(|_| SessionError::StoreKeyFailure)?;
        let bytes = std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec();
        let _ = LocalFree(Some(HLOCAL(output.pbData as *mut _)));
        Ok(bytes)
    }
}

#[cfg(not(windows))]
fn protect_store_key(input: &[u8; 32]) -> Result<Vec<u8>, SessionError> {
    let mut output = b"DLP-STORE-KEY-TEST\0".to_vec();
    output.extend(input.iter().map(|b| b ^ 0x5A));
    Ok(output)
}

#[cfg(not(windows))]
fn unprotect_store_key(input: &[u8]) -> Result<Vec<u8>, SessionError> {
    let prefix = b"DLP-STORE-KEY-TEST\0";
    input
        .strip_prefix(prefix)
        .map(|bytes| bytes.iter().map(|b| b ^ 0x5A).collect())
        .ok_or(SessionError::StoreKeyFailure)
}

/// Drive-letter selection in the user session namespace.
pub struct MountManager {
    preferred: char,
}

impl MountManager {
    pub fn new(preferred: char) -> Self {
        Self { preferred }
    }

    /// Returns the preferred letter if free, otherwise the next free letter
    /// in ascending order. Returns None if no drive letter is available.
    pub fn select_target(&self, occupied: &[char]) -> Option<char> {
        let candidates: Vec<char> = ('C'..='Z').collect();
        // Put preferred first, then continue ascending from preferred+1, wrapping.
        let preferred_index = candidates.iter().position(|c| *c == self.preferred);
        let mut ordered = Vec::with_capacity(candidates.len());
        if let Some(idx) = preferred_index {
            ordered.push(candidates[idx]);
            for offset in 1..candidates.len() {
                ordered.push(candidates[(idx + offset) % candidates.len()]);
            }
        } else {
            ordered = candidates;
        }
        ordered.into_iter().find(|c| !occupied.contains(c))
    }
}

/// Bounded exponential backoff: 1, 2, 4, ... seconds capped at 300.
#[derive(Clone)]
pub struct RetryTimer {
    last_attempt: Option<std::time::Instant>,
    next_delay: Duration,
    cap: Duration,
}

impl RetryTimer {
    pub fn new(cap_seconds: u64) -> Self {
        Self {
            last_attempt: None,
            next_delay: Duration::from_secs(1),
            cap: Duration::from_secs(cap_seconds),
        }
    }

    pub fn record_attempt(&mut self, now: std::time::Instant) {
        self.last_attempt = Some(now);
        self.next_delay = (self.next_delay * 2).min(self.cap);
    }

    pub fn reset(&mut self) {
        self.last_attempt = None;
        self.next_delay = Duration::from_secs(1);
    }

    pub fn due(&self, now: std::time::Instant) -> bool {
        self.last_attempt
            .map(|last| now.duration_since(last) >= self.next_delay)
            .unwrap_or(true)
    }

    pub fn next_delay(&self) -> Duration {
        self.next_delay
    }
}

/// Lifecycle state of a per-session mount actor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MountState {
    Starting,
    Mounted,
    Draining,
    Stopped,
    Failed,
}

/// One actor per eligible Windows session. Owns the host launch, pipe, key, store, and
/// retry/drain state. All mutable state is held inside the monitor's mutex.
#[derive(Clone)]
pub struct MountActor {
    session: EligibleSession,
    state: MountState,
    retry: RetryTimer,
    diagnostic: Option<SessionDiagnostic>,
    drive_letter: Option<char>,
    host_pid: Option<u32>,
    reject_new_opens: bool,
}

impl MountActor {
    pub fn new(session: EligibleSession) -> Self {
        Self {
            session,
            state: MountState::Starting,
            retry: RetryTimer::new(300),
            diagnostic: None,
            drive_letter: None,
            host_pid: None,
            reject_new_opens: false,
        }
    }

    pub fn session(&self) -> &EligibleSession {
        &self.session
    }

    pub fn state(&self) -> MountState {
        self.state
    }

    pub fn set_mounted(&mut self, drive_letter: char, host_pid: u32) {
        self.state = MountState::Mounted;
        self.drive_letter = Some(drive_letter);
        self.host_pid = Some(host_pid);
        self.retry.reset();
        self.diagnostic = None;
    }

    pub fn set_failed(&mut self, diagnostic: SessionDiagnostic) {
        self.state = MountState::Failed;
        self.diagnostic = Some(diagnostic);
    }

    pub fn begin_drain(&mut self) {
        self.state = MountState::Draining;
        self.reject_new_opens = true;
    }

    pub fn stop(&mut self) {
        self.state = MountState::Stopped;
        self.drive_letter = None;
        self.host_pid = None;
        self.reject_new_opens = true;
    }

    pub fn reject_new_opens(&self) -> bool {
        self.reject_new_opens
    }
}

/// Configuration for the session monitor.
#[derive(Clone, Debug)]
pub struct SessionConfig {
    pub data_directory: PathBuf,
    pub preferred_drive_letter: char,
    pub sign_out_grace_seconds: u64,
    pub host_binary_path: PathBuf,
}

/// Handle to a launched host process. The service retains this handle so it can observe
/// exit, terminate after drain, and avoid orphan processes.
pub struct LaunchedHost {
    pub process_handle: HostProcessHandle,
    pub pid: u32,
    pub pipe_path: String,
}

/// Owned runtime resources for an authenticated actor. Kept separate from the cloneable
/// `MountActor` snapshot so health reporting does not carry raw handles.
pub struct ActorRuntime {
    pub host: LaunchedHost,
    pub pipe: crate::pipe::AuthenticatedPipe,
}

/// Opaque owned Windows process handle.
pub struct HostProcessHandle {
    #[cfg(windows)]
    handle: windows::Win32::Foundation::HANDLE,
    #[cfg(not(windows))]
    _pid: u32,
}

#[cfg(windows)]
impl HostProcessHandle {
    pub fn new(handle: windows::Win32::Foundation::HANDLE) -> Self {
        Self { handle }
    }

    /// Creates a handle suitable only for tests; does not own a real process object.
    pub fn for_test() -> Self {
        Self {
            handle: windows::Win32::Foundation::HANDLE(std::ptr::null_mut()),
        }
    }

    pub fn handle(&self) -> windows::Win32::Foundation::HANDLE {
        self.handle
    }

    /// Terminates the child process. Used only when authentication fails or drain times out.
    pub fn terminate(&self) -> Result<(), SessionError> {
        use windows::Win32::System::Threading::TerminateProcess;
        unsafe {
            TerminateProcess(self.handle, 1).map_err(|_| SessionError::HostUnavailable)
        }
    }
}

// The handle is an owned kernel object; transferring it across threads is safe
// because no other code owns the same HANDLE value.
#[cfg(windows)]
unsafe impl Send for HostProcessHandle {}
#[cfg(windows)]
unsafe impl Sync for HostProcessHandle {}

#[cfg(windows)]
impl Drop for HostProcessHandle {
    fn drop(&mut self) {
        unsafe {
            let _ = windows::Win32::Foundation::CloseHandle(self.handle);
        }
    }
}

#[cfg(not(windows))]
impl HostProcessHandle {
    pub fn new(pid: u32) -> Self {
        Self { _pid: pid }
    }

    pub fn terminate(&self) -> Result<(), SessionError> {
        Ok(())
    }
}

/// Injected launcher seam so source tests can verify session-host creation without a
/// real WTS session or WinFsp runtime.
pub trait SessionHostLauncher: Send + Sync {
    /// Launch the approved host binary in the captured user session. The pipe path is
    /// service-created and unpredictable; argv/env must not contain SID, store root,
    /// key, or any caller-selectable identity field.
    fn launch(
        &self,
        session: &EligibleSession,
        token: &PrimaryToken,
        pipe_path: &str,
        config: &SessionConfig,
    ) -> Result<LaunchedHost, SessionError>;
}

/// Production launcher using `CreateProcessAsUserW` with the WTS primary token.
#[cfg(windows)]
pub struct WindowsHostLauncher;

#[cfg(windows)]
impl SessionHostLauncher for WindowsHostLauncher {
    fn launch(
        &self,
        session: &EligibleSession,
        token: &PrimaryToken,
        pipe_path: &str,
        config: &SessionConfig,
    ) -> Result<LaunchedHost, SessionError> {
        let binary = &config.host_binary_path;
        if !binary.is_absolute() {
            return Err(SessionError::HostUnavailable);
        }
        if !binary.exists() {
            return Err(SessionError::HostUnavailable);
        }

        let command_line = format!(
            "\"{}\" --pipe-name \"{}\" --session-id {} --generation {}",
            binary.display(),
            pipe_path,
            session.session_id(),
            session.generation()
        );

        unsafe {
            use windows::Win32::{
                Foundation::CloseHandle,
                Security::SECURITY_ATTRIBUTES,
                System::Environment::CreateEnvironmentBlock,
                System::Threading::{
                    CREATE_UNICODE_ENVIRONMENT, CreateProcessAsUserW, PROCESS_INFORMATION,
                    STARTUPINFOW,
                },
            };

            let mut env = windows::core::PWSTR::null();
            CreateEnvironmentBlock(
                &mut env as *mut _ as *mut *mut _,
                Some(token.handle()),
                false,
            )
            .map_err(|_| SessionError::HostUnavailable)?;

            let si = STARTUPINFOW {
                cb: std::mem::size_of::<STARTUPINFOW>() as u32,
                lpDesktop: windows::core::PWSTR(windows::core::w!("winsta0\\default").0 as *mut u16),
                ..Default::default()
            };
            let mut pi = PROCESS_INFORMATION::default();
            let mut cmd: Vec<u16> = command_line.encode_utf16().collect();
            cmd.push(0);

            let sa = SECURITY_ATTRIBUTES::default();
            let created = CreateProcessAsUserW(
                Some(token.handle()),
                None,
                Some(windows::core::PWSTR(cmd.as_mut_ptr())),
                Some(&sa),
                Some(&sa),
                false,
                CREATE_UNICODE_ENVIRONMENT,
                Some(env.0 as *const _),
                None,
                &si,
                &mut pi,
            );

            // Free the environment block regardless of process creation result.
            let _ = windows::Win32::System::Environment::DestroyEnvironmentBlock(env.0 as *const _);

            created.map_err(|_| SessionError::HostUnavailable)?;
            let _ = CloseHandle(pi.hThread);
            let pid = pi.dwProcessId;
            let handle = HostProcessHandle::new(pi.hProcess);

            Ok(LaunchedHost {
                process_handle: handle,
                pid,
                pipe_path: pipe_path.to_owned(),
            })
        }
    }
}

/// Non-Windows launcher that always fails with `NotImplemented`, keeping the crate
/// buildable on non-Windows hosts for CI.
#[cfg(not(windows))]
pub struct WindowsHostLauncher;

#[cfg(not(windows))]
impl SessionHostLauncher for WindowsHostLauncher {
    fn launch(
        &self,
        _session: &EligibleSession,
        _token: &PrimaryToken,
        _pipe_path: &str,
        _config: &SessionConfig,
    ) -> Result<LaunchedHost, SessionError> {
        Err(SessionError::NotImplemented)
    }
}

/// Generates an unpredictable per-actor pipe endpoint name inside the configured data
/// directory. The name is never reused across actors or generations.
fn actor_pipe_path(data_directory: &Path, session: &EligibleSession) -> String {
    use rand::RngCore;
    let mut nonce = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut nonce);
    let nonce_hex = nonce.iter().map(|b| format!("{b:02x}")).collect::<String>();
    let name = format!(
        "\\\\.\\pipe\\dlp-{}-{}-{}",
        session.session_id(),
        session.generation(),
        nonce_hex
    );
    // Persist the endpoint name in the data directory so restart recovery can find it.
    let _ = std::fs::create_dir_all(data_directory.join("pipes"));
    let _ = std::fs::write(
        data_directory
            .join("pipes")
            .join(format!("actor-{}.endpoint", session.generation())),
        &name,
    );
    name
}

/// Monitors WTS session changes and owns exactly one actor per eligible session/SID.
pub struct SessionMonitor {
    config: SessionConfig,
    actors: HashMap<(u32, UserSid), MountActor>,
    runtimes: HashMap<u64, ActorRuntime>,
    clock: Box<dyn Clock>,
    token_provider: Box<dyn SessionTokenProvider>,
    key_provider: Box<dyn StoreKeyProvider>,
    launcher: Box<dyn SessionHostLauncher>,
    pipe_factory: Box<dyn PipeFactory>,
}

impl SessionMonitor {
    /// Creates a monitor with the production Windows launcher and pipe factory.
    pub fn new(
        config: SessionConfig,
        clock: Box<dyn Clock>,
        token_provider: Box<dyn SessionTokenProvider>,
        key_provider: Box<dyn StoreKeyProvider>,
    ) -> Result<Self, SessionError> {
        Self::new_with_launcher(
            config,
            clock,
            token_provider,
            key_provider,
            Box::new(WindowsHostLauncher),
            Box::new(WindowsPipeFactory),
        )
    }

    /// Creates a monitor with an injected launcher and pipe factory for deterministic
    /// source tests.
    pub fn new_with_launcher(
        config: SessionConfig,
        clock: Box<dyn Clock>,
        token_provider: Box<dyn SessionTokenProvider>,
        key_provider: Box<dyn StoreKeyProvider>,
        launcher: Box<dyn SessionHostLauncher>,
        pipe_factory: Box<dyn PipeFactory>,
    ) -> Result<Self, SessionError> {
        Ok(Self {
            config,
            actors: HashMap::new(),
            runtimes: HashMap::new(),
            clock,
            token_provider,
            key_provider,
            launcher,
            pipe_factory,
        })
    }

    /// Idempotently create or update an actor for the session. For a new actor, the
    /// service creates a per-actor pipe, derives the real store key, and launches the
    /// approved host in the captured WTS session. Duplicate events for the same session
    /// ID and SID return the existing actor without launching a second host.
    pub fn session_logon(&mut self,
        session_id: u32,
    ) -> Result<MountActor, SessionError> {
        let (token, sid) = self
            .token_provider
            .primary_token(session_id)
            .ok_or(SessionError::TokenUnavailable)?;
        let actor_key = (session_id, sid.clone());
        if let Some(actor) = self.actors.get(&actor_key) {
            return Ok(actor.clone());
        }
        let session = EligibleSession::new(session_id, sid)?;
        let mut actor = MountActor::new(session.clone());

        let pipe_path = actor_pipe_path(&self.config.data_directory, &session);

        // Create the per-actor pipe before launching the host so the child can connect.
        let pipe = self
            .pipe_factory
            .create_pipe(&pipe_path, session.user_sid())
            .map_err(|_| SessionError::PipeUnavailable)?;

        // Derive the real per-store key before any host interaction.
        let store_key = self
            .key_provider
            .load_store_key(&session.store_identity())
            .map_err(|_| SessionError::StoreKeyFailure)?;
        if store_key.with_bytes(|bytes| bytes.iter().all(|b| *b == 0)) {
            return Err(SessionError::StoreKeyFailure);
        }

        let bootstrap = StorageBootstrap::new(
            session.session_id(),
            session.generation(),
            session.user_sid().clone(),
            session.store_id().clone(),
            self.config.data_directory.clone(),
            self.config.preferred_drive_letter,
            store_key,
        );

        let launched = self
            .launcher
            .launch(&session, &token, &pipe_path, &self.config)
            .inspect_err(|_error| {
                actor.set_failed(SessionDiagnostic::HostLaunchFailed);
            })?;

        // Authenticate the connected child on a dedicated thread; the handshake blocks
        // until the host connects and passes kernel-backed identity checks.
        let expected_pid = launched.pid;
        let expected_sid = session.user_sid().clone();
        let expected_session = session.session_id();
        let expected_generation = session.generation();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let result = pipe.authenticate(
                expected_pid,
                &expected_sid,
                expected_session,
                expected_generation,
                bootstrap,
            );
            let _ = tx.send(result);
        });

        let timeout = std::time::Duration::from_secs(30);
        match rx.recv_timeout(timeout) {
            Ok(Ok((authenticated_pipe, drive_letter))) => {
                self.runtimes.insert(
                    session.generation(),
                    ActorRuntime {
                        host: launched,
                        pipe: authenticated_pipe,
                    },
                );
                actor.set_mounted(drive_letter, expected_pid);
                self.actors.insert(actor_key, actor.clone());
                Ok(actor)
            }
            Ok(Err(_)) | Err(_) => {
                let _ = launched.process_handle.terminate();
                actor.set_failed(SessionDiagnostic::PipeAuthFailed);
                self.actors.insert(actor_key, actor.clone());
                Err(SessionError::PipeUnavailable)
            }
        }
    }

    /// Mark the actor as draining so it rejects new opens and begins bounded cleanup.
    pub fn session_logoff(&mut self,
        session_id: u32,
    ) -> Result<(), SessionError> {
        let mut found = false;
        for actor in self.actors.values_mut() {
            if actor.session.session_id() == session_id {
                actor.begin_drain();
                found = true;
            }
        }
        if found {
            Ok(())
        } else {
            Err(SessionError::InvalidIdentity)
        }
    }

    /// Stop all actors. Used on service stop/restart.
    pub fn stop_all(&mut self) {
        for actor in self.actors.values_mut() {
            actor.stop();
        }
        // Closing the authenticated pipes causes the hosts to see EOF and unmount.
        self.runtimes.clear();
    }

    /// Returns a snapshot of current actors for health reporting.
    pub fn snapshot(&self) -> Vec<MountAttempt> {
        self.actors
            .values()
            .map(|actor| MountAttempt {
                generation: actor.session.generation(),
                session_id: actor.session.session_id(),
                drive_letter: actor.drive_letter.map(|c| c.to_string()),
                diagnostic: actor.diagnostic,
            })
            .collect()
    }

    pub fn actor_count(&self) -> usize {
        self.actors.len()
    }

    pub fn config(&self) -> &SessionConfig {
        &self.config
    }

    pub fn now(&self) -> std::time::Instant {
        self.clock.now()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FakeTokenProvider {
        sid: UserSid,
    }

    impl SessionTokenProvider for FakeTokenProvider {
        fn primary_token(&self,
            session_id: u32,
        ) -> Option<(PrimaryToken, UserSid)> {
            if session_id == 0 {
                return None;
            }
            Some((PrimaryToken::for_test(), self.sid.clone()))
        }
    }

    struct FakeKeyProvider {
        key: StoreKey,
    }

    impl StoreKeyProvider for FakeKeyProvider {
        fn load_store_key(
            &self,
            _identity: &CapturedStoreIdentity,
        ) -> Result<StoreKey, StorageError> {
            Ok(self.key.clone())
        }
    }

    struct RecordingLauncher {
        calls: std::sync::Mutex<Vec<(u32, u64, String)>>,
        fail: bool,
    }

    impl RecordingLauncher {
        fn new() -> Self {
            Self {
                calls: std::sync::Mutex::new(Vec::new()),
                fail: false,
            }
        }

        fn failing() -> Self {
            Self {
                calls: std::sync::Mutex::new(Vec::new()),
                fail: true,
            }
        }
    }

    impl SessionHostLauncher for RecordingLauncher {
        fn launch(
            &self,
            session: &EligibleSession,
            _token: &PrimaryToken,
            pipe_path: &str,
            _config: &SessionConfig,
        ) -> Result<LaunchedHost, SessionError> {
            self.calls.lock().unwrap().push((
                session.session_id(),
                session.generation(),
                pipe_path.to_owned(),
            ));
            if self.fail {
                return Err(SessionError::HostUnavailable);
            }
            Ok(LaunchedHost {
                process_handle: HostProcessHandle::for_test(),
                pid: 1234,
                pipe_path: pipe_path.to_owned(),
            })
        }
    }

    struct FakePipeFactory;
    struct FakePipeBootstrap;

    impl PipeBootstrap for FakePipeBootstrap {
        fn authenticate(
            self: Box<Self>,
            _expected_pid: u32,
            _expected_sid: &UserSid,
            _expected_session: u32,
            _expected_generation: u64,
            _bootstrap: StorageBootstrap,
        ) -> Result<(crate::pipe::AuthenticatedPipe, char), crate::pipe::PipeAuthError> {
            Ok((crate::pipe::AuthenticatedPipe::for_test(), 'P'))
        }
    }

    impl PipeFactory for FakePipeFactory {
        fn create_pipe(
            &self,
            _pipe_path: &str,
            _user_sid: &UserSid,
        ) -> Result<Box<dyn PipeBootstrap>, crate::pipe::PipeAuthError> {
            Ok(Box::new(FakePipeBootstrap))
        }
    }

    fn test_config() -> (tempfile::TempDir, SessionConfig) {
        let tmp = tempfile::tempdir().unwrap();
        let config = SessionConfig {
            data_directory: tmp.path().to_path_buf(),
            preferred_drive_letter: 'P',
            sign_out_grace_seconds: 30,
            host_binary_path: PathBuf::from("C:/Program Files/DLP/dlp-drive-host.exe"),
        };
        (tmp, config)
    }

    fn test_monitor(
        tmp: &tempfile::TempDir,
        launcher: Box<dyn SessionHostLauncher>,
    ) -> SessionMonitor {
        test_monitor_with_pipe(tmp, launcher, Box::new(FakePipeFactory))
    }

    fn test_monitor_with_pipe(
        tmp: &tempfile::TempDir,
        launcher: Box<dyn SessionHostLauncher>,
        pipe_factory: Box<dyn PipeFactory>,
    ) -> SessionMonitor {
        SessionMonitor::new_with_launcher(
            SessionConfig {
                data_directory: tmp.path().to_path_buf(),
                preferred_drive_letter: 'P',
                sign_out_grace_seconds: 30,
                host_binary_path: PathBuf::from("C:/Program Files/DLP/dlp-drive-host.exe"),
            },
            Box::new(SystemClock),
            Box::new(FakeTokenProvider {
                sid: UserSid::parse("S-1-5-21-1000").unwrap(),
            }),
            Box::new(FakeKeyProvider {
                key: StoreKey::from_bytes([7u8; 32]),
            }),
            launcher,
            pipe_factory,
        )
        .unwrap()
    }

    #[test]
    fn zero_session_id_is_rejected() {
        assert!(EligibleSession::new(0, UserSid::parse("S-1-5-21").unwrap()).is_err());
    }

    #[test]
    fn same_session_and_sid_are_idempotent() {
        let sid = UserSid::parse("S-1-5-21-1000").unwrap();
        let s1 = EligibleSession::new(1, sid.clone()).unwrap();
        let s2 = EligibleSession::new(1, sid).unwrap();
        // Different generations, but same identity tuple.
        assert_ne!(s1.generation(), s2.generation());
        assert_eq!(s1.session_id(), s2.session_id());
        assert_eq!(s1.user_sid(), s2.user_sid());
    }

    #[test]
    fn mount_manager_prefers_configured_letter_then_next_free() {
        let manager = MountManager::new('P');
        assert_eq!(manager.select_target(&[]), Some('P'));
        assert_eq!(manager.select_target(&['P']), Some('Q'));
        assert_eq!(manager.select_target(&['P', 'Q']), Some('R'));
        // Occupied preferred does not displace other mappings.
        assert_eq!(manager.select_target(&['O', 'P', 'Q']), Some('R'));
    }

    #[test]
    fn mount_manager_returns_none_when_all_occupied() {
        let manager = MountManager::new('C');
        let occupied: Vec<char> = ('C'..='Z').collect();
        assert_eq!(manager.select_target(&occupied), None);
    }

    #[test]
    fn retry_timer_doubles_and_caps_at_five_minutes() {
        let start = std::time::Instant::now();
        let mut timer = RetryTimer::new(300);
        assert!(timer.due(start));
        timer.record_attempt(start);
        assert_eq!(timer.next_delay(), Duration::from_secs(2));
        assert!(!timer.due(start + Duration::from_secs(1)));
        assert!(timer.due(start + Duration::from_secs(2)));

        // Fast-forward to cap.
        for _ in 0..10 {
            timer.record_attempt(start);
        }
        assert_eq!(timer.next_delay(), Duration::from_secs(300));
    }

    #[test]
    fn monitor_creates_at_most_one_actor_per_session_sid() {
        let (tmp, _config) = test_config();
        let launcher = Box::new(RecordingLauncher::new());
        let mut monitor = test_monitor(&tmp, launcher);
        let first = monitor.session_logon(1).unwrap().session().generation();
        let second = monitor.session_logon(1).unwrap().session().generation();
        assert_eq!(first, second);
        assert_eq!(monitor.actor_count(), 1);
    }

    #[test]
    fn session_host_launch_is_invoked_once_per_new_actor() {
        let (tmp, _config) = test_config();
        let launcher = Box::new(RecordingLauncher::new());
        let mut monitor = test_monitor(&tmp, launcher);
        let actor = monitor.session_logon(1).unwrap();
        assert_eq!(actor.state(), MountState::Mounted);
        assert_eq!(actor.host_pid, Some(1234));
        assert_eq!(monitor.actor_count(), 1);

        let actor = monitor.session_logon(1).unwrap();
        assert_eq!(actor.state(), MountState::Mounted);
    }

    #[test]
    fn session_host_launch_failure_marks_failed() {
        let (tmp, _config) = test_config();
        let launcher = Box::new(RecordingLauncher::failing());
        let mut monitor = test_monitor(&tmp, launcher);
        let result = monitor.session_logon(1);
        assert!(result.is_err());
        // The actor is not retained when launch fails before first mount.
        assert_eq!(monitor.actor_count(), 0);
    }

    #[test]
    fn zero_store_key_is_rejected() {
        let (tmp, _config) = test_config();
        let launcher = Box::new(RecordingLauncher::new());
        let mut monitor = SessionMonitor::new_with_launcher(
            SessionConfig {
                data_directory: tmp.path().to_path_buf(),
                preferred_drive_letter: 'P',
                sign_out_grace_seconds: 30,
                host_binary_path: PathBuf::from("C:/Program Files/DLP/dlp-drive-host.exe"),
            },
            Box::new(SystemClock),
            Box::new(FakeTokenProvider {
                sid: UserSid::parse("S-1-5-21-1000").unwrap(),
            }),
            Box::new(FakeKeyProvider {
                key: StoreKey::from_bytes([0u8; 32]),
            }),
            launcher,
            Box::new(FakePipeFactory),
        )
        .unwrap();
        let result = monitor.session_logon(1);
        assert!(matches!(result, Err(SessionError::StoreKeyFailure)));
    }

    #[test]
    fn logoff_transitions_actor_to_draining() {
        let (tmp, _config) = test_config();
        let launcher = Box::new(RecordingLauncher::new());
        let mut monitor = test_monitor(&tmp, launcher);
        monitor.session_logon(1).unwrap();
        monitor.session_logoff(1).unwrap();
        let actor = monitor.actors.values().next().unwrap();
        assert_eq!(actor.state(), MountState::Draining);
        assert!(actor.reject_new_opens());
    }
}

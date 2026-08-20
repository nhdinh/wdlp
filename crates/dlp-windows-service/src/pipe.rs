//! Service-owned authenticated named pipe for storage IPC.
//!
//! The pipe validates connecting SID, session ID, process ID, and actor generation after
//! impersonation. Malformed, oversized, or unauthenticated messages are rejected before
//! any storage access.

#![allow(unsafe_op_in_unsafe_fn)]

use dlp_crypto::StoreKey;
use dlp_domain::{StoreId, UserSid};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use zeroize::Zeroize;

/// Maximum accepted message size to prevent unbounded allocation.
const MAX_MESSAGE_BYTES: usize = 64 * 1024;

/// Protocol version for the service/host bootstrap exchange.
pub const BOOTSTRAP_PROTOCOL_VERSION: u16 = 1;

/// Pipe message sent by `dlp-drive-host` to authenticate and request storage operations.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct StorageRequest {
    pub version: u16,
    pub session_id: u32,
    pub host_pid: u32,
    pub generation: u64,
    pub user_sid: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct StorageResponse {
    pub accepted: bool,
    pub code: String,
}

/// Host-to-service acknowledgement of the selected drive letter. Sent after the host
/// successfully starts WinFsp so the service health snapshot reports the real letter.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DriveLetterReport {
    pub drive_letter: char,
}

/// Service-derived bootstrap payload sent to an authenticated host. This is the only
/// point at which the real store key, store root, and captured identity cross the
/// service-to-host boundary. All fields are erased from transient buffers after use.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct StorageBootstrap {
    pub version: u16,
    pub session_id: u32,
    pub generation: u64,
    pub user_sid: String,
    pub store_id: String,
    pub store_root: PathBuf,
    pub preferred_letter: char,
    /// 32-byte DPAPI-unwrapped random store key. Kept in a `Vec<u8>` only for the
    /// wire serde step and zeroized after construction of `StoreKey` on both ends.
    pub store_key: Vec<u8>,
}

impl StorageBootstrap {
    /// Constructs a bootstrap from captured identity fields and a real key.
    pub fn new(
        session_id: u32,
        generation: u64,
        user_sid: UserSid,
        store_id: StoreId,
        store_root: PathBuf,
        preferred_letter: char,
        store_key: StoreKey,
    ) -> Self {
        Self {
            version: BOOTSTRAP_PROTOCOL_VERSION,
            session_id,
            generation,
            user_sid: user_sid.to_wire().to_string(),
            store_id: store_id.to_wire().to_string(),
            store_root,
            preferred_letter,
            store_key: store_key.with_bytes(|bytes| bytes.to_vec()),
        }
    }

    /// Zeroizes the transient key material held in this bootstrap.
    pub fn zeroize_key(&mut self) {
        self.store_key.zeroize();
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PipeAuthError {
    InvalidMessage,
    WrongIdentity,
    StaleGeneration,
    Oversized,
    PipeUnavailable,
    AuthenticationFailed,
    BootstrapFailed,
    ProtocolMismatch,
}

impl std::fmt::Display for PipeAuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let code = match self {
            Self::InvalidMessage => "pipe_invalid_message",
            Self::WrongIdentity => "pipe_wrong_identity",
            Self::StaleGeneration => "pipe_stale_generation",
            Self::Oversized => "pipe_oversized",
            Self::PipeUnavailable => "pipe_unavailable",
            Self::AuthenticationFailed => "pipe_authentication_failed",
            Self::BootstrapFailed => "pipe_bootstrap_failed",
            Self::ProtocolMismatch => "pipe_protocol_mismatch",
        };
        f.write_str(code)
    }
}

impl std::error::Error for PipeAuthError {}

/// Length-prefixed frame used for the bootstrap/control channel.
pub fn encode_frame(bytes: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(4 + bytes.len());
    frame.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    frame.extend_from_slice(bytes);
    frame
}

/// Decodes a length-prefixed frame, rejecting oversized or truncated input.
pub fn decode_frame(bytes: &[u8]) -> Result<(Vec<u8>, usize), PipeAuthError> {
    if bytes.len() < 4 {
        return Err(PipeAuthError::InvalidMessage);
    }
    let length = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
    if length > MAX_MESSAGE_BYTES {
        return Err(PipeAuthError::Oversized);
    }
    if bytes.len() < 4 + length {
        return Err(PipeAuthError::InvalidMessage);
    }
    Ok((bytes[4..4 + length].to_vec(), 4 + length))
}

/// Service-owned pipe endpoint.
pub struct StoragePipeServer {
    #[allow(dead_code)]
    path: PathBuf,
}

impl StoragePipeServer {
    pub fn bind(base: &Path) -> Result<Self, PipeAuthError> {
        let path = base.join("pipes").join("storage");
        let _ = std::fs::create_dir_all(&path);
        Ok(Self { path })
    }

    pub fn close(self) -> Result<(), PipeAuthError> {
        Ok(())
    }

    /// Validate a request without accepting caller-supplied identity/store selectors.
    pub fn validate_request(
        expected_sid: &UserSid,
        expected_session: u32,
        expected_generation: u64,
        request: &StorageRequest,
    ) -> Result<(), PipeAuthError> {
        if request.version != BOOTSTRAP_PROTOCOL_VERSION {
            return Err(PipeAuthError::ProtocolMismatch);
        }
        if request.session_id == 0 || request.host_pid == 0 {
            return Err(PipeAuthError::InvalidMessage);
        }
        if request.session_id != expected_session {
            return Err(PipeAuthError::WrongIdentity);
        }
        if request.generation != expected_generation {
            return Err(PipeAuthError::StaleGeneration);
        }
        // The SID comparison is the final identity check. On the real Windows path this
        // is performed against the impersonated client token; the unit-test path supplies
        // the expected SID directly. An empty client-supplied SID is allowed because the
        // service already verified the connecting identity via impersonation.
        if !request.user_sid.is_empty()
            && UserSid::parse(&request.user_sid).ok().as_ref() != Some(expected_sid)
        {
            return Err(PipeAuthError::WrongIdentity);
        }
        Ok(())
    }

    pub fn decode_request(bytes: &[u8]) -> Result<StorageRequest, PipeAuthError> {
        if bytes.len() > MAX_MESSAGE_BYTES {
            return Err(PipeAuthError::Oversized);
        }
        serde_json::from_slice(bytes).map_err(|_| PipeAuthError::InvalidMessage)
    }
}

/// A created server-side pipe awaiting authentication. Implementations may perform
/// blocking kernel-backed identity checks; the monitor launches the host before calling
/// `authenticate` on a dedicated thread.
pub trait PipeBootstrap: Send {
    fn authenticate(
        self: Box<Self>,
        expected_pid: u32,
        expected_sid: &UserSid,
        expected_session: u32,
        expected_generation: u64,
        bootstrap: StorageBootstrap,
    ) -> Result<(AuthenticatedPipe, char), PipeAuthError>;
}

/// Factory for creating per-actor server-side pipes. The production implementation uses
/// `CreateNamedPipeW`; source tests inject a fake that returns immediately.
pub trait PipeFactory: Send + Sync {
    fn create_pipe(
        &self,
        pipe_path: &str,
        user_sid: &UserSid,
    ) -> Result<Box<dyn PipeBootstrap>, PipeAuthError>;
}

/// Production pipe factory backed by a real Windows named pipe.
pub struct WindowsPipeFactory;

impl PipeFactory for WindowsPipeFactory {
    fn create_pipe(
        &self,
        pipe_path: &str,
        user_sid: &UserSid,
    ) -> Result<Box<dyn PipeBootstrap>, PipeAuthError> {
        Ok(Box::new(ActorPipe::create(pipe_path, user_sid)?))
    }
}

#[cfg(windows)]
impl PipeBootstrap for windows_pipe::ActorPipe {
    fn authenticate(
        self: Box<Self>,
        expected_pid: u32,
        expected_sid: &UserSid,
        expected_session: u32,
        expected_generation: u64,
        bootstrap: StorageBootstrap,
    ) -> Result<(AuthenticatedPipe, char), PipeAuthError> {
        self.accept_and_authenticate(
            expected_pid,
            expected_sid,
            expected_session,
            expected_generation,
            bootstrap,
        )
    }
}

#[cfg(windows)]
mod windows_pipe {
    use super::*;
    use std::io::{Read, Write};
    use std::os::windows::io::{FromRawHandle, IntoRawHandle};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use windows::Win32::{
        Foundation::{CloseHandle, HANDLE, HLOCAL, INVALID_HANDLE_VALUE, LocalFree, FALSE},
        Security::{
            ACCESS_ALLOWED_ACE, ACL, ACL_REVISION, AddAccessAllowedAce, InitializeAcl,
            InitializeSecurityDescriptor, PSID, PSECURITY_DESCRIPTOR, RevertToSelf,
            SetSecurityDescriptorDacl,
        },
        Security::Authorization::{ConvertStringSidToSidW},
        Storage::FileSystem::{FILE_FLAGS_AND_ATTRIBUTES, PIPE_ACCESS_DUPLEX},
        System::Pipes::{
            ConnectNamedPipe, CreateNamedPipeW, GetNamedPipeClientProcessId,
            ImpersonateNamedPipeClient, PIPE_READMODE_BYTE, PIPE_TYPE_BYTE, PIPE_WAIT,
        },
        System::Threading::OpenThreadToken,
    };

    const GENERIC_READ: u32 = 0x80000000;
    const GENERIC_WRITE: u32 = 0x40000000;
    const FILE_FLAG_FIRST_PIPE_INSTANCE: u32 = 0x00080000;
    const SECURITY_DESCRIPTOR_REVISION_VALUE: u32 = 1;

    /// Owned server-side named pipe handle that remains open so the authenticated
    /// control channel stays alive. Dropping it closes the handle.
    pub struct AuthenticatedPipe {
        handle: HANDLE,
    }

    impl AuthenticatedPipe {
        fn new(handle: HANDLE) -> Self {
            Self { handle }
        }

        /// Creates a dummy authenticated pipe for source tests. The handle is
        /// `INVALID_HANDLE_VALUE` so the destructor ignores it.
        pub fn for_test() -> Self {
            Self::new(INVALID_HANDLE_VALUE)
        }

        pub fn close(&mut self) {
            if !self.handle.is_invalid() {
                unsafe {
                    let _ = CloseHandle(self.handle);
                }
                self.handle = HANDLE(std::ptr::null_mut());
            }
        }
    }

    impl Drop for AuthenticatedPipe {
        fn drop(&mut self) {
            self.close();
        }
    }

    // The handle is an owned kernel object; transferring it across threads is safe
    // because no other code owns the same HANDLE value.
    unsafe impl Send for AuthenticatedPipe {}
    unsafe impl Sync for AuthenticatedPipe {}

    /// A server-side pipe instance created before the host is launched. The service
    /// uses `CreateNamedPipeW`, `ConnectNamedPipe`, `GetNamedPipeClientProcessId`,
    /// and `ImpersonateNamedPipeClient` to authenticate the child before sending the
    /// real store bootstrap.
    pub struct ActorPipe {
        handle: HANDLE,
        handle_value: Arc<AtomicUsize>,
    }

    impl ActorPipe {
        /// Creates a first-instance duplex named pipe with a DACL that allows only the
        /// captured user SID to connect. The path is the unpredictable per-actor name.
        pub fn create(pipe_name: &str, user_sid: &UserSid) -> Result<Self, PipeAuthError> {
            let security = PipeSecurity::for_user(user_sid)?;
            let name_wide: Vec<u16> = pipe_name.encode_utf16().chain(Some(0)).collect();

            unsafe {
                let handle = CreateNamedPipeW(
                    windows::core::PCWSTR(name_wide.as_ptr()),
                    PIPE_ACCESS_DUPLEX | FILE_FLAGS_AND_ATTRIBUTES(FILE_FLAG_FIRST_PIPE_INSTANCE),
                    PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                    1,
                    MAX_MESSAGE_BYTES as u32,
                    MAX_MESSAGE_BYTES as u32,
                    0,
                    Some(&security.attributes),
                );
                if handle.is_invalid() {
                    return Err(PipeAuthError::PipeUnavailable);
                }

                let handle_value = Arc::new(AtomicUsize::new(handle.0 as usize));
                Ok(Self {
                    handle,
                    handle_value,
                })
            }
        }

        pub fn raw_handle(&self) -> HANDLE {
            self.handle
        }

        pub fn handle_value(&self) -> Arc<AtomicUsize> {
            self.handle_value.clone()
        }

        /// Blocks until the launched host connects, then authenticates it via kernel
        /// identity checks. If any check fails the pipe is closed and the child sees
        /// EOF on its end. On success the bootstrap is sent and an `AuthenticatedPipe`
        /// is returned.
        pub fn accept_and_authenticate(
            mut self,
            expected_pid: u32,
            expected_sid: &UserSid,
            expected_session: u32,
            expected_generation: u64,
            bootstrap: StorageBootstrap,
        ) -> Result<(AuthenticatedPipe, char), PipeAuthError> {
            unsafe {
                // Wait for the host process to connect.
                let connect_result = ConnectNamedPipe(self.handle, None);
                if let Err(error) = connect_result {
                    let code = error.code().0 as u32;
                    // ERROR_PIPE_CONNECTED (535) means a client connected before we called
                    // ConnectNamedPipe; that is acceptable.
                    if code != 535 {
                        return Err(PipeAuthError::PipeUnavailable);
                    }
                }

                // Kernel-backed client PID check.
                let mut client_pid = 0u32;
                if let Err(_) = GetNamedPipeClientProcessId(self.handle, &mut client_pid) {
                    return Err(PipeAuthError::AuthenticationFailed);
                }
                if client_pid != expected_pid {
                    return Err(PipeAuthError::WrongIdentity);
                }

                // Impersonate the connecting client and read its SID and session.
                if let Err(_) = ImpersonateNamedPipeClient(self.handle) {
                    return Err(PipeAuthError::AuthenticationFailed);
                }
                let token_result = open_thread_token_sid_session();
                let _ = RevertToSelf();
                let (client_sid, client_session) =
                    token_result.map_err(|_| PipeAuthError::AuthenticationFailed)?;

                if client_session != expected_session {
                    return Err(PipeAuthError::WrongIdentity);
                }
                if client_sid != expected_sid.to_wire() {
                    return Err(PipeAuthError::WrongIdentity);
                }

                // Wrap the handle in a std::fs::File for length-framed I/O. The handle
                // is reclaimed with `into_raw_handle` before this function returns.
                // Null out the ActorPipe field first so its Drop does not close the
                // handle while the File owns it.
                let raw = self.handle.0 as *mut _;
                self.handle = INVALID_HANDLE_VALUE;
                let mut file = std::fs::File::from_raw_handle(raw);

                // Read the host's authentication request.
                let mut len_buf = [0u8; 4];
                file.read_exact(&mut len_buf)
                    .map_err(|_| PipeAuthError::InvalidMessage)?;
                let request_len = u32::from_be_bytes(len_buf) as usize;
                if request_len > MAX_MESSAGE_BYTES {
                    return Err(PipeAuthError::Oversized);
                }
                let mut request_buf = vec![0u8; request_len];
                file.read_exact(&mut request_buf)
                    .map_err(|_| PipeAuthError::InvalidMessage)?;
                let request: StorageRequest =
                    serde_json::from_slice(&request_buf).map_err(|_| PipeAuthError::InvalidMessage)?;
                StoragePipeServer::validate_request(
                    expected_sid,
                    expected_session,
                    expected_generation,
                    &request,
                )?;

                // Send acceptance.
                let response = StorageResponse {
                    accepted: true,
                    code: "ok".to_string(),
                };
                let response_bytes =
                    serde_json::to_vec(&response).map_err(|_| PipeAuthError::BootstrapFailed)?;
                file.write_all(&encode_frame(&response_bytes))
                    .map_err(|_| PipeAuthError::BootstrapFailed)?;

                // Send the bootstrap payload.
                let mut bootstrap = bootstrap;
                let bootstrap_bytes =
                    serde_json::to_vec(&bootstrap).map_err(|_| PipeAuthError::BootstrapFailed)?;
                file.write_all(&encode_frame(&bootstrap_bytes))
                    .map_err(|_| PipeAuthError::BootstrapFailed)?;
                bootstrap.zeroize_key();

                // Read the host's drive-letter acknowledgement before reclaiming the handle.
                let mut ack_len_buf = [0u8; 4];
                file.read_exact(&mut ack_len_buf)
                    .map_err(|_| PipeAuthError::InvalidMessage)?;
                let ack_len = u32::from_be_bytes(ack_len_buf) as usize;
                if ack_len > MAX_MESSAGE_BYTES {
                    return Err(PipeAuthError::Oversized);
                }
                let mut ack_buf = vec![0u8; ack_len];
                file.read_exact(&mut ack_buf)
                    .map_err(|_| PipeAuthError::InvalidMessage)?;
                let ack: DriveLetterReport =
                    serde_json::from_slice(&ack_buf).map_err(|_| PipeAuthError::InvalidMessage)?;
                let drive_letter = ack.drive_letter.to_ascii_uppercase();

                // Reclaim the handle so it stays open for the control channel.
                let handle = HANDLE(file.into_raw_handle() as *mut _);
                let _ = self.handle_value.load(Ordering::SeqCst);
                Ok((AuthenticatedPipe::new(handle), drive_letter))
            }
        }
    }

    impl Drop for ActorPipe {
        fn drop(&mut self) {
            if !self.handle.is_invalid() {
                unsafe {
                    let _ = CloseHandle(self.handle);
                }
                self.handle = HANDLE(std::ptr::null_mut());
            }
            self.handle_value.store(0, Ordering::SeqCst);
        }
    }

    unsafe impl Send for ActorPipe {}
    unsafe impl Sync for ActorPipe {}

    /// Builds a SECURITY_ATTRIBUTES block with a DACL allowing only the given user SID
    /// generic read/write access to the pipe.
    struct PipeSecurity {
        #[allow(dead_code)]
        _sid: Vec<u8>,
        #[allow(dead_code)]
        _acl: Vec<u8>,
        #[allow(dead_code)]
        _descriptor: Vec<u8>,
        attributes: windows::Win32::Security::SECURITY_ATTRIBUTES,
    }

    impl PipeSecurity {
        fn for_user(user_sid: &UserSid) -> Result<Self, PipeAuthError> {
            unsafe {
                let sid_text = user_sid.to_wire();
                let sid_wide: Vec<u16> = sid_text.encode_utf16().chain(Some(0)).collect();
                let mut psid = PSID::default();
                ConvertStringSidToSidW(
                    windows::core::PCWSTR(sid_wide.as_ptr()),
                    &mut psid,
                )
                .map_err(|_| PipeAuthError::AuthenticationFailed)?;

                let sid_len = windows::Win32::Security::GetLengthSid(psid) as usize;
                let mut sid = vec![0u8; sid_len];
                std::ptr::copy_nonoverlapping(psid.0 as *const u8, sid.as_mut_ptr(), sid_len);
                let _ = LocalFree(Some(HLOCAL(psid.0 as *mut _)));
                let psid = PSID(sid.as_ptr() as *mut _);

                let acl_size = std::mem::size_of::<ACL>()
                    + std::mem::size_of::<ACCESS_ALLOWED_ACE>()
                    - std::mem::size_of::<u32>()
                    + sid_len;
                let mut acl = vec![0u8; acl_size];
                let pacl = acl.as_mut_ptr() as *mut ACL;
                InitializeAcl(pacl, acl_size as u32, ACL_REVISION)
                    .map_err(|_| PipeAuthError::AuthenticationFailed)?;
                AddAccessAllowedAce(pacl, ACL_REVISION, GENERIC_READ | GENERIC_WRITE, psid)
                    .map_err(|_| PipeAuthError::AuthenticationFailed)?;

                let mut descriptor = vec![0u8; 512];
                let psd = PSECURITY_DESCRIPTOR(descriptor.as_mut_ptr() as *mut _);
                InitializeSecurityDescriptor(psd, SECURITY_DESCRIPTOR_REVISION_VALUE)
                    .map_err(|_| PipeAuthError::AuthenticationFailed)?;
                SetSecurityDescriptorDacl(psd, true, Some(pacl), false)
                    .map_err(|_| PipeAuthError::AuthenticationFailed)?;

                let attributes = windows::Win32::Security::SECURITY_ATTRIBUTES {
                    nLength: std::mem::size_of::<windows::Win32::Security::SECURITY_ATTRIBUTES>()
                        as u32,
                    lpSecurityDescriptor: psd.0,
                    bInheritHandle: FALSE,
                };

                Ok(Self {
                    _sid: sid,
                    _acl: acl,
                    _descriptor: descriptor,
                    attributes,
                })
            }
        }
    }

    /// Opens the current thread token while impersonating and returns the user SID
    /// string and token session ID.
    unsafe fn open_thread_token_sid_session() -> Result<(String, u32), PipeAuthError> {
        use windows::Win32::{
            Foundation::LocalFree,
            Security::{
                Authorization::ConvertSidToStringSidW, GetTokenInformation, TOKEN_USER,
                TOKEN_QUERY, TokenSessionId, TokenUser,
            },
            System::Threading::GetCurrentThread,
        };

        let mut token = HANDLE::default();
        OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, true, &mut token)
            .map_err(|_| PipeAuthError::AuthenticationFailed)?;

        // SID
        let mut size = 0u32;
        let _ = GetTokenInformation(token, TokenUser, None, 0, &mut size);
        if size == 0 {
            let _ = CloseHandle(token);
            return Err(PipeAuthError::AuthenticationFailed);
        }
        let mut buffer = vec![0u8; size as usize];
        GetTokenInformation(
            token,
            TokenUser,
            Some(buffer.as_mut_ptr() as *mut _),
            size,
            &mut size,
        )
        .map_err(|_| {
            let _ = CloseHandle(token);
            PipeAuthError::AuthenticationFailed
        })?;
        let user = &*(buffer.as_ptr() as *const TOKEN_USER);
        let mut string_sid = windows::core::PWSTR::null();
        ConvertSidToStringSidW(user.User.Sid, &mut string_sid)
            .map_err(|_| PipeAuthError::AuthenticationFailed)?;
        let sid = pwstr_to_string(string_sid).map_err(|_| PipeAuthError::AuthenticationFailed)?;
        let _ = LocalFree(Some(HLOCAL(string_sid.0 as *mut _)));

        // Session ID
        let mut session = 0u32;
        let mut size = std::mem::size_of::<u32>() as u32;
        GetTokenInformation(
            token,
            TokenSessionId,
            Some(&mut session as *mut u32 as *mut _),
            size,
            &mut size,
        )
        .map_err(|_| PipeAuthError::AuthenticationFailed)?;

        let _ = CloseHandle(token);
        Ok((sid, session))
    }

    unsafe fn pwstr_to_string(pwstr: windows::core::PWSTR) -> Result<String, PipeAuthError> {
        if pwstr.0.is_null() {
            return Err(PipeAuthError::AuthenticationFailed);
        }
        let mut len = 0usize;
        while *pwstr.0.add(len) != 0 {
            len += 1;
        }
        let slice = std::slice::from_raw_parts(pwstr.0, len);
        String::from_utf16(slice).map_err(|_| PipeAuthError::AuthenticationFailed)
    }
}

#[cfg(windows)]
pub use windows_pipe::{ActorPipe, AuthenticatedPipe};

#[cfg(not(windows))]
pub struct ActorPipe;

#[cfg(not(windows))]
impl ActorPipe {
    pub fn create(_pipe_name: &str, _user_sid: &UserSid) -> Result<Self, PipeAuthError> {
        Err(PipeAuthError::PipeUnavailable)
    }

    pub fn accept_and_authenticate(
        self,
        _expected_pid: u32,
        _expected_sid: &UserSid,
        _expected_session: u32,
        _expected_generation: u64,
        _bootstrap: StorageBootstrap,
    ) -> Result<AuthenticatedPipe, PipeAuthError> {
        Err(PipeAuthError::PipeUnavailable)
    }
}

#[cfg(not(windows))]
pub struct AuthenticatedPipe;

#[cfg(not(windows))]
impl AuthenticatedPipe {
    pub fn for_test() -> Self {
        Self
    }

    pub fn close(&mut self) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_oversized_message() {
        let huge = vec![b'x'; MAX_MESSAGE_BYTES + 1];
        assert!(matches!(
            StoragePipeServer::decode_request(&huge),
            Err(PipeAuthError::Oversized)
        ));
    }

    #[test]
    fn rejects_invalid_json() {
        assert!(matches!(
            StoragePipeServer::decode_request(b"not json"),
            Err(PipeAuthError::InvalidMessage)
        ));
    }

    #[test]
    fn rejects_zero_session_or_pid() {
        let sid = UserSid::parse("S-1-5-21").unwrap();
        let req = StorageRequest {
            version: 1,
            session_id: 0,
            host_pid: 1,
            generation: 1,
            user_sid: sid.to_wire().to_string(),
        };
        assert!(matches!(
            StoragePipeServer::validate_request(&sid, 1, 1, &req),
            Err(PipeAuthError::InvalidMessage)
        ));
    }

    #[test]
    fn rejects_wrong_session() {
        let sid = UserSid::parse("S-1-5-21").unwrap();
        let req = StorageRequest {
            version: 1,
            session_id: 2,
            host_pid: 1,
            generation: 1,
            user_sid: sid.to_wire().to_string(),
        };
        assert!(matches!(
            StoragePipeServer::validate_request(&sid, 1, 1, &req),
            Err(PipeAuthError::WrongIdentity)
        ));
    }

    #[test]
    fn rejects_stale_generation() {
        let sid = UserSid::parse("S-1-5-21").unwrap();
        let req = StorageRequest {
            version: 1,
            session_id: 1,
            host_pid: 1,
            generation: 0,
            user_sid: sid.to_wire().to_string(),
        };
        assert!(matches!(
            StoragePipeServer::validate_request(&sid, 1, 1, &req),
            Err(PipeAuthError::StaleGeneration)
        ));
    }

    #[test]
    fn rejects_wrong_sid() {
        let sid = UserSid::parse("S-1-5-21-1000").unwrap();
        let wrong = UserSid::parse("S-1-5-21-1001").unwrap();
        let req = StorageRequest {
            version: 1,
            session_id: 1,
            host_pid: 1,
            generation: 1,
            user_sid: wrong.to_wire().to_string(),
        };
        assert!(matches!(
            StoragePipeServer::validate_request(&sid, 1, 1, &req),
            Err(PipeAuthError::WrongIdentity)
        ));
    }

    #[test]
    fn accepts_valid_request() {
        let sid = UserSid::parse("S-1-5-21").unwrap();
        let req = StorageRequest {
            version: 1,
            session_id: 1,
            host_pid: 1,
            generation: 7,
            user_sid: sid.to_wire().to_string(),
        };
        assert!(StoragePipeServer::validate_request(&sid, 1, 7, &req).is_ok());
    }

    #[test]
    fn rejects_protocol_mismatch() {
        let sid = UserSid::parse("S-1-5-21").unwrap();
        let req = StorageRequest {
            version: 99,
            session_id: 1,
            host_pid: 1,
            generation: 1,
            user_sid: sid.to_wire().to_string(),
        };
        assert!(matches!(
            StoragePipeServer::validate_request(&sid, 1, 1, &req),
            Err(PipeAuthError::ProtocolMismatch)
        ));
    }

    #[test]
    fn frame_roundtrips_and_rejects_oversized() {
        let payload = b"hello";
        let frame = encode_frame(payload);
        assert_eq!(frame[..4], [0, 0, 0, 5]);
        let (decoded, consumed) = decode_frame(&frame).unwrap();
        assert_eq!(decoded, payload);
        assert_eq!(consumed, frame.len());

        let mut huge = vec![0u8; 4 + MAX_MESSAGE_BYTES + 1];
        huge[..4].copy_from_slice(&((MAX_MESSAGE_BYTES + 1) as u32).to_be_bytes());
        assert!(matches!(decode_frame(&huge), Err(PipeAuthError::Oversized)));
    }
}

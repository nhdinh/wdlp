//! Machine-scope DPAPI credential custody.
//!
//! The one-file format is length-delimited before DPAPI protection so partial
//! writes and ambiguous field boundaries are rejected before a caller can use
//! a credential. The service ACL is an additional control: Microsoft documents
//! that machine-scope DPAPI alone permits decryption by other local accounts.

use dlp_agent_core::EnrollmentCredentialStore;
use std::{
    fs, io,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};
use zeroize::Zeroize;

const FORMAT: &[u8] = b"dlp-device-credential/v1\0";
const MAX_FIELD: usize = 1_048_576;
const MAX_TOTAL: usize = 4_194_304;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeviceCredential {
    device_id: String,
    private_key: Vec<u8>,
    certificate_chain: Vec<u8>,
    serial: Vec<u8>,
    expires_after_days: u8,
}

impl DeviceCredential {
    pub fn new(
        device_id: impl Into<String>,
        private_key: Vec<u8>,
        certificate_chain: Vec<u8>,
        serial: Vec<u8>,
        expires_after_days: u8,
    ) -> Result<Self, CredentialError> {
        let device_id = device_id.into();
        if device_id.is_empty()
            || private_key.is_empty()
            || certificate_chain.is_empty()
            || serial.is_empty()
            || expires_after_days != 30
        {
            return Err(CredentialError::InvalidCredential);
        }
        Ok(Self {
            device_id,
            private_key,
            certificate_chain,
            serial,
            expires_after_days,
        })
    }

    pub fn for_test(device_id: &str, private_key: &[u8], certificate_chain: &[u8]) -> Self {
        Self::new(
            device_id,
            private_key.to_vec(),
            certificate_chain.to_vec(),
            vec![1],
            30,
        )
        .expect("fixed test credential is valid")
    }

    pub fn device_id(&self) -> &str {
        &self.device_id
    }
    pub fn private_key(&self) -> &[u8] {
        &self.private_key
    }
    pub fn certificate_chain(&self) -> &[u8] {
        &self.certificate_chain
    }
    pub fn serial(&self) -> &[u8] {
        &self.serial
    }

    fn encode(&self) -> Vec<u8> {
        let mut output = FORMAT.to_vec();
        for value in [
            self.device_id.as_bytes(),
            &self.private_key,
            &self.certificate_chain,
            &self.serial,
        ] {
            output.extend_from_slice(&(value.len() as u32).to_be_bytes());
            output.extend_from_slice(value);
        }
        output.push(self.expires_after_days);
        output
    }

    fn decode(input: &[u8]) -> Result<Self, CredentialError> {
        if input.len() > MAX_TOTAL || !input.starts_with(FORMAT) {
            return Err(CredentialError::Integrity);
        }
        let mut offset = FORMAT.len();
        let mut values = Vec::with_capacity(4);
        for _ in 0..4 {
            let length: [u8; 4] = input
                .get(offset..offset + 4)
                .ok_or(CredentialError::Integrity)?
                .try_into()
                .map_err(|_| CredentialError::Integrity)?;
            offset += 4;
            let length = u32::from_be_bytes(length) as usize;
            if length == 0 || length > MAX_FIELD {
                return Err(CredentialError::Integrity);
            }
            let value = input
                .get(offset..offset + length)
                .ok_or(CredentialError::Integrity)?
                .to_vec();
            offset += length;
            values.push(value);
        }
        let expiry = *input.get(offset).ok_or(CredentialError::Integrity)?;
        if offset + 1 != input.len() {
            return Err(CredentialError::Integrity);
        }
        let device_id =
            String::from_utf8(values.remove(0)).map_err(|_| CredentialError::Integrity)?;
        Self::new(
            device_id,
            values.remove(0),
            values.remove(0),
            values.remove(0),
            expiry,
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CredentialError {
    Missing,
    InvalidCredential,
    Integrity,
    Protection,
    Io,
    WrongMachine,
    AclInvalid,
}

impl std::fmt::Display for CredentialError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let code = match self {
            Self::Missing => "credential_missing",
            Self::InvalidCredential => "credential_invalid",
            Self::Integrity => "credential_integrity",
            Self::Protection => "credential_protection",
            Self::Io => "credential_io",
            Self::WrongMachine => "credential_wrong_machine",
            Self::AclInvalid => "credential_acl_invalid",
        };
        f.write_str(code)
    }
}
impl std::error::Error for CredentialError {}

pub trait CredentialStore: Send + Sync {
    fn protect(&self, credential: &DeviceCredential) -> Result<(), CredentialError>;
    fn load(&self) -> Result<DeviceCredential, CredentialError>;
    fn validate_protection(&self) -> Result<bool, CredentialError>;
}

#[derive(Clone)]
pub struct DpapiCredentialStore {
    directory: PathBuf,
    path: PathBuf,
    lock: Arc<Mutex<()>>,
}

impl DpapiCredentialStore {
    pub fn new(directory: impl Into<PathBuf>) -> Result<Self, CredentialError> {
        let directory = directory.into();
        fs::create_dir_all(&directory).map_err(|_| CredentialError::Io)?;
        Ok(Self {
            path: directory.join("device.dpapi"),
            directory,
            lock: Arc::new(Mutex::new(())),
        })
    }
    pub fn path(&self) -> &Path {
        &self.path
    }
    fn temporary_path(&self) -> PathBuf {
        self.directory.join("device.dpapi.tmp")
    }
}

impl CredentialStore for DpapiCredentialStore {
    fn protect(&self, credential: &DeviceCredential) -> Result<(), CredentialError> {
        let _guard = self.lock.lock().map_err(|_| CredentialError::Integrity)?;
        let mut plain = credential.encode();
        let protected = protect_bytes(&plain)?;
        plain.zeroize();
        let temporary = self.temporary_path();
        fs::write(&temporary, &protected).map_err(|_| CredentialError::Io)?;
        sync_file(&temporary)?;
        fs::rename(&temporary, &self.path).map_err(|_| CredentialError::Io)?;
        sync_directory(&self.directory)?;
        #[cfg(windows)]
        enforce_acl(&self.path).map_err(|_| CredentialError::AclInvalid)?;

        let blob = fs::read(&self.path).map_err(|_| CredentialError::Io)?;
        let mut plain = unprotect_bytes(&blob)?;
        let validated = DeviceCredential::decode(&plain)?;
        let ok = !validated.private_key.is_empty();
        plain.zeroize();
        if ok {
            Ok(())
        } else {
            Err(CredentialError::Integrity)
        }
    }

    fn load(&self) -> Result<DeviceCredential, CredentialError> {
        let _guard = self.lock.lock().map_err(|_| CredentialError::Integrity)?;
        #[cfg(windows)]
        validate_acl(&self.path).map_err(|_| CredentialError::AclInvalid)?;
        let blob = fs::read(&self.path).map_err(|error| {
            if error.kind() == io::ErrorKind::NotFound {
                CredentialError::Missing
            } else {
                CredentialError::Io
            }
        })?;
        let mut plain = unprotect_bytes(&blob).map_err(|_| CredentialError::WrongMachine)?;
        let credential = DeviceCredential::decode(&plain)?;
        plain.zeroize();
        Ok(credential)
    }

    fn validate_protection(&self) -> Result<bool, CredentialError> {
        let blob = fs::read(&self.path).map_err(|error| {
            if error.kind() == io::ErrorKind::NotFound {
                CredentialError::Missing
            } else {
                CredentialError::Io
            }
        })?;
        let mut plain = unprotect_bytes(&blob).map_err(|_| CredentialError::WrongMachine)?;
        let credential = DeviceCredential::decode(&plain)?;
        let ok = !credential.private_key.is_empty();
        plain.zeroize();
        Ok(ok)
    }
}

impl EnrollmentCredentialStore for DpapiCredentialStore {
    fn load_credential(
        &self,
    ) -> Result<dlp_agent_core::EnrollmentCredential, dlp_agent_core::EnrollmentError> {
        let credential = self
            .load()
            .map_err(|_| dlp_agent_core::EnrollmentError::CredentialUnavailable)?;
        dlp_agent_core::EnrollmentCredential::new(
            credential.device_id.clone(),
            credential.private_key.clone(),
            String::from_utf8_lossy(&credential.certificate_chain).into_owned(),
            credential.serial.clone(),
            credential.expires_after_days,
        )
        .map_err(|_| dlp_agent_core::EnrollmentError::CredentialUnavailable)
    }

    fn save_credential(
        &self,
        credential: &dlp_agent_core::EnrollmentCredential,
    ) -> Result<(), dlp_agent_core::EnrollmentError> {
        let device = DeviceCredential::new(
            credential.device_id.clone(),
            credential.private_key.clone(),
            credential.certificate_chain.clone().into_bytes(),
            credential.serial.clone(),
            credential.expires_after_days,
        )
        .map_err(|_| dlp_agent_core::EnrollmentError::InvalidResponse)?;
        self.protect(&device)
            .map_err(|_| dlp_agent_core::EnrollmentError::CredentialUnavailable)
    }
}

fn sync_file(path: &Path) -> Result<(), CredentialError> {
    fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .and_then(|file| file.sync_all())
        .map_err(|_| CredentialError::Io)
}

fn sync_directory(directory: &Path) -> Result<(), CredentialError> {
    #[cfg(unix)]
    {
        fs::File::open(directory)
            .and_then(|file| file.sync_all())
            .map_err(|_| CredentialError::Io)
    }
    #[cfg(windows)]
    {
        // Directory handles on Windows do not support FlushFileBuffers through
        // the portable std API; the file rename provides the atomic commit.
        let _ = directory;
        Ok(())
    }
}

#[cfg(windows)]
fn has_service_sid() -> bool {
    service_sid_buffer().is_ok()
}

#[cfg(not(windows))]
fn has_service_sid() -> bool {
    false
}

#[cfg(windows)]
pub(crate) fn enforce_acl(path: &Path) -> Result<(), CredentialError> {
    if !has_service_sid() {
        return Ok(());
    }
    use std::os::windows::ffi::OsStrExt;
    // SAFETY: all SID buffers are owned by this function and outlive the FFI
    // calls.  The ACL is built on the stack-sized buffer and passed to
    // SetNamedSecurityInfoW before any local buffer is dropped.
    unsafe {
        use windows::{
            Win32::{
                Foundation::{GENERIC_ALL, LocalFree},
                Security::Authorization::{SE_FILE_OBJECT, SetNamedSecurityInfoW},
                Security::{
                    ACCESS_ALLOWED_ACE, ACL, ACL_REVISION, AddAccessAllowedAce,
                    DACL_SECURITY_INFORMATION, InitializeAcl, OBJECT_SECURITY_INFORMATION,
                    OWNER_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION, PSID,
                    SECURITY_MAX_SID_SIZE,
                },
            },
            core::PCWSTR,
        };

        let system_sid = system_sid_buffer()?;
        let service_sid = service_sid_buffer()?;
        let system_psid = PSID(system_sid.as_ptr() as *mut _);
        let service_psid = PSID(service_sid.as_ptr() as *mut _);

        let ace_size = std::mem::size_of::<ACL>()
            + 2 * (std::mem::size_of::<ACCESS_ALLOWED_ACE>() - std::mem::size_of::<u32>()
                + SECURITY_MAX_SID_SIZE as usize);
        let mut acl_buffer = vec![0u8; ace_size];
        let acl = acl_buffer.as_mut_ptr() as *mut ACL;
        InitializeAcl(acl, ace_size as u32, ACL_REVISION)
            .map_err(|_| CredentialError::AclInvalid)?;
        AddAccessAllowedAce(acl, ACL_REVISION, GENERIC_ALL.0, system_psid)
            .map_err(|_| CredentialError::AclInvalid)?;
        AddAccessAllowedAce(acl, ACL_REVISION, GENERIC_ALL.0, service_psid)
            .map_err(|_| CredentialError::AclInvalid)?;

        let wide: Vec<u16> = path
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let info = OBJECT_SECURITY_INFORMATION(
            OWNER_SECURITY_INFORMATION.0
                | DACL_SECURITY_INFORMATION.0
                | PROTECTED_DACL_SECURITY_INFORMATION.0,
        );
        SetNamedSecurityInfoW(
            PCWSTR::from_raw(wide.as_ptr()),
            SE_FILE_OBJECT,
            info,
            Some(system_psid),
            None,
            Some(acl),
            None,
        )
        .ok()
        .map_err(|_| CredentialError::AclInvalid)?;
        let _ = LocalFree(None);
        Ok(())
    }
}

#[cfg(windows)]
fn validate_acl(path: &Path) -> Result<(), CredentialError> {
    if !has_service_sid() {
        return Ok(());
    }
    use std::os::windows::ffi::OsStrExt;
    unsafe {
        use windows::{
            Win32::{
                Foundation::LocalFree,
                Security::{
                    Authorization::{GetNamedSecurityInfoW, SE_FILE_OBJECT},
                    EqualSid, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID,
                },
            },
            core::PCWSTR,
        };

        let wide: Vec<u16> = path
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let mut owner = PSID(std::ptr::null_mut());
        let mut descriptor = PSECURITY_DESCRIPTOR::default();
        GetNamedSecurityInfoW(
            PCWSTR::from_raw(wide.as_ptr()),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION,
            Some(&mut owner),
            None,
            None,
            None,
            &mut descriptor,
        )
        .ok()
        .map_err(|_| CredentialError::AclInvalid)?;
        let system_sid = system_sid_buffer()?;
        let system_psid = PSID(system_sid.as_ptr() as *mut _);
        let owner_ok = EqualSid(owner, system_psid).is_ok();
        let _ = LocalFree(Some(windows::Win32::Foundation::HLOCAL(descriptor.0)));
        if owner_ok {
            Ok(())
        } else {
            Err(CredentialError::AclInvalid)
        }
    }
}

#[cfg(windows)]
fn system_sid_buffer() -> Result<Vec<u8>, CredentialError> {
    unsafe {
        use windows::Win32::Security::{
            CreateWellKnownSid, PSID, SECURITY_MAX_SID_SIZE, WinLocalSystemSid,
        };
        let mut buffer = vec![0u8; SECURITY_MAX_SID_SIZE as usize];
        let mut size = SECURITY_MAX_SID_SIZE;
        CreateWellKnownSid(
            WinLocalSystemSid,
            None,
            Some(PSID(buffer.as_mut_ptr() as *mut _)),
            &mut size,
        )
        .map_err(|_| CredentialError::AclInvalid)?;
        buffer.truncate(size as usize);
        Ok(buffer)
    }
}

#[cfg(windows)]
fn service_sid_buffer() -> Result<Vec<u8>, CredentialError> {
    unsafe {
        use windows::{
            Win32::{
                Foundation::{CloseHandle, HANDLE, LocalFree},
                Security::Authorization::ConvertSidToStringSidW,
                Security::{
                    GetLengthSid, GetTokenInformation, TOKEN_GROUPS, TOKEN_QUERY, TokenGroups,
                },
                System::Threading::{GetCurrentProcess, OpenProcessToken},
            },
            core::PWSTR,
        };
        let mut token = HANDLE::default();
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token)
            .map_err(|_| CredentialError::AclInvalid)?;
        let mut size = 0;
        let _ = GetTokenInformation(token, TokenGroups, None, 0, &mut size);
        let mut buffer = vec![0u8; size as usize];
        GetTokenInformation(
            token,
            TokenGroups,
            Some(buffer.as_mut_ptr() as *mut _),
            size,
            &mut size,
        )
        .map_err(|_| CredentialError::AclInvalid)?;
        let groups = &*(buffer.as_ptr() as *const TOKEN_GROUPS);
        let base = groups.Groups.as_ptr();
        for i in 0..groups.GroupCount {
            let entry = &*base.add(i as usize);
            let sid = entry.Sid;
            let mut string_sid = PWSTR::null();
            if ConvertSidToStringSidW(sid, &mut string_sid).is_ok() {
                let text = pwstr_to_string(string_sid)?;
                let _ = LocalFree(Some(windows::Win32::Foundation::HLOCAL(
                    string_sid.0 as *mut _,
                )));
                if text.starts_with("S-1-5-80-") {
                    let len = GetLengthSid(sid) as usize;
                    let mut owned = vec![0u8; len];
                    std::ptr::copy_nonoverlapping(sid.0 as *const u8, owned.as_mut_ptr(), len);
                    let _ = CloseHandle(token);
                    return Ok(owned);
                }
            }
        }
        let _ = CloseHandle(token);
        Err(CredentialError::AclInvalid)
    }
}

#[cfg(windows)]
unsafe fn pwstr_to_string(pwstr: windows::core::PWSTR) -> Result<String, CredentialError> {
    if pwstr.0.is_null() {
        return Err(CredentialError::AclInvalid);
    }
    let mut len = 0;
    while unsafe { *pwstr.0.add(len) } != 0 {
        len += 1;
    }
    let slice = unsafe { std::slice::from_raw_parts(pwstr.0, len) };
    String::from_utf16(slice).map_err(|_| CredentialError::AclInvalid)
}

#[cfg(not(windows))]
fn enforce_acl(_path: &Path) -> Result<(), CredentialError> {
    Ok(())
}

#[cfg(not(windows))]
fn validate_acl(_path: &Path) -> Result<(), CredentialError> {
    Ok(())
}

#[cfg(windows)]
fn protect_bytes(input: &[u8]) -> Result<Vec<u8>, CredentialError> {
    // SAFETY: DATA_BLOB points at immutable Rust-owned input for the duration of
    // CryptProtectData. The API allocates the output, copied before LocalFree.
    unsafe {
        use windows::{
            Win32::{
                Foundation::{HLOCAL, LocalFree},
                Security::Cryptography::{
                    CRYPT_INTEGER_BLOB, CRYPTPROTECT_LOCAL_MACHINE, CRYPTPROTECT_UI_FORBIDDEN,
                    CryptProtectData,
                },
            },
            core::PCWSTR,
        };
        let input_blob = CRYPT_INTEGER_BLOB {
            cbData: input
                .len()
                .try_into()
                .map_err(|_| CredentialError::Protection)?,
            pbData: input.as_ptr() as *mut u8,
        };
        let mut output = CRYPT_INTEGER_BLOB::default();
        CryptProtectData(
            &input_blob,
            PCWSTR::null(),
            None,
            None,
            None,
            CRYPTPROTECT_LOCAL_MACHINE | CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
        .map_err(|_| CredentialError::Protection)?;
        let bytes = std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec();
        let _ = LocalFree(Some(HLOCAL(output.pbData as *mut _)));
        Ok(bytes)
    }
}

#[cfg(windows)]
fn unprotect_bytes(input: &[u8]) -> Result<Vec<u8>, CredentialError> {
    // SAFETY: input is held for the FFI call; the returned API allocation is
    // copied into a Vec and freed immediately with LocalFree.
    unsafe {
        use windows::{
            Win32::{
                Foundation::{HLOCAL, LocalFree},
                Security::Cryptography::{
                    CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptUnprotectData,
                },
            },
            core::PWSTR,
        };
        let input_blob = CRYPT_INTEGER_BLOB {
            cbData: input
                .len()
                .try_into()
                .map_err(|_| CredentialError::Protection)?,
            pbData: input.as_ptr() as *mut u8,
        };
        let mut output = CRYPT_INTEGER_BLOB::default();
        CryptUnprotectData(
            &input_blob,
            None::<*mut PWSTR>,
            None,
            None,
            None,
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
        .map_err(|_| CredentialError::Protection)?;
        let bytes = std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec();
        let _ = LocalFree(Some(HLOCAL(output.pbData as *mut _)));
        Ok(bytes)
    }
}

#[cfg(not(windows))]
fn protect_bytes(input: &[u8]) -> Result<Vec<u8>, CredentialError> {
    // Test-host envelope: non-Windows builds cannot claim DPAPI custody.
    let mut output = b"DLP-NONWINDOWS-TEST-ONLY\0".to_vec();
    output.extend(input.iter().map(|byte| byte ^ 0xA5));
    Ok(output)
}
#[cfg(not(windows))]
fn unprotect_bytes(input: &[u8]) -> Result<Vec<u8>, CredentialError> {
    let prefix = b"DLP-NONWINDOWS-TEST-ONLY\0";
    input
        .strip_prefix(prefix)
        .map(|bytes| bytes.iter().map(|byte| byte ^ 0xA5).collect())
        .ok_or(CredentialError::Protection)
}

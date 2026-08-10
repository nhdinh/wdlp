//! Machine-scope DPAPI credential custody.
//!
//! The one-file format is length-delimited before DPAPI protection so partial
//! writes and ambiguous field boundaries are rejected before a caller can use
//! a credential. The service ACL is an additional control: Microsoft documents
//! that machine-scope DPAPI alone permits decryption by other local accounts.

use std::{
    fs, io,
    path::{Path, PathBuf},
    sync::Mutex,
};

const FORMAT: &[u8] = b"dlp-device-credential/v1\0";
const MAX_FIELD: usize = 1_048_576;

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
        if !input.starts_with(FORMAT) {
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
}

impl std::fmt::Display for CredentialError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let code = match self {
            Self::Missing => "credential_missing",
            Self::InvalidCredential => "credential_invalid",
            Self::Integrity => "credential_integrity",
            Self::Protection => "credential_protection",
            Self::Io => "credential_io",
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

pub struct DpapiCredentialStore {
    directory: PathBuf,
    path: PathBuf,
    lock: Mutex<()>,
}

impl DpapiCredentialStore {
    pub fn new(directory: impl Into<PathBuf>) -> Result<Self, CredentialError> {
        let directory = directory.into();
        fs::create_dir_all(&directory).map_err(|_| CredentialError::Io)?;
        Ok(Self {
            path: directory.join("device.dpapi"),
            directory,
            lock: Mutex::new(()),
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
        let protected = protect_bytes(&credential.encode())?;
        let temporary = self.temporary_path();
        fs::write(&temporary, protected).map_err(|_| CredentialError::Io)?;
        fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&temporary)
            .and_then(|file| file.sync_all())
            .map_err(|_| CredentialError::Io)?;
        fs::rename(&temporary, &self.path).map_err(|_| CredentialError::Io)?;
        let blob = fs::read(&self.path).map_err(|_| CredentialError::Io)?;
        let protected = unprotect_bytes(&blob)?;
        let validated = DeviceCredential::decode(&protected)?;
        if validated.private_key.is_empty() {
            return Err(CredentialError::Integrity);
        }
        Ok(())
    }

    fn load(&self) -> Result<DeviceCredential, CredentialError> {
        let _guard = self.lock.lock().map_err(|_| CredentialError::Integrity)?;
        let blob = fs::read(&self.path).map_err(|error| {
            if error.kind() == io::ErrorKind::NotFound {
                CredentialError::Missing
            } else {
                CredentialError::Io
            }
        })?;
        let plain = unprotect_bytes(&blob)?;
        DeviceCredential::decode(&plain)
    }

    fn validate_protection(&self) -> Result<bool, CredentialError> {
        let blob = fs::read(&self.path).map_err(|error| {
            if error.kind() == io::ErrorKind::NotFound {
                CredentialError::Missing
            } else {
                CredentialError::Io
            }
        })?;
        let plain = unprotect_bytes(&blob)?;
        let credential = DeviceCredential::decode(&plain)?;
        Ok(!credential.private_key.is_empty())
    }
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

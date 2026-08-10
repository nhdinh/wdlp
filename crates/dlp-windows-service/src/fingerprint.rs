//! Exact hardware fingerprint normalization shared with the trusted-station contract.

use sha2::{Digest, Sha256};

const VERSION: &[u8] = b"dlp-fingerprint/v1\0";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HardwareFingerprintSources {
    smbios_system_uuid: String,
    bios_serial: String,
    system_disk_serial: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FingerprintError {
    MissingOrSentinel,
    UnsupportedPlatform,
}

impl HardwareFingerprintSources {
    pub fn new(
        uuid: impl Into<String>,
        bios: impl Into<String>,
        disk: impl Into<String>,
    ) -> Result<Self, FingerprintError> {
        let normalize = |value: String| {
            let normalized = value.trim().to_ascii_uppercase();
            if normalized.is_empty()
                || matches!(
                    normalized.as_str(),
                    "UNKNOWN"
                        | "NONE"
                        | "TO BE FILLED BY O.E.M."
                        | "00000000-0000-0000-0000-000000000000"
                        | "FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF"
                )
            {
                Err(FingerprintError::MissingOrSentinel)
            } else {
                Ok(normalized)
            }
        };
        Ok(Self {
            smbios_system_uuid: normalize(uuid.into())?,
            bios_serial: normalize(bios.into())?,
            system_disk_serial: normalize(disk.into())?,
        })
    }
    pub fn digest(&self) -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update(VERSION);
        for (name, value) in [
            (
                b"system_uuid".as_slice(),
                self.smbios_system_uuid.as_bytes(),
            ),
            (b"bios_serial".as_slice(), self.bios_serial.as_bytes()),
            (
                b"system_disk_serial".as_slice(),
                self.system_disk_serial.as_bytes(),
            ),
        ] {
            hash.update((name.len() as u32).to_be_bytes());
            hash.update(name);
            hash.update((value.len() as u32).to_be_bytes());
            hash.update(value);
        }
        hash.finalize().into()
    }
}

/// Production collection is deliberately fail-closed until the SCM adapter is
/// running with the required firmware-table and storage-IOCTL privileges.
pub fn collect_hardware_fingerprint() -> Result<HardwareFingerprintSources, FingerprintError> {
    Err(FingerprintError::UnsupportedPlatform)
}

//! Exact hardware fingerprint normalization shared with the trusted-station contract.

use sha2::{Digest, Sha256};
use std::process::Command;

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

pub fn collect_hardware_fingerprint() -> Result<HardwareFingerprintSources, FingerprintError> {
    #[cfg(windows)]
    {
        // The CIM classes expose the same SMBIOS UUID, BIOS serial and physical
        // disk serial used by the trusted-station collector. The association walk
        // resolves the OS volume to its backing physical disk; no MAC address or
        // virtual adapter identifier can enter the digest.
        let script = "$ErrorActionPreference='Stop';$os=(Get-CimInstance Win32_OperatingSystem).SystemDrive.TrimEnd(':');$part=Get-CimAssociatedInstance -InputObject (Get-CimInstance Win32_LogicalDisk -Filter \"DeviceID='$os:'\") -Association Win32_LogicalDiskToPartition | Select-Object -First 1;$disk=Get-CimAssociatedInstance -InputObject $part -Association Win32_DiskDriveToDiskPartition | Select-Object -First 1;$uuid=(Get-CimInstance Win32_ComputerSystemProduct).UUID;$bios=(Get-CimInstance Win32_BIOS).SerialNumber;$serial=$disk.SerialNumber;@($uuid,$bios,$serial) | ForEach-Object {$_.ToString().Trim()}";
        let output = Command::new("powershell.exe")
            .args(["-NoProfile", "-NonInteractive", "-Command", script])
            .output()
            .map_err(|_| FingerprintError::UnsupportedPlatform)?;
        if !output.status.success() {
            return Err(FingerprintError::UnsupportedPlatform);
        }
        let values: Vec<String> = String::from_utf8_lossy(&output.stdout)
            .lines()
            .map(str::to_owned)
            .collect();
        if values.len() != 3 {
            return Err(FingerprintError::MissingOrSentinel);
        }
        HardwareFingerprintSources::new(&values[0], &values[1], &values[2])
    }
    #[cfg(not(windows))]
    {
        Err(FingerprintError::UnsupportedPlatform)
    }
}

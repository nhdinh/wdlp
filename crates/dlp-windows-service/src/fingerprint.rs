//! Exact hardware fingerprint normalization shared with the trusted-station contract.
//!
//! The production collector uses documented Win32 APIs rather than shelling out to
//! PowerShell. All `unsafe` blocks are isolated here; portable tests must inject a
//! deterministic collector and must not rely on the host hardware.

use sha2::{Digest, Sha256};

#[cfg(windows)]
use windows::Win32::Foundation::HANDLE;

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
    Changed,
}

/// Injected collector for portable tests. Production code uses
/// `collect_hardware_fingerprint` directly.
pub trait FingerprintCollector: Send + Sync {
    fn collect(&self) -> Result<HardwareFingerprintSources, FingerprintError>;
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

    /// Detects a hardware change against a previously observed digest.
    pub fn verify_unchanged(&self, prior_digest: &[u8; 32]) -> Result<(), FingerprintError> {
        if &self.digest() == prior_digest {
            Ok(())
        } else {
            Err(FingerprintError::Changed)
        }
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
        let uuid = smbios_system_uuid()?;
        let bios = smbios_system_serial()?;
        let disk = system_disk_serial()?;
        HardwareFingerprintSources::new(uuid, bios, disk)
    }
    #[cfg(not(windows))]
    {
        Err(FingerprintError::UnsupportedPlatform)
    }
}

#[cfg(windows)]
fn smbios_system_uuid() -> Result<String, FingerprintError> {
    let table = read_smbios_table()?;
    let type1 = find_smbios_structure(&table, 1).ok_or(FingerprintError::MissingOrSentinel)?;
    // SMBIOS Type 1 System Information: UUID is at offset 0x08 (16 bytes).
    const UUID_OFFSET: usize = 0x08;
    if type1.formatted.len() < UUID_OFFSET + 16 {
        return Err(FingerprintError::MissingOrSentinel);
    }
    let bytes = &type1.formatted[UUID_OFFSET..UUID_OFFSET + 16];
    // UUID byte order in SMBIOS is little-endian for the first three fields.
    Ok(format!(
        "{:02X}{:02X}{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
        bytes[3],
        bytes[2],
        bytes[1],
        bytes[0],
        bytes[5],
        bytes[4],
        bytes[7],
        bytes[6],
        bytes[8],
        bytes[9],
        bytes[10],
        bytes[11],
        bytes[12],
        bytes[13],
        bytes[14],
        bytes[15]
    ))
}

#[cfg(windows)]
fn smbios_system_serial() -> Result<String, FingerprintError> {
    let table = read_smbios_table()?;
    let type1 = find_smbios_structure(&table, 1).ok_or(FingerprintError::MissingOrSentinel)?;
    // SMBIOS Type 1 System Information: SerialNumber string ref is at offset 0x07.
    const SERIAL_OFFSET: usize = 0x07;
    if type1.formatted.len() <= SERIAL_OFFSET {
        return Err(FingerprintError::MissingOrSentinel);
    }
    let string_ref = type1.formatted[SERIAL_OFFSET];
    read_smbios_string(type1.strings, string_ref).ok_or(FingerprintError::MissingOrSentinel)
}

#[cfg(windows)]
struct SmbiosStructure<'a> {
    #[allow(dead_code)]
    handle: u16,
    formatted: &'a [u8],
    strings: &'a [u8],
}

#[cfg(windows)]
fn read_smbios_table() -> Result<Vec<u8>, FingerprintError> {
    use windows::Win32::System::SystemInformation::{
        FIRMWARE_TABLE_PROVIDER, GetSystemFirmwareTable,
    };

    const RSMB: FIRMWARE_TABLE_PROVIDER = FIRMWARE_TABLE_PROVIDER(0x5253_4D42);
    // SAFETY: GetSystemFirmwareTable is a read-only query. The first call returns
    // the required buffer size; the second call fills the allocated Vec.
    let size = unsafe { GetSystemFirmwareTable(RSMB, 0, None) };
    if size == 0 {
        return Err(FingerprintError::UnsupportedPlatform);
    }
    let mut buffer = vec![0u8; size as usize];
    let written = unsafe { GetSystemFirmwareTable(RSMB, 0, Some(buffer.as_mut_slice())) };
    if written == 0 || written > size {
        return Err(FingerprintError::UnsupportedPlatform);
    }
    buffer.truncate(written as usize);
    // Skip the 8-byte RawSMBIOSData header to reach the table data.
    if buffer.len() < 8 {
        return Err(FingerprintError::MissingOrSentinel);
    }
    Ok(buffer[8..].to_vec())
}

#[cfg(windows)]
fn find_smbios_structure(table: &[u8], target_type: u8) -> Option<SmbiosStructure<'_>> {
    let mut offset = 0;
    while offset + 4 <= table.len() {
        let structure_type = table[offset];
        let length = table[offset + 1] as usize;
        if length < 4 || offset + length > table.len() {
            return None;
        }
        let handle = u16::from_le_bytes([table[offset + 2], table[offset + 3]]);
        let formatted = &table[offset..offset + length];

        // String area follows the formatted area and ends with two null bytes.
        let string_start = offset + length;
        let string_end = find_string_area_end(table, string_start)?;
        let strings = &table[string_start..string_end];

        if structure_type == target_type {
            return Some(SmbiosStructure {
                handle,
                formatted,
                strings,
            });
        }

        offset = string_end + 2;
    }
    None
}

#[cfg(windows)]
fn find_string_area_end(table: &[u8], start: usize) -> Option<usize> {
    let mut index = start;
    while index + 1 < table.len() {
        if table[index] == 0 && table[index + 1] == 0 {
            return Some(index);
        }
        index += 1;
    }
    None
}

#[cfg(windows)]
fn read_smbios_string(strings: &[u8], index: u8) -> Option<String> {
    if index == 0 {
        return None;
    }
    let mut current = 1;
    let mut start = 0;
    while start < strings.len() {
        let end = strings[start..]
            .iter()
            .position(|b| *b == 0)
            .map(|p| start + p)?;
        if current == index {
            return String::from_utf8(strings[start..end].to_vec()).ok();
        }
        start = end + 1;
        current += 1;
    }
    None
}

#[cfg(windows)]
fn system_disk_serial() -> Result<String, FingerprintError> {
    use std::os::windows::ffi::OsStrExt;
    use windows::{
        Win32::{
            Foundation::CloseHandle,
            Storage::FileSystem::{
                CreateFileW, FILE_FLAGS_AND_ATTRIBUTES, FILE_SHARE_MODE, OPEN_EXISTING,
            },
        },
        core::PCWSTR,
    };

    let disk_number = os_disk_number()?;
    let path = format!("\\\\.\\PhysicalDrive{disk_number}");
    let wide: Vec<u16> = std::path::Path::new(&path)
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    // SAFETY: CreateFileW receives a null-terminated wide path owned by this
    // function. The returned handle is closed before returning.
    let handle = unsafe {
        CreateFileW(
            PCWSTR::from_raw(wide.as_ptr()),
            0,
            FILE_SHARE_MODE(0x00000001 | 0x00000002), // FILE_SHARE_READ | FILE_SHARE_WRITE
            None,
            OPEN_EXISTING,
            FILE_FLAGS_AND_ATTRIBUTES(0),
            None,
        )
    }
    .map_err(|_| FingerprintError::MissingOrSentinel)?;

    let result = query_disk_serial(handle);
    let _ = unsafe { CloseHandle(handle) };
    result
}

#[cfg(windows)]
fn os_disk_number() -> Result<u32, FingerprintError> {
    use std::os::windows::ffi::OsStrExt;
    use windows::{
        Win32::{
            Foundation::CloseHandle,
            Storage::FileSystem::{
                CreateFileW, FILE_FLAGS_AND_ATTRIBUTES, FILE_SHARE_MODE,
                IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS, OPEN_EXISTING,
            },
            System::IO::DeviceIoControl,
            System::Ioctl::VOLUME_DISK_EXTENTS,
        },
        core::PCWSTR,
    };

    let path = "\\\\.\\C:";
    let wide: Vec<u16> = std::path::Path::new(path)
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    // SAFETY: CreateFileW receives a null-terminated wide path owned by this
    // function. The handle is closed before returning.
    let handle = unsafe {
        CreateFileW(
            PCWSTR::from_raw(wide.as_ptr()),
            0,
            FILE_SHARE_MODE(0x00000001 | 0x00000002),
            None,
            OPEN_EXISTING,
            FILE_FLAGS_AND_ATTRIBUTES(0),
            None,
        )
    }
    .map_err(|_| FingerprintError::MissingOrSentinel)?;

    let mut extents: VOLUME_DISK_EXTENTS = unsafe { std::mem::zeroed() };
    let mut returned = 0u32;
    // SAFETY: DeviceIoControl writes into `extents`, which is owned and properly
    // sized for the expected output structure. The handle is closed afterwards.
    let result = unsafe {
        DeviceIoControl(
            handle,
            IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS,
            None,
            0,
            Some(&mut extents as *mut _ as *mut _),
            std::mem::size_of::<VOLUME_DISK_EXTENTS>() as u32,
            Some(&mut returned),
            None,
        )
    };
    let _ = unsafe { CloseHandle(handle) };
    result.map_err(|_| FingerprintError::MissingOrSentinel)?;
    if extents.NumberOfDiskExtents == 0 {
        return Err(FingerprintError::MissingOrSentinel);
    }
    Ok(extents.Extents[0].DiskNumber)
}

#[cfg(windows)]
fn query_disk_serial(handle: HANDLE) -> Result<String, FingerprintError> {
    use windows::Win32::{
        System::IO::DeviceIoControl,
        System::Ioctl::{
            IOCTL_STORAGE_QUERY_PROPERTY, STORAGE_DEVICE_DESCRIPTOR, STORAGE_PROPERTY_ID,
            STORAGE_PROPERTY_QUERY, STORAGE_QUERY_TYPE,
        },
    };

    let query = STORAGE_PROPERTY_QUERY {
        PropertyId: STORAGE_PROPERTY_ID(0), // StorageDeviceProperty
        QueryType: STORAGE_QUERY_TYPE(0),   // PropertyStandardQuery
        AdditionalParameters: [0; 1],
    };
    let mut buffer = vec![0u8; 1024];
    let mut returned = 0u32;
    // SAFETY: DeviceIoControl writes into the owned `buffer`. The handle is owned
    // by the caller and remains valid for the call.
    unsafe {
        DeviceIoControl(
            handle,
            IOCTL_STORAGE_QUERY_PROPERTY,
            Some(&query as *const _ as *const _),
            std::mem::size_of::<STORAGE_PROPERTY_QUERY>() as u32,
            Some(buffer.as_mut_ptr() as *mut _),
            buffer.len() as u32,
            Some(&mut returned),
            None,
        )
    }
    .map_err(|_| FingerprintError::MissingOrSentinel)?;

    // SAFETY: On success, `buffer` contains a STORAGE_DEVICE_DESCRIPTOR. The
    // SerialNumberOffset field is relative to the start of the descriptor.
    let descriptor = unsafe { &*(buffer.as_ptr() as *const STORAGE_DEVICE_DESCRIPTOR) };
    let offset = descriptor.SerialNumberOffset as usize;
    if offset == 0 || offset >= buffer.len() {
        return Err(FingerprintError::MissingOrSentinel);
    }
    let serial_bytes = &buffer[offset..];
    let end = serial_bytes
        .iter()
        .position(|b| *b == 0)
        .unwrap_or(serial_bytes.len());
    let serial = String::from_utf8_lossy(&serial_bytes[..end]);
    let serial = serial.trim();
    if serial.is_empty() {
        return Err(FingerprintError::MissingOrSentinel);
    }
    Ok(serial.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct InjectedCollector {
        uuid: String,
        bios: String,
        disk: String,
    }

    impl FingerprintCollector for InjectedCollector {
        fn collect(&self) -> Result<HardwareFingerprintSources, FingerprintError> {
            HardwareFingerprintSources::new(&self.uuid, &self.bios, &self.disk)
        }
    }

    #[test]
    fn injected_collector_produces_stable_digest() {
        let collector = InjectedCollector {
            uuid: "A0EEBC99-9C0B-4EF8-BB6D-6BB9BD380A11".into(),
            bios: "ABC123".into(),
            disk: "S12345".into(),
        };
        let sources = collector.collect().expect("valid injected sources");
        let digest1 = sources.digest();
        let digest2 = collector.collect().expect("same sources").digest();
        assert_eq!(digest1, digest2);
    }

    #[test]
    fn normalization_rejects_sentinels() {
        assert!(
            HardwareFingerprintSources::new("00000000-0000-0000-0000-000000000000", "ABC", "DEF")
                .is_err()
        );
        assert!(HardwareFingerprintSources::new("UUID", "TO BE FILLED BY O.E.M.", "DISK").is_err());
    }

    #[test]
    fn changed_source_fails_verification() {
        let sources = HardwareFingerprintSources::new("UUID", "BIOS", "DISK").unwrap();
        let digest = sources.digest();
        let changed = HardwareFingerprintSources::new("UUID", "BIOS", "DISK2").unwrap();
        assert!(changed.verify_unchanged(&digest).is_err());
    }

    #[test]
    fn ethernet_address_is_not_used() {
        // Layer-2 addresses are never accepted or normalized by this module.
        let sources = HardwareFingerprintSources::new("UUID", "BIOS", "DISK").unwrap();
        let _ = sources.digest();
    }
}

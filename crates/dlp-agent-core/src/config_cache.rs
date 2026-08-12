//! Durable, concurrency-safe current/LKG cache for signed configurations.
//!
//! The cache stores immutable content-addressed bundle files and a small
//! versioned pointer record. Every activation verifies exact bytes with
//! strict Ed25519, schema, key identifier, device audience, content digest,
//! and monotonic version before replacing pointers.

use dlp_crypto::{ConfigurationVerifier, CryptoError};
use dlp_domain::{BundleVersion, DeviceId};
use dlp_protocol::{ConfigurationEnvelopeV1, SignedConfigurationV1};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};

const WIRE_FORMAT_VERSION: u8 = 1;
const POINTER_MAGIC: &[u8; 8] = b"dlp-ptr1";
const POINTER_SCHEMA_VERSION: u64 = 1;

/// Errors that can occur while staging, verifying, or activating a bundle.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CacheError {
    InvalidSignature,
    InvalidContentHash,
    UnsupportedSchema,
    WrongAudience,
    WrongKeyId,
    StaleVersion { received: u64, active: u64 },
    IoFailure,
    CorruptPointer,
    MissingBundle,
    InvalidWireFormat,
}

impl std::fmt::Display for CacheError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidSignature => write!(formatter, "configuration signature invalid"),
            Self::InvalidContentHash => write!(formatter, "configuration content hash mismatch"),
            Self::UnsupportedSchema => write!(formatter, "unsupported configuration schema"),
            Self::WrongAudience => write!(formatter, "configuration audience mismatch"),
            Self::WrongKeyId => write!(formatter, "configuration key identifier mismatch"),
            Self::StaleVersion { received, active } => {
                write!(formatter, "configuration version {received} is not newer than {active}")
            }
            Self::IoFailure => write!(formatter, "cache I/O failure"),
            Self::CorruptPointer => write!(formatter, "cache pointer corrupt"),
            Self::MissingBundle => write!(formatter, "cached bundle missing"),
            Self::InvalidWireFormat => write!(formatter, "invalid configuration wire format"),
        }
    }
}

impl std::error::Error for CacheError {}

/// Stable view of the selected current and last-known-good bundles.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CachePointers {
    pub current_digest: Option<[u8; 32]>,
    pub current_version: Option<u64>,
    pub lkg_digest: Option<[u8; 32]>,
    pub lkg_version: Option<u64>,
}

/// Result of a successful activation attempt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ActivationOutcome {
    Activated { version: u64, digest: [u8; 32] },
    Unchanged,
}

struct ActivationState {
    generation: u64,
}

/// Durable cache of signed configurations.
pub struct ConfigurationCache {
    root: PathBuf,
    device_id: DeviceId,
    activation: Mutex<ActivationState>,
}

impl ConfigurationCache {
    /// Opens or creates a cache rooted at `root` for the given device audience.
    pub fn open(root: impl AsRef<Path>, device_id: DeviceId) -> Result<Self, CacheError> {
        let root = root.as_ref().to_path_buf();
        fs::create_dir_all(&root).map_err(|_| CacheError::IoFailure)?;
        fs::create_dir_all(root.join("staging")).map_err(|_| CacheError::IoFailure)?;
        Ok(Self {
            root,
            device_id,
            activation: Mutex::new(ActivationState { generation: 0 }),
        })
    }

    /// Returns the device audience bound to this cache.
    pub fn device_id(&self) -> &DeviceId {
        &self.device_id
    }

    /// Stages raw bytes, verifies them, and atomically activates if valid and newer.
    ///
    /// Verification order:
    /// 1. Wire format and content-digest integrity.
    /// 2. Strict Ed25519 signature over canonical envelope bytes.
    /// 3. Supported schema, trusted key identifier, device audience.
    /// 4. Strictly increasing numeric bundle version versus current.
    pub fn stage_verify_activate(
        &self,
        bytes: &[u8],
        verifier: &ConfigurationVerifier,
    ) -> Result<ActivationOutcome, CacheError> {
        let mut state = self.lock_activation()?;

        let signed = deserialize_signed_configuration(bytes)?;

        // Fixed hash: the digest stored in the bundle must match the envelope.
        let envelope_digest: [u8; 32] = Sha256::digest(signed.envelope().canonical_bytes()).into();
        if signed.content_digest() != &envelope_digest {
            return Err(CacheError::InvalidContentHash);
        }

        verifier
            .verify(
                signed.envelope().schema_version(),
                signed.key_id(),
                &signed.envelope().canonical_bytes(),
                signed.signature(),
            )
            .map_err(map_crypto_error)?;

        if signed.audience() != &self.device_id {
            return Err(CacheError::WrongAudience);
        }

        let version = parse_bundle_version(signed.envelope().bundle_version())?;
        let pointers = self.read_pointers()?;
        if let Some(current_version) = pointers.current_version
            && version <= current_version
        {
            return Err(CacheError::StaleVersion {
                received: version,
                active: current_version,
            });
        }

        let digest = *signed.content_digest();
        self.write_staged_bundle(&digest, bytes)?;

        let new_generation = state.generation.saturating_add(1);
        let new_pointers = CachePointers {
            current_digest: Some(digest),
            current_version: Some(version),
            lkg_digest: pointers.current_digest,
            lkg_version: pointers.current_version,
        };

        self.write_pointers(&new_pointers, new_generation)?;
        state.generation = new_generation;

        // Unreferenced staging is safe to clean only after pointers are durable.
        let _ = self.clean_staging(&new_pointers);

        Ok(ActivationOutcome::Activated { version, digest })
    }

    /// Loads the current pointer record from disk, validating each bundle independently.
    pub fn load_pointers(&self) -> Result<CachePointers, CacheError> {
        self.read_pointers()
    }

    /// Returns the current bundle if one is selected and independently valid.
    pub fn current_bundle(&self) -> Result<Option<SignedConfigurationV1>, CacheError> {
        let pointers = self.read_pointers()?;
        match pointers.current_digest {
            Some(digest) => self.load_bundle_at_digest(&digest),
            None => Ok(None),
        }
    }

    /// Returns the last-known-good bundle if one is selected and independently valid.
    pub fn lkg_bundle(&self) -> Result<Option<SignedConfigurationV1>, CacheError> {
        let pointers = self.read_pointers()?;
        match pointers.lkg_digest {
            Some(digest) => self.load_bundle_at_digest(&digest),
            None => Ok(None),
        }
    }

    /// Removes unreferenced staged bundles. Called automatically after activation;
    /// exposed for tests and restart cleanup.
    pub fn clean_staging(&self, pointers: &CachePointers) -> Result<(), CacheError> {
        let referenced: std::collections::HashSet<[u8; 32]> = [
            pointers.current_digest,
            pointers.lkg_digest,
        ]
        .into_iter()
        .flatten()
        .collect();

        let entries = fs::read_dir(self.root.join("staging")).map_err(|_| CacheError::IoFailure)?;
        for entry in entries {
            let entry = entry.map_err(|_| CacheError::IoFailure)?;
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if let Ok(digest) = hex::parse(&name)
                && !referenced.contains(&digest)
            {
                let _ = fs::remove_file(entry.path());
            }
        }
        Ok(())
    }

    fn load_bundle_at_digest(
        &self,
        digest: &[u8; 32],
    ) -> Result<Option<SignedConfigurationV1>, CacheError> {
        let bytes = self.read_staged_bundle(digest)?;
        let signed = deserialize_signed_configuration(&bytes)?;
        if signed.content_digest() != digest {
            return Err(CacheError::CorruptPointer);
        }
        Ok(Some(signed))
    }

    fn lock_activation(&self) -> Result<MutexGuard<'_, ActivationState>, CacheError> {
        self.activation.lock().map_err(|_| CacheError::IoFailure)
    }

    fn staging_path(&self, digest: &[u8; 32]) -> PathBuf {
        self.root.join("staging").join(hex::encode(digest))
    }

    fn pointers_path(&self) -> PathBuf {
        self.root.join("pointers")
    }

    fn temp_pointers_path(&self) -> PathBuf {
        self.root.join("pointers.tmp")
    }

    fn write_staged_bundle(&self, digest: &[u8; 32], bytes: &[u8]) -> Result<(), CacheError> {
        let path = self.staging_path(digest);
        let temp = path.with_extension("tmp");
        write_file_atomic(&path, &temp, bytes)
    }

    fn read_staged_bundle(&self, digest: &[u8; 32]) -> Result<Vec<u8>, CacheError> {
        fs::read(self.staging_path(digest)).map_err(|_| CacheError::MissingBundle)
    }

    fn read_pointers(&self) -> Result<CachePointers, CacheError> {
        let path = self.pointers_path();
        if !path.exists() {
            return Ok(CachePointers::default());
        }
        let bytes = fs::read(&path).map_err(|_| CacheError::IoFailure)?;
        deserialize_pointers(&bytes)
    }

    fn write_pointers(
        &self,
        pointers: &CachePointers,
        generation: u64,
    ) -> Result<(), CacheError> {
        let bytes = serialize_pointers(pointers, generation);
        let path = self.pointers_path();
        let temp = self.temp_pointers_path();
        write_file_atomic(&path, &temp, &bytes)
    }
}

fn parse_bundle_version(version: &BundleVersion) -> Result<u64, CacheError> {
    version
        .to_wire()
        .parse::<u64>()
        .map_err(|_| CacheError::InvalidWireFormat)
}

fn map_crypto_error(error: CryptoError) -> CacheError {
    match error {
        CryptoError::UnsupportedSchema { .. } => CacheError::UnsupportedSchema,
        CryptoError::KeyIdMismatch => CacheError::WrongKeyId,
        CryptoError::SignatureInvalid
        | CryptoError::InvalidSignatureLength
        | CryptoError::InvalidPublicKey
        | CryptoError::WeakKey => CacheError::InvalidSignature,
        CryptoError::InvalidKeyId => CacheError::WrongKeyId,
        _ => CacheError::InvalidSignature,
    }
}

fn write_file_atomic(path: &Path, temp: &Path, bytes: &[u8]) -> Result<(), CacheError> {
    let mut file = fs::File::create(temp).map_err(|_| CacheError::IoFailure)?;
    file.write_all(bytes).map_err(|_| CacheError::IoFailure)?;
    file.sync_all().map_err(|_| CacheError::IoFailure)?;
    drop(file);
    fs::rename(temp, path).map_err(|_| CacheError::IoFailure)?;
    Ok(())
}

/// Serializes a signed configuration into the cache wire format.
pub fn serialize_signed_configuration(signed: &SignedConfigurationV1) -> Vec<u8> {
    let mut output = Vec::new();
    output.push(WIRE_FORMAT_VERSION);
    append_u16(&mut output, signed.version());
    append_u16(&mut output, signed.envelope().schema_version());
    append_string(&mut output, signed.key_id());
    append_string(&mut output, signed.envelope().device_id().to_wire());
    append_string(&mut output, signed.envelope().bundle_version().to_wire());
    append_u64(&mut output, signed.envelope().issued_at_epoch_seconds());
    append_string(&mut output, signed.envelope().payload());
    append_bytes(&mut output, signed.signature());
    output.extend_from_slice(signed.content_digest());
    output
}

/// Deserializes and validates the cache wire format for a signed configuration.
pub fn deserialize_signed_configuration(bytes: &[u8]) -> Result<SignedConfigurationV1, CacheError> {
    let mut reader = ByteReader::new(bytes);
    let format_version = reader.read_u8()?;
    if format_version != WIRE_FORMAT_VERSION {
        return Err(CacheError::InvalidWireFormat);
    }
    let _api_version = reader.read_u16()?;
    let schema_version = reader.read_u16()?;
    if schema_version != dlp_protocol::CONFIGURATION_SCHEMA_VERSION_V1 {
        return Err(CacheError::UnsupportedSchema);
    }
    let key_id = reader.read_string()?;
    let device_id = reader.read_string()?;
    let bundle_version = reader.read_string()?;
    let issued_at = reader.read_u64()?;
    let payload = reader.read_string()?;
    let signature = reader.read_bytes()?;
    let content_digest = reader.read_fixed_bytes::<32>()?;
    reader.expect_empty()?;

    let device_id = DeviceId::parse(&device_id).map_err(|_| CacheError::InvalidWireFormat)?;
    let bundle_version =
        BundleVersion::parse(&bundle_version).map_err(|_| CacheError::InvalidWireFormat)?;
    let envelope = ConfigurationEnvelopeV1::new(schema_version, device_id, bundle_version, issued_at, payload)
        .map_err(|_| CacheError::InvalidWireFormat)?;

    // Validate that the embedded digest matches the envelope it claims to protect.
    let envelope_digest: [u8; 32] = Sha256::digest(envelope.canonical_bytes()).into();
    if envelope_digest != content_digest {
        return Err(CacheError::InvalidContentHash);
    }

    SignedConfigurationV1::new(envelope, key_id, signature)
        .map_err(|_| CacheError::InvalidWireFormat)
}

fn serialize_pointers(pointers: &CachePointers, generation: u64) -> Vec<u8> {
    let mut output = Vec::new();
    output.extend_from_slice(POINTER_MAGIC);
    append_u64(&mut output, POINTER_SCHEMA_VERSION);
    append_u64(&mut output, generation);
    append_optional_digest(&mut output, pointers.current_digest);
    if pointers.current_digest.is_some() {
        append_u64(&mut output, pointers.current_version.unwrap_or(0));
    }
    append_optional_digest(&mut output, pointers.lkg_digest);
    if pointers.lkg_digest.is_some() {
        append_u64(&mut output, pointers.lkg_version.unwrap_or(0));
    }
    output
}

fn deserialize_pointers(bytes: &[u8]) -> Result<CachePointers, CacheError> {
    let mut reader = ByteReader::new(bytes);
    let magic = reader.read_fixed_bytes::<8>()?;
    if &magic != POINTER_MAGIC {
        return Err(CacheError::CorruptPointer);
    }
    let schema_version = reader.read_u64()?;
    if schema_version != POINTER_SCHEMA_VERSION {
        return Err(CacheError::CorruptPointer);
    }
    let _generation = reader.read_u64()?;
    let current_digest = reader.read_optional_digest()?;
    let current_version = current_digest.map(|_| reader.read_u64().unwrap_or(0));
    let lkg_digest = reader.read_optional_digest()?;
    let lkg_version = lkg_digest.map(|_| reader.read_u64().unwrap_or(0));
    reader.expect_empty()?;

    Ok(CachePointers {
        current_digest,
        current_version,
        lkg_digest,
        lkg_version,
    })
}

fn append_u16(output: &mut Vec<u8>, value: u16) {
    output.extend_from_slice(&value.to_be_bytes());
}

fn append_u64(output: &mut Vec<u8>, value: u64) {
    output.extend_from_slice(&value.to_be_bytes());
}

fn append_string(output: &mut Vec<u8>, value: &str) {
    append_bytes(output, value.as_bytes());
}

fn append_bytes(output: &mut Vec<u8>, value: &[u8]) {
    let length = u32::try_from(value.len()).expect("validated protocol field length");
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value);
}

fn append_optional_digest(output: &mut Vec<u8>, digest: Option<[u8; 32]>) {
    match digest {
        Some(digest) => {
            output.push(1);
            output.extend_from_slice(&digest);
        }
        None => output.push(0),
    }
}

struct ByteReader<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> ByteReader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.position)
    }

    fn read_u8(&mut self) -> Result<u8, CacheError> {
        if self.remaining() < 1 {
            return Err(CacheError::InvalidWireFormat);
        }
        let value = self.bytes[self.position];
        self.position += 1;
        Ok(value)
    }

    fn read_u16(&mut self) -> Result<u16, CacheError> {
        if self.remaining() < 2 {
            return Err(CacheError::InvalidWireFormat);
        }
        let value = u16::from_be_bytes([
            self.bytes[self.position],
            self.bytes[self.position + 1],
        ]);
        self.position += 2;
        Ok(value)
    }

    fn read_u64(&mut self) -> Result<u64, CacheError> {
        if self.remaining() < 8 {
            return Err(CacheError::InvalidWireFormat);
        }
        let value = u64::from_be_bytes([
            self.bytes[self.position],
            self.bytes[self.position + 1],
            self.bytes[self.position + 2],
            self.bytes[self.position + 3],
            self.bytes[self.position + 4],
            self.bytes[self.position + 5],
            self.bytes[self.position + 6],
            self.bytes[self.position + 7],
        ]);
        self.position += 8;
        Ok(value)
    }

    fn read_fixed_bytes<const N: usize>(&mut self) -> Result<[u8; N], CacheError> {
        if self.remaining() < N {
            return Err(CacheError::InvalidWireFormat);
        }
        let mut output = [0u8; N];
        output.copy_from_slice(&self.bytes[self.position..self.position + N]);
        self.position += N;
        Ok(output)
    }

    fn read_bytes(&mut self) -> Result<Vec<u8>, CacheError> {
        let length = self.read_u32()? as usize;
        if self.remaining() < length {
            return Err(CacheError::InvalidWireFormat);
        }
        let value = self.bytes[self.position..self.position + length].to_vec();
        self.position += length;
        Ok(value)
    }

    fn read_u32(&mut self) -> Result<u32, CacheError> {
        if self.remaining() < 4 {
            return Err(CacheError::InvalidWireFormat);
        }
        let value = u32::from_be_bytes([
            self.bytes[self.position],
            self.bytes[self.position + 1],
            self.bytes[self.position + 2],
            self.bytes[self.position + 3],
        ]);
        self.position += 4;
        Ok(value)
    }

    fn read_string(&mut self) -> Result<String, CacheError> {
        let bytes = self.read_bytes()?;
        String::from_utf8(bytes).map_err(|_| CacheError::InvalidWireFormat)
    }

    fn read_optional_digest(&mut self) -> Result<Option<[u8; 32]>, CacheError> {
        match self.read_u8()? {
            0 => Ok(None),
            1 => Ok(Some(self.read_fixed_bytes::<32>()?)),
            _ => Err(CacheError::CorruptPointer),
        }
    }

    fn expect_empty(&self) -> Result<(), CacheError> {
        if self.remaining() == 0 {
            Ok(())
        } else {
            Err(CacheError::InvalidWireFormat)
        }
    }
}

mod hex {
    pub fn encode(bytes: &[u8; 32]) -> String {
        let mut output = String::with_capacity(64);
        for byte in bytes {
            output.push_str(&format!("{byte:02x}"));
        }
        output
    }

    pub fn parse(value: &str) -> Result<[u8; 32], ()> {
        if value.len() != 64 {
            return Err(());
        }
        let mut output = [0u8; 32];
        for (index, chunk) in value.as_bytes().chunks(2).enumerate() {
            let chunk = std::str::from_utf8(chunk).map_err(|_| ())?;
            output[index] = u8::from_str_radix(chunk, 16).map_err(|_| ())?;
        }
        Ok(output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dlp_crypto::ConfigurationSigner;

    fn test_device() -> DeviceId {
        DeviceId::parse("device-01").expect("valid device")
    }

    fn test_signer() -> ConfigurationSigner {
        ConfigurationSigner::from_seed("key-01", [7; 32])
    }

    fn signed_bundle(
        device_id: &DeviceId,
        version: u64,
        payload: &str,
        signer: &ConfigurationSigner,
    ) -> (SignedConfigurationV1, Vec<u8>) {
        let bundle_version = BundleVersion::parse(version.to_string()).expect("valid version");
        let envelope = ConfigurationEnvelopeV1::new(
            dlp_protocol::CONFIGURATION_SCHEMA_VERSION_V1,
            device_id.clone(),
            bundle_version,
            1_700_000_000,
            payload,
        )
        .expect("valid envelope");
        let signature = signer.sign(&envelope.canonical_bytes());
        let signed = SignedConfigurationV1::new(envelope, signer.key_id(), signature)
            .expect("valid signed configuration");
        let bytes = serialize_signed_configuration(&signed);
        (signed, bytes)
    }

    #[test]
    fn activate_valid_bundle_selects_current_with_no_lkg() {
        let tmp = std::env::temp_dir().join(format!(
            "dlp-cache-test-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&tmp);
        let cache = ConfigurationCache::open(&tmp, test_device()).expect("open cache");
        let signer = test_signer();
        let (_, bytes) = signed_bundle(&test_device(), 1, "allow", &signer);
        let verifier = ConfigurationVerifier::from_public_key_bytes(signer.key_id(), signer.public_key_bytes())
            .expect("valid verifier");

        let outcome = cache
            .stage_verify_activate(&bytes, &verifier)
            .expect("activate");
        assert_eq!(
            outcome,
            ActivationOutcome::Activated {
                version: 1,
                digest: *signed_bundle(&test_device(), 1, "allow", &signer).0.content_digest()
            }
        );

        let pointers = cache.load_pointers().expect("load pointers");
        assert_eq!(pointers.current_version, Some(1));
        assert!(pointers.lkg_version.is_none());

        let current = cache.current_bundle().expect("current").expect("present");
        assert_eq!(current.envelope().payload(), "allow");

        let _ = fs::remove_dir_all(&tmp);
    }
}

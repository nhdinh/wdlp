use crate::StorageError;
use dlp_crypto::{FORMAT_ID_V1, NONCE_LENGTH, NonceTracker, RecordAad, RecordCipher, RecordKind};

pub const FORMAT_VERSION_V1: u16 = 1;
const MAGIC: &[u8; 4] = b"DLP1";
const MAX_CIPHERTEXT: usize = 4 * 1024 * 1024 + 64 * 1024;

/// Fixed-field persisted AEAD record. Its header is also bound as AAD.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EncryptedRecordV1 {
    pub format_version: u16,
    pub store_id: String,
    pub file_id: String,
    pub generation: u64,
    pub record_kind: RecordKind,
    pub chunk_index: u64,
    pub plaintext_length: u64,
    pub nonce: [u8; NONCE_LENGTH],
    pub ciphertext: Vec<u8>,
}

impl EncryptedRecordV1 {
    pub fn seal(
        cipher: &RecordCipher,
        aad: RecordAad,
        plaintext: &[u8],
        nonces: &mut NonceTracker,
    ) -> Result<Self, StorageError> {
        let (nonce, ciphertext) = cipher
            .encrypt(&aad, plaintext)
            .map_err(|_| StorageError::IntegrityFailure)?;
        nonces
            .insert(nonce)
            .map_err(|_| StorageError::IntegrityFailure)?;
        Ok(Self {
            format_version: aad.format_version,
            store_id: aad.store_id,
            file_id: aad.file_id,
            generation: aad.generation,
            record_kind: aad.record_kind,
            chunk_index: aad.chunk_index,
            plaintext_length: aad.plaintext_length,
            nonce,
            ciphertext,
        })
    }

    pub fn aad(&self) -> RecordAad {
        RecordAad {
            format_version: self.format_version,
            store_id: self.store_id.clone(),
            file_id: self.file_id.clone(),
            generation: self.generation,
            record_kind: self.record_kind,
            chunk_index: self.chunk_index,
            plaintext_length: self.plaintext_length,
        }
    }

    pub fn open(&self, cipher: &RecordCipher) -> Result<Vec<u8>, StorageError> {
        if self.format_version != FORMAT_VERSION_V1 || self.plaintext_length > (usize::MAX as u64) {
            return Err(StorageError::IntegrityFailure);
        }
        let plaintext = cipher
            .decrypt(&self.aad(), &self.nonce, &self.ciphertext)
            .map_err(|_| StorageError::IntegrityFailure)?;
        if plaintext.len() as u64 != self.plaintext_length {
            return Err(StorageError::IntegrityFailure);
        }
        Ok(plaintext)
    }

    pub fn encode(&self) -> Result<Vec<u8>, StorageError> {
        if self.store_id.len() > u16::MAX as usize
            || self.file_id.len() > u16::MAX as usize
            || self.ciphertext.len() > MAX_CIPHERTEXT
        {
            return Err(StorageError::IntegrityFailure);
        }
        let mut bytes = Vec::with_capacity(
            96 + self.store_id.len() + self.file_id.len() + self.ciphertext.len(),
        );
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&self.format_version.to_le_bytes());
        bytes.extend_from_slice(&(self.store_id.len() as u16).to_le_bytes());
        bytes.extend_from_slice(self.store_id.as_bytes());
        bytes.extend_from_slice(&(self.file_id.len() as u16).to_le_bytes());
        bytes.extend_from_slice(self.file_id.as_bytes());
        bytes.extend_from_slice(&self.generation.to_le_bytes());
        bytes.push(self.record_kind.as_byte());
        bytes.extend_from_slice(&self.chunk_index.to_le_bytes());
        bytes.extend_from_slice(&self.plaintext_length.to_le_bytes());
        bytes.extend_from_slice(&self.nonce);
        bytes.extend_from_slice(&(self.ciphertext.len() as u64).to_le_bytes());
        bytes.extend_from_slice(&self.ciphertext);
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, StorageError> {
        let mut cursor = Cursor::new(bytes);
        if cursor.take(4)? != MAGIC {
            return Err(StorageError::IntegrityFailure);
        }
        let format_version = cursor.u16()?;
        let store_length = cursor.u16()? as usize;
        let store_id = cursor.text(store_length)?;
        let file_length = cursor.u16()? as usize;
        let file_id = cursor.text(file_length)?;
        let generation = cursor.u64()?;
        let record_kind = match cursor.byte()? {
            1 => RecordKind::Chunk,
            2 => RecordKind::Manifest,
            3 => RecordKind::Commit,
            _ => return Err(StorageError::IntegrityFailure),
        };
        let chunk_index = cursor.u64()?;
        let plaintext_length = cursor.u64()?;
        let nonce: [u8; NONCE_LENGTH] = cursor
            .take(NONCE_LENGTH)?
            .try_into()
            .map_err(|_| StorageError::IntegrityFailure)?;
        let ciphertext_len = cursor.u64()? as usize;
        if ciphertext_len > MAX_CIPHERTEXT || cursor.remaining() != ciphertext_len {
            return Err(StorageError::IntegrityFailure);
        }
        let ciphertext = cursor.take(ciphertext_len)?.to_vec();
        Ok(Self {
            format_version,
            store_id,
            file_id,
            generation,
            record_kind,
            chunk_index,
            plaintext_length,
            nonce,
            ciphertext,
        })
    }
}

/// Encrypted directory metadata for one immutable file generation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EncryptedManifestV1 {
    pub generation: u64,
    pub file_id: String,
    pub logical_length: u64,
    pub chunk_lengths: Vec<u64>,
}

impl EncryptedManifestV1 {
    pub fn encode(&self) -> Result<Vec<u8>, StorageError> {
        if self.file_id.len() > u16::MAX as usize || self.chunk_lengths.len() > u32::MAX as usize {
            return Err(StorageError::IntegrityFailure);
        }
        let mut out = Vec::new();
        out.extend_from_slice(FORMAT_ID_V1.as_bytes());
        out.push(0);
        out.extend_from_slice(&self.generation.to_le_bytes());
        out.extend_from_slice(&(self.file_id.len() as u16).to_le_bytes());
        out.extend_from_slice(self.file_id.as_bytes());
        out.extend_from_slice(&self.logical_length.to_le_bytes());
        out.extend_from_slice(&(self.chunk_lengths.len() as u32).to_le_bytes());
        for length in &self.chunk_lengths {
            out.extend_from_slice(&length.to_le_bytes());
        }
        Ok(out)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, StorageError> {
        let prefix = [FORMAT_ID_V1.as_bytes(), &[0]].concat();
        if !bytes.starts_with(&prefix) {
            return Err(StorageError::IntegrityFailure);
        }
        let mut cursor = Cursor::new(&bytes[prefix.len()..]);
        let generation = cursor.u64()?;
        let file_length = cursor.u16()? as usize;
        let file_id = cursor.text(file_length)?;
        let logical_length = cursor.u64()?;
        let count = cursor.u32()? as usize;
        if count > 1_000_000 || cursor.remaining() != count.saturating_mul(8) {
            return Err(StorageError::IntegrityFailure);
        }
        let mut chunk_lengths = Vec::with_capacity(count);
        for _ in 0..count {
            chunk_lengths.push(cursor.u64()?);
        }
        Ok(Self {
            generation,
            file_id,
            logical_length,
            chunk_lengths,
        })
    }
}

/// Authenticated selected-generation payload; publication writes this record last.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommitRecordV1 {
    pub generation: u64,
    pub file_id: String,
}
impl CommitRecordV1 {
    pub fn encode(&self) -> Result<Vec<u8>, StorageError> {
        if self.file_id.len() > u16::MAX as usize {
            return Err(StorageError::IntegrityFailure);
        }
        let mut out = Vec::new();
        out.extend_from_slice(&self.generation.to_le_bytes());
        out.extend_from_slice(&(self.file_id.len() as u16).to_le_bytes());
        out.extend_from_slice(self.file_id.as_bytes());
        Ok(out)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, StorageError> {
        let mut cursor = Cursor::new(bytes);
        let generation = cursor.u64()?;
        let file_length = cursor.u16()? as usize;
        let file_id = cursor.text(file_length)?;
        if cursor.remaining() != 0 {
            return Err(StorageError::IntegrityFailure);
        }
        Ok(Self {
            generation,
            file_id,
        })
    }
}

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}
impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }
    fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.offset)
    }
    fn take(&mut self, count: usize) -> Result<&'a [u8], StorageError> {
        let end = self
            .offset
            .checked_add(count)
            .ok_or(StorageError::IntegrityFailure)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(StorageError::IntegrityFailure)?;
        self.offset = end;
        Ok(value)
    }
    fn byte(&mut self) -> Result<u8, StorageError> {
        Ok(*self
            .take(1)?
            .first()
            .ok_or(StorageError::IntegrityFailure)?)
    }
    fn u16(&mut self) -> Result<u16, StorageError> {
        Ok(u16::from_le_bytes(
            self.take(2)?
                .try_into()
                .map_err(|_| StorageError::IntegrityFailure)?,
        ))
    }
    fn u32(&mut self) -> Result<u32, StorageError> {
        Ok(u32::from_le_bytes(
            self.take(4)?
                .try_into()
                .map_err(|_| StorageError::IntegrityFailure)?,
        ))
    }
    fn u64(&mut self) -> Result<u64, StorageError> {
        Ok(u64::from_le_bytes(
            self.take(8)?
                .try_into()
                .map_err(|_| StorageError::IntegrityFailure)?,
        ))
    }
    fn text(&mut self, count: usize) -> Result<String, StorageError> {
        let raw = self.take(count)?;
        let text = std::str::from_utf8(raw).map_err(|_| StorageError::IntegrityFailure)?;
        if text.is_empty()
            || text.len() > 128
            || !text
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            return Err(StorageError::IntegrityFailure);
        }
        Ok(text.to_owned())
    }
}

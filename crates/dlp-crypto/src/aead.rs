use crate::{CryptoError, StoreKey};
use aes_gcm::{
    Aes256Gcm, KeyInit, Nonce,
    aead::{Aead, Generate, Payload},
};
use std::collections::BTreeSet;

pub const FORMAT_ID_V1: &str = "dlp-store/aes256gcm-4m/v1";
pub const NONCE_LENGTH: usize = 12;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecordKind {
    Chunk,
    Manifest,
    Commit,
}

impl RecordKind {
    pub const fn as_byte(self) -> u8 {
        match self {
            Self::Chunk => 1,
            Self::Manifest => 2,
            Self::Commit => 3,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordAad {
    pub format_version: u16,
    pub store_id: String,
    pub file_id: String,
    pub generation: u64,
    pub record_kind: RecordKind,
    pub chunk_index: u64,
    pub plaintext_length: u64,
}

impl RecordAad {
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(96 + self.store_id.len() + self.file_id.len());
        bytes.extend_from_slice(FORMAT_ID_V1.as_bytes());
        bytes.extend_from_slice(&self.format_version.to_le_bytes());
        for value in [&self.store_id, &self.file_id] {
            bytes.extend_from_slice(&(value.len() as u16).to_le_bytes());
            bytes.extend_from_slice(value.as_bytes());
        }
        bytes.extend_from_slice(&self.generation.to_le_bytes());
        bytes.push(self.record_kind.as_byte());
        bytes.extend_from_slice(&self.chunk_index.to_le_bytes());
        bytes.extend_from_slice(&self.plaintext_length.to_le_bytes());
        bytes
    }
}

pub struct RecordCipher {
    cipher: Aes256Gcm,
}

impl RecordCipher {
    pub fn from_store_key(key: &StoreKey) -> Self {
        let cipher = key.with_bytes(|bytes| {
            Aes256Gcm::new_from_slice(bytes).expect("AES-256 key is exactly 32 bytes")
        });
        Self { cipher }
    }

    pub fn encrypt(
        &self,
        aad: &RecordAad,
        plaintext: &[u8],
    ) -> Result<([u8; NONCE_LENGTH], Vec<u8>), CryptoError> {
        let nonce = Nonce::generate();
        let nonce_bytes: [u8; NONCE_LENGTH] = nonce
            .as_slice()
            .try_into()
            .map_err(|_| CryptoError::EncryptionFailed)?;
        let ciphertext = self
            .cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: plaintext,
                    aad: &aad.canonical_bytes(),
                },
            )
            .map_err(|_| CryptoError::EncryptionFailed)?;
        Ok((nonce_bytes, ciphertext))
    }

    pub fn decrypt(
        &self,
        aad: &RecordAad,
        nonce: &[u8; NONCE_LENGTH],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        self.cipher
            .decrypt(
                &Nonce::try_from(nonce.as_slice()).map_err(|_| CryptoError::IntegrityFailure)?,
                Payload {
                    msg: ciphertext,
                    aad: &aad.canonical_bytes(),
                },
            )
            .map_err(|_| CryptoError::IntegrityFailure)
    }
}

impl std::fmt::Debug for RecordCipher {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RecordCipher")
            .field("algorithm", &"AES-256-GCM")
            .field("key", &"[REDACTED]")
            .finish()
    }
}

#[derive(Default)]
pub struct NonceTracker(BTreeSet<[u8; NONCE_LENGTH]>);

impl NonceTracker {
    pub fn insert(&mut self, nonce: [u8; NONCE_LENGTH]) -> Result<(), CryptoError> {
        if self.0.insert(nonce) {
            Ok(())
        } else {
            Err(CryptoError::DuplicateNonce)
        }
    }
}

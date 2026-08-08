#![forbid(unsafe_code)]

//! Strict configuration-signature verification and the audited AEAD primitive
//! boundary. This crate intentionally has no persisted record encoder.

use aes_gcm::{Aes256Gcm, KeyInit};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use std::fmt;

pub const CONFIGURATION_SCHEMA_VERSION_V1: u16 = 1;
pub const ED25519_SIGNATURE_LENGTH: usize = 64;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CryptoError {
    InvalidKeyId,
    InvalidPublicKey,
    InvalidSignatureLength,
    KeyIdMismatch,
    UnsupportedSchema { received: u16 },
    WeakKey,
    SignatureInvalid,
}

impl fmt::Display for CryptoError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidKeyId => write!(formatter, "invalid signing key identifier"),
            Self::InvalidPublicKey => write!(formatter, "invalid signing public key"),
            Self::InvalidSignatureLength => write!(formatter, "invalid signature length"),
            Self::KeyIdMismatch => write!(formatter, "signing key identifier mismatch"),
            Self::UnsupportedSchema { received } => {
                write!(formatter, "unsupported configuration schema {received}")
            }
            Self::WeakKey => write!(formatter, "weak signing public key"),
            Self::SignatureInvalid => {
                write!(formatter, "configuration signature verification failed")
            }
        }
    }
}

impl std::error::Error for CryptoError {}

/// Server-side signer for a single configuration-signing key identifier.
pub struct ConfigurationSigner {
    key_id: String,
    signing_key: SigningKey,
}

impl ConfigurationSigner {
    pub fn from_seed(key_id: impl Into<String>, seed: [u8; 32]) -> Self {
        Self {
            key_id: key_id.into(),
            signing_key: SigningKey::from_bytes(&seed),
        }
    }

    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.signing_key.verifying_key().to_bytes()
    }

    /// Signs the protocol crate's fixed-field canonical envelope bytes.
    pub fn sign(&self, canonical_bytes: &[u8]) -> Vec<u8> {
        self.signing_key.sign(canonical_bytes).to_bytes().to_vec()
    }
}

impl fmt::Debug for ConfigurationSigner {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConfigurationSigner")
            .field("key_id", &self.key_id)
            .field("signing_key", &"[REDACTED]")
            .finish()
    }
}

/// Agent-side verifier. It only accepts the matching trusted key identifier.
pub struct ConfigurationVerifier {
    key_id: String,
    verifying_key: VerifyingKey,
}

impl ConfigurationVerifier {
    pub fn from_public_key_bytes(
        key_id: impl Into<String>,
        bytes: [u8; 32],
    ) -> Result<Self, CryptoError> {
        let key_id = key_id.into();
        if key_id.is_empty() || key_id.len() > 128 {
            return Err(CryptoError::InvalidKeyId);
        }
        let verifying_key =
            VerifyingKey::from_bytes(&bytes).map_err(|_| CryptoError::InvalidPublicKey)?;
        if verifying_key.is_weak() {
            return Err(CryptoError::WeakKey);
        }
        Ok(Self {
            key_id,
            verifying_key,
        })
    }

    pub fn verify(
        &self,
        schema_version: u16,
        key_id: &str,
        canonical_bytes: &[u8],
        signature: &[u8],
    ) -> Result<(), CryptoError> {
        if schema_version != CONFIGURATION_SCHEMA_VERSION_V1 {
            return Err(CryptoError::UnsupportedSchema {
                received: schema_version,
            });
        }
        if key_id != self.key_id {
            return Err(CryptoError::KeyIdMismatch);
        }
        let signature_bytes: [u8; ED25519_SIGNATURE_LENGTH] = signature
            .try_into()
            .map_err(|_| CryptoError::InvalidSignatureLength)?;
        let signature = Signature::from_bytes(&signature_bytes);
        self.verifying_key
            .verify_strict(canonical_bytes, &signature)
            .map_err(|_| CryptoError::SignatureInvalid)
    }

    /// Calls activation only after schema, key identifier, and strict signature checks pass.
    pub fn verify_before_activation(
        &self,
        schema_version: u16,
        key_id: &str,
        canonical_bytes: &[u8],
        signature: &[u8],
        activate: impl FnOnce(),
    ) -> Result<(), CryptoError> {
        self.verify(schema_version, key_id, canonical_bytes, signature)?;
        activate();
        Ok(())
    }
}

impl fmt::Debug for ConfigurationVerifier {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConfigurationVerifier")
            .field("key_id", &self.key_id)
            .field("verifying_key", &"[REDACTED]")
            .finish()
    }
}

/// AES-256-GCM primitive boundary for the approved future store format.
///
/// The future `dlp-store/aes256gcm-4m/v1` writer owns nonce allocation, AAD,
/// record encoding, and durable publication; this type deliberately exposes none
/// of those one-way persisted-format operations.
pub struct RecordCipher {
    cipher: Aes256Gcm,
}

impl RecordCipher {
    pub fn from_key_bytes(key: [u8; 32]) -> Self {
        Self {
            cipher: Aes256Gcm::new_from_slice(&key).expect("AES-256 key is exactly 32 bytes"),
        }
    }

    pub const fn algorithm(&self) -> &'static str {
        "AES-256-GCM"
    }

    pub const fn nonce_size(&self) -> usize {
        12
    }

    /// Exposes the vetted primitive only; this plan defines no record encoding or persistence API.
    pub fn primitive(&self) -> &Aes256Gcm {
        &self.cipher
    }
}

impl fmt::Debug for RecordCipher {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RecordCipher")
            .field("algorithm", &self.algorithm())
            .field("key", &"[REDACTED]")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::{ConfigurationSigner, ConfigurationVerifier, CryptoError, RecordCipher};

    #[test]
    fn strict_verification_rejects_tamper_wrong_key_key_id_schema_and_truncation() {
        let signer = ConfigurationSigner::from_seed("key-01", [7; 32]);
        let verifier =
            ConfigurationVerifier::from_public_key_bytes("key-01", signer.public_key_bytes())
                .expect("valid key");
        let bytes = b"fixed canonical configuration bytes";
        let signature = signer.sign(bytes);

        assert!(verifier.verify(1, "key-01", bytes, &signature).is_ok());
        assert!(matches!(
            verifier.verify(1, "key-01", b"tampered", &signature),
            Err(CryptoError::SignatureInvalid)
        ));
        assert!(matches!(
            verifier.verify(1, "other-key", bytes, &signature),
            Err(CryptoError::KeyIdMismatch)
        ));
        assert!(matches!(
            verifier.verify(2, "key-01", bytes, &signature),
            Err(CryptoError::UnsupportedSchema { .. })
        ));
        assert!(matches!(
            verifier.verify(1, "key-01", bytes, &signature[..63]),
            Err(CryptoError::InvalidSignatureLength)
        ));

        let wrong_signer = ConfigurationSigner::from_seed("wrong", [8; 32]);
        let wrong_verifier =
            ConfigurationVerifier::from_public_key_bytes("key-01", wrong_signer.public_key_bytes())
                .expect("valid wrong key");
        assert!(matches!(
            wrong_verifier.verify(1, "key-01", bytes, &signature),
            Err(CryptoError::SignatureInvalid)
        ));
    }

    #[test]
    fn weak_public_keys_are_rejected_before_verification() {
        assert!(matches!(
            ConfigurationVerifier::from_public_key_bytes("key-01", [0; 32]),
            Err(CryptoError::WeakKey)
        ));
    }

    #[test]
    fn verification_runs_activation_only_after_a_strict_success() {
        let signer = ConfigurationSigner::from_seed("key-01", [7; 32]);
        let verifier =
            ConfigurationVerifier::from_public_key_bytes("key-01", signer.public_key_bytes())
                .expect("valid key");
        let bytes = b"fixed canonical configuration bytes";
        let signature = signer.sign(bytes);
        let mut activations = 0;

        verifier
            .verify_before_activation(1, "key-01", bytes, &signature, || activations += 1)
            .expect("valid configuration activates");
        assert_eq!(activations, 1);
        assert!(
            verifier
                .verify_before_activation(1, "key-01", b"tampered", &signature, || {
                    activations += 1
                })
                .is_err()
        );
        assert_eq!(activations, 1);
    }

    #[test]
    fn aes_gcm_boundary_accepts_only_256_bit_key_material() {
        let cipher = RecordCipher::from_key_bytes([9; 32]);
        assert_eq!(cipher.algorithm(), "AES-256-GCM");
        assert_eq!(cipher.nonce_size(), 12);
        let _ = cipher.primitive();
    }
}

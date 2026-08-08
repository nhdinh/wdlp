#![forbid(unsafe_code)]

#[cfg(test)]
mod tests {
    use super::{ConfigurationSigner, ConfigurationVerifier, CryptoError, RecordCipher};

    #[test]
    fn strict_verification_rejects_tamper_wrong_key_key_id_schema_and_truncation() {
        let signer = ConfigurationSigner::from_seed("key-01", [7; 32]);
        let verifier = ConfigurationVerifier::from_public_key_bytes(
            "key-01",
            signer.public_key_bytes(),
        )
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

        let wrong_verifier = ConfigurationVerifier::from_public_key_bytes("key-01", [8; 32])
            .expect("valid wrong key");
        assert!(matches!(
            wrong_verifier.verify(1, "key-01", bytes, &signature),
            Err(CryptoError::SignatureInvalid)
        ));
    }

    #[test]
    fn verification_runs_activation_only_after_a_strict_success() {
        let signer = ConfigurationSigner::from_seed("key-01", [7; 32]);
        let verifier = ConfigurationVerifier::from_public_key_bytes(
            "key-01",
            signer.public_key_bytes(),
        )
        .expect("valid key");
        let bytes = b"fixed canonical configuration bytes";
        let signature = signer.sign(bytes);
        let mut activations = 0;

        verifier
            .verify_before_activation(1, "key-01", bytes, &signature, || activations += 1)
            .expect("valid configuration activates");
        assert_eq!(activations, 1);
        assert!(verifier
            .verify_before_activation(1, "key-01", b"tampered", &signature, || {
                activations += 1
            })
            .is_err());
        assert_eq!(activations, 1);
    }

    #[test]
    fn aes_gcm_boundary_accepts_only_256_bit_key_material() {
        let cipher = RecordCipher::from_key_bytes([9; 32]);
        assert_eq!(cipher.algorithm(), "AES-256-GCM");
        assert_eq!(cipher.nonce_size(), 12);
    }
}

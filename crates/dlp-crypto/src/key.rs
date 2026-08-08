use secrecy::{ExposeSecret, SecretBox};
use std::fmt;
use zeroize::Zeroizing;

/// A per-user data-encryption key kept in a zeroizing secret container.
pub struct StoreKey(SecretBox<[u8; 32]>);

impl StoreKey {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(SecretBox::new(Box::new(bytes)))
    }

    pub fn with_bytes<T>(&self, operation: impl FnOnce(&[u8; 32]) -> T) -> T {
        operation(self.0.expose_secret())
    }
}

impl Clone for StoreKey {
    fn clone(&self) -> Self {
        let copy = self.with_bytes(|bytes| Zeroizing::new(*bytes));
        Self::from_bytes(*copy)
    }
}

impl fmt::Debug for StoreKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "StoreKey([REDACTED])")
    }
}

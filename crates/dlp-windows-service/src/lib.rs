//! Windows-only service adapters. Portable enrollment logic stays in dlp-agent-core.

pub mod credential;
pub mod fingerprint;
pub mod pipe;
pub mod service;
pub mod session;

pub use credential::{CredentialStore, DeviceCredential, DpapiCredentialStore};

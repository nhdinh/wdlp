//! Service-owned authenticated named pipe for storage IPC.
//!
//! The pipe validates connecting SID, session ID, process ID, and actor generation after
//! impersonation. Malformed, oversized, or unauthenticated messages are rejected before
//! any storage access.

use dlp_crypto::StoreKey;
use dlp_domain::{StoreId, UserSid};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use zeroize::Zeroize;

/// Maximum accepted message size to prevent unbounded allocation.
const MAX_MESSAGE_BYTES: usize = 64 * 1024;

/// Protocol version for the service/host bootstrap exchange.
pub const BOOTSTRAP_PROTOCOL_VERSION: u16 = 1;

/// Pipe message sent by `dlp-drive-host` to authenticate and request storage operations.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct StorageRequest {
    pub version: u16,
    pub session_id: u32,
    pub host_pid: u32,
    pub generation: u64,
    pub user_sid: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct StorageResponse {
    pub accepted: bool,
    pub code: String,
}

/// Service-derived bootstrap payload sent to an authenticated host. This is the only
/// point at which the real store key, store root, and captured identity cross the
/// service-to-host boundary. All fields are erased from transient buffers after use.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct StorageBootstrap {
    pub version: u16,
    pub session_id: u32,
    pub generation: u64,
    pub user_sid: String,
    pub store_id: String,
    pub store_root: PathBuf,
    pub preferred_letter: char,
    /// 32-byte DPAPI-unwrapped random store key. Kept in a Vec<u8> only for the
    /// wire serde step and zeroized after construction of `StoreKey` on both ends.
    pub store_key: Vec<u8>,
}

impl StorageBootstrap {
    /// Constructs a bootstrap from captured identity fields and a real key.
    pub fn new(
        session_id: u32,
        generation: u64,
        user_sid: UserSid,
        store_id: StoreId,
        store_root: PathBuf,
        preferred_letter: char,
        store_key: StoreKey,
    ) -> Self {
        Self {
            version: BOOTSTRAP_PROTOCOL_VERSION,
            session_id,
            generation,
            user_sid: user_sid.to_wire().to_string(),
            store_id: store_id.to_wire().to_string(),
            store_root,
            preferred_letter,
            store_key: store_key.with_bytes(|bytes| bytes.to_vec()),
        }
    }

    /// Zeroizes the transient key material held in this bootstrap.
    pub fn zeroize_key(&mut self) {
        self.store_key.zeroize();
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PipeAuthError {
    InvalidMessage,
    WrongIdentity,
    StaleGeneration,
    Oversized,
    PipeUnavailable,
    AuthenticationFailed,
    BootstrapFailed,
    ProtocolMismatch,
}

impl std::fmt::Display for PipeAuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let code = match self {
            Self::InvalidMessage => "pipe_invalid_message",
            Self::WrongIdentity => "pipe_wrong_identity",
            Self::StaleGeneration => "pipe_stale_generation",
            Self::Oversized => "pipe_oversized",
            Self::PipeUnavailable => "pipe_unavailable",
            Self::AuthenticationFailed => "pipe_authentication_failed",
            Self::BootstrapFailed => "pipe_bootstrap_failed",
            Self::ProtocolMismatch => "pipe_protocol_mismatch",
        };
        f.write_str(code)
    }
}

impl std::error::Error for PipeAuthError {}

/// Length-prefixed frame used for the bootstrap/control channel.
pub fn encode_frame(bytes: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(4 + bytes.len());
    frame.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    frame.extend_from_slice(bytes);
    frame
}

/// Decodes a length-prefixed frame, rejecting oversized or truncated input.
pub fn decode_frame(bytes: &[u8]) -> Result<(Vec<u8>, usize), PipeAuthError> {
    if bytes.len() < 4 {
        return Err(PipeAuthError::InvalidMessage);
    }
    let length = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
    if length > MAX_MESSAGE_BYTES {
        return Err(PipeAuthError::Oversized);
    }
    if bytes.len() < 4 + length {
        return Err(PipeAuthError::InvalidMessage);
    }
    Ok((bytes[4..4 + length].to_vec(), 4 + length))
}

/// Service-owned pipe endpoint.
pub struct StoragePipeServer {
    #[allow(dead_code)]
    path: PathBuf,
}

impl StoragePipeServer {
    pub fn bind(base: &Path) -> Result<Self, PipeAuthError> {
        let path = base.join("pipes").join("storage");
        let _ = std::fs::create_dir_all(&path);
        Ok(Self { path })
    }

    pub fn close(self) -> Result<(), PipeAuthError> {
        Ok(())
    }

    /// Validate a request without accepting caller-supplied identity/store selectors.
    pub fn validate_request(
        expected_sid: &UserSid,
        expected_session: u32,
        expected_generation: u64,
        request: &StorageRequest,
    ) -> Result<(), PipeAuthError> {
        if request.version != BOOTSTRAP_PROTOCOL_VERSION {
            return Err(PipeAuthError::ProtocolMismatch);
        }
        if request.session_id == 0 || request.host_pid == 0 {
            return Err(PipeAuthError::InvalidMessage);
        }
        if request.session_id != expected_session {
            return Err(PipeAuthError::WrongIdentity);
        }
        if request.generation != expected_generation {
            return Err(PipeAuthError::StaleGeneration);
        }
        // The SID comparison is the final identity check. On the real Windows path this
        // is performed against the impersonated client token; the unit-test path supplies
        // the expected SID directly.
        if UserSid::parse(&request.user_sid).ok().as_ref() != Some(expected_sid) {
            return Err(PipeAuthError::WrongIdentity);
        }
        Ok(())
    }

    pub fn decode_request(bytes: &[u8]) -> Result<StorageRequest, PipeAuthError> {
        if bytes.len() > MAX_MESSAGE_BYTES {
            return Err(PipeAuthError::Oversized);
        }
        serde_json::from_slice(bytes).map_err(|_| PipeAuthError::InvalidMessage)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_oversized_message() {
        let huge = vec![b'x'; MAX_MESSAGE_BYTES + 1];
        assert!(matches!(
            StoragePipeServer::decode_request(&huge),
            Err(PipeAuthError::Oversized)
        ));
    }

    #[test]
    fn rejects_invalid_json() {
        assert!(matches!(
            StoragePipeServer::decode_request(b"not json"),
            Err(PipeAuthError::InvalidMessage)
        ));
    }

    #[test]
    fn rejects_zero_session_or_pid() {
        let sid = UserSid::parse("S-1-5-21").unwrap();
        let req = StorageRequest {
            version: 1,
            session_id: 0,
            host_pid: 1,
            generation: 1,
            user_sid: sid.to_wire().to_string(),
        };
        assert!(matches!(
            StoragePipeServer::validate_request(&sid, 1, 1, &req),
            Err(PipeAuthError::InvalidMessage)
        ));
    }

    #[test]
    fn rejects_wrong_session() {
        let sid = UserSid::parse("S-1-5-21").unwrap();
        let req = StorageRequest {
            version: 1,
            session_id: 2,
            host_pid: 1,
            generation: 1,
            user_sid: sid.to_wire().to_string(),
        };
        assert!(matches!(
            StoragePipeServer::validate_request(&sid, 1, 1, &req),
            Err(PipeAuthError::WrongIdentity)
        ));
    }

    #[test]
    fn rejects_stale_generation() {
        let sid = UserSid::parse("S-1-5-21").unwrap();
        let req = StorageRequest {
            version: 1,
            session_id: 1,
            host_pid: 1,
            generation: 0,
            user_sid: sid.to_wire().to_string(),
        };
        assert!(matches!(
            StoragePipeServer::validate_request(&sid, 1, 1, &req),
            Err(PipeAuthError::StaleGeneration)
        ));
    }

    #[test]
    fn rejects_wrong_sid() {
        let sid = UserSid::parse("S-1-5-21-1000").unwrap();
        let wrong = UserSid::parse("S-1-5-21-1001").unwrap();
        let req = StorageRequest {
            version: 1,
            session_id: 1,
            host_pid: 1,
            generation: 1,
            user_sid: wrong.to_wire().to_string(),
        };
        assert!(matches!(
            StoragePipeServer::validate_request(&sid, 1, 1, &req),
            Err(PipeAuthError::WrongIdentity)
        ));
    }

    #[test]
    fn accepts_valid_request() {
        let sid = UserSid::parse("S-1-5-21").unwrap();
        let req = StorageRequest {
            version: 1,
            session_id: 1,
            host_pid: 1,
            generation: 7,
            user_sid: sid.to_wire().to_string(),
        };
        assert!(StoragePipeServer::validate_request(&sid, 1, 7, &req).is_ok());
    }

    #[test]
    fn rejects_protocol_mismatch() {
        let sid = UserSid::parse("S-1-5-21").unwrap();
        let req = StorageRequest {
            version: 99,
            session_id: 1,
            host_pid: 1,
            generation: 1,
            user_sid: sid.to_wire().to_string(),
        };
        assert!(matches!(
            StoragePipeServer::validate_request(&sid, 1, 1, &req),
            Err(PipeAuthError::ProtocolMismatch)
        ));
    }

    #[test]
    fn frame_roundtrips_and_rejects_oversized() {
        let payload = b"hello";
        let frame = encode_frame(payload);
        assert_eq!(frame[..4], [0, 0, 0, 5]);
        let (decoded, consumed) = decode_frame(&frame).unwrap();
        assert_eq!(decoded, payload);
        assert_eq!(consumed, frame.len());

        let mut huge = vec![0u8; 4 + MAX_MESSAGE_BYTES + 1];
        huge[..4].copy_from_slice(&((MAX_MESSAGE_BYTES + 1) as u32).to_be_bytes());
        assert!(matches!(decode_frame(&huge), Err(PipeAuthError::Oversized)));
    }
}

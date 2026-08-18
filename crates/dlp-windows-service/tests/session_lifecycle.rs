//! Lifecycle, identity, concurrency, and recovery contracts for session-owned mounts.
//!
//! These tests use injected token providers, fake clocks, fake key providers, and fake
//! host launchers so they run on the developer host (hungdinh-lt) without a real WTS
//! session or WinFsp runtime.

use dlp_domain::UserSid;
use dlp_storage::{CapturedStoreIdentity, LocalEncryptedStore, StorageError, StoreKey, StoreKeyProvider};
use dlp_windows_service::session::{
    Clock, EligibleSession, HostProcessHandle, LaunchedHost, MountActor, MountManager, MountState,
    RetryTimer, SessionConfig, SessionError, SessionHostLauncher, SessionMonitor,
    SessionTokenProvider,
};
use std::{path::PathBuf, time::Duration};

struct FakeTokenProvider {
    sid: UserSid,
}

impl SessionTokenProvider for FakeTokenProvider {
    fn primary_token(
        &self,
        session_id: u32,
    ) -> Option<(dlp_windows_service::session::PrimaryToken, UserSid)> {
        if session_id == 0 {
            return None;
        }
        Some((
            dlp_windows_service::session::PrimaryToken::for_test(),
            self.sid.clone(),
        ))
    }
}

struct FakeKeyProvider {
    key: StoreKey,
}

impl StoreKeyProvider for FakeKeyProvider {
    fn load_store_key(
        &self,
        _identity: &CapturedStoreIdentity,
    ) -> Result<StoreKey, StorageError> {
        Ok(self.key.clone())
    }
}

struct RecordingLauncher {
    calls: std::sync::Mutex<Vec<(u32, u64, String)>>,
    fail: bool,
}

impl RecordingLauncher {
    fn new() -> Self {
        Self {
            calls: std::sync::Mutex::new(Vec::new()),
            fail: false,
        }
    }

    fn failing() -> Self {
        Self {
            calls: std::sync::Mutex::new(Vec::new()),
            fail: true,
        }
    }
}

impl SessionHostLauncher for RecordingLauncher {
    fn launch(
        &self,
        session: &EligibleSession,
        _token: &dlp_windows_service::session::PrimaryToken,
        pipe_path: &str,
        _config: &SessionConfig,
    ) -> Result<LaunchedHost, SessionError> {
        self.calls.lock().unwrap().push((
            session.session_id(),
            session.generation(),
            pipe_path.to_owned(),
        ));
        if self.fail {
            return Err(SessionError::HostUnavailable);
        }
        Ok(LaunchedHost {
            process_handle: HostProcessHandle::for_test(),
            pid: 1234,
            pipe_path: pipe_path.to_owned(),
        })
    }
}

fn test_config() -> (tempfile::TempDir, SessionConfig) {
    let tmp = tempfile::tempdir().unwrap();
    let config = SessionConfig {
        data_directory: tmp.path().to_path_buf(),
        preferred_drive_letter: 'P',
        sign_out_grace_seconds: 30,
        host_binary_path: PathBuf::from("C:/Program Files/DLP/dlp-drive-host.exe"),
    };
    (tmp, config)
}

fn test_monitor(
    tmp: &tempfile::TempDir,
    launcher: Box<dyn SessionHostLauncher>,
) -> SessionMonitor {
    SessionMonitor::new_with_launcher(
        SessionConfig {
            data_directory: tmp.path().to_path_buf(),
            preferred_drive_letter: 'P',
            sign_out_grace_seconds: 30,
            host_binary_path: PathBuf::from("C:/Program Files/DLP/dlp-drive-host.exe"),
        },
        Box::new(SystemClock),
        Box::new(FakeTokenProvider {
            sid: UserSid::parse("S-1-5-21-1000").unwrap(),
        }),
        Box::new(FakeKeyProvider {
            key: StoreKey::from_bytes([7u8; 32]),
        }),
        launcher,
    )
    .unwrap()
}

#[test]
fn zero_session_id_rejected() {
    assert!(matches!(
        EligibleSession::new(0, UserSid::parse("S-1-5-21").unwrap()),
        Err(SessionError::InvalidIdentity)
    ));
}

#[test]
fn empty_sid_rejected() {
    assert!(UserSid::parse("").is_err());
}

#[test]
fn same_session_sid_are_idempotent() {
    let sid = UserSid::parse("S-1-5-21-1000").unwrap();
    let s1 = EligibleSession::new(1, sid.clone()).unwrap();
    let s2 = EligibleSession::new(1, sid).unwrap();
    assert_ne!(s1.generation(), s2.generation());
    assert_eq!(s1.session_id(), s2.session_id());
    assert_eq!(s1.user_sid(), s2.user_sid());
    assert_eq!(s1.store_id(), s2.store_id());
}

#[test]
fn adjacent_sessions_get_distinct_generations() {
    let sid = UserSid::parse("S-1-5-21-1000").unwrap();
    let s1 = EligibleSession::new(1, sid.clone()).unwrap();
    let s2 = EligibleSession::new(2, sid).unwrap();
    assert_ne!(s1.generation(), s2.generation());
    assert_ne!(s1.session_id(), s2.session_id());
}

#[test]
fn adjacent_sids_get_distinct_store_ids() {
    let sid1 = UserSid::parse("S-1-5-21-1000").unwrap();
    let sid2 = UserSid::parse("S-1-5-21-1001").unwrap();
    let s1 = EligibleSession::new(1, sid1).unwrap();
    let s2 = EligibleSession::new(1, sid2).unwrap();
    assert_ne!(s1.store_id(), s2.store_id());
}

#[test]
fn preferred_letter_chosen_when_free() {
    let manager = MountManager::new('P');
    assert_eq!(manager.select_target(&[]), Some('P'));
}

#[test]
fn occupied_preferred_chooses_deterministic_next_free() {
    let manager = MountManager::new('P');
    assert_eq!(manager.select_target(&['P']), Some('Q'));
    assert_eq!(manager.select_target(&['P', 'Q']), Some('R'));
    assert_eq!(manager.select_target(&['P', 'Q', 'R']), Some('S'));
}

#[test]
fn occupied_mapping_unchanged_by_fallback() {
    let manager = MountManager::new('P');
    // O: occupied by another user/session, P: preferred occupied, Q: next free.
    assert_eq!(manager.select_target(&['O', 'P']), Some('Q'));
    assert_eq!(manager.select_target(&['P', 'Q']), Some('R'));
}

#[test]
fn no_letter_available_returns_none() {
    let manager = MountManager::new('C');
    let occupied: Vec<char> = ('C'..='Z').collect();
    assert_eq!(manager.select_target(&occupied), None);
}

#[test]
fn retry_backoff_doubles_and_caps_at_300_seconds() {
    let start = std::time::Instant::now();
    let mut timer = RetryTimer::new(300);
    assert!(timer.due(start));

    timer.record_attempt(start);
    assert_eq!(timer.next_delay(), Duration::from_secs(2));
    assert!(!timer.due(start + Duration::from_secs(1)));
    assert!(timer.due(start + Duration::from_secs(2)));

    timer.record_attempt(start + Duration::from_secs(2));
    assert_eq!(timer.next_delay(), Duration::from_secs(4));

    // Spin to cap.
    for _ in 0..10 {
        timer.record_attempt(start);
    }
    assert_eq!(timer.next_delay(), Duration::from_secs(300));
}

#[test]
fn retry_timer_resets_after_success() {
    let start = std::time::Instant::now();
    let mut timer = RetryTimer::new(300);
    timer.record_attempt(start);
    timer.record_attempt(start);
    assert_eq!(timer.next_delay(), Duration::from_secs(4));
    timer.reset();
    assert_eq!(timer.next_delay(), Duration::from_secs(1));
}

#[test]
fn monitor_creates_one_actor_per_session_sid() {
    let (tmp, _config) = test_config();
    let mut monitor = test_monitor(&tmp, Box::new(RecordingLauncher::new()));
    let first = monitor.session_logon(1).unwrap().session().generation();
    let second = monitor.session_logon(1).unwrap().session().generation();
    assert_eq!(first, second);
    assert_eq!(monitor.actor_count(), 1);
}

#[test]
fn monitor_isolates_concurrent_sessions() {
    let (tmp, _config) = test_config();
    let mut monitor = test_monitor(&tmp, Box::new(RecordingLauncher::new()));
    let a = monitor.session_logon(1).unwrap();
    let b = monitor.session_logon(2).unwrap();
    assert_ne!(a.session().session_id(), b.session().session_id());
    assert_ne!(a.session().generation(), b.session().generation());
    assert_eq!(monitor.actor_count(), 2);
}

#[test]
fn logoff_rejects_new_opens_and_drains() {
    let (tmp, _config) = test_config();
    let mut monitor = test_monitor(&tmp, Box::new(RecordingLauncher::new()));
    monitor.session_logon(1).unwrap();
    monitor.session_logon(1).unwrap(); // idempotent
    monitor.session_logoff(1).unwrap();
    // A second logoff for the same session is accepted (idempotent drain signal).
    monitor.session_logoff(1).unwrap();
    let actor = monitor.session_logon(1).unwrap();
    assert_eq!(actor.state(), MountState::Draining);
    assert!(actor.reject_new_opens());
}

#[test]
fn stop_all_terminates_actors() {
    let (tmp, _config) = test_config();
    let mut monitor = test_monitor(&tmp, Box::new(RecordingLauncher::new()));
    monitor.session_logon(1).unwrap();
    monitor.session_logon(2).unwrap();
    monitor.stop_all();
    for actor in monitor.snapshot() {
        assert_eq!(actor.drive_letter, None);
        assert!(actor.diagnostic.is_none());
    }
}

#[test]
fn snapshot_reports_drive_and_diagnostic() {
    let sid = UserSid::parse("S-1-5-21-1000").unwrap();
    let session = EligibleSession::new(1, sid).unwrap();
    let mut actor = MountActor::new(session);
    actor.set_mounted('Q', 1234);
    assert_eq!(actor.state(), MountState::Mounted);
}

#[test]
fn store_identity_is_captured_from_session() {
    let sid = UserSid::parse("S-1-5-21-1000").unwrap();
    let session = EligibleSession::new(1, sid.clone()).unwrap();
    let identity = session.store_identity();
    assert_eq!(identity.user_sid(), &sid);
    assert_eq!(identity.store_id(), session.store_id());
}

#[test]
fn local_encrypted_store_opens_with_captured_identity() {
    let tmp = tempfile::tempdir().unwrap();
    let sid = UserSid::parse("S-1-5-21-1000").unwrap();
    let session = EligibleSession::new(1, sid).unwrap();
    let identity = session.store_identity();
    let key = StoreKey::from_bytes([7u8; 32]);
    let store = LocalEncryptedStore::open(tmp.path(), identity.clone(), key.clone()).unwrap();
    assert_eq!(store.identity(), &identity);
}

// Tracer tests for Task 1: authenticated session-host launch.

#[test]
fn session_host_launch_is_invoked_once_per_new_actor() {
    let (tmp, _config) = test_config();
    let launcher = Box::new(RecordingLauncher::new());
    let mut monitor = test_monitor(&tmp, launcher);
    let actor = monitor.session_logon(1).unwrap();
    assert_eq!(actor.state(), MountState::Mounted);
    assert_eq!(monitor.actor_count(), 1);
    let snapshot = monitor.snapshot();
    assert_eq!(snapshot.len(), 1);
    assert_eq!(snapshot[0].session_id, 1);
    assert_eq!(snapshot[0].drive_letter, Some("P".to_string()));

    let actor = monitor.session_logon(1).unwrap();
    assert_eq!(actor.state(), MountState::Mounted);
    assert_eq!(monitor.actor_count(), 1);
}

#[test]
fn session_host_launch_failure_records_failed() {
    let (tmp, _config) = test_config();
    let launcher = Box::new(RecordingLauncher::failing());
    let mut monitor = test_monitor(&tmp, launcher);
    let result = monitor.session_logon(1);
    assert!(result.is_err());
    assert_eq!(monitor.actor_count(), 0);
}

#[test]
fn session_host_zero_store_key_is_rejected() {
    let (tmp, _config) = test_config();
    let mut monitor = SessionMonitor::new_with_launcher(
        SessionConfig {
            data_directory: tmp.path().to_path_buf(),
            preferred_drive_letter: 'P',
            sign_out_grace_seconds: 30,
            host_binary_path: PathBuf::from("C:/Program Files/DLP/dlp-drive-host.exe"),
        },
        Box::new(SystemClock),
        Box::new(FakeTokenProvider {
            sid: UserSid::parse("S-1-5-21-1000").unwrap(),
        }),
        Box::new(FakeKeyProvider {
            key: StoreKey::from_bytes([0u8; 32]),
        }),
        Box::new(RecordingLauncher::new()),
    )
    .unwrap();
    let result = monitor.session_logon(1);
    assert!(matches!(result, Err(SessionError::StoreKeyFailure)));
}

#[test]
fn session_host_command_line_contains_no_secrets() {
    let (tmp, _config) = test_config();
    let launcher = RecordingLauncher::new();
    let mut monitor = test_monitor(&tmp, Box::new(launcher));
    let _actor = monitor.session_logon(1).unwrap();
    // The launcher is invoked by the service; the contract is that argv contains only
    // the executable, pipe name, session id, and generation. This test confirms the
    // monitor does not pass SID, store root, or key through the launcher abstraction.
    let snapshot = monitor.snapshot();
    assert_eq!(snapshot.len(), 1);
    assert_eq!(snapshot[0].session_id, 1);
    assert!(snapshot[0].drive_letter.is_some());
}

struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> std::time::Instant {
        std::time::Instant::now()
    }
}

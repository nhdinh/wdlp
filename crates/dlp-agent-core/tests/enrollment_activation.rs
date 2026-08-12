//! Signed-configuration cache activation, replay, concurrency, and restart contracts.

use dlp_agent_core::{
    ActivationOutcome, AgentHttpClient, CacheError, CachePointers, ConfigurationCache,
    ConfigurationTransport, RedactedDiagnostic,
};
use dlp_crypto::{ConfigurationSigner, ConfigurationVerifier};
use dlp_domain::{BundleVersion, DeviceId};
use dlp_protocol::{ConfigurationEnvelopeV1, SignedConfigurationV1};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Barrier};
use std::thread;

const TEST_DEVICE: &str = "device-01";
const OTHER_DEVICE: &str = "device-02";
const TEST_KEY_ID: &str = "key-01";
const WRONG_KEY_ID: &str = "key-02";

struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new() -> Self {
        let base = std::env::temp_dir();
        let name = format!(
            "dlp-enrollment-activation-{}-{}",
            std::process::id(),
            random_u64()
        );
        let path = base.join(name);
        fs::create_dir_all(&path).expect("create temp dir");
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn random_u64() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64
}

fn device_id(value: &str) -> DeviceId {
    DeviceId::parse(value).expect("valid device id")
}

fn signer(key_id: &str, seed: [u8; 32]) -> ConfigurationSigner {
    ConfigurationSigner::from_seed(key_id, seed)
}

fn verifier(signer: &ConfigurationSigner) -> ConfigurationVerifier {
    ConfigurationVerifier::from_public_key_bytes(signer.key_id(), signer.public_key_bytes())
        .expect("valid verifier")
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
        1_700_000_000 + version,
        payload,
    )
    .expect("valid envelope");
    let signature = signer.sign(&envelope.canonical_bytes());
    let signed = SignedConfigurationV1::new(envelope, signer.key_id(), signature)
        .expect("valid signed configuration");
    let bytes = dlp_agent_core::serialize_signed_configuration(&signed);
    (signed, bytes)
}

fn corrupt_byte(bytes: &mut [u8]) {
    if bytes.is_empty() {
        return;
    }
    // Flip a bit in the payload area, well after the fixed header.
    let index = (bytes.len() / 2).min(bytes.len() - 1);
    bytes[index] ^= 0x01;
}

fn truncate(bytes: &[u8]) -> Vec<u8> {
    bytes.iter().copied().take(bytes.len() / 2).collect()
}

fn assert_pointers_unchanged(
    cache: &ConfigurationCache,
    expected: &CachePointers,
) {
    let actual = cache.load_pointers().expect("load pointers");
    assert_eq!(&actual, expected, "cache pointers should not have changed");
}

#[test]
fn higher_valid_bundle_becomes_current_and_prior_becomes_lkg() {
    let tmp = TempDir::new();
    let cache = ConfigurationCache::open(tmp.path(), device_id(TEST_DEVICE)).expect("open cache");
    let signer = signer(TEST_KEY_ID, [7; 32]);
    let verifier = verifier(&signer);

    let (_, first) = signed_bundle(&device_id(TEST_DEVICE), 1, "allow-pdf", &signer);
    let outcome = cache
        .stage_verify_activate(&first, &verifier)
        .expect("activate first");
    assert!(matches!(outcome, ActivationOutcome::Activated { version: 1, .. }));

    let pointers_after_first = cache.load_pointers().expect("load pointers");
    assert_eq!(pointers_after_first.current_version, Some(1));
    assert!(pointers_after_first.lkg_version.is_none());

    let (_, second) = signed_bundle(&device_id(TEST_DEVICE), 2, "allow-pdf-and-docx", &signer);
    let outcome = cache
        .stage_verify_activate(&second, &verifier)
        .expect("activate second");
    assert!(matches!(outcome, ActivationOutcome::Activated { version: 2, .. }));

    let pointers_after_second = cache.load_pointers().expect("load pointers");
    assert_eq!(pointers_after_second.current_version, Some(2));
    assert_eq!(pointers_after_second.lkg_version, Some(1));
    assert_eq!(pointers_after_second.lkg_digest, pointers_after_first.current_digest);

    let current = cache.current_bundle().expect("current").expect("present");
    assert_eq!(current.envelope().payload(), "allow-pdf-and-docx");

    let lkg = cache.lkg_bundle().expect("lkg").expect("present");
    assert_eq!(lkg.envelope().payload(), "allow-pdf");
}

#[test]
fn unsigned_bundle_preserves_prior_pointers() {
    let tmp = TempDir::new();
    let cache = ConfigurationCache::open(tmp.path(), device_id(TEST_DEVICE)).expect("open cache");
    let signer = signer(TEST_KEY_ID, [7; 32]);
    let verifier = verifier(&signer);

    let (_, valid) = signed_bundle(&device_id(TEST_DEVICE), 1, "allow", &signer);
    cache
        .stage_verify_activate(&valid, &verifier)
        .expect("activate valid");
    let baseline = cache.load_pointers().expect("load pointers");

    // Unsigned: a random payload with no valid wire format at all.
    let unsigned = b"not a signed configuration at all".to_vec();
    let result = cache.stage_verify_activate(&unsigned, &verifier);
    assert!(matches!(result, Err(CacheError::InvalidWireFormat)));
    assert_pointers_unchanged(&cache, &baseline);
}

#[test]
fn tampered_bundle_preserves_prior_pointers() {
    let tmp = TempDir::new();
    let cache = ConfigurationCache::open(tmp.path(), device_id(TEST_DEVICE)).expect("open cache");
    let signer = signer(TEST_KEY_ID, [7; 32]);
    let verifier = verifier(&signer);

    let (_, valid) = signed_bundle(&device_id(TEST_DEVICE), 1, "allow", &signer);
    cache
        .stage_verify_activate(&valid, &verifier)
        .expect("activate valid");
    let baseline = cache.load_pointers().expect("load pointers");

    let (_, mut tampered) = signed_bundle(&device_id(TEST_DEVICE), 2, "block", &signer);
    corrupt_byte(&mut tampered);
    let result = cache.stage_verify_activate(&tampered, &verifier);
    assert!(matches!(result, Err(CacheError::InvalidSignature | CacheError::InvalidContentHash)));
    assert_pointers_unchanged(&cache, &baseline);
}

#[test]
fn wrong_key_bundle_preserves_prior_pointers() {
    let tmp = TempDir::new();
    let cache = ConfigurationCache::open(tmp.path(), device_id(TEST_DEVICE)).expect("open cache");
    let trusted = signer(TEST_KEY_ID, [7; 32]);
    let untrusted = signer(WRONG_KEY_ID, [8; 32]);
    let verifier = verifier(&trusted);

    let (_, valid) = signed_bundle(&device_id(TEST_DEVICE), 1, "allow", &trusted);
    cache
        .stage_verify_activate(&valid, &verifier)
        .expect("activate valid");
    let baseline = cache.load_pointers().expect("load pointers");

    let (_, wrong_key) = signed_bundle(&device_id(TEST_DEVICE), 2, "block", &untrusted);
    let result = cache.stage_verify_activate(&wrong_key, &verifier);
    assert!(matches!(result, Err(CacheError::InvalidSignature | CacheError::WrongKeyId)));
    assert_pointers_unchanged(&cache, &baseline);
}

#[test]
fn unsupported_schema_preserves_prior_pointers() {
    let tmp = TempDir::new();
    let cache = ConfigurationCache::open(tmp.path(), device_id(TEST_DEVICE)).expect("open cache");
    let signer = signer(TEST_KEY_ID, [7; 32]);
    let verifier = verifier(&signer);

    let (_, valid) = signed_bundle(&device_id(TEST_DEVICE), 1, "allow", &signer);
    cache
        .stage_verify_activate(&valid, &verifier)
        .expect("activate valid");
    let baseline = cache.load_pointers().expect("load pointers");

    // Mutate a valid wire bundle to claim schema version 2.
    let (_, mut bytes) = signed_bundle(&device_id(TEST_DEVICE), 2, "payload", &signer);
    // Wire layout: [format version:1][api_version:2][schema_version:2]...
    bytes[3] = 0x00;
    bytes[4] = 0x02;

    let result = cache.stage_verify_activate(&bytes, &verifier);
    assert!(matches!(result, Err(CacheError::UnsupportedSchema)));
    assert_pointers_unchanged(&cache, &baseline);
}

#[test]
fn hash_mismatch_preserves_prior_pointers() {
    let tmp = TempDir::new();
    let cache = ConfigurationCache::open(tmp.path(), device_id(TEST_DEVICE)).expect("open cache");
    let signer = signer(TEST_KEY_ID, [7; 32]);
    let verifier = verifier(&signer);

    let (_, valid) = signed_bundle(&device_id(TEST_DEVICE), 1, "allow", &signer);
    cache
        .stage_verify_activate(&valid, &verifier)
        .expect("activate valid");
    let baseline = cache.load_pointers().expect("load pointers");

    // Build a valid bundle then manually corrupt the embedded content digest.
    let (_signed, mut bytes) = signed_bundle(&device_id(TEST_DEVICE), 2, "block", &signer);
    let digest_offset = bytes.len() - 32;
    bytes[digest_offset] ^= 0x01;

    let result = cache.stage_verify_activate(&bytes, &verifier);
    assert!(matches!(result, Err(CacheError::InvalidContentHash)));
    assert_pointers_unchanged(&cache, &baseline);
}

#[test]
fn wrong_audience_preserves_prior_pointers() {
    let tmp = TempDir::new();
    let cache = ConfigurationCache::open(tmp.path(), device_id(TEST_DEVICE)).expect("open cache");
    let signer = signer(TEST_KEY_ID, [7; 32]);
    let verifier = verifier(&signer);

    let (_, valid) = signed_bundle(
        &device_id(TEST_DEVICE), 1, "allow", &signer);
    cache
        .stage_verify_activate(&valid, &verifier)
        .expect("activate valid");
    let baseline = cache.load_pointers().expect("load pointers");

    let (_, other_device_bundle) = signed_bundle(
        &device_id(OTHER_DEVICE), 2, "block", &signer);
    let result = cache.stage_verify_activate(
        &other_device_bundle, &verifier);
    assert!(matches!(result, Err(CacheError::WrongAudience)));
    assert_pointers_unchanged(&cache, &baseline);
}

#[test]
fn truncated_bundle_preserves_prior_pointers() {
    let tmp = TempDir::new();
    let cache = ConfigurationCache::open(tmp.path(), device_id(TEST_DEVICE)).expect("open cache");
    let signer = signer(TEST_KEY_ID, [7; 32]);
    let verifier = verifier(&signer);

    let (_, valid) = signed_bundle(
        &device_id(TEST_DEVICE), 1, "allow", &signer);
    cache
        .stage_verify_activate(&valid, &verifier)
        .expect("activate valid");
    let baseline = cache.load_pointers().expect("load pointers");

    let (_, full) = signed_bundle(
        &device_id(TEST_DEVICE), 2, "block", &signer);
    let truncated = truncate(&full);
    let result = cache.stage_verify_activate(
        &truncated, &verifier);
    assert!(matches!(result, Err(CacheError::InvalidWireFormat | CacheError::InvalidSignature)));
    assert_pointers_unchanged(&cache, &baseline);
}

#[test]
fn equal_or_lower_version_preserves_prior_pointers() {
    let tmp = TempDir::new();
    let cache = ConfigurationCache::open(tmp.path(), device_id(TEST_DEVICE)).expect("open cache");
    let signer = signer(TEST_KEY_ID, [7; 32]);
    let verifier = verifier(&signer);

    let (_, first) = signed_bundle(
        &device_id(TEST_DEVICE), 2, "allow", &signer);
    cache
        .stage_verify_activate(&first, &verifier)
        .expect("activate first");
    let baseline = cache.load_pointers().expect("load pointers");

    let (_, equal) = signed_bundle(
        &device_id(TEST_DEVICE), 2, "block", &signer);
    let result = cache.stage_verify_activate(
        &equal, &verifier);
    assert!(
        matches!(result, Err(CacheError::StaleVersion { received: 2, active: 2 })),
        "equal version should be rejected"
    );

    let (_, lower) = signed_bundle(
        &device_id(TEST_DEVICE), 1, "block", &signer);
    let result = cache.stage_verify_activate(
        &lower, &verifier);
    assert!(
        matches!(result, Err(CacheError::StaleVersion { received: 1, active: 2 })),
        "lower version should be rejected"
    );

    assert_pointers_unchanged(&cache, &baseline);
}

#[test]
fn interrupted_download_preserves_prior_pointers() {
    let tmp = TempDir::new();
    let cache = ConfigurationCache::open(tmp.path(), device_id(TEST_DEVICE)).expect("open cache");
    let signer = signer(TEST_KEY_ID, [7; 32]);
    let verifier = verifier(&signer);

    let (_, valid) = signed_bundle(
        &device_id(TEST_DEVICE), 1, "allow", &signer);
    cache
        .stage_verify_activate(&valid, &verifier)
        .expect("activate valid");
    let baseline = cache.load_pointers().expect("load pointers");

    // An empty slice never parses.
    let result = cache.stage_verify_activate(&[], &verifier);
    assert!(matches!(result, Err(CacheError::InvalidWireFormat)));
    assert_pointers_unchanged(&cache, &baseline);
}

#[test]
fn concurrent_activations_select_greatest_version_without_cross_linking() {
    let tmp = TempDir::new();
    let cache = Arc::new(ConfigurationCache::open(tmp.path(), device_id(TEST_DEVICE)).expect("open cache"));
    let trusted_signer = signer(TEST_KEY_ID, [7; 32]);
    let trusted_verifier = verifier(&trusted_signer);

    // Pre-activate version 1 so there is an LKG to potentially corrupt.
    let (_, first) = signed_bundle(
        &device_id(TEST_DEVICE), 1, "allow", &trusted_signer);
    cache
        .stage_verify_activate(&first, &trusted_verifier)
        .expect("activate first");

    let versions = vec![3, 5, 4, 2, 6, 5];
    let barrier = Arc::new(Barrier::new(versions.len()));
    let mut handles = Vec::new();

    for &version in &versions {
        let cache = Arc::clone(&cache);
        let thread_signer = signer(TEST_KEY_ID, [7; 32]);
        let thread_verifier = verifier(&thread_signer);
        let barrier = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            let (_, bytes) = signed_bundle(
                &device_id(TEST_DEVICE), version, &format!("policy-{version}"), &thread_signer);
            barrier.wait();
            cache.stage_verify_activate(&bytes, &thread_verifier)
        }));
    }

    let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    let activated_count = results
        .iter()
        .filter(|r| matches!(r, Ok(ActivationOutcome::Activated { .. })))
        .count();
    let stale_count = results
        .iter()
        .filter(|r| matches!(r, Err(CacheError::StaleVersion { .. })))
        .count();

    assert!(
        activated_count >= 1,
        "at least one thread should activate the highest version"
    );
    assert_eq!(
        activated_count + stale_count,
        versions.len(),
        "every result must be either activated or stale"
    );

    let pointers = cache.load_pointers().expect("load pointers");
    assert_eq!(pointers.current_version, Some(6), "greatest version must win");
    assert!(
        pointers.lkg_version.is_some(),
        "LKG must be set after at least one activation"
    );
    assert_ne!(
        pointers.current_digest, pointers.lkg_digest,
        "current and LKG must not cross-link to the same bundle"
    );

    let current = cache.current_bundle().expect("current").expect("present");
    assert_eq!(current.envelope().payload(), "policy-6");
}

#[test]
fn restart_validates_current_and_lkg_independently() {
    let tmp = TempDir::new();
    let signer = signer(TEST_KEY_ID, [7; 32]);
    let verifier = verifier(&signer);

    {
        let cache = ConfigurationCache::open(tmp.path(), device_id(TEST_DEVICE)).expect("open cache");
        let (_, first) = signed_bundle(
            &device_id(TEST_DEVICE), 1, "allow", &signer);
        cache
            .stage_verify_activate(&first, &verifier)
            .expect("activate first");
        let (_, second) = signed_bundle(
            &device_id(TEST_DEVICE), 2, "allow-pdf", &signer);
        cache
            .stage_verify_activate(&second, &verifier)
            .expect("activate second");
    }

    // Reopen the cache as if after a restart.
    let cache = ConfigurationCache::open(tmp.path(), device_id(TEST_DEVICE)).expect("reopen cache");
    let pointers = cache.load_pointers().expect("load pointers");
    assert_eq!(pointers.current_version, Some(2));
    assert_eq!(pointers.lkg_version, Some(1));

    let current = cache.current_bundle().expect("current").expect("present");
    assert_eq!(current.envelope().payload(), "allow-pdf");

    let lkg = cache.lkg_bundle().expect("lkg").expect("present");
    assert_eq!(lkg.envelope().payload(), "allow");
}

#[test]
fn restart_ignores_unreferenced_staging() {
    let tmp = TempDir::new();
    let signer = signer(TEST_KEY_ID, [7; 32]);
    let verifier = verifier(&signer);

    {
        let cache = ConfigurationCache::open(tmp.path(), device_id(TEST_DEVICE)).expect("open cache");
        let (_, first) = signed_bundle(
            &device_id(TEST_DEVICE), 1, "allow", &signer);
        cache
            .stage_verify_activate(&first, &verifier)
            .expect("activate first");
        let (_, second) = signed_bundle(
            &device_id(TEST_DEVICE), 2, "allow-pdf", &signer);
        cache
            .stage_verify_activate(&second, &verifier)
            .expect("activate second");
    }

    // Drop an extra staged file that was never selected.
    let orphan = [0u8; 32];
    fs::write(tmp.path().join("staging").join(hex_encode(&orphan)), b"orphan").expect("write orphan");

    let cache = ConfigurationCache::open(tmp.path(), device_id(TEST_DEVICE)).expect("reopen cache");
    let _ = cache.clean_staging(&cache.load_pointers().expect("load pointers"));

    let staging_files: Vec<_> = fs::read_dir(tmp.path().join("staging"))
        .unwrap()
        .filter_map(|e| e.ok())
        .collect();
    let orphan_present = staging_files
        .iter()
        .any(|e| e.file_name().to_string_lossy() == hex_encode(&orphan));
    assert!(
        !orphan_present,
        "unreferenced staging should be removed after restart cleanup"
    );
}

#[test]
fn agent_http_client_refuses_poll_without_device_mtls() {
    let client = AgentHttpClient::bootstrap("https://server.example", "-----BEGIN CERTIFICATE-----\nMIIB")
        .expect("valid bootstrap");
    assert!(!client.uses_device_mtls());

    struct FakeTransport(Vec<u8>);
    impl ConfigurationTransport for FakeTransport {
        fn fetch_configuration(&mut self) -> Result<Vec<u8>, dlp_agent_core::ClientError> {
            Ok(self.0.clone())
        }
    }

    let mut transport = FakeTransport(vec![1, 2, 3]);
    let result = client.poll_configuration(&mut transport);
    assert!(
        matches!(result, Err(dlp_agent_core::ClientError::MissingDeviceCredential)),
        "poll without device mTLS must fail"
    );
}

#[test]
fn health_snapshot_reports_active_bundle_version() {
    use dlp_agent_core::HealthSnapshot;

    let tmp = TempDir::new();
    let cache = ConfigurationCache::open(tmp.path(), device_id(TEST_DEVICE)).expect("open cache");
    let signer = signer(TEST_KEY_ID, [7; 32]);
    let verifier = verifier(&signer);

    let snapshot = HealthSnapshot::from_cache(
        "0.1.0",
        "running",
        "not_mounted",
        &cache,
        None,
        None,
    );
    assert_eq!(snapshot.config_state, "unconfigured");
    assert!(snapshot.active_bundle_version.is_none());

    let (_, valid) = signed_bundle(
        &device_id(TEST_DEVICE), 3, "allow", &signer);
    cache
        .stage_verify_activate(&valid, &verifier)
        .expect("activate");

    let snapshot = HealthSnapshot::from_cache(
        "0.1.0",
        "running",
        "mounted",
        &cache,
        Some(1_700_000_000),
        Some(RedactedDiagnostic::ConfigurationRejected),
    );
    assert_eq!(snapshot.config_state, "active");
    assert_eq!(snapshot.active_bundle_version, Some("3".to_owned()));
    assert_eq!(snapshot.last_successful_contact, Some(1_700_000_000));
    assert_eq!(snapshot.diagnostic, Some(RedactedDiagnostic::ConfigurationRejected));
}

fn hex_encode(bytes: &[u8; 32]) -> String {
    let mut output = String::with_capacity(64);
    for byte in bytes {
        output.push_str(&format!("{byte:02x}"));
    }
    output
}

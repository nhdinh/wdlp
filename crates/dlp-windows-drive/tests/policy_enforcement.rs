use dlp_domain::{
    DecisionReason, EnforcementAction, EnforcementEvent, Operation, PolicyInput, StoreId, UserSid,
};
use dlp_policy::{CompiledPolicyV2, DetectorCeilings, PolicyDocumentV2, PolicyRuleV2};
use dlp_storage::{CapturedStoreIdentity, LocalEncryptedStore, StoreKey, VirtualPath};
use dlp_windows_drive::{DlpFileSystemContext, EnforcementEventSink};
use std::sync::{Arc, Mutex};
use winfsp::FspError;

#[derive(Default)]
struct RecordingSink(Mutex<Vec<EnforcementEvent>>);

impl EnforcementEventSink for RecordingSink {
    fn record(&self, event: EnforcementEvent) {
        self.0.lock().expect("event sink lock").push(event);
    }
}

fn compiled(rules: Vec<PolicyRuleV2>) -> Arc<CompiledPolicyV2> {
    Arc::new(
        PolicyDocumentV2::new("policy-7", EnforcementAction::Allow)
            .with_rules(rules)
            .compile(DetectorCeilings::default())
            .expect("compile policy"),
    )
}

fn store_with_file(
    root: &std::path::Path,
    file_name: &str,
    plaintext: &[u8],
) -> (CapturedStoreIdentity, LocalEncryptedStore, VirtualPath) {
    let identity = CapturedStoreIdentity::new(
        UserSid::parse("S-1-5-21-2000").expect("SID"),
        StoreId::parse("policy-store").expect("store ID"),
    );
    let mut store =
        LocalEncryptedStore::open(root, identity.clone(), StoreKey::from_bytes([9; 32]))
            .expect("encrypted store");
    let path = VirtualPath::parse(file_name).expect("virtual path");
    let handle = store
        .create_or_open(&path, true, true)
        .expect("create file");
    store
        .write_handle(handle, 0, plaintext)
        .expect("stage file");
    store.flush_handle(handle).expect("publish file");
    store.close_handle(handle).expect("close file");
    (identity, store, path)
}

#[test]
fn read_export_tracer() {
    let root = tempfile::tempdir().expect("temporary store");
    let plaintext = b"authenticated plaintext";
    let (identity, store, path) = store_with_file(root.path(), "Report.DOCX", plaintext);
    let policy = compiled(vec![PolicyRuleV2::extension(
        "block-docx",
        "docx",
        10,
        EnforcementAction::Block,
    )]);
    let sink = Arc::new(RecordingSink::default());
    let context = DlpFileSystemContext::with_policy(identity, store, policy, sink.clone())
        .expect("policy-enabled context");

    let mut denied_buffer = vec![0_u8; plaintext.len()];
    let error = context
        .read_export(&path, &mut denied_buffer, 0)
        .expect_err("matching export must be denied");
    assert!(matches!(
        error,
        FspError::NTSTATUS(dlp_windows_drive::status::STATUS_ACCESS_DENIED)
    ));
    assert_eq!(denied_buffer, vec![0_u8; plaintext.len()]);

    let events = sink.0.lock().expect("events");
    assert_eq!(events.len(), 1);
    let event = &events[0];
    assert_eq!(event.policy_version, "policy-7");
    assert_eq!(event.rule_id.as_deref(), Some("block-docx"));
    assert_eq!(event.action, EnforcementAction::Block);
    assert_eq!(event.operation, Operation::Export);
    assert_eq!(event.reason, DecisionReason::MatchedRule);
    assert_eq!(event.canonical_bytes(), event.canonical_bytes());
    drop(events);

    let allow_root = tempfile::tempdir().expect("allow store");
    let (identity, store, path) = store_with_file(allow_root.path(), "notes.txt", plaintext);
    let sink = Arc::new(RecordingSink::default());
    let context = DlpFileSystemContext::with_policy(
        identity,
        store,
        compiled(vec![PolicyRuleV2::extension(
            "block-docx",
            "docx",
            10,
            EnforcementAction::Block,
        )]),
        sink.clone(),
    )
    .expect("allow-default context");
    let mut allowed_buffer = vec![0_u8; plaintext.len()];
    assert_eq!(
        context
            .read_export(&path, &mut allowed_buffer, 0)
            .expect("explicit allow default"),
        plaintext.len() as u32
    );
    assert_eq!(allowed_buffer, plaintext);
    assert_eq!(
        sink.0.lock().expect("allow event")[0].reason,
        DecisionReason::DefaultAction
    );

    let owner = UserSid::parse("S-1-5-21-2000").expect("SID");
    let input = PolicyInput::new("Report.DOCX", "docx", "Report.DOCX", owner, 42)
        .expect("policy input")
        .with_operation(Operation::Export);
    let first = compiled(vec![
        PolicyRuleV2::extension("z-warn", "docx", 9, EnforcementAction::Warn),
        PolicyRuleV2::extension("b-block", "docx", 9, EnforcementAction::Block),
        PolicyRuleV2::extension("a-block", "docx", 9, EnforcementAction::Block),
    ]);
    let second = compiled(vec![
        PolicyRuleV2::extension("a-block", "docx", 9, EnforcementAction::Block),
        PolicyRuleV2::extension("b-block", "docx", 9, EnforcementAction::Block),
        PolicyRuleV2::extension("z-warn", "docx", 9, EnforcementAction::Warn),
    ]);
    let first_decision = first.evaluate(&input);
    let second_decision = second.evaluate(&input);
    assert_eq!(first_decision, second_decision);
    assert_eq!(first_decision.rule_id.as_deref(), Some("a-block"));
    assert_eq!(first_decision.action, EnforcementAction::Block);
    assert_eq!(first_decision.reason, DecisionReason::EqualPriorityConflict);
    assert!(
        first_decision
            .observations
            .windows(2)
            .all(|pair| pair[0] < pair[1])
    );
}

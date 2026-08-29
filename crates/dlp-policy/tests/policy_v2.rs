use dlp_domain::{
    DecisionObservation, DecisionReason, EnforcementAction, InspectionFailure, Operation,
    PolicyInput, UserSid,
};
use dlp_policy::{
    ContentDetectorV2, DetectorCeilings, PolicyCompileErrorKind, PolicyConditionV2,
    PolicyDocumentV2, PolicyRuleV2, StructuredIdentifierKind,
};
use std::sync::Arc;

fn owner() -> UserSid {
    UserSid::parse("S-1-5-21-2000").expect("valid owner SID")
}

fn input(file_name: &str, extension: &str, path: &str, size_bytes: u64) -> PolicyInput {
    PolicyInput::new(file_name, extension, path, owner(), size_bytes)
        .expect("valid policy input")
        .with_operation(Operation::Export)
}

fn compile(
    rules: Vec<PolicyRuleV2>,
    default_action: EnforcementAction,
) -> dlp_policy::CompiledPolicyV2 {
    PolicyDocumentV2::new("policy-v2-test", default_action)
        .with_rules(rules)
        .compile(DetectorCeilings::default())
        .expect("policy compiles")
}

fn rule(
    rule_id: &str,
    priority: u32,
    action: EnforcementAction,
    conditions: Vec<PolicyConditionV2>,
) -> PolicyRuleV2 {
    PolicyRuleV2::new(rule_id, priority, action).with_conditions(conditions)
}

#[test]
fn authoring_validation_rejects_ambiguous_or_unsupported_documents() {
    let missing_default = br#"{
        "schema_version": 2,
        "policy_version": "missing-default",
        "rules": []
    }"#;
    assert_eq!(
        PolicyDocumentV2::from_json_bytes(missing_default)
            .expect_err("missing default must fail")
            .kind(),
        PolicyCompileErrorKind::MissingDefaultAction
    );

    let null_default = br#"{
        "schema_version": 2,
        "policy_version": "null-default",
        "default_action": null,
        "rules": []
    }"#;
    assert_eq!(
        PolicyDocumentV2::from_json_bytes(null_default)
            .expect_err("null default must fail")
            .kind(),
        PolicyCompileErrorKind::MissingDefaultAction
    );

    let unknown_field = br#"{
        "schema_version": 2,
        "policy_version": "unknown-field",
        "default_action": "allow",
        "rules": [],
        "surprise": true
    }"#;
    assert_eq!(
        PolicyDocumentV2::from_json_bytes(unknown_field)
            .expect_err("unknown fields must fail")
            .kind(),
        PolicyCompileErrorKind::UnknownField
    );

    let invalid_utf8 = [0xff, 0xfe, 0xfd];
    assert_eq!(
        PolicyDocumentV2::from_json_bytes(&invalid_utf8)
            .expect_err("serialized policy must be UTF-8")
            .kind(),
        PolicyCompileErrorKind::InvalidEncoding
    );

    let empty_any_of = rule(
        "empty-any-of",
        1,
        EnforcementAction::Block,
        vec![PolicyConditionV2::extension_any_of(Vec::<String>::new())],
    );
    assert_eq!(
        PolicyDocumentV2::new("empty-any-of", EnforcementAction::Allow)
            .with_rules(vec![empty_any_of])
            .compile(DetectorCeilings::default())
            .expect_err("empty any_of must fail")
            .kind(),
        PolicyCompileErrorKind::EmptyAnyOf
    );

    let duplicate = vec![
        PolicyRuleV2::extension("same-id", "txt", 1, EnforcementAction::Allow),
        PolicyRuleV2::extension("same-id", "pdf", 2, EnforcementAction::Block),
    ];
    assert_eq!(
        PolicyDocumentV2::new("duplicate", EnforcementAction::Allow)
            .with_rules(duplicate)
            .compile(DetectorCeilings::default())
            .expect_err("duplicate stable IDs must fail")
            .kind(),
        PolicyCompileErrorKind::DuplicateRuleId
    );

    assert_eq!(
        PolicyDocumentV2::new("unsupported", EnforcementAction::RequireJustification)
            .compile(DetectorCeilings::default())
            .expect_err("justification default must fail")
            .kind(),
        PolicyCompileErrorKind::UnsupportedAction
    );
}

#[test]
fn explicit_empty_default_and_single_rule_use_the_normal_evaluation_path() {
    let empty = compile(Vec::new(), EnforcementAction::AllowAndAudit);
    let empty_decision = empty.evaluate(&input("notes.txt", "txt", "/notes.txt", 0));
    assert_eq!(empty_decision.action, EnforcementAction::AllowAndAudit);
    assert_eq!(empty_decision.reason, DecisionReason::EmptyPolicy);
    assert!(empty_decision.rule_id.is_none());

    let single = compile(
        vec![PolicyRuleV2::extension(
            "block-txt",
            ".TXT",
            7,
            EnforcementAction::Block,
        )],
        EnforcementAction::Allow,
    );
    let decision = single.evaluate(&input("notes.txt", " txt ", "/notes.txt", 1));
    assert_eq!(decision.action, EnforcementAction::Block);
    assert_eq!(decision.reason, DecisionReason::MatchedRule);
    assert_eq!(decision.rule_id.as_deref(), Some("block-txt"));
}

#[test]
fn metadata_conditions_are_flat_and_with_field_specific_unicode_normalization() {
    let metadata_rule = rule(
        "metadata",
        10,
        EnforcementAction::Block,
        vec![
            PolicyConditionV2::file_name_any_of(["Résumé.TXT"]),
            PolicyConditionV2::extension_any_of([".txt"]),
            PolicyConditionV2::mime_type_any_of(["text/plain"]),
            PolicyConditionV2::path_any_of(["/docs/résumé.txt"]),
            PolicyConditionV2::owner_any_of(["S-1-5-21-2000"]),
            PolicyConditionV2::size_at_least(3),
            PolicyConditionV2::size_at_most(5),
        ],
    );
    let policy = compile(vec![metadata_rule], EnforcementAction::Allow);
    let matching =
        input("Résumé.TXT", ".TXT", "\\DOCS\\Résumé.TXT", 4).with_mime_type("Text/Plain");
    assert_eq!(policy.evaluate(&matching).action, EnforcementAction::Block);

    let different_code_points =
        input("Resume.TXT", ".TXT", "\\DOCS\\Resume.TXT", 4).with_mime_type("Text/Plain");
    assert_eq!(
        policy.evaluate(&different_code_points).reason,
        DecisionReason::DefaultAction
    );

    let missing_one_and_term = input("Résumé.TXT", ".TXT", "\\DOCS\\Résumé.TXT", 4)
        .with_mime_type("application/octet-stream");
    assert_eq!(
        policy.evaluate(&missing_one_and_term).action,
        EnforcementAction::Allow
    );
}

#[test]
fn inclusive_u64_size_thresholds_distinguish_n_minus_one_n_and_n_plus_one() {
    let policy = compile(
        vec![rule(
            "bounded-size",
            1,
            EnforcementAction::Block,
            vec![
                PolicyConditionV2::size_at_least(u64::MAX - 1),
                PolicyConditionV2::size_at_most(u64::MAX),
            ],
        )],
        EnforcementAction::Allow,
    );

    assert_eq!(
        policy
            .evaluate(&input("n-1.bin", "bin", "/n-1.bin", u64::MAX - 2))
            .action,
        EnforcementAction::Allow
    );
    assert_eq!(
        policy
            .evaluate(&input("n.bin", "bin", "/n.bin", u64::MAX - 1))
            .action,
        EnforcementAction::Block
    );
    assert_eq!(
        policy
            .evaluate(&input("n+1.bin", "bin", "/n+1.bin", u64::MAX))
            .action,
        EnforcementAction::Block
    );
}

#[test]
fn operations_actions_and_unavailable_destination_have_stable_evidence() {
    let operations = [
        Operation::Read,
        Operation::Write,
        Operation::Import,
        Operation::Export,
        Operation::Copy,
        Operation::Delete,
    ];
    for operation in operations {
        let policy = compile(
            vec![rule(
                operation.as_str(),
                1,
                EnforcementAction::AllowAndAudit,
                vec![PolicyConditionV2::operation_any_of([operation])],
            )],
            EnforcementAction::Allow,
        );
        let decision =
            policy.evaluate(&input("file.bin", "bin", "/file.bin", 1).with_operation(operation));
        assert_eq!(decision.action, EnforcementAction::AllowAndAudit);
        assert_eq!(decision.reason, DecisionReason::MatchedRule);
    }

    for action in [
        EnforcementAction::Allow,
        EnforcementAction::AllowAndAudit,
        EnforcementAction::Warn,
        EnforcementAction::Block,
    ] {
        let decision = compile(
            vec![PolicyRuleV2::extension("runtime-action", "bin", 1, action)],
            EnforcementAction::Allow,
        )
        .evaluate(&input("file.bin", "bin", "/file.bin", 1));
        assert_eq!(decision.action, action);
    }

    let unavailable = rule(
        "destination-required",
        20,
        EnforcementAction::Block,
        vec![PolicyConditionV2::destination_any_of(["usb://approved"])],
    );
    let fallback_match = rule(
        "export-warning",
        10,
        EnforcementAction::Warn,
        vec![PolicyConditionV2::operation_any_of([Operation::Export])],
    );
    let decision = compile(vec![unavailable, fallback_match], EnforcementAction::Allow)
        .evaluate(&input("file.bin", "bin", "/file.bin", 1));
    assert_eq!(decision.action, EnforcementAction::Warn);
    assert_eq!(decision.rule_id.as_deref(), Some("export-warning"));
    assert!(
        decision
            .observations
            .contains(&DecisionObservation::InputUnavailable {
                rule_id: "destination-required".to_owned(),
                field: "destination".to_owned(),
            })
    );
    assert!(
        decision
            .observations
            .windows(2)
            .all(|pair| pair[0] < pair[1])
    );
}

#[test]
fn bounded_regex_dictionary_and_structured_detectors_respect_prefix_boundaries() {
    let regex_rule = rule("regex", 1, EnforcementAction::Block, Vec::new())
        .with_detectors(vec![ContentDetectorV2::regex("digits", r"\d{4}", Some(9))]);
    let regex_policy = compile(vec![regex_rule], EnforcementAction::Allow);
    let boundary = input("regex.txt", "txt", "/regex.txt", 12).with_content_prefix(b"card=1234ZZZ");
    assert_eq!(
        regex_policy.evaluate(&boundary).action,
        EnforcementAction::Block
    );

    let outside = input("regex.txt", "txt", "/regex.txt", 13).with_content_prefix(b"card=x1234ZZZ");
    assert_eq!(
        regex_policy.evaluate(&outside).action,
        EnforcementAction::Allow
    );

    let dictionary_rule =
        rule("dictionary", 1, EnforcementAction::Warn, Vec::new()).with_detectors(vec![
            ContentDetectorV2::dictionary("terms", ["secret", "secret"], Some(12)),
        ]);
    let dictionary_decision = compile(vec![dictionary_rule], EnforcementAction::Allow).evaluate(
        &input("dictionary.txt", "txt", "/dictionary.txt", 12).with_content_prefix(b"secretsecret"),
    );
    assert_eq!(dictionary_decision.action, EnforcementAction::Warn);
    assert!(
        dictionary_decision
            .observations
            .windows(2)
            .all(|pair| pair[0] < pair[1]),
        "touching and duplicate matches must be sorted and deduplicated"
    );

    let identifier_rule = rule("structured", 1, EnforcementAction::Block, Vec::new())
        .with_detectors(vec![ContentDetectorV2::structured_identifier(
            "payment-card",
            StructuredIdentifierKind::Luhn,
            Some(16),
        )]);
    let identifier_input =
        input("card.txt", "txt", "/card.txt", 16).with_content_prefix(b"4111111111111111");
    assert_eq!(
        compile(vec![identifier_rule], EnforcementAction::Allow)
            .evaluate(&identifier_input)
            .action,
        EnforcementAction::Block
    );
}

#[test]
fn authenticated_hash_and_required_inspection_fail_closed() {
    let expected_digest = [0x5a; 32];
    let hash_rule = rule("hash", 1, EnforcementAction::Block, Vec::new()).with_detectors(vec![
        ContentDetectorV2::authenticated_sha256("known-file", expected_digest),
    ]);
    let hash_policy = compile(vec![hash_rule], EnforcementAction::Allow);
    let hash_match =
        input("hash.bin", "bin", "/hash.bin", 99).with_authenticated_digest(expected_digest);
    assert_eq!(
        hash_policy.evaluate(&hash_match).action,
        EnforcementAction::Block
    );

    let missing = hash_policy.evaluate(&input("hash.bin", "bin", "/hash.bin", 99));
    assert_eq!(missing.action, EnforcementAction::Block);
    assert_eq!(missing.reason, DecisionReason::InspectionFailed);
    assert_eq!(missing.rule_id.as_deref(), Some("hash"));

    let regex_rule = rule("required-regex", 2, EnforcementAction::Warn, Vec::new())
        .with_detectors(vec![ContentDetectorV2::regex("utf8", "secret", None)]);
    for failure in [
        InspectionFailure::Corrupt,
        InspectionFailure::Decode,
        InspectionFailure::Resource,
    ] {
        let failed = input("failed.txt", "txt", "/failed.txt", 1).with_inspection_failure(failure);
        let decision =
            compile(vec![regex_rule.clone()], EnforcementAction::Allow).evaluate(&failed);
        assert_eq!(decision.action, EnforcementAction::Block);
        assert_eq!(decision.reason, DecisionReason::InspectionFailed);
        assert_eq!(decision.rule_id.as_deref(), Some("required-regex"));
    }
}

#[test]
fn detector_defaults_and_hard_ceilings_are_enforced_before_activation() {
    let ceilings = DetectorCeilings::default();
    assert_eq!(ceilings.content_prefix_default, 1024 * 1024);
    assert_eq!(ceilings.content_prefix_hard, 4 * 1024 * 1024);
    assert_eq!(ceilings.regex_source_default, 4 * 1024);
    assert_eq!(ceilings.regex_source_hard, 16 * 1024);
    assert_eq!(ceilings.regex_nesting_default, 32);
    assert_eq!(ceilings.regex_nesting_hard, 64);
    assert_eq!(ceilings.regex_automaton_default, 1024 * 1024);
    assert_eq!(ceilings.regex_automaton_hard, 4 * 1024 * 1024);
    assert_eq!(ceilings.dictionary_entries_default, 10_000);
    assert_eq!(ceilings.dictionary_entries_hard, 25_000);
    assert_eq!(ceilings.dictionary_source_default, 1024 * 1024);
    assert_eq!(ceilings.dictionary_source_hard, 4 * 1024 * 1024);
    assert_eq!(ceilings.dictionary_automaton_default, 8 * 1024 * 1024);
    assert_eq!(ceilings.dictionary_automaton_hard, 16 * 1024 * 1024);

    let too_long = "x".repeat(ceilings.regex_source_hard + 1);
    let oversized_regex = rule("large-regex", 1, EnforcementAction::Block, Vec::new())
        .with_detectors(vec![ContentDetectorV2::regex("large", too_long, None)]);
    assert_eq!(
        PolicyDocumentV2::new("large-regex", EnforcementAction::Allow)
            .with_rules(vec![oversized_regex])
            .compile(ceilings)
            .expect_err("regex source hard ceiling must fail")
            .kind(),
        PolicyCompileErrorKind::LimitExceeded
    );

    let too_many_terms = (0..=ceilings.dictionary_entries_hard)
        .map(|index| format!("term-{index}"))
        .collect::<Vec<_>>();
    let oversized_dictionary =
        rule("large-dictionary", 1, EnforcementAction::Block, Vec::new()).with_detectors(vec![
            ContentDetectorV2::dictionary("large", too_many_terms, None),
        ]);
    assert_eq!(
        PolicyDocumentV2::new("large-dictionary", EnforcementAction::Allow)
            .with_rules(vec![oversized_dictionary])
            .compile(ceilings)
            .expect_err("dictionary entry hard ceiling must fail")
            .kind(),
        PolicyCompileErrorKind::LimitExceeded
    );

    let invalid_ceilings = DetectorCeilings {
        content_prefix_default: ceilings.content_prefix_hard + 1,
        ..ceilings
    };
    assert_eq!(
        PolicyDocumentV2::new("invalid-ceilings", EnforcementAction::Allow)
            .compile(invalid_ceilings)
            .expect_err("defaults cannot exceed immutable hard ceilings")
            .kind(),
        PolicyCompileErrorKind::LimitExceeded
    );
}

#[test]
fn decisions_are_byte_stable_across_order_repetition_and_parallel_evaluation() {
    let rules = vec![
        PolicyRuleV2::extension("z-warn", "txt", 7, EnforcementAction::Warn),
        PolicyRuleV2::extension("b-block", "txt", 7, EnforcementAction::Block),
        PolicyRuleV2::extension("a-block", "txt", 7, EnforcementAction::Block),
    ];
    let forward = compile(rules.clone(), EnforcementAction::Allow);
    let reverse = compile(rules.into_iter().rev().collect(), EnforcementAction::Allow);
    let policy_input = input("stable.txt", "txt", "/stable.txt", 42);
    let expected = forward.evaluate(&policy_input);
    assert_eq!(
        expected.canonical_bytes(),
        reverse.evaluate(&policy_input).canonical_bytes()
    );
    assert_eq!(expected.rule_id.as_deref(), Some("a-block"));
    assert_eq!(expected.reason, DecisionReason::EqualPriorityConflict);
    assert!(
        expected
            .observations
            .windows(2)
            .all(|pair| pair[0] < pair[1])
    );

    let compiled = Arc::new(forward);
    let handles = (0..8)
        .map(|_| {
            let compiled = Arc::clone(&compiled);
            let policy_input = policy_input.clone();
            let expected = expected.canonical_bytes();
            std::thread::spawn(move || {
                for _ in 0..100 {
                    assert_eq!(compiled.evaluate(&policy_input).canonical_bytes(), expected);
                }
            })
        })
        .collect::<Vec<_>>();
    for handle in handles {
        handle.join().expect("parallel evaluator must not panic");
    }

    let json_a = br#"{
        "schema_version": 2,
        "policy_version": "json-order",
        "default_action": "allow",
        "rules": [{
            "rule_id": "json-rule",
            "priority": 1,
            "action": "block",
            "conditions": [{"field": "extension", "any_of": ["txt"]}]
        }]
    }"#;
    let json_b = br#"{
        "rules": [{
            "conditions": [{"any_of": ["txt"], "field": "extension"}],
            "action": "block",
            "priority": 1,
            "rule_id": "json-rule"
        }],
        "default_action": "allow",
        "policy_version": "json-order",
        "schema_version": 2
    }"#;
    let from_a = PolicyDocumentV2::from_json_bytes(json_a)
        .expect("first key order parses")
        .compile(DetectorCeilings::default())
        .expect("first key order compiles");
    let from_b = PolicyDocumentV2::from_json_bytes(json_b)
        .expect("second key order parses")
        .compile(DetectorCeilings::default())
        .expect("second key order compiles");
    assert_eq!(
        from_a.evaluate(&policy_input).canonical_bytes(),
        from_b.evaluate(&policy_input).canonical_bytes()
    );
}

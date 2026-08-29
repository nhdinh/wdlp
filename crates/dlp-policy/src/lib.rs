#![forbid(unsafe_code)]

//! Deterministic, portable policy compilation and evaluation.

use aho_corasick::{AhoCorasick, AhoCorasickBuilder};
use dlp_domain::{
    DecisionObservation, DecisionReason, EnforcementAction, InspectionFailure, Operation,
    PolicyDecision, PolicyInput,
};
use regex::{Regex, RegexBuilder};
use serde_json::{Map, Value};
use std::{collections::BTreeSet, fmt};

const CONTENT_PREFIX_HARD_MAX: usize = 4 * 1024 * 1024;
const REGEX_SOURCE_HARD_MAX: usize = 16 * 1024;
const REGEX_NESTING_HARD_MAX: u32 = 64;
const REGEX_AUTOMATON_HARD_MAX: usize = 4 * 1024 * 1024;
const DICTIONARY_ENTRIES_HARD_MAX: usize = 25_000;
const DICTIONARY_SOURCE_HARD_MAX: usize = 4 * 1024 * 1024;
const DICTIONARY_AUTOMATON_HARD_MAX: usize = 16 * 1024 * 1024;
const ANY_OF_VALUE_MAX: usize = 256;
const ANY_OF_SOURCE_MAX: usize = 1024 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyRule {
    rule_id: String,
    extension: String,
    priority: u32,
    action: EnforcementAction,
}

impl PolicyRule {
    pub fn new(
        rule_id: impl Into<String>,
        extension: impl Into<String>,
        priority: u32,
        action: EnforcementAction,
    ) -> Self {
        Self {
            rule_id: rule_id.into(),
            extension: extension.into(),
            priority,
            action,
        }
    }

    fn matches(&self, input: &PolicyInput) -> bool {
        self.extension == input.extension
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PolicyEvaluator {
    default_action: EnforcementAction,
}

impl PolicyEvaluator {
    pub const fn new(default_action: EnforcementAction) -> Self {
        Self { default_action }
    }

    pub fn evaluate(&self, input: &PolicyInput, rules: &[PolicyRule]) -> PolicyDecision {
        let mut candidates = rules
            .iter()
            .filter(|rule| rule.matches(input))
            .collect::<Vec<_>>();
        if candidates.is_empty() {
            return PolicyDecision {
                action: self.default_action,
                reason: if rules.is_empty() {
                    DecisionReason::EmptyPolicy
                } else {
                    DecisionReason::DefaultAction
                },
                rule_id: None,
                observations: Vec::new(),
            };
        }
        candidates.sort_unstable_by(|left, right| compare_rules(left, right));
        let selected = candidates[0];
        let conflict = candidates
            .iter()
            .skip(1)
            .any(|candidate| candidate.priority == selected.priority);
        PolicyDecision {
            action: selected.action,
            reason: if conflict {
                DecisionReason::EqualPriorityConflict
            } else {
                DecisionReason::MatchedRule
            },
            rule_id: Some(selected.rule_id.clone()),
            observations: sorted_observations(candidates.iter().map(|candidate| {
                DecisionObservation::RuleMatched {
                    rule_id: candidate.rule_id.clone(),
                }
            })),
        }
    }
}

fn compare_rules(left: &PolicyRule, right: &PolicyRule) -> std::cmp::Ordering {
    right
        .priority
        .cmp(&left.priority)
        .then_with(|| {
            right
                .action
                .restrictiveness()
                .cmp(&left.action.restrictiveness())
        })
        .then_with(|| left.rule_id.cmp(&right.rule_id))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DetectorCeilings {
    pub content_prefix_default: usize,
    pub content_prefix_hard: usize,
    pub regex_source_default: usize,
    pub regex_source_hard: usize,
    pub regex_nesting_default: u32,
    pub regex_nesting_hard: u32,
    pub regex_automaton_default: usize,
    pub regex_automaton_hard: usize,
    pub dictionary_entries_default: usize,
    pub dictionary_entries_hard: usize,
    pub dictionary_source_default: usize,
    pub dictionary_source_hard: usize,
    pub dictionary_automaton_default: usize,
    pub dictionary_automaton_hard: usize,
}

impl Default for DetectorCeilings {
    fn default() -> Self {
        Self {
            content_prefix_default: 1024 * 1024,
            content_prefix_hard: CONTENT_PREFIX_HARD_MAX,
            regex_source_default: 4 * 1024,
            regex_source_hard: REGEX_SOURCE_HARD_MAX,
            regex_nesting_default: 32,
            regex_nesting_hard: REGEX_NESTING_HARD_MAX,
            regex_automaton_default: 1024 * 1024,
            regex_automaton_hard: REGEX_AUTOMATON_HARD_MAX,
            dictionary_entries_default: 10_000,
            dictionary_entries_hard: DICTIONARY_ENTRIES_HARD_MAX,
            dictionary_source_default: 1024 * 1024,
            dictionary_source_hard: DICTIONARY_SOURCE_HARD_MAX,
            dictionary_automaton_default: 8 * 1024 * 1024,
            dictionary_automaton_hard: DICTIONARY_AUTOMATON_HARD_MAX,
        }
    }
}

impl DetectorCeilings {
    fn validate(self) -> Result<Self, PolicyCompileError> {
        let valid = self.content_prefix_default <= self.content_prefix_hard
            && self.content_prefix_hard <= CONTENT_PREFIX_HARD_MAX
            && self.regex_source_default <= self.regex_source_hard
            && self.regex_source_hard <= REGEX_SOURCE_HARD_MAX
            && self.regex_nesting_default <= self.regex_nesting_hard
            && self.regex_nesting_hard <= REGEX_NESTING_HARD_MAX
            && self.regex_automaton_default <= self.regex_automaton_hard
            && self.regex_automaton_hard <= REGEX_AUTOMATON_HARD_MAX
            && self.dictionary_entries_default <= self.dictionary_entries_hard
            && self.dictionary_entries_hard <= DICTIONARY_ENTRIES_HARD_MAX
            && self.dictionary_source_default <= self.dictionary_source_hard
            && self.dictionary_source_hard <= DICTIONARY_SOURCE_HARD_MAX
            && self.dictionary_automaton_default <= self.dictionary_automaton_hard
            && self.dictionary_automaton_hard <= DICTIONARY_AUTOMATON_HARD_MAX;
        if valid {
            Ok(self)
        } else {
            Err(PolicyCompileError::new(
                PolicyCompileErrorKind::LimitExceeded,
            ))
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PolicyConditionV2 {
    FileNameAnyOf(Vec<String>),
    ExtensionAnyOf(Vec<String>),
    MimeTypeAnyOf(Vec<String>),
    PathAnyOf(Vec<String>),
    OwnerAnyOf(Vec<String>),
    DestinationAnyOf(Vec<String>),
    ProcessAnyOf(Vec<String>),
    OperationAnyOf(Vec<Operation>),
    SizeAtLeast(u64),
    SizeAtMost(u64),
}

impl PolicyConditionV2 {
    pub fn file_name_any_of<I, S>(values: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self::FileNameAnyOf(strings(values))
    }

    pub fn extension_any_of<I, S>(values: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self::ExtensionAnyOf(strings(values))
    }

    pub fn mime_type_any_of<I, S>(values: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self::MimeTypeAnyOf(strings(values))
    }

    pub fn path_any_of<I, S>(values: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self::PathAnyOf(strings(values))
    }

    pub fn owner_any_of<I, S>(values: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self::OwnerAnyOf(strings(values))
    }

    pub fn destination_any_of<I, S>(values: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self::DestinationAnyOf(strings(values))
    }

    pub fn process_any_of<I, S>(values: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self::ProcessAnyOf(strings(values))
    }

    pub fn operation_any_of<I>(values: I) -> Self
    where
        I: IntoIterator<Item = Operation>,
    {
        Self::OperationAnyOf(values.into_iter().collect())
    }

    pub const fn size_at_least(value: u64) -> Self {
        Self::SizeAtLeast(value)
    }

    pub const fn size_at_most(value: u64) -> Self {
        Self::SizeAtMost(value)
    }
}

fn strings<I, S>(values: I) -> Vec<String>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    values.into_iter().map(Into::into).collect()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StructuredIdentifierKind {
    Luhn,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ContentDetectorV2 {
    Regex {
        detector_id: String,
        pattern: String,
        prefix_bytes: Option<usize>,
    },
    Dictionary {
        detector_id: String,
        terms: Vec<String>,
        prefix_bytes: Option<usize>,
    },
    AuthenticatedSha256 {
        detector_id: String,
        digest: [u8; 32],
    },
    StructuredIdentifier {
        detector_id: String,
        kind: StructuredIdentifierKind,
        prefix_bytes: Option<usize>,
    },
}

impl ContentDetectorV2 {
    pub fn regex(
        detector_id: impl Into<String>,
        pattern: impl Into<String>,
        prefix_bytes: Option<usize>,
    ) -> Self {
        Self::Regex {
            detector_id: detector_id.into(),
            pattern: pattern.into(),
            prefix_bytes,
        }
    }

    pub fn dictionary<I, S>(
        detector_id: impl Into<String>,
        terms: I,
        prefix_bytes: Option<usize>,
    ) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self::Dictionary {
            detector_id: detector_id.into(),
            terms: strings(terms),
            prefix_bytes,
        }
    }

    pub fn authenticated_sha256(detector_id: impl Into<String>, digest: [u8; 32]) -> Self {
        Self::AuthenticatedSha256 {
            detector_id: detector_id.into(),
            digest,
        }
    }

    pub fn structured_identifier(
        detector_id: impl Into<String>,
        kind: StructuredIdentifierKind,
        prefix_bytes: Option<usize>,
    ) -> Self {
        Self::StructuredIdentifier {
            detector_id: detector_id.into(),
            kind,
            prefix_bytes,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyRuleV2 {
    rule_id: String,
    priority: u32,
    action: EnforcementAction,
    conditions: Vec<PolicyConditionV2>,
    detectors: Vec<ContentDetectorV2>,
}

impl PolicyRuleV2 {
    pub fn new(rule_id: impl Into<String>, priority: u32, action: EnforcementAction) -> Self {
        Self {
            rule_id: rule_id.into(),
            priority,
            action,
            conditions: Vec::new(),
            detectors: Vec::new(),
        }
    }

    pub fn extension(
        rule_id: impl Into<String>,
        extension: impl Into<String>,
        priority: u32,
        action: EnforcementAction,
    ) -> Self {
        Self::new(rule_id, priority, action)
            .with_conditions(vec![PolicyConditionV2::extension_any_of([extension])])
    }

    pub fn with_conditions(mut self, conditions: Vec<PolicyConditionV2>) -> Self {
        self.conditions = conditions;
        self
    }

    pub fn with_detectors(mut self, detectors: Vec<ContentDetectorV2>) -> Self {
        self.detectors = detectors;
        self
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyDocumentV2 {
    policy_version: String,
    default_action: EnforcementAction,
    rules: Vec<PolicyRuleV2>,
}

impl PolicyDocumentV2 {
    pub fn new(policy_version: impl Into<String>, default_action: EnforcementAction) -> Self {
        Self {
            policy_version: policy_version.into(),
            default_action,
            rules: Vec::new(),
        }
    }

    pub fn from_json_bytes(bytes: &[u8]) -> Result<Self, PolicyCompileError> {
        let text = std::str::from_utf8(bytes)
            .map_err(|_| PolicyCompileError::new(PolicyCompileErrorKind::InvalidEncoding))?;
        let value = serde_json::from_str::<Value>(text)
            .map_err(|_| PolicyCompileError::new(PolicyCompileErrorKind::InvalidDocument))?;
        parse_document(value)
    }

    pub fn with_rules(mut self, rules: Vec<PolicyRuleV2>) -> Self {
        self.rules = rules;
        self
    }

    pub fn compile(
        self,
        ceilings: DetectorCeilings,
    ) -> Result<CompiledPolicyV2, PolicyCompileError> {
        let ceilings = ceilings.validate()?;
        if self.policy_version.is_empty() {
            return Err(PolicyCompileError::new(
                PolicyCompileErrorKind::MissingVersion,
            ));
        }
        if self.default_action == EnforcementAction::RequireJustification {
            return Err(PolicyCompileError::new(
                PolicyCompileErrorKind::UnsupportedAction,
            ));
        }
        let mut identifiers = BTreeSet::new();
        let mut rules = Vec::with_capacity(self.rules.len());
        let mut dictionary_automaton_bytes = 0_usize;
        for rule in self.rules {
            if rule.rule_id.is_empty() {
                return Err(PolicyCompileError::new(PolicyCompileErrorKind::InvalidRule));
            }
            if rule.action == EnforcementAction::RequireJustification {
                return Err(PolicyCompileError::new(
                    PolicyCompileErrorKind::UnsupportedAction,
                ));
            }
            if !identifiers.insert(rule.rule_id.clone()) {
                return Err(PolicyCompileError::new(
                    PolicyCompileErrorKind::DuplicateRuleId,
                ));
            }
            let rule = CompiledRuleV2::compile(rule, ceilings)?;
            dictionary_automaton_bytes = dictionary_automaton_bytes
                .checked_add(rule.dictionary_memory_usage())
                .ok_or_else(|| PolicyCompileError::new(PolicyCompileErrorKind::LimitExceeded))?;
            if dictionary_automaton_bytes > ceilings.dictionary_automaton_default {
                return Err(PolicyCompileError::new(
                    PolicyCompileErrorKind::LimitExceeded,
                ));
            }
            rules.push(rule);
        }
        rules.sort_unstable_by(|left, right| left.rule_id.cmp(&right.rule_id));
        Ok(CompiledPolicyV2 {
            policy_version: self.policy_version,
            default_action: self.default_action,
            rules,
            ceilings,
        })
    }
}

#[derive(Clone, Debug)]
pub struct CompiledPolicyV2 {
    policy_version: String,
    default_action: EnforcementAction,
    rules: Vec<CompiledRuleV2>,
    ceilings: DetectorCeilings,
}

impl CompiledPolicyV2 {
    pub fn policy_version(&self) -> &str {
        &self.policy_version
    }

    pub const fn ceilings(&self) -> &DetectorCeilings {
        &self.ceilings
    }

    pub fn evaluate(&self, input: &PolicyInput) -> PolicyDecision {
        let mut matches = Vec::new();
        let mut failures = Vec::new();
        let mut observations = Vec::new();
        for rule in &self.rules {
            match rule.evaluate(input) {
                RuleOutcome::Matched(mut current) => {
                    observations.append(&mut current);
                    matches.push(rule);
                }
                RuleOutcome::NotMatched(mut current) => observations.append(&mut current),
                RuleOutcome::InspectionFailed(mut current) => {
                    observations.append(&mut current);
                    failures.push(rule);
                }
            }
        }
        let observations = sorted_observations(observations);
        if !failures.is_empty() {
            failures.sort_unstable_by(|left, right| compare_compiled_rules(left, right));
            return PolicyDecision {
                action: EnforcementAction::Block,
                reason: DecisionReason::InspectionFailed,
                rule_id: Some(failures[0].rule_id.clone()),
                observations,
            };
        }
        if matches.is_empty() {
            return PolicyDecision {
                action: self.default_action,
                reason: if self.rules.is_empty() {
                    DecisionReason::EmptyPolicy
                } else {
                    DecisionReason::DefaultAction
                },
                rule_id: None,
                observations,
            };
        }
        matches.sort_unstable_by(|left, right| compare_compiled_rules(left, right));
        let selected = matches[0];
        let conflict = matches
            .iter()
            .skip(1)
            .any(|candidate| candidate.priority == selected.priority);
        PolicyDecision {
            action: selected.action,
            reason: if conflict {
                DecisionReason::EqualPriorityConflict
            } else {
                DecisionReason::MatchedRule
            },
            rule_id: Some(selected.rule_id.clone()),
            observations,
        }
    }
}

fn compare_compiled_rules(left: &CompiledRuleV2, right: &CompiledRuleV2) -> std::cmp::Ordering {
    right
        .priority
        .cmp(&left.priority)
        .then_with(|| {
            right
                .action
                .restrictiveness()
                .cmp(&left.action.restrictiveness())
        })
        .then_with(|| left.rule_id.cmp(&right.rule_id))
}

#[derive(Clone, Debug)]
struct CompiledRuleV2 {
    rule_id: String,
    priority: u32,
    action: EnforcementAction,
    conditions: Vec<CompiledConditionV2>,
    detectors: Vec<CompiledDetectorV2>,
}

impl CompiledRuleV2 {
    fn compile(rule: PolicyRuleV2, ceilings: DetectorCeilings) -> Result<Self, PolicyCompileError> {
        let mut conditions = Vec::with_capacity(rule.conditions.len());
        let mut minimum = None;
        let mut maximum = None;
        for condition in rule.conditions {
            let condition = CompiledConditionV2::compile(condition)?;
            match condition {
                CompiledConditionV2::SizeAtLeast(value) => minimum = Some(value),
                CompiledConditionV2::SizeAtMost(value) => maximum = Some(value),
                _ => {}
            }
            conditions.push(condition);
        }
        if minimum
            .zip(maximum)
            .is_some_and(|(minimum, maximum)| minimum > maximum)
        {
            return Err(PolicyCompileError::new(PolicyCompileErrorKind::InvalidRule));
        }
        let mut ids = BTreeSet::new();
        let mut detectors = Vec::with_capacity(rule.detectors.len());
        for detector in rule.detectors {
            let detector = CompiledDetectorV2::compile(detector, ceilings)?;
            if !ids.insert(detector.id().to_owned()) {
                return Err(PolicyCompileError::new(
                    PolicyCompileErrorKind::DuplicateDetectorId,
                ));
            }
            detectors.push(detector);
        }
        detectors.sort_unstable_by(|left, right| left.id().cmp(right.id()));
        Ok(Self {
            rule_id: rule.rule_id,
            priority: rule.priority,
            action: rule.action,
            conditions,
            detectors,
        })
    }

    fn evaluate(&self, input: &PolicyInput) -> RuleOutcome {
        let mut matches = true;
        let mut observations = Vec::new();
        for condition in &self.conditions {
            match condition.evaluate(input) {
                ConditionOutcome::Match => {}
                ConditionOutcome::NoMatch => matches = false,
                ConditionOutcome::Unavailable(field) => {
                    matches = false;
                    observations.push(DecisionObservation::InputUnavailable {
                        rule_id: self.rule_id.clone(),
                        field: field.to_owned(),
                    });
                }
            }
        }
        if !matches {
            return RuleOutcome::NotMatched(observations);
        }
        for detector in &self.detectors {
            let found = match detector.find_matches(input) {
                Ok(found) => found,
                Err(_) => return RuleOutcome::InspectionFailed(observations),
            };
            if found.is_empty() {
                matches = false;
            }
            observations.extend(found.into_iter().map(|(start, end)| {
                DecisionObservation::DetectorMatch {
                    rule_id: self.rule_id.clone(),
                    detector_id: detector.id().to_owned(),
                    start,
                    end,
                }
            }));
        }
        if matches {
            observations.push(DecisionObservation::RuleMatched {
                rule_id: self.rule_id.clone(),
            });
            RuleOutcome::Matched(observations)
        } else {
            RuleOutcome::NotMatched(observations)
        }
    }

    fn dictionary_memory_usage(&self) -> usize {
        self.detectors
            .iter()
            .map(CompiledDetectorV2::dictionary_memory_usage)
            .sum()
    }
}

enum RuleOutcome {
    Matched(Vec<DecisionObservation>),
    NotMatched(Vec<DecisionObservation>),
    InspectionFailed(Vec<DecisionObservation>),
}

#[derive(Clone, Debug)]
enum CompiledConditionV2 {
    FileNameAnyOf(Vec<String>),
    ExtensionAnyOf(Vec<String>),
    MimeTypeAnyOf(Vec<String>),
    PathAnyOf(Vec<String>),
    OwnerAnyOf(Vec<String>),
    DestinationAnyOf(Vec<String>),
    ProcessAnyOf(Vec<String>),
    OperationAnyOf(Vec<Operation>),
    SizeAtLeast(u64),
    SizeAtMost(u64),
}

impl CompiledConditionV2 {
    fn compile(condition: PolicyConditionV2) -> Result<Self, PolicyCompileError> {
        Ok(match condition {
            PolicyConditionV2::FileNameAnyOf(values) => {
                Self::FileNameAnyOf(canonical_values(values, normalize_identity)?)
            }
            PolicyConditionV2::ExtensionAnyOf(values) => {
                Self::ExtensionAnyOf(canonical_values(values, normalize_extension)?)
            }
            PolicyConditionV2::MimeTypeAnyOf(values) => {
                Self::MimeTypeAnyOf(canonical_values(values, normalize_mime_type)?)
            }
            PolicyConditionV2::PathAnyOf(values) => {
                Self::PathAnyOf(canonical_values(values, normalize_path)?)
            }
            PolicyConditionV2::OwnerAnyOf(values) => {
                Self::OwnerAnyOf(canonical_values(values, normalize_identity)?)
            }
            PolicyConditionV2::DestinationAnyOf(values) => {
                Self::DestinationAnyOf(canonical_values(values, normalize_destination)?)
            }
            PolicyConditionV2::ProcessAnyOf(values) => {
                Self::ProcessAnyOf(canonical_values(values, normalize_process)?)
            }
            PolicyConditionV2::OperationAnyOf(mut values) => {
                if values.is_empty() {
                    return Err(PolicyCompileError::new(PolicyCompileErrorKind::EmptyAnyOf));
                }
                values.sort_unstable();
                values.dedup();
                Self::OperationAnyOf(values)
            }
            PolicyConditionV2::SizeAtLeast(value) => Self::SizeAtLeast(value),
            PolicyConditionV2::SizeAtMost(value) => Self::SizeAtMost(value),
        })
    }

    fn evaluate(&self, input: &PolicyInput) -> ConditionOutcome {
        match self {
            Self::FileNameAnyOf(values) => contains(values, &input.file_name),
            Self::ExtensionAnyOf(values) => {
                contains(values, &normalize_extension(&input.extension))
            }
            Self::MimeTypeAnyOf(values) => optional_contains(
                values,
                input.mime_type().map(normalize_mime_type),
                "mime_type",
            ),
            Self::PathAnyOf(values) => contains(values, &normalize_path(&input.path)),
            Self::OwnerAnyOf(values) => optional_contains(
                values,
                input
                    .owner_context()
                    .map(|owner| owner.to_wire().to_owned()),
                "owner",
            ),
            Self::DestinationAnyOf(values) => optional_contains(
                values,
                input.destination().map(normalize_destination),
                "destination",
            ),
            Self::ProcessAnyOf(values) => {
                optional_contains(values, input.process().map(normalize_process), "process")
            }
            Self::OperationAnyOf(values) => {
                if values.binary_search(&input.operation).is_ok() {
                    ConditionOutcome::Match
                } else {
                    ConditionOutcome::NoMatch
                }
            }
            Self::SizeAtLeast(value) => match input.size_bytes >= *value {
                true => ConditionOutcome::Match,
                false => ConditionOutcome::NoMatch,
            },
            Self::SizeAtMost(value) => match input.size_bytes <= *value {
                true => ConditionOutcome::Match,
                false => ConditionOutcome::NoMatch,
            },
        }
    }
}

enum ConditionOutcome {
    Match,
    NoMatch,
    Unavailable(&'static str),
}

fn contains(values: &[String], value: &str) -> ConditionOutcome {
    if values
        .binary_search_by(|candidate| candidate.as_str().cmp(value))
        .is_ok()
    {
        ConditionOutcome::Match
    } else {
        ConditionOutcome::NoMatch
    }
}

fn optional_contains(
    values: &[String],
    value: Option<String>,
    field: &'static str,
) -> ConditionOutcome {
    value.map_or(ConditionOutcome::Unavailable(field), |value| {
        contains(values, &value)
    })
}

fn canonical_values(
    values: Vec<String>,
    normalize: fn(&str) -> String,
) -> Result<Vec<String>, PolicyCompileError> {
    if values.is_empty() {
        return Err(PolicyCompileError::new(PolicyCompileErrorKind::EmptyAnyOf));
    }
    let source_bytes = values
        .iter()
        .try_fold(0_usize, |total, value| total.checked_add(value.len()))
        .ok_or_else(|| PolicyCompileError::new(PolicyCompileErrorKind::LimitExceeded))?;
    if values.len() > ANY_OF_VALUE_MAX || source_bytes > ANY_OF_SOURCE_MAX {
        return Err(PolicyCompileError::new(
            PolicyCompileErrorKind::LimitExceeded,
        ));
    }
    let mut values = values
        .into_iter()
        .map(|value| normalize(&value))
        .collect::<Vec<_>>();
    if values.iter().any(String::is_empty) {
        return Err(PolicyCompileError::new(PolicyCompileErrorKind::InvalidRule));
    }
    values.sort_unstable();
    values.dedup();
    Ok(values)
}

#[derive(Clone, Debug)]
enum CompiledDetectorV2 {
    Regex {
        detector_id: String,
        regex: Regex,
        prefix_bytes: usize,
    },
    Dictionary {
        detector_id: String,
        matcher: AhoCorasick,
        prefix_bytes: usize,
    },
    AuthenticatedSha256 {
        detector_id: String,
        digest: [u8; 32],
    },
    StructuredIdentifier {
        detector_id: String,
        kind: StructuredIdentifierKind,
        prefix_bytes: usize,
    },
}

impl CompiledDetectorV2 {
    fn compile(
        detector: ContentDetectorV2,
        ceilings: DetectorCeilings,
    ) -> Result<Self, PolicyCompileError> {
        match detector {
            ContentDetectorV2::Regex {
                detector_id,
                pattern,
                prefix_bytes,
            } => {
                validate_detector_id(&detector_id)?;
                if pattern.len() > ceilings.regex_source_default {
                    return Err(PolicyCompileError::new(
                        PolicyCompileErrorKind::LimitExceeded,
                    ));
                }
                let regex = RegexBuilder::new(&pattern)
                    .nest_limit(ceilings.regex_nesting_default)
                    .size_limit(ceilings.regex_automaton_default)
                    .dfa_size_limit(ceilings.regex_automaton_default)
                    .build()
                    .map_err(|_| {
                        PolicyCompileError::new(PolicyCompileErrorKind::DetectorCompileFailed)
                    })?;
                Ok(Self::Regex {
                    detector_id,
                    regex,
                    prefix_bytes: validate_prefix(prefix_bytes, ceilings)?,
                })
            }
            ContentDetectorV2::Dictionary {
                detector_id,
                mut terms,
                prefix_bytes,
            } => {
                validate_detector_id(&detector_id)?;
                terms.sort_unstable();
                terms.dedup();
                if terms.is_empty() {
                    return Err(PolicyCompileError::new(PolicyCompileErrorKind::EmptyAnyOf));
                }
                let source_bytes = terms
                    .iter()
                    .try_fold(0_usize, |total, term| total.checked_add(term.len()))
                    .ok_or_else(|| {
                        PolicyCompileError::new(PolicyCompileErrorKind::LimitExceeded)
                    })?;
                if terms.len() > ceilings.dictionary_entries_default
                    || source_bytes > ceilings.dictionary_source_default
                {
                    return Err(PolicyCompileError::new(
                        PolicyCompileErrorKind::LimitExceeded,
                    ));
                }
                let matcher = AhoCorasickBuilder::new().build(&terms).map_err(|_| {
                    PolicyCompileError::new(PolicyCompileErrorKind::DetectorCompileFailed)
                })?;
                if matcher.memory_usage() > ceilings.dictionary_automaton_default {
                    return Err(PolicyCompileError::new(
                        PolicyCompileErrorKind::LimitExceeded,
                    ));
                }
                Ok(Self::Dictionary {
                    detector_id,
                    matcher,
                    prefix_bytes: validate_prefix(prefix_bytes, ceilings)?,
                })
            }
            ContentDetectorV2::AuthenticatedSha256 {
                detector_id,
                digest,
            } => {
                validate_detector_id(&detector_id)?;
                Ok(Self::AuthenticatedSha256 {
                    detector_id,
                    digest,
                })
            }
            ContentDetectorV2::StructuredIdentifier {
                detector_id,
                kind,
                prefix_bytes,
            } => {
                validate_detector_id(&detector_id)?;
                Ok(Self::StructuredIdentifier {
                    detector_id,
                    kind,
                    prefix_bytes: validate_prefix(prefix_bytes, ceilings)?,
                })
            }
        }
    }

    fn id(&self) -> &str {
        match self {
            Self::Regex { detector_id, .. }
            | Self::Dictionary { detector_id, .. }
            | Self::AuthenticatedSha256 { detector_id, .. }
            | Self::StructuredIdentifier { detector_id, .. } => detector_id,
        }
    }

    fn find_matches(&self, input: &PolicyInput) -> Result<Vec<(usize, usize)>, InspectionFailure> {
        if let Some(failure) = input.inspection_failure() {
            return Err(failure);
        }
        match self {
            Self::Regex {
                regex,
                prefix_bytes,
                ..
            } => {
                let text = inspected_text(input, *prefix_bytes)?;
                Ok(regex
                    .find_iter(text)
                    .map(|matched| (matched.start(), matched.end()))
                    .collect())
            }
            Self::Dictionary {
                matcher,
                prefix_bytes,
                ..
            } => {
                let text = inspected_text(input, *prefix_bytes)?;
                Ok(matcher
                    .find_overlapping_iter(text)
                    .map(|matched| (matched.start(), matched.end()))
                    .collect())
            }
            Self::AuthenticatedSha256 { digest, .. } => input
                .authenticated_digest()
                .map(|actual| {
                    if actual == digest {
                        vec![(0, 32)]
                    } else {
                        Vec::new()
                    }
                })
                .ok_or(InspectionFailure::MissingDigest),
            Self::StructuredIdentifier {
                kind, prefix_bytes, ..
            } => {
                let text = inspected_text(input, *prefix_bytes)?;
                match kind {
                    StructuredIdentifierKind::Luhn => Ok(luhn_matches(text)),
                }
            }
        }
    }

    fn dictionary_memory_usage(&self) -> usize {
        match self {
            Self::Dictionary { matcher, .. } => matcher.memory_usage(),
            _ => 0,
        }
    }
}

fn validate_detector_id(detector_id: &str) -> Result<(), PolicyCompileError> {
    if detector_id.is_empty() {
        Err(PolicyCompileError::new(PolicyCompileErrorKind::InvalidRule))
    } else {
        Ok(())
    }
}

fn validate_prefix(
    prefix_bytes: Option<usize>,
    ceilings: DetectorCeilings,
) -> Result<usize, PolicyCompileError> {
    let prefix_bytes = prefix_bytes.unwrap_or(ceilings.content_prefix_default);
    if prefix_bytes > ceilings.content_prefix_hard {
        Err(PolicyCompileError::new(
            PolicyCompileErrorKind::LimitExceeded,
        ))
    } else {
        Ok(prefix_bytes)
    }
}

fn inspected_text(input: &PolicyInput, prefix_bytes: usize) -> Result<&str, InspectionFailure> {
    let content = input.content_prefix().ok_or(InspectionFailure::Resource)?;
    let prefix = &content[..content.len().min(prefix_bytes)];
    match std::str::from_utf8(prefix) {
        Ok(text) => Ok(text),
        Err(error) if error.error_len().is_none() && prefix.len() < content.len() => {
            std::str::from_utf8(&prefix[..error.valid_up_to()])
                .map_err(|_| InspectionFailure::Decode)
        }
        Err(_) => Err(InspectionFailure::Decode),
    }
}

fn luhn_matches(text: &str) -> Vec<(usize, usize)> {
    let bytes = text.as_bytes();
    let mut matches = Vec::new();
    let mut run_start = 0;
    while run_start < bytes.len() {
        if !bytes[run_start].is_ascii_digit() {
            run_start += 1;
            continue;
        }
        let mut run_end = run_start;
        while run_end < bytes.len() && bytes[run_end].is_ascii_digit() {
            run_end += 1;
        }
        for start in run_start..run_end {
            for length in 13..=19 {
                let end = start + length;
                if end <= run_end && luhn_valid(&bytes[start..end]) {
                    matches.push((start, end));
                }
            }
        }
        run_start = run_end;
    }
    matches
}

fn luhn_valid(digits: &[u8]) -> bool {
    let mut sum = 0_u32;
    let parity = digits.len() % 2;
    for (index, byte) in digits.iter().enumerate() {
        let mut digit = u32::from(byte - b'0');
        if index % 2 == parity {
            digit *= 2;
            if digit > 9 {
                digit -= 9;
            }
        }
        sum += digit;
    }
    sum.is_multiple_of(10)
}

fn sorted_observations(
    observations: impl IntoIterator<Item = DecisionObservation>,
) -> Vec<DecisionObservation> {
    observations
        .into_iter()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn normalize_identity(value: &str) -> String {
    value.to_owned()
}

fn normalize_extension(extension: &str) -> String {
    extension.trim().trim_start_matches('.').to_lowercase()
}

fn normalize_mime_type(value: &str) -> String {
    value.trim().to_lowercase()
}

fn normalize_path(value: &str) -> String {
    let normalized = value.trim().replace('\\', "/");
    format!("/{}", normalized.trim_start_matches('/')).to_lowercase()
}

fn normalize_destination(value: &str) -> String {
    value.trim().replace('\\', "/").to_lowercase()
}

fn normalize_process(value: &str) -> String {
    value.trim().replace('\\', "/").to_lowercase()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PolicyCompileErrorKind {
    MissingVersion,
    MissingDefaultAction,
    InvalidRule,
    DuplicateRuleId,
    DuplicateDetectorId,
    UnsupportedAction,
    EmptyAnyOf,
    InvalidEncoding,
    InvalidDocument,
    UnknownField,
    LimitExceeded,
    DetectorCompileFailed,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct PolicyCompileError {
    kind: PolicyCompileErrorKind,
}

impl PolicyCompileError {
    const fn new(kind: PolicyCompileErrorKind) -> Self {
        Self { kind }
    }

    pub const fn kind(&self) -> PolicyCompileErrorKind {
        self.kind
    }
}

impl fmt::Debug for PolicyCompileError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PolicyCompileError")
            .field("kind", &self.kind)
            .finish()
    }
}

impl fmt::Display for PolicyCompileError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "policy compilation failed: {}", self.kind.code())
    }
}

impl std::error::Error for PolicyCompileError {}

impl PolicyCompileErrorKind {
    const fn code(self) -> &'static str {
        match self {
            Self::MissingVersion => "missing_version",
            Self::MissingDefaultAction => "missing_default_action",
            Self::InvalidRule => "invalid_rule",
            Self::DuplicateRuleId => "duplicate_rule_id",
            Self::DuplicateDetectorId => "duplicate_detector_id",
            Self::UnsupportedAction => "unsupported_action",
            Self::EmptyAnyOf => "empty_any_of",
            Self::InvalidEncoding => "invalid_encoding",
            Self::InvalidDocument => "invalid_document",
            Self::UnknownField => "unknown_field",
            Self::LimitExceeded => "limit_exceeded",
            Self::DetectorCompileFailed => "detector_compile_failed",
        }
    }
}

fn parse_document(value: Value) -> Result<PolicyDocumentV2, PolicyCompileError> {
    let object = value
        .as_object()
        .ok_or_else(|| PolicyCompileError::new(PolicyCompileErrorKind::InvalidDocument))?;
    reject_unknown(
        object,
        &[
            "schema_version",
            "policy_version",
            "default_action",
            "rules",
        ],
    )?;
    if object.get("schema_version").and_then(Value::as_u64) != Some(2) {
        return Err(PolicyCompileError::new(
            PolicyCompileErrorKind::InvalidDocument,
        ));
    }
    let policy_version = required_string(object, "policy_version")?;
    let default_action = match object.get("default_action") {
        None | Some(Value::Null) => {
            return Err(PolicyCompileError::new(
                PolicyCompileErrorKind::MissingDefaultAction,
            ));
        }
        Some(value) => parse_action(value)?,
    };
    let values = object
        .get("rules")
        .and_then(Value::as_array)
        .ok_or_else(|| PolicyCompileError::new(PolicyCompileErrorKind::InvalidDocument))?;
    let rules = values
        .iter()
        .map(parse_rule)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(PolicyDocumentV2::new(policy_version, default_action).with_rules(rules))
}

fn parse_rule(value: &Value) -> Result<PolicyRuleV2, PolicyCompileError> {
    let object = value
        .as_object()
        .ok_or_else(|| PolicyCompileError::new(PolicyCompileErrorKind::InvalidDocument))?;
    reject_unknown(
        object,
        &["rule_id", "priority", "action", "conditions", "detectors"],
    )?;
    let rule_id = required_string(object, "rule_id")?;
    let priority = object
        .get("priority")
        .and_then(Value::as_u64)
        .and_then(|value| u32::try_from(value).ok())
        .ok_or_else(|| PolicyCompileError::new(PolicyCompileErrorKind::InvalidDocument))?;
    let action = object
        .get("action")
        .ok_or_else(|| PolicyCompileError::new(PolicyCompileErrorKind::InvalidDocument))
        .and_then(parse_action)?;
    let mut conditions = Vec::new();
    if let Some(values) = object.get("conditions") {
        for value in values
            .as_array()
            .ok_or_else(|| PolicyCompileError::new(PolicyCompileErrorKind::InvalidDocument))?
        {
            conditions.extend(parse_condition(value)?);
        }
    }
    let detectors = object
        .get("detectors")
        .map(|values| {
            values
                .as_array()
                .ok_or_else(|| PolicyCompileError::new(PolicyCompileErrorKind::InvalidDocument))?
                .iter()
                .map(parse_detector)
                .collect::<Result<Vec<_>, _>>()
        })
        .transpose()?
        .unwrap_or_default();
    Ok(PolicyRuleV2::new(rule_id, priority, action)
        .with_conditions(conditions)
        .with_detectors(detectors))
}

fn parse_condition(value: &Value) -> Result<Vec<PolicyConditionV2>, PolicyCompileError> {
    let object = value
        .as_object()
        .ok_or_else(|| PolicyCompileError::new(PolicyCompileErrorKind::InvalidDocument))?;
    reject_unknown(object, &["field", "any_of", "at_least", "at_most"])?;
    let field = required_string(object, "field")?;
    if field == "size" {
        let mut conditions = Vec::new();
        if let Some(value) = object.get("at_least").and_then(Value::as_u64) {
            conditions.push(PolicyConditionV2::size_at_least(value));
        }
        if let Some(value) = object.get("at_most").and_then(Value::as_u64) {
            conditions.push(PolicyConditionV2::size_at_most(value));
        }
        if conditions.is_empty() {
            return Err(PolicyCompileError::new(
                PolicyCompileErrorKind::InvalidDocument,
            ));
        }
        return Ok(conditions);
    }
    let values = object
        .get("any_of")
        .and_then(Value::as_array)
        .ok_or_else(|| PolicyCompileError::new(PolicyCompileErrorKind::InvalidDocument))?;
    if field == "operation" {
        let operations = values
            .iter()
            .map(parse_operation)
            .collect::<Result<Vec<_>, _>>()?;
        return Ok(vec![PolicyConditionV2::operation_any_of(operations)]);
    }
    let values = values
        .iter()
        .map(|value| {
            value
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| PolicyCompileError::new(PolicyCompileErrorKind::InvalidDocument))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let condition = match field.as_str() {
        "file_name" => PolicyConditionV2::file_name_any_of(values),
        "extension" => PolicyConditionV2::extension_any_of(values),
        "mime_type" => PolicyConditionV2::mime_type_any_of(values),
        "path" => PolicyConditionV2::path_any_of(values),
        "owner" => PolicyConditionV2::owner_any_of(values),
        "destination" => PolicyConditionV2::destination_any_of(values),
        "process" => PolicyConditionV2::process_any_of(values),
        _ => {
            return Err(PolicyCompileError::new(
                PolicyCompileErrorKind::InvalidDocument,
            ));
        }
    };
    Ok(vec![condition])
}

fn parse_detector(value: &Value) -> Result<ContentDetectorV2, PolicyCompileError> {
    let object = value
        .as_object()
        .ok_or_else(|| PolicyCompileError::new(PolicyCompileErrorKind::InvalidDocument))?;
    reject_unknown(
        object,
        &[
            "detector_id",
            "type",
            "pattern",
            "terms",
            "digest",
            "kind",
            "prefix_bytes",
        ],
    )?;
    let detector_id = required_string(object, "detector_id")?;
    let detector_type = required_string(object, "type")?;
    let prefix_bytes = object
        .get("prefix_bytes")
        .map(|value| {
            value
                .as_u64()
                .and_then(|value| usize::try_from(value).ok())
                .ok_or_else(|| PolicyCompileError::new(PolicyCompileErrorKind::InvalidDocument))
        })
        .transpose()?;
    match detector_type.as_str() {
        "regex" => Ok(ContentDetectorV2::regex(
            detector_id,
            required_string(object, "pattern")?,
            prefix_bytes,
        )),
        "dictionary" => {
            let terms = object
                .get("terms")
                .and_then(Value::as_array)
                .ok_or_else(|| PolicyCompileError::new(PolicyCompileErrorKind::InvalidDocument))?
                .iter()
                .map(|value| {
                    value.as_str().map(str::to_owned).ok_or_else(|| {
                        PolicyCompileError::new(PolicyCompileErrorKind::InvalidDocument)
                    })
                })
                .collect::<Result<Vec<_>, _>>()?;
            Ok(ContentDetectorV2::dictionary(
                detector_id,
                terms,
                prefix_bytes,
            ))
        }
        "sha256" => Ok(ContentDetectorV2::authenticated_sha256(
            detector_id,
            parse_digest(&required_string(object, "digest")?)?,
        )),
        "structured_identifier" => {
            if required_string(object, "kind")? != "luhn" {
                return Err(PolicyCompileError::new(
                    PolicyCompileErrorKind::InvalidDocument,
                ));
            }
            Ok(ContentDetectorV2::structured_identifier(
                detector_id,
                StructuredIdentifierKind::Luhn,
                prefix_bytes,
            ))
        }
        _ => Err(PolicyCompileError::new(
            PolicyCompileErrorKind::InvalidDocument,
        )),
    }
}

fn parse_digest(value: &str) -> Result<[u8; 32], PolicyCompileError> {
    if value.len() != 64 {
        return Err(PolicyCompileError::new(
            PolicyCompileErrorKind::InvalidDocument,
        ));
    }
    let mut digest = [0_u8; 32];
    for (index, byte) in digest.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|_| PolicyCompileError::new(PolicyCompileErrorKind::InvalidDocument))?;
    }
    Ok(digest)
}

fn parse_action(value: &Value) -> Result<EnforcementAction, PolicyCompileError> {
    match value.as_str() {
        Some("allow") => Ok(EnforcementAction::Allow),
        Some("block") => Ok(EnforcementAction::Block),
        Some("allow_and_audit") => Ok(EnforcementAction::AllowAndAudit),
        Some("warn") => Ok(EnforcementAction::Warn),
        Some("require_justification") => Ok(EnforcementAction::RequireJustification),
        _ => Err(PolicyCompileError::new(
            PolicyCompileErrorKind::InvalidDocument,
        )),
    }
}

fn parse_operation(value: &Value) -> Result<Operation, PolicyCompileError> {
    match value.as_str() {
        Some("read") => Ok(Operation::Read),
        Some("write") => Ok(Operation::Write),
        Some("import") => Ok(Operation::Import),
        Some("export") => Ok(Operation::Export),
        Some("copy") => Ok(Operation::Copy),
        Some("delete") => Ok(Operation::Delete),
        _ => Err(PolicyCompileError::new(
            PolicyCompileErrorKind::InvalidDocument,
        )),
    }
}

fn required_string(object: &Map<String, Value>, field: &str) -> Result<String, PolicyCompileError> {
    object
        .get(field)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| PolicyCompileError::new(PolicyCompileErrorKind::InvalidDocument))
}

fn reject_unknown(object: &Map<String, Value>, allowed: &[&str]) -> Result<(), PolicyCompileError> {
    if object.keys().any(|key| !allowed.contains(&key.as_str())) {
        Err(PolicyCompileError::new(
            PolicyCompileErrorKind::UnknownField,
        ))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{PolicyEvaluator, PolicyRule};
    use dlp_domain::{DecisionReason, EnforcementAction, PolicyInput, UserSid};

    fn input(extension: &str) -> PolicyInput {
        PolicyInput::new(
            "report.docx",
            extension,
            "/docs/report.docx",
            UserSid::parse("S-1-5-21").expect("valid SID"),
            42,
        )
        .expect("valid policy input")
    }

    #[test]
    fn matching_and_highest_priority_rule_win_deterministically() {
        let evaluator = PolicyEvaluator::new(EnforcementAction::Allow);
        let rules = vec![
            PolicyRule::new("warn-docx", "docx", 5, EnforcementAction::Warn),
            PolicyRule::new("block-docx", "docx", 10, EnforcementAction::Block),
        ];
        let decision = evaluator.evaluate(&input("docx"), &rules);
        assert_eq!(decision.action, EnforcementAction::Block);
        assert_eq!(decision.reason, DecisionReason::MatchedRule);
        assert_eq!(decision.rule_id.as_deref(), Some("block-docx"));
    }

    #[test]
    fn equal_priority_uses_restrictive_action_then_stable_rule_id() {
        let evaluator = PolicyEvaluator::new(EnforcementAction::Allow);
        let rules = vec![
            PolicyRule::new("z-warn", "docx", 10, EnforcementAction::Warn),
            PolicyRule::new("a-warn", "docx", 10, EnforcementAction::Warn),
            PolicyRule::new("block", "docx", 10, EnforcementAction::Block),
        ];
        let decision = evaluator.evaluate(&input("docx"), &rules);
        assert_eq!(decision.action, EnforcementAction::Block);
        assert_eq!(decision.reason, DecisionReason::EqualPriorityConflict);
        assert_eq!(decision.rule_id.as_deref(), Some("block"));
    }

    #[test]
    fn default_and_empty_inputs_are_deterministic_on_repeat() {
        let evaluator = PolicyEvaluator::new(EnforcementAction::Warn);
        let empty = evaluator.evaluate(&input("txt"), &[]);
        let non_matching = evaluator.evaluate(
            &input("txt"),
            &[PolicyRule::new("docx", "docx", 1, EnforcementAction::Block)],
        );
        assert_eq!(empty.action, EnforcementAction::Warn);
        assert_eq!(empty.reason, DecisionReason::EmptyPolicy);
        assert_eq!(non_matching.action, EnforcementAction::Warn);
        assert_eq!(non_matching.reason, DecisionReason::DefaultAction);
        assert_eq!(
            evaluator.evaluate(&input("txt"), &[]),
            evaluator.evaluate(&input("txt"), &[])
        );
    }
}

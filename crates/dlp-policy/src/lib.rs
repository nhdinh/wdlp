#![forbid(unsafe_code)]

//! Deterministic, portable policy selection. Drive enforcement is intentionally
//! outside this crate and remains a later-phase responsibility.

use dlp_domain::{
    DecisionObservation, DecisionReason, EnforcementAction, PolicyDecision, PolicyInput,
};
use std::{collections::BTreeSet, fmt};

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

        candidates.sort_unstable_by(|left, right| {
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
        });
        let selected = candidates[0];
        let equal_priority_conflict = candidates
            .iter()
            .skip(1)
            .any(|candidate| candidate.priority == selected.priority);

        let mut observations = candidates
            .iter()
            .map(|candidate| DecisionObservation::RuleMatched {
                rule_id: candidate.rule_id.clone(),
            })
            .collect::<Vec<_>>();
        observations.sort();
        observations.dedup();

        PolicyDecision {
            action: selected.action,
            reason: if equal_priority_conflict {
                DecisionReason::EqualPriorityConflict
            } else {
                DecisionReason::MatchedRule
            },
            rule_id: Some(selected.rule_id.clone()),
            observations,
        }
    }
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
            content_prefix_hard: 4 * 1024 * 1024,
            regex_source_default: 4 * 1024,
            regex_source_hard: 16 * 1024,
            regex_nesting_default: 32,
            regex_nesting_hard: 64,
            regex_automaton_default: 1024 * 1024,
            regex_automaton_hard: 4 * 1024 * 1024,
            dictionary_entries_default: 10_000,
            dictionary_entries_hard: 25_000,
            dictionary_source_default: 1024 * 1024,
            dictionary_source_hard: 4 * 1024 * 1024,
            dictionary_automaton_default: 8 * 1024 * 1024,
            dictionary_automaton_hard: 16 * 1024 * 1024,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyRuleV2 {
    rule_id: String,
    extension: String,
    priority: u32,
    action: EnforcementAction,
}

impl PolicyRuleV2 {
    pub fn extension(
        rule_id: impl Into<String>,
        extension: impl Into<String>,
        priority: u32,
        action: EnforcementAction,
    ) -> Self {
        Self {
            rule_id: rule_id.into(),
            extension: normalize_extension(&extension.into()),
            priority,
            action,
        }
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

    pub fn with_rules(mut self, rules: Vec<PolicyRuleV2>) -> Self {
        self.rules = rules;
        self
    }

    pub fn compile(
        self,
        ceilings: DetectorCeilings,
    ) -> Result<CompiledPolicyV2, PolicyCompileError> {
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
        for rule in self.rules {
            if rule.rule_id.is_empty() || rule.extension.is_empty() {
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
            rules.push(PolicyRule::new(
                rule.rule_id,
                rule.extension,
                rule.priority,
                rule.action,
            ));
        }
        rules.sort_unstable_by(|left, right| left.rule_id.cmp(&right.rule_id));
        Ok(CompiledPolicyV2 {
            policy_version: self.policy_version,
            evaluator: PolicyEvaluator::new(self.default_action),
            rules,
            ceilings,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompiledPolicyV2 {
    policy_version: String,
    evaluator: PolicyEvaluator,
    rules: Vec<PolicyRule>,
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
        let mut normalized = input.clone();
        normalized.extension = normalize_extension(&normalized.extension);
        self.evaluator.evaluate(&normalized, &self.rules)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PolicyCompileErrorKind {
    MissingVersion,
    InvalidRule,
    DuplicateRuleId,
    UnsupportedAction,
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
            Self::InvalidRule => "invalid_rule",
            Self::DuplicateRuleId => "duplicate_rule_id",
            Self::UnsupportedAction => "unsupported_action",
        }
    }
}

fn normalize_extension(extension: &str) -> String {
    extension.trim().trim_start_matches('.').to_lowercase()
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

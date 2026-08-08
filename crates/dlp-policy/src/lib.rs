#![forbid(unsafe_code)]

//! Deterministic, portable policy selection. Drive enforcement is intentionally
//! outside this crate and remains a later-phase responsibility.

use dlp_domain::{DecisionReason, EnforcementAction, PolicyDecision, PolicyInput};

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

        PolicyDecision {
            action: selected.action,
            reason: if equal_priority_conflict {
                DecisionReason::EqualPriorityConflict
            } else {
                DecisionReason::MatchedRule
            },
            rule_id: Some(selected.rule_id.clone()),
        }
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

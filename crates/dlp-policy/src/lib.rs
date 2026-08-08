#![forbid(unsafe_code)]

#[cfg(test)]
mod tests {
    use super::{PolicyEvaluator, PolicyRule};
    use dlp_domain::{
        DecisionReason, EnforcementAction, PolicyInput, UserSid,
    };

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

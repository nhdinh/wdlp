#![forbid(unsafe_code)]

use std::fmt;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DomainErrorKind {
    EmptyValue,
    InvalidIdentifier,
    InvalidPolicyInput,
}

#[derive(Clone, Eq, PartialEq)]
pub struct DomainError {
    kind: DomainErrorKind,
}

impl DomainError {
    pub const fn new(kind: DomainErrorKind, _subject: &'static str) -> Self {
        Self { kind }
    }

    pub const fn kind(&self) -> &DomainErrorKind {
        &self.kind
    }
}

impl fmt::Debug for DomainError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DomainError")
            .field("kind", &self.kind)
            .field("subject", &"[REDACTED]")
            .finish()
    }
}

impl fmt::Display for DomainError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "invalid domain value: [REDACTED]")
    }
}

impl std::error::Error for DomainError {}

macro_rules! typed_identifier {
    ($name:ident, $subject:literal) => {
        #[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
        pub struct $name(String);

        impl $name {
            pub fn parse(value: impl Into<String>) -> Result<Self, DomainError> {
                let value = value.into();
                if value.is_empty() {
                    return Err(DomainError::new(DomainErrorKind::EmptyValue, $subject));
                }
                if value.len() > 128
                    || !value
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
                {
                    return Err(DomainError::new(
                        DomainErrorKind::InvalidIdentifier,
                        $subject,
                    ));
                }
                Ok(Self(value))
            }

            pub fn to_wire(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(formatter, concat!(stringify!($name), "([REDACTED])"))
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(formatter, "[REDACTED]")
            }
        }
    };
}

typed_identifier!(DeviceId, "device id");
typed_identifier!(UserSid, "user SID");
typed_identifier!(StoreId, "store id");
typed_identifier!(FileId, "file id");
typed_identifier!(BundleVersion, "bundle version");

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyInput {
    pub file_name: String,
    pub extension: String,
    pub path: String,
    pub owner: UserSid,
    pub size_bytes: u64,
}

impl PolicyInput {
    pub fn new(
        file_name: impl Into<String>,
        extension: impl Into<String>,
        path: impl Into<String>,
        owner: UserSid,
        size_bytes: u64,
    ) -> Result<Self, DomainError> {
        let file_name = file_name.into();
        let extension = extension.into();
        let path = path.into();
        if file_name.is_empty() || extension.is_empty() || path.is_empty() {
            return Err(DomainError::new(
                DomainErrorKind::InvalidPolicyInput,
                "policy input",
            ));
        }
        Ok(Self {
            file_name,
            extension,
            path,
            owner,
            size_bytes,
        })
    }

    pub fn canonical_bytes(&self) -> Vec<u8> {
        format!(
            "file_name={};extension={};path={};owner={};size_bytes={}",
            self.file_name,
            self.extension,
            self.path,
            self.owner.to_wire(),
            self.size_bytes
        )
        .into_bytes()
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum EnforcementAction {
    Allow,
    Block,
    AllowAndAudit,
    Warn,
    RequireJustification,
}

impl EnforcementAction {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Block => "block",
            Self::AllowAndAudit => "allow_and_audit",
            Self::Warn => "warn",
            Self::RequireJustification => "require_justification",
        }
    }

    pub const fn restrictiveness(self) -> u8 {
        match self {
            Self::Allow => 0,
            Self::AllowAndAudit => 1,
            Self::Warn => 2,
            Self::RequireJustification => 3,
            Self::Block => 4,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum DecisionReason {
    MatchedRule,
    EqualPriorityConflict,
    DefaultAction,
    EmptyPolicy,
}

impl DecisionReason {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MatchedRule => "matched_rule",
            Self::EqualPriorityConflict => "equal_priority_conflict",
            Self::DefaultAction => "default_action",
            Self::EmptyPolicy => "empty_policy",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyDecision {
    pub action: EnforcementAction,
    pub reason: DecisionReason,
    pub rule_id: Option<String>,
}

impl PolicyDecision {
    pub fn canonical_bytes(&self) -> Vec<u8> {
        format!(
            "action={};reason={};rule_id={}",
            self.action.as_str(),
            self.reason.as_str(),
            self.rule_id.as_deref().unwrap_or(""),
        )
        .into_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::{
        DecisionReason, DeviceId, DomainError, DomainErrorKind, EnforcementAction, PolicyDecision,
        PolicyInput, UserSid,
    };
    use std::fs;
    use std::process::Command;

    #[test]
    fn typed_values_reject_bad_input_and_redact_sensitive_output() {
        let device = DeviceId::parse("device-01").expect("valid device id");
        assert_eq!(device.to_wire(), "device-01");
        assert!(DeviceId::parse(" ").is_err());
        assert_eq!(format!("{device:?}"), "DeviceId([REDACTED])");
        assert_eq!(device.to_string(), "[REDACTED]");
        assert_eq!(EnforcementAction::Block.as_str(), "block");
    }

    #[test]
    fn policy_values_and_errors_are_stable_and_redacted() {
        let owner = UserSid::parse("S-1-5-21").expect("valid SID");
        let input = PolicyInput::new("report.docx", "docx", "/docs/report.docx", owner, 42)
            .expect("valid policy input");
        let decision = PolicyDecision {
            action: EnforcementAction::Block,
            reason: DecisionReason::MatchedRule,
            rule_id: Some("rule-42".to_owned()),
        };
        let error = DomainError::new(DomainErrorKind::InvalidIdentifier, "device-secret");

        assert_eq!(input.canonical_bytes(), input.canonical_bytes());
        assert_eq!(decision.canonical_bytes(), decision.canonical_bytes());
        assert_eq!(decision, decision.clone());
        assert!(!format!("{error:?}").contains("device-secret"));
        assert!(!error.to_string().contains("device-secret"));
    }

    #[test]
    fn compile_fail_fixture_rejects_unsafe_portable_code() {
        let fixture_directory =
            std::env::temp_dir().join(format!("dlp-domain-unsafe-fixture-{}", std::process::id()));
        let _ = fs::remove_dir_all(&fixture_directory);
        fs::create_dir_all(&fixture_directory).expect("create temporary fixture directory");
        let source_path = fixture_directory.join("unsafe_fixture.rs");
        fs::write(
            &source_path,
            "#![forbid(unsafe_code)]\npub fn dereference(ptr: *const u8) { unsafe { let _ = *ptr; } }\n",
        )
        .expect("write compile-fail fixture");

        let output = Command::new("rustc")
            .args(["--crate-type", "lib"])
            .arg(&source_path)
            .current_dir(&fixture_directory)
            .output()
            .expect("run rustc for compile-fail fixture");

        let _ = fs::remove_dir_all(&fixture_directory);
        assert!(
            !output.status.success(),
            "unsafe fixture unexpectedly compiled"
        );
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("unsafe"),
            "fixture failure should be caused by the unsafe-code prohibition"
        );
    }
}

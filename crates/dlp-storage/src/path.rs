use std::fmt;

pub const MAX_PATH_LENGTH: usize = 260;
pub const MAX_COMPONENT_LENGTH: usize = 128;
pub const MAX_COMPONENTS: usize = 64;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PathError {
    InvalidPath,
}
impl fmt::Display for PathError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "invalid virtual path")
    }
}
impl std::error::Error for PathError {}

/// A bounded Windows-style virtual path with a stable display form and canonical lookup key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VirtualPath {
    display: Vec<String>,
    lookup: String,
}
impl VirtualPath {
    /// The synthetic root directory used internally by filesystem adapters.
    /// It is never parsed from caller input, so user-provided empty paths remain invalid.
    pub fn root() -> Self {
        Self {
            display: Vec::new(),
            lookup: String::new(),
        }
    }

    pub fn parse(input: &str) -> Result<Self, PathError> {
        if input.is_empty()
            || input.len() > MAX_PATH_LENGTH
            || input.contains('\0')
            || input.starts_with(['\\', '/'])
            || input.contains(':')
            || is_device_or_unc(input)
        {
            return Err(PathError::InvalidPath);
        }
        let display: Vec<String> = input
            .split(['\\', '/'])
            .filter(|part| !part.is_empty())
            .map(ToOwned::to_owned)
            .collect();
        if display.is_empty()
            || display.len() > MAX_COMPONENTS
            || display.iter().any(|part| !valid_component(part))
        {
            return Err(PathError::InvalidPath);
        }
        let lookup = display
            .iter()
            .map(|part| part.to_ascii_lowercase())
            .collect::<Vec<_>>()
            .join("/");
        Ok(Self { display, lookup })
    }
    pub fn lookup_key(&self) -> &str {
        &self.lookup
    }
    pub fn display_name(&self) -> Option<&str> {
        self.display.last().map(String::as_str)
    }
    pub(crate) fn parent_key(&self) -> Option<String> {
        let mut pieces = self.lookup.split('/').collect::<Vec<_>>();
        pieces.pop();
        if pieces.is_empty() {
            None
        } else {
            Some(pieces.join("/"))
        }
    }
}

fn is_device_or_unc(input: &str) -> bool {
    let upper = input.to_ascii_uppercase();
    upper.starts_with("\\\\") || upper.starts_with("\\DEVICE\\") || upper.starts_with("\\?\\")
}
fn valid_component(component: &str) -> bool {
    if component.is_empty()
        || component.len() > MAX_COMPONENT_LENGTH
        || component == "."
        || component == ".."
        || component.ends_with(['.', ' '])
        || component.chars().any(|character| {
            character.is_control() || matches!(character, '<' | '>' | '"' | '|' | '?' | '*')
        })
    {
        return false;
    }
    let stem = component
        .split('.')
        .next()
        .unwrap_or_default()
        .to_ascii_uppercase();
    !matches!(
        stem.as_str(),
        "CON"
            | "PRN"
            | "AUX"
            | "NUL"
            | "COM1"
            | "COM2"
            | "COM3"
            | "COM4"
            | "COM5"
            | "COM6"
            | "COM7"
            | "COM8"
            | "COM9"
            | "LPT1"
            | "LPT2"
            | "LPT3"
            | "LPT4"
            | "LPT5"
            | "LPT6"
            | "LPT7"
            | "LPT8"
            | "LPT9"
    )
}

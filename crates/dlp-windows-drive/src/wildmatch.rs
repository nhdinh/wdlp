//! Windows `FindFirstFile` wildcard semantics for directory enumeration.
//!
//! Supports `*` (zero or more characters) and `?` (exactly one character), with
//! case-insensitive ASCII matching. This is sufficient for Explorer and Office
//! directory listings; DOS-style suffix wildcards (e.g. `*.*`) are interpreted
//! literally as the pattern supplied by WinFsp.

/// Returns true when `name` matches `pattern` using Windows wildcard rules.
pub fn matches(pattern: &str, name: &str) -> bool {
    let pattern: Vec<char> = pattern.chars().flat_map(|c| c.to_lowercase()).collect();
    let name: Vec<char> = name.chars().flat_map(|c| c.to_lowercase()).collect();

    let mut pattern_index = 0usize;
    let mut name_index = 0usize;
    let mut star_index: Option<usize> = None;
    let mut match_index = 0usize;

    while name_index < name.len() {
        if pattern_index < pattern.len()
            && (pattern[pattern_index] == name[name_index] || pattern[pattern_index] == '?')
        {
            pattern_index += 1;
            name_index += 1;
        } else if pattern_index < pattern.len() && pattern[pattern_index] == '*' {
            star_index = Some(pattern_index);
            match_index = name_index;
            pattern_index += 1;
        } else if let Some(star) = star_index {
            pattern_index = star + 1;
            match_index += 1;
            name_index = match_index;
        } else {
            return false;
        }
    }

    while pattern_index < pattern.len() && pattern[pattern_index] == '*' {
        pattern_index += 1;
    }

    pattern_index == pattern.len()
}

#[cfg(test)]
mod tests {
    use super::matches;

    #[test]
    fn star_matches_zero_or_more_characters() {
        assert!(matches("*", "anything.txt"));
        assert!(matches("*.txt", "report.txt"));
        assert!(matches("*.txt", "a.txt"));
        assert!(!matches("*.txt", "report.docx"));
        assert!(matches("doc*", "document.txt"));
        assert!(!matches("doc*", "notes.txt"));
    }

    #[test]
    fn question_mark_matches_exactly_one_character() {
        assert!(matches("?.txt", "a.txt"));
        assert!(!matches("?.txt", "ab.txt"));
        assert!(matches("file?.txt", "file1.txt"));
        assert!(!matches("file?.txt", "file10.txt"));
    }

    #[test]
    fn matching_is_case_insensitive() {
        assert!(matches("*.TXT", "report.txt"));
        assert!(matches("Report.*", "report.TXT"));
        assert!(matches("FiLe?.TxT", "file1.txt"));
    }

    #[test]
    fn mixed_patterns() {
        assert!(matches("*report*.txt", "Quarterly report v2.txt"));
        assert!(matches("???", "abc"));
        assert!(!matches("???", "abcd"));
        assert!(matches("a?c*", "abcdef"));
    }
}

use std::sync::OnceLock;
use regex::Regex;

/// ReDoS-safe static regex patterns.
static WHITESPACE_RE: OnceLock<Regex> = OnceLock::new();
static NON_PRINTABLE_RE: OnceLock<Regex> = OnceLock::new();

/// Normalizes answers: strips whitespace, collapses runs, removes non-printable ASCII, and lowercases.
pub fn normalize_answer(raw: &str) -> String {
    let ws_re = WHITESPACE_RE.get_or_init(|| Regex::new(r"\s+").expect("Invalid regex"));
    let np_re = NON_PRINTABLE_RE.get_or_init(|| Regex::new(r"[^\x20-\x7E]").expect("Invalid regex"));
    
    let cleaned = np_re.replace_all(raw, "");
    let collapsed = ws_re.replace_all(cleaned.trim(), " ");
    collapsed.to_lowercase()
}



#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trim_and_lowercase() {
        assert_eq!(normalize_answer("  Hello World  "), "hello world");
    }

    #[test]
    fn test_collapse_whitespace() {
        assert_eq!(normalize_answer("the  quick   brown"), "the quick brown");
    }

    #[test]
    fn test_non_printable_stripped() {
        let input = "answer\x00\x01\x1f";
        assert_eq!(normalize_answer(input), "answer");
    }

    #[test]
    fn test_already_normalized() {
        assert_eq!(normalize_answer("correct answer"), "correct answer");
    }
}

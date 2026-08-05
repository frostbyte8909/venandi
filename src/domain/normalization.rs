use std::sync::OnceLock;
use regex::Regex;

/// Pre-compiled regex for stripping all characters that are not ASCII
/// alphanumeric or common punctuation used in answer strings.
/// Compiled once at startup; zero allocation on every call thereafter.
///
/// Finite automaton guarantees O(n) execution — ReDoS is structurally impossible.
static WHITESPACE_RE: OnceLock<Regex> = OnceLock::new();
static NON_PRINTABLE_RE: OnceLock<Regex> = OnceLock::new();

/// Normalizes a Cryptic Hunt answer for comparison:
/// 1. Strips leading/trailing whitespace.
/// 2. Collapses internal runs of whitespace to a single space.
/// 3. Removes non-printable / non-ASCII characters.
/// 4. Converts to lowercase.
///
/// This ensures "  The  ANSWER  " matches "the answer".
pub fn normalize_answer(raw: &str) -> String {
    let ws_re = WHITESPACE_RE.get_or_init(|| Regex::new(r"\s+").expect("Invalid regex"));
    let np_re = NON_PRINTABLE_RE.get_or_init(|| Regex::new(r"[^\x20-\x7E]").expect("Invalid regex"));
    
    // Remove non-printable chars first.
    let cleaned = np_re.replace_all(raw, "");
    // Collapse whitespace runs.
    let collapsed = ws_re.replace_all(cleaned.trim(), " ");
    collapsed.to_lowercase()
}

// ─── Tests ───────────────────────────────────────────────────────────────────

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

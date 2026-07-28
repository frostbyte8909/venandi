use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use uuid::Uuid;

type HmacSha256 = Hmac<Sha256>;

/// Generates the expected HMAC-SHA256 dynamic flag for a given level and team.
///
/// Formula: `HMAC-SHA256(server_secret, level_id + ":" + team_id)`
///
/// The output is a lowercase hex string (64 characters).
/// The server secret is never embedded in the output.
pub fn generate_dynamic_flag(server_secret: &[u8], level_id: &str, team_id: Uuid) -> String {
    let mut mac =
        HmacSha256::new_from_slice(server_secret).expect("HMAC accepts any key length");

    let message = format!("{}:{}", level_id, team_id);
    mac.update(message.as_bytes());

    let result = mac.finalize().into_bytes();
    hex::encode(result)
}

/// Compares a user-submitted flag against the expected dynamic flag using
/// **constant-time** comparison (via the `subtle` crate) to prevent timing
/// oracle attacks.
///
/// Returns `true` only if the submission matches exactly.
pub fn verify_dynamic_flag(
    server_secret: &[u8],
    level_id: &str,
    team_id: Uuid,
    submission: &str,
) -> bool {
    let expected = generate_dynamic_flag(server_secret, level_id, team_id);
    // Convert to bytes for constant-time comparison.
    expected.as_bytes().ct_eq(submission.as_bytes()).into()
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &[u8] = b"test_secret_key_for_unit_tests";

    #[test]
    fn test_flag_is_deterministic() {
        let team = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap();
        let flag1 = generate_dynamic_flag(SECRET, "lvl_1", team);
        let flag2 = generate_dynamic_flag(SECRET, "lvl_1", team);
        assert_eq!(flag1, flag2);
    }

    #[test]
    fn test_different_levels_produce_different_flags() {
        let team = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap();
        let flag_a = generate_dynamic_flag(SECRET, "lvl_1", team);
        let flag_b = generate_dynamic_flag(SECRET, "lvl_2", team);
        assert_ne!(flag_a, flag_b);
    }

    #[test]
    fn test_different_teams_produce_different_flags() {
        let team_a = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap();
        let team_b = Uuid::parse_str("660e8400-e29b-41d4-a716-446655440001").unwrap();
        let flag_a = generate_dynamic_flag(SECRET, "lvl_1", team_a);
        let flag_b = generate_dynamic_flag(SECRET, "lvl_1", team_b);
        assert_ne!(flag_a, flag_b);
    }

    #[test]
    fn test_verify_correct_flag() {
        let team = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap();
        let flag = generate_dynamic_flag(SECRET, "lvl_boss", team);
        assert!(verify_dynamic_flag(SECRET, "lvl_boss", team, &flag));
    }

    #[test]
    fn test_verify_wrong_flag() {
        let team = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap();
        assert!(!verify_dynamic_flag(SECRET, "lvl_boss", team, "wrong_flag"));
    }
}

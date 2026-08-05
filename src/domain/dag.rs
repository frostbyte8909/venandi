use crate::config::LevelConfig;
use std::collections::{HashMap, HashSet, VecDeque};

/// Evaluation context representing a team's current state.
#[derive(Debug, Clone)]
pub struct EvalContext {
    pub solved: HashSet<String>,
    pub score: u64,
}

/// Validates level graph using Kahn's algorithm. Panics on cycle detection to prevent invalid state.
pub fn validate_dag_or_panic(levels: &[LevelConfig]) {
    let mut in_degree: HashMap<&str, usize> = HashMap::new();
    let mut dependents: HashMap<&str, Vec<&str>> = HashMap::new();

    for level in levels {
        in_degree.entry(&level.id).or_insert(0);
        dependents.entry(&level.id).or_default();
    }

    for level in levels {
        if level.unlock_condition == "START" {
            continue;
        }
        let deps = extract_level_ids_from_condition(&level.unlock_condition, levels);
        for dep in deps {
            *in_degree.entry(level.id.as_str()).or_insert(0) += 1;
            dependents.entry(dep).or_default().push(&level.id);
        }
    }

    let mut queue: VecDeque<&str> = in_degree
        .iter()
        .filter(|(_, &deg)| deg == 0)
        .map(|(&id, _)| id)
        .collect();

    let mut processed = 0usize;

    while let Some(node) = queue.pop_front() {
        processed += 1;
        if let Some(deps) = dependents.get(node) {
            for &dep in deps {
                let degree = in_degree.entry(dep).or_insert(0);
                *degree -= 1;
                if *degree == 0 {
                    queue.push_back(dep);
                }
            }
        }
    }

    if processed != levels.len() {
        panic!(
            "[VENANDI BOOT ABORT] Cycle detected in hunt.json DAG. \
             Processed {processed}/{} nodes before deadlock. \
             Fix circular unlock_condition references before restarting.",
            levels.len()
        );
    }

    tracing::info!("DAG validation passed: {} levels, no cycles detected.", levels.len());
}

/// Evaluates boolean condition AST against EvalContext.
pub fn evaluate_condition(condition: &str, ctx: &EvalContext) -> bool {
    if condition.trim() == "START" {
        return true;
    }
    let tokens = tokenize(condition);
    let mut pos = 0;
    parse_expr(&tokens, &mut pos, ctx)
}



#[derive(Debug, Clone, PartialEq)]
enum Token {
    And,
    Or,
    LParen,
    RParen,
    Ident(String),
    Gte,
    Number(u64),
}

fn tokenize(input: &str) -> Vec<Token> {
    let mut tokens = Vec::new();
    let mut chars = input.chars().peekable();

    while let Some(&ch) = chars.peek() {
        match ch {
            ' ' | '\t' | '\n' => {
                chars.next();
            }
            '(' => {
                chars.next();
                tokens.push(Token::LParen);
            }
            ')' => {
                chars.next();
                tokens.push(Token::RParen);
            }
            '>' => {
                chars.next();
                if chars.peek() == Some(&'=') {
                    chars.next();
                    tokens.push(Token::Gte);
                }
            }
            c if c.is_alphanumeric() || c == '_' => {
                let mut word = String::new();
                while let Some(&ch) = chars.peek() {
                    if ch.is_alphanumeric() || ch == '_' {
                        word.push(ch);
                        chars.next();
                    } else {
                        break;
                    }
                }
                match word.as_str() {
                    "AND" => tokens.push(Token::And),
                    "OR" => tokens.push(Token::Or),
                    _ => {
                        if let Ok(n) = word.parse::<u64>() {
                            tokens.push(Token::Number(n));
                        } else {
                            tokens.push(Token::Ident(word));
                        }
                    }
                }
            }
            _ => {
                chars.next();
            }
        }
    }
    tokens
}

fn parse_expr(tokens: &[Token], pos: &mut usize, ctx: &EvalContext) -> bool {
    let mut result = parse_term(tokens, pos, ctx);
    while *pos < tokens.len() && tokens[*pos] == Token::Or {
        *pos += 1;
        let rhs = parse_term(tokens, pos, ctx);
        result = result || rhs;
    }
    result
}

fn parse_term(tokens: &[Token], pos: &mut usize, ctx: &EvalContext) -> bool {
    let mut result = parse_factor(tokens, pos, ctx);
    while *pos < tokens.len() && tokens[*pos] == Token::And {
        *pos += 1;
        let rhs = parse_factor(tokens, pos, ctx);
        result = result && rhs;
    }
    result
}

fn parse_factor(tokens: &[Token], pos: &mut usize, ctx: &EvalContext) -> bool {
    if *pos >= tokens.len() {
        return false;
    }
    match &tokens[*pos] {
        Token::LParen => {
            *pos += 1;
            let result = parse_expr(tokens, pos, ctx);
            if *pos < tokens.len() && tokens[*pos] == Token::RParen {
                *pos += 1;
            }
            result
        }
        Token::Ident(id) => {
            let id = id.clone();
            *pos += 1;
            if id == "team_score"
                && *pos < tokens.len()
                && tokens[*pos] == Token::Gte
            {
                *pos += 1;
                if let Some(Token::Number(n)) = tokens.get(*pos) {
                    let n = *n;
                    *pos += 1;
                    return ctx.score >= n;
                }
                return false;
            }
            ctx.solved.contains(&id)
        }
        _ => false,
    }
}

/// Extracts level identifiers for cycle detection.
fn extract_level_ids_from_condition<'a>(
    condition: &str,
    levels: &'a [LevelConfig],
) -> Vec<&'a str> {
    let level_id_set: HashSet<&str> = levels.iter().map(|l| l.id.as_str()).collect();
    let tokens = tokenize(condition);
    tokens
        .iter()
        .filter_map(|t| {
            if let Token::Ident(id) = t {
                if id != "team_score" && level_id_set.contains(id.as_str()) {
                    return levels
                        .iter()
                        .find(|l| l.id == *id)
                        .map(|l| l.id.as_str());
                }
            }
            None
        })
        .collect()
}



#[cfg(test)]
mod tests {
    use super::*;

    fn ctx(solved: &[&str], score: u64) -> EvalContext {
        EvalContext {
            solved: solved.iter().map(|s| s.to_string()).collect(),
            score,
        }
    }

    #[test]
    fn test_start_always_true() {
        assert!(evaluate_condition("START", &ctx(&[], 0)));
    }

    #[test]
    fn test_simple_and_true() {
        let c = ctx(&["lvl_1", "lvl_2"], 0);
        assert!(evaluate_condition("lvl_1 AND lvl_2", &c));
    }

    #[test]
    fn test_simple_and_false() {
        let c = ctx(&["lvl_1"], 0);
        assert!(!evaluate_condition("lvl_1 AND lvl_2", &c));
    }

    #[test]
    fn test_or_partial() {
        let c = ctx(&["lvl_1"], 0);
        assert!(evaluate_condition("lvl_1 OR lvl_2", &c));
    }

    #[test]
    fn test_score_predicate() {
        let c = ctx(&[], 350);
        assert!(evaluate_condition("team_score >= 300", &c));
        assert!(!evaluate_condition("team_score >= 400", &c));
    }

    #[test]
    fn test_complex_condition() {
        let c1 = ctx(&["lvl_1", "lvl_2"], 0);
        assert!(evaluate_condition("(lvl_1 AND lvl_2) OR team_score >= 300", &c1));

        let c2 = ctx(&[], 350);
        assert!(evaluate_condition("(lvl_1 AND lvl_2) OR team_score >= 300", &c2));

        let c3 = ctx(&["lvl_1"], 100);
        assert!(!evaluate_condition("(lvl_1 AND lvl_2) OR team_score >= 300", &c3));
    }

    #[test]
    #[should_panic(expected = "Cycle detected")]
    fn test_cycle_detection_panics() {
        let levels = vec![
            LevelConfig {
                id: "a".into(),
                points: 100,
                unlock_condition: "b".into(),
                answers: vec![],
                dynamic_flag: false,
            },
            LevelConfig {
                id: "b".into(),
                points: 100,
                unlock_condition: "a".into(),
                answers: vec![],
                dynamic_flag: false,
            },
        ];
        validate_dag_or_panic(&levels);
    }
}

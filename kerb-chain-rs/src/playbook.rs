//! Playbook DSL — small, deterministic, no eval.
//!
//! Direct port of `kerb_chain/playbook.py`. Same YAML shape, same
//! condition grammar, same defaults. The Python and Rust runtimes can
//! load each other's playbooks without translation.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow};
use serde::{Deserialize, Serialize};

use crate::engagement::Engagement;
use crate::findings::Finding;


// ─────────────────────────────────────────────────────────────────── //
//  Schema                                                             //
// ─────────────────────────────────────────────────────────────────── //


#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct CaptureRule {
    #[serde(default)]
    pub stdout_to_file:  Option<String>,
    #[serde(default)]
    pub cred_regex:      Option<String>,
    #[serde(default)]
    pub cred_hash_regex: Option<String>,
    #[serde(default)]
    pub files_glob:      Option<String>,
    #[serde(default)]
    pub owned_marker:    Option<String>,
    #[serde(default)]
    pub owned_host:      Option<String>,
}


/// A play's `command` field is either an argv list (preferred — no
/// shell interpretation) or a single shell string (rendered then
/// shell-split with shell-words to preserve quoting).
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub enum Command {
    Argv(Vec<String>),
    Shell(String),
}


fn default_per()      -> String { "engagement".to_string() }
fn default_category() -> String { "enumeration".to_string() }
fn default_timeout()  -> u64    { 600 }


#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Play {
    pub name:        String,
    #[serde(default)]
    pub description: String,
    pub command:     Command,
    #[serde(default)]
    pub when:        String,
    #[serde(default = "default_per")]
    pub per:         String, // "engagement" or "finding"
    #[serde(default)]
    pub capture:     CaptureRule,
    #[serde(default)]
    pub on_success:  Vec<String>,
    #[serde(default)]
    pub requires_aggressive: bool,
    #[serde(default = "default_category")]
    pub category:    String,
    #[serde(default = "default_timeout")]
    pub timeout:     u64,
}


#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Playbook {
    #[serde(default)]
    pub name:        String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub plays:       Vec<Play>,
    #[serde(skip)]
    pub path:        Option<PathBuf>,
}

impl Playbook {
    pub fn from_path<P: AsRef<Path>>(path: P) -> Result<Self> {
        let p = path.as_ref();
        let text = std::fs::read_to_string(p)
            .with_context(|| format!("reading {}", p.display()))?;
        let mut pb: Playbook = serde_yaml::from_str(&text)
            .with_context(|| format!("parsing {} as YAML", p.display()))?;

        // Validate plays — fail loudly on obvious typos rather than
        // silently dropping plays at runtime.
        for (i, play) in pb.plays.iter().enumerate() {
            if play.name.is_empty() {
                return Err(anyhow!("{}: play #{} missing 'name'", p.display(), i));
            }
            match &play.command {
                Command::Argv(v)  if v.is_empty() => {
                    return Err(anyhow!(
                        "{}: play '{}' has empty argv", p.display(), play.name));
                }
                Command::Shell(s) if s.trim().is_empty() => {
                    return Err(anyhow!(
                        "{}: play '{}' has empty shell command",
                        p.display(), play.name));
                }
                _ => {}
            }
        }

        if pb.name.is_empty() {
            pb.name = p.file_stem()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_else(|| "playbook".to_string());
        }
        pb.path = Some(p.to_path_buf());
        Ok(pb)
    }

    pub fn by_name(&self, name: &str) -> Option<&Play> {
        self.plays.iter().find(|p| p.name == name)
    }
}


// ─────────────────────────────────────────────────────────────────── //
//  Condition language                                                 //
// ─────────────────────────────────────────────────────────────────── //


/// Evaluate a `when` clause. Returns `true` when:
///
/// - the expression is empty
/// - all `and`-joined sub-clauses match
/// - any `or`-joined sub-clause matches (left-associative, no parens)
///
/// Supported atoms (no eval, no exec):
///
/// ```text
/// finding.attack == 'Kerberoast'
/// finding.attack in ['DCSync (full)', 'DCSync (partial)']
/// finding.severity in ['CRITICAL', 'HIGH']
/// finding.data.encryption == 'RC4'
/// loot.has_credential
/// loot.has_credential_for finding.target
/// not loot.has_credential
/// ```
pub fn evaluate_condition(
    expr:       &str,
    finding:    Option<&Finding>,
    engagement: &Engagement,
) -> bool {
    if expr.trim().is_empty() {
        return true;
    }
    let tokens = tokenise_logical(expr);
    if tokens.is_empty() {
        return true;
    }

    let mut result = eval_clause(&tokens[0], finding, engagement);
    let mut i = 1;
    while i + 1 < tokens.len() {
        let op  = tokens[i].to_ascii_lowercase();
        let rhs = eval_clause(&tokens[i + 1], finding, engagement);
        result = match op.as_str() {
            "and" => result && rhs,
            "or"  => result || rhs,
            _     => result,  // unknown joiner — keep going, ignore
        };
        i += 2;
    }
    result
}


fn tokenise_logical(expr: &str) -> Vec<String> {
    let chars: Vec<char> = expr.chars().collect();
    let n = chars.len();
    let mut out: Vec<String> = Vec::new();
    let mut buf: String = String::new();
    let mut i = 0usize;
    let mut in_quote: Option<char> = None;

    while i < n {
        let c = chars[i];

        if let Some(q) = in_quote {
            buf.push(c);
            if c == q { in_quote = None; }
            i += 1;
            continue;
        }
        if c == '\'' || c == '"' {
            in_quote = Some(c);
            buf.push(c);
            i += 1;
            continue;
        }

        // Boundary check: only split on ` and ` / ` or ` (whitespace
        // before the keyword) so we don't break identifiers like
        // `command`. Equivalent to the Python tokeniser's `buf[-1].isspace()`
        // guard.
        let prev_is_ws = buf.chars().last().map(|c| c.is_whitespace()).unwrap_or(true);
        if prev_is_ws {
            let rest_lower: String = chars[i..].iter().collect::<String>().to_ascii_lowercase();
            if rest_lower.starts_with("and ") {
                out.push(buf.trim().to_string());
                out.push("and".to_string());
                buf.clear();
                i += 4;     // "and "
                continue;
            }
            if rest_lower.starts_with("or ") {
                out.push(buf.trim().to_string());
                out.push("or".to_string());
                buf.clear();
                i += 3;     // "or "
                continue;
            }
        }

        buf.push(c);
        i += 1;
    }

    let last = buf.trim().to_string();
    if !last.is_empty() {
        out.push(last);
    }
    out.into_iter().filter(|s| !s.is_empty()).collect()
}


fn eval_clause(clause: &str, finding: Option<&Finding>, engagement: &Engagement) -> bool {
    let c = clause.trim();
    if let Some(rest) = c.strip_prefix("not ") {
        return !eval_clause(rest, finding, engagement);
    }

    if c == "loot.has_credential" {
        return !engagement.loot.credentials.is_empty();
    }
    if let Some(rest) = c.strip_prefix("loot.has_credential_for ") {
        let target = resolve_value(rest.trim(), finding, engagement);
        return target
            .as_str()
            .map(|s| engagement.loot.has_creds_for(s))
            .unwrap_or(false);
    }

    if let Some((lhs, rhs)) = split_once_outside_quotes(c, " == ") {
        return resolve_value(lhs, finding, engagement) == parse_literal(rhs);
    }
    if let Some((lhs, rhs)) = split_once_outside_quotes(c, " != ") {
        return resolve_value(lhs, finding, engagement) != parse_literal(rhs);
    }
    if let Some((lhs, rhs)) = split_once_outside_quotes(c, " in ") {
        let lhs_v = resolve_value(lhs, finding, engagement);
        let rhs_v = parse_literal(rhs);
        if let Some(arr) = rhs_v.as_array() {
            return arr.iter().any(|v| v == &lhs_v);
        }
        return false;
    }

    // Bare identifier — truthy fallback
    matches!(resolve_value(c, finding, engagement),
             serde_json::Value::Bool(true))
}


/// Split on `sep` only when `sep` doesn't fall inside a quoted region.
/// Used so that `finding.target == 'a == b'` doesn't mis-split.
fn split_once_outside_quotes<'a>(s: &'a str, sep: &str) -> Option<(&'a str, &'a str)> {
    let bytes = s.as_bytes();
    let sep_bytes = sep.as_bytes();
    let mut in_quote: Option<u8> = None;
    let mut i = 0usize;
    while i + sep_bytes.len() <= bytes.len() {
        let b = bytes[i];
        if let Some(q) = in_quote {
            if b == q { in_quote = None; }
            i += 1;
            continue;
        }
        if b == b'\'' || b == b'"' {
            in_quote = Some(b);
            i += 1;
            continue;
        }
        if &bytes[i..i + sep_bytes.len()] == sep_bytes {
            return Some((&s[..i], &s[i + sep_bytes.len()..]));
        }
        i += 1;
    }
    None
}


fn resolve_value(
    token:      &str,
    finding:    Option<&Finding>,
    engagement: &Engagement,
) -> serde_json::Value {
    let t = token.trim();

    if let Some(rest) = t.strip_prefix("finding.") {
        let Some(f) = finding else { return serde_json::Value::Null };
        let mut node: serde_json::Value =
            serde_json::Value::Object(serde_json::Map::from_iter(f.clone()));
        for part in rest.split('.') {
            node = match node {
                serde_json::Value::Object(map) => {
                    map.get(part).cloned().unwrap_or(serde_json::Value::Null)
                }
                _ => serde_json::Value::Null,
            };
        }
        return node;
    }

    if t == "loot.credentials" {
        return serde_json::Value::Bool(!engagement.loot.credentials.is_empty());
    }

    serde_json::Value::String(t.to_string())
}


fn parse_literal(token: &str) -> serde_json::Value {
    let t = token.trim();
    if (t.starts_with('\'') && t.ends_with('\'')) || (t.starts_with('"') && t.ends_with('"')) {
        return serde_json::Value::String(t[1..t.len() - 1].to_string());
    }
    if t.starts_with('[') && t.ends_with(']') {
        let body = t[1..t.len() - 1].trim();
        if body.is_empty() {
            return serde_json::Value::Array(Vec::new());
        }
        let mut parts: Vec<String> = Vec::new();
        let mut buf = String::new();
        let mut in_q: Option<char> = None;
        for ch in body.chars() {
            if let Some(q) = in_q {
                buf.push(ch);
                if ch == q { in_q = None; }
                continue;
            }
            if ch == '\'' || ch == '"' {
                in_q = Some(ch);
                buf.push(ch);
                continue;
            }
            if ch == ',' {
                parts.push(buf.trim().to_string());
                buf.clear();
                continue;
            }
            buf.push(ch);
        }
        if !buf.is_empty() { parts.push(buf.trim().to_string()); }
        return serde_json::Value::Array(parts.into_iter().map(|p| parse_literal(&p)).collect());
    }
    if let Ok(n) = t.parse::<i64>() { return serde_json::Value::from(n); }
    if let Ok(f) = t.parse::<f64>() { return serde_json::Value::from(f); }

    // Bare identifier — treat as a string.
    serde_json::Value::String(t.to_string())
}

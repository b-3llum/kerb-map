//! Load kerb-map's JSON output into a normalised list of findings.
//!
//! Same forgiving shape detection as the Python loader: prefers
//! `targets`, falls back to `findings`, accepts a bare list. Anything
//! else returns a clear error rather than silently producing zero plays.

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{Context, Result, anyhow};
use serde_json::Value;

/// One ranked attack-surface item produced by kerb-map. We keep it as a
/// loose `serde_json::Value` rather than a fully-typed struct so that
/// new finding fields the Python scanner adds don't require a Rust
/// rebuild — the orchestrator only reaches into specific keys.
pub type Finding = serde_json::Map<String, Value>;

/// Read a kerb-map JSON file and return its findings list.
pub fn load_findings<P: AsRef<Path>>(path: P) -> Result<Vec<Finding>> {
    let path = path.as_ref();
    let bytes = std::fs::read(path)
        .with_context(|| format!("opening {}", path.display()))?;
    let raw: Value = serde_json::from_slice(&bytes)
        .with_context(|| format!("parsing {} as JSON", path.display()))?;
    extract_findings(raw).map_err(|e| anyhow!("{}: {}", path.display(), e))
}

fn extract_findings(value: Value) -> Result<Vec<Finding>> {
    match value {
        Value::Array(items) => Ok(into_objects(items)),
        Value::Object(mut map) => {
            // Stash the document's top-level `meta` block (domain, dc_ip,
            // etc.) into the first finding under `__meta__` so the
            // Engagement constructor can see it without an extra
            // out-of-band channel. Mirrors the Python loader's contract.
            let meta = map.remove("meta");
            let mut items = if let Some(Value::Array(items)) = map.remove("targets") {
                into_objects(items)
            } else if let Some(Value::Array(items)) = map.remove("findings") {
                into_objects(items)
            } else {
                return Err(anyhow!(
                    "unrecognised kerb-map JSON shape — expected an object with \
                     a 'targets' or 'findings' key, or a bare list of findings"
                ));
            };
            if let (Some(meta_v), Some(first)) = (meta, items.first_mut()) {
                first.insert("__meta__".to_string(), meta_v);
            }
            Ok(items)
        }
        _ => Err(anyhow!("expected JSON object or array at top level")),
    }
}

fn into_objects(items: Vec<Value>) -> Vec<Finding> {
    items
        .into_iter()
        .filter_map(|v| match v {
            Value::Object(m) => Some(m),
            _ => None,
        })
        .collect()
}

/// Group findings by their `attack` field — handy for `kerb-chain show`.
pub fn index_by_attack(findings: &[Finding]) -> BTreeMap<String, Vec<&Finding>> {
    let mut out: BTreeMap<String, Vec<&Finding>> = BTreeMap::new();
    for f in findings {
        let attack = f
            .get("attack")
            .and_then(|v| v.as_str())
            .unwrap_or("<unknown>")
            .to_string();
        out.entry(attack).or_default().push(f);
    }
    out
}

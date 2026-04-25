//! Engagement state — the in-memory graph kerb-chain walks.
//!
//! Direct port of `kerb_chain/engagement.py`. The serialised
//! `journal.json` format is byte-compatible with the Python version
//! (verified by integration test), so operators can run either runtime
//! against the same engagement directory and the history interleaves.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Result, anyhow};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::findings::Finding;


// ─────────────────────────────────────────────────────────────────── //
//  Loot                                                               //
// ─────────────────────────────────────────────────────────────────── //


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Credential {
    pub username: String,
    pub domain:   String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nt_hash:  Option<String>,
    #[serde(default)]
    pub source:   String,
    #[serde(default)]
    pub obtained_at: String,
}

impl Credential {
    pub fn new(username: impl Into<String>, domain: impl Into<String>) -> Self {
        Self {
            username:    username.into(),
            domain:      domain.into(),
            password:    None,
            nt_hash:     None,
            source:      "operator".to_string(),
            obtained_at: now_iso(),
        }
    }

    pub fn with_password(mut self, pw: impl Into<String>) -> Self {
        self.password = Some(pw.into());
        self
    }

    pub fn with_hash(mut self, nt_hash: impl Into<String>) -> Self {
        self.nt_hash = Some(nt_hash.into());
        self
    }

    pub fn with_source(mut self, source: impl Into<String>) -> Self {
        self.source = source.into();
        self
    }

    pub fn validate(&self) -> Result<()> {
        if self.password.is_none() && self.nt_hash.is_none() {
            return Err(anyhow!("Credential needs at least one of password / nt_hash"));
        }
        Ok(())
    }

    pub fn upn(&self) -> String {
        format!("{}@{}", self.username, self.domain)
    }
}


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ticket {
    pub principal:   String,
    pub path:        PathBuf,
    pub kind:        String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub spn:         Option<String>,
    #[serde(default)]
    pub source:      String,
    #[serde(default)]
    pub obtained_at: String,
}


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Certificate {
    pub subject:   String,
    pub pfx_path:  PathBuf,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pfx_pass:  Option<String>,
    #[serde(default)]
    pub source:    String,
    #[serde(default)]
    pub obtained_at: String,
}


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OwnedHost {
    pub name:        String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip:          Option<String>,
    #[serde(default)]
    pub via_play:    String,
    #[serde(default)]
    pub obtained_at: String,
    #[serde(default)]
    pub notes:       String,
}


#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Loot {
    #[serde(default)]
    pub credentials:  Vec<Credential>,
    #[serde(default)]
    pub tickets:      Vec<Ticket>,
    #[serde(default)]
    pub certificates: Vec<Certificate>,
    #[serde(default)]
    pub owned_hosts:  Vec<OwnedHost>,
    #[serde(default)]
    pub files:        BTreeMap<String, PathBuf>,
}

impl Loot {
    pub fn has_creds_for(&self, username: &str) -> bool {
        let lc = username.to_ascii_lowercase();
        self.credentials.iter().any(|c| c.username.to_ascii_lowercase() == lc)
    }

    /// Newest credential, optionally filtered by username. Used by the
    /// default `{{operator_user}}` / `{{operator_pass}}` placeholders.
    pub fn best_cred(&self, username: Option<&str>) -> Option<&Credential> {
        self.credentials
            .iter()
            .rev()
            .find(|c| match username {
                None    => true,
                Some(u) => c.username.eq_ignore_ascii_case(u),
            })
    }
}


// ─────────────────────────────────────────────────────────────────── //
//  Engagement + history                                               //
// ─────────────────────────────────────────────────────────────────── //


#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PlayRecord {
    pub play:        String,
    #[serde(default)]
    pub command:     Vec<String>,
    pub started_at:  String,
    #[serde(default)]
    pub finished_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit_code:   Option<i32>,
    #[serde(default)]
    pub stdout:      String,
    #[serde(default)]
    pub stderr:      String,
    #[serde(default)]
    pub loot_added:  BTreeMap<String, usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub skipped:     Option<String>,
}


#[derive(Debug)]
pub struct Engagement {
    pub findings:   Vec<Finding>,
    pub domain:     String,
    pub dc_ip:      String,
    pub base_dn:    String,
    pub domain_sid: Option<String>,
    pub operator:   Option<Credential>,
    pub loot:       Loot,
    pub history:    Vec<PlayRecord>,
    pub run_dir:    PathBuf,
    pub dry_run:    bool,
}

#[derive(Debug, Default)]
pub struct EngagementOpts {
    pub domain:     Option<String>,
    pub dc_ip:      Option<String>,
    pub base_dn:    Option<String>,
    pub domain_sid: Option<String>,
    pub operator:   Option<Credential>,
    pub run_dir:    Option<PathBuf>,
    pub dry_run:    bool,
}

impl Engagement {
    /// Build an engagement from a findings list. Mirrors
    /// `Engagement.from_findings(...)` on the Python side: pulls
    /// `domain` / `dc_ip` from the first finding's `__meta__` block
    /// when not explicitly provided, derives `domain_sid` from any
    /// finding that carries it, materialises `run_dir` on disk, and
    /// seeds the loot with the operator credential.
    pub fn from_findings(findings: Vec<Finding>, opts: EngagementOpts) -> Result<Self> {
        let meta = findings
            .first()
            .and_then(|f| f.get("__meta__"))
            .and_then(|v| v.as_object())
            .cloned()
            .unwrap_or_default();

        let pick_str = |opt: Option<String>, key: &str| -> String {
            opt.unwrap_or_else(|| {
                meta.get(key)
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
                    .unwrap_or_default()
            })
        };

        let domain  = pick_str(opts.domain, "domain");
        let dc_ip   = pick_str(opts.dc_ip,  "dc_ip");
        let base_dn = pick_str(opts.base_dn, "base_dn");

        // domain_sid: prefer explicit > meta > scan through findings.data
        let mut domain_sid = opts.domain_sid.or_else(|| {
            meta.get("domain_sid").and_then(|v| v.as_str()).map(|s| s.to_string())
        });
        if domain_sid.is_none() {
            for f in &findings {
                if let Some(ds) = f
                    .get("data")
                    .and_then(|v| v.as_object())
                    .and_then(|d| d.get("domain_sid"))
                    .and_then(|v| v.as_str())
                {
                    domain_sid = Some(ds.to_string());
                    break;
                }
            }
        }

        let run_dir = opts.run_dir.unwrap_or_else(|| default_run_dir(&domain));
        std::fs::create_dir_all(&run_dir)?;

        let mut loot = Loot::default();
        if let Some(cred) = opts.operator.clone() {
            cred.validate()?;
            loot.credentials.push(cred);
        }

        Ok(Self {
            findings,
            domain,
            dc_ip,
            base_dn,
            domain_sid,
            operator: opts.operator,
            loot,
            history: Vec::new(),
            run_dir,
            dry_run: opts.dry_run,
        })
    }

    /// Substitute `{{...}}` placeholders into a template.
    /// Resolves the engagement context plus per-finding fields
    /// (`finding.target`, `finding.attack`, `finding.severity`,
    /// `finding.data.*`). Unknown placeholders are left in place so
    /// operators notice typos rather than silently getting empty strings.
    pub fn render(&self, template: &str, finding: Option<&Finding>) -> String {
        let ctx = self.render_context(finding);
        let mut out = template.to_string();
        for _ in 0..4 {
            let prev = out.clone();
            for (key, value) in &ctx {
                let needle = format!("{{{{{key}}}}}");
                if out.contains(&needle) {
                    out = out.replace(&needle, value);
                }
            }
            if out == prev {
                break;
            }
        }
        out
    }

    fn render_context(&self, finding: Option<&Finding>) -> BTreeMap<String, String> {
        let mut ctx: BTreeMap<String, String> = BTreeMap::new();
        ctx.insert("domain".into(),     self.domain.clone());
        ctx.insert("dc_ip".into(),      self.dc_ip.clone());
        ctx.insert("base_dn".into(),    self.base_dn.clone());
        ctx.insert("domain_sid".into(), self.domain_sid.clone().unwrap_or_default());
        ctx.insert("run_dir".into(),    self.run_dir.display().to_string());

        let op = self.loot.best_cred(None).or(self.operator.as_ref());
        ctx.insert("operator_user".into(), op.map(|c| c.username.clone()).unwrap_or_default());
        ctx.insert("operator_pass".into(), op.and_then(|c| c.password.clone()).unwrap_or_default());
        ctx.insert("operator_hash".into(), op.and_then(|c| c.nt_hash.clone()).unwrap_or_default());

        if let Some(f) = finding {
            if let Some(v) = f.get("target").and_then(|v| v.as_str()) {
                ctx.insert("finding.target".into(), v.to_string());
            }
            if let Some(v) = f.get("attack").and_then(|v| v.as_str()) {
                ctx.insert("finding.attack".into(), v.to_string());
            }
            if let Some(v) = f.get("severity").and_then(|v| v.as_str()) {
                ctx.insert("finding.severity".into(), v.to_string());
            }
            if let Some(data) = f.get("data").and_then(|v| v.as_object()) {
                for (k, v) in data {
                    ctx.insert(format!("finding.data.{k}"), value_to_template_string(v));
                }
            }
        }
        ctx
    }

    /// Write the loot + history to `run_dir/journal.json`. Matches the
    /// Python writer field-for-field; verified by the parity test.
    pub fn write_journal(&self) -> Result<PathBuf> {
        let path = self.run_dir.join("journal.json");

        #[derive(Serialize)]
        struct LootPayload<'a> {
            credentials:  &'a [Credential],
            tickets:      &'a [Ticket],
            certificates: &'a [Certificate],
            owned_hosts:  &'a [OwnedHost],
            files:        BTreeMap<String, String>,
        }
        #[derive(Serialize)]
        struct Payload<'a> {
            domain:     &'a str,
            dc_ip:      &'a str,
            #[serde(skip_serializing_if = "Option::is_none")]
            domain_sid: Option<&'a str>,
            loot:       LootPayload<'a>,
            history:    &'a [PlayRecord],
        }

        let files_str: BTreeMap<String, String> = self
            .loot
            .files
            .iter()
            .map(|(k, v)| (k.clone(), v.display().to_string()))
            .collect();

        let payload = Payload {
            domain: &self.domain,
            dc_ip:  &self.dc_ip,
            domain_sid: self.domain_sid.as_deref(),
            loot: LootPayload {
                credentials:  &self.loot.credentials,
                tickets:      &self.loot.tickets,
                certificates: &self.loot.certificates,
                owned_hosts:  &self.loot.owned_hosts,
                files:        files_str,
            },
            history: &self.history,
        };
        let serialized = serde_json::to_string_pretty(&payload)?;
        std::fs::write(&path, serialized)?;
        Ok(path)
    }
}


// ─────────────────────────────────────────────────────────────────── //
//  Helpers                                                            //
// ─────────────────────────────────────────────────────────────────── //


fn now_iso() -> String {
    let now: DateTime<Utc> = Utc::now();
    now.format("%Y-%m-%dT%H:%M:%S+00:00").to_string()
}


fn default_run_dir(domain: &str) -> PathBuf {
    let ts = Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
    let domain_part = if domain.is_empty() {
        "engagement".to_string()
    } else {
        domain.replace('.', "_")
    };
    let base: PathBuf = std::env::var_os("KERB_CHAIN_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            std::env::var_os("HOME")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("."))
                .join(".kerb-chain")
        });
    base.join("runs").join(format!("{domain_part}_{ts}"))
}


fn value_to_template_string(v: &serde_json::Value) -> String {
    match v {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Null      => String::new(),
        other                        => other.to_string(),
    }
}


// ─────────────────────────────────────────────────────────────────── //
//  Path helper visible to runner                                      //
// ─────────────────────────────────────────────────────────────────── //


/// Resolve a (possibly templated, possibly relative) path against the
/// engagement's `run_dir`. Used by capture rules for file output.
pub fn resolve_under_run_dir(run_dir: &Path, candidate: impl AsRef<Path>) -> PathBuf {
    let p = candidate.as_ref();
    if p.is_absolute() {
        p.to_path_buf()
    } else {
        run_dir.join(p)
    }
}

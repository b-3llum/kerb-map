//! Integration tests for the Rust kerb-chain port.
//!
//! Mirrors the Python test_kerb_chain.py coverage so the two runtimes
//! stay behaviourally interchangeable.

use std::collections::BTreeMap;
use std::path::PathBuf;

use serde_json::{Value, json};
use tempfile::TempDir;

use kerb_chain::{
    Credential, Engagement, Playbook, Runner,
    findings::{index_by_attack, load_findings},
    playbook::evaluate_condition,
    engagement::EngagementOpts,
};


// ─────────────────────────────────────────────────────────────────── //
//  Fixtures                                                           //
// ─────────────────────────────────────────────────────────────────── //


fn engagement_with(findings: Vec<serde_json::Map<String, Value>>) -> (TempDir, Engagement) {
    let tmp = TempDir::new().unwrap();
    let cred = Credential::new("op", "corp.local").with_password("Pa$$w0rd");
    let opts = EngagementOpts {
        domain:     Some("corp.local".into()),
        dc_ip:      Some("10.0.0.1".into()),
        base_dn:    Some("DC=corp,DC=local".into()),
        domain_sid: Some("S-1-5-21-1-2-3".into()),
        operator:   Some(cred),
        run_dir:    Some(tmp.path().to_path_buf()),
        dry_run:    true,
    };
    let eng = Engagement::from_findings(findings, opts).unwrap();
    (tmp, eng)
}


fn obj(pairs: &[(&str, Value)]) -> serde_json::Map<String, Value> {
    let mut m = serde_json::Map::new();
    for (k, v) in pairs {
        m.insert((*k).to_string(), v.clone());
    }
    m
}


fn write_json(dir: &TempDir, name: &str, value: Value) -> PathBuf {
    let p = dir.path().join(name);
    std::fs::write(&p, serde_json::to_string(&value).unwrap()).unwrap();
    p
}


// ─────────────────────────────────────────────────────────────────── //
//  load_findings                                                      //
// ─────────────────────────────────────────────────────────────────── //


#[test]
fn load_findings_handles_full_data_shape() {
    let tmp = TempDir::new().unwrap();
    let p = write_json(&tmp, "scan.json", json!({
        "meta":    { "domain": "corp.local" },
        "targets": [{ "target": "svc_sql", "attack": "Kerberoast" }],
    }));
    let f = load_findings(&p).unwrap();
    assert_eq!(f.len(), 1);
    assert_eq!(f[0].get("target").unwrap().as_str(), Some("svc_sql"));
}


#[test]
fn load_findings_handles_bare_list() {
    let tmp = TempDir::new().unwrap();
    let p = write_json(&tmp, "list.json", json!([
        { "target": "x", "attack": "y" }
    ]));
    let f = load_findings(&p).unwrap();
    assert_eq!(f.len(), 1);
}


#[test]
fn load_findings_rejects_unknown_shape() {
    let tmp = TempDir::new().unwrap();
    let p = write_json(&tmp, "bad.json", json!({ "random": [1, 2, 3] }));
    let err = load_findings(&p).unwrap_err();
    assert!(err.to_string().contains("unrecognised"));
}


#[test]
fn index_by_attack_groups_correctly() {
    let fs = vec![
        obj(&[("attack", json!("Kerberoast")), ("target", json!("a"))]),
        obj(&[("attack", json!("Kerberoast")), ("target", json!("b"))]),
        obj(&[("attack", json!("AS-REP Roast")), ("target", json!("c"))]),
    ];
    let idx = index_by_attack(&fs);
    assert_eq!(idx["Kerberoast"].len(),    2);
    assert_eq!(idx["AS-REP Roast"].len(), 1);
}


// ─────────────────────────────────────────────────────────────────── //
//  Engagement / placeholder rendering                                 //
// ─────────────────────────────────────────────────────────────────── //


#[test]
fn render_resolves_engagement_placeholders() {
    let (_tmp, eng) = engagement_with(Vec::new());
    let out = eng.render("{{operator_user}}@{{domain}} on {{dc_ip}}", None);
    assert_eq!(out, "op@corp.local on 10.0.0.1");
}


#[test]
fn render_resolves_finding_placeholders() {
    let (_tmp, eng) = engagement_with(Vec::new());
    let f = obj(&[("target", json!("svc_sql")), ("attack", json!("Kerberoast"))]);
    let out = eng.render("hit {{finding.target}} ({{finding.attack}})", Some(&f));
    assert_eq!(out, "hit svc_sql (Kerberoast)");
}


#[test]
fn render_resolves_finding_data_fields() {
    let (_tmp, eng) = engagement_with(Vec::new());
    let f = obj(&[("data", json!({ "principal_sid": "S-1-5-21-1-2-3-1234" }))]);
    let out = eng.render("sid={{finding.data.principal_sid}}", Some(&f));
    assert!(out.contains("S-1-5-21-1-2-3-1234"));
}


#[test]
fn render_leaves_unknown_placeholder_in_place() {
    let (_tmp, eng) = engagement_with(Vec::new());
    let out = eng.render("hi {{not_a_real_var}}", None);
    assert!(out.contains("{{not_a_real_var}}"));
}


#[test]
fn credential_validate_requires_password_or_hash() {
    let bare = Credential::new("x", "y");
    assert!(bare.validate().is_err());
    assert!(bare.clone().with_password("z").validate().is_ok());
    assert!(bare.with_hash("h").validate().is_ok());
}


// ─────────────────────────────────────────────────────────────────── //
//  Condition language                                                 //
// ─────────────────────────────────────────────────────────────────── //


#[test]
fn condition_empty_is_true() {
    let (_tmp, eng) = engagement_with(Vec::new());
    assert!(evaluate_condition("", None, &eng));
}


#[test]
fn condition_attack_equals() {
    let (_tmp, eng) = engagement_with(Vec::new());
    let f = obj(&[("attack", json!("Kerberoast"))]);
    assert!( evaluate_condition("finding.attack == 'Kerberoast'", Some(&f), &eng));
    let g = obj(&[("attack", json!("AS-REP Roast"))]);
    assert!(!evaluate_condition("finding.attack == 'Kerberoast'", Some(&g), &eng));
}


#[test]
fn condition_attack_in_list() {
    let (_tmp, eng) = engagement_with(Vec::new());
    let f = obj(&[("attack", json!("DCSync (full)"))]);
    assert!(evaluate_condition(
        "finding.attack in ['DCSync (full)', 'DCSync (partial)']",
        Some(&f), &eng,
    ));
}


#[test]
fn condition_loot_has_credential() {
    let (_tmp, eng) = engagement_with(Vec::new());
    assert!(evaluate_condition("loot.has_credential", None, &eng));
}


#[test]
fn condition_negation() {
    let (_tmp, mut eng) = engagement_with(Vec::new());
    eng.loot.credentials.clear();
    assert!(evaluate_condition("not loot.has_credential", None, &eng));
}


#[test]
fn condition_and_combination() {
    let (_tmp, eng) = engagement_with(Vec::new());
    let f = obj(&[
        ("attack", json!("Kerberoast")),
        ("data",   json!({ "encryption": "RC4" })),
    ]);
    assert!(evaluate_condition(
        "finding.attack == 'Kerberoast' and finding.data.encryption == 'RC4'",
        Some(&f), &eng,
    ));
    assert!(!evaluate_condition(
        "finding.attack == 'Kerberoast' and finding.data.encryption == 'AES'",
        Some(&f), &eng,
    ));
}


#[test]
fn condition_or_combination() {
    let (_tmp, eng) = engagement_with(Vec::new());
    let f = obj(&[("attack", json!("Kerberoast"))]);
    assert!(evaluate_condition(
        "finding.attack == 'Kerberoast' or finding.attack == 'AS-REP Roast'",
        Some(&f), &eng,
    ));
}


#[test]
fn condition_quoted_literal_contains_logical_keyword() {
    let (_tmp, eng) = engagement_with(Vec::new());
    let f = obj(&[("target", json!("svc and stuff"))]);
    assert!(evaluate_condition(
        "finding.target == 'svc and stuff'", Some(&f), &eng,
    ));
}


// ─────────────────────────────────────────────────────────────────── //
//  Playbook loading                                                   //
// ─────────────────────────────────────────────────────────────────── //


#[test]
fn playbook_parses_minimal_yaml() {
    let tmp = TempDir::new().unwrap();
    let p = tmp.path().join("tiny.yaml");
    std::fs::write(&p, "name: test\nplays:\n  - name: hello\n    command: ['echo', 'hi']\n").unwrap();
    let pb = Playbook::from_path(&p).unwrap();
    assert_eq!(pb.name, "test");
    assert_eq!(pb.plays.len(), 1);
}


#[test]
fn playbook_rejects_play_with_empty_argv() {
    let tmp = TempDir::new().unwrap();
    let p = tmp.path().join("bad.yaml");
    std::fs::write(&p, "name: bad\nplays:\n  - name: x\n    command: []\n").unwrap();
    let err = Playbook::from_path(&p).unwrap_err();
    assert!(err.to_string().contains("empty argv"));
}


#[test]
fn bundled_python_playbook_loads_clean() {
    // The bundled standard.yaml lives alongside the Python package; the
    // Rust port is supposed to consume it unchanged. Walk up looking
    // for it so the test passes whether you `cargo test` from the
    // crate dir or the repo root.
    let candidates = [
        PathBuf::from("../kerb_chain/playbooks/standard.yaml"),
        PathBuf::from("kerb_chain/playbooks/standard.yaml"),
    ];
    let path = candidates.iter().find(|p| p.exists())
        .expect("bundled standard.yaml missing — build layout changed?");
    let pb = Playbook::from_path(path).unwrap();
    assert!(!pb.plays.is_empty());
    for play in &pb.plays {
        assert!(!play.name.is_empty());
    }
}


// ─────────────────────────────────────────────────────────────────── //
//  Runner                                                             //
// ─────────────────────────────────────────────────────────────────── //


#[test]
fn runner_dry_run_does_not_subprocess() {
    let tmp = TempDir::new().unwrap();
    let yaml = tmp.path().join("p.yaml");
    std::fs::write(&yaml,
        "name: t\nplays:\n  - name: echo\n    command: ['echo', '{{operator_user}}']\n").unwrap();
    let pb = Playbook::from_path(&yaml).unwrap();
    let (_t2, mut eng) = engagement_with(Vec::new());
    Runner::new(&pb, &mut eng).verbose(false).run().unwrap();
    let last = eng.history.last().unwrap();
    assert_eq!(last.skipped.as_deref(), Some("dry-run"));
    assert_eq!(last.command, vec!["echo", "op"]);
}


#[test]
fn runner_skips_aggressive_play_without_flag() {
    let tmp = TempDir::new().unwrap();
    let yaml = tmp.path().join("p.yaml");
    std::fs::write(&yaml,
        "name: t\nplays:\n  - name: loud\n    command: ['true']\n    requires_aggressive: true\n").unwrap();
    let pb = Playbook::from_path(&yaml).unwrap();
    let (_t2, mut eng) = engagement_with(Vec::new());
    eng.dry_run = false;
    Runner::new(&pb, &mut eng).verbose(false).run().unwrap();
    assert_eq!(eng.history.last().unwrap().skipped.as_deref(),
               Some("requires --aggressive"));
}


#[test]
fn runner_executes_plain_command_and_records_exit() {
    let tmp = TempDir::new().unwrap();
    let yaml = tmp.path().join("p.yaml");
    std::fs::write(&yaml, "name: t\nplays:\n  - name: t\n    command: ['true']\n").unwrap();
    let pb = Playbook::from_path(&yaml).unwrap();
    let (_t2, mut eng) = engagement_with(Vec::new());
    eng.dry_run = false;
    Runner::new(&pb, &mut eng).verbose(false).run().unwrap();
    let last = eng.history.last().unwrap();
    assert_eq!(last.exit_code, Some(0));
    assert!(last.skipped.is_none());
}


#[test]
fn runner_records_command_not_found() {
    let tmp = TempDir::new().unwrap();
    let yaml = tmp.path().join("p.yaml");
    std::fs::write(&yaml,
        "name: t\nplays:\n  - name: ghost\n    command: ['definitely-not-on-path']\n").unwrap();
    let pb = Playbook::from_path(&yaml).unwrap();
    let (_t2, mut eng) = engagement_with(Vec::new());
    eng.dry_run = false;
    Runner::new(&pb, &mut eng).verbose(false).run().unwrap();
    let skip = eng.history.last().unwrap().skipped.clone().unwrap_or_default();
    assert!(skip.starts_with("command not found"), "got: {skip}");
}


#[test]
fn runner_captures_credentials_via_regex() {
    let tmp = TempDir::new().unwrap();
    let yaml = tmp.path().join("p.yaml");
    std::fs::write(&yaml,
        "name: t\nplays:\n  - name: fake-crack\n    command: ['echo', 'alice:Spring2026!']\n    capture:\n      cred_regex: '^(?P<user>[^:]+):(?P<pass>.+)$'\n").unwrap();
    let pb = Playbook::from_path(&yaml).unwrap();
    let (_t2, mut eng) = engagement_with(Vec::new());
    eng.dry_run = false;
    Runner::new(&pb, &mut eng).verbose(false).run().unwrap();
    let captured: Vec<&Credential> =
        eng.loot.credentials.iter().filter(|c| c.username == "alice").collect();
    assert_eq!(captured.len(), 1);
    assert_eq!(captured[0].password.as_deref(), Some("Spring2026!"));
    assert!(captured[0].source.starts_with("capture:"));
}


#[test]
fn runner_per_finding_expands_to_one_call_per_match() {
    let tmp = TempDir::new().unwrap();
    let yaml = tmp.path().join("p.yaml");
    std::fs::write(&yaml,
        "name: t\nplays:\n  - name: kerberoast\n    command: ['echo', '{{finding.target}}']\n    when: \"finding.attack == 'Kerberoast'\"\n    per: finding\n").unwrap();
    let pb = Playbook::from_path(&yaml).unwrap();
    let findings = vec![
        obj(&[("target", json!("svc1")), ("attack", json!("Kerberoast"))]),
        obj(&[("target", json!("svc2")), ("attack", json!("Kerberoast"))]),
        obj(&[("target", json!("u1")),   ("attack", json!("AS-REP Roast"))]),
    ];
    let (_t2, mut eng) = engagement_with(findings);
    Runner::new(&pb, &mut eng).verbose(false).run().unwrap();
    let rendered: Vec<String> = eng.history.iter()
        .filter(|r| r.skipped.as_deref() == Some("dry-run") && r.command.len() >= 2)
        .map(|r| r.command[1].clone())
        .collect();
    assert_eq!(rendered, vec!["svc1".to_string(), "svc2".to_string()]);
}


#[test]
fn runner_on_success_enqueues_each_follow_up_once() {
    let tmp = TempDir::new().unwrap();
    let yaml = tmp.path().join("p.yaml");
    std::fs::write(&yaml,
        "name: t\nplays:\n  - name: a\n    command: ['true']\n    on_success: [b]\n  - name: b\n    command: ['true']\n").unwrap();
    let pb = Playbook::from_path(&yaml).unwrap();
    let (_t2, mut eng) = engagement_with(Vec::new());
    eng.dry_run = false;
    Runner::new(&pb, &mut eng).verbose(false).run().unwrap();
    let b_count: usize = eng.history.iter().filter(|r| r.play == "b").count();
    assert_eq!(b_count, 1, "play b ran more than once");
}


#[test]
fn runner_writes_journal() {
    let tmp = TempDir::new().unwrap();
    let yaml = tmp.path().join("p.yaml");
    std::fs::write(&yaml, "name: t\nplays:\n  - name: t\n    command: ['true']\n").unwrap();
    let pb = Playbook::from_path(&yaml).unwrap();
    let (_t2, mut eng) = engagement_with(Vec::new());
    Runner::new(&pb, &mut eng).verbose(false).run().unwrap();
    let path = eng.write_journal().unwrap();
    assert!(path.exists());
    let parsed: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    assert_eq!(parsed["domain"].as_str(), Some("corp.local"));
    assert!(parsed["history"].as_array().unwrap().len() >= 1);
}


// ─────────────────────────────────────────────────────────────────── //
//  Journal parity with Python                                         //
// ─────────────────────────────────────────────────────────────────── //


#[test]
fn journal_top_level_keys_match_python() {
    // The Python writer emits exactly these keys; if we drift, two
    // operators using different runtimes against the same engagement
    // dir will produce different shapes. Catch that here.
    let (_tmp, mut eng) = engagement_with(Vec::new());
    let p = eng.write_journal().unwrap();
    let parsed: Value = serde_json::from_str(&std::fs::read_to_string(&p).unwrap()).unwrap();
    let obj = parsed.as_object().unwrap();
    let mut keys: Vec<&String> = obj.keys().collect();
    keys.sort();
    assert_eq!(keys, vec!["dc_ip", "domain", "domain_sid", "history", "loot"]);

    let loot = obj["loot"].as_object().unwrap();
    let mut loot_keys: Vec<&String> = loot.keys().collect();
    loot_keys.sort();
    assert_eq!(
        loot_keys,
        vec!["certificates", "credentials", "files", "owned_hosts", "tickets"],
    );
}


#[test]
fn loot_has_creds_for_is_case_insensitive() {
    let mut eng = engagement_with(Vec::new()).1;
    eng.loot.credentials.push(
        Credential::new("Alice", "corp.local").with_password("x")
    );
    assert!(eng.loot.has_creds_for("alice"));
    assert!(eng.loot.has_creds_for("ALICE"));
    assert!(!eng.loot.has_creds_for("bob"));
}


// touch the unused import warning
#[allow(dead_code)]
fn _silence_unused(_: BTreeMap<String, String>) {}

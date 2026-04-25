"""kerb-chain — orchestrator MVP tests.

Covers: findings loading, condition language, placeholder rendering,
runner with mocked subprocess, dry-run behaviour, capture rule wiring.
The bundled standard.yaml is exercised at the parse + show level.
"""

import json
from unittest.mock import patch

import pytest

from kerb_chain.engagement import Credential, Engagement
from kerb_chain.findings import index_by_attack, load_findings
from kerb_chain.playbook import (
    CaptureRule,
    Play,
    Playbook,
    evaluate_condition,
)
from kerb_chain.runner import Runner

# ────────────────────────────────────────────────────────────────────── #
#  load_findings                                                         #
# ────────────────────────────────────────────────────────────────────── #


def test_load_findings_handles_full_data_shape(tmp_path):
    p = tmp_path / "scan.json"
    p.write_text(json.dumps({
        "meta": {"domain": "corp.local"},
        "targets": [{"target": "svc_sql", "attack": "Kerberoast"}],
    }))
    findings = load_findings(p)
    assert len(findings) == 1
    # The top-level meta block is stashed onto the first finding under
    # __meta__ so Engagement.from_findings can resolve domain / dc_ip
    # without an out-of-band channel. (Same contract on the Rust side.)
    assert findings[0]["target"] == "svc_sql"
    assert findings[0]["attack"] == "Kerberoast"
    assert findings[0]["__meta__"] == {"domain": "corp.local"}


def test_load_findings_handles_bare_list(tmp_path):
    p = tmp_path / "list.json"
    p.write_text(json.dumps([{"target": "x", "attack": "y"}]))
    assert load_findings(p) == [{"target": "x", "attack": "y"}]


def test_load_findings_rejects_unknown_shape(tmp_path):
    p = tmp_path / "bad.json"
    p.write_text(json.dumps({"random": [1, 2, 3]}))
    with pytest.raises(ValueError, match="unrecognised"):
        load_findings(p)


def test_index_by_attack_groups_correctly():
    fs = [
        {"attack": "Kerberoast", "target": "a"},
        {"attack": "Kerberoast", "target": "b"},
        {"attack": "AS-REP Roast", "target": "c"},
    ]
    out = index_by_attack(fs)
    assert len(out["Kerberoast"]) == 2
    assert len(out["AS-REP Roast"]) == 1


# ────────────────────────────────────────────────────────────────────── #
#  Engagement / placeholder rendering                                    #
# ────────────────────────────────────────────────────────────────────── #


def _engagement(*, dry_run=True, **overrides):
    findings = overrides.pop("findings", [])
    op = overrides.pop("operator_cred", Credential(
        username="op", domain="corp.local", password="Pa$$w0rd"))
    return Engagement.from_findings(
        findings, domain="corp.local", dc_ip="10.0.0.1",
        base_dn="DC=corp,DC=local", domain_sid="S-1-5-21-1-2-3",
        operator_cred=op, dry_run=dry_run, **overrides,
    )


def test_render_resolves_engagement_placeholders():
    eng = _engagement()
    out = eng.render("{{operator_user}}@{{domain}} on {{dc_ip}}")
    assert out == "op@corp.local on 10.0.0.1"


def test_render_resolves_finding_placeholders():
    eng = _engagement()
    out = eng.render("hit {{finding.target}} ({{finding.attack}})",
                     finding={"target": "svc_sql", "attack": "Kerberoast"})
    assert out == "hit svc_sql (Kerberoast)"


def test_render_resolves_finding_data_fields():
    eng = _engagement()
    out = eng.render("sid={{finding.data.principal_sid}}",
                     finding={"data": {"principal_sid": "S-1-5-21-1-2-3-1234"}})
    assert "S-1-5-21-1-2-3-1234" in out


def test_render_leaves_unknown_placeholder_in_place():
    """Operators should notice typos rather than getting silent empty strings."""
    eng = _engagement()
    assert "{{not_a_real_var}}" in eng.render("hi {{not_a_real_var}}")


def test_credential_requires_password_or_hash():
    with pytest.raises(ValueError):
        Credential(username="x", domain="y")


def test_credential_records_obtained_at_automatically():
    c = Credential(username="x", domain="y", password="z")
    assert c.obtained_at  # ISO timestamp string


# ────────────────────────────────────────────────────────────────────── #
#  Condition language                                                    #
# ────────────────────────────────────────────────────────────────────── #


def test_condition_empty_is_true():
    assert evaluate_condition("", finding=None, engagement=_engagement())


def test_condition_attack_equals():
    eng = _engagement()
    assert evaluate_condition(
        "finding.attack == 'Kerberoast'",
        finding={"attack": "Kerberoast"},
        engagement=eng,
    )
    assert not evaluate_condition(
        "finding.attack == 'Kerberoast'",
        finding={"attack": "AS-REP Roast"},
        engagement=eng,
    )


def test_condition_attack_in_list():
    eng = _engagement()
    assert evaluate_condition(
        "finding.attack in ['DCSync (full)', 'DCSync (partial)']",
        finding={"attack": "DCSync (full)"},
        engagement=eng,
    )


def test_condition_loot_has_credential():
    eng = _engagement()
    assert evaluate_condition("loot.has_credential", finding=None, engagement=eng)


def test_condition_negation():
    eng = _engagement(operator_cred=None)
    eng.loot.credentials.clear()
    assert evaluate_condition("not loot.has_credential", finding=None, engagement=eng)


def test_condition_and_combination():
    eng = _engagement()
    finding = {"attack": "Kerberoast", "data": {"encryption": "RC4"}}
    assert evaluate_condition(
        "finding.attack == 'Kerberoast' and finding.data.encryption == 'RC4'",
        finding=finding, engagement=eng,
    )
    assert not evaluate_condition(
        "finding.attack == 'Kerberoast' and finding.data.encryption == 'AES'",
        finding=finding, engagement=eng,
    )


def test_condition_or_combination():
    eng = _engagement()
    finding = {"attack": "Kerberoast"}
    assert evaluate_condition(
        "finding.attack == 'Kerberoast' or finding.attack == 'AS-REP Roast'",
        finding=finding, engagement=eng,
    )


def test_condition_quoted_literal_contains_logical_keyword():
    """`foo == 'a and b'` must NOT be split on the inner ` and `."""
    eng = _engagement()
    assert evaluate_condition(
        "finding.target == 'svc and stuff'",
        finding={"target": "svc and stuff"},
        engagement=eng,
    )


# ────────────────────────────────────────────────────────────────────── #
#  Playbook loading                                                      #
# ────────────────────────────────────────────────────────────────────── #


def test_playbook_parses_minimal_yaml(tmp_path):
    p = tmp_path / "tiny.yaml"
    p.write_text(
        "name: test\n"
        "plays:\n"
        "  - name: hello\n"
        "    command: ['echo', 'hi']\n"
    )
    pb = Playbook.from_file(p)
    assert pb.name == "test"
    assert len(pb.plays) == 1
    assert pb.plays[0].command == ["echo", "hi"]


def test_playbook_rejects_play_missing_command(tmp_path):
    p = tmp_path / "bad.yaml"
    p.write_text("name: bad\nplays:\n  - name: x\n")
    with pytest.raises(ValueError, match="missing 'command'"):
        Playbook.from_file(p)


def test_bundled_standard_playbook_loads_clean():
    """The shipped default must always parse — guard against typos."""
    from pathlib import Path
    bundled = Path(__file__).parent.parent / "kerb_chain" / "playbooks" / "standard.yaml"
    pb = Playbook.from_file(bundled)
    assert pb.plays
    assert all(p.name and p.command for p in pb.plays)


# ────────────────────────────────────────────────────────────────────── #
#  Runner                                                                #
# ────────────────────────────────────────────────────────────────────── #


def _run_one_play(*, play, finding=None, engagement=None, **runner_kwargs):
    pb = Playbook(name="t", plays=[play])
    eng = engagement or _engagement(dry_run=False)
    runner = Runner(pb, eng, verbose=False, **runner_kwargs)
    runner.run()
    return eng


def test_runner_dry_run_does_not_subprocess():
    play = Play(name="echo", command=["echo", "{{operator_user}}"])
    with patch("kerb_chain.runner.subprocess.run") as m:
        eng = _run_one_play(play=play, engagement=_engagement(dry_run=True))
    m.assert_not_called()
    rec = eng.history[-1]
    assert rec.skipped == "dry-run"
    assert rec.command == ["echo", "op"]   # template still rendered


def test_runner_skips_aggressive_play_without_flag():
    play = Play(name="loud", command=["true"], requires_aggressive=True)
    with patch("kerb_chain.runner.subprocess.run") as m:
        eng = _run_one_play(play=play, aggressive=False)
    m.assert_not_called()
    assert eng.history[-1].skipped == "requires --aggressive"


def test_runner_runs_aggressive_play_with_flag():
    play = Play(name="loud", command=["true"], requires_aggressive=True)
    with patch("kerb_chain.runner.subprocess.run") as m:
        m.return_value.returncode = 0
        m.return_value.stdout = ""
        m.return_value.stderr = ""
        eng = _run_one_play(play=play, aggressive=True)
    assert m.called
    assert eng.history[-1].exit_code == 0


def test_runner_records_command_not_found():
    play = Play(name="ghost", command=["definitely-not-on-path"])
    eng = _run_one_play(play=play)
    assert "command not found" in eng.history[-1].skipped


def test_runner_captures_credentials_via_regex():
    play = Play(
        name="fake-crack",
        command=["echo", "alice:Spring2026!"],
        capture=CaptureRule(cred_regex=r"^(?P<user>[^:]+):(?P<pass>.+)$"),
    )
    with patch("kerb_chain.runner.subprocess.run") as m:
        m.return_value.returncode = 0
        m.return_value.stdout = "alice:Spring2026!\n"
        m.return_value.stderr = ""
        eng = _run_one_play(play=play)
    captured = [c for c in eng.loot.credentials if c.username == "alice"]
    assert captured
    assert captured[0].password == "Spring2026!"
    assert captured[0].source.startswith("capture:")


def test_runner_per_finding_expands_to_one_call_per_match():
    play = Play(
        name="kerberoast",
        command=["echo", "{{finding.target}}"],
        when="finding.attack == 'Kerberoast'",
        per="finding",
    )
    eng = _engagement(
        dry_run=True,
        findings=[
            {"target": "svc1", "attack": "Kerberoast"},
            {"target": "svc2", "attack": "Kerberoast"},
            {"target": "u1",   "attack": "AS-REP Roast"},
        ],
    )
    Runner(Playbook(name="t", plays=[play]), eng, verbose=False).run()
    rendered = [rec.command[1] for rec in eng.history if rec.skipped == "dry-run"]
    assert rendered == ["svc1", "svc2"]


def test_runner_on_success_enqueues_follow_up():
    a = Play(name="a", command=["true"], on_success=["b"])
    b = Play(name="b", command=["true"])
    pb = Playbook(name="t", plays=[a, b])
    eng = _engagement(dry_run=True)
    Runner(pb, eng, verbose=False).run()
    play_names = [r.play for r in eng.history]
    # b appears at least once (initial enqueue) and might re-enqueue on
    # a.on_success — guard against duplicate execution by checking the
    # de-dup set caps it.
    assert play_names.count("b") == 1


def test_runner_writes_journal(tmp_path):
    play = Play(name="echo", command=["true"])
    eng = _engagement(dry_run=True, run_dir=tmp_path)
    Runner(Playbook(name="t", plays=[play]), eng, verbose=False).run()
    journal = eng.write_journal()
    assert journal.exists()
    payload = json.loads(journal.read_text())
    assert payload["history"]
    assert payload["domain"] == "corp.local"

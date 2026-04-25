"""
§1.6 — BloodHound-Lite exporter renamed (option b in the brief).

Confirms the new class name and CLI flag are in place and that the
exporter still produces valid JSON. The full BH-CE-compatible exporter
(option a) is deferred to a later PR; tests here only pin the rename
and the deliberate non-ingestibility disclaimer.
"""

import json

import pytest

from kerb_map.cli import build_parser
from kerb_map.output.exporter import BloodHoundLiteExporter


def test_class_renamed_and_old_name_gone():
    import kerb_map.output.exporter as exporter_mod
    assert hasattr(exporter_mod, "BloodHoundLiteExporter")
    # Old name must NOT be exposed — keeping it would re-create the
    # confusion the rename is meant to prevent.
    assert not hasattr(exporter_mod, "BloodHoundExporter")


def test_docstring_warns_about_bh_ce_incompatibility():
    doc = BloodHoundLiteExporter.__doc__ or ""
    assert "NOT ingestible" in doc
    assert "BloodHound CE" in doc


def test_cli_choice_uses_bloodhound_lite():
    parser = build_parser()
    args = parser.parse_args(
        ["-d", "x.local", "-dc", "1.1.1.1", "-u", "u",
         "-o", "bloodhound-lite"]
    )
    assert args.output == "bloodhound-lite"


def test_cli_rejects_old_bloodhound_choice():
    parser = build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(
            ["-d", "x.local", "-dc", "1.1.1.1", "-u", "u",
             "-o", "bloodhound"]
        )


def test_exporter_writes_valid_json(tmp_path):
    out = tmp_path / "lite.json"
    sample = {
        "meta": {"domain": "corp.local"},
        "spns":   [{"account": "svc_sql", "password_age_days": 900}],
        "asrep":  [{"account": "oldsvc"}],
        "delegations": {
            "unconstrained": [{"account": "WEB01$", "dns_name": "web01.corp.local"}],
            "constrained":   [],
            "rbcd":          [],
        },
        "hygiene": {},
        "trusts":  [],
    }
    BloodHoundLiteExporter().export(sample, str(out))

    payload = json.loads(out.read_text())
    assert payload["meta"]["count"] == len(payload["data"]) == 3
    oids = {n["ObjectIdentifier"] for n in payload["data"]}
    assert "CORP.LOCAL\\svc_sql" in oids
    assert "CORP.LOCAL\\oldsvc" in oids
    assert "CORP.LOCAL\\WEB01$" in oids

"""HTML exporter — self-contained client-facing report."""

import re

import pytest

from kerb_map.output.exporter import HTMLExporter, _h

# ────────────────────────────────────────────────── fixtures ────


def _sample_data():
    return {
        "meta": {
            "domain":     "corp.local",
            "dc_ip":      "10.0.0.5",
            "operator":   "jsmith",
            "timestamp":  "2026-04-25T12:00:00Z",
            "duration_s": 12.4,
        },
        "domain_info": {
            "domain":           "corp.local",
            "functional_level": "Windows Server 2016/2019/2022",
            "fl_int":           7,
            "domain_sid":       "S-1-5-21-1-2-3",
        },
        "targets": [
            {"target": "svc_old_admin", "attack": "DCSync (full)",
             "severity": "CRITICAL", "priority": 95,
             "category": "attack-path", "mitre": "T1003.006",
             "reason": "Has DS-Replication-Get-Changes(-All) on domain root",
             "next_step": "secretsdump.py -just-dc-ntlm corp.local/svc_old_admin@10.0.0.5"},
            {"target": "svc_sql", "attack": "Kerberoast",
             "severity": "HIGH", "priority": 80,
             "category": "kerberoast", "mitre": "T1558.003",
             "reason": "MSSQLSvc/sql01.lab.local + RC4 + ancient password",
             "next_step": "GetUserSPNs.py corp.local/op:pass -dc-ip 10.0.0.5\nhashcat -m 13100 ..."},
            {"target": "oldsvc", "attack": "AS-REP Roast",
             "severity": "HIGH", "priority": 70,
             "category": "asrep", "mitre": "T1558.004",
             "reason": "DONT_REQUIRE_PREAUTH",
             "next_step": "GetNPUsers.py corp.local/oldsvc -no-pass"},
        ],
    }


# ─────────────────────────────────────────── structure ────


def test_html_is_self_contained(tmp_path):
    """No external asset references — the file must open on an air-gapped
    box. CSS is inline; there must be no <link>/<script src>/remote http
    asset fetch."""
    out = tmp_path / "scan.html"
    HTMLExporter().export(_sample_data(), str(out))
    text = out.read_text()
    assert text.startswith("<!DOCTYPE html>")
    assert "<style>" in text
    assert "<link" not in text.lower()
    assert "<script" not in text.lower()
    # The only permitted URL is the project link in the footer; no asset
    # is fetched over the network at render time.
    asset_urls = re.findall(r'(?:src|href)\s*=\s*"(https?://[^"]+)"', text)
    assert asset_urls == ["https://github.com/b-3llum/kerb-map"]


def test_html_header_includes_meta(tmp_path):
    out = tmp_path / "scan.html"
    HTMLExporter().export(_sample_data(), str(out))
    text = out.read_text()
    assert "kerb-map report" in text
    assert "corp.local" in text
    assert "10.0.0.5" in text
    assert "jsmith" in text
    assert "12.4s" in text
    assert "<title>kerb-map report — corp.local</title>" in text


def test_html_summary_counts_by_severity(tmp_path):
    out = tmp_path / "scan.html"
    HTMLExporter().export(_sample_data(), str(out))
    text = out.read_text()
    # One CRITICAL and two HIGH in the sample.
    tiles = re.findall(
        r'<div class="tile-n">(\d+)</div>\s*<div class="tile-l">(\w+)</div>',
        text,
    )
    counts = {label: int(n) for n, label in tiles}
    assert counts["CRITICAL"] == 1
    assert counts["HIGH"] == 2
    assert counts["MEDIUM"] == 0
    assert counts["LOW"] == 0
    assert counts["INFO"] == 0


def test_html_top_priority_table_lists_targets(tmp_path):
    out = tmp_path / "scan.html"
    HTMLExporter().export(_sample_data(), str(out))
    text = out.read_text()
    assert "Top priorities" in text
    for target in ("svc_old_admin", "svc_sql", "oldsvc"):
        assert target in text


def test_html_groups_by_category_ordered_by_priority_sum(tmp_path):
    """attack-path (95) above kerberoast (80) above asrep (70)."""
    out = tmp_path / "scan.html"
    HTMLExporter().export(_sample_data(), str(out))
    text = out.read_text()
    assert "Findings by category" in text
    ap    = text.index(">attack-path ")
    kr    = text.index(">kerberoast ")
    asrep = text.index(">asrep ")
    assert ap < kr < asrep


def test_html_next_step_preserved_in_pre(tmp_path):
    out = tmp_path / "scan.html"
    HTMLExporter().export(_sample_data(), str(out))
    text = out.read_text()
    assert "<pre>" in text
    assert "GetUserSPNs.py" in text
    assert "hashcat -m 13100" in text


def test_html_domain_info_appendix(tmp_path):
    out = tmp_path / "scan.html"
    HTMLExporter().export(_sample_data(), str(out))
    text = out.read_text()
    assert "Domain info appendix" in text
    assert "S-1-5-21-1-2-3" in text
    assert "Windows Server 2016" in text


def test_html_omits_empty_appendix(tmp_path):
    out = tmp_path / "scan.html"
    HTMLExporter().export({"meta": {}, "targets": []}, str(out))
    assert "Domain info appendix" not in out.read_text()


def test_html_handles_empty_targets(tmp_path):
    """Genuinely clean domain — valid document, explicit no-findings note,
    not a blank page."""
    out = tmp_path / "clean.html"
    HTMLExporter().export(
        {"meta": {"domain": "clean.local"}, "targets": []}, str(out)
    )
    text = out.read_text()
    assert text.startswith("<!DOCTYPE html>")
    assert text.rstrip().endswith("</html>")
    assert "clean.local" in text
    assert "No findings." in text


# ───────────────────────────────────── injection safety ────


def test_html_escapes_attacker_controlled_fields(tmp_path):
    """Account names / descriptions / next-step come straight from AD and
    are attacker-controllable. A description containing markup must render
    as inert text, never as live DOM, when the operator opens the report."""
    out = tmp_path / "evil.html"
    payload = '<script>alert(1)</script>'
    data = {
        "meta": {"domain": "corp.local"},
        "targets": [{
            "target": f'svc"{payload}',
            "attack": payload,
            "severity": "HIGH", "priority": 50,
            "category": payload,
            "reason": payload,
            "next_step": payload,
        }],
    }
    HTMLExporter().export(data, str(out))
    text = out.read_text()
    # The raw <script> tag must never appear literally in the output …
    assert "<script>alert(1)</script>" not in text
    # … and its escaped form must be present (proving the value survived,
    # just neutralised).
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in text
    # The only real <script/<style> tokens are the exporter's own inline
    # <style>; there is exactly one, and no <script> element at all.
    assert text.lower().count("<script") == 0
    assert text.lower().count("<style>") == 1


def test_h_escapes_quotes_and_none():
    assert _h('a"b') == "a&quot;b"
    assert _h("a<b>c") == "a&lt;b&gt;c"
    assert _h("a&b") == "a&amp;b"
    assert _h(None) == ""
    assert _h(7) == "7"


# ───────────────────────────────────── CLI integration ────


def test_cli_choice_includes_html():
    from kerb_map.cli import build_parser
    parser = build_parser()
    args = parser.parse_args(
        ["-d", "corp.local", "-dc", "1.1.1.1", "-u", "u", "-o", "html"]
    )
    assert args.output == "html"


@pytest.mark.parametrize("bad", ["yaml", "pdf", "xml"])
def test_cli_rejects_unknown_output_format(bad):
    from kerb_map.cli import build_parser
    parser = build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(
            ["-d", "corp.local", "-dc", "1.1.1.1", "-u", "u", "-o", bad]
        )

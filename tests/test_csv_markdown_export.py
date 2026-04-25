"""CSV + Markdown exporters (brief §3.2)."""

import csv
import io

import pytest

from kerb_map.output.exporter import CSVExporter, MarkdownExporter, _md_escape

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


# ──────────────────────────────────────────────────── CSV ────


def test_csv_writes_one_row_per_target(tmp_path):
    out = tmp_path / "scan.csv"
    CSVExporter().export(_sample_data(), str(out))

    rows = list(csv.DictReader(out.read_text().splitlines()))
    assert len(rows) == 3
    assert {r["target"] for r in rows} == {"svc_old_admin", "svc_sql", "oldsvc"}


def test_csv_columns_are_stable():
    """Operators import this into Excel; column order matters and
    must not drift across versions."""
    assert CSVExporter.COLUMNS == [
        "priority", "severity", "category", "mitre",
        "target", "attack", "reason", "next_step",
    ]


def test_csv_header_row_present(tmp_path):
    out = tmp_path / "scan.csv"
    CSVExporter().export(_sample_data(), str(out))
    first_line = out.read_text().splitlines()[0]
    assert first_line == ",".join(CSVExporter.COLUMNS)


def test_csv_normalises_newlines_in_next_step(tmp_path):
    """Each row must be exactly one CSV record. Embedded newlines in
    next_step would split the row in non-quote-aware parsers (split,
    awk, csv with quoting=NONE)."""
    out = tmp_path / "scan.csv"
    CSVExporter().export(_sample_data(), str(out))
    raw = out.read_text()
    # Count records — should be header + 3 data rows = 4 lines exactly.
    # If newlines weren't normalised, the svc_sql row would wrap.
    # csv.DictReader with quoting handles multi-line cells, but our
    # invariant is one-record-per-line.
    line_count = len([
        ln for ln in raw.splitlines()
        if not ln.startswith("priority,")  # skip header for the count check
    ])
    assert line_count == 3
    # And the literal \n appears in the next_step cell:
    assert "\\n" in raw


def test_csv_handles_empty_targets(tmp_path):
    """Clean domain — header only, no error, 0 rows."""
    out = tmp_path / "empty.csv"
    CSVExporter().export({"targets": []}, str(out))
    assert out.read_text().strip() == ",".join(CSVExporter.COLUMNS)


def test_csv_skips_unknown_target_keys(tmp_path):
    """Extras in the target dict (a future v3 module's data field)
    must NOT appear as new columns — that would silently shift the
    column layout for downstream consumers."""
    out = tmp_path / "scan.csv"
    data = {"targets": [
        {"target": "x", "attack": "y", "severity": "HIGH", "priority": 50,
         "future_field": "should not appear"},
    ]}
    CSVExporter().export(data, str(out))
    text = out.read_text()
    assert "future_field" not in text
    assert "should not appear" not in text


def test_csv_handles_special_characters_in_reason(tmp_path):
    """Reasons containing commas / quotes must be properly escaped per
    RFC 4180 (the csv module does this automatically — pin via parse)."""
    out = tmp_path / "scan.csv"
    data = {"targets": [
        {"target": 'svc, "weird"', "attack": "X",
         "severity": "HIGH", "priority": 50,
         "reason": 'has, comma and "quotes" in it', "next_step": ""},
    ]}
    CSVExporter().export(data, str(out))

    rows = list(csv.DictReader(out.read_text().splitlines()))
    assert len(rows) == 1
    assert rows[0]["target"] == 'svc, "weird"'
    assert rows[0]["reason"] == 'has, comma and "quotes" in it'


# ────────────────────────────────────────────── Markdown ────


def test_markdown_includes_header_with_meta(tmp_path):
    out = tmp_path / "scan.md"
    MarkdownExporter().export(_sample_data(), str(out))
    text = out.read_text()
    assert "# kerb-map report — corp.local" in text
    assert "10.0.0.5" in text
    assert "jsmith" in text
    assert "12.4s" in text


def test_markdown_includes_top_priorities_table(tmp_path):
    out = tmp_path / "scan.md"
    MarkdownExporter().export(_sample_data(), str(out))
    text = out.read_text()
    assert "## Top priorities" in text
    # Severity badges:
    assert "🟥 CRITICAL" in text
    assert "🟧 HIGH" in text
    # All three targets in the priority table:
    for target in ("svc_old_admin", "svc_sql", "oldsvc"):
        assert target in text


def test_markdown_groups_by_category(tmp_path):
    out = tmp_path / "scan.md"
    MarkdownExporter().export(_sample_data(), str(out))
    text = out.read_text()
    assert "## Findings by category" in text
    # The three categories present in sample data:
    assert "### attack-path" in text
    assert "### kerberoast" in text
    assert "### asrep" in text


def test_markdown_categories_ordered_by_priority_sum(tmp_path):
    """attack-path (priority 95) should appear above kerberoast
    (priority 80) which should appear above asrep (priority 70)."""
    out = tmp_path / "scan.md"
    MarkdownExporter().export(_sample_data(), str(out))
    text = out.read_text()
    ap_pos    = text.index("### attack-path")
    kr_pos    = text.index("### kerberoast")
    asrep_pos = text.index("### asrep")
    assert ap_pos < kr_pos < asrep_pos


def test_markdown_renders_next_step_as_fenced_block(tmp_path):
    out = tmp_path / "scan.md"
    MarkdownExporter().export(_sample_data(), str(out))
    text = out.read_text()
    # Multi-line next_step from svc_sql should appear inside ```...```
    assert "```" in text
    assert "GetUserSPNs.py" in text
    assert "hashcat -m 13100" in text


def test_markdown_handles_empty_targets(tmp_path):
    """Customer's domain is genuinely clean — output should still be a
    valid markdown skeleton with an explicit "no findings" note."""
    out = tmp_path / "clean.md"
    MarkdownExporter().export({"meta": {"domain": "clean.local"}, "targets": []}, str(out))
    text = out.read_text()
    assert "# kerb-map report — clean.local" in text
    assert "*No findings.*" in text


def test_markdown_includes_domain_info_appendix(tmp_path):
    out = tmp_path / "scan.md"
    MarkdownExporter().export(_sample_data(), str(out))
    text = out.read_text()
    assert "## Domain info appendix" in text
    assert "S-1-5-21-1-2-3" in text
    assert "Windows Server 2016" in text


def test_markdown_omits_empty_appendix(tmp_path):
    """No domain_info → no empty appendix."""
    out = tmp_path / "scan.md"
    MarkdownExporter().export({"meta": {}, "targets": []}, str(out))
    assert "## Domain info appendix" not in out.read_text()


# ───────────────────────────────────────── _md_escape ────


@pytest.mark.parametrize("raw,expected", [
    ("plain text",            "plain text"),
    ("a | b",                 "a \\| b"),
    ("multi\nline",           "multi line"),
    ("crlf\r\nhere",          "crlf here"),
    ("path\\with\\slashes",   "path\\\\with\\\\slashes"),
    ("",                      ""),
])
def test_md_escape_handles_table_breakers(raw, expected):
    assert _md_escape(raw) == expected


def test_md_escape_handles_none_safely():
    assert _md_escape(None) == ""


# ───────────────────────────────────────── CLI integration ────


def test_cli_choices_include_csv_and_markdown():
    from kerb_map.cli import build_parser
    parser = build_parser()
    args = parser.parse_args(
        ["-d", "corp.local", "-dc", "1.1.1.1", "-u", "u", "-o", "csv"]
    )
    assert args.output == "csv"
    args = parser.parse_args(
        ["-d", "corp.local", "-dc", "1.1.1.1", "-u", "u", "-o", "markdown"]
    )
    assert args.output == "markdown"


def test_cli_rejects_unknown_output_format():
    from kerb_map.cli import build_parser
    parser = build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(
            ["-d", "corp.local", "-dc", "1.1.1.1", "-u", "u", "-o", "yaml"]
        )


# Silence the unused-import warning for io.StringIO that the linter
# might flag — we use it transitively in tests via csv.
_ = io.StringIO

"""Cache.list_scans severity aggregate (brief §3.4).

Operators want to see at a glance which stored scans are juicy
without --show-scan'ing each one. Pin the SQL aggregate shape and the
renderer format — both are part of the §3.4 contract.
"""

import pytest

from kerb_map.cli import _format_list_scans_row
from kerb_map.db.cache import Cache

# ────────────────────────────────────── Cache.list_scans aggregate ─


@pytest.fixture
def cache(tmp_path):
    return Cache(db_path=str(tmp_path / "scans.db"))


def _stub_scan(cache, *, domain="corp.local", dc_ip="10.0.0.1",
               operator="moussa", duration=12.4, findings=()):
    """Save a scan with the given findings list. Each finding is a
    (severity, attack) tuple — minimal shape to drive the aggregate."""
    targets = [
        {"category": "cve", "target": f"t{i}", "attack": atk,
         "severity": sev, "priority": 80, "reason": "...",
         "next_step": "..."}
        for i, (sev, atk) in enumerate(findings)
    ]
    return cache.save_scan(
        domain=domain, dc_ip=dc_ip, operator=operator,
        data={"meta": {"domain": domain}}, targets=targets,
        duration_s=duration,
    )


def test_list_scans_returns_dict_shape(cache):
    """Old API returned tuples; new contract is a list of dicts so
    the renderer doesn't have to tuple-index."""
    _stub_scan(cache, findings=[("HIGH", "Kerberoast")])
    rows = cache.list_scans()
    assert len(rows) == 1
    r = rows[0]
    assert isinstance(r, dict)
    assert {"id", "domain", "dc_ip", "operator",
            "timestamp", "duration_s", "counts"} <= set(r.keys())


def test_counts_breakdown_per_severity(cache):
    """The headline §3.4 feature: each scan carries its severity
    histogram so list-scans can render '3C/8H/15M/16L'."""
    _stub_scan(cache, findings=[
        ("CRITICAL", "ZeroLogon"),
        ("CRITICAL", "ESC1"),
        ("CRITICAL", "AdminSDHolder ACL"),
        ("HIGH",     "Kerberoast"),
        ("HIGH",     "ASREProast"),
        ("MEDIUM",   "RC4 only"),
        ("LOW",      "stale account"),
        ("INFO",     "trust mapped"),
    ])
    counts = cache.list_scans()[0]["counts"]
    assert counts["CRITICAL"] == 3
    assert counts["HIGH"]     == 2
    assert counts["MEDIUM"]   == 1
    assert counts["LOW"]      == 1
    assert counts["INFO"]     == 1
    assert counts["total"]    == 8


def test_scan_with_zero_findings_returns_zero_counts(cache):
    """LEFT JOIN must return the scan row even when no findings exist —
    otherwise an empty scan vanishes from list-scans, which would
    surprise an operator who knows it ran."""
    _stub_scan(cache, findings=[])
    rows = cache.list_scans()
    assert len(rows) == 1
    assert rows[0]["counts"]["total"] == 0
    assert rows[0]["counts"]["CRITICAL"] == 0


def test_multiple_scans_each_get_own_counts(cache):
    """The GROUP BY must scope to scan_id — a regression here would
    smear all findings across all scans."""
    _stub_scan(cache, findings=[("CRITICAL", "x")])
    _stub_scan(cache, findings=[("HIGH", "y"), ("HIGH", "z")])
    rows = cache.list_scans()
    assert len(rows) == 2
    # Newest first (ORDER BY timestamp DESC).
    assert rows[0]["counts"]["HIGH"]     == 2
    assert rows[0]["counts"]["CRITICAL"] == 0
    assert rows[1]["counts"]["CRITICAL"] == 1
    assert rows[1]["counts"]["HIGH"]     == 0


def test_duration_s_round_trips(cache):
    _stub_scan(cache, duration=42.7, findings=[])
    assert cache.list_scans()[0]["duration_s"] == pytest.approx(42.7)


def test_domain_filter_still_works(cache):
    """The optional domain= kwarg pre-existed — make sure adding the
    aggregate didn't break it."""
    _stub_scan(cache, domain="alpha.local",  findings=[("HIGH", "x")])
    _stub_scan(cache, domain="bravo.local",  findings=[("CRITICAL", "y")])
    alpha = cache.list_scans(domain="alpha.local")
    assert len(alpha) == 1
    assert alpha[0]["domain"] == "alpha.local"
    assert alpha[0]["counts"]["HIGH"] == 1


# ────────────────────────────────────── renderer ─


def test_renderer_includes_total_and_breakdown():
    """The brief's example format: '42 findings (3C/8H/15M/16L)'.
    Tested as a substring so the surrounding rich markup can change
    without rewriting these assertions."""
    row = {
        "id": 3, "domain": "corp.local", "dc_ip": "10.0.0.5",
        "operator": "moussa", "timestamp": "2026-04-25T10:30:00",
        "duration_s": 12.4,
        "counts": {"CRITICAL": 3, "HIGH": 8, "MEDIUM": 15,
                   "LOW": 16, "INFO": 0, "total": 42},
    }
    out = _format_list_scans_row(row)
    assert "ID   3" in out
    assert "corp.local" in out
    assert "10.0.0.5"   in out
    assert "moussa"     in out
    assert "2026-04-25 10:30:00" in out
    assert "42 findings" in out
    assert "3C/8H/15M/16L/0I" in out
    assert "12.4s" in out


def test_renderer_handles_missing_operator_and_zero_duration():
    """Operator can be NULL in older cached rows; duration_s defaulted
    to 0.0. The renderer must not blow up on either."""
    row = {
        "id": 1, "domain": "x", "dc_ip": "1.1.1.1",
        "operator": None, "timestamp": "2026-04-25T10:30:00",
        "duration_s": 0.0,
        "counts": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0,
                   "LOW": 0, "INFO": 0, "total": 0},
    }
    out = _format_list_scans_row(row)
    assert "unknown" in out
    assert "0 findings" in out


def test_renderer_strips_microseconds_from_timestamp():
    """Cached timestamps include microseconds (datetime.isoformat()).
    The renderer truncates so the row fits one terminal line."""
    row = {
        "id": 9, "domain": "x", "dc_ip": "1.1.1.1",
        "operator": "y", "timestamp": "2026-04-25T10:30:00.123456",
        "duration_s": 1.0,
        "counts": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0,
                   "LOW": 0, "INFO": 0, "total": 0},
    }
    out = _format_list_scans_row(row)
    assert "2026-04-25 10:30:00" in out
    assert ".123456" not in out

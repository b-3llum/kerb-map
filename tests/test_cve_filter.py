"""--list-cves and --only-cves (brief §3.7).

Operators want to skip ZeroLogon (their EDR fires) but still run
noPac. ``--only-cves CVE-2021-42278/42287`` filters the check list to
just the named subset. ``--list-cves`` prints every available check
with its CVE-ID and aggressive-flag so the operator can copy IDs.
"""

from unittest.mock import MagicMock

from kerb_map.modules.cve_scanner import CVEScanner

# ──────────────────────────────────────────────── list_checks ────


def test_list_checks_returns_every_safe_and_aggressive_check():
    """Regression guard: if a check is added or removed, the list
    output must reflect it. Currently 7 safe + 3 aggressive = 10."""
    checks = CVEScanner.list_checks()
    safe   = [c for c in checks if not c["requires_aggressive"]]
    loud   = [c for c in checks if c["requires_aggressive"]]
    assert len(safe)  == len(CVEScanner.SAFE_CHECKS)
    assert len(loud)  == len(CVEScanner.AGGRESSIVE_CHECKS)


def test_list_checks_includes_cve_id_and_name():
    checks = CVEScanner.list_checks()
    for c in checks:
        assert c["cve_id"], f"missing cve_id in {c}"
        assert c["name"],   f"missing name in {c}"
        assert isinstance(c["requires_aggressive"], bool)


def test_list_checks_marks_zerologon_aggressive():
    """ZeroLogon should land in the aggressive bucket, NoPac in safe."""
    checks   = {c["cve_id"]: c for c in CVEScanner.list_checks()}
    assert checks["CVE-2020-1472"]["requires_aggressive"] is True
    assert checks["CVE-2021-42278/42287"]["requires_aggressive"] is False


# ──────────────────────────────────────────────────── only-filter ────


def _scanner_with_mocked_checks():
    """Build a CVEScanner whose .check() always returns a stub
    CVEResult so we can exercise the orchestration path without
    real LDAP."""
    from kerb_map.modules.cves.cve_base import CVEResult, Severity

    scanner = CVEScanner(MagicMock(), "1.1.1.1", "corp.local")
    for c in scanner._safe + scanner._loud:
        c.check = MagicMock(return_value=CVEResult(
            cve_id=getattr(type(c), "CVE_ID", type(c).__name__),
            name=getattr(type(c), "NAME", type(c).__name__),
            severity=Severity.INFO,
            vulnerable=False,
            reason="stub",
            evidence={},
            remediation="",
            next_step="",
        ))
    return scanner


def _ran_cve_ids(scanner) -> set[str]:
    """Which checks actually had .check() invoked. Easier than parsing
    the result list since not-vulnerable results sort to the end."""
    out = set()
    for c in scanner._safe + scanner._loud:
        if c.check.called:
            out.add(getattr(type(c), "CVE_ID", type(c).__name__))
    return out


def test_only_filter_runs_named_check_and_skips_others():
    scanner = _scanner_with_mocked_checks()
    scanner.run(aggressive=False, only={"CVE-2021-42278/42287"})
    ran = _ran_cve_ids(scanner)
    assert ran == {"CVE-2021-42278/42287"}


def test_only_filter_is_case_insensitive():
    """Operators paste IDs as they remember them; the match should be
    case-insensitive so 'cve-2014-6324' works the same as 'CVE-2014-6324'."""
    scanner = _scanner_with_mocked_checks()
    scanner.run(aggressive=False, only={"cve-2014-6324"})
    ran = _ran_cve_ids(scanner)
    assert "CVE-2014-6324" in ran


def test_only_filter_with_unknown_id_runs_nothing():
    """Operator typos shouldn't silently run *every* check — they
    should run *zero* checks. That's the behaviour the brief asks for."""
    scanner = _scanner_with_mocked_checks()
    scanner.run(aggressive=False, only={"CVE-9999-9999"})
    ran = _ran_cve_ids(scanner)
    assert ran == set()


def test_only_filter_named_aggressive_check_skipped_without_aggressive_flag():
    """ZeroLogon is aggressive; --only-cves CVE-2020-1472 without
    --aggressive should produce zero runs (and a warning, not a crash)."""
    scanner = _scanner_with_mocked_checks()
    scanner.run(aggressive=False, only={"CVE-2020-1472"})
    ran = _ran_cve_ids(scanner)
    assert ran == set()


def test_only_filter_named_aggressive_check_runs_with_aggressive_flag():
    scanner = _scanner_with_mocked_checks()
    scanner.run(aggressive=True, only={"CVE-2020-1472"})
    ran = _ran_cve_ids(scanner)
    assert ran == {"CVE-2020-1472"}


def test_no_only_filter_runs_all_safe_checks():
    """No filter = every safe check runs (legacy behaviour preserved)."""
    scanner = _scanner_with_mocked_checks()
    scanner.run(aggressive=False)
    ran = _ran_cve_ids(scanner)
    expected = {getattr(c, "CVE_ID", c.__name__) for c in CVEScanner.SAFE_CHECKS}
    assert ran == expected


# ──────────────────────────────────────── argparse wiring ────


def test_argparse_list_cves_default_false():
    from kerb_map.cli import build_parser
    args = build_parser().parse_args(
        ["-d", "corp.local", "-dc", "1.1.1.1", "-u", "u"]
    )
    assert args.list_cves is False
    assert args.only_cves is None


def test_argparse_list_cves_true_when_set():
    from kerb_map.cli import build_parser
    args = build_parser().parse_args(["--list-cves"])
    assert args.list_cves is True


def test_argparse_only_cves_parses_comma_separated():
    from kerb_map.cli import build_parser
    args = build_parser().parse_args(
        ["-d", "corp.local", "-dc", "1.1.1.1", "-u", "u",
         "--only-cves", "CVE-2021-42278/42287,LDAP-SIGNING"]
    )
    assert args.only_cves == "CVE-2021-42278/42287,LDAP-SIGNING"

"""GPP Passwords (MS14-025) — honest reporting (field bug fix).

Pre-fix bug: the check counted groupPolicyContainer entries (always
present in any AD) and reported "HIGH vulnerable". On a clean lab
domain with just the two default GPOs, kerb-map false-flagged
MS14-025 — eroding operator trust in the rest of the priority table.

These tests pin the new contract: GPO discovery is INFO-grade
intel; we only claim "vulnerable" when we have actual cpassword
evidence (which currently we never do, since SMB grep isn't plumbed
through the CVE infrastructure yet).
"""

from unittest.mock import MagicMock

from kerb_map.modules.cves.cve_base import (
    PATCH_STATUS_INDETERMINATE,
    Severity,
)
from kerb_map.modules.cves.gpp_passwords import GPPPasswords


def _entry(values: dict):
    e = MagicMock()
    e.__contains__ = lambda self, k: k in values
    def _get(self, k):
        v = values[k]
        m = MagicMock()
        m.value = v
        m.__str__ = lambda self: "" if v is None else str(v)
        return m
    e.__getitem__ = _get
    return e


def _ldap(entries):
    ldap = MagicMock()
    ldap.query.return_value = entries
    return ldap


def _gpo(name, path):
    return _entry({"displayName": name, "gPCFileSysPath": path})


# ────────────────────────────────────── no GPOs ─


def test_no_gpos_returns_info_not_vulnerable():
    """Empty SYSVOL = nothing to claim. Don't pollute the priority
    table with a non-finding."""
    check = GPPPasswords(_ldap([]), "10.0.0.1", "corp.local")
    r = check.check()
    assert r.vulnerable is False
    assert r.severity == Severity.INFO
    assert "No GPOs" in r.reason
    assert r.next_step == ""


# ────────────────────────────────────── default GPOs (the field bug) ─


def test_only_default_gpos_does_not_claim_vulnerable():
    """The exact field-bug scenario: clean AD with only Default Domain
    Policy + Default Domain Controllers Policy. Pre-fix, kerb-map
    reported HIGH/vulnerable. Post-fix: INFO/not-vulnerable, with the
    operator pointed at manual verification."""
    check = GPPPasswords(_ldap([
        _gpo("Default Domain Policy",
             "\\\\corp.local\\sysvol\\corp.local\\Policies\\{31B2F340-016D-11D2-945F-00C04FB984F9}"),
        _gpo("Default Domain Controllers Policy",
             "\\\\corp.local\\sysvol\\corp.local\\Policies\\{6AC1786C-016F-11D2-945F-00C04fB984F9}"),
    ]), "10.0.0.1", "corp.local")
    r = check.check()
    assert r.vulnerable is False
    assert r.severity == Severity.INFO


def test_default_gpos_set_indeterminate_patch_status():
    """Brief §2.1 pattern: when we can't directly verify, mark
    INDETERMINATE so the scorer downgrades and the operator knows."""
    check = GPPPasswords(_ldap([_gpo("anything", "\\\\corp\\sysvol\\...")]),
                         "10.0.0.1", "corp.local")
    r = check.check()
    assert r.patch_status == PATCH_STATUS_INDETERMINATE


def test_reason_credits_the_smb_gap_explicitly():
    """Operator needs to know WHY we're not claiming vulnerability —
    'kerb-map cannot grep without SMB credentials'. A regression to
    silent INFO-with-no-context is worse than no-finding."""
    check = GPPPasswords(_ldap([_gpo("X", "\\\\corp\\sysvol\\...")]),
                         "10.0.0.1", "corp.local")
    r = check.check()
    assert "SMB" in r.reason
    assert "cpassword" in r.reason


def test_next_step_contains_manual_verification_recipes():
    """Three paths the operator can take to actually verify — pin
    them so a refactor doesn't leave the operator stranded."""
    check = GPPPasswords(_ldap([_gpo("X", "\\\\corp\\sysvol\\...")]),
                         "10.0.0.1", "corp.local")
    r = check.check()
    assert "smbclient" in r.next_step
    assert "Get-GPPPassword" in r.next_step
    assert "grep" in r.next_step
    assert "10.0.0.1" in r.next_step    # DC IP substituted
    assert "corp.local" in r.next_step  # domain substituted


# ────────────────────────────────────── evidence preserved ─


def test_evidence_carries_gpo_paths_for_operator_pivot():
    """Even when not claiming vulnerability, give the operator the
    discovered paths — they may want to grep the specific GPO that
    looks suspicious."""
    paths = [_gpo(f"GPO{i}", f"\\\\corp\\sysvol\\policies\\{{{i}}}") for i in range(8)]
    check = GPPPasswords(_ldap(paths), "10.0.0.1", "corp.local")
    r = check.check()
    assert r.evidence["gpo_count"] == 8
    # Capped at 5 — first 5 are exposed; full list lives in LDAP if
    # the operator wants more.
    assert len(r.evidence["gpo_paths"]) == 5

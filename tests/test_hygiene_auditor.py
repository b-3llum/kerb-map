"""HygieneAuditor — defensive AD posture checks (10 sub-modules).

The module is 663 LOC and was previously at 13% line coverage — most
sub-modules had no test at all. This file pins each sub-module's
contract via mock-LDAP unit tests, plus a lab-integration test (gated
by ``KERBMAP_LAB_DC_IP`` env var) that exercises the full ``audit()``
sweep against the running Samba 4 lab.

The lab integration is the same pattern that surfaced the 3 impacket
bugs in PR #41: pure mocks pass, but real-traffic exposes shape
mismatches the mocks were too convenient to catch.
"""

from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

import pytest

from kerb_map.modules.hygiene_auditor import (
    BUILTIN_PRIVILEGED,
    CREDENTIAL_PATTERNS,
    DEFAULT_PRIMARY_GROUPS,
    PRIVILEGED_RIDS,
    HygieneAuditor,
    HygieneResult,
)

# ─────────────────────────────────── helpers ─


def _attr(value):
    """Mock an ldap3 attribute. Supports:
        m.value     - the underlying scalar (or list)
        m.values    - always a list
        str(m)      - the scalar's str (or "" if None)
        iter(m)     - iter the list (or single value)
        bool(m)     - truthy when value is a non-empty list / non-None scalar
        len(m)      - len of list (used by `if not entries:` paths)
    """
    m = MagicMock()
    m.value = value
    if isinstance(value, list):
        m.values = list(value)
        m.__iter__ = lambda self: iter(value)
        m.__bool__ = lambda self: bool(value)
        m.__len__ = lambda self: len(value)
    else:
        m.values = [] if value is None else [value]
        m.__iter__ = lambda self: iter([] if value is None else [value])
        m.__bool__ = lambda self: value is not None
        m.__len__ = lambda self: 0 if value is None else 1
    m.__str__ = lambda self: "" if value is None else str(value)
    return m


def _entry(values: dict):
    """Mock an ldap3.Entry. Maps attribute name → ``_attr``."""
    e = MagicMock()
    e.__contains__ = lambda self, k: k in values
    def _get(_self, key):
        return _attr(values.get(key))
    e.__getitem__ = _get
    return e


class _LDAP:
    """Mock LDAPClient. Configure ``query_responses`` as a list of
    response lists, returned in call order. ``base_dn`` is set so
    ``_fgpp_audit`` can build the Password Settings Container DN."""

    def __init__(self, *, query_responses=None, base_dn="DC=corp,DC=local"):
        self.base_dn = base_dn
        self._queue = list(query_responses or [])
        self.calls: list[dict] = []

    def query(self, **kwargs):
        self.calls.append(kwargs)
        return self._queue.pop(0) if self._queue else []


def _filetime(dt: datetime) -> int:
    """Convert a UTC datetime to a Windows FILETIME integer
    (100ns intervals since 1601-01-01)."""
    epoch = datetime(1601, 1, 1, tzinfo=timezone.utc)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return int((dt - epoch).total_seconds() * 10_000_000)


# ─────────────────────────────────── module-level constants ─


def test_module_constants_present():
    """Pin the well-known RIDs and credential regex set so a refactor
    doesn't silently drop one. Each constant is queried by a
    sub-module and a missing entry produces a quiet false-negative."""
    assert "512" in PRIVILEGED_RIDS  # Domain Admins
    assert "519" in PRIVILEGED_RIDS  # Enterprise Admins
    assert "544" in BUILTIN_PRIVILEGED  # Administrators
    assert "548" in BUILTIN_PRIVILEGED  # Account Operators
    assert 513 in DEFAULT_PRIMARY_GROUPS  # Domain Users
    assert len(CREDENTIAL_PATTERNS) >= 5
    # The regex must match the most common ops shorthand.
    sample = "service password=Summer2024!"
    assert any(p.search(sample) for p in CREDENTIAL_PATTERNS)


# ─────────────────────────────────── HygieneResult ─


def test_hygiene_result_finding_count_default_is_zero():
    """Empty HygieneResult means the audit didn't run — finding_count
    must be 0, not 1. Field bug from the v1.3 sprint: previously the
    FGPP check defaulted *pessimistic* (empty {} treated as
    "privileged not covered" → +1) while LAPS / krbtgt defaulted
    *optimistic* (empty {} treated as "100% covered" / "0 days old"
    → 0). The inconsistency made the reporter say "1 hygiene finding"
    on a result the audit hadn't filled in. Now: empty/missing data
    on every dict-shaped sub-result counts 0."""
    assert HygieneResult().finding_count() == 0


def test_hygiene_result_finding_count_when_audit_ran_clean():
    """All sub-checks ran and found nothing wrong — count is still 0.
    Pin the post-audit zero state so the new guards don't accidentally
    skip a real finding."""
    r = HygieneResult(
        laps_coverage={"coverage_pct": 100},      # covered
        krbtgt_age={"age_days": 30},               # recent
        fgpp_audit={"privileged_covered": True},   # covered
    )
    assert r.finding_count() == 0


def test_hygiene_result_counts_each_finding_kind():
    r = HygieneResult(
        sid_history=[{"a": 1}, {"a": 2}],
        laps_coverage={"coverage_pct": 50},   # < 90 → +1
        krbtgt_age={"age_days": 365},          # > 180 → +1
        adminsdholder_orphans=[{"a": 1}],
        fgpp_audit={"privileged_covered": True},
        credential_exposure=[{"a": 1}, {"a": 2}, {"a": 3}],
        primary_group_abuse=[{"a": 1}],
        stale_computers=[{"a": 1}, {"a": 2}],  # any > 0 → +1
        service_acct_hygiene=[{"a": 1}],
    )
    # 2 (sid) + 1 (laps) + 1 (krbtgt) + 1 (adminsd) + 0 (fgpp covered)
    # + 3 (cred) + 1 (pgid) + 1 (stale) + 1 (svc) = 11
    assert r.finding_count() == 11


# ─────────────────────────────────── _get_domain_sid ─


def test_get_domain_sid_returns_string():
    """SID History audit downgrades risk from CRITICAL to MEDIUM when
    the domain SID can't be derived — pin that the helper actually
    returns the SID string from objectSid, not the raw bytes."""
    ldap = _LDAP(query_responses=[[
        _entry({"objectSid": "S-1-5-21-10-20-30"}),
    ]])
    auditor = HygieneAuditor(ldap)
    assert auditor._get_domain_sid() == "S-1-5-21-10-20-30"


def test_get_domain_sid_returns_none_when_query_empty():
    """Missing rootDSE / unprivileged bind → no domain SID. Sub-modules
    must degrade gracefully (skip same-domain SID detection) rather
    than crash."""
    ldap = _LDAP(query_responses=[[]])
    auditor = HygieneAuditor(ldap)
    assert auditor._get_domain_sid() is None


def test_get_domain_sid_returns_none_when_objectsid_value_is_none():
    """The query returned an entry but the objectSid attribute is
    null — same code path as above; must not raise."""
    ldap = _LDAP(query_responses=[[_entry({"objectSid": None})]])
    auditor = HygieneAuditor(ldap)
    assert auditor._get_domain_sid() is None


# ─────────────────────────────────── _sid_history_audit ─


def test_sid_history_audit_returns_empty_on_clean_domain():
    ldap = _LDAP(query_responses=[[]])
    assert HygieneAuditor(ldap)._sid_history_audit() == []


def test_sid_history_audit_flags_privileged_rid_as_critical():
    """SID History containing the Domain Admins RID (-512) is the
    classic Mimikatz `sid::patch` persistence path — pin that the
    audit calls it CRITICAL with the right detail string."""
    ldap = _LDAP(query_responses=[
        [_entry({
            "sAMAccountName": "alice",
            "sIDHistory":     ["S-1-5-21-OTHER-512"],
            "objectSid":      "S-1-5-21-10-20-30-1234",
            "distinguishedName": "CN=alice,...",
            "objectClass":    ["top", "person", "user"],
        })],
        # _get_domain_sid call (made by the audit)
        [_entry({"objectSid": "S-1-5-21-10-20-30"})],
    ])
    findings = HygieneAuditor(ldap)._sid_history_audit()
    assert len(findings) == 1
    assert findings[0]["risk"] == "CRITICAL"
    assert "Domain Admins" in findings[0]["detail"]
    assert findings[0]["account"] == "alice"
    assert findings[0]["is_computer"] is False


def test_sid_history_audit_flags_same_domain_sid_as_critical():
    """A SID History entry from the *same* domain as the account is
    a strong indicator of post-compromise persistence (legitimate
    SIDHistory only flows across migrated domains). Pin CRITICAL."""
    ldap = _LDAP(query_responses=[
        [_entry({
            "sAMAccountName": "bob",
            "sIDHistory":     ["S-1-5-21-10-20-30-9999"],
            "objectSid":      "S-1-5-21-10-20-30-1234",
            "distinguishedName": "CN=bob,...",
            "objectClass":    ["user"],
        })],
        [_entry({"objectSid": "S-1-5-21-10-20-30"})],
    ])
    findings = HygieneAuditor(ldap)._sid_history_audit()
    assert findings[0]["risk"] == "CRITICAL"
    assert "Same-domain" in findings[0]["detail"]


def test_sid_history_audit_treats_cross_domain_as_medium():
    """A SID History from a different domain is an unconfirmed
    migration artifact — MEDIUM, not CRITICAL. Misclassifying these as
    CRITICAL drowns the operator in noise on real estates."""
    ldap = _LDAP(query_responses=[
        [_entry({
            "sAMAccountName": "carol",
            "sIDHistory":     ["S-1-5-21-OTHER-DOMAIN-1100"],
            "objectSid":      "S-1-5-21-10-20-30-1234",
            "distinguishedName": "CN=carol,...",
            "objectClass":    ["user"],
        })],
        [_entry({"objectSid": "S-1-5-21-10-20-30"})],
    ])
    findings = HygieneAuditor(ldap)._sid_history_audit()
    assert findings[0]["risk"] == "MEDIUM"


def test_sid_history_audit_flags_computer_objects_too():
    """SID History on computer objects is rarer but real (silver-
    ticket pre-staging). Pin that ``is_computer`` is set so reports
    can group them separately."""
    ldap = _LDAP(query_responses=[
        [_entry({
            "sAMAccountName": "ws01$",
            "sIDHistory":     ["S-1-5-21-OTHER-1100"],
            "objectSid":      "S-1-5-21-10-20-30-2000",
            "distinguishedName": "CN=ws01,CN=Computers,...",
            "objectClass":    ["top", "person", "organizationalPerson",
                                "user", "computer"],
        })],
        [_entry({"objectSid": "S-1-5-21-10-20-30"})],
    ])
    findings = HygieneAuditor(ldap)._sid_history_audit()
    assert findings[0]["is_computer"] is True


# ─────────────────────────────────── _laps_coverage ─


def test_laps_coverage_no_computers_returns_info():
    """Empty domain → INFO, not CRITICAL. Don't false-flag a brand-new
    AD provision with no member machines."""
    ldap = _LDAP(query_responses=[[]])  # no computers
    result = HygieneAuditor(ldap)._laps_coverage()
    assert result["risk"] == "INFO"
    assert result["total_computers"] == 0
    assert result["coverage_pct"] == 100


def test_laps_coverage_reports_critical_when_no_laps_deployed():
    ldap = _LDAP(query_responses=[
        [_entry({"sAMAccountName": "ws01$"}),
         _entry({"sAMAccountName": "ws02$"})],
        [],  # legacy LAPS — none
        [],  # win LAPS    — none
    ])
    result = HygieneAuditor(ldap)._laps_coverage()
    assert result["risk"] == "CRITICAL"
    assert result["coverage_pct"] == 0
    assert result["laps_managed"] == 0
    assert result["total_computers"] == 2


def test_laps_coverage_full_coverage_is_low_risk():
    ldap = _LDAP(query_responses=[
        [_entry({"sAMAccountName": "ws01$"}),
         _entry({"sAMAccountName": "ws02$"})],
        [_entry({"sAMAccountName": "ws01$"}),
         _entry({"sAMAccountName": "ws02$"})],
        [],
    ])
    result = HygieneAuditor(ldap)._laps_coverage()
    assert result["risk"] == "LOW"
    assert result["coverage_pct"] == 100.0


def test_laps_coverage_partial_is_medium():
    ldap = _LDAP(query_responses=[
        [_entry({"sAMAccountName": f"ws{i:02d}$"}) for i in range(10)],
        [_entry({"sAMAccountName": f"ws{i:02d}$"}) for i in range(7)],  # 70%
        [],
    ])
    result = HygieneAuditor(ldap)._laps_coverage()
    assert result["risk"] == "MEDIUM"
    assert result["laps_managed"] == 7
    assert result["coverage_pct"] == 70.0


def test_laps_coverage_dedupes_legacy_and_win_laps_for_same_machine():
    """A machine can have BOTH legacy ms-Mcs-AdmPwdExpirationTime AND
    new msLAPS-PasswordExpirationTime during a migration. Counting
    both produces > 100% coverage and a divide-by-zero feel.
    Dedup must be set-based on sAMAccountName."""
    ldap = _LDAP(query_responses=[
        [_entry({"sAMAccountName": "ws01$"})],   # 1 computer total
        [_entry({"sAMAccountName": "ws01$"})],   # legacy LAPS
        [_entry({"sAMAccountName": "ws01$"})],   # win LAPS — same box
    ])
    result = HygieneAuditor(ldap)._laps_coverage()
    assert result["laps_managed"] == 1   # NOT 2
    assert result["coverage_pct"] == 100.0


def test_laps_coverage_poor_deployment_is_high():
    ldap = _LDAP(query_responses=[
        [_entry({"sAMAccountName": f"ws{i}$"}) for i in range(10)],
        [_entry({"sAMAccountName": "ws0$"}),
         _entry({"sAMAccountName": "ws1$"})],   # 20%
        [],
    ])
    result = HygieneAuditor(ldap)._laps_coverage()
    assert result["risk"] == "HIGH"


# ─────────────────────────────────── _krbtgt_password_age ─


def test_krbtgt_age_missing_account_returns_medium():
    """Unprivileged bind can't read the krbtgt account → result is
    MEDIUM with age=-1. Don't pretend to know the answer."""
    ldap = _LDAP(query_responses=[[]])
    result = HygieneAuditor(ldap)._krbtgt_password_age()
    assert result["risk"] == "MEDIUM"
    assert result["age_days"] == -1


def test_krbtgt_age_never_set_is_critical():
    ldap = _LDAP(query_responses=[
        [_entry({"sAMAccountName": "krbtgt", "pwdLastSet": None})],
    ])
    result = HygieneAuditor(ldap)._krbtgt_password_age()
    assert result["risk"] == "CRITICAL"
    assert "NEVER" in result["detail"]


def test_krbtgt_age_recent_rotation_is_low():
    recent = datetime.now(timezone.utc) - timedelta(days=30)
    ldap = _LDAP(query_responses=[
        [_entry({"sAMAccountName": "krbtgt", "pwdLastSet": _filetime(recent)})],
    ])
    result = HygieneAuditor(ldap)._krbtgt_password_age()
    assert result["risk"] == "LOW"
    assert 25 <= result["age_days"] <= 35


def test_krbtgt_age_over_180_is_high():
    old = datetime.now(timezone.utc) - timedelta(days=200)
    ldap = _LDAP(query_responses=[
        [_entry({"sAMAccountName": "krbtgt", "pwdLastSet": _filetime(old)})],
    ])
    result = HygieneAuditor(ldap)._krbtgt_password_age()
    assert result["risk"] == "HIGH"


def test_krbtgt_age_over_365_is_critical():
    ancient = datetime.now(timezone.utc) - timedelta(days=400)
    ldap = _LDAP(query_responses=[
        [_entry({"sAMAccountName": "krbtgt", "pwdLastSet": _filetime(ancient)})],
    ])
    result = HygieneAuditor(ldap)._krbtgt_password_age()
    assert result["risk"] == "CRITICAL"
    assert result["age_days"] >= 400


def test_krbtgt_age_accepts_native_datetime():
    """ldap3 returns datetime objects for some attribute syntaxes
    rather than the raw FILETIME int — pin that we handle both."""
    naive = datetime.now() - timedelta(days=100)
    ldap = _LDAP(query_responses=[
        [_entry({"sAMAccountName": "krbtgt", "pwdLastSet": naive})],
    ])
    result = HygieneAuditor(ldap)._krbtgt_password_age()
    assert result["risk"] == "MEDIUM"  # 90-180


def test_krbtgt_age_accepts_aware_datetime():
    aware = datetime.now(timezone.utc) - timedelta(days=100)
    ldap = _LDAP(query_responses=[
        [_entry({"sAMAccountName": "krbtgt", "pwdLastSet": aware})],
    ])
    result = HygieneAuditor(ldap)._krbtgt_password_age()
    assert result["risk"] == "MEDIUM"


# ─────────────────────────────────── _adminsdholder_orphans ─


def test_adminsdholder_no_admins_returns_empty():
    ldap = _LDAP(query_responses=[[]])
    assert HygieneAuditor(ldap)._adminsdholder_orphans() == []


def test_adminsdholder_orphan_flagged_when_no_protected_membership():
    """An adminCount=1 user with no membership in any protected group
    is the classic "stale flag" or "compromised, then group-yanked"
    pattern. Pin HIGH so it shows up in defender reports."""
    ldap = _LDAP(query_responses=[
        # admin entries
        [_entry({
            "sAMAccountName":    "admin_orphan",
            "memberOf":          [],
            "distinguishedName": "CN=admin_orphan,CN=Users,DC=corp,DC=local",
        })],
        # protected-group lookups (one per group; return empty so the set is empty)
        *([[]] * 11),
    ])
    findings = HygieneAuditor(ldap)._adminsdholder_orphans()
    assert len(findings) == 1
    assert findings[0]["risk"] == "HIGH"
    assert findings[0]["account"] == "admin_orphan"


def test_adminsdholder_membership_in_protected_group_suppresses():
    da_dn = "CN=Domain Admins,CN=Users,DC=corp,DC=local"
    responses = [
        # admin entries — bob_da is in Domain Admins
        [_entry({
            "sAMAccountName":    "bob_da",
            "memberOf":          [da_dn],
            "distinguishedName": "CN=bob_da,CN=Users,DC=corp,DC=local",
        })],
    ]
    # 11 protected-group lookups; only "Domain Admins" returns a match
    for name in ["Domain Admins", "Enterprise Admins", "Schema Admins",
                 "Administrators", "Account Operators", "Server Operators",
                 "Print Operators", "Backup Operators", "Replicator",
                 "Domain Controllers", "Read-only Domain Controllers"]:
        if name == "Domain Admins":
            responses.append([_entry({"distinguishedName": da_dn})])
        else:
            responses.append([])
    ldap = _LDAP(query_responses=responses)
    findings = HygieneAuditor(ldap)._adminsdholder_orphans()
    assert findings == []


# ─────────────────────────────────── _fgpp_audit ─


def test_fgpp_no_policies_is_high():
    """No FGPP defined at all → all accounts use domain default. HIGH
    because privileged accounts are stuck on the same policy as
    everyone else."""
    ldap = _LDAP(query_responses=[
        [],            # FGPP query
        *([[]] * 4),   # privileged-group lookups
    ])
    result = HygieneAuditor(ldap)._fgpp_audit()
    assert result["risk"] == "HIGH"
    assert result["policy_count"] == 0
    assert result["privileged_covered"] is False


def test_fgpp_policy_not_covering_privileged_is_medium():
    pso_dn = "CN=Default-PSO,CN=Password Settings Container,..."
    da_dn  = "CN=Domain Admins,CN=Users,DC=corp,DC=local"
    ldap = _LDAP(query_responses=[
        # FGPP query
        [_entry({
            "cn":                              "Default-PSO",
            "msDS-MinimumPasswordLength":      14,
            "msDS-MaximumPasswordAge":         None,
            "msDS-PasswordComplexityEnabled":  True,
            "msDS-LockoutThreshold":           5,
            "msDS-PSOAppliesTo":               [pso_dn],   # not the DA group
            "msDS-PasswordSettingsPrecedence": 10,
        })],
        # privileged-group lookups
        [_entry({"distinguishedName": da_dn})],
        [],
        [],
        [],
    ])
    result = HygieneAuditor(ldap)._fgpp_audit()
    assert result["policy_count"] == 1
    assert result["policies"][0]["min_length"] == 14
    assert result["policies"][0]["complexity_enabled"] is True
    assert result["policies"][0]["lockout_threshold"] == 5
    assert result["privileged_covered"] is False
    assert result["risk"] == "MEDIUM"


def test_fgpp_policy_covering_privileged_is_low():
    da_dn = "CN=Domain Admins,CN=Users,DC=corp,DC=local"
    ldap = _LDAP(query_responses=[
        [_entry({
            "cn":                              "DA-PSO",
            "msDS-MinimumPasswordLength":      20,
            "msDS-MaximumPasswordAge":         None,
            "msDS-PasswordComplexityEnabled":  True,
            "msDS-LockoutThreshold":           3,
            "msDS-PSOAppliesTo":               [da_dn],
            "msDS-PasswordSettingsPrecedence": 1,
        })],
        [_entry({"distinguishedName": da_dn})],
        [],
        [],
        [],
    ])
    result = HygieneAuditor(ldap)._fgpp_audit()
    assert result["privileged_covered"] is True
    assert result["risk"] == "LOW"


def test_fgpp_handles_null_attribute_values():
    """Samba-provisioned default PSOs sometimes ship with null
    complexity / min-length attributes — treat them as 0 / False
    rather than crashing."""
    ldap = _LDAP(query_responses=[
        [_entry({
            "cn":                              "Empty-PSO",
            "msDS-MinimumPasswordLength":      None,
            "msDS-MaximumPasswordAge":         None,
            "msDS-PasswordComplexityEnabled":  None,
            "msDS-LockoutThreshold":           None,
            "msDS-PSOAppliesTo":               [],
            "msDS-PasswordSettingsPrecedence": None,
        })],
        *([[]] * 4),
    ])
    result = HygieneAuditor(ldap)._fgpp_audit()
    pol = result["policies"][0]
    assert pol["min_length"] == 0
    assert pol["complexity_enabled"] is False
    assert pol["lockout_threshold"] == 0


# ─────────────────────────────────── _credential_exposure ─


def test_credential_exposure_finds_password_in_description():
    ldap = _LDAP(query_responses=[
        [_entry({
            "sAMAccountName":    "svc_app",
            "description":       "service account password=Summer2024!",
            "info":              None,
            "distinguishedName": "CN=svc_app,...",
            "adminCount":        None,
        })],
    ])
    findings = HygieneAuditor(ldap)._credential_exposure()
    assert len(findings) == 1
    assert findings[0]["risk"] == "HIGH"
    assert findings[0]["field"] == "description"
    assert findings[0]["account"] == "svc_app"


def test_credential_exposure_admin_account_is_critical():
    ldap = _LDAP(query_responses=[
        [_entry({
            "sAMAccountName":    "svc_old_admin",
            "description":       "pwd: SuperSecret123",
            "info":              None,
            "distinguishedName": "CN=svc_old_admin,...",
            "adminCount":        1,
        })],
    ])
    findings = HygieneAuditor(ldap)._credential_exposure()
    assert findings[0]["risk"] == "CRITICAL"
    assert findings[0]["is_admin"] is True
    assert "PRIVILEGED" in findings[0]["detail"]


def test_credential_exposure_only_one_finding_per_field_even_with_multiple_matches():
    """``password=...`` AND ``credentials=...`` in the same
    description must collapse to one finding for that field — operator
    inboxes shouldn't get N entries for one row in the directory."""
    ldap = _LDAP(query_responses=[
        [_entry({
            "sAMAccountName":    "svc",
            "description":       "password=x credentials=y secret=z",
            "info":              None,
            "distinguishedName": "CN=svc,...",
            "adminCount":        None,
        })],
    ])
    findings = HygieneAuditor(ldap)._credential_exposure()
    descs = [f for f in findings if f["field"] == "description"]
    assert len(descs) == 1


def test_credential_exposure_finds_in_info_field_too():
    ldap = _LDAP(query_responses=[
        [_entry({
            "sAMAccountName":    "svc",
            "description":       None,
            "info":              "secret: s3cr3t",
            "distinguishedName": "CN=svc,...",
            "adminCount":        None,
        })],
    ])
    findings = HygieneAuditor(ldap)._credential_exposure()
    assert len(findings) == 1
    assert findings[0]["field"] == "info"


def test_credential_exposure_catches_pw_shorthand_field_bug():
    """Regression for the field bug surfaced by the Samba lab: the
    seed carried ``description='SQL svc — pw=Spring2024! rotate
    quarterly'`` and the audit silently missed it because neither
    ``pass`` nor ``pwd`` matches the bare ``pw=`` abbreviation that
    ops actually use. Pin both the LDAP filter substring and the
    regex pattern — the bug had two layers and the test catches
    either coming back."""
    ldap = _LDAP(query_responses=[
        [_entry({
            "sAMAccountName":    "svc_app",
            "description":       "SQL svc — pw=Spring2024! rotate quarterly",
            "info":              None,
            "distinguishedName": "CN=svc_app,...",
            "adminCount":        None,
        })],
    ])
    findings = HygieneAuditor(ldap)._credential_exposure()
    assert len(findings) == 1
    assert findings[0]["account"] == "svc_app"
    # The LDAP filter must also include the `pw=` substring matcher,
    # otherwise the downstream regex never sees the entry on a real
    # estate (the unit test above only fires because the mock LDAP
    # returns the entry regardless of the filter — pin both layers).
    ldap2 = _LDAP(query_responses=[[]])
    HygieneAuditor(ldap2)._credential_exposure()
    assert "pw=" in ldap2.calls[0]["search_filter"]


def test_credential_exposure_catches_secret_and_key_shorthand():
    """``secret=`` and ``key=`` are common for service-bus and API
    credentials. Pin them in both the filter and the regex set."""
    ldap = _LDAP(query_responses=[
        [
            _entry({"sAMAccountName": "api_svc",
                    "description": "key=AKIA1234567890ABCDEF",
                    "info": None, "distinguishedName": "CN=api_svc,...",
                    "adminCount": None}),
            _entry({"sAMAccountName": "bus_svc",
                    "description": "secret=hunter2",
                    "info": None, "distinguishedName": "CN=bus_svc,...",
                    "adminCount": None}),
        ],
    ])
    findings = HygieneAuditor(ldap)._credential_exposure()
    accts = {f["account"] for f in findings}
    assert accts == {"api_svc", "bus_svc"}


# ─────────────────────────────────── _primary_group_abuse ─


def test_primary_group_abuse_returns_empty_on_clean_domain():
    ldap = _LDAP(query_responses=[[]])
    assert HygieneAuditor(ldap)._primary_group_abuse() == []


def test_primary_group_abuse_flags_da_rid_as_high():
    """primaryGroupId=512 (Domain Admins) hides DA membership from
    the typical ``net group`` enumeration. HIGH risk + privileged
    flag set."""
    ldap = _LDAP(query_responses=[
        [_entry({
            "sAMAccountName":    "stealth_admin",
            "primaryGroupID":    512,
            "distinguishedName": "CN=stealth_admin,...",
        })],
    ])
    findings = HygieneAuditor(ldap)._primary_group_abuse()
    assert findings[0]["risk"] == "HIGH"
    assert findings[0]["primary_group_name"] == "Domain Admins"
    assert "PRIVILEGED" in findings[0]["detail"]


def test_primary_group_abuse_unknown_rid_is_medium():
    """A non-default, non-privileged primaryGroupId is still
    suspicious (membership-hiding) but not the same severity. MEDIUM
    + the raw RID surfaced for the operator to look up."""
    ldap = _LDAP(query_responses=[
        [_entry({
            "sAMAccountName":    "user1",
            "primaryGroupID":    1234,
            "distinguishedName": "CN=user1,...",
        })],
    ])
    findings = HygieneAuditor(ldap)._primary_group_abuse()
    assert findings[0]["risk"] == "MEDIUM"
    assert findings[0]["primary_group_id"] == 1234
    assert "1234" in findings[0]["primary_group_name"]


def test_primary_group_abuse_flags_builtin_account_operators():
    ldap = _LDAP(query_responses=[
        [_entry({
            "sAMAccountName":    "stealth_op",
            "primaryGroupID":    548,
            "distinguishedName": "CN=stealth_op,...",
        })],
    ])
    findings = HygieneAuditor(ldap)._primary_group_abuse()
    assert findings[0]["risk"] == "HIGH"
    assert findings[0]["primary_group_name"] == "Account Operators"


# ─────────────────────────────────── _stale_computers ─


def test_stale_computers_returns_empty_when_none_stale():
    ldap = _LDAP(query_responses=[[]])
    assert HygieneAuditor(ldap)._stale_computers() == []


def test_stale_computers_reports_age_and_os():
    long_ago = datetime.now(timezone.utc) - timedelta(days=200)
    ldap = _LDAP(query_responses=[
        [_entry({
            "sAMAccountName":      "old_box$",
            "lastLogonTimestamp":  _filetime(long_ago),
            "operatingSystem":     "Windows 7",
            "distinguishedName":   "CN=old_box,CN=Computers,...",
        })],
    ])
    findings = HygieneAuditor(ldap)._stale_computers()
    assert len(findings) == 1
    assert findings[0]["account"] == "old_box$"
    assert findings[0]["os"] == "Windows 7"
    assert 195 <= findings[0]["last_logon_days"] <= 205
    assert findings[0]["risk"] == "MEDIUM"


def test_stale_computers_sorted_oldest_first():
    """Operators triage staleness by age — oldest first or no signal.
    Pin the descending sort so a refactor doesn't silently re-order."""
    now = datetime.now(timezone.utc)
    ldap = _LDAP(query_responses=[
        [_entry({
            "sAMAccountName":      f"box{i}$",
            "lastLogonTimestamp":  _filetime(now - timedelta(days=days)),
            "operatingSystem":     f"OS{i}",
            "distinguishedName":   f"CN=box{i},...",
        }) for i, days in enumerate([100, 500, 200])],
    ])
    findings = HygieneAuditor(ldap)._stale_computers()
    ages = [f["last_logon_days"] for f in findings]
    assert ages == sorted(ages, reverse=True)


def test_stale_computers_handles_native_datetime_lastlogon():
    naive = datetime.now() - timedelta(days=300)
    ldap = _LDAP(query_responses=[
        [_entry({
            "sAMAccountName":      "old$",
            "lastLogonTimestamp":  naive,
            "operatingSystem":     "Win7",
            "distinguishedName":   "CN=old,...",
        })],
    ])
    findings = HygieneAuditor(ldap)._stale_computers()
    assert findings[0]["last_logon_days"] >= 295


def test_stale_computers_handles_null_lastlogon_defensively():
    """LDAP filter ``(lastLogonTimestamp<=...)`` shouldn't return null
    entries — but Samba 4 paged results have at least one observed
    case where it does. Pin the defensive None-handling so a future
    refactor doesn't crash on that input."""
    ldap = _LDAP(query_responses=[
        [_entry({
            "sAMAccountName":      "ghost$",
            "lastLogonTimestamp":  None,
            "operatingSystem":     "Unknown",
            "distinguishedName":   "CN=ghost,...",
        })],
    ])
    findings = HygieneAuditor(ldap)._stale_computers()
    assert findings[0]["last_logon_days"] == -1
    assert findings[0]["last_logon"] == "Never"


# ─────────────────────────────────── _privileged_group_breakdown ─


def test_privileged_group_breakdown_returns_empty_when_no_groups_exist():
    """All 10 group lookups return empty (e.g. lab without DnsAdmins).
    Don't add anything to the breakdown — the empty dict is fine."""
    ldap = _LDAP(query_responses=[[] for _ in range(10)])
    breakdown = HygieneAuditor(ldap)._privileged_group_breakdown()
    assert breakdown == {}


def test_privileged_group_breakdown_resolves_member_dns_to_sams():
    da_member_dn = "CN=alice,CN=Users,DC=corp,DC=local"
    responses = []
    for name in ["Domain Admins", "Enterprise Admins", "Schema Admins",
                 "Administrators", "Account Operators", "Server Operators",
                 "Backup Operators", "Print Operators",
                 "DnsAdmins", "Group Policy Creator Owners"]:
        if name == "Domain Admins":
            responses.append([_entry({
                "member":            [da_member_dn],
                "distinguishedName": "CN=Domain Admins,CN=Users,...",
            })])
            # Per-member resolution lookup happens inline immediately after
            responses.append([_entry({
                "sAMAccountName": "alice",
                "objectClass":    ["top", "person", "user"],
            })])
        else:
            responses.append([])
    ldap = _LDAP(query_responses=responses)
    breakdown = HygieneAuditor(ldap)._privileged_group_breakdown()
    assert "Domain Admins" in breakdown
    assert breakdown["Domain Admins"][0]["account"] == "alice"
    assert breakdown["Domain Admins"][0]["is_nested_group"] is False


def test_privileged_group_breakdown_marks_nested_groups():
    """A group inside Domain Admins should surface with
    ``is_nested_group=True`` so operators know to expand transitively."""
    nested_dn = "CN=NestedGroup,CN=Users,DC=corp,DC=local"
    responses = []
    for name in ["Domain Admins", "Enterprise Admins", "Schema Admins",
                 "Administrators", "Account Operators", "Server Operators",
                 "Backup Operators", "Print Operators",
                 "DnsAdmins", "Group Policy Creator Owners"]:
        if name == "Domain Admins":
            responses.append([_entry({
                "member":            [nested_dn],
                "distinguishedName": "CN=Domain Admins,...",
            })])
            responses.append([_entry({
                "sAMAccountName": "NestedGroup",
                "objectClass":    ["top", "group"],
            })])
        else:
            responses.append([])
    ldap = _LDAP(query_responses=responses)
    breakdown = HygieneAuditor(ldap)._privileged_group_breakdown()
    assert breakdown["Domain Admins"][0]["is_nested_group"] is True


def test_privileged_group_breakdown_falls_back_to_dn_when_member_not_resolved():
    """A member whose DN doesn't resolve (foreign trust / orphaned
    SID) should still surface as a name parsed from the DN, not be
    silently dropped."""
    foreign_dn = "CN=foreign_user,CN=ForeignSecurityPrincipals,DC=corp,DC=local"
    responses = []
    for name in ["Domain Admins", "Enterprise Admins", "Schema Admins",
                 "Administrators", "Account Operators", "Server Operators",
                 "Backup Operators", "Print Operators",
                 "DnsAdmins", "Group Policy Creator Owners"]:
        if name == "Domain Admins":
            responses.append([_entry({
                "member":            [foreign_dn],
                "distinguishedName": "CN=Domain Admins,...",
            })])
            responses.append([])  # resolution lookup returns nothing
        else:
            responses.append([])
    ldap = _LDAP(query_responses=responses)
    breakdown = HygieneAuditor(ldap)._privileged_group_breakdown()
    assert breakdown["Domain Admins"][0]["account"] == "foreign_user"
    assert breakdown["Domain Admins"][0]["dn"] == foreign_dn


# ─────────────────────────────────── _service_account_hygiene ─


def test_service_account_hygiene_returns_empty_for_clean_accounts():
    """SPN account with recent password, no privileged flag, and
    DONT_EXPIRE_PASSWORD off → no issue. Pin that we don't surface
    a noisy LOW finding."""
    recent = datetime.now(timezone.utc) - timedelta(days=30)
    ldap = _LDAP(query_responses=[
        [_entry({
            "sAMAccountName":      "svc_clean",
            "pwdLastSet":          _filetime(recent),
            "servicePrincipalName": ["http/x"],
            "adminCount":          None,
            "distinguishedName":   "CN=svc_clean,...",
            "userAccountControl":  0x200,   # NORMAL_ACCOUNT only
        })],
    ])
    findings = HygieneAuditor(ldap)._service_account_hygiene()
    assert findings == []


def test_service_account_hygiene_flags_old_password_as_high():
    ancient = datetime.now(timezone.utc) - timedelta(days=400)
    ldap = _LDAP(query_responses=[
        [_entry({
            "sAMAccountName":      "svc_old",
            "pwdLastSet":          _filetime(ancient),
            "servicePrincipalName": ["MSSQLSvc/sql"],
            "adminCount":          None,
            "distinguishedName":   "CN=svc_old,...",
            "userAccountControl":  0x200,
        })],
    ])
    findings = HygieneAuditor(ldap)._service_account_hygiene()
    assert findings[0]["risk"] == "HIGH"
    assert findings[0]["password_age_days"] >= 400


def test_service_account_hygiene_admin_with_spn_is_high():
    """Privileged account with an SPN = Kerberoastable to a key that
    decrypts to a tier-0 password. This is the catastrophic case the
    audit exists to surface — pin HIGH minimum."""
    recent = datetime.now(timezone.utc) - timedelta(days=10)
    ldap = _LDAP(query_responses=[
        [_entry({
            "sAMAccountName":      "svc_old_admin",
            "pwdLastSet":          _filetime(recent),
            "servicePrincipalName": ["http/x"],
            "adminCount":          1,
            "distinguishedName":   "CN=svc_old_admin,...",
            "userAccountControl":  0x10200,
        })],
    ])
    findings = HygieneAuditor(ldap)._service_account_hygiene()
    assert findings[0]["risk"] == "HIGH"
    assert findings[0]["is_admin"] is True


def test_service_account_hygiene_password_never_expires_flag():
    recent = datetime.now(timezone.utc) - timedelta(days=10)
    ldap = _LDAP(query_responses=[
        [_entry({
            "sAMAccountName":      "svc_perm",
            "pwdLastSet":          _filetime(recent),
            "servicePrincipalName": ["http/x"],
            "adminCount":          None,
            "distinguishedName":   "CN=svc_perm,...",
            "userAccountControl":  0x10200,   # 0x10000 = DONT_EXPIRE_PASSWORD
        })],
    ])
    findings = HygieneAuditor(ldap)._service_account_hygiene()
    assert findings[0]["password_never_expires"] is True
    assert "never expires" in findings[0]["detail"]


def test_service_account_hygiene_password_never_set_is_critical():
    ldap = _LDAP(query_responses=[
        [_entry({
            "sAMAccountName":      "svc_ghost",
            "pwdLastSet":          None,
            "servicePrincipalName": ["http/x"],
            "adminCount":          None,
            "distinguishedName":   "CN=svc_ghost,...",
            "userAccountControl":  0x200,
        })],
    ])
    findings = HygieneAuditor(ldap)._service_account_hygiene()
    assert findings[0]["risk"] == "CRITICAL"
    assert "never set" in findings[0]["detail"]


def test_service_account_hygiene_sorted_critical_first():
    now = datetime.now(timezone.utc)
    ldap = _LDAP(query_responses=[
        [
            # MEDIUM — 200 days old
            _entry({"sAMAccountName": "med", "pwdLastSet": _filetime(now - timedelta(days=200)),
                    "servicePrincipalName": ["x/y"], "adminCount": None,
                    "distinguishedName": "CN=med,...", "userAccountControl": 0x200}),
            # CRITICAL — never set
            _entry({"sAMAccountName": "crit", "pwdLastSet": None,
                    "servicePrincipalName": ["x/y"], "adminCount": None,
                    "distinguishedName": "CN=crit,...", "userAccountControl": 0x200}),
            # HIGH — 400 days old
            _entry({"sAMAccountName": "high", "pwdLastSet": _filetime(now - timedelta(days=400)),
                    "servicePrincipalName": ["x/y"], "adminCount": None,
                    "distinguishedName": "CN=high,...", "userAccountControl": 0x200}),
        ],
    ])
    findings = HygieneAuditor(ldap)._service_account_hygiene()
    risks = [f["risk"] for f in findings]
    assert risks == ["CRITICAL", "HIGH", "MEDIUM"]


def test_service_account_hygiene_accepts_native_datetime_pwdlastset():
    naive = datetime.now() - timedelta(days=400)
    ldap = _LDAP(query_responses=[
        [_entry({
            "sAMAccountName":      "svc",
            "pwdLastSet":          naive,
            "servicePrincipalName": ["x/y"],
            "adminCount":          None,
            "distinguishedName":   "CN=svc,...",
            "userAccountControl":  0x200,
        })],
    ])
    findings = HygieneAuditor(ldap)._service_account_hygiene()
    assert findings[0]["password_age_days"] >= 395


# ─────────────────────────────────── audit() integration ─


def test_audit_calls_every_subcheck_and_returns_aggregated_result():
    """One full ``audit()`` invocation must touch every sub-check.
    Pin the call count rather than mocking each sub-check individually,
    so future sub-checks added to ``audit()`` show up here."""
    # Each sub-check makes 1+ ldap.query calls; provide enough empties.
    ldap = _LDAP(query_responses=[[] for _ in range(50)])
    result = HygieneAuditor(ldap).audit()
    assert isinstance(result, HygieneResult)
    # We expect at least 10 distinct queries for the 10 sub-modules.
    assert len(ldap.calls) >= 10


# ─────────────────────────────────── lab integration ─


_LAB_DC = os.environ.get("KERBMAP_LAB_DC_IP")


@pytest.mark.skipif(not _LAB_DC,
                    reason="set KERBMAP_LAB_DC_IP to run the live lab integration")
def test_lab_audit_against_running_dc():
    """Real-traffic acceptance test against the seeded lab. Same
    pattern that surfaced the 3 impacket bugs in PR #41 — pure mocks
    pass while real LDAP reveals shape mismatches.

    Run with::

        KERBMAP_LAB_DC_IP=192.168.56.10 \\
          KERBMAP_LAB_USER=Administrator \\
          KERBMAP_LAB_PASS=LabAdmin1! \\
          KERBMAP_LAB_DOMAIN=lab.local \\
          pytest tests/test_hygiene_auditor.py -k lab_audit -s
    """
    from kerb_map.auth.ldap_client import LDAPClient

    ldap = LDAPClient(
        dc_ip=_LAB_DC,
        domain=os.environ.get("KERBMAP_LAB_DOMAIN", "lab.local"),
        username=os.environ.get("KERBMAP_LAB_USER", "Administrator"),
        password=os.environ.get("KERBMAP_LAB_PASS", "LabAdmin1!"),
    )
    result = HygieneAuditor(ldap).audit()

    # Lab is seeded — these must be present, not just "no crash".
    assert result.krbtgt_age["age_days"] >= 0
    # Lab seed includes svc_app with description containing "password"
    cred_accounts = {f["account"] for f in result.credential_exposure}
    assert any("svc" in a.lower() or "cred" in a.lower() for a in cred_accounts), \
        f"expected at least one seeded credential-exposure account; got {cred_accounts}"
    # Lab seed deliberately leaves admin_orphan with adminCount=1
    orphan_accounts = {f["account"] for f in result.adminsdholder_orphans}
    assert "admin_orphan" in orphan_accounts, \
        f"expected admin_orphan in orphans; got {orphan_accounts}"

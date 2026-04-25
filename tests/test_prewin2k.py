"""Pre-Windows 2000 Compatible Access module tests."""

from unittest.mock import MagicMock

from kerb_map.modules.prewin2k import (
    SID_ANONYMOUS_LOGON,
    SID_AUTHENTICATED_USERS,
    SID_EVERYONE,
    PreWin2kAccess,
    ds_heuristics_allows_anonymous,
)
from kerb_map.plugin import ScanContext


def _entry(values: dict):
    e = MagicMock()
    e.__contains__ = lambda self, k: k in values
    def _get(self, k):
        v = values[k]
        m = MagicMock()
        m.value = v
        m.values = v if isinstance(v, list) else [v]
        return m
    e.__getitem__ = _get
    return e


def _ctx(query_responses, *, query_config_responses=None):
    """ldap.query queue covers (1) the Pre-Win2k group lookup and
    (2..N) per-member resolution. ldap.query_config covers dSHeuristics."""
    ldap = MagicMock()
    qq = list(query_responses)
    ldap.query.side_effect = lambda **_: qq.pop(0) if qq else []
    qc = list(query_config_responses or [])
    ldap.query_config.side_effect = lambda **_: qc.pop(0) if qc else []
    return ScanContext(
        ldap=ldap,
        domain="corp.local",
        base_dn="DC=corp,DC=local",
        dc_ip="10.0.0.1",
        domain_sid="S-1-5-21-1-2-3",
    )


def _foreign_sp_entry(sid: str):
    return _entry({
        "objectClass": ["top", "foreignSecurityPrincipal"],
        "cn":          sid,
        "sAMAccountName": None,
        "objectSid":   None,
    })


# ────────────────────────────────────────────── group missing ────


def test_group_missing_returns_inapplicable():
    """Both the Builtin lookup AND the SID fallback come back empty."""
    ctx = _ctx([[], []])
    result = PreWin2kAccess().scan(ctx)
    assert result.findings == []
    assert result.raw["applicable"] is False


# ────────────────────────────────────────────── Auth Users ───────


def test_auth_users_in_group_is_high():
    """The Microsoft-default state on Server 2022/2025."""
    grp = _entry({
        "distinguishedName": "CN=Pre-Windows 2000 Compatible Access,CN=Builtin,DC=corp,DC=local",
        "objectSid":         b"\x01\x02\x00\x00\x00\x00\x00\x05\x20\x00\x00\x00\x2a\x02\x00\x00",
        "member":            ["CN=S-1-5-11,CN=ForeignSecurityPrincipals,DC=corp,DC=local"],
    })
    member = _foreign_sp_entry(SID_AUTHENTICATED_USERS)

    ctx = _ctx([[grp], [member]])
    result = PreWin2kAccess().scan(ctx)
    high = [f for f in result.findings if f.severity == "HIGH"]
    assert len(high) == 1
    assert "Authenticated Users" in high[0].attack
    assert high[0].priority == 78
    assert "net user" in high[0].reason or "RID" in high[0].reason or "enumeration" in high[0].reason


def test_anonymous_in_group_is_critical():
    grp = _entry({
        "distinguishedName": "CN=Pre-Windows 2000 Compatible Access,CN=Builtin,...",
        "objectSid":         b"\x01\x02",
        "member":            ["CN=S-1-5-7,CN=ForeignSecurityPrincipals,DC=corp,DC=local"],
    })
    member = _foreign_sp_entry(SID_ANONYMOUS_LOGON)

    ctx = _ctx([[grp], [member]])
    result = PreWin2kAccess().scan(ctx)
    crit = [f for f in result.findings if f.severity == "CRITICAL"]
    assert len(crit) == 1
    assert "Anonymous" in crit[0].attack
    assert crit[0].priority == 95
    assert "rpcclient" in crit[0].next_step or "nxc" in crit[0].next_step


# ──────────────────────────────────── compound dsHeuristics finding ─


def test_anonymous_binds_plus_auth_users_compounds_to_critical():
    """dsHeuristics char 7 = '2' AND Auth Users in Pre-Win2k = full
    unauthenticated directory dump. Should add the compound CRITICAL
    finding on top of the per-member ones."""
    grp = _entry({
        "distinguishedName": "CN=Pre-Windows 2000 Compatible Access,...",
        "objectSid":         b"\x01\x02",
        "member":            ["CN=S-1-5-11,CN=ForeignSecurityPrincipals,DC=corp,DC=local"],
    })
    member = _foreign_sp_entry(SID_AUTHENTICATED_USERS)
    ds = _entry({"dSHeuristics": "0000002"})  # 7 chars, last is '2'

    ctx = _ctx([[grp], [member]], query_config_responses=[[ds]])
    result = PreWin2kAccess().scan(ctx)
    compound = [f for f in result.findings if "Anonymous LDAP" in f.attack]
    assert len(compound) == 1
    assert compound[0].severity == "CRITICAL"
    assert compound[0].priority == 96


# ─────────────────────────────────── non-default principal ───────


def test_random_principal_in_group_is_medium():
    """A specific account added to the group later — operator probably
    did it intentionally, but worth surfacing."""
    grp = _entry({
        "distinguishedName": "CN=Pre-Windows 2000 Compatible Access,...",
        "objectSid":         b"\x01\x02",
        "member":            ["CN=svc_legacy,CN=Users,DC=corp,DC=local"],
    })
    user = _entry({
        "objectClass":      ["user"],
        "cn":               "svc_legacy",
        "sAMAccountName":   "svc_legacy",
        "objectSid":        b"\x01\x05\x00\x00\x00\x00\x00\x05\x15\x00\x00\x00"
                            b"\x01\x00\x00\x00\x02\x00\x00\x00\x03\x00\x00\x00"
                            b"\xd2\x04\x00\x00",
    })

    ctx = _ctx([[grp], [user]])
    result = PreWin2kAccess().scan(ctx)
    med = [f for f in result.findings if f.severity == "MEDIUM"]
    assert len(med) == 1
    assert "non-default" in med[0].attack.lower()
    assert "svc_legacy" in med[0].reason


# ────────────────────────────────── ds_heuristics parsing ────────


def test_ds_heuristics_anonymous_bit_detection():
    # Position 7 (1-indexed) = index 6 in Python.
    assert ds_heuristics_allows_anonymous("0000002")     # char 7 = '2'
    assert ds_heuristics_allows_anonymous("0000002extra")
    assert not ds_heuristics_allows_anonymous("0000000") # char 7 = '0'
    assert not ds_heuristics_allows_anonymous("0000001") # char 7 = '1'
    assert not ds_heuristics_allows_anonymous("000000")  # too short
    assert not ds_heuristics_allows_anonymous("")
    assert not ds_heuristics_allows_anonymous(None)


# ───────────────────────────────────── empty group is clean ─────


def test_empty_group_emits_no_findings():
    grp = _entry({
        "distinguishedName": "CN=Pre-Windows 2000 Compatible Access,...",
        "objectSid":         b"\x01\x02",
        "member":            [],
    })
    ctx = _ctx([[grp]])
    result = PreWin2kAccess().scan(ctx)
    assert result.findings == []
    assert result.raw["applicable"] is True
    assert result.raw["summary"]["members_total"] == 0

"""BadSuccessor (CVE-2025-53779) module tests.

Same mocked-LDAP strategy. Lab acceptance ("Server 2025 lab, plant a
DA-precessor link, scan flags CRITICAL") deferred until lab is up.
"""

from unittest.mock import MagicMock

from kerb_map.acl import (
    ADS_RIGHT_DS_CREATE_CHILD,
    ADS_RIGHT_GENERIC_ALL,
    OBJECT_CLASS_DMSA,
    AceMatch,
)
from kerb_map.modules.badsuccessor import SERVER_2025_FL, BadSuccessor
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


def _ctx(query_responses, *, fl: int = SERVER_2025_FL):
    ldap = MagicMock()
    queue = list(query_responses)
    ldap.query.side_effect = lambda **_: queue.pop(0) if queue else []
    return ScanContext(
        ldap=ldap,
        domain="corp.local",
        base_dn="DC=corp,DC=local",
        dc_ip="10.0.0.1",
        domain_sid="S-1-5-21-1-2-3",
        domain_info={"fl_int": fl},
    )


# ────────────────────────────────────────────── functional-level gate ----


def test_pre_2025_domain_returns_inapplicable():
    ctx = _ctx([], fl=7)  # 2016/2019/2022
    result = BadSuccessor().scan(ctx)
    assert result.findings == []
    assert result.raw["applicable"] is False
    assert "10" in result.raw["reason"]


def test_2025_domain_runs_full_audit():
    ctx = _ctx([[], []])  # both queries empty
    result = BadSuccessor().scan(ctx)
    assert result.raw["applicable"] is True
    assert result.raw["functional_level"] == 10


# ────────────────────────────────────── existing dMSA → predecessor link ----


def test_dmsa_pointing_at_da_is_critical():
    """Akamai's reference attack: dMSA whose predecessor link points
    at a Domain Admin = staged BadSuccessor. CRITICAL."""
    dmsa = _entry({
        "sAMAccountName":                       "kerbmap_dmsa$",
        "distinguishedName":                    "CN=kerbmap_dmsa,OU=Lab,DC=corp,DC=local",
        "msDS-ManagedAccountPrecededByLink":    ["CN=Administrator,CN=Users,DC=corp,DC=local"],
        "msDS-DelegatedMSAState":               2,
        "whenCreated":                          "2026-04-25T10:00:00Z",
    })
    da = _entry({
        "sAMAccountName": "Administrator",
        "memberOf":       ["CN=Domain Admins,CN=Users,DC=corp,DC=local"],
        "adminCount":     1,
    })

    ctx = _ctx([
        [dmsa],         # objectClass=msDS-DelegatedManagedServiceAccount query
        [da],           # predecessor lookup
        [],             # OU audit query
    ])
    result = BadSuccessor().scan(ctx)
    assert any(f.severity == "CRITICAL" and "BadSuccessor (staged)" in f.attack
               for f in result.findings)
    crit = [f for f in result.findings if f.severity == "CRITICAL"][0]
    assert crit.priority == 98
    assert "Administrator" in crit.reason
    assert "getST.py" in crit.next_step


def test_dmsa_with_unprivileged_predecessor_is_inventory_only():
    """A dMSA pointing at a normal user is unusual but not a finding —
    it shows up in raw output for review."""
    dmsa = _entry({
        "sAMAccountName":                       "svc_dmsa$",
        "distinguishedName":                    "CN=svc_dmsa,OU=Services,DC=corp,DC=local",
        "msDS-ManagedAccountPrecededByLink":    ["CN=svc_old,OU=Services,DC=corp,DC=local"],
        "msDS-DelegatedMSAState":               2,
        "whenCreated":                          None,
    })
    boring = _entry({
        "sAMAccountName": "svc_old",
        "memberOf":       [],
        "adminCount":     None,
    })

    ctx = _ctx([[dmsa], [boring], []])
    result = BadSuccessor().scan(ctx)
    assert all(f.attack != "BadSuccessor (staged)" for f in result.findings)
    assert len(result.raw["existing_dmsas"]) == 1
    assert result.raw["summary"]["with_privileged_predecessor"] == 0


# ────────────────────────────────────────────── OU CreateChild audit ----


def test_ou_create_child_by_non_default_principal_is_high(monkeypatch):
    """Random user with CreateChild on an OU on a Server 2025 domain
    can stage BadSuccessor. HIGH (priority 88)."""
    ou = _entry({
        "distinguishedName":  "OU=Lab,DC=corp,DC=local",
        "nTSecurityDescriptor": b"<sd>",
    })
    monkeypatch.setattr("kerb_map.modules.badsuccessor.parse_sd", lambda raw: object())
    monkeypatch.setattr(
        "kerb_map.modules.badsuccessor.walk_aces",
        lambda sd, object_dn="": [
            AceMatch(object_dn=object_dn, trustee_sid="S-1-5-21-1-2-3-1500",
                     access_mask=ADS_RIGHT_DS_CREATE_CHILD,
                     object_type_guid=OBJECT_CLASS_DMSA, ace_type=0x05),
        ])
    monkeypatch.setattr(
        "kerb_map.modules.badsuccessor.resolve_sids",
        lambda ldap, sids, base_dn: {
            "S-1-5-21-1-2-3-1500": {"sAMAccountName": "ou_admin",
                                    "distinguishedName": "...", "objectClass": "user"}})

    ctx = _ctx([[], [ou]])
    result = BadSuccessor().scan(ctx)
    ou_findings = [f for f in result.findings if f.attack == "BadSuccessor (writable OU)"]
    assert len(ou_findings) == 1
    f = ou_findings[0]
    assert f.severity == "HIGH"
    assert f.priority == 88
    assert "ou_admin" in f.target
    assert "OU=Lab" in f.target
    assert "PrecededByLink" in f.next_step or "PrecededByLink" in f.next_step


def test_ou_with_well_known_writer_only_is_clean(monkeypatch):
    """Domain Admins having CreateChild everywhere = expected. No finding."""
    ou = _entry({"distinguishedName": "OU=Lab,DC=corp,DC=local",
                 "nTSecurityDescriptor": b"<sd>"})
    monkeypatch.setattr("kerb_map.modules.badsuccessor.parse_sd", lambda raw: object())
    monkeypatch.setattr(
        "kerb_map.modules.badsuccessor.walk_aces",
        lambda sd, object_dn="": [
            AceMatch(object_dn=object_dn, trustee_sid="S-1-5-21-1-2-3-512",
                     access_mask=ADS_RIGHT_GENERIC_ALL,
                     object_type_guid=None, ace_type=0x00),
        ])
    ctx = _ctx([[], [ou]])
    result = BadSuccessor().scan(ctx)
    ou_findings = [f for f in result.findings if f.attack == "BadSuccessor (writable OU)"]
    assert ou_findings == []
    assert result.raw["summary"]["ous_with_non_default_writer"] == 0


def test_create_child_for_other_class_does_not_match(monkeypatch):
    """CreateChild scoped to a non-dMSA class (e.g., user) shouldn't
    trip BadSuccessor — it's a different attack path."""
    ou = _entry({"distinguishedName": "OU=Lab,DC=corp,DC=local",
                 "nTSecurityDescriptor": b"<sd>"})
    monkeypatch.setattr("kerb_map.modules.badsuccessor.parse_sd", lambda raw: object())
    monkeypatch.setattr(
        "kerb_map.modules.badsuccessor.walk_aces",
        lambda sd, object_dn="": [
            AceMatch(object_dn=object_dn, trustee_sid="S-1-5-21-1-2-3-1500",
                     access_mask=ADS_RIGHT_DS_CREATE_CHILD,
                     object_type_guid="bf967aba-0de6-11d0-a285-00aa003049e2",  # user class
                     ace_type=0x05),
        ])
    ctx = _ctx([[], [ou]])
    result = BadSuccessor().scan(ctx)
    assert all(f.attack != "BadSuccessor (writable OU)" for f in result.findings)

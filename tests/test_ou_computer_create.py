"""OU computer-create rights audit (brief §4.7).

Mocked-LDAP unit tests pinning the contract:
  - CreateChild(computer) on an OU, granted to a non-default principal,
    is a HIGH finding (an RBCD pivot survives MAQ=0 hardening).
  - GenericAll on an OU is CRITICAL (full container takeover subsumes
    create-computer).
  - Authenticated Users on the default CN=Computers container is
    suppressed — that's the MAQ pathway, owned by NoPac/Certifried.
  - Account Operators is suppressed — Tier-0 audit owns that question.
  - MAQ context shapes the *reason* / *next_step* but not the severity:
    even with MAQ=10 the ACE is the post-hardening pivot we want
    operators to know about.
"""

from unittest.mock import MagicMock

from kerb_map.acl import (
    ADS_RIGHT_DS_CREATE_CHILD,
    ADS_RIGHT_GENERIC_ALL,
    OBJECT_CLASS_COMPUTER,
    AceMatch,
)
from kerb_map.modules.ou_computer_create import OuComputerCreate
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


def _ou(name="HelpdeskOU", dn=None, sd=b"<sd>"):
    return _entry({
        "ou":                 name,
        "distinguishedName":  dn or f"OU={name},DC=corp,DC=local",
        "nTSecurityDescriptor": sd,
    })


def _computers_container(sd=b"<sd>"):
    return _entry({
        "cn":                 "Computers",
        "distinguishedName":  "CN=Computers,DC=corp,DC=local",
        "nTSecurityDescriptor": sd,
    })


def _ctx(query_responses, *, maq=10):
    """Drive ldap.query from a queue. The module makes two query calls
    in this order: OUs first, then the default Computers container."""
    ldap = MagicMock()
    qq = list(query_responses)
    ldap.query.side_effect = lambda **_: qq.pop(0) if qq else []
    return ScanContext(
        ldap=ldap,
        domain="corp.local",
        base_dn="DC=corp,DC=local",
        dc_ip="10.0.0.1",
        domain_sid="S-1-5-21-1-2-3",
        domain_info={"machine_account_quota": maq},
    )


# ────────────────────────────────────────────── module gating ────


def test_no_ous_and_no_computers_container_returns_inapplicable():
    ctx = _ctx([[], []])  # no OUs, no Computers container
    result = OuComputerCreate().scan(ctx)
    assert result.findings == []
    assert result.raw["applicable"] is False


# ────────────────────────────────────────────── HIGH path ────────


def test_create_child_computer_to_non_default_is_high(monkeypatch):
    """The headline finding: a helpdesk-style account holding
    CreateChild(computer) on an OU is a HIGH RBCD pivot regardless
    of MAQ."""
    ou = _ou("HelpdeskOU")
    monkeypatch.setattr("kerb_map.modules.ou_computer_create.parse_sd",
                        lambda raw: object() if raw else None)
    monkeypatch.setattr(
        "kerb_map.modules.ou_computer_create.walk_aces",
        lambda sd, object_dn="": [
            AceMatch(object_dn=object_dn,
                     trustee_sid="S-1-5-21-1-2-3-1900",  # non-default
                     access_mask=ADS_RIGHT_DS_CREATE_CHILD,
                     object_type_guid=OBJECT_CLASS_COMPUTER,
                     ace_type=0x05),
        ])
    monkeypatch.setattr(
        "kerb_map.modules.ou_computer_create.resolve_sids",
        lambda ldap, sids, base_dn: {
            "S-1-5-21-1-2-3-1900": {"sAMAccountName": "helpdesk_op",
                                    "distinguishedName": "...",
                                    "objectClass": "user"}})

    ctx = _ctx([[ou], []], maq=0)  # MAQ=0 → finding is the post-hardening pivot
    result = OuComputerCreate().scan(ctx)
    assert len(result.findings) == 1
    f = result.findings[0]
    assert f.severity == "HIGH"
    assert f.priority == 86
    assert "CreateChild(computer)" in f.attack
    assert "helpdesk_op" in f.reason
    assert "MAQ=0" in f.reason
    assert "addcomputer" in f.next_step.lower()


def test_create_child_any_class_is_high(monkeypatch):
    """Un-typed CreateChild ACE (no object_type_guid) covers all child
    classes including computer — same severity as scoped CreateChild."""
    ou = _ou("WildOU")
    monkeypatch.setattr("kerb_map.modules.ou_computer_create.parse_sd",
                        lambda raw: object() if raw else None)
    monkeypatch.setattr(
        "kerb_map.modules.ou_computer_create.walk_aces",
        lambda sd, object_dn="": [
            AceMatch(object_dn=object_dn,
                     trustee_sid="S-1-5-21-1-2-3-1901",
                     access_mask=ADS_RIGHT_DS_CREATE_CHILD,
                     object_type_guid=None,   # un-typed = all classes
                     ace_type=0x00),
        ])
    monkeypatch.setattr(
        "kerb_map.modules.ou_computer_create.resolve_sids",
        lambda *a, **kw: {"S-1-5-21-1-2-3-1901":
                          {"sAMAccountName": "auto_join_svc"}})

    ctx = _ctx([[ou], []])
    result = OuComputerCreate().scan(ctx)
    assert len(result.findings) == 1
    assert "CreateChild(any)" in result.findings[0].attack
    assert result.findings[0].severity == "HIGH"


# ────────────────────────────────────────────── CRITICAL path ────


def test_generic_all_on_ou_is_critical(monkeypatch):
    """GenericAll on the OU subsumes create-computer (and everything
    else) — CRITICAL with priority 90."""
    ou = _ou("FullCtrlOU")
    monkeypatch.setattr("kerb_map.modules.ou_computer_create.parse_sd",
                        lambda raw: object() if raw else None)
    monkeypatch.setattr(
        "kerb_map.modules.ou_computer_create.walk_aces",
        lambda sd, object_dn="": [
            AceMatch(object_dn=object_dn,
                     trustee_sid="S-1-5-21-1-2-3-1902",
                     access_mask=ADS_RIGHT_GENERIC_ALL,
                     object_type_guid=None, ace_type=0x00),
        ])
    monkeypatch.setattr(
        "kerb_map.modules.ou_computer_create.resolve_sids",
        lambda *a, **kw: {"S-1-5-21-1-2-3-1902":
                          {"sAMAccountName": "ou_owner"}})

    ctx = _ctx([[ou], []])
    result = OuComputerCreate().scan(ctx)
    assert len(result.findings) == 1
    f = result.findings[0]
    assert f.severity == "CRITICAL"
    assert f.priority == 90
    assert "GenericAll" in f.attack


# ────────────────────────────────────────────── suppressions ─────


def test_well_known_privileged_writer_suppressed(monkeypatch):
    """Domain Admins / SYSTEM / EAs holding CreateChild on an OU is
    by design — never a finding."""
    ou = _ou("AnyOU")
    monkeypatch.setattr("kerb_map.modules.ou_computer_create.parse_sd",
                        lambda raw: object() if raw else None)
    monkeypatch.setattr(
        "kerb_map.modules.ou_computer_create.walk_aces",
        lambda sd, object_dn="": [
            AceMatch(object_dn=object_dn,
                     trustee_sid="S-1-5-21-1-2-3-512",  # Domain Admins
                     access_mask=ADS_RIGHT_GENERIC_ALL,
                     object_type_guid=None, ace_type=0x00),
            AceMatch(object_dn=object_dn,
                     trustee_sid="S-1-5-18",  # SYSTEM
                     access_mask=ADS_RIGHT_DS_CREATE_CHILD,
                     object_type_guid=OBJECT_CLASS_COMPUTER, ace_type=0x05),
        ])
    monkeypatch.setattr(
        "kerb_map.modules.ou_computer_create.resolve_sids", lambda *a, **kw: {})

    ctx = _ctx([[ou], []])
    result = OuComputerCreate().scan(ctx)
    assert result.findings == []


def test_account_operators_suppressed(monkeypatch):
    """Account Operators (S-1-5-32-548) is designed to hold CreateChild
    by default. Tier-0 ACL audit owns the membership question; this
    module just suppresses the noise."""
    ou = _ou("UsersOU")
    monkeypatch.setattr("kerb_map.modules.ou_computer_create.parse_sd",
                        lambda raw: object() if raw else None)
    monkeypatch.setattr(
        "kerb_map.modules.ou_computer_create.walk_aces",
        lambda sd, object_dn="": [
            AceMatch(object_dn=object_dn,
                     trustee_sid="S-1-5-32-548",  # Account Operators
                     access_mask=ADS_RIGHT_DS_CREATE_CHILD,
                     object_type_guid=OBJECT_CLASS_COMPUTER, ace_type=0x05),
        ])
    monkeypatch.setattr(
        "kerb_map.modules.ou_computer_create.resolve_sids", lambda *a, **kw: {})

    ctx = _ctx([[ou], []])
    result = OuComputerCreate().scan(ctx)
    assert result.findings == []


def test_authenticated_users_on_default_computers_container_suppressed(monkeypatch):
    """Authenticated Users → CreateChild(computer) on CN=Computers is
    the *MAQ pathway*. NoPac / Certifried scanners report it from the
    MAQ angle; this module would just double-flag."""
    container = _computers_container()
    monkeypatch.setattr("kerb_map.modules.ou_computer_create.parse_sd",
                        lambda raw: object() if raw else None)
    monkeypatch.setattr(
        "kerb_map.modules.ou_computer_create.walk_aces",
        lambda sd, object_dn="": [
            AceMatch(object_dn=object_dn,
                     trustee_sid="S-1-5-11",  # Authenticated Users
                     access_mask=ADS_RIGHT_DS_CREATE_CHILD,
                     object_type_guid=OBJECT_CLASS_COMPUTER, ace_type=0x05),
        ])
    monkeypatch.setattr(
        "kerb_map.modules.ou_computer_create.resolve_sids", lambda *a, **kw: {})

    ctx = _ctx([[], [container]])
    result = OuComputerCreate().scan(ctx)
    assert result.findings == []


def test_authenticated_users_on_custom_ou_is_NOT_suppressed(monkeypatch):
    """Suppression for Authenticated Users only applies to the *default*
    CN=Computers container. If an admin granted Authenticated Users
    CreateChild(computer) on a custom OU, that's a real finding —
    the MAQ-pathway suppression doesn't apply."""
    ou = _ou("RogueOU")
    monkeypatch.setattr("kerb_map.modules.ou_computer_create.parse_sd",
                        lambda raw: object() if raw else None)
    monkeypatch.setattr(
        "kerb_map.modules.ou_computer_create.walk_aces",
        lambda sd, object_dn="": [
            AceMatch(object_dn=object_dn,
                     trustee_sid="S-1-5-11",  # Authenticated Users
                     access_mask=ADS_RIGHT_DS_CREATE_CHILD,
                     object_type_guid=OBJECT_CLASS_COMPUTER, ace_type=0x05),
        ])
    monkeypatch.setattr(
        "kerb_map.modules.ou_computer_create.resolve_sids",
        lambda *a, **kw: {"S-1-5-11":
                          {"sAMAccountName": "Authenticated Users"}})

    ctx = _ctx([[ou], []])
    result = OuComputerCreate().scan(ctx)
    assert len(result.findings) == 1
    assert "Authenticated Users" in result.findings[0].reason


# ────────────────────────────────────────────── MAQ context ──────


def test_reason_text_differs_when_maq_is_zero_vs_nonzero(monkeypatch):
    """MAQ context shapes the reason: MAQ=0 → 'survives the hardening',
    MAQ>0 → 'informational unless MAQ later set to 0'. Severity is
    unchanged because the operator-impact is identical."""
    ou = _ou("HelpdeskOU")
    monkeypatch.setattr("kerb_map.modules.ou_computer_create.parse_sd",
                        lambda raw: object() if raw else None)
    monkeypatch.setattr(
        "kerb_map.modules.ou_computer_create.walk_aces",
        lambda sd, object_dn="": [
            AceMatch(object_dn=object_dn,
                     trustee_sid="S-1-5-21-1-2-3-1903",
                     access_mask=ADS_RIGHT_DS_CREATE_CHILD,
                     object_type_guid=OBJECT_CLASS_COMPUTER, ace_type=0x05),
        ])
    monkeypatch.setattr(
        "kerb_map.modules.ou_computer_create.resolve_sids",
        lambda *a, **kw: {"S-1-5-21-1-2-3-1903":
                          {"sAMAccountName": "helpdesk_op"}})

    ctx_hardened = _ctx([[ou], []], maq=0)
    f_hard = OuComputerCreate().scan(ctx_hardened).findings[0]
    assert "survives" in f_hard.reason.lower()
    assert f_hard.severity == "HIGH"

    # Re-mock for the second call (queue is exhausted).
    ctx_default = _ctx([[ou], []], maq=10)
    f_def = OuComputerCreate().scan(ctx_default).findings[0]
    assert "MAQ=10" in f_def.reason
    assert f_def.severity == "HIGH"  # unchanged


def test_unknown_maq_defaults_to_ten(monkeypatch):
    """Missing MAQ in domain_info → assume the AD default (10) so
    the reason text doesn't break."""
    ou = _ou("OU1")
    monkeypatch.setattr("kerb_map.modules.ou_computer_create.parse_sd",
                        lambda raw: object() if raw else None)
    monkeypatch.setattr(
        "kerb_map.modules.ou_computer_create.walk_aces",
        lambda sd, object_dn="": [
            AceMatch(object_dn=object_dn,
                     trustee_sid="S-1-5-21-1-2-3-1904",
                     access_mask=ADS_RIGHT_DS_CREATE_CHILD,
                     object_type_guid=OBJECT_CLASS_COMPUTER, ace_type=0x05),
        ])
    monkeypatch.setattr(
        "kerb_map.modules.ou_computer_create.resolve_sids",
        lambda *a, **kw: {"S-1-5-21-1-2-3-1904":
                          {"sAMAccountName": "svc_join"}})

    ldap = MagicMock()
    qq = [[ou], []]
    ldap.query.side_effect = lambda **_: qq.pop(0) if qq else []
    ctx = ScanContext(ldap=ldap, domain="corp.local",
                      base_dn="DC=corp,DC=local", dc_ip="10.0.0.1",
                      domain_sid="S-1-5-21-1-2-3",
                      domain_info={})  # no MAQ key
    f = OuComputerCreate().scan(ctx).findings[0]
    assert "MAQ=10" in f.reason


# ────────────────────────────────────────────── data shape ───────


def test_finding_data_carries_writer_and_target_for_bloodhound(monkeypatch):
    """The BH CE exporter consumes finding.data — pin the keys it
    needs (writer_sid, target_dn, right) so the exporter contract
    stays intact."""
    ou = _ou("HelpdeskOU", dn="OU=Helpdesk,DC=corp,DC=local")
    monkeypatch.setattr("kerb_map.modules.ou_computer_create.parse_sd",
                        lambda raw: object() if raw else None)
    monkeypatch.setattr(
        "kerb_map.modules.ou_computer_create.walk_aces",
        lambda sd, object_dn="": [
            AceMatch(object_dn=object_dn,
                     trustee_sid="S-1-5-21-1-2-3-1905",
                     access_mask=ADS_RIGHT_DS_CREATE_CHILD,
                     object_type_guid=OBJECT_CLASS_COMPUTER, ace_type=0x05),
        ])
    monkeypatch.setattr(
        "kerb_map.modules.ou_computer_create.resolve_sids",
        lambda *a, **kw: {"S-1-5-21-1-2-3-1905":
                          {"sAMAccountName": "helpdesk_op"}})

    ctx = _ctx([[ou], []])
    f = OuComputerCreate().scan(ctx).findings[0]
    assert f.data["writer_sid"] == "S-1-5-21-1-2-3-1905"
    assert f.data["target_dn"] == "OU=Helpdesk,DC=corp,DC=local"
    assert f.data["right"] == "CreateChild(computer)"

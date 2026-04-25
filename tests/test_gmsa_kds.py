"""GMSA / dMSA / KDS root key audit tests."""

from unittest.mock import MagicMock

from kerb_map.acl import (
    ADS_RIGHT_DS_CONTROL_ACCESS,
    ADS_RIGHT_GENERIC_ALL,
    AceMatch,
)
from kerb_map.modules.gmsa_kds import (
    ADS_RIGHT_READ_PROPERTY,
    GmsaKdsAudit,
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
    """Two queues: query (gMSA + dMSA + SID resolution) and query_config
    (KDS root keys)."""
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


# ────────────────────────────────────────────── KDS root key ────


def test_kds_root_key_with_only_default_readers_clean(monkeypatch):
    """Domain Controllers + LocalSystem reading the KDS root key is
    expected — no finding."""
    key = _entry({
        "cn":                "key1",
        "distinguishedName": "CN=key1,CN=Master Root Keys,...",
        "whenCreated":       "2025-01-01T00:00:00Z",
        "msKds-Version":     1,
        "nTSecurityDescriptor": b"<sd>",
    })
    monkeypatch.setattr("kerb_map.modules.gmsa_kds.parse_sd", lambda raw: object())
    monkeypatch.setattr(
        "kerb_map.modules.gmsa_kds.walk_aces",
        lambda sd, object_dn="": [
            AceMatch(object_dn=object_dn, trustee_sid="S-1-5-21-1-2-3-516",  # Domain Controllers
                     access_mask=ADS_RIGHT_GENERIC_ALL,
                     object_type_guid=None, ace_type=0x00),
            AceMatch(object_dn=object_dn, trustee_sid="S-1-5-18",  # LocalSystem
                     access_mask=ADS_RIGHT_GENERIC_ALL,
                     object_type_guid=None, ace_type=0x00),
        ])
    monkeypatch.setattr("kerb_map.modules.gmsa_kds.resolve_sids", lambda *a, **kw: {})

    ctx = _ctx([[], []], query_config_responses=[[key]])
    result = GmsaKdsAudit().scan(ctx)
    kds_findings = [f for f in result.findings if "Golden dMSA" in f.attack]
    assert kds_findings == []
    assert result.raw["summary"]["kds_keys"] == 1
    assert result.raw["summary"]["kds_with_extra_readers"] == 0


def test_kds_root_key_extra_reader_is_critical(monkeypatch):
    """A non-default principal with read access on a KDS root key is
    the Golden dMSA prereq — CRITICAL."""
    key = _entry({
        "cn":                "key1",
        "distinguishedName": "CN=key1,CN=Master Root Keys,...",
        "whenCreated":       None,
        "msKds-Version":     1,
        "nTSecurityDescriptor": b"<sd>",
    })
    monkeypatch.setattr("kerb_map.modules.gmsa_kds.parse_sd", lambda raw: object())
    monkeypatch.setattr(
        "kerb_map.modules.gmsa_kds.walk_aces",
        lambda sd, object_dn="": [
            AceMatch(object_dn=object_dn, trustee_sid="S-1-5-21-1-2-3-1500",  # random user
                     access_mask=ADS_RIGHT_READ_PROPERTY,
                     object_type_guid=None, ace_type=0x00),
        ])
    monkeypatch.setattr(
        "kerb_map.modules.gmsa_kds.resolve_sids",
        lambda ldap, sids, base_dn: {
            "S-1-5-21-1-2-3-1500": {"sAMAccountName": "svc_helpdesk",
                                    "distinguishedName": "...",
                                    "objectClass": "user"}})

    ctx = _ctx([[], []], query_config_responses=[[key]])
    result = GmsaKdsAudit().scan(ctx)
    kds_findings = [f for f in result.findings if "Golden dMSA" in f.attack]
    assert len(kds_findings) == 1
    assert kds_findings[0].severity == "CRITICAL"
    assert kds_findings[0].priority == 97
    assert "svc_helpdesk" in kds_findings[0].reason
    assert "key1" in kds_findings[0].target
    assert "GoldenDMSA.py" in kds_findings[0].next_step or "ManagedPasswordId" in kds_findings[0].reason


def test_kds_multiple_extra_readers_collapse_to_one_finding(monkeypatch):
    """Two extra readers on the same key shouldn't yield two findings —
    one finding listing both readers is more useful."""
    key = _entry({
        "cn":                "key1",
        "distinguishedName": "CN=key1,...",
        "whenCreated":       None,
        "msKds-Version":     1,
        "nTSecurityDescriptor": b"<sd>",
    })
    monkeypatch.setattr("kerb_map.modules.gmsa_kds.parse_sd", lambda raw: object())
    monkeypatch.setattr(
        "kerb_map.modules.gmsa_kds.walk_aces",
        lambda sd, object_dn="": [
            AceMatch(object_dn=object_dn, trustee_sid="S-1-5-21-1-2-3-1500",
                     access_mask=ADS_RIGHT_READ_PROPERTY,
                     object_type_guid=None, ace_type=0x00),
            AceMatch(object_dn=object_dn, trustee_sid="S-1-5-21-1-2-3-1501",
                     access_mask=ADS_RIGHT_READ_PROPERTY,
                     object_type_guid=None, ace_type=0x00),
        ])
    monkeypatch.setattr(
        "kerb_map.modules.gmsa_kds.resolve_sids",
        lambda ldap, sids, base_dn: {
            "S-1-5-21-1-2-3-1500": {"sAMAccountName": "alice", "distinguishedName": "", "objectClass": "user"},
            "S-1-5-21-1-2-3-1501": {"sAMAccountName": "bob",   "distinguishedName": "", "objectClass": "user"},
        })

    ctx = _ctx([[], []], query_config_responses=[[key]])
    result = GmsaKdsAudit().scan(ctx)
    kds_findings = [f for f in result.findings if "Golden dMSA" in f.attack]
    assert len(kds_findings) == 1
    assert "alice" in kds_findings[0].reason
    assert "bob"   in kds_findings[0].reason


# ────────────────────────────────────────────── gMSA inventory ───


def test_gmsa_with_default_only_readers_no_finding(monkeypatch):
    gmsa = _entry({
        "sAMAccountName":       "gmsa_app$",
        "distinguishedName":    "CN=gmsa_app,CN=Managed Service Accounts,...",
        "objectSid":            None,
        "msDS-GroupMSAMembership": b"<sd>",
        "msDS-ManagedPasswordInterval": 30,
        "pwdLastSet":           None,
        "userAccountControl":   0x1000,
    })
    monkeypatch.setattr("kerb_map.modules.gmsa_kds.parse_sd", lambda raw: object())
    monkeypatch.setattr(
        "kerb_map.modules.gmsa_kds.walk_aces",
        lambda sd, object_dn="": [
            AceMatch(object_dn=object_dn, trustee_sid="S-1-5-21-1-2-3-512",  # Domain Admins
                     access_mask=ADS_RIGHT_GENERIC_ALL,
                     object_type_guid=None, ace_type=0x00),
        ])
    monkeypatch.setattr("kerb_map.modules.gmsa_kds.resolve_sids", lambda *a, **kw: {})

    ctx = _ctx([[gmsa], []])
    result = GmsaKdsAudit().scan(ctx)
    gmsa_findings = [f for f in result.findings if "gMSA password" in f.attack]
    assert gmsa_findings == []
    assert result.raw["summary"]["gmsa_count"] == 1


def test_gmsa_with_extra_reader_is_high(monkeypatch):
    gmsa = _entry({
        "sAMAccountName":       "gmsa_app$",
        "distinguishedName":    "CN=gmsa_app,...",
        "objectSid":            None,
        "msDS-GroupMSAMembership": b"<sd>",
        "msDS-ManagedPasswordInterval": 30,
        "pwdLastSet":           None,
        "userAccountControl":   0x1000,
    })
    monkeypatch.setattr("kerb_map.modules.gmsa_kds.parse_sd", lambda raw: object())
    monkeypatch.setattr(
        "kerb_map.modules.gmsa_kds.walk_aces",
        lambda sd, object_dn="": [
            AceMatch(object_dn=object_dn, trustee_sid="S-1-5-21-1-2-3-1700",
                     access_mask=ADS_RIGHT_READ_PROPERTY,
                     object_type_guid=None, ace_type=0x00),
        ])
    monkeypatch.setattr(
        "kerb_map.modules.gmsa_kds.resolve_sids",
        lambda ldap, sids, base_dn: {
            "S-1-5-21-1-2-3-1700": {"sAMAccountName": "appsupport",
                                    "distinguishedName": "...",
                                    "objectClass": "user"}})

    ctx = _ctx([[gmsa], []])
    result = GmsaKdsAudit().scan(ctx)
    gmsa_findings = [f for f in result.findings if "gMSA password" in f.attack]
    assert len(gmsa_findings) == 1
    assert gmsa_findings[0].severity == "HIGH"
    assert gmsa_findings[0].priority == 82
    assert "appsupport" in gmsa_findings[0].reason
    assert "gMSADumper" in gmsa_findings[0].next_step


# ────────────────────────────────────────────── dMSA inventory ───


def test_dmsa_inventory_lists_without_finding():
    """dMSAs are inventoried as raw output — the BadSuccessor module
    handles the per-dMSA finding logic, this one just completes the
    visibility picture."""
    dmsa = _entry({
        "sAMAccountName":      "kerbmap_dmsa$",
        "distinguishedName":   "CN=kerbmap_dmsa,OU=Lab,...",
        "msDS-DelegatedMSAState": 2,
        "msDS-ManagedAccountPrecededByLink": ["CN=svc_old,..."],
        "whenCreated":         None,
    })
    ctx = _ctx([[], [dmsa]])
    result = GmsaKdsAudit().scan(ctx)
    assert result.raw["summary"]["dmsa_count"] == 1
    assert result.raw["dmsas"][0]["sAMAccountName"] == "kerbmap_dmsa$"
    # No finding in the dMSA channel from THIS module.
    assert all("dMSA" not in f.attack for f in result.findings)

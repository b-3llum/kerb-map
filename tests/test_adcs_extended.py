"""ADCS Extended module — ESC9 / ESC13 / ESC15 detection.

Same mocked-LDAP strategy as the rest of the v2 module tests. Lab
acceptance ("seeded ADCS lab with ESC9/13/15 templates, scan flags
each correctly") deferred until the lab is up.
"""

from unittest.mock import MagicMock

from kerb_map.acl import (
    ADS_RIGHT_DS_CONTROL_ACCESS,
    ADS_RIGHT_GENERIC_ALL,
    AceMatch,
)
from kerb_map.modules.adcs_extended import (
    CT_FLAG_NO_SECURITY_EXTENSION,
    EXT_RIGHT_ENROLL,
    AdcsExtended,
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


def _ctx(query_config_responses, query_responses=None):
    """ldap.query_config returns from a queue; ldap.query is for SID/DN
    resolution and follows a separate queue."""
    ldap = MagicMock()
    qc = list(query_config_responses)
    ldap.query_config.side_effect = lambda **_: qc.pop(0) if qc else []
    qq = list(query_responses or [])
    ldap.query.side_effect = lambda **_: qq.pop(0) if qq else []
    return ScanContext(
        ldap=ldap,
        domain="corp.local",
        base_dn="DC=corp,DC=local",
        dc_ip="10.0.0.1",
        domain_sid="S-1-5-21-1-2-3",
    )


# ────────────────────────────────────────────── module gating ────


def test_no_templates_returns_inapplicable():
    ctx = _ctx([[], []])  # no templates, no OIDs
    result = AdcsExtended().scan(ctx)
    assert result.findings == []
    assert result.raw["applicable"] is False
    assert "ADCS" in result.raw["reason"] or "templates" in result.raw["reason"]


# ────────────────────────────────────────────── ESC9 ─────────────


def test_esc9_no_security_extension_with_public_enrol_is_high(monkeypatch):
    """Template flagged ESC9: schema v2 + CT_FLAG_NO_SECURITY_EXTENSION
    + Authenticated Users have Enroll → HIGH (priority 82)."""
    tpl = _entry({
        "cn":                              "EnrolledUserCert",
        "displayName":                     "Enrolled User Cert",
        "distinguishedName":               "CN=EnrolledUserCert,CN=Templates,...",
        "msPKI-Template-Schema-Version":   2,
        "msPKI-Enrollment-Flag":           CT_FLAG_NO_SECURITY_EXTENSION,
        "msPKI-Certificate-Policy":        [],
        "nTSecurityDescriptor":            b"<sd>",
    })
    monkeypatch.setattr("kerb_map.modules.adcs_extended.parse_sd", lambda raw: object())
    monkeypatch.setattr(
        "kerb_map.modules.adcs_extended.walk_aces",
        lambda sd, object_dn="": [
            AceMatch(object_dn=object_dn, trustee_sid="S-1-5-11",
                     access_mask=ADS_RIGHT_DS_CONTROL_ACCESS,
                     object_type_guid=EXT_RIGHT_ENROLL, ace_type=0x05),
        ])
    monkeypatch.setattr(
        "kerb_map.modules.adcs_extended.resolve_sids",
        lambda ldap, sids, base_dn: {"S-1-5-11": {
            "sAMAccountName": "Authenticated Users",
            "distinguishedName": "", "objectClass": "well-known",
        }})

    ctx = _ctx([[tpl], []])
    result = AdcsExtended().scan(ctx)
    esc9 = [f for f in result.findings if "ESC9" in f.attack]
    assert len(esc9) == 1
    assert esc9[0].severity == "HIGH"
    assert esc9[0].priority == 82
    assert "userPrincipalName" in esc9[0].reason or "UPN" in esc9[0].reason
    assert "certipy" in esc9[0].next_step.lower()


def test_esc9_without_public_enrol_does_not_fire(monkeypatch):
    """ESC9 only matters when the template is publicly enrolable —
    a template restricted to Domain Admins is not a finding."""
    tpl = _entry({
        "cn":                              "AdminOnlyCert",
        "distinguishedName":               "CN=AdminOnlyCert,...",
        "msPKI-Template-Schema-Version":   2,
        "msPKI-Enrollment-Flag":           CT_FLAG_NO_SECURITY_EXTENSION,
        "msPKI-Certificate-Policy":        [],
        "nTSecurityDescriptor":            b"<sd>",
    })
    monkeypatch.setattr("kerb_map.modules.adcs_extended.parse_sd", lambda raw: object())
    monkeypatch.setattr(
        "kerb_map.modules.adcs_extended.walk_aces",
        lambda sd, object_dn="": [
            AceMatch(object_dn=object_dn,
                     trustee_sid="S-1-5-21-1-2-3-512",  # Domain Admins
                     access_mask=ADS_RIGHT_GENERIC_ALL,
                     object_type_guid=None, ace_type=0x00),
        ])
    monkeypatch.setattr("kerb_map.modules.adcs_extended.resolve_sids", lambda *a, **kw: {})

    ctx = _ctx([[tpl], []])
    result = AdcsExtended().scan(ctx)
    assert all("ESC9" not in f.attack for f in result.findings)


# ────────────────────────────────────────────── ESC13 ────────────


def test_esc13_template_oid_linked_to_da_is_critical(monkeypatch):
    """Template carries a policy OID that maps to Domain Admins via
    msDS-OIDToGroupLink → CRITICAL (priority 92)."""
    tpl = _entry({
        "cn":                              "AdminCert",
        "distinguishedName":               "CN=AdminCert,...",
        "msPKI-Template-Schema-Version":   2,
        "msPKI-Enrollment-Flag":           0,
        "msPKI-Certificate-Policy":        ["1.3.6.1.4.1.311.21.10.1.1"],
        "nTSecurityDescriptor":            b"<sd>",
    })
    oid_entry = _entry({
        "msPKI-Cert-Template-OID":  "1.3.6.1.4.1.311.21.10.1.1",
        "msDS-OIDToGroupLink":      ["CN=Domain Admins,CN=Users,DC=corp,DC=local"],
        "displayName":              "AdminLink",
    })
    da_group = _entry({
        "sAMAccountName": "Domain Admins",
        "objectSid":      b"\x01\x05\x00\x00\x00\x00\x00\x05\x15\x00\x00\x00"
                          b"\x01\x00\x00\x00\x02\x00\x00\x00\x03\x00\x00\x00"
                          b"\x00\x02\x00\x00",  # ends -512 in LE
        "adminCount":     1,
    })

    monkeypatch.setattr("kerb_map.modules.adcs_extended.parse_sd", lambda raw: object())
    monkeypatch.setattr(
        "kerb_map.modules.adcs_extended.walk_aces",
        lambda sd, object_dn="": [
            AceMatch(object_dn=object_dn, trustee_sid="S-1-5-11",
                     access_mask=ADS_RIGHT_DS_CONTROL_ACCESS,
                     object_type_guid=EXT_RIGHT_ENROLL, ace_type=0x05),
        ])
    monkeypatch.setattr("kerb_map.modules.adcs_extended.resolve_sids", lambda *a, **kw: {})

    ctx = _ctx(
        query_config_responses=[[tpl], [oid_entry]],
        query_responses=[[da_group]],
    )
    result = AdcsExtended().scan(ctx)
    esc13 = [f for f in result.findings if "ESC13" in f.attack]
    assert len(esc13) == 1
    assert esc13[0].severity == "CRITICAL"
    assert esc13[0].priority == 92


def test_esc13_unprivileged_oid_link_is_not_a_finding(monkeypatch):
    """Policy OID linked to a normal group (not adminCount=1, not
    well-known privileged) is informational, not a finding."""
    tpl = _entry({
        "cn":                              "AppCert",
        "distinguishedName":               "CN=AppCert,...",
        "msPKI-Template-Schema-Version":   2,
        "msPKI-Enrollment-Flag":           0,
        "msPKI-Certificate-Policy":        ["1.2.3"],
        "nTSecurityDescriptor":            b"<sd>",
    })
    oid_entry = _entry({
        "msPKI-Cert-Template-OID":  "1.2.3",
        "msDS-OIDToGroupLink":      ["CN=AppUsers,CN=Users,DC=corp,DC=local"],
        "displayName":              "AppLink",
    })
    boring_group = _entry({
        "sAMAccountName": "AppUsers",
        "objectSid":      b"\x01\x05\x00\x00\x00\x00\x00\x05\x15\x00\x00\x00"
                          b"\x01\x00\x00\x00\x02\x00\x00\x00\x03\x00\x00\x00"
                          b"\xd2\x04\x00\x00",  # RID 1234, no adminCount
        "adminCount":     None,
    })

    monkeypatch.setattr("kerb_map.modules.adcs_extended.parse_sd", lambda raw: object())
    monkeypatch.setattr(
        "kerb_map.modules.adcs_extended.walk_aces",
        lambda sd, object_dn="": [
            AceMatch(object_dn=object_dn, trustee_sid="S-1-5-11",
                     access_mask=ADS_RIGHT_DS_CONTROL_ACCESS,
                     object_type_guid=EXT_RIGHT_ENROLL, ace_type=0x05),
        ])
    monkeypatch.setattr("kerb_map.modules.adcs_extended.resolve_sids", lambda *a, **kw: {})

    ctx = _ctx(
        query_config_responses=[[tpl], [oid_entry]],
        query_responses=[[boring_group]],
    )
    result = AdcsExtended().scan(ctx)
    assert all("ESC13" not in f.attack for f in result.findings)


# ────────────────────────────────────────────── ESC15 / EKUwu ────


def test_esc15_v1_publicly_enrolable_template_is_high(monkeypatch):
    """V1 (schema=1) template + publicly enrolable → ESC15."""
    tpl = _entry({
        "cn":                              "WebServer",
        "distinguishedName":               "CN=WebServer,CN=Templates,...",
        "msPKI-Template-Schema-Version":   1,
        "msPKI-Enrollment-Flag":           0,
        "msPKI-Certificate-Policy":        [],
        "nTSecurityDescriptor":            b"<sd>",
    })
    monkeypatch.setattr("kerb_map.modules.adcs_extended.parse_sd", lambda raw: object())
    monkeypatch.setattr(
        "kerb_map.modules.adcs_extended.walk_aces",
        lambda sd, object_dn="": [
            AceMatch(object_dn=object_dn, trustee_sid="S-1-5-11",
                     access_mask=ADS_RIGHT_DS_CONTROL_ACCESS,
                     object_type_guid=EXT_RIGHT_ENROLL, ace_type=0x05),
        ])
    monkeypatch.setattr("kerb_map.modules.adcs_extended.resolve_sids", lambda *a, **kw: {})

    ctx = _ctx([[tpl], []])
    result = AdcsExtended().scan(ctx)
    esc15 = [f for f in result.findings if "ESC15" in f.attack or "EKUwu" in f.attack]
    assert len(esc15) == 1
    assert esc15[0].severity == "HIGH"
    assert "CVE-2024-49019" in esc15[0].reason
    assert "Application Polic" in esc15[0].reason or "application-policies" in esc15[0].next_step.lower()


def test_esc15_v2_template_does_not_fire(monkeypatch):
    """V2 templates are not subject to EKUwu — only v1."""
    tpl = _entry({
        "cn":                              "ModernCert",
        "distinguishedName":               "CN=ModernCert,...",
        "msPKI-Template-Schema-Version":   2,
        "msPKI-Enrollment-Flag":           0,
        "msPKI-Certificate-Policy":        [],
        "nTSecurityDescriptor":            b"<sd>",
    })
    monkeypatch.setattr("kerb_map.modules.adcs_extended.parse_sd", lambda raw: object())
    monkeypatch.setattr(
        "kerb_map.modules.adcs_extended.walk_aces",
        lambda sd, object_dn="": [
            AceMatch(object_dn=object_dn, trustee_sid="S-1-5-11",
                     access_mask=ADS_RIGHT_DS_CONTROL_ACCESS,
                     object_type_guid=EXT_RIGHT_ENROLL, ace_type=0x05),
        ])
    monkeypatch.setattr("kerb_map.modules.adcs_extended.resolve_sids", lambda *a, **kw: {})

    ctx = _ctx([[tpl], []])
    result = AdcsExtended().scan(ctx)
    assert all("ESC15" not in f.attack and "EKUwu" not in f.attack for f in result.findings)


# ────────────────────────────────────────────── summary counts ───


def test_summary_reflects_finding_buckets(monkeypatch):
    """Three templates, one of each ESC type, should give summary 1/1/1."""
    tpl_esc9 = _entry({
        "cn": "T9", "distinguishedName": "CN=T9,...",
        "msPKI-Template-Schema-Version": 2,
        "msPKI-Enrollment-Flag":         CT_FLAG_NO_SECURITY_EXTENSION,
        "msPKI-Certificate-Policy":      [], "nTSecurityDescriptor": b"<sd>",
    })
    tpl_esc15 = _entry({
        "cn": "T15", "distinguishedName": "CN=T15,...",
        "msPKI-Template-Schema-Version": 1,
        "msPKI-Enrollment-Flag":         0,
        "msPKI-Certificate-Policy":      [], "nTSecurityDescriptor": b"<sd>",
    })
    monkeypatch.setattr("kerb_map.modules.adcs_extended.parse_sd", lambda raw: object())
    monkeypatch.setattr(
        "kerb_map.modules.adcs_extended.walk_aces",
        lambda sd, object_dn="": [
            AceMatch(object_dn=object_dn, trustee_sid="S-1-5-11",
                     access_mask=ADS_RIGHT_DS_CONTROL_ACCESS,
                     object_type_guid=EXT_RIGHT_ENROLL, ace_type=0x05),
        ])
    monkeypatch.setattr("kerb_map.modules.adcs_extended.resolve_sids", lambda *a, **kw: {})

    ctx = _ctx([[tpl_esc9, tpl_esc15], []])
    result = AdcsExtended().scan(ctx)
    s = result.raw["summary"]
    assert s["templates_total"] == 2
    assert s["esc9_count"]  == 1
    assert s["esc15_count"] == 1

"""Shadow Credentials module — populated-key inventory + write-ACL audit.

Same testing strategy as DCSync: mock the SD parser and the LDAP client
to exercise the bucketing logic. Real-DC integration is brief §4.1's
acceptance criterion — skipped until the lab is up.
"""

from unittest.mock import MagicMock

from kerb_map.acl import (
    ADS_RIGHT_DS_WRITE_PROP,
    ADS_RIGHT_GENERIC_ALL,
    ATTR_KEY_CREDENTIAL_LINK,
    AceMatch,
)
from kerb_map.modules.shadow_credentials import ShadowCredentials
from kerb_map.plugin import ScanContext

# ---------------------------------------------- helpers ----


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


def _ctx(query_responses):
    """Build a context whose ldap.query() returns successive responses
    from a queue. The module makes 2 queries; index 0 for the inventory,
    index 1 for the privileged-account ACL audit."""
    ldap = MagicMock()
    queue = list(query_responses)
    ldap.query.side_effect = lambda **_: queue.pop(0) if queue else []
    return ScanContext(
        ldap=ldap,
        domain="corp.local",
        base_dn="DC=corp,DC=local",
        dc_ip="10.0.0.1",
        domain_sid="S-1-5-21-1-2-3",
    )


# ---------------------------------------------- inventory ----


def test_workstation_with_whfb_is_info_not_finding():
    """Win10 computer with msDS-KeyCredentialLink = legitimate WHfB."""
    ws = _entry({
        "sAMAccountName":          "WS01$",
        "distinguishedName":       "CN=WS01,CN=Computers,DC=corp,DC=local",
        "objectClass":             ["top", "person", "user", "computer"],
        "userAccountControl":      0x1000,  # WORKSTATION_TRUST_ACCOUNT
        "memberOf":                [],
        "msDS-KeyCredentialLink":  ["B:828:..."],
        "primaryGroupID":          515,  # Domain Computers
        "operatingSystem":         "Windows 10 Enterprise",
    })
    ctx = _ctx([[ws], []])  # inventory then ACL audit (empty)
    result = ShadowCredentials().scan(ctx)
    assert len(result.findings) == 1
    assert result.findings[0].severity == "INFO"


def test_privileged_user_with_keys_is_critical():
    """Domain Admin with KeyCredentialLink populated = high-fidelity IOC."""
    da = _entry({
        "sAMAccountName":          "alice_da",
        "distinguishedName":       "CN=alice_da,CN=Users,DC=corp,DC=local",
        "objectClass":             ["top", "person", "user"],
        "userAccountControl":      0x200,
        "memberOf":                ["CN=Domain Admins,CN=Users,DC=corp,DC=local"],
        "msDS-KeyCredentialLink":  ["B:828:..."],
        "primaryGroupID":          513,
        "operatingSystem":         None,
    })
    ctx = _ctx([[da], []])
    result = ShadowCredentials().scan(ctx)
    assert len(result.findings) == 1
    f = result.findings[0]
    assert f.severity == "CRITICAL"
    assert f.priority == 90
    assert "Whisker" in f.reason or "Tier-0" in f.reason
    assert f.mitre == "T1556.007"


def test_normal_user_with_keys_is_high():
    user = _entry({
        "sAMAccountName":          "svc_app",
        "distinguishedName":       "CN=svc_app,...",
        "objectClass":             ["top", "person", "user"],
        "userAccountControl":      0x10200,
        "memberOf":                [],
        "msDS-KeyCredentialLink":  ["B:828:...", "B:828:..."],
        "primaryGroupID":          513,
        "operatingSystem":         None,
    })
    ctx = _ctx([[user], []])
    result = ShadowCredentials().scan(ctx)
    f = result.findings[0]
    assert f.severity == "HIGH"
    assert f.data["key_count"] == 2


def test_inventory_summary_counts():
    ws = _entry({
        "sAMAccountName": "WS01$", "distinguishedName": "CN=WS01,...",
        "objectClass": ["computer"], "userAccountControl": 0x1000,
        "memberOf": [], "msDS-KeyCredentialLink": ["B:..."],
        "primaryGroupID": 515, "operatingSystem": "Windows 10",
    })
    da = _entry({
        "sAMAccountName": "alice_da", "distinguishedName": "CN=alice_da,...",
        "objectClass": ["user"], "userAccountControl": 0x200,
        "memberOf": ["CN=Domain Admins,..."],
        "msDS-KeyCredentialLink": ["B:..."],
        "primaryGroupID": 513, "operatingSystem": None,
    })
    ctx = _ctx([[ws, da], []])
    result = ShadowCredentials().scan(ctx)
    assert result.raw["summary"]["with_keys"] == 2
    assert result.raw["summary"]["privileged_with_keys"] == 1


# ---------------------------------------------- write ACL audit ----


def test_write_property_to_keycredlink_emits_finding(monkeypatch):
    """Some non-default principal can WriteProperty msDS-KeyCredentialLink
    on a Domain Admin → CRITICAL finding."""
    da_target = _entry({
        "sAMAccountName": "bob_da",
        "distinguishedName": "CN=bob_da,...",
        "objectSid": "S-1-5-21-1-2-3-1100",
        "nTSecurityDescriptor": b"<sd>",
    })
    monkeypatch.setattr(
        "kerb_map.modules.shadow_credentials.parse_sd",
        lambda raw: object())
    monkeypatch.setattr(
        "kerb_map.modules.shadow_credentials.walk_aces",
        lambda sd, object_dn="": [
            AceMatch(object_dn=object_dn, trustee_sid="S-1-5-21-1-2-3-1500",
                     access_mask=ADS_RIGHT_DS_WRITE_PROP,
                     object_type_guid=ATTR_KEY_CREDENTIAL_LINK,
                     ace_type=0x05),
        ])
    monkeypatch.setattr(
        "kerb_map.modules.shadow_credentials.resolve_sids",
        lambda ldap, sids, base_dn: {
            "S-1-5-21-1-2-3-1500": {"sAMAccountName": "helpdesk_op",
                                    "distinguishedName": "...",
                                    "objectClass": "user"}})

    ctx = _ctx([
        [],         # empty inventory query
        [da_target],  # ACL audit query returns one privileged target
    ])
    result = ShadowCredentials().scan(ctx)
    assert len(result.findings) == 1
    f = result.findings[0]
    assert f.severity == "CRITICAL"
    assert f.priority == 92
    assert f.target == "bob_da"
    assert "helpdesk_op" in f.reason
    assert "pywhisker" in f.next_step.lower()
    assert "gettgtpkinit" in f.next_step.lower()


def test_well_known_writer_is_suppressed(monkeypatch):
    """Domain Admins writing to a DA target = noise, not a finding."""
    da_target = _entry({
        "sAMAccountName": "bob_da", "distinguishedName": "CN=bob_da,...",
        "objectSid": "S-1-5-21-1-2-3-1100", "nTSecurityDescriptor": b"<sd>",
    })
    monkeypatch.setattr(
        "kerb_map.modules.shadow_credentials.parse_sd",
        lambda raw: object())
    monkeypatch.setattr(
        "kerb_map.modules.shadow_credentials.walk_aces",
        lambda sd, object_dn="": [
            AceMatch(object_dn=object_dn, trustee_sid="S-1-5-21-1-2-3-512",
                     access_mask=ADS_RIGHT_GENERIC_ALL,
                     object_type_guid=None, ace_type=0x00),
        ])

    ctx = _ctx([[], [da_target]])
    result = ShadowCredentials().scan(ctx)
    # No inventory entries, no non-well-known writers → zero findings.
    assert result.findings == []
    assert result.raw["summary"]["non_default_writers"] == 0


def test_acl_audit_handles_missing_sd(monkeypatch):
    """Targets that don't return a parseable SD are skipped, not crashed."""
    bad_target = _entry({
        "sAMAccountName": "bob_da", "distinguishedName": "CN=bob_da,...",
        "objectSid": "S-1-5-21-1-2-3-1100", "nTSecurityDescriptor": None,
    })
    monkeypatch.setattr(
        "kerb_map.modules.shadow_credentials.parse_sd",
        lambda raw: None)  # parser returns None for garbage

    ctx = _ctx([[], [bad_target]])
    result = ShadowCredentials().scan(ctx)
    assert result.findings == []

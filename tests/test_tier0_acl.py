"""Tier-0 ACL audit module (brief §4.6).

Mocks the SD parser + recursive group resolution so the bucketing
logic is exercised without touching impacket internals or a real DC.
Lab acceptance ("seeded backdoor ACE on AdminSDHolder, scan flags it
CRITICAL; in-tier writer suppressed") deferred until vagrant up runs.
"""

from unittest.mock import MagicMock

from kerb_map.acl import (
    ADS_RIGHT_DS_CONTROL_ACCESS,
    ADS_RIGHT_DS_SELF,
    ADS_RIGHT_DS_WRITE_PROP,
    ADS_RIGHT_GENERIC_ALL,
    ADS_RIGHT_GENERIC_WRITE,
    ADS_RIGHT_WRITE_DAC,
    ADS_RIGHT_WRITE_OWNER,
    ATTR_MEMBER,
    AceMatch,
)
from kerb_map.modules.tier0_acl import (
    Tier0AclAudit,
    _classify_ace,
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


def _ctx(query_responses):
    """ctx with an LDAP whose query() returns a queue of responses.
    We use a deque so the test author can be loose about exactly which
    queries fire in which order — empty default for un-anticipated queries."""
    ldap = MagicMock()
    queue = list(query_responses)
    def _resp(**_):
        return queue.pop(0) if queue else []
    ldap.query.side_effect = _resp
    return ScanContext(
        ldap=ldap,
        domain="corp.local",
        base_dn="DC=corp,DC=local",
        dc_ip="10.0.0.1",
        domain_sid="S-1-5-21-1-2-3",
    )


# ─────────────────────────────────────── _classify_ace bucketing ────


def _ace(sid, mask, guid=None, ace_type=0x05):
    return AceMatch(
        object_dn="CN=x,...", trustee_sid=sid,
        access_mask=mask, object_type_guid=guid, ace_type=ace_type,
    )


def test_classify_generic_all_is_critical_95():
    c = _classify_ace(_ace("S-1-5-21-1-2-3-1500", ADS_RIGHT_GENERIC_ALL))
    assert c["label"]    == "GenericAll"
    assert c["severity"] == "CRITICAL"
    assert c["priority"] == 95


def test_classify_writedacl_is_critical_93():
    c = _classify_ace(_ace("S-1-5-21-1-2-3-1500", ADS_RIGHT_WRITE_DAC))
    assert c["label"] == "WriteDACL"
    assert c["priority"] == 93


def test_classify_writeowner_is_critical_92():
    c = _classify_ace(_ace("S-1-5-21-1-2-3-1500", ADS_RIGHT_WRITE_OWNER))
    assert c["label"] == "WriteOwner"


def test_classify_genericwrite_is_high_85():
    c = _classify_ace(_ace("S-1-5-21-1-2-3-1500", ADS_RIGHT_GENERIC_WRITE))
    assert c["label"] == "GenericWrite"
    assert c["severity"] == "HIGH"


def test_classify_writeproperty_member_is_high_88():
    """WriteProperty scoped to the member attribute = AddMember
    primitive — the BloodHound 'AddMember' edge."""
    c = _classify_ace(_ace(
        "S-1-5-21-1-2-3-1500",
        ADS_RIGHT_DS_WRITE_PROP, guid=ATTR_MEMBER,
    ))
    assert c["label"]    == "WriteProperty(member)"
    assert c["priority"] == 88


def test_classify_self_on_member_is_high_86():
    """Self ACE scoped to member = AddSelf — walk yourself in."""
    c = _classify_ace(_ace(
        "S-1-5-21-1-2-3-1500",
        ADS_RIGHT_DS_SELF, guid=ATTR_MEMBER,
    ))
    assert c["label"]    == "Self (AddSelf)"
    assert c["priority"] == 86


def test_classify_self_on_other_attr_does_not_match():
    """Self ACE scoped to a non-member attribute is a different attack
    path (passwordReset etc.) — not what this module is auditing."""
    other_guid = "12345678-1234-1234-1234-123456789abc"
    c = _classify_ace(_ace(
        "S-1-5-21-1-2-3-1500",
        ADS_RIGHT_DS_SELF, guid=other_guid,
    ))
    assert c is None


def test_classify_self_with_no_guid_matches():
    """ACE_OBJECT_TYPE_PRESENT not set = applies to all attributes,
    which includes the member attribute."""
    c = _classify_ace(_ace(
        "S-1-5-21-1-2-3-1500",
        ADS_RIGHT_DS_SELF, guid=None,
    ))
    assert c is not None and c["label"] == "Self (AddSelf)"


def test_classify_unrelated_right_returns_none():
    """ReadProperty / List / etc. — not dangerous, return None."""
    c = _classify_ace(_ace("S-1-5-21-1-2-3-1500", 0x10))  # READ_PROPERTY
    assert c is None


def test_classify_returns_loudest_right_first():
    """An ACE with both GenericAll and WriteOwner should classify as
    GenericAll (the loudest of the two). Ordering matters."""
    c = _classify_ace(_ace(
        "S-1-5-21-1-2-3-1500",
        ADS_RIGHT_GENERIC_ALL | ADS_RIGHT_WRITE_OWNER,
    ))
    assert c["label"] == "GenericAll"


# ────────────────────────────────────────── module — finding shape ────


def _target_entry(sam, dn, sid, kind="Privileged group"):
    """Build the dict shape _enumerate_targets returns for a single
    Tier-0 object (with an opaque SD blob)."""
    return {
        "sam": sam, "dn": dn, "sid": sid, "kind": kind,
        "nTSecurityDescriptor": b"<sd>",
    }


def test_no_targets_returns_inapplicable():
    """If the target enumeration comes back empty (e.g. operator
    pointed kerb-map at a non-DC), the module bails cleanly without
    touching the SD parser."""
    ctx = _ctx([
        [], [], [], [],   # admin_sd / builtin / domain / priv_users all empty
    ])
    result = Tier0AclAudit().scan(ctx)
    assert result.findings == []
    assert result.raw["applicable"] is False


def test_critical_finding_for_non_default_genericall(monkeypatch):
    """The headline case: random user with GenericAll on Domain Admins
    = CRITICAL, with the writer's name in the reason and a populated
    next_step."""
    target = _target_entry(
        "Domain Admins",
        "CN=Domain Admins,CN=Users,DC=corp,DC=local",
        "S-1-5-21-1-2-3-512",
    )
    monkeypatch.setattr(
        "kerb_map.modules.tier0_acl.Tier0AclAudit._enumerate_targets",
        lambda self, ctx: [target],
    )
    monkeypatch.setattr(
        "kerb_map.modules.tier0_acl.parse_sd", lambda raw: object())
    monkeypatch.setattr(
        "kerb_map.modules.tier0_acl.walk_aces",
        lambda sd, object_dn="": [
            AceMatch(object_dn=object_dn, trustee_sid="S-1-5-21-1-2-3-1500",
                     access_mask=ADS_RIGHT_GENERIC_ALL,
                     object_type_guid=None, ace_type=0x00),
        ])
    monkeypatch.setattr(
        "kerb_map.modules.tier0_acl.resolve_sids",
        lambda ldap, sids, base_dn: {
            "S-1-5-21-1-2-3-1500": {
                "sAMAccountName": "rogue_user",
                "distinguishedName": "CN=rogue_user,CN=Users,DC=corp,DC=local",
                "objectClass": "user",
            }})
    monkeypatch.setattr(
        "kerb_map.modules.tier0_acl.is_member_of",
        lambda *a, **kw: False,   # rogue_user is NOT in tier-0 already
    )

    ctx = _ctx([])
    result = Tier0AclAudit().scan(ctx)
    assert len(result.findings) == 1
    f = result.findings[0]
    assert f.severity == "CRITICAL"
    assert f.priority == 95
    assert f.target   == "Domain Admins"
    assert "rogue_user" in f.reason
    assert "GenericAll" in f.attack
    assert "net rpc group" in f.next_step or "dacledit" in f.next_step


def test_in_tier_writer_is_suppressed(monkeypatch):
    """Domain Admin member having GenericAll on AdminSDHolder = by
    design, NOT a finding. The recursive-group check catches it."""
    target = _target_entry(
        "AdminSDHolder",
        "CN=AdminSDHolder,CN=System,DC=corp,DC=local",
        None,
        kind="AdminSDHolder",
    )
    monkeypatch.setattr(
        "kerb_map.modules.tier0_acl.Tier0AclAudit._enumerate_targets",
        lambda self, ctx: [target,
                           _target_entry("Domain Admins", "CN=Domain Admins,...",
                                          "S-1-5-21-1-2-3-512")])
    monkeypatch.setattr(
        "kerb_map.modules.tier0_acl.parse_sd", lambda raw: object())
    monkeypatch.setattr(
        "kerb_map.modules.tier0_acl.walk_aces",
        lambda sd, object_dn="": [
            AceMatch(object_dn=object_dn, trustee_sid="S-1-5-21-1-2-3-1100",
                     access_mask=ADS_RIGHT_GENERIC_ALL,
                     object_type_guid=None, ace_type=0x00),
        ])
    monkeypatch.setattr(
        "kerb_map.modules.tier0_acl.resolve_sids",
        lambda ldap, sids, base_dn: {
            "S-1-5-21-1-2-3-1100": {
                "sAMAccountName": "alice_da",
                "distinguishedName": "CN=alice_da,CN=Users,DC=corp,DC=local",
                "objectClass": "user",
            }})
    monkeypatch.setattr(
        "kerb_map.modules.tier0_acl.is_member_of",
        lambda *a, **kw: True,    # alice_da IS in Domain Admins (nested)
    )

    ctx = _ctx([])
    result = Tier0AclAudit().scan(ctx)
    # No findings — the in-tier writer is suppressed.
    assert result.findings == []
    # But the raw output records the in-tier writers so the operator
    # can still see them if they want.
    in_tier = [r for r in result.raw["entries"] if r["in_tier"]]
    assert len(in_tier) >= 1
    assert all(r["writer_sam"] == "alice_da" for r in in_tier)


def test_well_known_sid_writer_skipped(monkeypatch):
    """Writers like Domain Admins / Domain Controllers on AdminSDHolder
    are filtered by is_well_known_privileged BEFORE we even get to the
    in-tier suppression. They never appear in raw entries either."""
    target = _target_entry(
        "AdminSDHolder",
        "CN=AdminSDHolder,...",
        None, kind="AdminSDHolder",
    )
    monkeypatch.setattr(
        "kerb_map.modules.tier0_acl.Tier0AclAudit._enumerate_targets",
        lambda self, ctx: [target],
    )
    monkeypatch.setattr(
        "kerb_map.modules.tier0_acl.parse_sd", lambda raw: object())
    monkeypatch.setattr(
        "kerb_map.modules.tier0_acl.walk_aces",
        lambda sd, object_dn="": [
            AceMatch(object_dn=object_dn, trustee_sid="S-1-5-21-1-2-3-512",
                     access_mask=ADS_RIGHT_GENERIC_ALL,
                     object_type_guid=None, ace_type=0x00),
        ])
    monkeypatch.setattr(
        "kerb_map.modules.tier0_acl.resolve_sids", lambda *a, **kw: {})

    ctx = _ctx([])
    result = Tier0AclAudit().scan(ctx)
    assert result.findings == []
    # Raw entries should also be empty — well-known writers are dropped
    # before they even get into the deferred list.
    assert result.raw.get("entries", []) == []


def test_writeproperty_member_emits_high(monkeypatch):
    """The AddMember primitive — group-membership escalation."""
    target = _target_entry(
        "Domain Admins",
        "CN=Domain Admins,CN=Users,DC=corp,DC=local",
        "S-1-5-21-1-2-3-512",
    )
    monkeypatch.setattr(
        "kerb_map.modules.tier0_acl.Tier0AclAudit._enumerate_targets",
        lambda self, ctx: [target],
    )
    monkeypatch.setattr(
        "kerb_map.modules.tier0_acl.parse_sd", lambda raw: object())
    monkeypatch.setattr(
        "kerb_map.modules.tier0_acl.walk_aces",
        lambda sd, object_dn="": [
            AceMatch(object_dn=object_dn, trustee_sid="S-1-5-21-1-2-3-1500",
                     access_mask=ADS_RIGHT_DS_WRITE_PROP,
                     object_type_guid=ATTR_MEMBER, ace_type=0x05),
        ])
    monkeypatch.setattr(
        "kerb_map.modules.tier0_acl.resolve_sids",
        lambda ldap, sids, base_dn: {
            "S-1-5-21-1-2-3-1500": {
                "sAMAccountName": "helpdesk_op",
                "distinguishedName": "CN=helpdesk_op,...",
                "objectClass": "user",
            }})
    monkeypatch.setattr(
        "kerb_map.modules.tier0_acl.is_member_of", lambda *a, **kw: False)

    ctx = _ctx([])
    result = Tier0AclAudit().scan(ctx)
    assert len(result.findings) == 1
    f = result.findings[0]
    assert f.severity == "HIGH"
    assert "WriteProperty(member)" in f.attack
    assert "addmem" in f.next_step or "addmember" in f.next_step.lower()


def test_module_uses_attack_path_category():
    """Categories drive Scorer ranking and BH CE edge mapping."""
    assert Tier0AclAudit.category == "attack-path"
    assert Tier0AclAudit.in_default_run is True
    assert Tier0AclAudit.requires_aggressive is False


def test_finding_data_carries_writer_and_target_for_bh_edge(monkeypatch):
    """The BH CE exporter needs writer_sid + target_sid (or _dn) to
    attach the KerbMapWriteAcl edge — pin that contract here."""
    target = _target_entry(
        "Domain Admins",
        "CN=Domain Admins,CN=Users,DC=corp,DC=local",
        "S-1-5-21-1-2-3-512",
    )
    monkeypatch.setattr(
        "kerb_map.modules.tier0_acl.Tier0AclAudit._enumerate_targets",
        lambda self, ctx: [target],
    )
    monkeypatch.setattr(
        "kerb_map.modules.tier0_acl.parse_sd", lambda raw: object())
    monkeypatch.setattr(
        "kerb_map.modules.tier0_acl.walk_aces",
        lambda sd, object_dn="": [
            AceMatch(object_dn=object_dn, trustee_sid="S-1-5-21-1-2-3-1500",
                     access_mask=ADS_RIGHT_GENERIC_ALL,
                     object_type_guid=None, ace_type=0x00),
        ])
    monkeypatch.setattr(
        "kerb_map.modules.tier0_acl.resolve_sids",
        lambda ldap, sids, base_dn: {
            "S-1-5-21-1-2-3-1500": {"sAMAccountName": "rogue_user",
                                    "distinguishedName": "CN=rogue_user,...",
                                    "objectClass": "user"}})
    monkeypatch.setattr(
        "kerb_map.modules.tier0_acl.is_member_of", lambda *a, **kw: False)

    ctx = _ctx([])
    f = Tier0AclAudit().scan(ctx).findings[0]
    assert f.data["writer_sid"] == "S-1-5-21-1-2-3-1500"
    assert f.data["target_sid"] == "S-1-5-21-1-2-3-512"
    assert f.data["right"]      == "GenericAll"

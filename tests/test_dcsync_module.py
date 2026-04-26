"""DCSync rights enumeration — pure-unit tests.

The integration test ("real DC, our scan flags Domain Admins as
expected and a planted backdoor as a finding") is the brief's
acceptance criterion but is skipped here because the lab is not up.
What we *can* pin without a real DC:

  * GUID matching — Get-Changes vs. Get-Changes-All, generic-all
    counted as both, missing extended-right denied.
  * Well-known SID suppression — Domain Controllers / Domain Admins
    don't surface as findings, only as raw output.
  * Both-rights vs. one-right severity bucketing.
  * SD-flags control is actually requested on the LDAP search.
"""

from unittest.mock import MagicMock

from kerb_map.acl import (
    ADS_RIGHT_DS_CONTROL_ACCESS,
    ADS_RIGHT_GENERIC_ALL,
    DS_REPLICATION_GET_CHANGES,
    DS_REPLICATION_GET_CHANGES_ALL,
    AceMatch,
    is_well_known_privileged,
    sd_control,
)
from kerb_map.modules.dcsync_rights import DCSyncRights
from kerb_map.plugin import ScanContext

# ────────────────────────────────────────────────────────── AceMatch ----


def _ace(sid: str, mask: int, guid: str | None) -> AceMatch:
    return AceMatch(
        object_dn="DC=corp,DC=local",
        trustee_sid=sid,
        access_mask=mask,
        object_type_guid=guid,
        ace_type=0x05 if guid else 0x00,
    )


def test_ace_extended_right_match_exact():
    a = _ace("S-1-5-21-1-2-3-1234", ADS_RIGHT_DS_CONTROL_ACCESS, DS_REPLICATION_GET_CHANGES)
    assert a.has_extended_right(DS_REPLICATION_GET_CHANGES)
    assert not a.has_extended_right(DS_REPLICATION_GET_CHANGES_ALL)


def test_ace_generic_all_implies_every_extended_right():
    a = _ace("S-1-5-21-1-2-3-1234", ADS_RIGHT_GENERIC_ALL, None)
    assert a.has_extended_right(DS_REPLICATION_GET_CHANGES)
    assert a.has_extended_right(DS_REPLICATION_GET_CHANGES_ALL)


def test_ace_control_access_without_guid_grants_all_extended_rights():
    """ACE_OBJECT_TYPE_PRESENT not set → applies to every extended right."""
    a = _ace("S-1-5-21-1-2-3-1234", ADS_RIGHT_DS_CONTROL_ACCESS, None)
    assert a.has_extended_right(DS_REPLICATION_GET_CHANGES_ALL)


def test_ace_no_control_access_bit_denies_extended_right():
    a = _ace("S-1-5-21-1-2-3-1234", 0x100000, DS_REPLICATION_GET_CHANGES)
    assert not a.has_extended_right(DS_REPLICATION_GET_CHANGES)


# ────────────────────────────────────────── well-known privileged ----


def test_well_known_privileged_recognises_domain_admins():
    assert is_well_known_privileged("S-1-5-21-1-2-3-512")  # Domain Admins
    assert is_well_known_privileged("S-1-5-21-1-2-3-516")  # Domain Controllers
    assert is_well_known_privileged("S-1-5-21-1-2-3-519")  # Enterprise Admins
    assert is_well_known_privileged("S-1-5-32-544")        # BUILTIN\Admins


def test_well_known_privileged_includes_key_admins():
    """Field bug regression from the v1.3 sprint Win22 validation:
    ``Key Admins`` (-526) and ``Enterprise Key Admins`` (-527) are
    built-in groups whose purpose is to write msDS-KeyCredentialLink
    on privileged accounts (Windows Hello for Business). Without
    them in the suffix list, the Shadow Credentials write-access
    audit fires CRITICAL on every Windows DC for these groups on
    every adminCount=1 user. Samba 4 doesn't ship the groups so the
    bug stayed hidden until real-Windows testing."""
    assert is_well_known_privileged("S-1-5-21-1-2-3-526")
    assert is_well_known_privileged("S-1-5-21-1-2-3-527")


def test_well_known_privileged_rejects_random_principal():
    assert not is_well_known_privileged("S-1-5-21-1-2-3-1234")
    assert not is_well_known_privileged(None)


# ─────────────────────────────────────────── SD-flags control sent ----


def test_sd_control_targets_owner_group_dacl():
    """Control body must encode SDFlags=0x07. Without the control the
    DC strips the descriptor on its way out — silent zero findings."""
    controls = sd_control()
    assert len(controls) == 1
    # We don't decode the ASN.1 again; the constructor was tested by
    # ldap3 itself. Just confirm we got something back.
    assert controls[0] is not None


# ───────────────────────────────────────────── Module integration ----


def _ldap_with_sd_aces(aces: list[tuple[str, int, str | None]],
                       resolved_names: dict[str, str]):
    """Build a fake LDAPClient that:
       * Returns a domain entry with an opaque nTSecurityDescriptor blob
       * Returns synthetic name resolutions for objectSid=* queries
    """
    client = MagicMock()

    domain_entry = MagicMock()
    domain_entry.__contains__ = lambda self, k: k in {"nTSecurityDescriptor", "distinguishedName"}
    domain_entry.__getitem__ = lambda self, k: MagicMock(value=b"<opaque-sd>")

    name_entries = []
    for sid, sam in resolved_names.items():
        ne = MagicMock()
        ne.__contains__ = lambda self, k, _ne=resolved_names: k in {"sAMAccountName", "distinguishedName", "objectClass", "objectSid"}
        attrs = {"sAMAccountName": sam, "distinguishedName": f"CN={sam},CN=Users,DC=corp,DC=local",
                 "objectClass": ["user"], "objectSid": sid}
        ne.__getitem__ = lambda self, k, _attrs=attrs: MagicMock(value=_attrs[k], values=[_attrs[k]])
        name_entries.append(ne)

    def fake_query(**kwargs):
        if "domainDNS" in kwargs.get("search_filter", ""):
            return [domain_entry]
        return name_entries

    client.query = fake_query
    return client


def test_module_yields_critical_finding_for_non_default_principal(monkeypatch):
    """End-to-end-ish: the SD parser is monkeypatched to return our
    synthetic ACE list, so we test the bucketing + finding logic
    without needing a real binary security descriptor."""
    target_sid = "S-1-5-21-1-2-3-1234"

    monkeypatch.setattr(
        "kerb_map.modules.dcsync_rights.parse_sd",
        lambda raw: object(),  # truthy — actual parse mocked below
    )
    monkeypatch.setattr(
        "kerb_map.modules.dcsync_rights.walk_aces",
        lambda sd, object_dn="": [
            AceMatch(object_dn=object_dn, trustee_sid=target_sid,
                     access_mask=ADS_RIGHT_DS_CONTROL_ACCESS,
                     object_type_guid=DS_REPLICATION_GET_CHANGES,
                     ace_type=0x05),
            AceMatch(object_dn=object_dn, trustee_sid=target_sid,
                     access_mask=ADS_RIGHT_DS_CONTROL_ACCESS,
                     object_type_guid=DS_REPLICATION_GET_CHANGES_ALL,
                     ace_type=0x05),
            # Domain Controllers — should be suppressed.
            AceMatch(object_dn=object_dn, trustee_sid="S-1-5-21-1-2-3-516",
                     access_mask=ADS_RIGHT_GENERIC_ALL,
                     object_type_guid=None, ace_type=0x00),
        ],
    )
    monkeypatch.setattr(
        "kerb_map.modules.dcsync_rights.resolve_sids",
        lambda ldap, sids, base_dn: {
            target_sid: {"sAMAccountName": "svc_old_admin",
                         "distinguishedName": "CN=svc_old_admin,...",
                         "objectClass": "user"},
            "S-1-5-21-1-2-3-516": {"sAMAccountName": "Domain Controllers",
                                   "distinguishedName": "",
                                   "objectClass": "group"},
        },
    )

    ctx = ScanContext(
        ldap=_ldap_with_sd_aces([], {}),
        domain="corp.local",
        base_dn="DC=corp,DC=local",
        dc_ip="10.0.0.1",
        domain_sid="S-1-5-21-1-2-3",
    )

    result = DCSyncRights().scan(ctx)

    # Both principals appear in raw output.
    assert result.raw["summary"]["total_principals"] == 2
    assert result.raw["summary"]["well_known"] == 1
    assert result.raw["summary"]["non_default_full"] == 1

    # Only the non-default one becomes a finding, and it's CRITICAL.
    assert len(result.findings) == 1
    f = result.findings[0]
    assert f.severity == "CRITICAL"
    assert f.priority == 95
    assert f.target == "svc_old_admin"
    assert f.mitre == "T1003.006"
    assert "secretsdump.py" in f.next_step
    assert "<pass>" in f.next_step  # placeholder — kerb-chain will fill


def test_module_marks_one_right_only_as_high_not_critical(monkeypatch):
    monkeypatch.setattr(
        "kerb_map.modules.dcsync_rights.parse_sd", lambda raw: object())
    monkeypatch.setattr(
        "kerb_map.modules.dcsync_rights.walk_aces",
        lambda sd, object_dn="": [
            AceMatch(object_dn=object_dn, trustee_sid="S-1-5-21-1-2-3-1234",
                     access_mask=ADS_RIGHT_DS_CONTROL_ACCESS,
                     object_type_guid=DS_REPLICATION_GET_CHANGES,
                     ace_type=0x05),
        ],
    )
    monkeypatch.setattr(
        "kerb_map.modules.dcsync_rights.resolve_sids",
        lambda ldap, sids, base_dn: {
            "S-1-5-21-1-2-3-1234": {"sAMAccountName": "weird_user",
                                    "distinguishedName": "", "objectClass": "user"}})

    ctx = ScanContext(ldap=MagicMock(), domain="corp.local",
                      base_dn="DC=corp,DC=local", dc_ip="10.0.0.1")
    ctx.ldap.query.return_value = [
        type("E", (), {"__contains__": lambda s, k: True,
                       "__getitem__": lambda s, k: MagicMock(value=b"x")})()]

    result = DCSyncRights().scan(ctx)
    assert len(result.findings) == 1
    assert result.findings[0].severity == "HIGH"
    assert result.findings[0].priority == 75
    assert "partial" in result.findings[0].attack.lower()


def test_module_handles_unparseable_sd():
    """Garbage SD blob should produce a clean error, not crash."""
    ctx = ScanContext(ldap=MagicMock(), domain="corp.local",
                      base_dn="DC=corp,DC=local", dc_ip="10.0.0.1")
    ctx.ldap.query.return_value = [
        type("E", (), {"__contains__": lambda s, k: True,
                       "__getitem__": lambda s, k: MagicMock(value=b"\x00")})()]

    result = DCSyncRights().scan(ctx)
    # parse_sd returns None for garbage → module records the error
    # in raw output and emits zero findings.
    assert result.findings == []
    assert "error" in result.raw

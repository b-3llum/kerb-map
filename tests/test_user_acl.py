"""User ACL audit — lateral-movement enumeration (field gap fix).

Pin the contract: non-default writers on enabled non-Tier-0 users are
HIGH/MEDIUM lateral-edge findings; the noise floor is kept low by
suppressing Account Operators / Server Operators / Backup Operators
(their broad rights on regular users are by AD design and the Tier-0
audit owns the membership question).

Field-validated against shibuya.jujutsu.local where ``choso`` had
WriteDACL on ``itadori`` — caught by this module, missed by the
Tier-0 audit.
"""

from unittest.mock import MagicMock

from kerb_map.acl import (
    ADS_RIGHT_GENERIC_ALL,
    ADS_RIGHT_WRITE_DAC,
    AceMatch,
)
from kerb_map.modules.user_acl import (
    DEFAULT_MAX_FINDINGS,
    DEFAULT_PRIVILEGED_BUILTIN_SIDS,
    UserAclAudit,
)
from kerb_map.plugin import ScanContext


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


def _user(sam, sid_bytes, sd=b"<sd>"):
    """Mock LDAP user entry. ``sid_bytes`` becomes objectSid → sid_to_str."""
    return _entry({
        "sAMAccountName":       sam,
        "distinguishedName":    f"CN={sam},CN=Users,DC=corp,DC=local",
        "objectSid":            sid_bytes,
        "nTSecurityDescriptor": sd,
    })


def _ctx(users):
    ldap = MagicMock()
    ldap.query.return_value = users
    return ScanContext(
        ldap=ldap, domain="corp.local", base_dn="DC=corp,DC=local",
        dc_ip="10.0.0.1", domain_sid="S-1-5-21-1-2-3",
    )


# Pre-built SID bytes for two test users.
SID_ITADORI_BYTES = bytes.fromhex(
    "0105000000000005150000000a0000001400000028000000"
    "5d030000"
)  # S-1-5-21-10-20-40-861
SID_CHOSO       = "S-1-5-21-10-20-40-862"
SID_ACCT_OPS    = "S-1-5-32-548"
SID_DOMAIN_ADMS = "S-1-5-21-10-20-40-512"
SID_SYSTEM      = "S-1-5-18"


# ────────────────────────────────────── headline finding ─


def test_writedacl_from_non_default_principal_is_high(monkeypatch):
    """The headline field-bug case: ``choso`` has WriteDACL on
    ``itadori``. Pre-fix Tier-0 audit missed this entirely (itadori
    isn't tier-0); this module catches it."""
    monkeypatch.setattr("kerb_map.modules.user_acl.parse_sd",
                        lambda raw: object() if raw else None)
    monkeypatch.setattr(
        "kerb_map.modules.user_acl.walk_aces",
        lambda sd, object_dn="": [
            AceMatch(object_dn=object_dn, trustee_sid=SID_CHOSO,
                     access_mask=ADS_RIGHT_WRITE_DAC,
                     object_type_guid=None, ace_type=0x00),
        ])
    monkeypatch.setattr(
        "kerb_map.modules.user_acl.resolve_sids",
        lambda ldap, sids, base_dn: {SID_CHOSO: {"sAMAccountName": "choso"}})
    ctx = _ctx([_user("itadori", SID_ITADORI_BYTES)])
    out = UserAclAudit().scan(ctx)
    assert len(out.findings) == 1
    f = out.findings[0]
    assert f.severity == "HIGH"
    assert "choso" in f.reason
    assert "itadori" in f.reason
    assert "WriteDACL" in f.attack
    assert "→ itadori" in f.attack


# ────────────────────────────────────── expanded full-control mask ─


def test_expanded_full_control_mask_caught_via_writedac(monkeypatch):
    """Real-world DACLs often have the *expanded* 0xf01ff full-control
    mask instead of the literal GENERIC_ALL bit. The classifier must
    catch this via the WRITE_DAC bit (0x40000) embedded in 0xf01ff —
    the field bug was that Tier-0 audit missed expanded full-control
    on non-Tier-0 targets entirely."""
    monkeypatch.setattr("kerb_map.modules.user_acl.parse_sd",
                        lambda raw: object() if raw else None)
    # 0xf01ff — Account Operators / similar BUILTIN groups have this on
    # non-protected users by default, and so do attacker-granted
    # GenericAll edges. Use a non-default principal here.
    monkeypatch.setattr(
        "kerb_map.modules.user_acl.walk_aces",
        lambda sd, object_dn="": [
            AceMatch(object_dn=object_dn,
                     trustee_sid="S-1-5-21-10-20-40-1900",
                     access_mask=0xf01ff,
                     object_type_guid=None, ace_type=0x00),
        ])
    monkeypatch.setattr(
        "kerb_map.modules.user_acl.resolve_sids",
        lambda *a, **kw: {"S-1-5-21-10-20-40-1900":
                          {"sAMAccountName": "rogue"}})
    ctx = _ctx([_user("victim", SID_ITADORI_BYTES)])
    out = UserAclAudit().scan(ctx)
    assert len(out.findings) == 1
    # WriteDACL (priority 74) is what the classifier picks first since
    # it iterates GenericAll → WriteDACL → WriteOwner → GenericWrite
    # and 0xf01ff doesn't have the literal GENERIC_ALL bit (0x10000000).
    assert out.findings[0].attack.startswith("User ACL: WriteDACL")


# ────────────────────────────────────── suppressions ─


def test_well_known_privileged_writers_suppressed(monkeypatch):
    """Domain Admins, SYSTEM, Enterprise Admins etc. have these rights
    on everyone by design. Tier0AclAudit owns the question of who's
    in those groups; this module would only add noise."""
    monkeypatch.setattr("kerb_map.modules.user_acl.parse_sd",
                        lambda raw: object() if raw else None)
    monkeypatch.setattr(
        "kerb_map.modules.user_acl.walk_aces",
        lambda sd, object_dn="": [
            AceMatch(object_dn=object_dn, trustee_sid=SID_DOMAIN_ADMS,
                     access_mask=ADS_RIGHT_GENERIC_ALL,
                     object_type_guid=None, ace_type=0x00),
            AceMatch(object_dn=object_dn, trustee_sid=SID_SYSTEM,
                     access_mask=ADS_RIGHT_GENERIC_ALL,
                     object_type_guid=None, ace_type=0x00),
        ])
    monkeypatch.setattr(
        "kerb_map.modules.user_acl.resolve_sids", lambda *a, **kw: {})
    ctx = _ctx([_user("victim", SID_ITADORI_BYTES)])
    out = UserAclAudit().scan(ctx)
    assert out.findings == []


def test_account_operators_suppressed_by_default(monkeypatch):
    """Field-finding: in the lab, BUILTIN\\Account Operators had
    WriteDACL on every non-protected user — would generate one
    finding per user (10+ on a small lab, hundreds on real estate).
    Already-Tier-0-sensitive groups are suppressed so the operator
    sees the *attacker-grantable* edges, not the design-defaults."""
    monkeypatch.setattr("kerb_map.modules.user_acl.parse_sd",
                        lambda raw: object() if raw else None)
    monkeypatch.setattr(
        "kerb_map.modules.user_acl.walk_aces",
        lambda sd, object_dn="": [
            AceMatch(object_dn=object_dn, trustee_sid=SID_ACCT_OPS,
                     access_mask=ADS_RIGHT_WRITE_DAC,
                     object_type_guid=None, ace_type=0x00),
        ])
    monkeypatch.setattr(
        "kerb_map.modules.user_acl.resolve_sids", lambda *a, **kw: {})
    ctx = _ctx([_user("victim", SID_ITADORI_BYTES)])
    out = UserAclAudit().scan(ctx)
    assert out.findings == []


def test_self_ace_suppressed(monkeypatch):
    """Every user has rights on themselves (Self ACE for password
    change etc.). Self-on-self is not a finding."""
    self_sid = "S-1-5-21-10-20-40-861"   # matches SID_ITADORI_BYTES
    monkeypatch.setattr("kerb_map.modules.user_acl.parse_sd",
                        lambda raw: object() if raw else None)
    monkeypatch.setattr(
        "kerb_map.modules.user_acl.walk_aces",
        lambda sd, object_dn="": [
            AceMatch(object_dn=object_dn, trustee_sid=self_sid,
                     access_mask=ADS_RIGHT_GENERIC_ALL,
                     object_type_guid=None, ace_type=0x00),
        ])
    monkeypatch.setattr(
        "kerb_map.modules.user_acl.resolve_sids", lambda *a, **kw: {})
    ctx = _ctx([_user("itadori", SID_ITADORI_BYTES)])
    out = UserAclAudit().scan(ctx)
    assert out.findings == []


def test_account_operators_constant_includes_print_and_backup(monkeypatch):
    """Pin the suppression list so a refactor doesn't quietly drop
    one of the BUILTIN privilege groups — every entry was added in
    response to a real-world noise source."""
    assert "S-1-5-32-548" in DEFAULT_PRIVILEGED_BUILTIN_SIDS  # Acct Ops
    assert "S-1-5-32-549" in DEFAULT_PRIVILEGED_BUILTIN_SIDS  # Server Ops
    assert "S-1-5-32-550" in DEFAULT_PRIVILEGED_BUILTIN_SIDS  # Print Ops
    assert "S-1-5-32-551" in DEFAULT_PRIVILEGED_BUILTIN_SIDS  # Backup Ops


# ────────────────────────────────────── target enumeration ─


def test_no_users_returns_inapplicable():
    ctx = _ctx([])
    out = UserAclAudit().scan(ctx)
    assert out.findings == []
    assert out.raw["applicable"] is False


def test_query_excludes_admincount_one_users():
    """Tier-0 owns adminCount=1 users; this module covers the rest.
    Pin the LDAP filter so a regression doesn't double-cover them."""
    ctx = _ctx([])
    UserAclAudit().scan(ctx)
    captured = ctx.ldap.query.call_args.kwargs
    assert "(!(adminCount=1))" in captured["search_filter"]
    assert "(!(objectClass=computer))" in captured["search_filter"]
    # And disabled accounts excluded via the UAC bit.
    assert "userAccountControl:1.2.840.113556.1.4.803:=2" in captured["search_filter"]


# ────────────────────────────────────── output cap ─


def test_finding_cap_truncates_to_limit(monkeypatch):
    """A 5k-user estate with permissive ACLs would otherwise drown
    the priority table. Cap kicks in; raw_entries still records all
    so the operator can grep the JSON for the long tail."""
    n_users = DEFAULT_MAX_FINDINGS + 25
    users = [
        _user(f"u{i}",
              # Build a unique SID per user so self-suppression doesn't fire.
              # Bytes encode S-1-5-21-10-20-40-(900+i).
              bytes.fromhex(
                  "0105000000000005150000000a0000001400000028000000"
              ) + (900 + i).to_bytes(4, "little"))
        for i in range(n_users)
    ]
    monkeypatch.setattr("kerb_map.modules.user_acl.parse_sd",
                        lambda raw: object() if raw else None)
    monkeypatch.setattr(
        "kerb_map.modules.user_acl.walk_aces",
        lambda sd, object_dn="": [
            AceMatch(object_dn=object_dn,
                     trustee_sid="S-1-5-21-10-20-40-1900",
                     access_mask=ADS_RIGHT_GENERIC_ALL,
                     object_type_guid=None, ace_type=0x00),
        ])
    monkeypatch.setattr(
        "kerb_map.modules.user_acl.resolve_sids",
        lambda *a, **kw: {"S-1-5-21-10-20-40-1900":
                          {"sAMAccountName": "rogue"}})
    ctx = _ctx(users)
    out = UserAclAudit().scan(ctx)
    assert len(out.findings) == DEFAULT_MAX_FINDINGS
    assert out.raw["summary"]["truncated"] is True
    assert out.raw["summary"]["raw_entry_count"] == n_users

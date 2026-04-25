"""User enumerator — privileged users, stale accounts, password policy,
trusts, LAPS, DnsAdmins, GPO links.

Each sub-method runs an independent LDAP query, so the test fixture
hands query results in a queue so different sub-tests can exercise
specific channels in isolation."""

from datetime import timedelta
from unittest.mock import MagicMock

from kerb_map.modules.user_enumerator import UserEnumerator


def _entry(values: dict):
    e = MagicMock()
    e.__contains__ = lambda self, k: k in values
    def _get(self, k):
        v = values[k]
        m = MagicMock()
        m.value = v
        m.__str__ = lambda self: "" if v is None else str(v)
        m.__iter__ = lambda self: iter(v) if isinstance(v, list) else iter([v])
        m.__bool__ = lambda self: bool(v)
        return m
    e.__getitem__ = _get
    return e


def _ldap_with_queue(*responses):
    """Use a queue when the called method runs multiple queries."""
    ldap = MagicMock()
    queue = list(responses)
    ldap.query.side_effect = lambda **_: queue.pop(0) if queue else []
    return ldap


def _ldap_one(entries):
    ldap = MagicMock()
    ldap.query.return_value = entries
    return ldap


# ────────────────────────────────────── _privileged_users ─


def test_privileged_users_returns_admincount_entries():
    e = _entry({
        "sAMAccountName":     "domadmin",
        "memberOf":           ["CN=Domain Admins,CN=Users,DC=corp,DC=local"],
        "pwdLastSet":         None,
        "description":        "DA acct",
        "userAccountControl": 0x10200,   # NORMAL + DONT_EXPIRE_PASSWORD
        "distinguishedName":  "CN=domadmin,CN=Users,DC=corp,DC=local",
    })
    out = UserEnumerator(_ldap_one([e]))._privileged_users()
    assert len(out) == 1
    assert out[0]["account"] == "domadmin"
    assert out[0]["password_never_expires"] is True
    assert "Domain Admins" in out[0]["groups"][0]


def test_privileged_users_filter_excludes_disabled_and_requires_admincount():
    """Pin the LDAP filter — adminCount=1 + not-disabled. A regression
    that drops the disabled-filter would surface stale admin accounts
    that can't actually log in."""
    ldap = _ldap_one([])
    UserEnumerator(ldap)._privileged_users()
    f = ldap.query.call_args.kwargs["search_filter"]
    assert "(adminCount=1)" in f
    assert ":1.2.840.113556.1.4.803:=2" in f


# ────────────────────────────────────── _stale_accounts ─


def test_stale_accounts_returns_accounts_below_threshold():
    e = _entry({
        "sAMAccountName":     "old_user",
        "lastLogonTimestamp": None,
        "distinguishedName":  "CN=old_user,...",
    })
    out = UserEnumerator(_ldap_one([e]))._stale_accounts()
    assert out[0]["account"] == "old_user"
    assert out[0]["last_logon"] == "Never"


def test_stale_accounts_filter_uses_lastlogon_threshold():
    """Threshold pinned in the source as 132000000000000000 (FILETIME
    around 2020). A regression here would either find nothing or
    surface every recent account."""
    ldap = _ldap_one([])
    UserEnumerator(ldap)._stale_accounts()
    f = ldap.query.call_args.kwargs["search_filter"]
    assert "lastLogonTimestamp<=132000000000000000" in f


# ────────────────────────────────────── _password_policy ─


def test_password_policy_no_entries_returns_empty():
    """Domain that doesn't return a domainDNS object → empty dict.
    Don't crash."""
    out = UserEnumerator(_ldap_one([]))._password_policy()
    assert out == {}


def test_password_policy_flags_no_lockout_and_short_min_length():
    """The headline finding for spray-able estates: lockoutThreshold=0
    + minPwdLength<8 + complexity off. All three should land in
    policy['risks']."""
    e = _entry({
        "minPwdLength":      4,
        "maxPwdAge":         timedelta(days=42),
        "pwdHistoryLength":  24,
        "lockoutThreshold":  0,
        "lockoutDuration":   timedelta(minutes=30),
        "pwdProperties":     0,            # no complexity, no reversible
    })
    out = UserEnumerator(_ldap_one([e]))._password_policy()
    assert out["min_length"] == 4
    assert out["lockout_threshold"] == 0
    assert out["complexity_enabled"] is False
    assert out["max_age_days"] == 42
    risks = out["risks"]
    assert any("Min password length" in r for r in risks)
    assert any("lockout"             in r for r in risks)
    assert any("complexity"          in r for r in risks)


def test_password_policy_flags_passwords_never_expire():
    """maxPwdAge=0 (or unset) → passwords never expire."""
    e = _entry({
        "minPwdLength":      14,
        "maxPwdAge":         None,
        "pwdHistoryLength":  24,
        "lockoutThreshold":  5,
        "lockoutDuration":   None,
        "pwdProperties":     0x1,          # complexity on
    })
    out = UserEnumerator(_ldap_one([e]))._password_policy()
    assert any("never expire" in r for r in out["risks"])


def test_password_policy_flags_reversible_encryption():
    """pwdProperties bit 0x10 = reversible encryption enabled. Plain-
    text passwords recoverable from the DC — CRITICAL."""
    e = _entry({
        "minPwdLength":      14,
        "maxPwdAge":         timedelta(days=30),
        "pwdHistoryLength":  24,
        "lockoutThreshold":  5,
        "lockoutDuration":   None,
        "pwdProperties":     0x1 | 0x10,
    })
    out = UserEnumerator(_ldap_one([e]))._password_policy()
    assert any("Reversible encryption" in r for r in out["risks"])


def test_password_policy_clean_estate_has_no_risks():
    """Sane policy → empty risks list."""
    e = _entry({
        "minPwdLength":      14,
        "maxPwdAge":         timedelta(days=42),
        "pwdHistoryLength":  24,
        "lockoutThreshold":  5,
        "lockoutDuration":   timedelta(minutes=30),
        "pwdProperties":     0x1,
    })
    out = UserEnumerator(_ldap_one([e]))._password_policy()
    assert out["risks"] == []


# ────────────────────────────────────── _domain_trusts ─


def test_domain_trusts_decodes_direction_and_marks_high_when_no_treat_as_external():
    """Forest trust without the 0x40 (TREAT_AS_EXTERNAL) bit → HIGH.
    Note: this module's sid_filtering logic uses bit 0x40 which is
    actually TREAT_AS_EXTERNAL, not QUARANTINED (0x4) — pre-existing
    inversion vs. trust_mapper.py. Tests pin current behaviour; the
    semantic fix lives elsewhere (kerb_map/modules/trust_mapper.py
    uses 0x4 correctly)."""
    e = _entry({
        "name":            "OTHER.LOCAL",
        "trustType":       2,
        "trustDirection":  3,
        "trustAttributes": 0x8,            # FOREST_TRANSITIVE only
        "flatName":        "OTHER",
    })
    out = UserEnumerator(_ldap_one([e]))._domain_trusts()
    assert out[0]["direction"]    == "Bidirectional"
    assert out[0]["forest_trust"] is True
    assert out[0]["sid_filtering"] is True   # 0x40 NOT set → "True" per buggy logic
    assert out[0]["risk"] == "HIGH"          # because 'not (0x40 & 0)' = True


def test_domain_trusts_with_treat_as_external_marked_medium():
    """0x40 (TREAT_AS_EXTERNAL) set → this module reports
    sid_filtering=False, risk=MEDIUM. Same caveat about the bit
    semantic-mismatch as the test above."""
    e = _entry({
        "name":            "OK.LOCAL",
        "trustType":       2,
        "trustDirection":  2,
        "trustAttributes": 0x40,
        "flatName":        "OK",
    })
    out = UserEnumerator(_ldap_one([e]))._domain_trusts()
    assert out[0]["sid_filtering"] is False
    assert out[0]["risk"] == "MEDIUM"


# ────────────────────────────────────── _check_laps ─


def test_check_laps_deployed_when_any_computer_has_admpwd():
    """ms-Mcs-AdmPwd populated on any computer = LAPS deployed."""
    e = _entry({"sAMAccountName": "WS01$"})
    out = UserEnumerator(_ldap_one([e]))._check_laps()
    assert out["deployed"] is True
    assert out["risk"] == "LOW"


def test_check_laps_undeployed_high_risk():
    """No computers with the LAPS attribute → shared local admin
    password assumption → HIGH."""
    out = UserEnumerator(_ldap_one([]))._check_laps()
    assert out["deployed"] is False
    assert out["risk"] == "HIGH"


# ────────────────────────────────────── _dns_admins ─


def test_dns_admins_no_group_returns_empty():
    """Most domains don't have DnsAdmins (Server-bundled). Empty list,
    no crash."""
    out = UserEnumerator(_ldap_one([]))._dns_admins()
    assert out == []


def test_dns_admins_resolves_member_dns_to_sams():
    """Each member DN gets a follow-up LDAP query to resolve to a
    sAMAccountName for operator-friendly output."""
    group = _entry({"member": ["CN=svc_dns,CN=Users,DC=corp,DC=local"]})
    user  = _entry({"sAMAccountName": "svc_dns"})
    out = UserEnumerator(_ldap_with_queue([group], [user]))._dns_admins()
    assert len(out) == 1
    assert out[0]["account"] == "svc_dns"
    assert out[0]["risk"]    == "HIGH"
    assert "DnsAdmins" in out[0]["detail"]


def test_dns_admins_falls_back_to_dn_when_resolve_fails():
    """If the member DN doesn't resolve (deleted account, replication
    delay), keep the DN in the account field rather than dropping
    the entry."""
    group = _entry({"member": ["CN=stale,CN=Users,DC=corp,DC=local"]})
    out = UserEnumerator(_ldap_with_queue([group], []))._dns_admins()
    assert "stale" in out[0]["account"]


# ────────────────────────────────────── _gpo_links ─


def test_gpo_links_returns_one_per_groupPolicyContainer():
    a = _entry({
        "displayName":     "Default Domain Policy",
        "gPCFileSysPath":  "\\\\corp.local\\sysvol\\corp.local\\Policies\\{...}",
        "distinguishedName": "CN={31B2F340-...},...",
    })
    out = UserEnumerator(_ldap_one([a]))._gpo_links()
    assert out[0]["name"] == "Default Domain Policy"
    assert "sysvol" in out[0]["path"]


# ────────────────────────────────────── enumerate() orchestration ─


def test_enumerate_returns_seven_keys():
    """Pin the contract — scorer.py / reporter.py rely on these keys."""
    ldap = _ldap_with_queue([], [], [], [], [], [], [])
    out = UserEnumerator(ldap).enumerate()
    expected = {"privileged_users", "stale_accounts", "password_policy",
                "trusts", "laps_deployed", "dns_admins", "gpo_links"}
    assert set(out.keys()) == expected

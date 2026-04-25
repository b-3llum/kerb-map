"""ASREProast scanner — finds DONT_REQUIRE_PREAUTH accounts.

These tests pin the LDAP filter shape, the disabled-account skip, the
admin detection (adminCount=1 OR memberOf Domain Admins), and the
crack-score boundaries. Mocked LDAP — no DC needed.
"""

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

from kerb_map.modules.asrep_scanner import ASREPAccount, ASREPScanner


def _entry(values: dict):
    """ldap3-shaped mock. str(e['sAMAccountName']) → the value (which
    is what asrep_scanner uses), e['memberOf'] iterable, e['attr'].value
    direct access for typed reads."""
    e = MagicMock()
    e.__contains__ = lambda self, k: k in values
    def _get(self, k):
        v = values[k]
        m = MagicMock()
        m.value = v
        m.__iter__ = lambda self: iter(v) if isinstance(v, list) else iter([v])
        m.__str__ = lambda self: "" if v is None else str(v)
        return m
    e.__getitem__ = _get
    return e


def _ldap(entries):
    """Fake LDAPClient with a recorded query() that returns ``entries``."""
    ldap = MagicMock()
    ldap.query.return_value = entries
    return ldap


# ────────────────────────────────────── filter shape ─


def test_scan_uses_dont_require_preauth_filter():
    """The whole module hinges on this LDAP filter — bit 0x400000 of
    userAccountControl. A regression here would silently return zero
    AS-REP candidates and the operator would think the domain was clean."""
    ldap = _ldap([])
    ASREPScanner(ldap).scan()
    captured = ldap.query.call_args.kwargs
    assert "userAccountControl:1.2.840.113556.1.4.803:=4194304" in captured["search_filter"]
    assert "(!(objectClass=computer))" in captured["search_filter"]


def test_scan_requests_required_attributes():
    ldap = _ldap([])
    ASREPScanner(ldap).scan()
    attrs = set(ldap.query.call_args.kwargs["attributes"])
    assert {"sAMAccountName", "pwdLastSet", "lastLogonTimestamp",
            "userAccountControl", "memberOf", "description",
            "adminCount"} <= attrs


# ────────────────────────────────────── disabled-account skip ─


def _basic_entry(*, sam="alice", uac=0x400000, admin_count=None,
                 member_of=None, pwd_last=None, last_logon=None,
                 description=""):
    return _entry({
        "sAMAccountName":     sam,
        "userAccountControl": uac,
        "adminCount":         admin_count,
        "memberOf":           member_of or [],
        "pwdLastSet":         pwd_last,
        "lastLogonTimestamp": last_logon,
        "description":        description,
    })


def test_disabled_account_skipped():
    """ACCOUNTDISABLE bit (0x2) means "operator can't authenticate as
    them anyway" — no value to crack."""
    disabled = _basic_entry(uac=0x400000 | 0x2)  # DONT_REQUIRE_PREAUTH | DISABLE
    out = ASREPScanner(_ldap([disabled])).scan()
    assert out == []


def test_enabled_account_returned():
    enabled = _basic_entry(uac=0x400000)
    out = ASREPScanner(_ldap([enabled])).scan()
    assert len(out) == 1
    assert out[0]["account"] == "alice"
    assert out[0]["is_enabled"] is True


# ────────────────────────────────────── admin detection ─


def test_admin_count_one_marks_admin():
    """adminCount=1 = AdminSDHolder-protected = Tier-0. Always admin."""
    e = _basic_entry(sam="oldadmin", admin_count=1)
    out = ASREPScanner(_ldap([e])).scan()
    assert out[0]["is_admin"] is True


def test_membership_in_domain_admins_marks_admin_case_insensitively():
    """The membership check folds case — DOmain ADmins still counts."""
    e = _basic_entry(
        sam="bob",
        member_of=["CN=Domain Admins,CN=Users,DC=corp,DC=local"],
    )
    out = ASREPScanner(_ldap([e])).scan()
    assert out[0]["is_admin"] is True


def test_non_admin_account_marked_false():
    e = _basic_entry(sam="joe", member_of=["CN=Users,CN=Builtin,DC=corp,DC=local"])
    out = ASREPScanner(_ldap([e])).scan()
    assert out[0]["is_admin"] is False


# ────────────────────────────────────── crack score ─


def test_score_baseline_for_non_admin_no_age():
    """No creds needed = base 60 even for a fresh non-admin."""
    a = ASREPAccount(account="x", password_age_days=None, is_admin=False,
                     is_enabled=True, description="", last_logon_days=None)
    assert ASREPScanner(None)._score(a) == 60


def test_score_admin_bonus():
    a = ASREPAccount(account="x", password_age_days=None, is_admin=True,
                     is_enabled=True, description="", last_logon_days=None)
    assert ASREPScanner(None)._score(a) == 85


def test_score_old_password_bonus():
    """Password >365 days suggests it's been crackable for ages and
    nobody's rotated — bumps score by 15."""
    a = ASREPAccount(account="x", password_age_days=400, is_admin=False,
                     is_enabled=True, description="", last_logon_days=None)
    assert ASREPScanner(None)._score(a) == 75


def test_score_admin_plus_old_password_caps_at_100():
    """60 + 25 + 15 = 100. Cap stops the score from blowing past the
    ranking range when both bonuses apply."""
    a = ASREPAccount(account="x", password_age_days=999, is_admin=True,
                     is_enabled=True, description="", last_logon_days=None)
    assert ASREPScanner(None)._score(a) == 100


def test_score_password_age_threshold_is_one_year():
    """365 days exactly = no bonus. 366 = bonus."""
    young = ASREPAccount(account="x", password_age_days=365, is_admin=False,
                         is_enabled=True, description="", last_logon_days=None)
    old = ASREPAccount(account="x", password_age_days=366, is_admin=False,
                       is_enabled=True, description="", last_logon_days=None)
    assert ASREPScanner(None)._score(young) == 60
    assert ASREPScanner(None)._score(old)   == 75


# ────────────────────────────────────── _days_since ─


def test_days_since_none_returns_none():
    assert ASREPScanner._days_since(None) is None


def test_days_since_recent_dt_is_small_positive():
    recent = datetime.now(timezone.utc) - timedelta(days=10)
    assert ASREPScanner._days_since(recent) == 10


def test_days_since_naive_dt_assumed_utc():
    """ldap3 sometimes returns naive datetimes. Don't crash on them —
    assume UTC, the AD canonical timezone."""
    naive = datetime.now() - timedelta(days=5)
    out = ASREPScanner._days_since(naive)
    assert out in (5, 4, 6)   # tolerate wall-clock drift across midnight


# ────────────────────────────────────── _memberships ─


def test_memberships_strips_cn_prefix_and_folds_case():
    """The set is used by 'domain admins' membership check — must be
    lowercase."""
    e = _basic_entry(member_of=[
        "CN=Domain Admins,CN=Users,DC=corp,DC=local",
        "CN=Backup Operators,CN=Builtin,DC=corp,DC=local",
    ])
    out = ASREPScanner._memberships(e)
    assert "domain admins" in out
    assert "backup operators" in out


def test_memberships_handles_empty_member_of():
    """Account with no group memberships → empty set, not crash."""
    e = _basic_entry(member_of=[])
    assert ASREPScanner._memberships(e) == set()


# ────────────────────────────────────── ranking / output ─


def test_results_sorted_by_score_descending():
    a_admin = _basic_entry(sam="admin", admin_count=1)
    b_normal = _basic_entry(sam="normal")
    out = ASREPScanner(_ldap([b_normal, a_admin])).scan()
    assert [r["account"] for r in out] == ["admin", "normal"]


def test_results_returned_as_dicts_not_dataclasses():
    """Downstream Scorer reads dicts. Pin the contract."""
    out = ASREPScanner(_ldap([_basic_entry()])).scan()
    assert isinstance(out[0], dict)
    assert {"account", "crack_score", "is_admin", "is_enabled",
            "password_age_days", "description", "last_logon_days"} <= set(out[0])

"""SPN scanner — Kerberoastable account discovery + crack scoring.

The score table is what bumps an SPN account up the priority list,
so the boundary cases (RC4 vs AES-only, age thresholds, admin
membership, high-value SPN types) deserve regression coverage.
"""

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

from kerb_map.modules.spn_scanner import (
    ADMIN_GROUPS,
    HIGH_VALUE_SPNS,
    SPNAccount,
    SPNScanner,
)


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


def _ldap(entries):
    ldap = MagicMock()
    ldap.query.return_value = entries
    return ldap


def _spn_entry(*, sam="svc_sql", spns=None, enc=0x4, age_days=None,
               admin=False, member_of=None, description="",
               last_logon_days=None):
    """Build a Kerberoastable LDAP entry. ``enc`` defaults to RC4-only
    so the score lands in the HIGH band by default."""
    pls = (datetime.now(timezone.utc) - timedelta(days=age_days)) if age_days is not None else None
    ll  = (datetime.now(timezone.utc) - timedelta(days=last_logon_days)) if last_logon_days is not None else None
    return _entry({
        "sAMAccountName":                 sam,
        "servicePrincipalName":           spns or ["MSSQLSvc/sql01.corp.local"],
        "pwdLastSet":                     pls,
        "lastLogonTimestamp":             ll,
        "msDS-SupportedEncryptionTypes":  enc,
        "memberOf":                       member_of or [],
        "userAccountControl":             0,
        "description":                    description,
        "adminCount":                     1 if admin else None,
    })


# ────────────────────────────────────── _supports_rc4 / _aes_only ─


def test_rc4_supported_when_enc_zero_default():
    """msDS-SupportedEncryptionTypes=0 = "no explicit setting" =
    AD's RC4 default kicks in. Critical to flag — operators don't
    realise the default is RC4."""
    assert SPNScanner._supports_rc4(0) is True
    assert SPNScanner._aes_only(0)     is False


def test_rc4_explicit_bit():
    assert SPNScanner._supports_rc4(0x4) is True


def test_aes_only_when_aes_set_and_no_rc4():
    """0x18 is AES (128+256). Without 0x4 (RC4) → aes_only."""
    assert SPNScanner._aes_only(0x18)     is True
    assert SPNScanner._supports_rc4(0x18) is False


def test_rc4_plus_aes_is_not_aes_only():
    """Mixed → still RC4-roastable. Score weights this lower than
    pure RC4 because operator can request either type."""
    assert SPNScanner._supports_rc4(0x4 | 0x18) is True
    assert SPNScanner._aes_only(0x4 | 0x18)     is False


# ────────────────────────────────────── _days_since ─


def test_days_since_none_returns_none():
    assert SPNScanner._days_since(None) is None


def test_days_since_handles_naive_datetime():
    """ldap3 sometimes returns naive datetimes — assume UTC, don't
    raise."""
    naive = datetime.now() - timedelta(days=10)
    out = SPNScanner._days_since(naive)
    assert out in (10, 9, 11)


def test_days_since_aware_datetime_round_trips():
    aware = datetime.now(timezone.utc) - timedelta(days=42)
    assert SPNScanner._days_since(aware) == 42


# ────────────────────────────────────── _get_memberships ─


def test_get_memberships_strips_cn_and_lowercases():
    """Score lookup uses lowercased group names (ADMIN_GROUPS set is
    lowercase). Pin the casing contract."""
    e = _entry({"memberOf": [
        "CN=Domain Admins,CN=Users,DC=corp,DC=local",
        "CN=SQLPro,OU=Apps,DC=corp,DC=local",
    ]})
    out = SPNScanner._get_memberships(e)
    assert "domain admins" in out
    assert "sqlpro"        in out


def test_get_memberships_handles_empty():
    assert SPNScanner._get_memberships(_entry({"memberOf": []})) == set()


# ────────────────────────────────────── _score boundary table ─


def _acct(**kw):
    """Build an SPNAccount with sane defaults — overrides isolate
    one score factor at a time. Default ``spns`` is non-high-value
    so the score stays at 0 unless the test explicitly opts into a
    bonus."""
    base = dict(
        account="x", spns=["random/x"],
        password_age_days=None, rc4_allowed=False, aes_only=False,
        is_admin=False, is_service=False, description="",
        last_logon_days=None, never_logged_in=False,
    )
    base.update(kw)
    return SPNAccount(**base)


def test_score_rc4_only_full_weight():
    """RC4 supported AND not aes_only → +40 (full RC4 bonus)."""
    assert SPNScanner(MagicMock())._score(_acct(rc4_allowed=True, aes_only=False)) == 40


def test_score_rc4_with_aes_half_weight_via_dead_branch():
    """The scorer has an ``elif a.rc4_allowed`` branch (+20) that the
    parser can never trigger — _aes_only/_supports_rc4 are mutually
    exclusive in practice. Test the elif via direct SPNAccount
    construction so a refactor doesn't silently drop the branch."""
    assert SPNScanner(MagicMock())._score(
        _acct(rc4_allowed=True, aes_only=True)) == 20


def test_score_password_age_thresholds():
    """Three age tiers: >730 → +30, >365 → +20, >180 → +10."""
    s = SPNScanner(MagicMock())
    assert s._score(_acct(password_age_days=731)) == 30
    assert s._score(_acct(password_age_days=366)) == 20
    assert s._score(_acct(password_age_days=181)) == 10
    assert s._score(_acct(password_age_days=100)) == 0


def test_score_admin_bonus():
    assert SPNScanner(MagicMock())._score(_acct(is_admin=True)) == 20


def test_score_high_value_spn_bonus():
    """MSSQLSvc / kadmin / HTTP / WSMAN / RestrictedKrbHost — operator
    looks at these first."""
    assert SPNScanner(MagicMock())._score(_acct(spns=["MSSQLSvc/db.corp.local"])) == 10
    assert SPNScanner(MagicMock())._score(_acct(spns=["WSMAN/web.corp.local"]))   == 10
    assert SPNScanner(MagicMock())._score(_acct(spns=["random/svc.corp.local"]))  == 0


def test_score_never_logged_in_bonus():
    """Forgotten service account → likely weak/default password."""
    assert SPNScanner(MagicMock())._score(_acct(never_logged_in=True)) == 5


def test_score_caps_at_100():
    """Stack every bonus → would sum to 105; cap so the priority
    table doesn't overflow the bucket band."""
    s = SPNScanner(MagicMock())._score(_acct(
        rc4_allowed=True, aes_only=False, password_age_days=999,
        is_admin=True, spns=["MSSQLSvc/x"], never_logged_in=True,
    ))
    assert s == 100   # capped (40+30+20+10+5 = 105)


def test_priority_label_boundaries():
    s = SPNScanner._priority_label
    assert s(100) == "CRITICAL"
    assert s(80)  == "CRITICAL"
    assert s(79)  == "HIGH"
    assert s(60)  == "HIGH"
    assert s(59)  == "MEDIUM"
    assert s(40)  == "MEDIUM"
    assert s(39)  == "LOW"
    assert s(0)   == "LOW"


# ────────────────────────────────────── _parse / scan ─


def test_parse_extracts_account_and_spns():
    e = _spn_entry(sam="svc_db", spns=["MSSQLSvc/db.corp.local"])
    a = SPNScanner(MagicMock())._parse(e)
    assert a.account == "svc_db"
    assert a.spns    == ["MSSQLSvc/db.corp.local"]


def test_parse_admin_via_admin_count():
    e = _spn_entry(admin=True)
    a = SPNScanner(MagicMock())._parse(e)
    assert a.is_admin is True


def test_parse_admin_via_admin_group_membership():
    """adminCount might not be set, but membership in Domain Admins
    is the canonical signal — don't miss it."""
    e = _spn_entry(member_of=["CN=Domain Admins,CN=Users,DC=corp,DC=local"])
    a = SPNScanner(MagicMock())._parse(e)
    assert a.is_admin is True


def test_parse_service_naming_heuristic():
    """svc_/sql/service/_sa prefixes mark dedicated service accounts —
    weight in the report later. Check the prefix list is honoured."""
    for sam in ("svc_sql", "svc-app", "service_old", "sql_user", "_sa"):
        a = SPNScanner(MagicMock())._parse(_spn_entry(sam=sam))
        assert a.is_service is True, f"{sam} should be tagged service"
    a = SPNScanner(MagicMock())._parse(_spn_entry(sam="randomuser"))
    assert a.is_service is False


def test_parse_never_logged_in_when_last_logon_none():
    a = SPNScanner(MagicMock())._parse(_spn_entry(last_logon_days=None))
    assert a.never_logged_in is True


def test_scan_filter_excludes_computers_krbtgt_disabled():
    """Pin the filter — drift would either return computer SPNs (mostly
    noise) or include krbtgt (sensitive, special-handling needed)."""
    ldap = _ldap([])
    SPNScanner(ldap).scan()
    f = ldap.query.call_args.kwargs["search_filter"]
    assert "servicePrincipalName=*"           in f
    assert "(!(objectClass=computer))"        in f
    assert "(!(cn=krbtgt))"                   in f
    assert ":1.2.840.113556.1.4.803:=2"       in f   # disabled UAC bit (negated)


def test_scan_returns_dicts_sorted_by_score_desc():
    """Downstream Scorer reads dicts. Highest-score account first so
    the priority table renders in the right order."""
    weak  = _spn_entry(sam="weak",  enc=0x18, age_days=30)   # AES-only, fresh → low
    juicy = _spn_entry(sam="juicy", enc=0x4,  age_days=800,
                       admin=True)                            # RC4 + old + admin
    out = SPNScanner(_ldap([weak, juicy])).scan()
    assert isinstance(out[0], dict)
    assert out[0]["account"] == "juicy"
    assert out[1]["account"] == "weak"
    assert out[0]["crack_score"] > out[1]["crack_score"]


def test_admin_groups_lowercased():
    """ADMIN_GROUPS is lowercase because membership lookup folds case;
    a regression to mixed-case here would silently miss every admin."""
    for g in ("domain admins", "enterprise admins", "schema admins",
              "administrators"):
        assert g in ADMIN_GROUPS


def test_high_value_spns_pinned():
    """Pin the canonical high-value list so a refactor doesn't drop a
    juicy target type."""
    for spn in ("MSSQLSvc", "kadmin", "HTTP", "WSMAN", "RestrictedKrbHost"):
        assert spn in HIGH_VALUE_SPNS

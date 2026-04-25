"""Shared LDAP helpers — entry access, FILETIME, DN, UAC, SID."""

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

from kerb_map.ldap_helpers import (
    UAC,
    attr,
    attrs,
    cn_from_dn,
    days_since,
    dt_to_filetime,
    filetime_to_dt,
    is_domain_sid,
    sid_to_str,
    uac_has,
)

# ---------------------------------------------------------------- attr ----

def _entry(values: dict):
    """Build a fake ldap3-style entry from a dict."""
    e = MagicMock()
    e.__contains__ = lambda self, k: k in values
    e.__getitem__ = lambda self, k: MagicMock(value=values[k])
    return e


def test_attr_returns_value_when_present():
    assert attr(_entry({"sAMAccountName": "jsmith"}), "sAMAccountName") == "jsmith"


def test_attr_returns_default_when_missing():
    assert attr(_entry({}), "missing", default="fallback") == "fallback"


def test_attr_returns_default_on_none_value():
    assert attr(_entry({"x": None}), "x", default="d") == "d"


def test_attrs_normalises_to_list():
    assert attrs(_entry({"x": "single"}), "x") == ["single"]
    assert attrs(_entry({"x": ["a", "b"]}), "x") == ["a", "b"]
    assert attrs(_entry({}), "missing") == []


# ------------------------------------------------------------ FILETIME ----

def test_filetime_to_dt_round_trip():
    when = datetime(2026, 4, 25, 12, 0, 0, tzinfo=timezone.utc)
    ticks = dt_to_filetime(when)
    assert filetime_to_dt(ticks).replace(microsecond=0) == when


def test_filetime_to_dt_handles_zero_and_none():
    assert filetime_to_dt(0) is None
    assert filetime_to_dt(None) is None
    assert filetime_to_dt("not a number") is None


def test_filetime_to_dt_passes_through_datetimes():
    naive = datetime(2026, 1, 1)
    out = filetime_to_dt(naive)
    assert out.tzinfo == timezone.utc


def test_days_since_recent_value():
    recent = datetime.now(timezone.utc) - timedelta(days=30)
    assert days_since(dt_to_filetime(recent)) == 30


# ------------------------------------------------------------------ DN ----

def test_cn_from_dn_simple():
    assert cn_from_dn("CN=jsmith,CN=Users,DC=corp,DC=local") == "jsmith"


def test_cn_from_dn_handles_escaped_comma():
    # The classic "Smith, John" case — naïve split breaks on this.
    assert cn_from_dn(r"CN=Smith\, John,OU=Users,DC=corp,DC=local") == "Smith, John"


def test_cn_from_dn_empty():
    assert cn_from_dn("") == ""


# ----------------------------------------------------------------- UAC ----

def test_uac_has_known_bit():
    asrep_bit = UAC["DONT_REQUIRE_PREAUTH"]
    uac_value = asrep_bit | UAC["ACCOUNTDISABLE"]
    assert uac_has(uac_value, "DONT_REQUIRE_PREAUTH")
    assert uac_has(uac_value, "ACCOUNTDISABLE")
    assert not uac_has(uac_value, "TRUSTED_FOR_DELEGATION")


def test_uac_has_handles_garbage():
    assert not uac_has(None, "DONT_REQUIRE_PREAUTH")
    assert not uac_has("not a number", "DONT_REQUIRE_PREAUTH")


# ----------------------------------------------------------------- SID ----

def test_sid_to_str_renders_well_known_domain_sid():
    # S-1-5-21-1234567890-2345678901-3456789012 in binary form
    raw = bytes.fromhex(
        "01"            # revision
        "04"            # sub-authority count
        "000000000005"  # authority (big-endian, NT_AUTHORITY=5)
        "15000000"      # sub-auth 1: 21
        "d2029649"      # sub-auth 2 (little-endian)
        "8530c2dd"      # sub-auth 3
        "2bc0e6ee"      # sub-auth 4 (so we cleanly stop at 4 sub-auths)
    )
    sid = sid_to_str(raw)
    assert sid is not None
    assert sid.startswith("S-1-5-21-")
    assert sid.count("-") == 6  # S-1-5-21-X-Y-Z


def test_sid_to_str_passes_through_strings():
    assert sid_to_str("S-1-5-21-1-2-3") == "S-1-5-21-1-2-3"


def test_sid_to_str_handles_none():
    assert sid_to_str(None) is None
    assert sid_to_str(b"") is None


def test_is_domain_sid_truthy_only_for_domain():
    assert is_domain_sid("S-1-5-21-1-2-3-500")
    assert not is_domain_sid("S-1-5-32-544")  # builtin Administrators
    assert not is_domain_sid("S-1-1-0")       # Everyone
    assert not is_domain_sid(None)

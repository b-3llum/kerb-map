"""Recursive group resolution helper (brief §2.8).

Pins the matching-rule-in-chain LDAP filter shape and the conservative
error handling. ``is_member_of`` is the new primitive Tier-0 ACL audit
uses to suppress in-tier writers — a regression here would either
spam noise findings or hide real ones, so the contract is locked.
"""

from unittest.mock import MagicMock

from kerb_map.ldap_helpers import (
    LDAP_MATCHING_RULE_IN_CHAIN,
    find_chain_members,
    is_member_of,
)


def _entry(values: dict):
    e = MagicMock()
    e.__contains__ = lambda self, k: k in values
    e.__getitem__ = lambda self, k: MagicMock(value=values[k])
    return e


# ────────────────────────────────────────────── filter shape ────


def test_oid_matches_microsoft_documented_value():
    """1.2.840.113556.1.4.1941 is the documented OID for matching rule
    in chain. Don't drift — every test below depends on this."""
    assert LDAP_MATCHING_RULE_IN_CHAIN == "1.2.840.113556.1.4.1941"


def test_is_member_of_uses_chain_filter():
    """The filter must be (memberOf:1.2.840.113556.1.4.1941:=<DN>)
    — anything else is server-side recursive resolution we don't get."""
    ldap = MagicMock()
    captured = {}
    def fake_query(**kw):
        captured.update(kw)
        return []
    ldap.query.side_effect = fake_query

    is_member_of(ldap, "CN=alice,CN=Users,DC=corp,DC=local",
                 "CN=Domain Admins,CN=Users,DC=corp,DC=local")
    assert (
        f"memberOf:{LDAP_MATCHING_RULE_IN_CHAIN}:=" in captured["search_filter"]
    )
    assert "CN=Domain Admins" in captured["search_filter"]


def test_is_member_of_scopes_search_to_account_dn():
    """We search base = the candidate account, not the whole domain.
    Cuts the result set to "did this specific account come back?" — one
    entry max — which is much cheaper than walking the whole DIT."""
    ldap = MagicMock()
    captured = {}
    def fake_query(**kw):
        captured.update(kw)
        return []
    ldap.query.side_effect = fake_query

    is_member_of(ldap, "CN=alice,...", "CN=Domain Admins,...")
    assert captured["search_base"] == "CN=alice,..."


# ────────────────────────────────────────────── True / False ────


def test_account_in_chain_returns_true():
    """The server walked the chain and returned the account → True."""
    account_dn = "CN=alice,CN=Users,DC=corp,DC=local"
    ldap = MagicMock()
    ldap.query.return_value = [
        _entry({"distinguishedName": account_dn})
    ]
    assert is_member_of(ldap, account_dn, "CN=Domain Admins,...") is True


def test_account_not_in_chain_returns_false():
    """No results from the chain query → not a member."""
    ldap = MagicMock()
    ldap.query.return_value = []
    assert is_member_of(ldap, "CN=alice,...", "CN=Domain Admins,...") is False


def test_match_is_case_insensitive_on_dn():
    """ldap3 sometimes normalises DN casing differently. We compare
    case-insensitively so 'CN=Alice' = 'cn=alice'."""
    ldap = MagicMock()
    ldap.query.return_value = [
        _entry({"distinguishedName": "CN=ALICE,CN=USERS,DC=CORP,DC=LOCAL"})
    ]
    assert is_member_of(ldap, "cn=alice,cn=users,dc=corp,dc=local",
                        "CN=Domain Admins,...") is True


def test_unrelated_dn_in_results_does_not_match():
    """Defensive: if the DC returns an unrelated entry (shouldn't
    happen with the chain filter + account_dn search base, but
    paranoia is cheap), don't false-positive."""
    ldap = MagicMock()
    ldap.query.return_value = [
        _entry({"distinguishedName": "CN=bob,CN=Users,DC=corp,DC=local"})
    ]
    assert is_member_of(ldap, "CN=alice,CN=Users,DC=corp,DC=local",
                        "CN=Domain Admins,...") is False


# ────────────────────────────────────────────── error handling ──


def test_query_exception_returns_false_not_raises():
    """A transient LDAP error (server bounced, connection broken) must
    NOT make an account look privileged. Returning False is the
    conservative answer — Tier-0 writers stay flagged."""
    ldap = MagicMock()
    ldap.query.side_effect = RuntimeError("ldap is on fire")
    assert is_member_of(ldap, "CN=alice,...", "CN=Domain Admins,...") is False


def test_empty_dn_args_returns_false_without_query():
    """No DN → no query, no work. Avoids hammering the DC with bad input."""
    ldap = MagicMock()
    assert is_member_of(ldap, "", "CN=Domain Admins,...") is False
    assert is_member_of(ldap, "CN=alice,...", "") is False
    ldap.query.assert_not_called()


# ────────────────────────────────────────────── find_chain_members ──


def test_find_chain_members_returns_every_recursive_member():
    """Sister helper for "give me the whole effective membership."
    Used when we want the full set, not just yes/no for one account."""
    ldap = MagicMock()
    ldap.query.return_value = [
        _entry({"sAMAccountName": "alice"}),
        _entry({"sAMAccountName": "bob"}),
        _entry({"sAMAccountName": "svc_old"}),
    ]
    members = find_chain_members(ldap, "CN=Domain Admins,...")
    assert len(members) == 3


def test_find_chain_members_returns_empty_on_error():
    ldap = MagicMock()
    ldap.query.side_effect = RuntimeError("nope")
    assert find_chain_members(ldap, "CN=Domain Admins,...") == []


def test_find_chain_members_handles_empty_dn():
    ldap = MagicMock()
    assert find_chain_members(ldap, "") == []

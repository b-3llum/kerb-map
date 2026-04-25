"""
§1.3 — LDAP paging regression test.

The old `LDAPClient.query()` issued a single `conn.search()` call with no
paging and silently dropped any object past the server's MaxPageSize
(1000 on a stock Windows DC). These tests pin the new paged behaviour:

  * the loop iterates while the server returns a non-empty cookie
  * cookies received from one page are echoed back on the next request
  * all entries from every page are concatenated into the return value
"""

from unittest.mock import MagicMock, patch

import pytest
from ldap3 import MOCK_SYNC, OFFLINE_AD_2012_R2, Connection, Server

from kerb_map.auth.ldap_client import LDAPClient

# ---------------------------------------------------------------- helpers ----

def _client_with(conn) -> LDAPClient:
    """Build an LDAPClient without going through __init__ (skips real bind)."""
    c = LDAPClient.__new__(LDAPClient)
    c.dc_ip = "127.0.0.1"
    c.domain = "corp.local"
    c.username = "tester"
    c.base_dn = "DC=corp,DC=local"
    c.stealth = False
    c.timeout = 10
    c._query_count = 0
    c.conn = conn
    return c


# ---------------------------------------------------------- integration-ish --

@pytest.fixture
def mock_dit():
    """In-memory DIT with 2,500 user entries — exceeds default MaxPageSize."""
    server = Server("mock_dc", get_info=OFFLINE_AD_2012_R2)
    conn = Connection(
        server,
        user="cn=admin,dc=corp,dc=local",
        password="x",
        client_strategy=MOCK_SYNC,
    )
    for i in range(2500):
        conn.strategy.add_entry(
            f"CN=user{i:04d},CN=Users,DC=corp,DC=local",
            {
                "sAMAccountName": f"user{i:04d}",
                "objectClass": ["top", "person", "user"],
            },
        )
    conn.bind()
    yield conn
    conn.unbind()


@pytest.mark.skip(
    reason=(
        "ldap3 2.9.1 MOCK_SYNC returns a malformed paged-results control "
        "list on the second iteration ('TypeError: string indices must be "
        "integers'); not a regression in our paging logic — the unit-level "
        "paged-cookie tests below cover the loop behaviour without MOCK_SYNC. "
        "Re-enable when ldap3 ships a fix or we move to ASYNC strategy."
    ),
)
def test_query_returns_all_entries_from_large_dit(mock_dit):
    """End-to-end: 2,500 entries flow through the paged query loop intact."""
    client = _client_with(mock_dit)
    entries = client.query("(objectClass=user)", ["sAMAccountName"])
    assert len(entries) == 2500
    assert client.query_count == 1


# --------------------------------------------------------------- unit-level --

def _page(entries, cookie):
    """Build a fake `conn.result` payload that ldap3 would produce."""
    return {
        "controls": {
            LDAPClient._PAGED_RESULTS_OID: {"value": {"cookie": cookie}},
        },
    }


def test_paged_loop_follows_cookies_until_exhausted():
    """3 pages × 1,000 entries — verify cookies drive the loop and stop on b''."""
    pages = [
        ([f"e{i}" for i in range(1000)],     b"cookie-1"),
        ([f"e{i}" for i in range(1000, 2000)], b"cookie-2"),
        ([f"e{i}" for i in range(2000, 2500)], b""),  # empty cookie = done
    ]
    call_log = []

    conn = MagicMock()

    def fake_search(**kwargs):
        call_log.append(kwargs.get("paged_cookie"))
        idx = len(call_log) - 1
        conn.entries = pages[idx][0]
        conn.result = _page(pages[idx][0], pages[idx][1])
        return True

    conn.search.side_effect = fake_search

    client = _client_with(conn)
    entries = client.query("(objectClass=user)", ["sAMAccountName"], page_size=1000)

    assert len(entries) == 2500
    # First call has no cookie; subsequent calls echo back the prior cookie.
    assert call_log == [None, b"cookie-1", b"cookie-2"]
    assert conn.search.call_count == 3


def test_paged_loop_stops_on_missing_control():
    """Server omits the paged-results control entirely → single page, exit."""
    conn = MagicMock()
    conn.entries = ["only-entry"]
    conn.result = {"controls": {}}  # no paged control at all

    client = _client_with(conn)
    entries = client.query("(objectClass=user)", ["sAMAccountName"])

    assert entries == ["only-entry"]
    assert conn.search.call_count == 1


def test_paged_loop_returns_partial_results_on_ldap_error():
    """If page 2 raises, page 1 results are returned rather than discarded."""
    from ldap3.core.exceptions import LDAPException

    conn = MagicMock()
    call_count = {"n": 0}

    def fake_search(**kwargs):
        call_count["n"] += 1
        if call_count["n"] == 1:
            conn.entries = ["page1-a", "page1-b"]
            conn.result = _page(conn.entries, b"more")
            return True
        raise LDAPException("server hiccup")

    conn.search.side_effect = fake_search

    client = _client_with(conn)
    entries = client.query("(objectClass=user)", ["sAMAccountName"])

    assert entries == ["page1-a", "page1-b"]

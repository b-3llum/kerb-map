"""LDAPClient.get_domain_info — RODC detection (v1.3 sprint).

Real RODCs hold a *partial* NTDS replica. Several kerb-map findings
walk DACLs or read secrets that the RODC may not have, so the bound
client must surface ``is_rodc=True`` and the CLI banners a warning.

Without this signal, scanning an RODC silently returns incomplete
results — the worst kind of "looks fine" failure.
"""

from unittest.mock import MagicMock

from kerb_map.auth.ldap_client import LDAPClient


def _client_with_rootdse(other: dict, query_responses=None) -> LDAPClient:
    """LDAPClient with mocked rootDSE attrs and ``query()`` queue."""
    c = LDAPClient.__new__(LDAPClient)
    c.dc_ip = "127.0.0.1"
    c.domain = "corp.local"
    c.username = "tester"
    c.base_dn = "DC=corp,DC=local"
    c.stealth = False
    c.timeout = 10
    c._query_count = 0
    c.conn = MagicMock()
    c.conn.server.info.other = other
    queue = list(query_responses or [])
    c.query = lambda *a, **kw: queue.pop(0) if queue else []
    return c


def _domaindns_entry(values: dict):
    e = MagicMock()
    e.__contains__ = lambda self, k: k in values
    def _get(_self, k):
        m = MagicMock()
        m.value = values.get(k)
        return m
    e.__getitem__ = _get
    return e


def test_writable_dc_is_rodc_false():
    """Vanilla writable DC — rootDSE has no ``isReadOnly`` (or has
    ``FALSE``); ``is_rodc`` defaults to False. Pin the default so a
    refactor doesn't accidentally inject a True (which would surface
    a phantom RODC banner on every scan)."""
    c = _client_with_rootdse(
        other={"dnsHostName": ["dc01.corp.local"]},
        query_responses=[[_domaindns_entry({"dc": "corp"})]],
    )
    info = c.get_domain_info()
    assert info.get("is_rodc") is False


def test_rodc_detected_via_rootdse_isreadonly_true_string():
    """Real RODCs return ``isReadOnly: TRUE`` in rootDSE. ldap3 may
    surface the value as a string in a list, so the parser handles
    both shapes."""
    c = _client_with_rootdse(
        other={"isReadOnly": ["TRUE"], "dnsHostName": ["rodc01.corp.local"]},
        query_responses=[[_domaindns_entry({"dc": "corp"})]],
    )
    info = c.get_domain_info()
    assert info.get("is_rodc") is True


def test_rodc_detected_via_isreadonly_bare_string():
    """Some ldap3 versions / server quirks deliver the value as a
    bare string rather than a single-element list. Pin both."""
    c = _client_with_rootdse(
        other={"isReadOnly": "TRUE"},
        query_responses=[[_domaindns_entry({"dc": "corp"})]],
    )
    info = c.get_domain_info()
    assert info.get("is_rodc") is True


def test_rodc_isreadonly_false_string_is_writable():
    """Explicit FALSE means writable DC — don't false-flag it as RODC."""
    c = _client_with_rootdse(
        other={"isReadOnly": ["FALSE"], "dnsHostName": ["dc01.corp.local"]},
        query_responses=[[_domaindns_entry({"dc": "corp"})]],
    )
    info = c.get_domain_info()
    assert info.get("is_rodc") is False


def test_rodc_attribute_missing_is_writable():
    """Older / non-AD LDAP servers omit ``isReadOnly`` entirely.
    Treat absence as writable to avoid a false-positive banner on
    Samba / OpenLDAP / etc."""
    c = _client_with_rootdse(
        other={"dnsHostName": ["dc01.corp.local"]},
        query_responses=[[_domaindns_entry({"dc": "corp"})]],
    )
    info = c.get_domain_info()
    assert info.get("is_rodc") is False


def test_rootdse_other_unreadable_does_not_crash():
    """If `self.conn.server.info.other` raises (mock LDAP, broken
    server, partial init), get_domain_info must still return — just
    without the dc_dns_hostname / is_rodc keys populated."""
    c = _client_with_rootdse(other=None,
                             query_responses=[[_domaindns_entry({"dc": "corp"})]])
    # Force the .other access to raise
    c.conn.server.info = None
    info = c.get_domain_info()
    assert info.get("is_rodc") is False
    assert info.get("dc_dns_hostname") is None

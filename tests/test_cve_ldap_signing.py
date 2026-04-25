"""LDAP signing not required — NTLM-relay-to-LDAP precondition."""

from unittest.mock import MagicMock

from kerb_map.modules.cves.cve_base import Severity
from kerb_map.modules.cves.ldap_signing import LDAPSigning


def _entry(dn="DC=corp,DC=local"):
    e = MagicMock()
    e.__contains__ = lambda self, k: k == "distinguishedName"
    def _get(self, k):
        m = MagicMock()
        m.value = dn
        return m
    e.__getitem__ = _get
    return e


def _ldap(*, port, bound=True, has_entries=True):
    """Mock LDAP with port + bind state on conn.server."""
    ldap = MagicMock()
    ldap.query.return_value = [_entry()] if has_entries else []
    ldap.conn.bound = bound
    ldap.conn.server.port = port
    return ldap


def test_port_389_bind_means_signing_not_required():
    """Connected on 389 = simple bind succeeded without signing → DC
    isn't enforcing it."""
    r = LDAPSigning(_ldap(port=389), "10.0.0.1", "corp.local").check()
    assert r.vulnerable is True
    assert r.severity == Severity.HIGH
    assert "ntlmrelayx" in r.next_step
    assert "10.0.0.1" in r.next_step


def test_port_636_ldaps_marked_signed():
    """LDAPS = transport-level encryption + signing baked in."""
    r = LDAPSigning(_ldap(port=636), "10.0.0.1", "corp.local").check()
    assert r.vulnerable is False
    assert r.next_step == ""


def test_unbound_connection_conservatively_marked_signed():
    """Can't tell → assume enforced (don't false-flag)."""
    r = LDAPSigning(_ldap(port=389, bound=False), "10.0.0.1", "x").check()
    assert r.vulnerable is False


def test_no_domain_entries_returns_vulnerable():
    """Empty domainDNS query → can't verify policy. Code returns
    False from _check_signing (i.e. vulnerable=True). Conservative
    direction here is "warn the operator" — better a false flag
    they can dismiss than missing real exposure."""
    r = LDAPSigning(_ldap(port=389, has_entries=False), "10.0.0.1", "x").check()
    assert r.vulnerable is True

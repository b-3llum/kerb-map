"""
§1.4 — LDAPS / StartTLS / plain fallback chain.

Pure-unit tests: monkeypatch ``LDAPClient._open`` to record which
transports are attempted in which order. A real Samba 4 DC integration
test (``ldap server require strong auth = yes`` rejecting plain bind,
StartTLS succeeding) is the brief's acceptance criterion but is skipped
here because the lab VM is not up.
"""

from unittest.mock import MagicMock

import pytest
from ldap3.core.exceptions import (
    LDAPBindError,
    LDAPException,
    LDAPSocketOpenError,
)

from kerb_map.auth import ldap_client as lc
from kerb_map.auth.ldap_client import (
    TRANSPORT_LDAPS,
    TRANSPORT_PLAIN,
    TRANSPORT_SIGNED,
    TRANSPORT_STARTTLS,
    LDAPAuthError,
    LDAPClient,
)


def _build(monkeypatch, behaviour, **client_kwargs):
    """Construct an LDAPClient with _open() replaced by `behaviour(transport)`.

    behaviour: callable(transport_name) -> raises or returns a fake conn.
    """
    attempted: list[str] = []

    def fake_open(self, transport, username, password, hashes, use_kerberos):
        attempted.append(transport)
        return behaviour(transport)

    def fake_announce(self, transport, conn):
        return None  # silence rich output in tests

    monkeypatch.setattr(LDAPClient, "_open", fake_open)
    monkeypatch.setattr(LDAPClient, "_announce_bind", fake_announce)

    defaults = dict(
        dc_ip="10.0.0.1",
        domain="corp.local",
        username="tester",
        password="x",
    )
    defaults.update(client_kwargs)
    client = LDAPClient(**defaults)
    return client, attempted


def test_default_chain_uses_ldaps_first(monkeypatch):
    client, attempted = _build(monkeypatch, lambda t: MagicMock())
    assert attempted == [TRANSPORT_LDAPS]
    assert client.transport_used == TRANSPORT_LDAPS


def test_falls_back_through_chain_until_one_succeeds(monkeypatch):
    def behaviour(transport):
        if transport == TRANSPORT_LDAPS:
            raise LDAPSocketOpenError("connection refused on 636")
        if transport == TRANSPORT_STARTTLS:
            raise LDAPException("StartTLS refused")
        return MagicMock()  # plain succeeds (signed skipped — no kerberos)

    client, attempted = _build(monkeypatch, behaviour)
    assert attempted == [TRANSPORT_LDAPS, TRANSPORT_STARTTLS, TRANSPORT_PLAIN]
    assert client.transport_used == TRANSPORT_PLAIN


def test_signed_transport_only_attempted_with_kerberos(monkeypatch):
    def behaviour(transport):
        if transport == TRANSPORT_PLAIN:
            return MagicMock()
        raise LDAPSocketOpenError("nope")

    client, attempted = _build(monkeypatch, behaviour, use_kerberos=True)
    assert attempted == [TRANSPORT_LDAPS, TRANSPORT_STARTTLS, TRANSPORT_SIGNED, TRANSPORT_PLAIN]


def test_pinned_transport_does_not_fall_back(monkeypatch):
    def behaviour(transport):
        raise LDAPBindError("strong auth required")

    with pytest.raises(LDAPAuthError, match="ldaps"):
        _build(monkeypatch, behaviour, transport=TRANSPORT_LDAPS)


def test_legacy_use_ssl_pins_ldaps(monkeypatch):
    client, attempted = _build(monkeypatch, lambda t: MagicMock(), use_ssl=True)
    assert attempted == [TRANSPORT_LDAPS]


def test_all_transports_failing_raises(monkeypatch):
    def behaviour(transport):
        raise LDAPSocketOpenError(f"{transport} unreachable")

    with pytest.raises(LDAPAuthError, match="All LDAP transports failed"):
        _build(monkeypatch, behaviour)

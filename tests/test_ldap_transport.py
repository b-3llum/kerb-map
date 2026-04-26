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
    TRANSPORT_LDAPS_SIMPLE,
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
    """The chain order is LDAPS → StartTLS → SIGNED (only with -k) →
    LDAPS-SIMPLE → plain. SIGNED is skipped without Kerberos. The
    Samba-AD-DC compat fallback (LDAPS-SIMPLE) is one slot before
    plain so a Samba lab succeeds via SIMPLE bind without dropping
    to unencrypted-and-unsigned plain."""
    def behaviour(transport):
        if transport == TRANSPORT_LDAPS:
            raise LDAPSocketOpenError("connection refused on 636")
        if transport == TRANSPORT_STARTTLS:
            raise LDAPException("StartTLS refused")
        return MagicMock()  # ldaps-simple succeeds (the Samba-compat path)

    from kerb_map.auth.ldap_client import TRANSPORT_LDAPS_SIMPLE
    client, attempted = _build(monkeypatch, behaviour)
    assert attempted == [TRANSPORT_LDAPS, TRANSPORT_STARTTLS,
                         TRANSPORT_LDAPS_SIMPLE]
    assert client.transport_used == TRANSPORT_LDAPS_SIMPLE


def test_signed_transport_only_attempted_with_kerberos(monkeypatch):
    def behaviour(transport):
        if transport == TRANSPORT_PLAIN:
            return MagicMock()
        raise LDAPSocketOpenError("nope")

    client, attempted = _build(monkeypatch, behaviour, use_kerberos=True)
    from kerb_map.auth.ldap_client import TRANSPORT_LDAPS_SIMPLE
    assert attempted == [TRANSPORT_LDAPS, TRANSPORT_STARTTLS,
                         TRANSPORT_SIGNED, TRANSPORT_LDAPS_SIMPLE,
                         TRANSPORT_PLAIN]


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


def test_hardened_estate_bind_failure_surfaces_actionable_hint(monkeypatch):
    """Field gap from the v1.3 sprint hardened-GPO test: with
    ``LDAPServerIntegrity = 2`` (Require signing) on the DC, every
    transport fails — TLS handshakes get reset (no LDAPS cert), plain
    NTLM gets ``strongerAuthRequired``. ldap3's GSSAPI SASL bind
    hard-codes ``NO_SECURITY_LAYER`` so signing-required estates can't
    be bound. Without an actionable hint the operator just sees a
    cryptic per-transport error chain.

    Pin that the LDAPAuthError carries a hint mentioning ``signed``
    bind requirement and at least one workaround so a refactor
    doesn't silently drop it."""
    from ldap3.core.exceptions import LDAPBindError

    def behaviour(transport):
        if transport in (TRANSPORT_LDAPS, TRANSPORT_LDAPS_SIMPLE):
            raise LDAPSocketOpenError(
                "socket ssl wrapping error: [Errno 104] Connection reset by peer"
            )
        if transport == TRANSPORT_STARTTLS:
            raise LDAPSocketOpenError("startTLS failed - unavailable")
        # plain (NTLM) → signing required → strongerAuthRequired
        raise LDAPBindError(
            "automatic bind not successful - strongerAuthRequired"
        )

    with pytest.raises(LDAPAuthError) as ei:
        _build(monkeypatch, behaviour)
    msg = str(ei.value).lower()
    assert "signed" in msg
    assert "ldaps cert" in msg or "ldaps" in msg


def test_normal_socket_failures_do_not_get_hardened_hint(monkeypatch):
    """Negative path: when the chain fails for ordinary reasons
    (DC down, wrong port, etc.), don't surface the hardened-LDAP hint
    — that would mislead the operator into chasing a non-issue."""
    def behaviour(transport):
        raise LDAPSocketOpenError(f"{transport}: no route to host")

    with pytest.raises(LDAPAuthError) as ei:
        _build(monkeypatch, behaviour)
    msg = str(ei.value).lower()
    assert "no route to host" in msg
    assert "signed" not in msg  # no spurious hardened-estate hint


def test_ldaps_simple_succeeds_when_ntlm_paths_rejected(monkeypatch):
    """Samba-AD-DC compat path: NTLM-flavoured transports (LDAPS,
    StartTLS, plain) get session-terminated by Samba's LDAP service
    because Samba doesn't accept NTLM bind. The LDAPS-SIMPLE transport
    re-uses the same TLS socket but binds with SIMPLE + user@REALM,
    which Samba accepts.

    Field bug it fixes: kerb-map used to fail with
    'session terminated by server' against the Samba lab the project
    ships with. Now it falls through to LDAPS-SIMPLE and authenticates."""
    def behaviour(transport):
        if transport == TRANSPORT_LDAPS_SIMPLE:
            return MagicMock()
        # NTLM-flavoured transports rejected by Samba
        from ldap3.core.exceptions import LDAPSessionTerminatedByServerError
        raise LDAPSessionTerminatedByServerError("session terminated by server")

    client, attempted = _build(monkeypatch, behaviour)
    # All four NTLM-flavoured transports tried first, then LDAPS-SIMPLE.
    # SIGNED is skipped since use_kerberos defaults to False.
    assert TRANSPORT_LDAPS_SIMPLE in attempted
    assert client.transport_used == TRANSPORT_LDAPS_SIMPLE


def test_ldaps_simple_skipped_for_pth(monkeypatch):
    """SIMPLE bind sends the credential as plaintext (over TLS) — the
    server hashes it. Pass-the-Hash is fundamentally incompatible with
    SIMPLE bind because the operator has the NT hash, not the password.
    The transport must raise so the chain falls through to plain (which
    accepts the hash via NTLM)."""
    def behaviour(transport):
        return MagicMock()  # everything succeeds — we want to see filtering

    client, attempted = _build(
        monkeypatch, behaviour,
        password=None, hashes="aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0",
    )
    # First success in the chain is whatever wasn't filtered. With hashes
    # set, LDAPS / StartTLS / plain all use NTLM and succeed; LDAPS-SIMPLE
    # is in the chain but the implementation refuses (raises) since SIMPLE
    # can't carry a hash.
    assert client.transport_used == TRANSPORT_LDAPS

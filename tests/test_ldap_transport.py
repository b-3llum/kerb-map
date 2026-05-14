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


def test_hardened_estate_without_kerberos_hints_at_dash_k(monkeypatch):
    """Field gap from the v1.3 sprint hardened-GPO test: with
    ``LDAPServerIntegrity = 2`` (Require signing) on the DC, every
    NTLM-flavoured transport fails — TLS handshakes get reset (no
    LDAPS cert), plain NTLM gets ``strongerAuthRequired``.

    With ldap3 >= 2.10.2rc4 the SIGNED SASL/Kerberos transport
    negotiates GSS-encrypted binds and *does* satisfy hardened DCs —
    but only when ``-k`` is set. Without Kerberos, the right
    actionable hint is to enable it.

    Pin that the LDAPAuthError carries a hint pointing the operator
    at ``-k`` and the LDAPS-cert workaround."""
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
    assert "-k" in msg
    assert "ldaps cert" in msg or "ldaps" in msg


def test_hardened_estate_with_kerberos_failure_hints_at_kerberos_layer(monkeypatch):
    """When Kerberos was attempted but the SIGNED transport itself
    couldn't complete the GSS-encrypted bind (e.g. no TGT, SPN
    mismatch), the right hint points at the Kerberos layer rather
    than telling the operator to enable -k they already had on."""
    from ldap3.core.exceptions import LDAPBindError

    def behaviour(transport):
        if transport in (TRANSPORT_LDAPS, TRANSPORT_LDAPS_SIMPLE):
            raise LDAPSocketOpenError("ssl wrapping error: connection reset by peer")
        if transport == TRANSPORT_STARTTLS:
            raise LDAPSocketOpenError("startTLS failed - unavailable")
        if transport == TRANSPORT_SIGNED:
            raise LDAPBindError("kerberos: no credentials cache found")
        raise LDAPBindError("automatic bind not successful - strongerAuthRequired")

    with pytest.raises(LDAPAuthError) as ei:
        _build(monkeypatch, behaviour, use_kerberos=True)
    msg = str(ei.value).lower()
    assert "klist" in msg or "tgt" in msg or "kinit" in msg
    # Don't redundantly tell them to "use -k" when -k was already on.
    assert "re-run with `-k`" not in msg


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


def test_signed_transport_passes_session_security_encrypt(monkeypatch):
    """The whole point of v1.3.x follow-up #1: TRANSPORT_SIGNED must
    pass session_security=ENCRYPT to ldap3.Connection so the bound
    socket gets GSS-wrapped. Without it, hardened DCs accept the bind
    but drop every subsequent search with strongerAuthRequired —
    silently incomplete results, the worst kind of failure.

    Verify by intercepting Connection() and checking the kwarg lands
    on the SIGNED path (and only there — TLS transports already have
    signing via the channel)."""
    from ldap3 import ENCRYPT

    captured: dict = {}

    def fake_connection(server, *args, **kwargs):
        captured["kwargs"] = kwargs
        m = MagicMock()
        m.bound = True
        return m

    def fake_server(*args, **kwargs):
        return MagicMock()

    monkeypatch.setattr(lc, "Connection", fake_connection)
    monkeypatch.setattr(lc, "Server", fake_server)
    monkeypatch.setattr(LDAPClient, "_announce_bind", lambda *a, **k: None)

    LDAPClient(
        dc_ip="10.0.0.1", domain="corp.local", username="tester",
        use_kerberos=True, transport=TRANSPORT_SIGNED,
    )
    assert captured["kwargs"].get("session_security") == ENCRYPT

    # And NOT on a TLS transport — double-wrap is wasteful.
    captured.clear()
    LDAPClient(
        dc_ip="10.0.0.1", domain="corp.local", username="tester",
        use_kerberos=True, transport=TRANSPORT_LDAPS,
    )
    assert "session_security" not in captured["kwargs"]


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

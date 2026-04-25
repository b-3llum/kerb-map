"""ZeroLogon — SecuraBV NetrServerAuthenticate3 probe (brief §2.2).

Mocks the impacket RPC layer so we can exercise the bucketing logic
(vulnerable / patched / probe-failed → indeterminate) without needing
a real DC. The full lab integration ("seeded unpatched DC, scan
returns CRITICAL within 1s; seeded patched DC, scan returns INFO
after 2000 denials") is the brief's acceptance criterion and is
deferred until vagrant up runs.
"""

from unittest.mock import MagicMock, patch

import pytest

from kerb_map.modules.cves.cve_base import (
    PATCH_STATUS_INDETERMINATE,
    PATCH_STATUS_RPC_CONFIRMED_PATCHED,
    PATCH_STATUS_RPC_CONFIRMED_VULNERABLE,
    Severity,
)
from kerb_map.modules.cves.zerologon import MAX_ATTEMPTS, ZeroLogon


def _entry(values: dict):
    e = MagicMock()
    e.__contains__ = lambda self, k: k in values
    e.__getitem__ = lambda self, k: MagicMock(value=values[k])
    return e


def _ldap_with_dc(name: str = "DC01", dns: str = "dc01.corp.local"):
    """Fake LDAPClient that returns one DC entry from the
    primaryGroupID=516 lookup."""
    ldap = MagicMock()
    ldap.query.return_value = [
        _entry({"sAMAccountName": f"{name}$", "dNSHostName": dns})
    ]
    return ldap


def _zerologon(probe_outcome):
    """Build a ZeroLogon instance whose ``_probe_securabv`` returns the
    given outcome (True / False / None) without going near impacket."""
    z = ZeroLogon(_ldap_with_dc(), "10.0.0.5", "corp.local")
    z._probe_securabv = lambda: probe_outcome   # type: ignore
    return z


# ────────────────────────────────────────── result bucketing ────


def test_probe_returns_true_yields_critical():
    """Ground-truth vulnerable → CRITICAL + RPC_CONFIRMED_VULNERABLE."""
    with patch("kerb_map.modules.cves.zerologon.IMPACKET_AVAILABLE", True):
        result = _zerologon(True).check()
    assert result.severity == Severity.CRITICAL
    assert result.vulnerable is True
    assert result.patch_status == PATCH_STATUS_RPC_CONFIRMED_VULNERABLE
    assert "NetrServerAuthenticate3" in result.reason
    assert result.next_step  # exploitation recipe present


def test_probe_returns_false_yields_info_not_vulnerable():
    """Ground-truth patched → INFO + not-vulnerable + RPC_CONFIRMED_PATCHED."""
    with patch("kerb_map.modules.cves.zerologon.IMPACKET_AVAILABLE", True):
        result = _zerologon(False).check()
    assert result.severity == Severity.INFO
    assert result.vulnerable is False
    assert result.patch_status == PATCH_STATUS_RPC_CONFIRMED_PATCHED
    assert str(MAX_ATTEMPTS) in result.reason
    assert result.next_step == ""    # nothing to exploit


def test_probe_returns_none_yields_indeterminate():
    """Probe failed → HIGH + INDETERMINATE + vulnerable=True (CVE
    applies until proven otherwise)."""
    with patch("kerb_map.modules.cves.zerologon.IMPACKET_AVAILABLE", True):
        result = _zerologon(None).check()
    assert result.severity == Severity.HIGH
    assert result.vulnerable is True
    assert result.patch_status == PATCH_STATUS_INDETERMINATE
    assert "could not" in result.reason.lower() or "verify externally" in result.reason.lower()


def test_no_impacket_yields_indeterminate(monkeypatch):
    """impacket missing → never call _probe_securabv, return INDETERMINATE."""
    monkeypatch.setattr("kerb_map.modules.cves.zerologon.IMPACKET_AVAILABLE", False)
    z = ZeroLogon(_ldap_with_dc(), "10.0.0.5", "corp.local")
    z._probe_securabv = MagicMock()  # should NOT be called
    result = z.check()
    assert result.patch_status == PATCH_STATUS_INDETERMINATE
    assert z._probe_securabv.called is False


# ────────────────────────────────────────── DC name resolution ────


def test_resolve_dc_name_matches_by_ip():
    """When self.dc_ip appears in dNSHostName, that DC wins over any
    other DC enumerated."""
    ldap = MagicMock()
    ldap.query.return_value = [
        _entry({"sAMAccountName": "DC02$", "dNSHostName": "dc02.corp.local"}),
        _entry({"sAMAccountName": "DC01$", "dNSHostName": "dc01.corp.local"}),
    ]
    z = ZeroLogon(ldap, "10.0.0.5", "corp.local")  # IP not in either name
    # Both names match no IP — falls back to first
    assert z._resolve_dc_name() == "DC02"


def test_resolve_dc_name_strips_trailing_dollar():
    """sAMAccountName for a computer object ends with $ — the
    NetrServerAuthenticate3 caller adds the $ back, so we strip here
    to keep the boundary clean."""
    z = ZeroLogon(_ldap_with_dc(name="DC01"), "10.0.0.5", "corp.local")
    assert z._resolve_dc_name() == "DC01"


def test_resolve_dc_name_returns_none_when_no_dcs():
    ldap = MagicMock()
    ldap.query.return_value = []
    z = ZeroLogon(ldap, "10.0.0.5", "corp.local")
    assert z._resolve_dc_name() is None


def test_resolve_dc_name_handles_query_exception():
    """LDAP query raises (e.g. unbound connection mid-scan) — return
    None so the probe doesn't crash on a bad assumption."""
    ldap = MagicMock()
    ldap.query.side_effect = RuntimeError("ldap is on fire")
    z = ZeroLogon(ldap, "10.0.0.5", "corp.local")
    assert z._resolve_dc_name() is None


# ────────────────────────────────────── _single_attempt buckets ────


def test_single_attempt_succeeds_returns_true(monkeypatch):
    """rpc.request(...) returns without raising → ErrorCode was 0
    → vulnerable → return True."""
    monkeypatch.setattr("kerb_map.modules.cves.zerologon.IMPACKET_AVAILABLE", True)
    fake_rpc = MagicMock()
    fake_rpc.request.return_value = MagicMock()  # no exception

    fake_factory = MagicMock()
    fake_factory.get_dce_rpc.return_value = fake_rpc
    monkeypatch.setattr(
        "kerb_map.modules.cves.zerologon.transport.DCERPCTransportFactory",
        lambda *_: fake_factory,
    )

    z = ZeroLogon(_ldap_with_dc(), "10.0.0.5", "corp.local")
    assert z._single_attempt("ncacn_ip_tcp:dc[49153]", "DC01") is True


def test_single_attempt_access_denied_returns_false(monkeypatch):
    """STATUS_ACCESS_DENIED (0xc0000022) → False (retry)."""
    from impacket.dcerpc.v5.rpcrt import DCERPCException

    monkeypatch.setattr("kerb_map.modules.cves.zerologon.IMPACKET_AVAILABLE", True)

    class AccessDenied(DCERPCException):
        def get_error_code(self):
            return 0xc0000022

    fake_rpc = MagicMock()
    fake_rpc.request.side_effect = AccessDenied()
    fake_factory = MagicMock()
    fake_factory.get_dce_rpc.return_value = fake_rpc
    monkeypatch.setattr(
        "kerb_map.modules.cves.zerologon.transport.DCERPCTransportFactory",
        lambda *_: fake_factory,
    )

    z = ZeroLogon(_ldap_with_dc(), "10.0.0.5", "corp.local")
    assert z._single_attempt("ncacn_ip_tcp:dc[49153]", "DC01") is False


def test_single_attempt_unexpected_error_returns_none(monkeypatch):
    """Any non-0xc0000022 RPC error or general Exception → None
    (probe failed, don't lie about the result)."""
    from impacket.dcerpc.v5.rpcrt import DCERPCException

    monkeypatch.setattr("kerb_map.modules.cves.zerologon.IMPACKET_AVAILABLE", True)

    class WeirdError(DCERPCException):
        def get_error_code(self):
            return 0xdeadbeef  # not access-denied

    fake_rpc = MagicMock()
    fake_rpc.request.side_effect = WeirdError()
    fake_factory = MagicMock()
    fake_factory.get_dce_rpc.return_value = fake_rpc
    monkeypatch.setattr(
        "kerb_map.modules.cves.zerologon.transport.DCERPCTransportFactory",
        lambda *_: fake_factory,
    )

    z = ZeroLogon(_ldap_with_dc(), "10.0.0.5", "corp.local")
    assert z._single_attempt("ncacn_ip_tcp:dc[49153]", "DC01") is None


# ────────────────────────────────────── full probe — outer loop ────


def test_probe_returns_true_on_first_success(monkeypatch):
    """A single _single_attempt → True ends the loop immediately,
    even if there are 1999 attempts left."""
    monkeypatch.setattr("kerb_map.modules.cves.zerologon.IMPACKET_AVAILABLE", True)
    monkeypatch.setattr(
        "kerb_map.modules.cves.zerologon.epm.hept_map",
        lambda *a, **kw: "ncacn_ip_tcp:dc[49153]",
    )

    z = ZeroLogon(_ldap_with_dc(), "10.0.0.5", "corp.local")

    call_count = {"n": 0}
    def fake_attempt(binding, target_dc):
        call_count["n"] += 1
        if call_count["n"] >= 5:
            return True   # 5th attempt succeeds → vulnerable
        return False
    z._single_attempt = fake_attempt   # type: ignore

    assert z._probe_securabv() is True
    assert call_count["n"] == 5


def test_probe_returns_none_on_unexpected_error(monkeypatch):
    """Any _single_attempt → None aborts the whole probe, returns None
    so the result builder picks INDETERMINATE."""
    monkeypatch.setattr("kerb_map.modules.cves.zerologon.IMPACKET_AVAILABLE", True)
    monkeypatch.setattr(
        "kerb_map.modules.cves.zerologon.epm.hept_map",
        lambda *a, **kw: "ncacn_ip_tcp:dc[49153]",
    )

    z = ZeroLogon(_ldap_with_dc(), "10.0.0.5", "corp.local")
    z._single_attempt = lambda b, t: None
    assert z._probe_securabv() is None


def test_probe_returns_false_after_max_attempts(monkeypatch):
    """All attempts return False → patched verdict.
    We use a tiny MAX_ATTEMPTS so the test runs in <1ms."""
    monkeypatch.setattr("kerb_map.modules.cves.zerologon.IMPACKET_AVAILABLE", True)
    monkeypatch.setattr("kerb_map.modules.cves.zerologon.MAX_ATTEMPTS", 5)
    monkeypatch.setattr(
        "kerb_map.modules.cves.zerologon.epm.hept_map",
        lambda *a, **kw: "ncacn_ip_tcp:dc[49153]",
    )

    z = ZeroLogon(_ldap_with_dc(), "10.0.0.5", "corp.local")
    z._single_attempt = lambda b, t: False   # type: ignore
    assert z._probe_securabv() is False


def test_probe_returns_none_when_dc_name_unresolvable(monkeypatch):
    monkeypatch.setattr("kerb_map.modules.cves.zerologon.IMPACKET_AVAILABLE", True)
    z = ZeroLogon(_ldap_with_dc(), "10.0.0.5", "corp.local")
    z._resolve_dc_name = lambda: None   # type: ignore
    assert z._probe_securabv() is None


def test_probe_returns_none_when_epm_lookup_fails(monkeypatch):
    monkeypatch.setattr("kerb_map.modules.cves.zerologon.IMPACKET_AVAILABLE", True)
    def boom(*a, **kw):
        raise OSError("epm unreachable")
    monkeypatch.setattr("kerb_map.modules.cves.zerologon.epm.hept_map", boom)

    z = ZeroLogon(_ldap_with_dc(), "10.0.0.5", "corp.local")
    assert z._probe_securabv() is None


# ────────────────────────────────── module declarations ────


def test_max_attempts_default_matches_securabv():
    """SecuraBV's reference threshold is 2000. Don't drift from it
    without thinking — change requires updating the patched-result
    reason text and the docstring."""
    # Re-import to bypass any monkey-patches in earlier tests.
    import importlib

    import kerb_map.modules.cves.zerologon as zmod
    importlib.reload(zmod)
    assert zmod.MAX_ATTEMPTS == 2000


def test_module_keeps_cve_id_and_name():
    assert ZeroLogon.CVE_ID == "CVE-2020-1472"
    assert ZeroLogon.NAME   == "ZeroLogon"


@pytest.fixture(autouse=True)
def _isolate_zerologon_constants():
    """Reload zerologon after each test so monkey-patches to
    MAX_ATTEMPTS / IMPACKET_AVAILABLE don't leak across tests."""
    yield
    import importlib

    import kerb_map.modules.cves.zerologon as zmod
    importlib.reload(zmod)

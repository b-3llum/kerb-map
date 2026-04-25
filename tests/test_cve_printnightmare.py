"""PrintNightmare + PetitPotam — RPC pipe-reachability probes.

These checks open a DCERPC connection to the target pipe; success =
preconditions present (not necessarily vulnerable, but pipe-reachable
DCs are very often unpatched). Tests mock the transport so we never
hit the network."""

from unittest.mock import MagicMock, patch

from kerb_map.modules.cves.cve_base import Severity
from kerb_map.modules.cves.printnightmare import PetitPotam, PrintNightmare

# ────────────────────────────────────── PrintNightmare ─


def test_printnightmare_when_pipe_reachable_critical():
    """spoolss pipe binds → operator can coerce NTLM via printerbug.
    Recipe ready to run with substituted DC IP."""
    pn = PrintNightmare(MagicMock(), "10.0.0.1", "corp.local")
    with patch.object(pn, "_probe_spooler", return_value=True):
        r = pn.check()
    assert r.vulnerable is True
    assert r.severity == Severity.CRITICAL
    assert "spoolss" in r.reason
    assert "printerbug.py" in r.next_step
    assert "10.0.0.1" in r.next_step


def test_printnightmare_when_pipe_unreachable_clean():
    pn = PrintNightmare(MagicMock(), "10.0.0.1", "corp.local")
    with patch.object(pn, "_probe_spooler", return_value=False):
        r = pn.check()
    assert r.vulnerable is False
    assert r.next_step == ""


def test_printnightmare_probe_swallows_exceptions():
    """RPC connect failures (timeout, refused, no-pipe) must return
    False — the operator-facing scan continues with a 'not reachable'
    result rather than crashing."""
    pn = PrintNightmare(MagicMock(), "10.0.0.1", "x")
    fake_transport = MagicMock()
    fake_transport.get_dce_rpc.return_value.connect.side_effect = OSError("no route")
    with patch("kerb_map.modules.cves.printnightmare.transport.DCERPCTransportFactory",
               return_value=fake_transport):
        assert pn._probe_spooler() is False


def test_printnightmare_probe_returns_true_when_bind_succeeds():
    """Happy path: connect + bind both succeed → probe returns True."""
    pn = PrintNightmare(MagicMock(), "10.0.0.1", "x")
    fake_transport = MagicMock()
    fake_dce = MagicMock()
    fake_transport.get_dce_rpc.return_value = fake_dce
    with patch("kerb_map.modules.cves.printnightmare.transport.DCERPCTransportFactory",
               return_value=fake_transport):
        assert pn._probe_spooler() is True
    fake_dce.connect.assert_called_once()
    fake_dce.bind.assert_called_once()


# ────────────────────────────────────── PetitPotam ─


def test_petitpotam_when_pipe_reachable_high():
    """lsarpc pipe binds → EFS coercion path is open."""
    pp = PetitPotam(MagicMock(), "10.0.0.1", "corp.local")
    with patch.object(pp, "_probe_efs", return_value=True):
        r = pp.check()
    assert r.vulnerable is True
    assert r.severity == Severity.HIGH
    assert "EFSRPC" in r.reason or "LSARPC" in r.reason
    assert "PetitPotam.py" in r.next_step


def test_petitpotam_when_pipe_unreachable_clean():
    pp = PetitPotam(MagicMock(), "10.0.0.1", "x")
    with patch.object(pp, "_probe_efs", return_value=False):
        r = pp.check()
    assert r.vulnerable is False


def test_petitpotam_probe_swallows_exceptions():
    pp = PetitPotam(MagicMock(), "10.0.0.1", "x")
    fake_transport = MagicMock()
    fake_transport.get_dce_rpc.return_value.connect.side_effect = OSError("nope")
    with patch("kerb_map.modules.cves.printnightmare.transport.DCERPCTransportFactory",
               return_value=fake_transport):
        assert pp._probe_efs() is False


def test_petitpotam_probe_returns_true_when_bind_succeeds():
    pp = PetitPotam(MagicMock(), "10.0.0.1", "x")
    fake_transport = MagicMock()
    fake_dce = MagicMock()
    fake_transport.get_dce_rpc.return_value = fake_dce
    with patch("kerb_map.modules.cves.printnightmare.transport.DCERPCTransportFactory",
               return_value=fake_transport):
        assert pp._probe_efs() is True
    fake_dce.bind.assert_called_once()

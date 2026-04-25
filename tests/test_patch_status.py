"""Honest CVE patch reporting (brief §2.1).

The DFL-based ``_infer_patch_status`` heuristic was wrong both ways
(modern unpatched domain → "patched"; legacy patched domain →
"vulnerable"). These tests pin the new behaviour: precondition
checks remain, but the verdict is honest about what LDAP can and
can't determine.
"""

from unittest.mock import MagicMock

from kerb_map.modules.cves.bronze_bit import BronzeBit
from kerb_map.modules.cves.certifried import Certifried
from kerb_map.modules.cves.cve_base import (
    PATCH_STATUS_INDETERMINATE,
    Severity,
)
from kerb_map.modules.cves.nopac import NoPac
from kerb_map.modules.cves.zerologon import ZeroLogon


def _entry(values: dict):
    e = MagicMock()
    e.__contains__ = lambda self, k: k in values
    e.__getitem__ = lambda self, k: MagicMock(value=values[k])
    return e


def _ldap(query_responses, query_config_responses=None):
    """Build a fake LDAP whose query() returns successive responses."""
    ldap = MagicMock()
    qq = list(query_responses)
    ldap.query.side_effect = lambda *a, **kw: qq.pop(0) if qq else []
    qc = list(query_config_responses or [])
    ldap.query_config.side_effect = lambda *a, **kw: qc.pop(0) if qc else []
    return ldap


# ────────────────────────────────────────────────── infrastructure ────


def test_no_module_still_calls_infer_patch_status():
    """Regression guard. The method existed on four CVE modules; if
    anyone re-adds it, this test catches it before the wrong-answer
    bug returns."""
    for cls in (NoPac, Certifried, BronzeBit, ZeroLogon):
        assert not hasattr(cls, "_infer_patch_status"), (
            f"{cls.__name__} regrew _infer_patch_status — see brief §2.1"
        )


def test_patch_status_indeterminate_constant_exists():
    assert "indeterminate" in PATCH_STATUS_INDETERMINATE.lower()


def test_cveresult_carries_patch_status_field():
    """The CVEResult.to_dict() output must include patch_status so
    the JSON export and the kerb-chain consumer see it."""
    from kerb_map.modules.cves.cve_base import CVEResult
    r = CVEResult(
        cve_id="X", name="Y", severity=Severity.HIGH,
        vulnerable=True, reason="r", evidence={}, remediation="rem",
        next_step="ns",
    )
    d = r.to_dict()
    assert "patch_status" in d
    assert d["patch_status"] == PATCH_STATUS_INDETERMINATE


# ────────────────────────────────────────────────────────── noPac ────


def test_nopac_maq_zero_is_info_with_na_patch_status():
    """No precondition → INFO, patch_status = N/A. Used to be CRITICAL
    even when MAQ=0 because the DFL heuristic dominated."""
    ldap = _ldap([[_entry({"ms-DS-MachineAccountQuota": 0})]])
    result = NoPac(ldap, "1.1.1.1", "corp.local").check()
    assert result.severity == Severity.INFO
    assert result.vulnerable is False
    assert "N/A" in result.patch_status


def test_nopac_maq_positive_is_high_indeterminate():
    """Precondition present → HIGH (not CRITICAL — we can't confirm
    patch state), patch_status = INDETERMINATE, vulnerable=True
    pending operator confirmation."""
    ldap = _ldap([[_entry({"ms-DS-MachineAccountQuota": 10})]])
    result = NoPac(ldap, "1.1.1.1", "corp.local").check()
    assert result.severity == Severity.HIGH
    assert result.vulnerable is True
    assert result.patch_status == PATCH_STATUS_INDETERMINATE
    assert "noPac.py" in result.next_step


def test_nopac_no_longer_consults_dfl():
    """The new code path must not query msDS-Behavior-Version. If a
    new contributor re-adds the DFL check by accident, the LDAP mock
    only returning the MAQ entry will surface the bug as an exception."""
    ldap = _ldap([[_entry({"ms-DS-MachineAccountQuota": 10})]])
    NoPac(ldap, "1.1.1.1", "corp.local").check()
    # Only ONE query was needed (MAQ); the DFL query is gone.
    assert ldap.query.call_count == 1


# ──────────────────────────────────────────────────────── Certifried ──


def test_certifried_no_adcs_is_info():
    ldap = MagicMock()
    ldap.query_config.return_value = []     # no enrollment services
    ldap.query.return_value = [_entry({"ms-DS-MachineAccountQuota": 10})]
    result = Certifried(ldap, "1.1.1.1", "corp.local").check()
    assert result.severity == Severity.INFO
    assert result.vulnerable is False
    assert "AD CS not deployed" in result.reason


def test_certifried_adcs_with_maq_zero_is_info():
    ldap = MagicMock()
    ldap.query_config.return_value = [_entry({"cn": "CA1"})]
    ldap.query.return_value = [_entry({"ms-DS-MachineAccountQuota": 0})]
    result = Certifried(ldap, "1.1.1.1", "corp.local").check()
    assert result.severity == Severity.INFO
    assert result.vulnerable is False
    assert "MachineAccountQuota=0" in result.reason


def test_certifried_adcs_plus_maq_is_high_indeterminate():
    ldap = MagicMock()
    ldap.query_config.return_value = [_entry({"cn": "CA1"})]
    ldap.query.return_value = [_entry({"ms-DS-MachineAccountQuota": 10})]
    result = Certifried(ldap, "1.1.1.1", "corp.local").check()
    assert result.severity == Severity.HIGH
    assert result.vulnerable is True
    assert result.patch_status == PATCH_STATUS_INDETERMINATE
    assert "certipy" in result.next_step.lower()


# ─────────────────────────────────────────────────────── Bronze Bit ──


def test_bronze_bit_no_constrained_delegation_is_info():
    ldap = _ldap([[]])    # no constrained-delegation accounts
    result = BronzeBit(ldap, "1.1.1.1", "corp.local").check()
    assert result.severity == Severity.INFO
    assert result.vulnerable is False
    assert "No constrained delegation" in result.reason


def test_bronze_bit_with_constrained_is_medium_indeterminate():
    ldap = _ldap([[_entry({"sAMAccountName": "svc_app"})]])
    result = BronzeBit(ldap, "1.1.1.1", "corp.local").check()
    # MEDIUM (down from HIGH) — we can't verify patch state from LDAP.
    assert result.severity == Severity.MEDIUM
    assert result.vulnerable is True
    assert result.patch_status == PATCH_STATUS_INDETERMINATE
    assert "PerformTicketSignature" in result.remediation


# ────────────────────────────────────────────────────── ZeroLogon ────


def test_zerologon_no_rpc_probe_is_high_indeterminate(monkeypatch):
    """When impacket is unavailable (or --aggressive not passed and
    the RPC probe is skipped), report HIGH + INDETERMINATE."""
    monkeypatch.setattr(
        "kerb_map.modules.cves.zerologon.IMPACKET_AVAILABLE", False)
    result = ZeroLogon(MagicMock(), "1.1.1.1", "corp.local").check()
    assert result.severity == Severity.HIGH
    assert result.vulnerable is True   # CVE applies until proven otherwise
    assert result.patch_status == PATCH_STATUS_INDETERMINATE
    assert "zerologon_tester.py" in result.next_step


def test_zerologon_rpc_indicates_patched_is_info(monkeypatch):
    """If the SecuraBV probe affirmatively returns False (patched),
    downgrade to INFO and mark not-vulnerable."""
    monkeypatch.setattr(
        "kerb_map.modules.cves.zerologon.IMPACKET_AVAILABLE", True)

    class FakeProbeZeroLogon(ZeroLogon):
        def _probe_securabv(self) -> bool:
            return False
    result = FakeProbeZeroLogon(MagicMock(), "1.1.1.1", "corp.local").check()
    assert result.severity == Severity.INFO
    assert result.vulnerable is False
    assert "patched" in result.patch_status.lower()


def test_zerologon_rpc_indicates_vulnerable_is_critical(monkeypatch):
    """SecuraBV probe succeeded — DC accepted the zeroed challenge.
    CRITICAL + RPC_CONFIRMED_VULNERABLE patch_status (no longer a
    'heuristic' string — the probe is now ground truth)."""
    monkeypatch.setattr(
        "kerb_map.modules.cves.zerologon.IMPACKET_AVAILABLE", True)

    class FakeProbeZeroLogon(ZeroLogon):
        def _probe_securabv(self) -> bool:
            return True
    result = FakeProbeZeroLogon(MagicMock(), "1.1.1.1", "corp.local").check()
    assert result.severity == Severity.CRITICAL
    assert result.vulnerable is True
    assert "confirms vulnerable" in result.patch_status.lower()

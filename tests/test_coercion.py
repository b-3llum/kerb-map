"""Coercion module tests.

Mocks the impacket RPC plumbing so we can exercise the bucketing and
finding-shape logic without needing a real DC. Lab acceptance ("seeded
DC, scan flags PrinterBug + PetitPotam available, ShadowCoerce missing")
deferred until lab is up.
"""

from unittest.mock import MagicMock

from kerb_map.modules.coercion import (
    VECTORS,
    CoercionVector,
    CoercionVectors,
    probe_rpc_interface,
)
from kerb_map.plugin import ScanContext

# ────────────────────────────────────────────── helpers ────


def _entry(values: dict):
    e = MagicMock()
    e.__contains__ = lambda self, k: k in values
    def _get(self, k):
        v = values[k]
        m = MagicMock()
        m.value = v
        m.values = v if isinstance(v, list) else [v]
        return m
    e.__getitem__ = _get
    return e


def _ctx(query_responses, *, aggressive=True):
    ldap = MagicMock()
    queue = list(query_responses)
    ldap.query.side_effect = lambda **_: queue.pop(0) if queue else []
    return ScanContext(
        ldap=ldap,
        domain="corp.local",
        base_dn="DC=corp,DC=local",
        dc_ip="10.0.0.5",
        domain_sid="S-1-5-21-1-2-3",
        aggressive=aggressive,
    )


def _dc_entry(name: str, dns: str | None = None, os_name: str | None = None):
    return _entry({
        "sAMAccountName":  f"{name}$",
        "name":            name,
        "dNSHostName":     dns or f"{name.lower()}.corp.local",
        "operatingSystem": os_name,
    })


# ─────────────────────────────────────── module declaration ────


def test_module_requires_aggressive_by_default():
    """RPC binds are loud-by-perception even though no Event 5145 fires;
    keep the gate so deeply-paranoid environments can opt out."""
    assert CoercionVectors.requires_aggressive is True
    assert CoercionVectors.in_default_run is True


def test_vectors_cover_all_four_techniques():
    """Regression guard: if someone removes a vector by accident, this
    test catches it before a real DC scan."""
    techniques = {v.technique for v in VECTORS}
    assert "PrinterBug" in techniques
    assert any(t.startswith("PetitPotam") for t in techniques)
    assert "DFSCoerce" in techniques
    assert "ShadowCoerce" in techniques


def test_each_vector_has_uuid_and_pipe():
    for v in VECTORS:
        assert v.interface_uuid
        assert v.pipe.startswith(r"\pipe\\") or v.pipe.startswith("\\pipe\\")
        assert v.technique


# ───────────────────────────────────── DC enumeration ────


def test_enumerate_dcs_pulls_primary_group_516():
    """Filter must use primaryGroupID=516 (Domain Controllers) so it
    works on both Samba and Windows."""
    dc = _dc_entry("DC01")
    ctx = _ctx([[dc], []])  # one DC, then empty for any subsequent query

    # Force probe_rpc_interface to return False so we don't actually
    # try real RPC during this test.
    import kerb_map.modules.coercion as cmod
    saved_probe = cmod.probe_rpc_interface
    try:
        cmod.probe_rpc_interface = lambda target, vector, **_: (False, "mocked")
        result = CoercionVectors().scan(ctx)
    finally:
        cmod.probe_rpc_interface = saved_probe

    assert result.raw["applicable"] is True
    assert "DC01" in result.raw["dcs_probed"]


def test_no_dcs_returns_inapplicable():
    ctx = _ctx([[]])
    result = CoercionVectors().scan(ctx)
    assert result.findings == []
    assert result.raw["applicable"] is False


# ─────────────────────────────────── per-vector finding ────


def test_available_vector_emits_high_finding(monkeypatch):
    """One DC, one vector reachable → one HIGH finding (per-vector) +
    optionally a compound finding when MS-EFSR is among them."""
    dc = _dc_entry("DC01")
    monkeypatch.setattr(
        "kerb_map.modules.coercion.probe_rpc_interface",
        lambda target, vector, **_: (
            (True, "bound") if vector.technique == "PrinterBug" else (False, "mocked")
        ),
    )
    ctx = _ctx([[dc]])
    result = CoercionVectors().scan(ctx)
    high = [f for f in result.findings if f.attack.startswith("Coercion: PrinterBug")]
    assert len(high) == 1
    assert high[0].severity == "HIGH"
    assert high[0].priority == 85
    assert high[0].mitre == "T1187"
    assert "Coercer.py" in high[0].next_step
    assert "ms-rprn" in high[0].next_step.lower()


def test_petitpotam_available_emits_compound_critical(monkeypatch):
    """MS-EFSR available → ESC8-relay-ready compound finding (CRITICAL,
    priority 94) on top of the per-vector HIGH."""
    dc = _dc_entry("DC01")
    monkeypatch.setattr(
        "kerb_map.modules.coercion.probe_rpc_interface",
        lambda target, vector, **_: (
            (True, "bound") if vector.technique.startswith("PetitPotam") else (False, "mocked")
        ),
    )
    ctx = _ctx([[dc]])
    result = CoercionVectors().scan(ctx)

    compound = [f for f in result.findings
                if f.attack.startswith("PetitPotam → ESC8")]
    assert len(compound) == 1
    assert compound[0].severity == "CRITICAL"
    assert compound[0].priority == 94
    assert "ntlmrelayx" in compound[0].next_step.lower()


def test_no_available_vectors_emits_no_findings(monkeypatch):
    dc = _dc_entry("DC01")
    monkeypatch.setattr(
        "kerb_map.modules.coercion.probe_rpc_interface",
        lambda target, vector, **_: (False, "ConnectionError: nope"),
    )
    ctx = _ctx([[dc]])
    result = CoercionVectors().scan(ctx)
    assert result.findings == []
    assert result.raw["summary"]["vectors_available"] == 0


def test_summary_counts_techniques(monkeypatch):
    dc = _dc_entry("DC01")
    available = {"PrinterBug", "DFSCoerce"}
    monkeypatch.setattr(
        "kerb_map.modules.coercion.probe_rpc_interface",
        lambda target, vector, **_: (
            (True, "bound") if vector.technique in available else (False, "mocked")
        ),
    )
    ctx = _ctx([[dc]])
    result = CoercionVectors().scan(ctx)
    s = result.raw["summary"]
    assert s["vectors_available"] == 2
    assert set(s["techniques_available"]) == available


def test_multiple_dcs_each_get_probed(monkeypatch):
    """Two DCs, vector available on both → two findings (one per DC)."""
    dc1 = _dc_entry("DC01")
    dc2 = _dc_entry("DC02", dns="dc02.corp.local")
    monkeypatch.setattr(
        "kerb_map.modules.coercion.probe_rpc_interface",
        lambda target, vector, **_: (
            (True, "bound") if vector.technique == "PrinterBug" else (False, "mocked")
        ),
    )
    ctx = _ctx([[dc1, dc2]])
    result = CoercionVectors().scan(ctx)
    pb_findings = [f for f in result.findings if "PrinterBug" in f.attack]
    assert len(pb_findings) == 2
    targets = {f.target for f in pb_findings}
    assert targets == {"dc01.corp.local", "dc02.corp.local"}


# ───────────────────────────────────────── probe behaviour ────


def test_probe_handles_impacket_missing(monkeypatch):
    """If impacket isn't installed (e.g. operator stripped deps),
    probe returns (False, error message) rather than crashing."""
    import builtins
    real_import = builtins.__import__
    def fake_import(name, *args, **kw):
        if name.startswith("impacket"):
            raise ImportError("simulated missing impacket")
        return real_import(name, *args, **kw)
    monkeypatch.setattr(builtins, "__import__", fake_import)

    available, detail = probe_rpc_interface(
        "dc.example.com",
        CoercionVector(
            technique="PrinterBug",
            interface_uuid="12345678-1234-ABCD-EF00-0123456789AB",
            interface_version="1.0",
            pipe=r"\pipe\spoolss",
            description="x",
        ),
    )
    assert available is False
    assert "impacket" in detail.lower()

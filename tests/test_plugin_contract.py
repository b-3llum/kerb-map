"""Plugin contract — registry behaviour and Module ABC."""

import pytest

from kerb_map.plugin import (
    _REGISTRY,
    Finding,
    Module,
    ScanContext,
    ScanResult,
    all_modules,
    register,
)


@pytest.fixture(autouse=True)
def isolate_registry():
    """Each test gets a clean registry — module imports elsewhere
    shouldn't leak into these unit tests."""
    saved = list(_REGISTRY)
    _REGISTRY.clear()
    yield
    _REGISTRY.clear()
    _REGISTRY.extend(saved)


def _module(flag: str, name: str = "test"):
    """Helper: build a minimal Module subclass with the given flag."""
    class _M(Module):
        pass
    _M.name = name
    _M.flag = flag
    _M.description = f"{name} module"
    _M.scan = lambda self, ctx: ScanResult()
    _M.__name__ = f"M_{flag}"
    return _M


def test_register_adds_module():
    M = _module("x")
    register(M)
    assert M in all_modules()


def test_register_rejects_non_module():
    class NotAModule:
        flag = "n"

    with pytest.raises(TypeError):
        register(NotAModule)


def test_register_rejects_missing_flag():
    NoFlag = _module("")
    with pytest.raises(ValueError, match="flag must be set"):
        register(NoFlag)


def test_register_rejects_duplicate_flag():
    register(_module("dup", name="A"))
    with pytest.raises(ValueError, match="flag conflict"):
        register(_module("dup", name="B"))


def test_finding_as_dict_round_trip():
    f = Finding(
        target="svc_sql", attack="Kerberoast", severity="HIGH",
        priority=80, reason="RC4 + 4y old", next_step="GetUserSPNs.py ...",
        category="kerberoast", mitre="T1558.003",
    )
    d = f.as_dict()
    assert d["target"] == "svc_sql"
    assert d["mitre"] == "T1558.003"
    assert d["data"] == {}


def test_scan_context_carries_resolved_state():
    ctx = ScanContext(
        ldap=object(), domain="corp.local", base_dn="DC=corp,DC=local",
        dc_ip="10.0.0.1", aggressive=True,
        domain_info={"fl_int": 10}, domain_sid="S-1-5-21-1-2-3",
    )
    assert ctx.aggressive is True
    assert ctx.domain_sid.startswith("S-1-5-21-")
    assert ctx.domain_info["fl_int"] == 10


def test_module_must_implement_scan():
    """Subclassing Module without implementing scan() is forbidden by ABC."""
    class Incomplete(Module):
        name = "i"
        flag = "i"
        description = "i"

    with pytest.raises(TypeError):
        Incomplete()

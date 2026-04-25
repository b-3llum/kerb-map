"""
Plugin contract for kerb-map scan modules.

A module is a class that:
  * subclasses ``Module``
  * declares ``name``, ``flag``, ``description``, ``category``
  * implements ``scan(ctx) -> ScanResult``

Modules register themselves with ``@register`` at import time. ``cli.py``
walks the registry to build the argparse flag group, dispatch the
selected scans, hand findings to the scorer, and feed the reporter and
exporter — *no* per-module wiring lives in the CLI.

Adding a new module = drop one file under ``kerb_map/modules/`` (or
``kerb_map/modules/cves/``) with the ``@register`` decorator. The CLI
picks it up on next launch.
"""

from __future__ import annotations

import importlib
import pkgutil
from abc import ABC, abstractmethod
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

# ────────────────────────────────────────────────────────────────────── #
#  Result types                                                          #
# ────────────────────────────────────────────────────────────────────── #


@dataclass
class Finding:
    """A single attack-surface item produced by a module.

    ``priority`` and ``severity`` feed the Scorer's ranked output;
    ``next_step`` is the operator-facing exploit recipe; ``data`` is the
    raw evidence (used by exporters and by kerb-chain to fill in
    placeholders like ``<DC_IP>`` or ``<DOMAIN_SID>``).
    """

    target:    str                  # the principal / object the finding is about
    attack:    str                  # short attack/finding name
    severity:  str                  # CRITICAL / HIGH / MEDIUM / LOW / INFO
    priority:  int                  # 0–100, higher = act on it sooner
    reason:    str                  # one-line operator-facing rationale
    next_step: str = ""             # ready-to-run command(s); placeholders allowed
    category:  str = ""             # filled in by Module.category if blank
    mitre:     str = ""             # MITRE ATT&CK technique ID, e.g. T1558.003
    data:      dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "target":    self.target,
            "attack":    self.attack,
            "severity":  self.severity,
            "priority":  self.priority,
            "reason":    self.reason,
            "next_step": self.next_step,
            "category":  self.category,
            "mitre":     self.mitre,
            "data":      self.data,
        }


@dataclass
class ScanResult:
    """What a module returns from ``scan(ctx)``.

    ``raw`` is the structured-but-not-yet-prioritised payload (kept for
    JSON / BloodHound export). ``findings`` is the list the scorer
    consumes; modules can return raw without findings (informational
    enumeration) or findings without raw (pure attack-surface modules).
    """

    raw:      Any = None
    findings: list[Finding] = field(default_factory=list)
    info:     dict[str, Any] = field(default_factory=dict)


# ────────────────────────────────────────────────────────────────────── #
#  Scan context — what every module gets                                 #
# ────────────────────────────────────────────────────────────────────── #


@dataclass
class ScanContext:
    """Everything a module might need, resolved once at the top of the
    scan and passed by reference to each module so modules don't each
    re-derive the same data.
    """

    ldap:         Any                       # bound LDAPClient
    domain:       str                       # e.g. 'corp.local'
    base_dn:      str                       # 'DC=corp,DC=local'
    dc_ip:        str
    aggressive:   bool = False              # gate for RPC / loud probes
    domain_info:  dict[str, Any] = field(default_factory=dict)  # filled by core
    domain_sid:   str | None = None         # filled by core when known


# ────────────────────────────────────────────────────────────────────── #
#  Base class                                                            #
# ────────────────────────────────────────────────────────────────────── #


class Module(ABC):
    """Subclass + ``@register`` to add a new scan module.

    Subclasses must set ``name``, ``flag``, ``description``,
    ``category``. Override ``requires_aggressive`` to True for modules
    that issue RPC calls or other loud probes — the CLI will skip them
    unless ``--aggressive`` was passed.
    """

    name:        str = ""
    flag:        str = ""           # CLI flag without leading '--', e.g. 'dcsync'
    description: str = ""
    category:    str = "enumeration"  # 'enumeration', 'cve', 'hygiene', 'attack-path'
    requires_aggressive: bool = False
    in_default_run:      bool = True   # included by --all / no module flag

    @abstractmethod
    def scan(self, ctx: ScanContext) -> ScanResult:  # pragma: no cover - abstract
        ...


# ────────────────────────────────────────────────────────────────────── #
#  Registry                                                              #
# ────────────────────────────────────────────────────────────────────── #


_REGISTRY: list[type[Module]] = []


def register(cls: type[Module]) -> type[Module]:
    """Decorator. Adds a Module subclass to the registry at import time.

    Each subclass must be unique by ``flag``; registering a duplicate
    raises immediately so two modules can't silently fight over a CLI flag.
    """
    if not issubclass(cls, Module):
        raise TypeError(f"@register expects a Module subclass, got {cls!r}")
    if not cls.flag:
        raise ValueError(f"{cls.__name__}: Module.flag must be set")

    for existing in _REGISTRY:
        if existing.flag == cls.flag:
            raise ValueError(
                f"flag conflict: {cls.__name__} and {existing.__name__} "
                f"both claim --{cls.flag}"
            )

    _REGISTRY.append(cls)
    return cls


def all_modules() -> list[type[Module]]:
    """Snapshot of every registered Module subclass, in registration order."""
    return list(_REGISTRY)


def discover(packages: Iterable[str] = ("kerb_map.modules",)) -> int:
    """Import every submodule under ``packages`` so their ``@register``
    side-effects run. Returns the number of modules discovered.

    Called once from the CLI before parsing args. Submodules that raise
    on import are skipped with a console warning rather than killing the
    whole CLI — a broken plugin shouldn't stop the rest of the tool.
    """
    initial = len(_REGISTRY)
    for pkg_name in packages:
        try:
            pkg = importlib.import_module(pkg_name)
        except ImportError:
            continue
        for mod_info in pkgutil.walk_packages(pkg.__path__, prefix=pkg.__name__ + "."):
            try:
                importlib.import_module(mod_info.name)
            except Exception as e:  # noqa: BLE001 - one bad plugin shouldn't kill CLI
                from kerb_map.output.logger import Logger
                Logger().warn(f"plugin import failed: {mod_info.name}: {e}")
    return len(_REGISTRY) - initial

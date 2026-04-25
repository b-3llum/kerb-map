"""
Partial-scan persistence (brief §3.8).

A v2 plugin / CVE scan against a large estate can run for minutes —
losing it all to an LDAP timeout or Ctrl-C halfway through is the most
operator-hostile outcome the brief calls out. This module persists
each completed module's findings to ``~/.kerb-map/in_progress/<id>.json``
as the scan runs, so:

  1. Ctrl-C / network blip / timeout doesn't lose work already done.
  2. ``--resume <id>`` picks up at the next un-finished module.
  3. ``--list-resumable`` shows which scans can be continued.

Scope decision: resume covers the **CVE checks and v2 plugin modules**
because those are the slow ones (per-CVE network probe, per-template
DACL walk). Legacy LDAP scans (SPN, ASREP, delegation, user enum)
re-run cheaply on resume — they're a few queries each. Persisting
their dataclass output would need bespoke (de)serialisers; the simplification keeps this PR focused.

Storage shape (on disk, JSON):
    {
      "scan_id":         "<uuid4>",
      "domain":          "corp.local",
      "started_at":      "2026-04-25T11:30:00",
      "completed":       {"<module_flag>": [<finding-dict>, ...], ...},
      "raw":             {"<module_flag>": <raw-dict>, ...}
    }
"""

from __future__ import annotations

import datetime
import json
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

STATE_DIR = Path.home() / ".kerb-map" / "in_progress"


@dataclass
class ResumeState:
    """Per-scan partial state. Held in memory by the CLI; flushed to
    disk after every completed module."""

    scan_id:    str
    domain:     str
    started_at: str
    completed:  dict[str, list[dict]] = field(default_factory=dict)
    raw:        dict[str, Any]        = field(default_factory=dict)

    # ─────────────────────────────────────────────── factories ─

    @classmethod
    def new(cls, *, domain: str) -> ResumeState:
        """Fresh scan — generate a UUID, stamp now, flush immediately
        so the on-disk file exists before any module runs.

        Field bug it fixes: the CLI prints "Scan id: X — resume with
        --resume X if interrupted" right after this returns. Pre-fix,
        the in_progress JSON was only written on the first ``record()``
        call (i.e. after the first v2/CVE module completed). An operator
        who Ctrl-C'd during the legacy SPN/ASREP/delegation modules
        would see the announcement but ``--resume X`` would fail with
        "no resumable scan matches X". Eager flush makes the
        announcement honest — even an early Ctrl-C can be resumed
        (it just re-runs everything, which is the expected semantics
        of "no work lost")."""
        state = cls(
            scan_id    = uuid.uuid4().hex[:12],
            domain     = domain,
            started_at = datetime.datetime.now().isoformat(timespec="seconds"),
        )
        state._flush()
        return state

    @classmethod
    def load(cls, scan_id: str) -> ResumeState | None:
        """Load by full ID or unique prefix (8+ chars). Returns None
        when no state file matches — caller handles the "no such resumable"
        error message."""
        path = _resolve_state_path(scan_id)
        if path is None or not path.is_file():
            return None
        data = json.loads(path.read_text())
        return cls(
            scan_id    = data["scan_id"],
            domain     = data["domain"],
            started_at = data["started_at"],
            completed  = data.get("completed", {}),
            raw        = data.get("raw", {}),
        )

    # ─────────────────────────────────────────────── queries ─

    def is_done(self, module_flag: str) -> bool:
        """True if the named module has already produced findings in
        this scan. Also true when the module ran and produced zero
        findings (the empty-list distinguishes "ran" from "skipped")."""
        return module_flag in self.completed

    def findings_for(self, module_flag: str) -> list[dict]:
        """Cached finding dicts for a previously-run module. Empty list
        is a valid result — means "ran and found nothing"."""
        return list(self.completed.get(module_flag, []))

    def all_findings(self) -> list[dict]:
        """Flatten every module's findings into one list."""
        out: list[dict] = []
        for items in self.completed.values():
            out.extend(items)
        return out

    # ─────────────────────────────────────────────── mutation ─

    def record(self, module_flag: str,
               findings: list[Any] | None = None,
               raw: Any = None) -> None:
        """Mark a module done, store its serialised findings + raw dict.
        Findings can be Finding dataclasses, CVEResult dataclasses, or
        plain dicts — whatever round-trips through ``_to_dict``."""
        self.completed[module_flag] = [_to_dict(f) for f in (findings or [])]
        if raw is not None:
            self.raw[module_flag] = _to_dict(raw)
        self._flush()

    def discard(self) -> None:
        """Remove the on-disk state file. Called once the scan completes
        successfully — partial state has served its purpose."""
        path = STATE_DIR / f"{self.scan_id}.json"
        if path.is_file():
            path.unlink()

    def _flush(self) -> None:
        STATE_DIR.mkdir(parents=True, exist_ok=True)
        path = STATE_DIR / f"{self.scan_id}.json"
        path.write_text(json.dumps(asdict(self), indent=2, default=str))


# ───────────────────────────────────────────────── helpers ─


def _to_dict(obj: Any) -> Any:
    """Best-effort dataclass / object → dict for JSON storage. Handles
    Finding, CVEResult, plain dicts, lists. Falls back to str() for
    exotic types so we never blow up the flush."""
    if obj is None:
        return None
    # Finding has as_dict; CVEResult has to_dict.
    if hasattr(obj, "as_dict") and callable(obj.as_dict):
        return obj.as_dict()
    if hasattr(obj, "to_dict") and callable(obj.to_dict):
        return obj.to_dict()
    if isinstance(obj, dict):
        return obj
    if isinstance(obj, list):
        return [_to_dict(x) for x in obj]
    if hasattr(obj, "__dataclass_fields__"):
        return asdict(obj)
    return obj


def _resolve_state_path(scan_id: str) -> Path | None:
    """Resolve a scan_id (full or unique prefix) to a state file path.
    Returns None if no match or ambiguous prefix."""
    if not scan_id or not STATE_DIR.is_dir():
        return None
    matches = sorted(STATE_DIR.glob(f"{scan_id}*.json"))
    if len(matches) == 1:
        return matches[0]
    return None


def list_resumable() -> list[dict]:
    """Return one dict per in-progress scan, newest first. Used by
    ``--list-resumable``."""
    if not STATE_DIR.is_dir():
        return []
    out: list[dict] = []
    for path in STATE_DIR.glob("*.json"):
        try:
            data = json.loads(path.read_text())
        except (OSError, json.JSONDecodeError):
            continue
        out.append({
            "scan_id":    data.get("scan_id", path.stem),
            "domain":     data.get("domain", "?"),
            "started_at": data.get("started_at", "?"),
            "modules":    list(data.get("completed", {}).keys()),
            "findings":   sum(len(v) for v in data.get("completed", {}).values()),
        })
    out.sort(key=lambda r: r["started_at"], reverse=True)
    return out

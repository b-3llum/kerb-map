"""Load kerb-map's JSON output into a normalised list of finding dicts.

kerb-map's full_data blob has a deeply nested shape (meta, spns, asrep,
cves, hygiene, targets, …). For chain execution we only need the
``targets`` array — the ranked, deduplicated attack-surface list. Each
target carries enough data fields (target, attack, severity, priority,
data{...}) for the playbook to make routing decisions.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def load_findings(path: str | Path) -> list[dict[str, Any]]:
    """Read a kerb-map JSON export and return its ``targets`` list.

    Accepts both the current full_data shape (``{"meta":..., "targets":[...]}``)
    and a bare list of finding dicts (for hand-crafted scenario files).
    Raises ValueError on anything else so a typo'd path doesn't silently
    produce zero plays.
    """
    p = Path(path)
    raw = json.loads(p.read_text())

    if isinstance(raw, list):
        return raw
    if isinstance(raw, dict):
        items = None
        if "targets" in raw:
            items = list(raw["targets"])
        elif "findings" in raw:
            items = list(raw["findings"])
        if items is not None:
            # Stash the document's top-level meta block (domain, dc_ip, etc.)
            # into the first finding under __meta__ so Engagement.from_findings
            # can pick it up without an extra channel. Mirrors the Rust loader.
            meta = raw.get("meta")
            if meta and items and isinstance(items[0], dict):
                items[0] = {**items[0], "__meta__": meta}
            return items
    raise ValueError(
        f"{p}: unrecognised kerb-map JSON shape — expected an object with "
        f"a 'targets' or 'findings' key, or a bare list of findings."
    )


def index_by_attack(findings: list[dict]) -> dict[str, list[dict]]:
    """Group findings by their ``attack`` string. Useful inside playbook
    conditions: ``len(findings.by_attack['Kerberoast'])``."""
    out: dict[str, list[dict]] = {}
    for f in findings:
        out.setdefault(f.get("attack", "<unknown>"), []).append(f)
    return out

"""
Diff two cached scans.

Brief §3.3 — "highest-value feature for retest engagements." After a
remediation cycle the operator needs a one-glance answer to: *what did
the customer actually fix, what did they introduce, and what's still
exposed?*

Match findings by ``(target, attack)`` tuple — same key the Scorer
already uses for deduplication, so a finding that survives a re-scan
matches itself across runs even if its priority shifted slightly.

Output is three buckets:

  REMOVED   in scan A, not in scan B  (customer fixed this — good)
  ADDED     in scan B, not in scan A  (new attack surface — bad)
  UNCHANGED in both                   (still exposed — chase the customer)
"""

from __future__ import annotations

from dataclasses import dataclass

# ────────────────────────────────────────────────────────────────────── #
#  Types                                                                 #
# ────────────────────────────────────────────────────────────────────── #


# A finding is just the dict shape the Cache returns. Spelled out as a
# type alias so the diff API reads cleanly.
Finding = dict


@dataclass
class DiffResult:
    removed:   list[Finding]
    added:     list[Finding]
    unchanged: list[Finding]
    scan_a_id: int
    scan_b_id: int

    @property
    def total(self) -> int:
        return len(self.removed) + len(self.added) + len(self.unchanged)


# ────────────────────────────────────────────────────────────────────── #
#  Core                                                                  #
# ────────────────────────────────────────────────────────────────────── #


def _key(f: Finding) -> tuple[str, str]:
    """Match key. Lower-cased so a re-scan that capitalised differently
    doesn't show as a spurious removal+addition pair."""
    return (
        str(f.get("target", "")).lower(),
        str(f.get("attack", "")).lower(),
    )


def diff_findings(
    a: list[Finding],
    b: list[Finding],
    *,
    scan_a_id: int = 0,
    scan_b_id: int = 0,
) -> DiffResult:
    """Diff two findings lists. Both arguments are lists of dicts as
    returned by ``Cache.get_findings(scan_id)``.

    A finding ``f`` from A is REMOVED if no finding in B has the same
    ``_key(f)``. Vice versa for ADDED. UNCHANGED entries are taken from
    B (the more-recent scan) so any priority/severity drift is the
    fresh value, not the stale one.
    """
    a_keys = {_key(f) for f in a}
    b_keys = {_key(f) for f in b}

    a_by_key = {_key(f): f for f in a}
    b_by_key = {_key(f): f for f in b}

    removed   = sorted(
        (a_by_key[k] for k in (a_keys - b_keys)),
        key=lambda f: (-int(f.get("priority", 0)), str(f.get("target", ""))),
    )
    added     = sorted(
        (b_by_key[k] for k in (b_keys - a_keys)),
        key=lambda f: (-int(f.get("priority", 0)), str(f.get("target", ""))),
    )
    unchanged = sorted(
        (b_by_key[k] for k in (a_keys & b_keys)),
        key=lambda f: (-int(f.get("priority", 0)), str(f.get("target", ""))),
    )

    return DiffResult(
        removed=removed,
        added=added,
        unchanged=unchanged,
        scan_a_id=scan_a_id,
        scan_b_id=scan_b_id,
    )

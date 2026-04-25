"""
Self-update plumbing (brief §3.6).

The legacy ``--update`` ran a bare ``git pull`` and called it done. That
fails silently — and noisily, and often destructively — on three
common operator setups:

  * dirty working tree — ``git pull`` refuses or merges junk in
  * detached HEAD — ``git pull`` does nothing useful but exits 0
  * different upstream — pulls the wrong remote

This module exposes small, mockable helpers that the CLI orchestrates:

  is_clean(repo)            → False if working tree has uncommitted changes
  is_detached(repo)         → True if HEAD doesn't point to a branch
  current_commit(repo)      → short SHA of HEAD
  fetch(repo)               → run `git fetch --tags`
  pull_ff_only(repo)        → fast-forward only; never merges
  checkout(repo, ref)       → check out a tag / branch / sha
  log_range(repo, a, b)     → list[str] of "<sha> <subject>" between a and b

Each returns simple types and raises ``UpdateError`` on subprocess
failure so the CLI orchestration is linear and testable. ``--tag REF``
swaps the pull for ``checkout(REF)``; ``--force`` skips the dirty /
detached precheck.
"""

from __future__ import annotations

import subprocess
from pathlib import Path


class UpdateError(Exception):
    """Subprocess failure during a self-update step."""


def _run(repo: Path | str, *args: str) -> str:
    """Run a git command in ``repo``, return stdout, raise on non-zero.
    All callers pre-validated their args, so we don't shell-quote — the
    list form is safe."""
    result = subprocess.run(
        ["git", *args],
        cwd=str(repo),
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise UpdateError(
            f"git {' '.join(args)} failed: {result.stderr.strip() or result.stdout.strip()}"
        )
    return result.stdout


# ────────────────────────────────────────────────── precheck ─


def is_clean(repo: Path | str) -> bool:
    """True if the working tree has no uncommitted or untracked changes.
    ``git status --porcelain`` prints nothing when clean — that's the
    safe-to-pull contract."""
    out = _run(repo, "status", "--porcelain")
    return out.strip() == ""


def is_detached(repo: Path | str) -> bool:
    """True if HEAD doesn't point to a branch (detached at a tag/sha).
    ``git symbolic-ref -q HEAD`` exits non-zero in detached state, so we
    invert that here without raising on the expected non-zero exit."""
    result = subprocess.run(
        ["git", "symbolic-ref", "-q", "HEAD"],
        cwd=str(repo), capture_output=True, text=True,
    )
    return result.returncode != 0


# ────────────────────────────────────────────────── inspection ─


def current_commit(repo: Path | str) -> str:
    """Short SHA of HEAD — used to compute the pulled-commit range."""
    return _run(repo, "rev-parse", "--short", "HEAD").strip()


def log_range(repo: Path | str, a: str, b: str) -> list[str]:
    """Return one entry per commit in ``a..b`` as ``"<short-sha> <subject>"``.
    Empty list when nothing was pulled."""
    if a == b:
        return []
    out = _run(repo, "log", f"{a}..{b}", "--oneline", "--no-decorate")
    return [line for line in out.splitlines() if line.strip()]


# ────────────────────────────────────────────────── mutation ─


def fetch(repo: Path | str) -> None:
    """``git fetch --tags`` — pulls refs without touching the working
    tree. Always safe to call; needed before pull or tag-checkout so
    the local view of remote refs is current."""
    _run(repo, "fetch", "--tags")


def pull_ff_only(repo: Path | str) -> None:
    """Fast-forward only — never merges, never rewrites history. If
    the local branch has diverged, this raises rather than silently
    merging."""
    _run(repo, "pull", "--ff-only")


def checkout(repo: Path | str, ref: str) -> None:
    """Check out an arbitrary ref (tag, branch, sha). Used by
    ``--update --tag v1.2.0`` to pin to a release."""
    _run(repo, "checkout", ref)

"""Partial-scan persistence (brief §3.8).

Pin the on-disk shape, the prefix-match resume contract, and the
round-trip semantics. The CLI integration is exercised at smoke level
(parse args + dispatch); the real coverage lives here on the data
layer.
"""

import json
from pathlib import Path

import pytest

from kerb_map import resume as rs
from kerb_map.plugin import Finding


@pytest.fixture(autouse=True)
def isolated_state_dir(tmp_path, monkeypatch):
    """Redirect STATE_DIR to a temp path so tests don't touch the
    operator's real ~/.kerb-map/in_progress/."""
    monkeypatch.setattr(rs, "STATE_DIR", tmp_path / "in_progress")
    return tmp_path / "in_progress"


# ────────────────────────────────────────────── factory + flush ─


def test_new_state_has_uuid_scan_id(isolated_state_dir):
    state = rs.ResumeState.new(domain="corp.local")
    assert state.scan_id
    assert len(state.scan_id) >= 8
    assert state.domain == "corp.local"
    assert state.completed == {}


def test_new_state_eagerly_flushes_to_disk(isolated_state_dir):
    """Field bug: pre-fix, the in_progress JSON was only written on the
    first ``record()`` call. The CLI announces "Scan id: X — resume
    with --resume X if interrupted" right after ``new()``, so an
    operator who Ctrl-C'd before any v2/CVE module completed would
    see the announcement but ``--resume X`` would fail with "no
    resumable scan matches X" — the tool lying about its own
    capability. Eager flush makes the announcement honest."""
    state = rs.ResumeState.new(domain="corp.local")
    path = isolated_state_dir / f"{state.scan_id}.json"
    assert path.is_file()
    # And it loads back even with no modules recorded.
    loaded = rs.ResumeState.load(state.scan_id)
    assert loaded is not None
    assert loaded.scan_id == state.scan_id
    assert loaded.completed == {}


def test_record_writes_state_to_disk(isolated_state_dir):
    """The brief's headline guarantee: after every module the disk
    state must be current. A regression here means Ctrl-C loses work."""
    state = rs.ResumeState.new(domain="corp.local")
    state.record("cves", findings=[])
    path = isolated_state_dir / f"{state.scan_id}.json"
    assert path.is_file()
    data = json.loads(path.read_text())
    assert data["scan_id"] == state.scan_id
    assert "cves" in data["completed"]


def test_record_serialises_finding_dataclasses_via_as_dict():
    """Finding has as_dict(); _to_dict must use it so resume picks up
    the canonical shape rather than something brittle."""
    state = rs.ResumeState.new(domain="x")
    f = Finding(target="dc01", attack="DCSync", severity="CRITICAL",
                priority=99, reason="...", next_step="secretsdump",
                data={"principal_sid": "S-1-5-21-1-2-3-1100"})
    state.record("cves", findings=[f])
    serialised = state.completed["cves"][0]
    assert serialised["target"]   == "dc01"
    assert serialised["severity"] == "CRITICAL"
    assert serialised["data"]["principal_sid"].startswith("S-1-5-")


def test_record_handles_plain_dicts_unchanged():
    """Some callers (legacy CVE results) pass dicts directly — must
    pass through without mutation."""
    state = rs.ResumeState.new(domain="x")
    raw_dict = {"cve_id": "CVE-2020-1472", "vulnerable": True, "severity": "CRITICAL"}
    state.record("cves", findings=[raw_dict])
    assert state.completed["cves"][0] == raw_dict


def test_empty_findings_list_still_marks_module_done():
    """A module that ran and found nothing must be flagged as done so
    --resume doesn't re-run it. is_done() returns True; findings_for()
    returns []."""
    state = rs.ResumeState.new(domain="x")
    state.record("cves", findings=[])
    assert state.is_done("cves")
    assert state.findings_for("cves") == []


def test_record_persists_raw_payload():
    """v2 modules carry a raw dict alongside findings — used by the
    JSON export. Resume must round-trip both."""
    state = rs.ResumeState.new(domain="x")
    state.record("v2:dcsync", findings=[], raw={"applicable": True, "writers": []})
    assert state.raw["v2:dcsync"]["applicable"] is True


# ────────────────────────────────────────────── load / resume ─


def test_load_returns_none_when_no_match():
    """Bad scan-id is not a crash — caller decides how to surface it."""
    assert rs.ResumeState.load("does-not-exist") is None


def test_load_with_full_id_round_trips(isolated_state_dir):
    state = rs.ResumeState.new(domain="corp.local")
    state.record("cves", findings=[
        Finding(target="x", attack="y", severity="HIGH",
                priority=80, reason="r", next_step="s"),
    ])
    loaded = rs.ResumeState.load(state.scan_id)
    assert loaded is not None
    assert loaded.scan_id == state.scan_id
    assert loaded.domain  == "corp.local"
    assert loaded.is_done("cves")
    assert loaded.findings_for("cves")[0]["target"] == "x"


def test_load_with_unique_prefix_round_trips(isolated_state_dir):
    """Operator types --resume <first-8-chars> instead of the full UUID
    — cleaner UX. Pin that prefix-match works when unambiguous."""
    state = rs.ResumeState.new(domain="x")
    state.record("cves", findings=[])
    prefix = state.scan_id[:6]
    loaded = rs.ResumeState.load(prefix)
    assert loaded is not None
    assert loaded.scan_id == state.scan_id


def test_load_returns_none_when_prefix_is_ambiguous(isolated_state_dir):
    """Two scans share a prefix → don't pick one silently. Operator
    must use a longer prefix or the full id."""
    s1 = rs.ResumeState.new(domain="a")
    s2 = rs.ResumeState.new(domain="b")
    # Force the IDs to share a prefix.
    s1.scan_id = "abc12345"
    s2.scan_id = "abc67890"
    s1._flush()
    s2._flush()
    assert rs.ResumeState.load("abc") is None
    # Longer prefix still works for the unique branch.
    assert rs.ResumeState.load("abc1") is not None


def test_is_done_separates_completed_from_pending():
    state = rs.ResumeState.new(domain="x")
    state.record("cves", findings=[])
    assert state.is_done("cves") is True
    assert state.is_done("v2:dcsync") is False


# ────────────────────────────────────────────── lifecycle ─


def test_discard_removes_state_file(isolated_state_dir):
    """End-of-scan: SQLite cache holds the canonical record, so the
    in-progress JSON is no longer needed and would clutter
    --list-resumable."""
    state = rs.ResumeState.new(domain="x")
    state.record("cves", findings=[])
    path = isolated_state_dir / f"{state.scan_id}.json"
    assert path.is_file()
    state.discard()
    assert not path.is_file()


def test_discard_is_idempotent(isolated_state_dir):
    """Don't blow up if the file's already gone — operator might have
    deleted it manually."""
    state = rs.ResumeState.new(domain="x")
    state.discard()  # never flushed
    state.discard()  # second call


# ────────────────────────────────────────────── list_resumable ─


def test_list_resumable_returns_empty_when_no_dir(tmp_path, monkeypatch):
    """Fresh install: no in_progress dir yet — must not crash."""
    monkeypatch.setattr(rs, "STATE_DIR", tmp_path / "missing")
    assert rs.list_resumable() == []


def test_list_resumable_returns_per_scan_summary(isolated_state_dir):
    """The shape that --list-resumable will render."""
    s1 = rs.ResumeState.new(domain="alpha.local")
    s1.record("cves", findings=[
        Finding(target="x", attack="y", severity="HIGH", priority=80, reason="..."),
    ])
    s2 = rs.ResumeState.new(domain="bravo.local")
    s2.record("v2:dcsync", findings=[])
    s2.record("cves",       findings=[])
    rows = rs.list_resumable()
    assert len(rows) == 2
    by_domain = {r["domain"]: r for r in rows}
    assert by_domain["alpha.local"]["findings"] == 1
    assert by_domain["alpha.local"]["modules"]  == ["cves"]
    assert by_domain["bravo.local"]["findings"] == 0
    assert sorted(by_domain["bravo.local"]["modules"]) == ["cves", "v2:dcsync"]


def test_list_resumable_skips_corrupt_files(isolated_state_dir):
    """If a state file got partially written / hand-edited, skip it
    rather than crashing the whole listing."""
    isolated_state_dir.mkdir(parents=True, exist_ok=True)
    (isolated_state_dir / "broken.json").write_text("{not json")
    good = rs.ResumeState.new(domain="x")
    good.record("cves", findings=[])
    rows = rs.list_resumable()
    assert len(rows) == 1
    assert rows[0]["scan_id"] == good.scan_id

"""--diff between scans (brief §3.3)."""

from kerb_map.diff import DiffResult, diff_findings


def _f(target, attack, **kw):
    """Build a finding dict that matches what Cache.get_findings returns."""
    base = {"target": target, "attack": attack, "severity": "HIGH",
            "priority": 75, "reason": f"{attack} on {target}"}
    base.update(kw)
    return base


# ─────────────────────────────────────── identity / shape ────


def test_diff_returns_diffresult():
    r = diff_findings([], [])
    assert isinstance(r, DiffResult)
    assert r.removed == []
    assert r.added == []
    assert r.unchanged == []
    assert r.total == 0


def test_diff_records_scan_ids():
    r = diff_findings([], [], scan_a_id=3, scan_b_id=7)
    assert r.scan_a_id == 3
    assert r.scan_b_id == 7


# ───────────────────────────────────────────── REMOVED ────


def test_finding_in_a_only_is_removed():
    a = [_f("svc_sql", "Kerberoast")]
    b: list = []
    r = diff_findings(a, b)
    assert len(r.removed) == 1
    assert r.removed[0]["target"] == "svc_sql"
    assert r.added == []
    assert r.unchanged == []


def test_multiple_removed_sorted_by_priority_desc():
    a = [
        _f("low_pri",  "Hygiene", priority=20),
        _f("high_pri", "DCSync",  priority=95),
        _f("med_pri",  "Asrep",   priority=60),
    ]
    r = diff_findings(a, [])
    priorities = [f["priority"] for f in r.removed]
    assert priorities == sorted(priorities, reverse=True)


# ─────────────────────────────────────────────── ADDED ────


def test_finding_in_b_only_is_added():
    b = [_f("oldsvc", "AS-REP Roast")]
    r = diff_findings([], b)
    assert len(r.added) == 1
    assert r.added[0]["target"] == "oldsvc"
    assert r.removed == []


def test_multiple_added_sorted_by_priority_desc():
    b = [
        _f("a", "X", priority=10),
        _f("b", "Y", priority=80),
        _f("c", "Z", priority=50),
    ]
    r = diff_findings([], b)
    priorities = [f["priority"] for f in r.added]
    assert priorities == sorted(priorities, reverse=True)


# ────────────────────────────────────────── UNCHANGED ────


def test_finding_in_both_is_unchanged():
    a = [_f("svc_sql", "Kerberoast")]
    b = [_f("svc_sql", "Kerberoast")]
    r = diff_findings(a, b)
    assert len(r.unchanged) == 1
    assert r.added == []
    assert r.removed == []


def test_unchanged_takes_b_values_when_severity_drifts():
    """If priority/severity drift between scans, the UNCHANGED entry
    should reflect the *fresh* (B) value — operators want the latest
    state, not the stale baseline."""
    a = [_f("svc_sql", "Kerberoast", severity="MEDIUM", priority=50)]
    b = [_f("svc_sql", "Kerberoast", severity="HIGH",   priority=80)]
    r = diff_findings(a, b)
    assert len(r.unchanged) == 1
    assert r.unchanged[0]["severity"] == "HIGH"
    assert r.unchanged[0]["priority"] == 80


# ────────────────────────────────────── matching key ────


def test_match_is_case_insensitive():
    """A re-scan that capitalised differently shouldn't show as a
    spurious removal+addition pair."""
    a = [_f("SVC_SQL", "Kerberoast")]
    b = [_f("svc_sql", "kerberoast")]
    r = diff_findings(a, b)
    assert len(r.unchanged) == 1
    assert r.removed == []
    assert r.added == []


def test_different_attack_on_same_target_is_separate_finding():
    """svc_sql being both Kerberoastable AND in DCSync rights = two
    distinct findings; diff treats them independently."""
    a = [_f("svc_sql", "Kerberoast")]
    b = [_f("svc_sql", "Kerberoast"),
         _f("svc_sql", "DCSync (full)", priority=95)]
    r = diff_findings(a, b)
    assert len(r.unchanged) == 1
    assert len(r.added) == 1
    assert r.added[0]["attack"] == "DCSync (full)"


# ─────────────────────────────────── realistic scenario ────


def test_typical_retest_scenario():
    """The headline use case: customer fixed 2 things, introduced 1
    new thing, 3 are still exposed. The diff should bucket cleanly."""
    a = [
        _f("svc_sql",  "Kerberoast",            priority=80),  # fixed
        _f("oldsvc",   "AS-REP Roast",          priority=70),  # fixed
        _f("WEB01$",   "Unconstrained Delegation", priority=95),  # still exposed
        _f("svc_app",  "Credential exposure",   priority=40),    # still exposed
        _f("krbtgt",   "krbtgt rotation overdue", priority=60),  # still exposed
    ]
    b = [
        _f("WEB01$",   "Unconstrained Delegation", priority=95),  # still exposed
        _f("svc_app",  "Credential exposure",   priority=40),    # still exposed
        _f("krbtgt",   "krbtgt rotation overdue", priority=60),  # still exposed
        _f("kdsleaker","Golden dMSA prerequisite (KDS root key readable)",
                                                priority=97),    # NEW
    ]
    r = diff_findings(a, b)
    assert len(r.removed)   == 2
    assert {f["target"] for f in r.removed} == {"svc_sql", "oldsvc"}
    assert len(r.added)     == 1
    assert r.added[0]["target"] == "kdsleaker"
    assert len(r.unchanged) == 3
    assert r.total == 6

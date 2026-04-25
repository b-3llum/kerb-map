"""Password spray pre-check (brief §4.8).

Pin the lockout-safety contract and the spray ordering. The actual
LDAP bind is mocked via ``try_credential_fn`` injection — we never
hit a network in unit tests.
"""

import pytest

from kerb_map.modules.spray import (
    SprayHit,
    SprayResult,
    generate_wordlist,
    safe_password_count,
    spray,
)

# ────────────────────────────────────── wordlist generation ─


def test_wordlist_includes_season_year():
    """Headline candidate: helpdesk-set Spring2026!. Year forced for
    determinism — a regression that drops the season+year pattern
    would silently lose the most-likely guesses."""
    out = generate_wordlist("corp.local", year=2026)
    assert "Spring2026!" in out
    assert "Summer2026!" in out
    assert "Autumn2026!" in out
    assert "Winter2026!" in out


def test_wordlist_includes_prior_year_seasonal():
    """Newly hired admins often have a year-1 password (set during
    onboarding, never rotated)."""
    out = generate_wordlist("corp.local", year=2026)
    assert "Spring2025!" in out


def test_wordlist_includes_domain_year():
    """The 'CORP2026!' helpdesk-default — every estate has one."""
    out = generate_wordlist("corp.local", year=2026)
    assert "CORP2026!" in out
    assert "CORP2026"  in out


def test_wordlist_uppercase_domain_short_name_only():
    """'corp.local' → 'CORP' — only the first DNS label, uppercased.
    A regression that included the .local suffix would generate
    nonsense passwords."""
    out = generate_wordlist("corp.example.org", year=2026)
    assert "CORP2026!" in out
    assert "EXAMPLE2026!" not in out
    assert "corp2026!"   not in out


def test_wordlist_includes_universal_stock_passwords():
    """The 'Welcome1' tier — these hit on freshly-provisioned accounts
    that nobody changed."""
    out = generate_wordlist("corp.local", year=2026)
    assert "Welcome1"   in out
    assert "Password1"  in out


def test_wordlist_de_duplicates():
    """No duplicate entries — wastes attempts and inflates the
    lockout-safety calculation."""
    out = generate_wordlist("corp.local", year=2026)
    assert len(out) == len(set(out))


def test_wordlist_respects_max_count():
    """Operator can cap the dictionary size to fit a tight lockout
    policy (e.g., 3-attempt lockout)."""
    out = generate_wordlist("corp.local", year=2026, max_count=5)
    assert len(out) == 5


def test_wordlist_works_without_domain():
    """Operator might invoke without --domain in some flows — fall
    back to seasons + stock without the domain bucket."""
    out = generate_wordlist(None, year=2026)
    assert "Spring2026!" in out
    assert "Welcome1"    in out
    assert not any("CORP" in pw for pw in out)


# ────────────────────────────────────── lockout gate ─


def test_safe_count_with_threshold_5_leaves_buffer():
    """Default policy: lockout at 5 bad. We use 4 to leave one slot."""
    assert safe_password_count(5) == 4


def test_safe_count_threshold_zero_means_unlimited():
    """lockoutThreshold=0 == lockout disabled. Spray freely."""
    assert safe_password_count(0) is None


def test_safe_count_unknown_threshold_assumes_default():
    """If we couldn't read the policy, assume the AD default (5) so
    we don't stomp accounts in unlucky environments."""
    assert safe_password_count(None) == 4


def test_safe_count_very_low_threshold_returns_at_least_one():
    """Even with threshold=1, we'd allow 1 attempt — caller has
    already gated on the policy at the confirmation prompt."""
    assert safe_password_count(1) == 1
    assert safe_password_count(2) == 1


def test_safe_count_buffer_is_configurable():
    """Operator owns the policy → can set buffer=0 to use the full
    threshold."""
    assert safe_password_count(5, bad_count_buffer=0) == 5


# ────────────────────────────────────── orchestrator ─


def _record_attempts(record: list):
    """Build a fake try_credential that logs every attempt and returns
    True for one specific (user, password) pair."""
    def fn(dc_ip, domain, user, password):
        record.append((user, password))
        return user == "alice" and password == "Spring2026!"
    return fn


def test_spray_finds_credential_and_stops_for_that_user():
    """A user who hit on password A must not be tried again on B/C —
    that's the canonical spray semantic and reduces lockout exposure
    if the user was already at high badPwdCount."""
    record: list = []
    result = spray(
        dc_ip="dc", domain="corp", users=["alice", "bob"],
        passwords=["Welcome1", "Spring2026!", "Password1"],
        lockout_threshold=0,           # lockout disabled, use full list
        inter_attempt_seconds=0,
        try_credential_fn=_record_attempts(record),
    )
    assert len(result.hits) == 1
    assert result.hits[0].username == "alice"
    assert result.hits[0].password == "Spring2026!"
    # alice attempts: Welcome1 (no), Spring2026! (yes) — then no more
    alice_attempts = [(u, p) for u, p in record if u == "alice"]
    assert len(alice_attempts) == 2


def test_spray_iterates_passwords_outer_users_inner():
    """Canonical order: every user gets password A before anyone gets
    password B. A regression to inner-passwords would burn a single
    user through the whole list back-to-back, hitting lockout faster."""
    record: list = []
    spray(
        dc_ip="dc", domain="corp",
        users=["a", "b"], passwords=["P1", "P2"],
        lockout_threshold=0, inter_attempt_seconds=0,
        try_credential_fn=lambda *a: (record.append(a[2:4]), False)[1],
    )
    # Expected: (a, P1), (b, P1), (a, P2), (b, P2)
    assert record == [("a", "P1"), ("b", "P1"), ("a", "P2"), ("b", "P2")]


def test_spray_truncates_to_lockout_safe_slice():
    """7 passwords × threshold=5 → truncate to 4. No way to reach the
    lockout boundary without operator override of safe_password_count."""
    record: list = []
    spray(
        dc_ip="dc", domain="corp",
        users=["alice"],
        passwords=[f"P{i}" for i in range(7)],
        lockout_threshold=5,
        inter_attempt_seconds=0,
        try_credential_fn=lambda *a: (record.append(a[2:4]), False)[1],
    )
    assert len(record) == 4    # safe_password_count(5) = 4


def test_spray_threshold_zero_uses_full_list():
    """Lockout disabled → no truncation."""
    record: list = []
    spray(
        dc_ip="dc", domain="corp",
        users=["alice"],
        passwords=[f"P{i}" for i in range(20)],
        lockout_threshold=0,
        inter_attempt_seconds=0,
        try_credential_fn=lambda *a: (record.append(a[2:4]), False)[1],
    )
    assert len(record) == 20


def test_spray_calls_on_attempt_callback():
    """The CLI uses on_attempt to print live hits — ensure the hook
    fires for every attempt with the right boolean."""
    seen: list = []
    spray(
        dc_ip="dc", domain="corp",
        users=["alice"], passwords=["Welcome1", "Spring2026!"],
        lockout_threshold=0, inter_attempt_seconds=0,
        try_credential_fn=lambda dc, dom, u, p: p == "Spring2026!",
        on_attempt=lambda u, p, hit: seen.append((u, p, hit)),
    )
    assert seen == [("alice", "Welcome1", False),
                    ("alice", "Spring2026!", True)]


def test_spray_returns_result_dataclass():
    """Pin the result shape — exporter / JSON consumers will read it."""
    result = spray(
        dc_ip="dc", domain="corp", users=["alice"],
        passwords=["Welcome1"], lockout_threshold=0,
        inter_attempt_seconds=0,
        try_credential_fn=lambda *a: True,
    )
    assert isinstance(result, SprayResult)
    assert result.attempts == 1
    assert isinstance(result.hits[0], SprayHit)


def test_spray_empty_users_returns_empty_result():
    """Defensive: --spray run before user enumeration found anyone.
    Don't crash — return empty."""
    result = spray(
        dc_ip="dc", domain="corp", users=[], passwords=["x"],
        lockout_threshold=0, inter_attempt_seconds=0,
        try_credential_fn=lambda *a: False,
    )
    assert result.hits == []
    assert result.attempts == 0


@pytest.mark.parametrize("rate_seconds", [0, 0.001])
def test_spray_no_actual_sleep_at_zero_rate(rate_seconds, monkeypatch):
    """Rate=0 means no inter-attempt delay (test convenience). Confirm
    the orchestrator doesn't accidentally call sleep when it shouldn't."""
    sleep_calls: list = []
    import kerb_map.modules.spray as sp
    monkeypatch.setattr(sp.time, "sleep", lambda s: sleep_calls.append(s))
    spray(
        dc_ip="dc", domain="corp", users=["a"], passwords=["x"],
        lockout_threshold=0, inter_attempt_seconds=rate_seconds,
        try_credential_fn=lambda *a: False,
    )
    if rate_seconds == 0:
        assert sleep_calls == []
    else:
        assert sleep_calls == [rate_seconds]

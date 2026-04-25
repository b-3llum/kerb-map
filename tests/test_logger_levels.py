"""Logger verbosity + colour control (brief §3.1, §3.9).

Pin the level filter contract so a regression doesn't silently mute
WARN under --quiet or hide debug output under -v. The renderer is
tested via captured-stdout from rich rather than by intercepting
console.print — gives a closer-to-real check.
"""

from io import StringIO

import pytest
from rich.console import Console

from kerb_map.output.logger import (
    Level,
    Logger,
    register_console,
)


@pytest.fixture
def captured_console(monkeypatch):
    """Replace the module-level console with one that writes to a
    StringIO so we can assert on what got rendered. Restores after."""
    import kerb_map.output.logger as lg
    buf = StringIO()
    fake = Console(file=buf, force_terminal=False, no_color=True, width=200)
    monkeypatch.setattr(lg, "console", fake)
    register_console(fake)
    yield buf
    # Reset level so the next test isn't poisoned by the previous one's
    # configure() call (Logger is a singleton).
    Logger().set_level(Level.NORMAL)
    Logger().set_color(True)


# ────────────────────────────────────────── level filter ─


def test_normal_level_shows_info_and_warn(captured_console):
    Logger().set_level(Level.NORMAL)
    log = Logger()
    log.info("normal info")
    log.warn("normal warn")
    out = captured_console.getvalue()
    assert "normal info" in out
    assert "normal warn" in out


def test_quiet_suppresses_info_but_not_warn(captured_console):
    """--quiet for log capture: only WARN+ gets through."""
    Logger().set_level(Level.QUIET)
    log = Logger()
    log.info("hidden info")
    log.success("hidden success")
    log.section("hidden section")
    log.warn("visible warn")
    log.error("visible error")
    out = captured_console.getvalue()
    assert "hidden info"    not in out
    assert "hidden success" not in out
    assert "hidden section" not in out
    assert "visible warn"   in out
    assert "visible error"  in out


def test_normal_hides_debug_and_trace(captured_console):
    """Default level: debug() and trace() are silent."""
    Logger().set_level(Level.NORMAL)
    log = Logger()
    log.debug("hidden debug")
    log.trace("hidden trace")
    out = captured_console.getvalue()
    assert "hidden debug" not in out
    assert "hidden trace" not in out


def test_verbose_shows_debug_but_not_trace(captured_console):
    """-v shows operator-readable debug; raw LDAP filter (trace) stays
    hidden until -vv."""
    Logger().set_level(Level.VERBOSE)
    log = Logger()
    log.debug("visible debug")
    log.trace("hidden trace")
    out = captured_console.getvalue()
    assert "visible debug" in out
    assert "hidden trace"  not in out


def test_vverbose_shows_everything_including_trace(captured_console):
    """-vv: the wire view. Raw LDAP filters land here."""
    Logger().set_level(Level.VVERBOSE)
    log = Logger()
    log.info("info")
    log.debug("debug")
    log.trace("trace")
    out = captured_console.getvalue()
    assert "info"  in out
    assert "debug" in out
    assert "trace" in out


# ────────────────────────────────────────── predicates ─


def test_is_trace_true_only_at_vvverbose():
    """Hot-path callers (ldap_client.query) check is_trace() before
    building the f-string — pin the boundary."""
    log = Logger()
    log.set_level(Level.NORMAL)
    assert log.is_trace() is False
    log.set_level(Level.VERBOSE)
    assert log.is_trace() is False
    log.set_level(Level.VVERBOSE)
    assert log.is_trace() is True


def test_is_verbose_true_at_v_and_vv():
    log = Logger()
    log.set_level(Level.NORMAL)
    assert log.is_verbose() is False
    log.set_level(Level.VERBOSE)
    assert log.is_verbose() is True
    log.set_level(Level.VVERBOSE)
    assert log.is_verbose() is True


def test_is_quiet_only_true_at_quiet():
    log = Logger()
    log.set_level(Level.QUIET)
    assert log.is_quiet() is True
    log.set_level(Level.NORMAL)
    assert log.is_quiet() is False


# ────────────────────────────────────────── singleton state ─


def test_logger_is_singleton():
    """Modules import their own Logger() — must all share state so
    .configure() in cli.py reaches them."""
    a = Logger()
    b = Logger()
    assert a is b
    a.set_level(Level.VERBOSE)
    assert b.is_verbose()


def test_configure_sets_both_level_and_color(captured_console):
    Logger().configure(level=Level.VVERBOSE, color=False)
    assert Logger().is_trace()
    # no_color flag flipped on the fake console too (it was registered
    # in the fixture).
    import kerb_map.output.logger as lg
    assert lg.console.no_color is True


# ────────────────────────────────────────── colour control ─


def test_set_color_disabled_flips_no_color_on_all_known_consoles():
    """Multiple modules own their own Console — register_console adds
    them to the registry so --no-color reaches all of them. Without
    this, ldap_client / reporter would still emit ANSI escapes."""
    extra = Console(file=StringIO(), force_terminal=False, no_color=False)
    register_console(extra)
    Logger().set_color(False)
    assert extra.no_color is True
    Logger().set_color(True)
    assert extra.no_color is False


def test_register_console_is_idempotent():
    """Calling register_console twice with the same Console doesn't
    duplicate the entry — important because module-level register
    calls run on every import."""
    import kerb_map.output.logger as lg
    c = Console(file=StringIO())
    register_console(c)
    before = len(lg._known_consoles)
    register_console(c)
    after = len(lg._known_consoles)
    assert before == after


# ────────────────────────────────────────── always-on warn ─


def test_warn_visible_at_every_level(captured_console):
    """Brief §3.1 explicit guarantee: --quiet still shows WARN+. A
    regression here would silently break log-capture workflows."""
    log = Logger()
    for level in (Level.QUIET, Level.NORMAL, Level.VERBOSE, Level.VVERBOSE):
        captured_console.truncate(0)
        captured_console.seek(0)
        log.set_level(level)
        log.warn(f"warn at {level.name}")
        log.error(f"error at {level.name}")
        log.critical(f"critical at {level.name}")
        out = captured_console.getvalue()
        assert f"warn at {level.name}"     in out
        assert f"error at {level.name}"    in out
        assert f"critical at {level.name}" in out

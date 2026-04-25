"""
§1.5 — secret resolution hygiene.

Pins the contract that passwords/hashes can come from --password-env,
--password-stdin, an interactive prompt (when -p is given without a
value), or as a literal -p argument — and that conflicting sources are
rejected rather than silently overriding one another.

Manual ps-aux verification on a real lab host is the brief's acceptance
criterion; that step is skipped here because the lab is not up.
"""

import io
import sys

import pytest

from kerb_map.cli import PROMPT_SENTINEL, resolve_secret


def test_no_source_returns_none():
    assert resolve_secret(None, None, False, label="password") is None


def test_literal_argument_is_returned_verbatim():
    assert resolve_secret("Password123", None, False, label="password") == "Password123"


def test_env_var_is_read(monkeypatch):
    monkeypatch.setenv("MY_PW", "from-env")
    assert resolve_secret(None, "MY_PW", False, label="password") == "from-env"


def test_missing_env_var_exits(monkeypatch, capsys):
    monkeypatch.delenv("DOES_NOT_EXIST", raising=False)
    with pytest.raises(SystemExit) as ei:
        resolve_secret(None, "DOES_NOT_EXIST", False, label="password")
    assert ei.value.code == 1


def test_stdin_strips_trailing_newline(monkeypatch):
    monkeypatch.setattr("sys.stdin", io.StringIO("from-stdin\n"))
    assert resolve_secret(None, None, True, label="password") == "from-stdin"


def test_stdin_preserves_internal_whitespace(monkeypatch):
    # Real passwords may have spaces; only the trailing CR/LF should be removed.
    monkeypatch.setattr("sys.stdin", io.StringIO("a b  c\r\n"))
    assert resolve_secret(None, None, True, label="password") == "a b  c"


def test_empty_stdin_exits(monkeypatch):
    monkeypatch.setattr("sys.stdin", io.StringIO(""))
    with pytest.raises(SystemExit):
        resolve_secret(None, None, True, label="password")


def test_prompt_sentinel_calls_getpass(monkeypatch):
    called = {}

    def fake_getpass(prompt):
        called["prompt"] = prompt
        return "typed-by-user"

    monkeypatch.setattr("getpass.getpass", fake_getpass)
    monkeypatch.setattr("kerb_map.cli.getpass.getpass", fake_getpass)

    val = resolve_secret(PROMPT_SENTINEL, None, False, label="password")
    assert val == "typed-by-user"
    assert called["prompt"].lower().startswith("password")


def test_multiple_sources_rejected():
    with pytest.raises(SystemExit):
        resolve_secret("literal", "ENV", False, label="password")
    with pytest.raises(SystemExit):
        resolve_secret(None, "ENV", True, label="password")
    with pytest.raises(SystemExit):
        resolve_secret("literal", None, True, label="password")


def test_argparse_p_without_value_yields_sentinel():
    """argparse: `-p` (no value) should resolve to PROMPT_SENTINEL, not None."""
    from kerb_map.cli import build_parser
    args = build_parser().parse_args(
        ["-d", "corp.local", "-dc", "10.0.0.1", "-u", "jsmith", "-p"]
    )
    assert args.password == PROMPT_SENTINEL


def test_argparse_p_with_value_passes_through():
    from kerb_map.cli import build_parser
    args = build_parser().parse_args(
        ["-d", "corp.local", "-dc", "10.0.0.1", "-u", "jsmith", "-p", "secret"]
    )
    assert args.password == "secret"


def test_argparse_password_stdin_flag_default_false():
    from kerb_map.cli import build_parser
    args = build_parser().parse_args(
        ["-d", "corp.local", "-dc", "10.0.0.1", "-u", "jsmith"]
    )
    assert args.password_stdin is False
    assert args.password_env is None

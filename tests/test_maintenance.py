"""Self-update plumbing (brief §3.6).

Each helper is exercised against a real temp git repo (not just a
subprocess mock) so we cover actual git semantics — porcelain output,
detached HEAD, fast-forward refusal on diverged branches, etc. These
are the edge cases the legacy ``--update`` got wrong, so the test
must hit them with the real tool.
"""

import os
import shutil
import subprocess
from pathlib import Path

import pytest

from kerb_map import maintenance as mx

# ────────────────────────────────────────── fixtures ─


def _git(repo: Path, *args: str) -> str:
    """Run a git command and return stdout. Raises on non-zero so a
    setup failure surfaces immediately."""
    r = subprocess.run(
        ["git", *args], cwd=str(repo),
        capture_output=True, text=True, check=True,
    )
    return r.stdout


def _make_commit(repo: Path, *, msg: str, content: str | None = None) -> str:
    """Touch README, commit, return short sha. Content defaults to msg
    so each call produces a real diff (git refuses to commit when
    nothing changed)."""
    (repo / "README").write_text(content if content is not None else msg)
    _git(repo, "add", "README")
    _git(repo, "-c", "user.name=test", "-c", "user.email=t@t",
         "-c", "commit.gpgsign=false",
         "commit", "-m", msg)
    return _git(repo, "rev-parse", "--short", "HEAD").strip()


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    """Bare-bones git repo on a 'main' branch with one initial commit."""
    if not shutil.which("git"):
        pytest.skip("git not available")
    r = tmp_path / "repo"
    r.mkdir()
    _git(r, "init", "-b", "main")
    # Quiet the auto-gpg-sign / commit hooks if a host config has them.
    env = os.environ.copy()
    env["GIT_CONFIG_NOSYSTEM"] = "1"
    _make_commit(r, msg="initial")
    return r


@pytest.fixture
def repo_with_remote(tmp_path: Path):
    """Local repo + remote so fetch / pull / log_range have something
    to actually exchange. Remote starts one commit ahead so fetch
    + pull_ff_only have something to apply."""
    if not shutil.which("git"):
        pytest.skip("git not available")
    remote = tmp_path / "remote.git"
    _git(tmp_path, "init", "--bare", "-b", "main", str(remote))

    local = tmp_path / "local"
    _git(tmp_path, "clone", str(remote), str(local))
    _make_commit(local, msg="initial")
    _git(local, "push", "-u", "origin", "main")

    # Build a separate clone, push an extra commit so the first clone's
    # main is one behind origin/main.
    other = tmp_path / "other"
    _git(tmp_path, "clone", str(remote), str(other))
    _make_commit(other, msg="upstream change", content="changed")
    _git(other, "push", "origin", "main")

    return local


# ────────────────────────────────────────── precheck ─


def test_clean_repo_is_clean(repo):
    assert mx.is_clean(repo) is True


def test_uncommitted_change_marks_dirty(repo):
    """The headline §3.6 guard: an operator with WIP must not have
    their changes silently merged or stomped by `git pull`."""
    (repo / "README").write_text("dirty edit")
    assert mx.is_clean(repo) is False


def test_untracked_file_marks_dirty(repo):
    """Brand-new file (not yet tracked) must also count as dirty —
    `git pull` won't blow it away but the operator might forget about
    it; better to refuse and prompt."""
    (repo / "scratch.py").write_text("# notes")
    assert mx.is_clean(repo) is False


def test_branch_head_is_not_detached(repo):
    assert mx.is_detached(repo) is False


def test_checkout_to_sha_marks_detached(repo):
    sha = _git(repo, "rev-parse", "HEAD").strip()
    _git(repo, "checkout", sha)
    assert mx.is_detached(repo) is True


# ────────────────────────────────────────── inspection ─


def test_current_commit_returns_short_sha(repo):
    out = mx.current_commit(repo)
    # Short SHAs are 7+ hex chars.
    assert len(out) >= 7
    assert all(c in "0123456789abcdef" for c in out)


def test_log_range_empty_when_same_commit(repo):
    sha = mx.current_commit(repo)
    assert mx.log_range(repo, sha, sha) == []


def test_log_range_returns_one_line_per_commit(repo):
    a = mx.current_commit(repo)
    _make_commit(repo, msg="second")
    _make_commit(repo, msg="third")
    b = mx.current_commit(repo)
    lines = mx.log_range(repo, a, b)
    assert len(lines) == 2
    # Subjects appear; --no-decorate keeps it stable.
    assert any("second" in line for line in lines)
    assert any("third"  in line for line in lines)


# ────────────────────────────────────────── mutation ─


def test_fetch_succeeds_with_remote(repo_with_remote):
    """fetch() is the prerequisite for everything else — it must not
    raise on a normal repo. (No assertion on output; --tags is silent
    when nothing changes.)"""
    mx.fetch(repo_with_remote)


def test_pull_ff_only_advances_to_remote(repo_with_remote):
    """The headline operator workflow: clean tree, attached HEAD,
    fetch + pull_ff_only → working tree at origin/main."""
    mx.fetch(repo_with_remote)
    before = mx.current_commit(repo_with_remote)
    mx.pull_ff_only(repo_with_remote)
    after  = mx.current_commit(repo_with_remote)
    assert before != after


def test_pull_ff_only_refuses_diverged_branch(repo_with_remote):
    """The whole point of --ff-only: when local has diverged, refuse
    rather than create a merge commit. Operators expect a clean update."""
    # Diverge: commit locally without pulling first.
    _make_commit(repo_with_remote, msg="local-only", content="local")
    mx.fetch(repo_with_remote)
    with pytest.raises(mx.UpdateError):
        mx.pull_ff_only(repo_with_remote)


def test_checkout_tag_pins_to_release(repo):
    """--update --tag v1.2.0 — tag a commit, checkout the tag, verify
    HEAD is at that commit (and now in detached state, which is the
    expected post-tag-checkout shape)."""
    _make_commit(repo, msg="release candidate")
    target_sha = _git(repo, "rev-parse", "HEAD").strip()
    _git(repo, "tag", "v0.0.1")
    _make_commit(repo, msg="post-release")

    mx.checkout(repo, "v0.0.1")
    assert _git(repo, "rev-parse", "HEAD").strip() == target_sha
    assert mx.is_detached(repo) is True


def test_checkout_unknown_ref_raises(repo):
    """Defensive: typo or stale tag name surfaces as UpdateError, not
    a silent no-op."""
    with pytest.raises(mx.UpdateError):
        mx.checkout(repo, "v99.99.99-does-not-exist")


# ────────────────────────────────────────── error reporting ─


def test_update_error_includes_git_stderr(tmp_path):
    """When a git command fails, the operator needs to see *why* —
    not just 'git failed'. Pin that the message carries the underlying
    git output."""
    not_a_repo = tmp_path / "not-a-repo"
    not_a_repo.mkdir()
    with pytest.raises(mx.UpdateError) as exc:
        mx.is_clean(not_a_repo)
    assert "git status" in str(exc.value) or "not a git" in str(exc.value).lower()

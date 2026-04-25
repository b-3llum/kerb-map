"""
The execution engine.

Walks the playbook in order, evaluating each play's ``when`` against
the engagement (and per-finding for ``per: finding`` plays), running
the command, and applying capture rules to fold loot back into the
engagement state.

Concurrency model: sequential within a chain, parallel-safe across
engagements (the whole module is purely functional given an Engagement
instance — operators can run multiple chains in subprocess workers if
they want). Most AD attack chains *are* causally sequential — you
can't crack-spray-DCSync in parallel — so we don't try to be clever.

Safety:
  - Dry-run mode (``Engagement.dry_run = True``): every play is
    rendered, condition-evaluated, and recorded in the history, but
    the subprocess is never spawned. Loot capture is skipped.
  - ``requires_aggressive`` plays are skipped unless ``Runner(..,
    aggressive=True)`` is set.
  - Per-play timeout (default 600s) enforced via subprocess.run.
"""

from __future__ import annotations

import re
import shlex
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from kerb_chain.engagement import Credential, Engagement, OwnedHost, PlayRecord
from kerb_chain.playbook import CaptureRule, Play, Playbook, evaluate_condition


class Runner:
    def __init__(
        self,
        playbook:    Playbook,
        engagement:  Engagement,
        *,
        aggressive:  bool = False,
        verbose:     bool = True,
    ):
        self.playbook = playbook
        self.engagement = engagement
        self.aggressive = aggressive
        self.verbose = verbose
        self._enqueued: set[str] = set()      # plays already queued for this run

    # ------------------------------------------------------------------ #
    #  Top-level entry                                                   #
    # ------------------------------------------------------------------ #

    def run(self) -> list[PlayRecord]:
        # Start with the playbook's natural order; on_success edges add
        # to the queue as plays succeed.
        queue: list[tuple[Play, dict | None]] = [
            (play, None) for play in self.playbook.plays
        ]
        i = 0
        while i < len(queue):
            play, finding = queue[i]
            i += 1
            self._run_one(play, finding, queue)
        return self.engagement.history

    # ------------------------------------------------------------------ #
    #  Per-play execution                                                #
    # ------------------------------------------------------------------ #

    def _run_one(
        self,
        play:    Play,
        finding: dict | None,
        queue:   list[tuple[Play, dict | None]],
    ) -> None:
        if play.requires_aggressive and not self.aggressive:
            self._record(play, finding, skipped="requires --aggressive")
            return

        if play.per == "finding" and finding is None:
            # Expand into one execution per matching finding.
            for f in self.engagement.findings:
                if evaluate_condition(play.when, finding=f, engagement=self.engagement):
                    queue.append((play, f))
            return

        if not evaluate_condition(play.when, finding=finding, engagement=self.engagement):
            self._record(play, finding, skipped="condition false")
            return

        argv = self._render_command(play.command, finding)
        self._log(f"\n[+] {play.name}  →  {' '.join(argv)}")

        if self.engagement.dry_run:
            self._record(play, finding, command=argv, skipped="dry-run")
            return

        started = datetime.now(timezone.utc).isoformat(timespec="seconds")
        try:
            proc = subprocess.run(  # noqa: S603 — operator-controlled commands
                argv,
                capture_output=True,
                text=True,
                timeout=play.timeout,
            )
        except subprocess.TimeoutExpired as e:
            self._record(
                play, finding, command=argv,
                skipped=f"timeout after {play.timeout}s",
                stdout=(e.stdout or "") if isinstance(e.stdout, str) else "",
                stderr=(e.stderr or "") if isinstance(e.stderr, str) else "",
            )
            return
        except FileNotFoundError as e:
            self._record(play, finding, command=argv,
                         skipped=f"command not found: {e.filename}")
            return

        loot_added = self._apply_capture(play.capture, proc.stdout, proc.stderr, finding)

        record = PlayRecord(
            play=play.name,
            command=argv,
            started_at=started,
            finished_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
            exit_code=proc.returncode,
            stdout=proc.stdout[-4000:],  # cap for journal size
            stderr=proc.stderr[-2000:],
            loot_added=loot_added,
        )
        self.engagement.history.append(record)

        if proc.returncode == 0:
            for follow in play.on_success:
                next_play = self.playbook.by_name(follow)
                if next_play and next_play.name not in self._enqueued:
                    self._enqueued.add(next_play.name)
                    queue.append((next_play, finding))

    # ------------------------------------------------------------------ #
    #  Capture                                                           #
    # ------------------------------------------------------------------ #

    def _apply_capture(
        self,
        rule:    CaptureRule,
        stdout:  str,
        stderr:  str,
        finding: dict | None,
    ) -> dict[str, int]:
        added = {"credentials": 0, "files": 0, "owned_hosts": 0}

        if rule.stdout_to_file:
            target = Path(self.engagement.render(rule.stdout_to_file, finding=finding))
            if not target.is_absolute():
                target = self.engagement.run_dir / target
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(stdout)
            self.engagement.loot.files[target.name] = target
            added["files"] += 1

        if rule.cred_regex:
            for m in re.finditer(rule.cred_regex, stdout, flags=re.MULTILINE):
                user = m.groupdict().get("user")
                pwd  = m.groupdict().get("pass")
                if user and pwd:
                    self.engagement.loot.credentials.append(Credential(
                        username=user,
                        domain=self.engagement.domain,
                        password=pwd,
                        source="capture:" + (finding or {}).get("attack", "play"),
                    ))
                    added["credentials"] += 1

        if rule.cred_hash_regex:
            for m in re.finditer(rule.cred_hash_regex, stdout, flags=re.MULTILINE):
                user = m.groupdict().get("user")
                h    = m.groupdict().get("hash")
                if user and h:
                    self.engagement.loot.credentials.append(Credential(
                        username=user,
                        domain=self.engagement.domain,
                        nt_hash=h,
                        source="capture:" + (finding or {}).get("attack", "play"),
                    ))
                    added["credentials"] += 1

        if rule.files_glob:
            for f in sorted(self.engagement.run_dir.glob(rule.files_glob)):
                self.engagement.loot.files.setdefault(f.name, f)
                added["files"] += 1

        if rule.owned_marker and rule.owned_marker in stdout:
            host_name = self.engagement.render(
                rule.owned_host or "{{finding.target}}",
                finding=finding,
            ) or "unknown"
            self.engagement.loot.owned_hosts.append(OwnedHost(
                name=host_name,
                via_play=(finding or {}).get("attack", "play"),
            ))
            added["owned_hosts"] += 1

        return added

    # ------------------------------------------------------------------ #
    #  Helpers                                                           #
    # ------------------------------------------------------------------ #

    def _render_command(self, command: list[str] | str, finding: dict | None) -> list[str]:
        if isinstance(command, str):
            rendered = self.engagement.render(command, finding=finding)
            return shlex.split(rendered)
        return [self.engagement.render(arg, finding=finding) for arg in command]

    def _record(self, play: Play, finding: dict | None, **kwargs) -> None:
        rec = PlayRecord(
            play=play.name,
            command=kwargs.get("command", []),
            started_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
            finished_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
            exit_code=kwargs.get("exit_code"),
            stdout=kwargs.get("stdout", ""),
            stderr=kwargs.get("stderr", ""),
            skipped=kwargs.get("skipped"),
        )
        self.engagement.history.append(rec)
        if self.verbose and rec.skipped:
            self._log(f"    [-] skipped: {rec.skipped}")

    def _log(self, msg: str) -> None:
        if self.verbose:
            print(msg)

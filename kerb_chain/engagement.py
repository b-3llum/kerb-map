"""
Engagement state — the in-memory graph kerb-chain walks.

An Engagement starts with whatever kerb-map already discovered
(findings, domain info, the operator's bind credential) and grows as
plays run: each play can deposit credentials, hashes, Kerberos
tickets, owned hosts, and certificates. Subsequent plays consult the
state to decide what to run next, and the placeholder substitution in
play command templates pulls from here too.

The state is intentionally a plain Python dataclass tree rather than a
graph database — kerb-chain's MVP target is a single-engagement
operator session, not a multi-team C2. If we later need
cross-engagement queries (or a UI on top), pivoting to Neo4j /
memgraph is one adapter.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

# ────────────────────────────────────────────────────────────────────── #
#  Loot                                                                  #
# ────────────────────────────────────────────────────────────────────── #


@dataclass
class Credential:
    """A username + secret + the play that produced it. Either ``password``
    or ``nt_hash`` is set; never both blank."""

    username:  str
    domain:    str
    password:  str | None = None
    nt_hash:   str | None = None
    source:    str = "operator"          # play name, or 'operator' for the seed cred
    obtained_at: str = ""

    def __post_init__(self):
        if not self.obtained_at:
            self.obtained_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
        if not (self.password or self.nt_hash):
            raise ValueError("Credential needs at least one of password / nt_hash")

    @property
    def upn(self) -> str:
        return f"{self.username}@{self.domain}"


@dataclass
class Ticket:
    """A Kerberos TGT or service ticket on disk (ccache or .kirbi)."""

    principal: str
    path:      Path
    kind:      str = "tgt"               # 'tgt' or 'service'
    spn:       str | None = None         # for service tickets
    source:    str = "operator"
    obtained_at: str = ""

    def __post_init__(self):
        if not self.obtained_at:
            self.obtained_at = datetime.now(timezone.utc).isoformat(timespec="seconds")


@dataclass
class Certificate:
    """A captured PFX + (optional) password — typically from ESC1/4/8 or
    Shadow Credentials chains."""

    subject:   str
    pfx_path:  Path
    pfx_pass:  str | None = None
    source:    str = ""
    obtained_at: str = ""

    def __post_init__(self):
        if not self.obtained_at:
            self.obtained_at = datetime.now(timezone.utc).isoformat(timespec="seconds")


@dataclass
class OwnedHost:
    """A host kerb-chain has popped a session on (or already had access
    to). 'session' is whatever the play produced — ssh, smbexec, wmiexec
    output handle, etc."""

    name:       str
    ip:         str | None = None
    via_play:   str = ""
    obtained_at: str = ""
    notes:      str = ""

    def __post_init__(self):
        if not self.obtained_at:
            self.obtained_at = datetime.now(timezone.utc).isoformat(timespec="seconds")


@dataclass
class Loot:
    """All collected loot in one place. Plays read and append; the
    Engagement passes a reference to each play's command-template
    renderer, so any of these can be referenced as ``{{loot.foo}}``."""

    credentials: list[Credential]   = field(default_factory=list)
    tickets:     list[Ticket]       = field(default_factory=list)
    certificates: list[Certificate] = field(default_factory=list)
    owned_hosts: list[OwnedHost]    = field(default_factory=list)
    files:       dict[str, Path]    = field(default_factory=dict)

    def has_creds_for(self, username: str) -> bool:
        return any(c.username.lower() == username.lower() for c in self.credentials)

    def best_cred(self, username: str | None = None) -> Credential | None:
        """The newest credential, optionally filtered by username.
        Used by the default placeholder ``{{operator}}`` in playbooks."""
        candidates = self.credentials
        if username:
            candidates = [c for c in candidates if c.username.lower() == username.lower()]
        return candidates[-1] if candidates else None


# ────────────────────────────────────────────────────────────────────── #
#  Engagement                                                            #
# ────────────────────────────────────────────────────────────────────── #


@dataclass
class PlayRecord:
    """One play execution — what ran, when, what came out."""

    play:       str
    command:    list[str]
    started_at: str
    finished_at: str = ""
    exit_code:  int | None = None
    stdout:     str = ""
    stderr:     str = ""
    loot_added: dict[str, int] = field(default_factory=dict)
    skipped:    str | None = None        # reason if not executed


@dataclass
class Engagement:
    """The full state kerb-chain operates on. Construct with
    ``Engagement.from_findings(...)`` rather than the bare constructor;
    that ensures sensible defaults for run_dir, operator cred, dry-run."""

    findings:   list[dict]
    domain:     str
    dc_ip:      str
    base_dn:    str
    domain_sid: str | None
    operator:   Credential | None       # the bind credential kerb-map used
    loot:       Loot                  = field(default_factory=Loot)
    history:    list[PlayRecord]      = field(default_factory=list)
    run_dir:    Path                  = field(default_factory=Path.cwd)
    dry_run:    bool                  = False

    @classmethod
    def from_findings(
        cls,
        findings: list[dict],
        *,
        domain:    str = "",
        dc_ip:     str = "",
        base_dn:   str = "",
        domain_sid: str | None = None,
        operator_cred: Credential | None = None,
        run_dir:   str | Path | None = None,
        dry_run:   bool = False,
    ) -> Engagement:
        # When the findings carry a meta block (the kerb-map JSON shape),
        # use it as the source of truth for domain/dc_ip — otherwise the
        # operator must pass them explicitly.
        meta = {}
        if findings and isinstance(findings, list) and findings[0].get("__meta__"):
            meta = findings[0]["__meta__"]

        domain  = domain or meta.get("domain", "")
        dc_ip   = dc_ip or meta.get("dc_ip", "")
        base_dn = base_dn or meta.get("base_dn", "")
        domain_sid = domain_sid or meta.get("domain_sid")

        # Pull domain_sid out of the first finding that has one, if
        # we still don't know it — DCSync / Shadow Creds findings carry it.
        if not domain_sid:
            for f in findings:
                ds = (f.get("data") or {}).get("domain_sid")
                if ds:
                    domain_sid = ds
                    break

        out_dir = Path(run_dir or _default_run_dir(domain))
        out_dir.mkdir(parents=True, exist_ok=True)

        loot = Loot()
        if operator_cred:
            loot.credentials.append(operator_cred)

        return cls(
            findings=findings,
            domain=domain,
            dc_ip=dc_ip,
            base_dn=base_dn,
            domain_sid=domain_sid,
            operator=operator_cred,
            loot=loot,
            run_dir=out_dir,
            dry_run=dry_run,
        )

    # ------------------------------------------------------------------ #
    #  Placeholder substitution                                          #
    # ------------------------------------------------------------------ #

    def render(self, template: str, *, finding: dict | None = None) -> str:
        """Substitute ``{{domain}}``, ``{{dc_ip}}``, ``{{operator_user}}``,
        ``{{operator_pass}}``, ``{{run_dir}}``, ``{{finding.target}}``,
        ``{{finding.data.X}}``, etc. into ``template``.

        Deliberately a tiny custom resolver rather than Jinja — playbooks
        should be auditable and a sandbox-friendly subset is enough.
        Unknown placeholders are left as-is so the operator notices.
        """
        ctx = self._render_context(finding)
        out = template
        # Two passes so that {{a}} can resolve to "{{b}}" once and we still
        # try {{b}} the second time. Cap at a few iterations to stop cycles.
        for _ in range(4):
            new = out
            for key, value in ctx.items():
                new = new.replace("{{" + key + "}}", str(value))
            if new == out:
                break
            out = new
        return out

    def _render_context(self, finding: dict | None) -> dict[str, object]:
        op = self.loot.best_cred() or self.operator
        ctx: dict[str, object] = {
            "domain":         self.domain,
            "dc_ip":          self.dc_ip,
            "base_dn":        self.base_dn,
            "domain_sid":     self.domain_sid or "",
            "run_dir":        str(self.run_dir),
            "operator_user":  op.username if op else "",
            "operator_pass":  op.password if op else "",
            "operator_hash":  op.nt_hash if op else "",
        }
        if finding:
            ctx["finding.target"]   = finding.get("target", "")
            ctx["finding.attack"]   = finding.get("attack", "")
            ctx["finding.severity"] = finding.get("severity", "")
            for k, v in (finding.get("data") or {}).items():
                ctx[f"finding.data.{k}"] = v
        return ctx

    # ------------------------------------------------------------------ #
    #  Persistence                                                       #
    # ------------------------------------------------------------------ #

    def write_journal(self) -> Path:
        """Write the run history + loot to ``run_dir/journal.json``.
        Caller decides when (typically end-of-run, but per-play is fine
        for long sessions where you want progress on disk)."""
        out = self.run_dir / "journal.json"
        payload = {
            "domain":     self.domain,
            "dc_ip":      self.dc_ip,
            "domain_sid": self.domain_sid,
            "loot": {
                "credentials":  [_dataclass_dict(c) for c in self.loot.credentials],
                "tickets":      [_dataclass_dict(t) for t in self.loot.tickets],
                "certificates": [_dataclass_dict(c) for c in self.loot.certificates],
                "owned_hosts":  [_dataclass_dict(h) for h in self.loot.owned_hosts],
                "files":        {k: str(v) for k, v in self.loot.files.items()},
            },
            "history": [_dataclass_dict(p) for p in self.history],
        }
        out.write_text(json.dumps(payload, indent=2, default=str))
        return out


def _default_run_dir(domain: str) -> Path:
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    domain_part = domain.replace(".", "_") if domain else "engagement"
    base = Path(os.environ.get("KERB_CHAIN_HOME") or (Path.home() / ".kerb-chain"))
    return base / "runs" / f"{domain_part}_{ts}"


def _dataclass_dict(obj) -> dict:
    """Best-effort dataclass → dict that handles Path and the dataclasses
    we actually use. Avoids importing dataclasses.asdict (which complains
    about non-dataclass fields the operator might add)."""
    out: dict[str, object] = {}
    for k, v in vars(obj).items():
        if isinstance(v, Path):
            v = str(v)
        out[k] = v
    return out

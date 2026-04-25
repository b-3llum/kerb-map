"""
Playbook DSL — small, deterministic, auditable.

A playbook is a YAML file with a ``name`` and a list of ``plays``. Each
play has:

  name:        Free-form identifier shown in the runner's output.
  description: Human note for operators reviewing the playbook.
  when:        A simple condition expression (see ``conditions.py``)
               — the play runs once per *finding* that matches.
  command:     Either a list of argv, or a shell string. Placeholders
               (``{{domain}}``, ``{{finding.target}}``, etc.) are
               substituted from the Engagement context just before exec.
  capture:     Rules for parsing stdout/stderr/files into Loot.
  on_success:  List of follow-up play names to enqueue.
  requires_aggressive: Bool gate — operator passes ``--aggressive`` to
               kerb-chain to opt in to noisy plays (network spray,
               authentication coercion, anything that creates AD objects).
  category:    Free-form tag, used by ``--only-category`` filters.

The DSL deliberately has *no* loops, no variable assignment, no
sub-templating beyond placeholder substitution. Anything more complex
should be a real Python module wired in alongside.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


@dataclass
class CaptureRule:
    """How a play teaches the runner to extract loot from its output.

    All fields are optional — a play with no capture rules just runs
    for side effects.
    """

    # Save stdout to a file in run_dir. Useful as a checkpoint or as
    # input to a follow-up play.
    stdout_to_file: str | None = None

    # Regex applied per-line over stdout; each match produces a
    # Credential whose username/password come from the named groups.
    cred_regex:        str | None = None    # must define groups 'user' and 'pass'
    cred_hash_regex:   str | None = None    # must define groups 'user' and 'hash'

    # Glob pattern under run_dir; every match becomes a Path entry in
    # loot.files keyed by the basename.
    files_glob: str | None = None

    # Mark a host as owned when stdout contains this substring.
    owned_marker: str | None = None
    owned_host:   str | None = None         # the host to record (template-rendered)


@dataclass
class Play:
    name:                str
    command:             list[str] | str    # argv list (preferred) or shell string
    description:         str = ""
    when:                str = ""           # empty = always
    per:                 str = "engagement"  # 'engagement' or 'finding'
    capture:             CaptureRule = field(default_factory=CaptureRule)
    on_success:          list[str] = field(default_factory=list)
    requires_aggressive: bool = False
    category:            str = "enumeration"
    timeout:             int = 600          # seconds


@dataclass
class Playbook:
    name:        str
    plays:       list[Play]
    description: str = ""
    path:        Path | None = None

    def by_name(self, name: str) -> Play | None:
        for p in self.plays:
            if p.name == name:
                return p
        return None

    @classmethod
    def from_file(cls, path: str | Path) -> Playbook:
        p = Path(path)
        data = yaml.safe_load(p.read_text())
        if not isinstance(data, dict):
            raise ValueError(f"{p}: top-level must be a mapping")

        raw_plays = data.get("plays") or []
        plays: list[Play] = []
        for i, item in enumerate(raw_plays):
            if "name" not in item:
                raise ValueError(f"{p}: play #{i} missing 'name'")
            if "command" not in item:
                raise ValueError(f"{p}: play '{item['name']}' missing 'command'")
            cap = CaptureRule(**(item.get("capture") or {}))
            plays.append(Play(
                name=item["name"],
                description=item.get("description", ""),
                command=item["command"],
                when=item.get("when", ""),
                per=item.get("per", "engagement"),
                capture=cap,
                on_success=list(item.get("on_success", []) or []),
                requires_aggressive=bool(item.get("requires_aggressive", False)),
                category=item.get("category", "enumeration"),
                timeout=int(item.get("timeout", 600)),
            ))
        return cls(
            name=data.get("name", p.stem),
            description=data.get("description", ""),
            plays=plays,
            path=p,
        )


# ────────────────────────────────────────────────────────────────────── #
#  Condition language                                                    #
# ────────────────────────────────────────────────────────────────────── #


def evaluate_condition(expr: str, *, finding: dict | None, engagement: Any) -> bool:
    """A tiny, hand-rolled condition language. No eval(), no exec().

    Supported forms (all return bool, all are case-insensitive on the LHS
    where appropriate):

      ``finding.attack == 'Kerberoast'``
      ``finding.attack in ['DCSync (full)', 'DCSync (partial)']``
      ``finding.severity in ['CRITICAL', 'HIGH']``
      ``finding.data.encryption == 'RC4'``
      ``loot.has_credential``
      ``loot.has_credential_for finding.target``
      ``not loot.has_credential``

    Multiple clauses joined by ``and`` / ``or`` (left-associative, no
    parens). Empty expression evaluates to True.
    """
    if not expr or not expr.strip():
        return True

    # Split on `and`/`or` while remembering the operator order.
    tokens = _tokenise_logical(expr)
    if not tokens:
        return True

    # Evaluate the first clause, then fold subsequent ones with the
    # operator that preceded them.
    result = _eval_clause(tokens[0], finding=finding, engagement=engagement)
    i = 1
    while i + 1 < len(tokens):
        op = tokens[i].lower()
        clause = tokens[i + 1]
        rhs = _eval_clause(clause, finding=finding, engagement=engagement)
        result = (result and rhs) if op == "and" else (result or rhs)
        i += 2
    return result


def _tokenise_logical(expr: str) -> list[str]:
    """Split a condition string on the keywords ``and`` / ``or`` while
    keeping the operators as separate tokens. Quoted substrings are
    preserved verbatim so something like ``foo == 'a and b'`` doesn't
    get split on the inner ``and``."""
    out: list[str] = []
    buf: list[str] = []
    i, n = 0, len(expr)
    in_quote: str | None = None
    while i < n:
        c = expr[i]
        if in_quote:
            buf.append(c)
            if c == in_quote:
                in_quote = None
            i += 1
            continue
        if c in "'\"":
            in_quote = c
            buf.append(c)
            i += 1
            continue
        # Try to match `and `/`or ` boundaries with whitespace.
        rest = expr[i:].lstrip()
        if rest.lower().startswith("and ") and (not buf or buf[-1].isspace()):
            out.append("".join(buf).strip())
            out.append("and")
            buf = []
            i = expr.index(rest, i) + 3
            continue
        if rest.lower().startswith("or ") and (not buf or buf[-1].isspace()):
            out.append("".join(buf).strip())
            out.append("or")
            buf = []
            i = expr.index(rest, i) + 2
            continue
        buf.append(c)
        i += 1
    last = "".join(buf).strip()
    if last:
        out.append(last)
    return [t for t in out if t]


def _eval_clause(clause: str, *, finding: dict | None, engagement: Any) -> bool:
    c = clause.strip()
    if c.startswith("not "):
        return not _eval_clause(c[4:], finding=finding, engagement=engagement)

    # loot predicates
    if c == "loot.has_credential":
        return bool(engagement.loot.credentials)
    if c.startswith("loot.has_credential_for "):
        target_expr = c[len("loot.has_credential_for "):].strip()
        target = _resolve_value(target_expr, finding=finding, engagement=engagement)
        if not isinstance(target, str):
            return False
        return engagement.loot.has_creds_for(target)

    # comparisons: lhs == 'literal' | lhs in [...]
    if " == " in c:
        lhs, rhs = c.split(" == ", 1)
        return _resolve_value(lhs, finding=finding, engagement=engagement) == _parse_literal(rhs)
    if " != " in c:
        lhs, rhs = c.split(" != ", 1)
        return _resolve_value(lhs, finding=finding, engagement=engagement) != _parse_literal(rhs)
    if " in " in c:
        lhs, rhs = c.split(" in ", 1)
        rhs_val = _parse_literal(rhs)
        if not isinstance(rhs_val, (list, tuple, set)):
            return False
        return _resolve_value(lhs, finding=finding, engagement=engagement) in rhs_val

    # bare identifier — truthy resolution
    return bool(_resolve_value(c, finding=finding, engagement=engagement))


def _resolve_value(token: str, *, finding: dict | None, engagement: Any) -> Any:
    token = token.strip()
    if token.startswith("finding."):
        if finding is None:
            return None
        path = token.split(".")[1:]
        node: Any = finding
        for part in path:
            if isinstance(node, dict):
                node = node.get(part)
            else:
                return None
        return node
    if token.startswith("loot.credentials"):
        return engagement.loot.credentials
    return token  # treat as literal-ish


def _parse_literal(token: str) -> Any:
    t = token.strip()
    if (t.startswith("'") and t.endswith("'")) or (t.startswith('"') and t.endswith('"')):
        return t[1:-1]
    if t.startswith("[") and t.endswith("]"):
        # Naïve list parser — splits on commas, respects single quotes.
        body = t[1:-1].strip()
        if not body:
            return []
        parts: list[str] = []
        buf: list[str] = []
        in_q: str | None = None
        for ch in body:
            if in_q:
                buf.append(ch)
                if ch == in_q:
                    in_q = None
                continue
            if ch in "'\"":
                in_q = ch
                buf.append(ch)
                continue
            if ch == ",":
                parts.append("".join(buf).strip())
                buf = []
                continue
            buf.append(ch)
        if buf:
            parts.append("".join(buf).strip())
        return [_parse_literal(p) for p in parts]
    # numeric
    try:
        if "." in t:
            return float(t)
        return int(t)
    except ValueError:
        return t  # bare identifier

"""
Export writers.

  JSONExporter            — full data dump (lossless, machine-readable)
  BloodHoundLiteExporter  — kerb-map's custom JSON shape (replay only)
  CSVExporter             — one row per priority target (spreadsheet)
  MarkdownExporter        — full report — top priorities + per-section
                            findings + raw-evidence appendix
"""

import csv
import datetime
import json
from io import StringIO
from pathlib import Path
from typing import Any

from kerb_map.output.logger import Logger

log = Logger()


def _default(obj):
    """JSON serialiser for non-serialisable types."""
    if isinstance(obj, datetime.datetime):
        return obj.isoformat()
    if isinstance(obj, datetime.timedelta):
        return str(obj)
    if isinstance(obj, bytes):
        return obj.hex()
    return str(obj)


class JSONExporter:
    def export(self, data: dict[str, Any], path: str) -> None:
        out = Path(path)
        with out.open("w") as f:
            json.dump(data, f, indent=2, default=_default)
        log.success(f"JSON report written → {out.resolve()}")


class BloodHoundLiteExporter:
    """
    Writes a *custom* BloodHound-style JSON file — NOT ingestible into
    BloodHound CE, BloodHound 4.x, or BloodHound 5.x as-is.

    The output uses ``DOMAIN\\account`` strings as ObjectIdentifiers, which
    BloodHound CE rejects (it requires S-1-5-21-... domain SIDs). There
    are also no separate users/computers/groups/domains files, no edges,
    and the meta block is non-conformant. Treat this as kerb-map's own
    serialisation format for re-ingestion via ``--show-scan``; a real
    BH-CE-compatible exporter is tracked as the brief's §1.6 option (a).
    """

    def export(self, data: dict[str, Any], path: str) -> None:
        bh = {
            "meta": {
                "methods": 0,
                "type": "users",
                "count": 0,
                "version": 5,
            },
            "data": [],
        }

        nodes = []
        domain = data.get("meta", {}).get("domain", "UNKNOWN").upper()

        # Kerberoastable users
        for spn in data.get("spns", []):
            nodes.append({
                "ObjectIdentifier": f"{domain}\\{spn['account']}",
                "ObjectType": "User",
                "Properties": {
                    "name":          f"{spn['account'].upper()}@{domain}",
                    "kerberoastable": True,
                    "hasspn":        True,
                    "pwdlastset":    spn.get("password_age_days"),
                    "description":   spn.get("description", ""),
                },
                "Aces": [],
            })

        # AS-REP roastable users
        for user in data.get("asrep", []):
            nodes.append({
                "ObjectIdentifier": f"{domain}\\{user['account']}",
                "ObjectType": "User",
                "Properties": {
                    "name":            f"{user['account'].upper()}@{domain}",
                    "dontreqpreauth":  True,
                },
                "Aces": [],
            })

        # Unconstrained delegation computers
        delegations = data.get("delegations", {})
        for d in delegations.get("unconstrained", []):
            nodes.append({
                "ObjectIdentifier": f"{domain}\\{d['account']}",
                "ObjectType": "Computer",
                "Properties": {
                    "name":                    f"{d['account'].upper()}@{domain}",
                    "unconstraineddelegation":  True,
                    "dnshostname":             d.get("dns_name", ""),
                },
                "Aces": [],
            })

        # Constrained delegation
        for d in delegations.get("constrained", []):
            nodes.append({
                "ObjectIdentifier": f"{domain}\\{d['account']}",
                "ObjectType": "User",
                "Properties": {
                    "name":                f"{d['account'].upper()}@{domain}",
                    "allowedtodelegate":   d.get("allowed_to", []),
                    "trustedtoauth":       d.get("protocol_transition", False),
                },
                "Aces": [],
            })

        # RBCD targets
        for d in delegations.get("rbcd", []):
            nodes.append({
                "ObjectIdentifier": f"{domain}\\{d['target']}",
                "ObjectType": "Computer",
                "Properties": {
                    "name":        f"{d['target'].upper()}@{domain}",
                    "rbcd":        True,
                    "dnshostname": d.get("dns_name", ""),
                },
                "Aces": [],
            })

        # Hygiene findings — credential exposure
        hygiene = data.get("hygiene", {})
        for c in hygiene.get("credential_exposure", []):
            nodes.append({
                "ObjectIdentifier": f"{domain}\\{c['account']}",
                "ObjectType": "User",
                "Properties": {
                    "name":               f"{c['account'].upper()}@{domain}",
                    "credentialexposed":   True,
                    "exposurefield":       c.get("field", ""),
                    "admincount":          c.get("is_admin", False),
                },
                "Aces": [],
            })

        # Hygiene findings — SID History abuse
        for s in hygiene.get("sid_history", []):
            obj_type = "Computer" if s.get("is_computer") else "User"
            nodes.append({
                "ObjectIdentifier": f"{domain}\\{s['account']}",
                "ObjectType": obj_type,
                "Properties": {
                    "name":            f"{s['account'].upper()}@{domain}",
                    "sidhistory":      [s.get("sid_history_entry", "")],
                    "sidhistoryrisk":  s.get("risk", "MEDIUM"),
                },
                "Aces": [],
            })

        # Hygiene findings — service account hygiene issues
        for svc in hygiene.get("service_acct_hygiene", []):
            nodes.append({
                "ObjectIdentifier": f"{domain}\\{svc['account']}",
                "ObjectType": "User",
                "Properties": {
                    "name":              f"{svc['account'].upper()}@{domain}",
                    "hasspn":            True,
                    "passwordagedays":   svc.get("password_age_days"),
                    "pwdneverexpires":   svc.get("password_never_expires", False),
                    "hygienerisk":       svc.get("risk", "LOW"),
                },
                "Aces": [],
            })

        # Trust relationships
        for t in data.get("trusts", []):
            nodes.append({
                "ObjectIdentifier": f"{t.get('partner', t.get('trusted_domain', 'UNKNOWN')).upper()}",
                "ObjectType": "Domain",
                "Properties": {
                    "name":          t.get("partner", t.get("trusted_domain", "UNKNOWN")).upper(),
                    "trustdirection": t.get("direction", "Unknown"),
                    "sidfiltering":  t.get("sid_filtering", True),
                    "trustrisk":     t.get("risk", "MEDIUM"),
                },
                "Aces": [],
            })

        # Deduplicate nodes by ObjectIdentifier (keep first occurrence)
        seen = set()
        unique_nodes = []
        for node in nodes:
            oid = node["ObjectIdentifier"]
            if oid not in seen:
                seen.add(oid)
                unique_nodes.append(node)

        bh["data"]         = unique_nodes
        bh["meta"]["count"]= len(unique_nodes)

        out = Path(path)
        with out.open("w") as f:
            json.dump(bh, f, indent=2, default=_default)

        log.success(
            f"BloodHound-Lite JSON written → {out.resolve()} "
            f"({len(unique_nodes)} nodes — note: not BloodHound-CE ingestible, "
            f"see exporter docstring)"
        )


# ────────────────────────────────────────────────────────────────────── #
#  CSV — one row per priority target                                      #
# ────────────────────────────────────────────────────────────────────── #


class CSVExporter:
    """Spreadsheet-friendly export. One row per priority target with a
    fixed column set; the row order matches the ranked priority list
    (highest priority first). Used by consultants importing findings
    into Excel / Google Sheets / a ticketing system that consumes CSV.

    Newlines inside ``next_step`` are normalised to ``\\n`` literals so
    every row is exactly one CSV record — Excel chokes otherwise.
    """

    COLUMNS = [
        "priority", "severity", "category", "mitre",
        "target", "attack", "reason", "next_step",
    ]

    def export(self, data: dict[str, Any], path: str) -> None:
        targets = data.get("targets", [])
        out = Path(path)
        # Use StringIO buffer + atomic write so a crash mid-export
        # doesn't leave a half-written CSV on disk.
        buf = StringIO()
        writer = csv.DictWriter(
            buf,
            fieldnames=self.COLUMNS,
            extrasaction="ignore",       # extra dict keys silently dropped
            quoting=csv.QUOTE_MINIMAL,
            lineterminator="\n",
        )
        writer.writeheader()
        for t in targets:
            row = {col: t.get(col, "") for col in self.COLUMNS}
            # Normalise newlines so every row is one record. Excel and
            # most ticketing-system CSV parsers handle quoted multi-line
            # cells, but the long tail (split / awk / Python's
            # csv-with-quoting=NONE) does not.
            ns = row.get("next_step") or ""
            if isinstance(ns, str):
                row["next_step"] = ns.replace("\r\n", "\\n").replace("\n", "\\n")
            writer.writerow(row)
        out.write_text(buf.getvalue())
        log.success(
            f"CSV report written → {out.resolve()} ({len(targets)} rows)"
        )


# ────────────────────────────────────────────────────────────────────── #
#  Markdown — full operator-report                                        #
# ────────────────────────────────────────────────────────────────────── #


class MarkdownExporter:
    """A complete report in Markdown. Designed to drop into Obsidian /
    Notion / a customer-facing doc with minimal post-processing.

    Layout:
      1. Header (domain, DC, scan timestamp, operator, scan duration)
      2. Top priorities table (the same ranking print_priority_targets shows)
      3. Findings by category (kerberoast, asrep, delegation, cves,
         hygiene, attack-path) — one heading per category, one bullet
         per finding with target / severity / next_step
      4. Domain info / module summary appendix

    Empty data → still produces a valid markdown skeleton with explicit
    "no findings" notes so the file isn't blank when the customer's
    domain is genuinely clean.
    """

    SEVERITY_BADGE = {
        "CRITICAL": "🟥 CRITICAL",
        "HIGH":     "🟧 HIGH",
        "MEDIUM":   "🟨 MEDIUM",
        "LOW":      "🟩 LOW",
        "INFO":     "⬜ INFO",
    }

    def export(self, data: dict[str, Any], path: str) -> None:
        out = Path(path)
        meta    = data.get("meta") or {}
        targets = data.get("targets") or []

        sections: list[str] = []
        sections.append(self._header(meta))
        sections.append(self._top_priority_table(targets))
        sections.append(self._findings_by_category(targets))
        sections.append(self._appendix(data))

        out.write_text("\n\n".join(s for s in sections if s) + "\n")
        log.success(
            f"Markdown report written → {out.resolve()} "
            f"({len(targets)} targets across "
            f"{len({t.get('category', '') for t in targets})} categories)"
        )

    # ------------------------------------------------------------------ #
    #  Sections                                                           #
    # ------------------------------------------------------------------ #

    def _header(self, meta: dict[str, Any]) -> str:
        domain    = meta.get("domain")    or "(unknown)"
        dc_ip     = meta.get("dc_ip")     or "(unknown)"
        operator  = meta.get("operator")  or "(unknown)"
        timestamp = meta.get("timestamp") or "(unknown)"
        duration  = meta.get("duration_s")
        return (
            f"# kerb-map report — {domain}\n\n"
            f"| Field | Value |\n"
            f"|---|---|\n"
            f"| Domain | `{_md_escape(str(domain))}` |\n"
            f"| Domain Controller | `{_md_escape(str(dc_ip))}` |\n"
            f"| Operator | `{_md_escape(str(operator))}` |\n"
            f"| Scan timestamp | {_md_escape(str(timestamp))} |\n"
            + (f"| Duration | {duration:.1f}s |\n" if isinstance(duration, (int, float)) else "")
        )

    def _top_priority_table(self, targets: list[dict]) -> str:
        if not targets:
            return "## Top priorities\n\n*No findings.*"
        rows = [
            "## Top priorities",
            "",
            "| # | Severity | Target | Attack | Priority |",
            "|---|---|---|---|---|",
        ]
        for i, t in enumerate(targets[:25], 1):
            sev = self.SEVERITY_BADGE.get(t.get("severity", ""), t.get("severity", ""))
            rows.append(
                f"| {i} | {sev} "
                f"| `{_md_escape(str(t.get('target', '?')))}` "
                f"| {_md_escape(str(t.get('attack', '?')))} "
                f"| {t.get('priority', 0)} |"
            )
        return "\n".join(rows)

    def _findings_by_category(self, targets: list[dict]) -> str:
        if not targets:
            return ""
        # Group by category. Stable order: by total priority desc per category
        # (so the most-impactful category surfaces first).
        groups: dict[str, list[dict]] = {}
        for t in targets:
            groups.setdefault(t.get("category", "uncategorised"), []).append(t)

        ordered_cats = sorted(
            groups.items(),
            key=lambda kv: -sum(int(t.get("priority", 0)) for t in kv[1]),
        )

        out = ["## Findings by category"]
        for cat, items in ordered_cats:
            out.append(f"\n### {_md_escape(cat or 'uncategorised')} ({len(items)})\n")
            for t in items:
                sev    = self.SEVERITY_BADGE.get(t.get("severity", ""), t.get("severity", ""))
                target = _md_escape(str(t.get("target", "?")))
                attack = _md_escape(str(t.get("attack", "?")))
                reason = _md_escape(str(t.get("reason", "")))
                out.append(f"- **{sev}** — `{target}` — {attack}")
                if reason:
                    out.append(f"  - {reason}")
                next_step = t.get("next_step", "")
                if next_step:
                    out.append("  - Next step:")
                    out.append("    ```")
                    out.append(_indent(str(next_step), "    "))
                    out.append("    ```")
        return "\n".join(out)

    def _appendix(self, data: dict[str, Any]) -> str:
        info = data.get("domain_info") or {}
        if not info:
            return ""
        rows = ["## Domain info appendix", "", "| Field | Value |", "|---|---|"]
        for k in ("domain", "functional_level", "fl_int", "machine_account_quota",
                  "min_pwd_length", "pwd_history_length", "lockout_threshold",
                  "when_created", "domain_sid"):
            if k in info:
                rows.append(f"| {k} | `{_md_escape(str(info[k]))}` |")
        return "\n".join(rows)


# ────────────────────────────────────────────────────────────────────── #
#  Markdown helpers                                                       #
# ────────────────────────────────────────────────────────────────────── #


def _md_escape(s: str) -> str:
    """Tame the markdown special characters that break tables (pipes,
    backslashes, newlines). We don't try to be a full sanitiser —
    just enough that ``a | b`` doesn't become a column boundary and
    ``a\\nb`` doesn't break a single-line cell."""
    if not s:
        return ""
    return (
        s.replace("\\", "\\\\")
         .replace("|", "\\|")
         .replace("\r\n", " ")
         .replace("\n", " ")
    )


def _indent(text: str, prefix: str) -> str:
    """Indent every line of ``text`` by ``prefix`` for fenced code blocks
    inside a list item."""
    return "\n".join(prefix + line for line in text.splitlines())

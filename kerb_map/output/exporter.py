"""
Export writers.

  JSONExporter            — full data dump (lossless, machine-readable)
  BloodHoundLiteExporter  — kerb-map's custom JSON shape (replay only)
  CSVExporter             — one row per priority target (spreadsheet)
  MarkdownExporter        — full report — top priorities + per-section
                            findings + raw-evidence appendix
  HTMLExporter            — self-contained single-file report (no external
                            assets) for a client-facing deliverable /
                            browser-print-to-PDF
"""

import csv
import datetime
import html
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


# ────────────────────────────────────────────────────────────────────── #
#  HTML — self-contained client-facing report                            #
# ────────────────────────────────────────────────────────────────────── #


class HTMLExporter:
    """A complete report as a single self-contained HTML file.

    No external assets (CSS/JS/fonts are all inline), so the file opens
    identically on an air-gapped review box, an emailed copy, or the
    engagement share. Print styles are included so an operator can
    browser-print it to a client-ready PDF.

    Layout mirrors ``MarkdownExporter`` so the two stay in lock-step:
      1. Header (domain, DC, operator, timestamp, duration)
      2. Severity summary tiles (counts per severity across targets)
      3. Top priorities table
      4. Findings grouped by category (ordered by priority sum desc)
      5. Domain-info appendix

    **Injection safety.** Every dynamic value — account names, LDAP
    descriptions, SPNs, next-step commands — is attacker-controllable AD
    data. All of it is routed through :func:`html.escape` before it
    reaches the document, so a ``description`` of
    ``<script>…`` renders as inert text rather than executing when the
    operator opens the report. There is no un-escaped interpolation path.

    Empty data still produces a valid document with an explicit "no
    findings" note, so a genuinely clean domain doesn't yield a blank
    page.
    """

    SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

    # Palette shared by the tiles, badges and category accents. Colours
    # picked for adequate contrast on the dark card background *and* when
    # printed on white (the badges keep their fill in print CSS).
    SEVERITY_COLOR = {
        "CRITICAL": "#e5484d",
        "HIGH":     "#f76808",
        "MEDIUM":   "#ffb224",
        "LOW":      "#46a758",
        "INFO":     "#8b93a7",
    }

    def export(self, data: dict[str, Any], path: str) -> None:
        out = Path(path)
        meta    = data.get("meta") or {}
        targets = data.get("targets") or []

        body = "\n".join(s for s in (
            self._header(meta),
            self._summary(targets),
            self._top_priority_table(targets),
            self._findings_by_category(targets),
            self._appendix(data),
        ) if s)

        out.write_text(self._document(meta, body))
        log.success(
            f"HTML report written → {out.resolve()} "
            f"({len(targets)} targets across "
            f"{len({t.get('category', '') for t in targets})} categories)"
        )

    # ------------------------------------------------------------------ #
    #  Document shell                                                     #
    # ------------------------------------------------------------------ #

    def _document(self, meta: dict[str, Any], body: str) -> str:
        domain = _h(meta.get("domain") or "(unknown)")
        return (
            "<!DOCTYPE html>\n"
            '<html lang="en">\n<head>\n'
            '<meta charset="utf-8">\n'
            '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
            f"<title>kerb-map report — {domain}</title>\n"
            f"<style>{self._CSS}</style>\n"
            "</head>\n<body>\n"
            '<main class="wrap">\n'
            f"{body}\n"
            '<footer class="foot">Generated by '
            '<a href="https://github.com/b-3llum/kerb-map">kerb-map</a> — '
            "authorized engagement use only.</footer>\n"
            "</main>\n</body>\n</html>\n"
        )

    # ------------------------------------------------------------------ #
    #  Sections                                                           #
    # ------------------------------------------------------------------ #

    def _header(self, meta: dict[str, Any]) -> str:
        domain    = _h(meta.get("domain")    or "(unknown)")
        dc_ip     = _h(meta.get("dc_ip")     or "(unknown)")
        operator  = _h(meta.get("operator")  or "(unknown)")
        timestamp = _h(meta.get("timestamp") or "(unknown)")
        duration  = meta.get("duration_s")
        dur_row = (
            f"<tr><th>Duration</th><td>{duration:.1f}s</td></tr>"
            if isinstance(duration, (int, float)) else ""
        )
        return (
            f"<h1>kerb-map report <span class='dom'>{domain}</span></h1>\n"
            '<table class="meta">\n'
            f"<tr><th>Domain</th><td><code>{domain}</code></td></tr>\n"
            f"<tr><th>Domain Controller</th><td><code>{dc_ip}</code></td></tr>\n"
            f"<tr><th>Operator</th><td><code>{operator}</code></td></tr>\n"
            f"<tr><th>Scan timestamp</th><td>{timestamp}</td></tr>\n"
            f"{dur_row}\n"
            "</table>"
        )

    def _summary(self, targets: list[dict]) -> str:
        counts = {sev: 0 for sev in self.SEVERITY_ORDER}
        for t in targets:
            sev = str(t.get("severity", "")).upper()
            if sev in counts:
                counts[sev] += 1
        tiles = []
        for sev in self.SEVERITY_ORDER:
            color = self.SEVERITY_COLOR[sev]
            tiles.append(
                f'<div class="tile" style="--sev:{color}">'
                f'<div class="tile-n">{counts[sev]}</div>'
                f'<div class="tile-l">{sev}</div></div>'
            )
        return '<section class="tiles">\n' + "\n".join(tiles) + "\n</section>"

    def _badge(self, severity: str) -> str:
        sev = str(severity or "").upper()
        color = self.SEVERITY_COLOR.get(sev, "#8b93a7")
        label = _h(sev or "—")
        return f'<span class="badge" style="--sev:{color}">{label}</span>'

    def _top_priority_table(self, targets: list[dict]) -> str:
        if not targets:
            return '<h2>Top priorities</h2>\n<p class="empty">No findings.</p>'
        rows = [
            "<h2>Top priorities</h2>",
            '<table class="findings">',
            "<thead><tr><th>#</th><th>Severity</th><th>Target</th>"
            "<th>Attack</th><th>Priority</th></tr></thead>",
            "<tbody>",
        ]
        for i, t in enumerate(targets[:25], 1):
            rows.append(
                f"<tr><td>{i}</td>"
                f"<td>{self._badge(t.get('severity', ''))}</td>"
                f"<td><code>{_h(t.get('target', '?'))}</code></td>"
                f"<td>{_h(t.get('attack', '?'))}</td>"
                f"<td>{_h(t.get('priority', 0))}</td></tr>"
            )
        rows += ["</tbody>", "</table>"]
        return "\n".join(rows)

    def _findings_by_category(self, targets: list[dict]) -> str:
        if not targets:
            return ""
        groups: dict[str, list[dict]] = {}
        for t in targets:
            groups.setdefault(t.get("category", "uncategorised"), []).append(t)
        ordered_cats = sorted(
            groups.items(),
            key=lambda kv: -sum(int(t.get("priority", 0)) for t in kv[1]),
        )

        out = ["<h2>Findings by category</h2>"]
        for cat, items in ordered_cats:
            out.append(
                f'<h3>{_h(cat or "uncategorised")} '
                f'<span class="count">{len(items)}</span></h3>'
            )
            for t in items:
                out.append('<article class="finding">')
                out.append(
                    '<div class="finding-head">'
                    f"{self._badge(t.get('severity', ''))}"
                    f'<code class="tgt">{_h(t.get("target", "?"))}</code>'
                    f'<span class="atk">{_h(t.get("attack", "?"))}</span>'
                )
                mitre = t.get("mitre")
                if mitre:
                    out.append(f'<span class="mitre">{_h(mitre)}</span>')
                out.append("</div>")
                reason = t.get("reason")
                if reason:
                    out.append(f'<p class="reason">{_h(reason)}</p>')
                next_step = t.get("next_step")
                if next_step:
                    out.append(
                        '<div class="next"><span class="next-l">Next step</span>'
                        f"<pre>{_h(str(next_step))}</pre></div>"
                    )
                out.append("</article>")
        return "\n".join(out)

    def _appendix(self, data: dict[str, Any]) -> str:
        info = data.get("domain_info") or {}
        if not info:
            return ""
        rows = [
            "<h2>Domain info appendix</h2>",
            '<table class="meta">',
        ]
        for k in ("domain", "functional_level", "fl_int", "machine_account_quota",
                  "min_pwd_length", "pwd_history_length", "lockout_threshold",
                  "when_created", "domain_sid"):
            if k in info:
                rows.append(f"<tr><th>{_h(k)}</th><td><code>{_h(info[k])}</code></td></tr>")
        rows.append("</table>")
        return "\n".join(rows)

    # ------------------------------------------------------------------ #
    #  Inline stylesheet                                                  #
    # ------------------------------------------------------------------ #

    _CSS = (
        ":root{color-scheme:dark}"
        "*{box-sizing:border-box}"
        "body{margin:0;background:#0e1117;color:#c9d1d9;"
        "font:15px/1.55 -apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,"
        "Helvetica,Arial,sans-serif}"
        ".wrap{max-width:960px;margin:0 auto;padding:32px 16px 64px}"
        "h1{font-size:1.7rem;margin:0 0 .2em;font-weight:650}"
        "h1 .dom{color:#58a6ff}"
        "h2{font-size:1.25rem;margin:2em 0 .6em;padding-bottom:.3em;"
        "border-bottom:1px solid #21262d}"
        "h3{font-size:1.02rem;margin:1.6em 0 .5em;font-weight:600}"
        "h3 .count{display:inline-block;min-width:1.4em;padding:0 .4em;"
        "margin-left:.4em;border-radius:10px;background:#21262d;color:#8b93a7;"
        "font-size:.8rem;text-align:center}"
        "code{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;"
        "font-size:.9em}"
        "a{color:#58a6ff}"
        "table{border-collapse:collapse;width:100%;margin:.4em 0}"
        "table.meta{max-width:520px}"
        "table.meta th{text-align:left;color:#8b93a7;font-weight:500;"
        "white-space:nowrap;padding:.25em 1.2em .25em 0;vertical-align:top}"
        "table.meta td{padding:.25em 0}"
        "table.findings{font-size:.92rem}"
        "table.findings th{text-align:left;color:#8b93a7;font-weight:500;"
        "border-bottom:1px solid #21262d;padding:.45em .6em}"
        "table.findings td{padding:.45em .6em;border-bottom:1px solid #161b22;"
        "vertical-align:top}"
        ".tiles{display:flex;flex-wrap:wrap;gap:12px;margin:1.4em 0 0}"
        ".tile{flex:1 1 90px;min-width:90px;background:#161b22;"
        "border:1px solid #21262d;border-top:3px solid var(--sev);"
        "border-radius:8px;padding:12px 14px}"
        ".tile-n{font-size:1.7rem;font-weight:700;color:var(--sev);line-height:1}"
        ".tile-l{font-size:.72rem;letter-spacing:.06em;color:#8b93a7;"
        "margin-top:4px}"
        ".badge{display:inline-block;padding:.08em .55em;border-radius:4px;"
        "font-size:.72rem;font-weight:700;letter-spacing:.04em;color:#0e1117;"
        "background:var(--sev)}"
        ".finding{background:#161b22;border:1px solid #21262d;border-radius:8px;"
        "padding:14px 16px;margin:.7em 0}"
        ".finding-head{display:flex;flex-wrap:wrap;align-items:center;gap:10px}"
        ".finding-head .tgt{font-size:.95rem;color:#e6edf3}"
        ".finding-head .atk{color:#c9d1d9}"
        ".finding-head .mitre{margin-left:auto;font-size:.72rem;color:#8b93a7;"
        "border:1px solid #30363d;border-radius:4px;padding:.05em .4em}"
        ".reason{margin:.6em 0 0;color:#adbac7}"
        ".next{margin-top:.7em}"
        ".next-l{display:block;font-size:.7rem;letter-spacing:.06em;"
        "color:#8b93a7;margin-bottom:.3em}"
        ".next pre{margin:0;padding:10px 12px;background:#0e1117;"
        "border:1px solid #21262d;border-radius:6px;overflow-x:auto;"
        "font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;"
        "font-size:.82rem;white-space:pre-wrap;word-break:break-word}"
        ".empty{color:#8b93a7;font-style:italic}"
        ".foot{margin-top:3em;padding-top:1em;border-top:1px solid #21262d;"
        "color:#6b7280;font-size:.8rem}"
        "@media print{body{background:#fff;color:#111}"
        ".wrap{max-width:none}"
        ".tile,.finding{background:#f6f8fa;border-color:#d0d7de;"
        "-webkit-print-color-adjust:exact;print-color-adjust:exact}"
        ".next pre{background:#f6f8fa;color:#111}"
        ".badge{-webkit-print-color-adjust:exact;print-color-adjust:exact}"
        "a{color:#0969da}h1 .dom{color:#0969da}}"
    )


def _h(value: Any) -> str:
    """HTML-escape any value for safe interpolation into the report.

    Findings carry attacker-controllable AD strings (descriptions, SPNs,
    account names). Everything user-facing goes through here so the
    report itself can never become an injection vector when opened in a
    browser. ``None`` renders as an empty string, matching the other
    exporters' treatment of missing values.
    """
    if value is None:
        return ""
    return html.escape(str(value), quote=True)

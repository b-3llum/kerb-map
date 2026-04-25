#!/usr/bin/env python3
"""
kerb-map — Kerberos Attack Surface Mapper
==========================================
AD enumeration · Kerberoast scoring · CVE detection · Priority ranking

Usage:
  python kerb-map.py -d corp.local -dc 192.168.1.10 -u jsmith -p Password123
  python kerb-map.py -d corp.local -dc 192.168.1.10 -u jsmith -H <NT_HASH>
  python kerb-map.py -d corp.local -dc 192.168.1.10 -u jsmith -k          (ccache)
  python kerb-map.py -d corp.local -dc 192.168.1.10 -u jsmith -p pass --cves --aggressive
"""

import argparse
import datetime
import getpass
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

# ── make sure the package is importable when running as a script ──
sys.path.insert(0, str(Path(__file__).parent.parent))

from kerb_map.auth.ldap_client import LDAPClient
from kerb_map.db.cache import Cache
from kerb_map.modules.asrep_scanner import ASREPScanner
from kerb_map.modules.cve_scanner import CVEScanner
from kerb_map.modules.delegation_mapper import DelegationMapper
from kerb_map.modules.enc_auditor import EncAuditor
from kerb_map.modules.hygiene_auditor import HygieneAuditor
from kerb_map.modules.scorer import Scorer
from kerb_map.modules.spn_scanner import SPNScanner
from kerb_map.modules.trust_mapper import TrustMapper
from kerb_map.modules.user_enumerator import UserEnumerator
from kerb_map.output.bloodhound_ce import BloodHoundCEExporter
from kerb_map.output.exporter import (
    BloodHoundLiteExporter,
    CSVExporter,
    JSONExporter,
    MarkdownExporter,
)
from kerb_map.output.logger import Logger, console
from kerb_map.output.reporter import (
    print_asrep_results,
    print_banner,
    print_cve_results,
    print_delegation_results,
    print_domain_info,
    print_enc_audit_results,
    print_hygiene_results,
    print_priority_targets,
    print_spn_results,
    print_summary,
    print_trust_results,
    print_user_results,
)
from kerb_map.plugin import ScanContext, all_modules, discover
from kerb_map.substitute import SubstitutionContext, apply_to_findings, substitute

log = Logger()

# Marker placed in args.password / args.hash by argparse when the flag
# was given without a value — meaning "prompt me interactively".
PROMPT_SENTINEL = "<<KERBMAP_PROMPT>>"

# ──────────────────────────────────────────────────────────────────────────────
# Argument Parser
# ──────────────────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="kerb-map",
        description="Kerberos Attack Surface Mapper — AD enumeration and CVE detection",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Password auth, full scan
  python kerb-map.py -d corp.local -dc 192.168.1.10 -u jsmith -p Summer2024!

  # Pass-the-Hash
  python kerb-map.py -d corp.local -dc 192.168.1.10 -u jsmith -H aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0

  # Kerberos ticket (set KRB5CCNAME first)
  python kerb-map.py -d corp.local -dc 192.168.1.10 -u jsmith -k

  # Full scan with CVEs + aggressive RPC probes + JSON output
  python kerb-map.py -d corp.local -dc 192.168.1.10 -u jsmith -p pass --all --aggressive -o json

  # Stealth mode — slow LDAP queries, skip RPC checks
  python kerb-map.py -d corp.local -dc 192.168.1.10 -u jsmith -p pass --stealth

  # List previous scans stored in local DB
  python kerb-map.py --list-scans

  # Replay/dump a stored scan
  python kerb-map.py --show-scan 3
        """,
    )

    # ── Required ──────────────────────────────────────────────────
    req = p.add_argument_group("Target (required for live scan)")
    req.add_argument("-d",  "--domain",   help="Target domain  (e.g. corp.local)")
    req.add_argument("-dc", "--dc-ip",    help="Domain controller IP")
    req.add_argument("-u",  "--username", help="Username")

    # ── Auth ──────────────────────────────────────────────────────
    # Avoid putting the secret on argv (visible in `ps aux`, shell history,
    # auditd). Prefer --password-stdin / --password-env, or omit the value
    # to be prompted interactively.
    auth = p.add_argument_group("Authentication (pick one)")
    auth.add_argument("-p",  "--password",
                      nargs="?", const=PROMPT_SENTINEL, default=None,
                      help="Plaintext password (omit value to prompt — avoids ps-aux leak)")
    auth.add_argument("--password-stdin", action="store_true",
                      help="Read password from stdin (one line, trailing newline stripped)")
    auth.add_argument("--password-env", metavar="VAR",
                      help="Read password from the named environment variable")
    auth.add_argument("-H",  "--hash",
                      nargs="?", const=PROMPT_SENTINEL, default=None,
                      help="NTLM hash LM:NT or NT only (omit value to prompt)")
    auth.add_argument("--hash-stdin", action="store_true",
                      help="Read NTLM hash from stdin")
    auth.add_argument("--hash-env", metavar="VAR",
                      help="Read NTLM hash from the named environment variable")
    auth.add_argument("-k",  "--kerberos",  action="store_true",
                      help="Use ccache ticket (set KRB5CCNAME env var first)")

    # ── Module selection ──────────────────────────────────────────
    mods = p.add_argument_group("Module selection")
    mods.add_argument("--all",         action="store_true", help="Run all modules (default)")
    mods.add_argument("--spn",         action="store_true", help="Kerberoastable accounts")
    mods.add_argument("--asrep",       action="store_true", help="AS-REP Roastable accounts")
    mods.add_argument("--delegation",  action="store_true", help="Delegation mapping")
    mods.add_argument("--users",       action="store_true", help="User/policy enumeration")
    mods.add_argument("--cves",        action="store_true", help="CVE / misconfiguration checks")
    mods.add_argument("--encryption", action="store_true", help="Weak encryption audit (RC4/DES)")
    mods.add_argument("--trusts",     action="store_true", help="Domain trust mapping")
    mods.add_argument("--hygiene",   action="store_true",
                      help="Defensive hygiene audit (LAPS coverage, krbtgt age, SID history, FGPP, stale machines, etc.)")
    mods.add_argument("--aggressive",  action="store_true",
                      help="Enable RPC-based CVE probes (louder — generates Event 5145)")
    mods.add_argument("--v2", action="store_true",
                      help="Run the v2 plugin-contract modules (DCSync rights, "
                           "Shadow Credentials, BadSuccessor — auto-discovered via "
                           "@register). Additive to the legacy modules above.")
    mods.add_argument("--list-cves", dest="list_cves", action="store_true",
                      help="Print every available CVE check (with CVE-ID + "
                           "aggressive flag) and exit. No live scan.")
    mods.add_argument("--only-cves", dest="only_cves", metavar="IDS",
                      help="Run only the named CVE checks (comma-separated CVE-IDs "
                           "from --list-cves). Combine with --aggressive when naming "
                           "an aggressive check (otherwise it's filtered out).")

    # ── Output ────────────────────────────────────────────────────
    out = p.add_argument_group("Output")
    out.add_argument("-o", "--output",
                     choices=["json", "bloodhound-lite", "bloodhound-ce",
                              "csv", "markdown"],
                     help="Write results to file. 'bloodhound-ce' is a real "
                          "BloodHound CE 5.x ingestible zip (users/computers/groups/"
                          "domains JSON + custom KerbMap* edges). 'bloodhound-lite' "
                          "is the legacy custom-shape JSON (NOT BH-CE-ingestible). "
                          "'csv' = one row per priority target (spreadsheet). "
                          "'markdown' = full operator-report (drops into Obsidian).")
    out.add_argument("--outfile", default=None,
                     help="Output filename (default: kerb-map_<domain>_<ts>.<ext>)")
    out.add_argument("--top",    type=int, default=15,
                     help="Number of priority targets to display (default: 15)")
    out.add_argument("--no-cache", action="store_true",
                     help="Do not save results to local SQLite cache")

    # ── Tuning ────────────────────────────────────────────────────
    tune = p.add_argument_group("Tuning")
    tune.add_argument("--stealth",  action="store_true",
                      help="Add random jitter between LDAP queries (slower but quieter)")
    tune.add_argument("--timeout",  type=int, default=10,
                      help="LDAP connection timeout in seconds (default: 10)")

    # ── Transport / TLS ──────────────────────────────────────────
    # Default behaviour: try LDAPS → StartTLS → (signed if --kerberos) → plain.
    # Use one of these flags to pin a single transport.
    tls = p.add_argument_group("Transport (mutually exclusive — default is auto)")
    tls_group = tls.add_mutually_exclusive_group()
    tls_group.add_argument("--ldaps",    action="store_true",
                           help="Force LDAPS (port 636); skip the fallback chain")
    tls_group.add_argument("--starttls", action="store_true",
                           help="Force StartTLS upgrade on port 389")
    tls_group.add_argument("--no-tls",   action="store_true",
                           help="Force plain LDAP on 389 — unencrypted, unsigned")

    # ── DB operations ─────────────────────────────────────────────
    db = p.add_argument_group("Scan history (no live scan required)")
    db.add_argument("--list-scans",  action="store_true",
                    help="List all scans stored in local cache")
    db.add_argument("--show-scan",   type=int, metavar="ID",
                    help="Display findings from a previous scan by ID")
    db.add_argument("--diff",        nargs=2, type=int, metavar=("A", "B"),
                    help="Diff two scans by ID — prints REMOVED (fixed) / "
                         "ADDED (new) / UNCHANGED (still exposed) buckets. "
                         "The high-value retest feature.")

    # ── Maintenance ─────────────────────────────────────────────
    maint = p.add_argument_group("Maintenance")
    maint.add_argument("--update", action="store_true",
                       help="Pull latest version from GitHub and reinstall")

    return p


# ──────────────────────────────────────────────────────────────────────────────
# DB operations (no network required)
# ──────────────────────────────────────────────────────────────────────────────

def cmd_list_scans():
    cache = Cache()
    rows  = cache.list_scans()
    if not rows:
        log.warn("No scans in local cache yet.")
        return
    console.print("\n[bold cyan]Stored Scans[/bold cyan]")
    for r in rows:
        console.print(_format_list_scans_row(r))
    console.print()


def _format_list_scans_row(r: dict) -> str:
    """One-line summary per scan (brief §3.4). Format:
      ID  N  domain  DC: ip  operator  short-ts  N findings (NC/NH/NM/NL/NI)  Xs
    """
    ts = r.get("timestamp") or ""
    short_ts = ts.replace("T", " ").split(".", 1)[0]   # 2026-04-25 10:30:00
    counts   = r.get("counts") or {}
    total    = counts.get("total", 0)
    breakdown = (
        f"{counts.get('CRITICAL', 0)}C/"
        f"{counts.get('HIGH', 0)}H/"
        f"{counts.get('MEDIUM', 0)}M/"
        f"{counts.get('LOW', 0)}L/"
        f"{counts.get('INFO', 0)}I"
    )
    duration = r.get("duration_s") or 0.0
    return (
        f"  [cyan]ID {r['id']:>3}[/cyan]  "
        f"{(r.get('domain') or '?'):<25}  "
        f"DC: {(r.get('dc_ip') or '?'):<16}  "
        f"{(r.get('operator') or 'unknown'):<15}  "
        f"{short_ts:<19}  "
        f"[bold]{total:>3} findings[/bold] "
        f"[dim]({breakdown})[/dim]  "
        f"[dim]{duration:>5.1f}s[/dim]"
    )


def cmd_diff(a_id: int, b_id: int):
    """Diff two cached scans. ``A`` is the older / baseline; ``B`` is the
    newer / re-test. The console output is intentionally three buckets
    in green / red / yellow so the operator can grep visually."""
    from kerb_map.diff import diff_findings

    cache = Cache()
    a_scan = cache.get_scan(a_id)
    b_scan = cache.get_scan(b_id)
    if not a_scan or not b_scan:
        missing = []
        if not a_scan:
            missing.append(str(a_id))
        if not b_scan:
            missing.append(str(b_id))
        log.error(f"Scan ID(s) not found: {', '.join(missing)}")
        sys.exit(1)

    a_findings = cache.get_findings(a_id)
    b_findings = cache.get_findings(b_id)
    result     = diff_findings(a_findings, b_findings, scan_a_id=a_id, scan_b_id=b_id)

    a_meta = a_scan.get("meta", {})
    b_meta = b_scan.get("meta", {})

    console.print(
        f"\n[bold cyan]Diff: scan #{a_id}[/bold cyan] "
        f"({a_meta.get('domain', '?')} @ {a_meta.get('timestamp', '?')})"
        f"  →  [bold cyan]scan #{b_id}[/bold cyan] "
        f"({b_meta.get('domain', '?')} @ {b_meta.get('timestamp', '?')})"
    )
    console.print(
        f"  [green]REMOVED  {len(result.removed):>3}  (fixed)[/green]"
        f"  [red]ADDED  {len(result.added):>3}  (new)[/red]"
        f"  [yellow]UNCHANGED  {len(result.unchanged):>3}  (still exposed)[/yellow]\n"
    )

    def _print_bucket(label: str, colour: str, findings: list[dict]):
        if not findings:
            return
        console.print(f"[bold {colour}]── {label} ──[/bold {colour}]")
        for f in findings:
            sev_col = {"CRITICAL": "red", "HIGH": "red", "MEDIUM": "yellow",
                       "LOW": "green", "INFO": "dim"}.get(f.get("severity", ""), "white")
            console.print(
                f"  [{sev_col}]{f.get('severity', '?'):<10}[/{sev_col}] "
                f"[cyan]{f.get('attack', '?'):<40}[/cyan]  "
                f"{f.get('target', '?')}"
            )
            if f.get("reason"):
                console.print(f"             [dim]{f['reason']}[/dim]")
        console.print()

    _print_bucket("REMOVED — customer fixed these",      "green",  result.removed)
    _print_bucket("ADDED — new findings since last scan", "red",    result.added)
    _print_bucket("UNCHANGED — still exposed",            "yellow", result.unchanged)


def cmd_list_cves():
    """Print every CVE check kerb-map ships with — for use with
    --only-cves. No live scan."""
    from kerb_map.modules.cve_scanner import CVEScanner

    checks = CVEScanner.list_checks()
    console.print("\n[bold cyan]Available CVE checks[/bold cyan]")
    console.print("[dim](use the CVE-ID column with --only-cves "
                  "<id>,<id>,...)[/dim]\n")
    safe = [c for c in checks if not c["requires_aggressive"]]
    loud = [c for c in checks if c["requires_aggressive"]]

    def _print(rows, label):
        if not rows:
            return
        console.print(f"[bold]{label}[/bold]")
        for r in rows:
            console.print(
                f"  [cyan]{r['cve_id']:<28}[/cyan]  {r['name']}"
            )
        console.print()

    _print(safe, "Safe checks (always run with --cves)")
    _print(loud, "Aggressive checks (require --aggressive — generate Event 5145)")


def cmd_show_scan(scan_id: int):
    cache    = Cache()
    findings = cache.get_findings(scan_id)
    if not findings:
        log.error(f"Scan ID {scan_id} not found.")
        return
    console.print(f"\n[bold cyan]Findings — Scan #{scan_id}[/bold cyan]")
    for f in findings:
        sev_col = {"CRITICAL": "red", "HIGH": "red", "MEDIUM": "yellow",
                   "LOW": "green"}.get(f["severity"], "white")
        console.print(
            f"  [{sev_col}]{f['severity']:<10}[/{sev_col}] "
            f"[cyan]{f['attack']:<40}[/cyan]  {f['target']}"
        )
    console.print()


# ──────────────────────────────────────────────────────────────────────────────
# Self-update
# ──────────────────────────────────────────────────────────────────────────────

def cmd_update():
    repo_root = Path(__file__).resolve().parent.parent
    git_dir   = repo_root / ".git"

    if not git_dir.is_dir():
        log.error("Not installed from a git clone — cannot auto-update.")
        log.info("Re-clone from: https://github.com/b-3llum/kerb-map")
        sys.exit(1)

    log.section("Updating kerb-map")

    # Pull latest
    log.info("Running git pull...")
    result = subprocess.run(
        ["git", "pull"], cwd=repo_root, capture_output=True, text=True,
    )
    if result.returncode != 0:
        log.error(f"git pull failed: {result.stderr.strip()}")
        sys.exit(1)
    console.print(f"  {result.stdout.strip()}")

    if "Already up to date" in result.stdout:
        log.success("Already on the latest version.")
        return

    # Reinstall if pipx is available
    if shutil.which("pipx"):
        log.info("Reinstalling via pipx...")
        r = subprocess.run(
            ["pipx", "install", "--force", str(repo_root)],
            capture_output=True, text=True,
        )
        if r.returncode == 0:
            log.success("Updated and reinstalled via pipx.")
        else:
            log.warn(f"pipx reinstall failed: {r.stderr.strip()}")
            log.info("Run manually: pipx install --force " + str(repo_root))
    elif shutil.which("pip"):
        log.info("Reinstalling via pip...")
        r = subprocess.run(
            ["pip", "install", "--upgrade", str(repo_root)],
            capture_output=True, text=True,
        )
        if r.returncode == 0:
            log.success("Updated and reinstalled via pip.")
        else:
            log.warn(f"pip reinstall failed: {r.stderr.strip()}")
    else:
        log.success("Source updated. No pip/pipx found — running directly is fine.")


# ──────────────────────────────────────────────────────────────────────────────
# Secret resolution
# ──────────────────────────────────────────────────────────────────────────────

def resolve_secret(arg_value, env_var, read_stdin, *, label):
    """Resolve a secret from --foo, --foo-env VAR, --foo-stdin, or interactive
    prompt. Returns the secret string or ``None`` if no source was provided.

    Resolution order: --foo-env > --foo-stdin > --foo (or prompt sentinel).
    Exits the process on inconsistent input rather than silently picking one.
    """
    sources = [bool(env_var), bool(read_stdin), arg_value is not None]
    if sum(sources) > 1:
        log.error(f"--{label}, --{label}-stdin, and --{label}-env are mutually exclusive")
        sys.exit(1)

    if env_var:
        val = os.environ.get(env_var)
        if val is None:
            log.error(f"--{label}-env: environment variable {env_var!r} is not set")
            sys.exit(1)
        return val

    if read_stdin:
        val = sys.stdin.readline()
        if not val:
            log.error(f"--{label}-stdin: no input received on stdin")
            sys.exit(1)
        return val.rstrip("\r\n")

    if arg_value == PROMPT_SENTINEL:
        return getpass.getpass(f"{label.capitalize()}: ")

    return arg_value


# ──────────────────────────────────────────────────────────────────────────────
# Main scan
# ──────────────────────────────────────────────────────────────────────────────

def run_scan(args):
    # ── Validate required args ────────────────────────────────────
    if not all([args.domain, args.dc_ip, args.username]):
        log.error("--domain, --dc-ip, and --username are required for a live scan.")
        sys.exit(1)

    # Resolve secrets BEFORE handing them to LDAPClient. Doing it here keeps
    # passwords / hashes off the process command line: the operator can use
    # --password-stdin, --password-env, or `-p` with no value (interactive
    # prompt) instead of `-p Password123`.
    password = resolve_secret(args.password, args.password_env, args.password_stdin,
                              label="password")
    nthash   = resolve_secret(args.hash,     args.hash_env,     args.hash_stdin,
                              label="hash")

    if not password and not nthash and not args.kerberos:
        log.error(
            "Provide one of: --password (or --password-stdin / --password-env), "
            "--hash (or --hash-stdin / --hash-env), or --kerberos"
        )
        sys.exit(1)

    if password and nthash:
        log.error("Pick one credential: password OR hash, not both")
        sys.exit(1)

    # ── Determine which modules to run ───────────────────────────
    run_all = args.all or not any([
        args.spn, args.asrep, args.delegation, args.users, args.cves,
        args.encryption, args.trusts, args.hygiene,
    ])

    run_spn    = run_all or args.spn
    run_asrep  = run_all or args.asrep
    run_deleg  = run_all or args.delegation
    run_user   = run_all or args.users
    run_cve    = run_all or args.cves
    run_enc    = run_all or args.encryption
    run_trust  = run_all or args.trusts
    run_hygiene= run_all or args.hygiene

    # ── Connect ───────────────────────────────────────────────────
    print_banner()
    log.section("Connecting")

    transport = None
    if args.ldaps:
        transport = "ldaps"
    elif args.starttls:
        transport = "starttls"
    elif args.no_tls:
        transport = "plain"

    try:
        ldap = LDAPClient(
            dc_ip       = args.dc_ip,
            domain      = args.domain,
            username    = args.username,
            password    = password,
            hashes      = nthash,
            use_kerberos= args.kerberos,
            transport   = transport,
            timeout     = args.timeout,
            stealth     = args.stealth,
        )
    except Exception as e:
        log.error(f"Failed to connect: {e}")
        sys.exit(1)

    start_ts = time.time()

    # ── Domain overview ───────────────────────────────────────────
    log.section("Domain Overview")
    domain_info = ldap.get_domain_info()
    print_domain_info(domain_info)

    # Build the placeholder substitution context (brief §3.5). Applied
    # below to every CVE / v2 / scorer next_step so operators can copy
    # the recipe straight into a terminal.
    sub_ctx = SubstitutionContext(
        dc_ip=args.dc_ip,
        domain=args.domain,
        domain_sid=domain_info.get("domain_sid"),
        dc_fqdn=domain_info.get("dc_dns_hostname"),
        base_dn=ldap.base_dn,
    )

    # ── Kerberoastable accounts ───────────────────────────────────
    spns = []
    if run_spn:
        log.section("SPN Scan — Kerberoastable Accounts")
        spns = SPNScanner(ldap).scan()
        print_spn_results(spns)

    # ── AS-REP Roastable ─────────────────────────────────────────
    asrep = []
    if run_asrep:
        log.section("AS-REP Roastable Accounts")
        asrep = ASREPScanner(ldap).scan()
        print_asrep_results(asrep)

    # ── Delegation ────────────────────────────────────────────────
    delegations = {"unconstrained": [], "constrained": [], "rbcd": []}
    if run_deleg:
        log.section("Kerberos Delegation Mapping")
        delegations = DelegationMapper(ldap).map_all()
        print_delegation_results(delegations)

    # ── User / Policy Enumeration ─────────────────────────────────
    user_data = {}
    if run_user:
        log.section("User & Policy Enumeration")
        user_data = UserEnumerator(ldap).enumerate()
        print_user_results(user_data)

    # ── Encryption Audit ────────────────────────────────────────────
    enc_audit = None
    if run_enc:
        log.section("Kerberos Encryption Audit")
        enc_audit = EncAuditor(ldap).audit()
        print_enc_audit_results(enc_audit)

    # ── Domain Trusts ────────────────────────────────────────────
    trusts = []
    if run_trust:
        log.section("Domain Trust Mapping")
        trusts = TrustMapper(ldap).map()
        print_trust_results(trusts)

    # ── CVE Checks ────────────────────────────────────────────────
    cve_results = []
    if run_cve:
        log.section("CVE & Misconfiguration Checks")
        if args.aggressive:
            log.warn("Aggressive mode ON — RPC probes will generate Windows Event 5145")
        only_cves = None
        if args.only_cves:
            only_cves = {x.strip() for x in args.only_cves.split(",") if x.strip()}
        cve_results = CVEScanner(ldap, args.dc_ip, args.domain).run(
            aggressive=args.aggressive,
            only=only_cves,
        )
        apply_to_findings(cve_results, sub_ctx)
        print_cve_results(cve_results)

    # ── Hygiene Audit ────────────────────────────────────────────
    hygiene = None
    if run_hygiene:
        log.section("Defensive Hygiene Audit")
        hygiene = HygieneAuditor(ldap).audit()
        print_hygiene_results(hygiene)

    # ── v2 plugin modules (DCSync rights, Shadow Creds, BadSuccessor) ─
    v2_results: dict[str, dict] = {}
    v2_findings: list = []
    if args.v2:
        discover()  # imports @register'd modules under kerb_map.modules
        ctx = ScanContext(
            ldap=ldap, domain=args.domain, base_dn=ldap.base_dn,
            dc_ip=args.dc_ip, aggressive=args.aggressive,
            domain_info=domain_info,
            domain_sid=domain_info.get("domain_sid"),
        )
        for cls in all_modules():
            if cls.requires_aggressive and not args.aggressive:
                continue
            log.section(f"v2: {cls.name}")
            try:
                result = cls().scan(ctx)
            except Exception as e:
                log.warn(f"v2 module {cls.name} failed: {e}")
                continue
            v2_results[cls.flag] = result.raw if result.raw is not None else {}
            apply_to_findings(result.findings, sub_ctx)
            v2_findings.extend(result.findings)
            for f in result.findings:
                sev_col = {"CRITICAL": "red", "HIGH": "red", "MEDIUM": "yellow",
                           "LOW": "green", "INFO": "dim"}.get(f.severity, "white")
                console.print(
                    f"  [{sev_col}]{f.severity:<10}[/{sev_col}] "
                    f"[cyan]{f.attack:<40}[/cyan]  {f.target}"
                )
                if f.reason:
                    console.print(f"             [dim]{f.reason}[/dim]")

    # ── Score & Rank ──────────────────────────────────────────────
    log.section("Attack Path Scoring")
    targets = Scorer().rank(spns, asrep, delegations, cve_results, user_data,
                            enc_audit=enc_audit, trusts=trusts, hygiene=hygiene)
    # Fold v2 findings into the priority list. The legacy Scorer doesn't
    # know about them, so we append directly — already structured the
    # same shape (target / attack / severity / priority / reason /
    # next_step / category / mitre / data) by the Finding dataclass.
    if v2_findings:
        targets.extend(f.as_dict() for f in v2_findings)
        targets.sort(key=lambda t: t.get("priority", 0), reverse=True)
    # Catch any next_step strings the legacy Scorer emitted with
    # placeholders (scorer.py hard-codes <DC_NAME>, <BASE>, etc.).
    for t in targets:
        if "next_step" in t:
            t["next_step"] = substitute(t["next_step"], sub_ctx)
    print_priority_targets(targets, top=args.top)

    # ── Summary ───────────────────────────────────────────────────
    duration = time.time() - start_ts
    print_summary(targets, cve_results)
    log.info(f"Scan completed in {duration:.1f}s")

    # ── Assemble full data blob ───────────────────────────────────
    full_data = {
        "meta": {
            "domain":    args.domain,
            "dc_ip":     args.dc_ip,
            "operator":  args.username,
            "timestamp": datetime.datetime.now().isoformat(),
            "duration_s":round(duration, 2),
        },
        "domain_info": domain_info,
        "spns":        spns,
        "asrep":       asrep,
        "delegations": delegations,
        "user_data":   user_data,
        "enc_audit":   {
            "rc4_only":  len(enc_audit.rc4_only_accounts) if enc_audit else 0,
            "des":       len(enc_audit.des_accounts) if enc_audit else 0,
            "weak_dcs":  len(enc_audit.weak_dcs) if enc_audit else 0,
        },
        "trusts":      [{"partner": t.trust_partner, "direction": t.direction,
                         "risk": t.risk, "sid_filtering": t.sid_filtering}
                        for t in trusts],
        "cves":        [r.to_dict() for r in cve_results],
        "hygiene": {
            "sid_history":          hygiene.sid_history if hygiene else [],
            "laps_coverage":        hygiene.laps_coverage if hygiene else {},
            "krbtgt_age":           hygiene.krbtgt_age if hygiene else {},
            "adminsdholder_orphans":hygiene.adminsdholder_orphans if hygiene else [],
            "fgpp_audit":           hygiene.fgpp_audit if hygiene else {},
            "credential_exposure":  hygiene.credential_exposure if hygiene else [],
            "primary_group_abuse":  hygiene.primary_group_abuse if hygiene else [],
            "stale_computers":      len(hygiene.stale_computers) if hygiene else 0,
            "privileged_groups":    {k: len(v) for k, v in hygiene.privileged_groups.items()} if hygiene else {},
            "service_acct_hygiene": hygiene.service_acct_hygiene if hygiene else [],
        },
        "targets":     targets,
        "v2":          v2_results,
    }

    # ── Cache ─────────────────────────────────────────────────────
    if not args.no_cache:
        try:
            cache   = Cache()
            scan_id = cache.save_scan(
                domain    = args.domain,
                dc_ip     = args.dc_ip,
                operator  = args.username,
                data      = full_data,
                targets   = targets,
                duration_s= duration,
            )
            log.success(f"Results cached (scan ID: {scan_id})  — replay with --show-scan {scan_id}")
        except Exception as e:
            log.warn(f"Cache write failed: {e}")

    # ── File export ───────────────────────────────────────────────
    if args.output:
        ts  = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        ext_map = {"json": "json", "bloodhound-lite": "bloodhound-lite.json",
                   "bloodhound-ce": "bloodhound.zip",
                   "csv": "csv", "markdown": "md"}
        default_name = f"kerb-map_{args.domain}_{ts}.{ext_map[args.output]}"
        outfile      = args.outfile or default_name

        if args.output == "json":
            JSONExporter().export(full_data, outfile)
        elif args.output == "bloodhound-lite":
            BloodHoundLiteExporter().export(full_data, outfile)
        elif args.output == "bloodhound-ce":
            ce = BloodHoundCEExporter(
                ldap=ldap, domain=args.domain,
                domain_sid=domain_info.get("domain_sid"),
                base_dn=ldap.base_dn,
            )
            ce.add_findings(v2_findings)
            ce.export(outfile)
        elif args.output == "csv":
            CSVExporter().export(full_data, outfile)
        elif args.output == "markdown":
            MarkdownExporter().export(full_data, outfile)

    ldap.close()


# ──────────────────────────────────────────────────────────────────────────────
# Entry
# ──────────────────────────────────────────────────────────────────────────────

def main():
    parser = build_parser()
    args   = parser.parse_args()

    # Maintenance operations
    if args.update:
        cmd_update()
        return

    # DB-only operations
    if args.list_scans:
        cmd_list_scans()
        return

    if args.show_scan:
        cmd_show_scan(args.show_scan)
        return

    if args.diff:
        cmd_diff(args.diff[0], args.diff[1])
        return

    if args.list_cves:
        cmd_list_cves()
        return

    # Live scan
    run_scan(args)


if __name__ == "__main__":
    main()

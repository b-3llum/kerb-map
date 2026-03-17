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

import sys
import time
import argparse
import json
import datetime
from pathlib import Path

# ── make sure the package is importable when running as a script ──
sys.path.insert(0, str(Path(__file__).parent.parent))

from kerb_map.auth.ldap_client          import LDAPClient
from kerb_map.modules.spn_scanner       import SPNScanner
from kerb_map.modules.asrep_scanner     import ASREPScanner
from kerb_map.modules.delegation_mapper import DelegationMapper
from kerb_map.modules.user_enumerator   import UserEnumerator
from kerb_map.modules.cve_scanner       import CVEScanner
from kerb_map.modules.scorer            import Scorer
from kerb_map.output.reporter           import (
    print_banner, print_domain_info, print_priority_targets,
    print_spn_results, print_asrep_results, print_delegation_results,
    print_cve_results, print_user_results, print_summary,
)
from kerb_map.output.exporter           import JSONExporter, BloodHoundExporter
from kerb_map.db.cache                  import Cache
from kerb_map.output.logger             import Logger, console

log = Logger()

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
    auth = p.add_argument_group("Authentication (pick one)")
    auth.add_argument("-p",  "--password",  help="Plaintext password")
    auth.add_argument("-H",  "--hash",      help="NTLM hash  LM:NT  or  NT only")
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
    mods.add_argument("--aggressive",  action="store_true",
                      help="Enable RPC-based CVE probes (louder — generates Event 5145)")

    # ── Output ────────────────────────────────────────────────────
    out = p.add_argument_group("Output")
    out.add_argument("-o", "--output",
                     choices=["json", "bloodhound"],
                     help="Write results to file in chosen format")
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

    # ── DB operations ─────────────────────────────────────────────
    db = p.add_argument_group("Scan history (no live scan required)")
    db.add_argument("--list-scans",  action="store_true",
                    help="List all scans stored in local cache")
    db.add_argument("--show-scan",   type=int, metavar="ID",
                    help="Display findings from a previous scan by ID")

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
        console.print(
            f"  [cyan]ID {r[0]:>3}[/cyan]  {r[1]:<25}  DC: {r[2]:<16}  "
            f"Operator: {r[3] or 'unknown':<15}  {r[4]}"
        )
    console.print()


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
# Main scan
# ──────────────────────────────────────────────────────────────────────────────

def run_scan(args):
    # ── Validate required args ────────────────────────────────────
    if not all([args.domain, args.dc_ip, args.username]):
        log.error("--domain, --dc-ip, and --username are required for a live scan.")
        sys.exit(1)

    if not args.password and not args.hash and not args.kerberos:
        log.error("Provide one of: --password, --hash, or --kerberos")
        sys.exit(1)

    # ── Determine which modules to run ───────────────────────────
    run_all = args.all or not any([
        args.spn, args.asrep, args.delegation, args.users, args.cves
    ])

    run_spn  = run_all or args.spn
    run_asrep= run_all or args.asrep
    run_deleg= run_all or args.delegation
    run_user = run_all or args.users
    run_cve  = run_all or args.cves

    # ── Connect ───────────────────────────────────────────────────
    print_banner()
    log.section("Connecting")

    try:
        ldap = LDAPClient(
            dc_ip       = args.dc_ip,
            domain      = args.domain,
            username    = args.username,
            password    = args.password,
            hashes      = args.hash,
            use_kerberos= args.kerberos,
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

    # ── CVE Checks ────────────────────────────────────────────────
    cve_results = []
    if run_cve:
        log.section("CVE & Misconfiguration Checks")
        if args.aggressive:
            log.warn("Aggressive mode ON — RPC probes will generate Windows Event 5145")
        cve_results = CVEScanner(ldap, args.dc_ip, args.domain).run(
            aggressive=args.aggressive
        )
        print_cve_results(cve_results)

    # ── Score & Rank ──────────────────────────────────────────────
    log.section("Attack Path Scoring")
    targets = Scorer().rank(spns, asrep, delegations, cve_results, user_data)
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
        "cves":        [r.to_dict() for r in cve_results],
        "targets":     targets,
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
        ext = "json" if args.output == "json" else "json"
        default_name = f"kerb-map_{args.domain}_{ts}.{ext}"
        outfile      = args.outfile or default_name

        if args.output == "json":
            JSONExporter().export(full_data, outfile)
        elif args.output == "bloodhound":
            BloodHoundExporter().export(full_data, outfile)

    ldap.close()


# ──────────────────────────────────────────────────────────────────────────────
# Entry
# ──────────────────────────────────────────────────────────────────────────────

def main():
    parser = build_parser()
    args   = parser.parse_args()

    # DB-only operations
    if args.list_scans:
        cmd_list_scans()
        return

    if args.show_scan:
        cmd_show_scan(args.show_scan)
        return

    # Live scan
    run_scan(args)


if __name__ == "__main__":
    main()

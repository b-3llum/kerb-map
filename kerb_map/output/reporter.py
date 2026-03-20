"""
Reporter — Rich-powered terminal display for all scan results.
"""

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.columns import Columns
from rich.text import Text
from rich import box
from typing import Dict, Any, List

console = Console()

SEV_COLOR = {
    "CRITICAL": "bold white on red",
    "HIGH":     "bold red",
    "MEDIUM":   "bold yellow",
    "LOW":      "bold green",
    "INFO":     "bold blue",
}

VULN_COLORS = {
    True:  "[bold red]YES[/bold red]",
    False: "[bold green]NO[/bold green]",
}


def _sev(s: str) -> str:
    color = SEV_COLOR.get(s, "white")
    return f"[{color}]{s}[/{color}]"


# ──────────────────────────────────────────────────────────────────────────────
# Banner
# ──────────────────────────────────────────────────────────────────────────────

def print_banner():
    banner = r"""
  _  __         _       __  __
 | |/ /        | |     |  \/  |
 | ' / ___ _ __| |__   | \  / | __ _ _ __
 |  < / _ \ '__| '_ \  | |\/| |/ _` | '_ \
 | . \  __/ |  | |_) | | |  | | (_| | |_) |
 |_|\_\___|_|  |_.__/  |_|  |_|\__,_| .__/
                                     | |
  Kerberos Attack Surface Mapper     |_|  v1.1
"""
    console.print(f"[bold cyan]{banner}[/bold cyan]")
    console.print(
        "  [dim]AD enumeration · Kerberoast scoring · CVE detection · Hygiene audit · Priority ranking[/dim]\n"
    )


# ──────────────────────────────────────────────────────────────────────────────
# Domain Info
# ──────────────────────────────────────────────────────────────────────────────

def print_domain_info(info: Dict[str, Any]):
    if not info:
        return

    console.rule("[bold cyan]Domain Overview[/bold cyan]")

    items = [
        f"[cyan]Domain:[/cyan]              {info.get('domain', 'N/A')}",
        f"[cyan]Functional Level:[/cyan]    {info.get('functional_level', 'N/A')}",
        f"[cyan]Machine Acct Quota:[/cyan]  {info.get('machine_account_quota', 'N/A')}",
        f"[cyan]Min Pwd Length:[/cyan]      {info.get('min_pwd_length', 'N/A')}",
        f"[cyan]Pwd History:[/cyan]         {info.get('pwd_history_length', 'N/A')}",
        f"[cyan]Lockout Threshold:[/cyan]   {info.get('lockout_threshold', 'N/A')} "
        + ("[bold red](NONE — spray freely)[/bold red]"
           if info.get("lockout_threshold") == 0 else ""),
    ]

    for item in items:
        console.print(f"  {item}")
    console.print()


# ──────────────────────────────────────────────────────────────────────────────
# Priority Hit List
# ──────────────────────────────────────────────────────────────────────────────

def print_priority_targets(targets: List[Dict], top: int = 15):
    console.rule("[bold red]⚡  Priority Attack Paths[/bold red]")

    if not targets:
        console.print("  [green]No attack paths identified.[/green]\n")
        return

    table = Table(
        box=box.ROUNDED,
        show_header=True,
        header_style="bold cyan",
        show_lines=True,
        expand=True,
    )
    table.add_column("#",        style="bold", width=3,  no_wrap=True)
    table.add_column("Target",   style="white",width=22, no_wrap=True)
    table.add_column("Attack",   width=32)
    table.add_column("Severity", width=10,     no_wrap=True)
    table.add_column("Score",    width=6,       no_wrap=True, justify="center")
    table.add_column("Reason",   width=38)
    table.add_column("Next Step",style="green", width=45)

    for i, t in enumerate(targets[:top], 1):
        sev   = t.get("severity", "INFO")
        color = {"CRITICAL": "red", "HIGH": "red", "MEDIUM": "yellow",
                 "LOW": "green", "INFO": "blue"}.get(sev, "white")
        table.add_row(
            str(i),
            t.get("target", ""),
            t.get("attack", ""),
            _sev(sev),
            f"[{color}]{t.get('priority', 0)}[/{color}]",
            t.get("reason", ""),
            t.get("next_step", "").split("\n")[0],
        )

    console.print(table)
    if len(targets) > top:
        console.print(f"  [dim]... and {len(targets) - top} more (use -o json for full output)[/dim]")
    console.print()


# ──────────────────────────────────────────────────────────────────────────────
# SPN / Kerberoast Results
# ──────────────────────────────────────────────────────────────────────────────

def print_spn_results(spns: List[Dict]):
    console.rule("[bold cyan]Kerberoastable Accounts[/bold cyan]")

    if not spns:
        console.print("  [green]No Kerberoastable accounts found.[/green]\n")
        return

    table = Table(box=box.SIMPLE_HEAD, header_style="bold cyan", show_lines=False)
    table.add_column("Account",     width=25)
    table.add_column("SPN Types",   width=22)
    table.add_column("Pwd Age",     width=12, justify="right")
    table.add_column("RC4",         width=6,  justify="center")
    table.add_column("Admin",       width=7,  justify="center")
    table.add_column("Score",       width=6,  justify="center")
    table.add_column("Description", width=30)

    for s in spns:
        age = f"{s['password_age_days']}d" if s.get("password_age_days") else "[red]Never[/red]"
        rc4 = "[red]YES[/red]" if s.get("rc4_allowed") else "[green]no[/green]"
        adm = "[bold red]YES[/bold red]" if s.get("is_admin") else "no"
        sc  = s.get("crack_score", 0)
        sc_color = "red" if sc >= 70 else "yellow" if sc >= 40 else "green"

        table.add_row(
            s["account"],
            ", ".join(spn.split("/")[0] for spn in s.get("spns", [])),
            age,
            rc4, adm,
            f"[{sc_color}]{sc}[/{sc_color}]",
            s.get("description", "")[:30],
        )

    console.print(table)
    console.print()


# ──────────────────────────────────────────────────────────────────────────────
# AS-REP Results
# ──────────────────────────────────────────────────────────────────────────────

def print_asrep_results(users: List[Dict]):
    console.rule("[bold cyan]AS-REP Roastable Accounts[/bold cyan]")

    if not users:
        console.print("  [green]No AS-REP Roastable accounts found.[/green]\n")
        return

    table = Table(box=box.SIMPLE_HEAD, header_style="bold cyan")
    table.add_column("Account",     width=25)
    table.add_column("Admin",       width=7, justify="center")
    table.add_column("Description", width=45)

    for u in users:
        adm = "[bold red]YES[/bold red]" if u.get("is_admin") else "no"
        table.add_row(u["account"], adm, u.get("description", ""))

    console.print(table)
    console.print()


# ──────────────────────────────────────────────────────────────────────────────
# Delegation Results
# ──────────────────────────────────────────────────────────────────────────────

def print_delegation_results(delegations: Dict):
    console.rule("[bold cyan]Kerberos Delegation[/bold cyan]")

    unc = delegations.get("unconstrained", [])
    con = delegations.get("constrained", [])
    rbc = delegations.get("rbcd", [])

    if not unc and not con and not rbc:
        console.print("  [green]No delegation misconfigurations found.[/green]\n")
        return

    if unc:
        console.print(f"  [bold red]Unconstrained Delegation ({len(unc)} host(s)):[/bold red]")
        for d in unc:
            console.print(f"    [red]•[/red] {d['account']} [{d['type']}]  {d.get('dns_name', '')}")
        console.print()

    if con:
        console.print(f"  [bold yellow]Constrained Delegation ({len(con)} account(s)):[/bold yellow]")
        for d in con:
            pt = "[red](S4U2Self ENABLED)[/red]" if d["protocol_transition"] else ""
            console.print(f"    [yellow]•[/yellow] {d['account']}  {pt}")
            for spn in d.get("allowed_to", [])[:3]:
                console.print(f"        → {spn}")
        console.print()

    if rbc:
        console.print(f"  [bold yellow]RBCD Configured ({len(rbc)} target(s)):[/bold yellow]")
        for d in rbc:
            console.print(f"    [yellow]•[/yellow] {d['target']}  {d.get('dns_name', '')}")
        console.print()


# ──────────────────────────────────────────────────────────────────────────────
# CVE Results
# ──────────────────────────────────────────────────────────────────────────────

def print_cve_results(results: list):
    console.rule("[bold red]CVE / Misconfiguration Checks[/bold red]")

    if not results:
        console.print("  [dim]No CVE checks were run.[/dim]\n")
        return

    table = Table(box=box.ROUNDED, header_style="bold cyan", show_lines=True, expand=True)
    table.add_column("CVE / Finding",  width=28)
    table.add_column("Name",           width=32)
    table.add_column("Severity",       width=10, no_wrap=True)
    table.add_column("Vulnerable",     width=10, justify="center")
    table.add_column("Detail",         width=50)

    for r in results:
        table.add_row(
            r.cve_id,
            r.name,
            _sev(r.severity.value),
            VULN_COLORS[r.vulnerable],
            r.reason[:100],
        )

    console.print(table)

    # Print next steps for vulnerable findings
    vuln = [r for r in results if r.vulnerable]
    if vuln:
        console.print("\n  [bold red]Exploitation paths for vulnerable findings:[/bold red]")
        for r in vuln:
            if r.next_step:
                console.print(f"\n  [bold cyan]{r.cve_id}[/bold cyan]")
                for line in r.next_step.strip().split("\n"):
                    console.print(f"    [green]{line}[/green]")
    console.print()


# ──────────────────────────────────────────────────────────────────────────────
# User / Policy Results
# ──────────────────────────────────────────────────────────────────────────────

def print_user_results(user_data: Dict):
    console.rule("[bold cyan]Domain User Analysis[/bold cyan]")

    # Password policy risks
    policy = user_data.get("password_policy", {})
    risks  = policy.get("risks", [])
    if risks:
        console.print("  [bold yellow]Password Policy Risks:[/bold yellow]")
        for r in risks:
            console.print(f"    [red]![/red] {r}")
        console.print()

    # Privileged users
    priv = user_data.get("privileged_users", [])
    if priv:
        console.print(f"  [bold yellow]Privileged Accounts (adminCount=1): {len(priv)}[/bold yellow]")
        for u in priv[:10]:
            pwd_flag = " [red](pwd never expires)[/red]" if u.get("password_never_expires") else ""
            console.print(f"    [cyan]•[/cyan] {u['account']}{pwd_flag}")
        if len(priv) > 10:
            console.print(f"    [dim]... and {len(priv) - 10} more[/dim]")
        console.print()

    # DnsAdmins
    dns = user_data.get("dns_admins", [])
    if dns:
        console.print(f"  [bold red]DnsAdmins Members ({len(dns)}) — can load DLL on DC as SYSTEM:[/bold red]")
        for u in dns:
            console.print(f"    [red]•[/red] {u['account']}")
        console.print()

    # Stale accounts
    stale = user_data.get("stale_accounts", [])
    if stale:
        console.print(f"  [bold yellow]Stale Accounts (no logon since ~2020): {len(stale)}[/bold yellow]")
        for u in stale[:5]:
            console.print(f"    [yellow]•[/yellow] {u['account']}  last: {u.get('last_logon', 'N/A')}")
        if len(stale) > 5:
            console.print(f"    [dim]... and {len(stale) - 5} more[/dim]")
        console.print()

    # Domain trusts
    trusts = user_data.get("trusts", [])
    if trusts:
        console.print(f"  [bold yellow]Domain Trusts ({len(trusts)}):[/bold yellow]")
        for t in trusts:
            risk_col = "red" if t["risk"] == "HIGH" else "yellow"
            console.print(
                f"    [{risk_col}]•[/{risk_col}] {t['trusted_domain']}  "
                f"[{t['direction']}]  SID filtering: "
                + ("[green]ON[/green]" if t.get("sid_filtering") else "[red]OFF[/red]")
            )
        console.print()

    # LAPS
    laps = user_data.get("laps_deployed", {})
    if laps:
        laps_color = "green" if laps.get("deployed") else "red"
        console.print(
            f"  LAPS: [{laps_color}]{laps.get('detail', 'Unknown')}[/{laps_color}]\n"
        )


# ──────────────────────────────────────────────────────────────────────────────
# Encryption Audit Results
# ──────────────────────────────────────────────────────────────────────────────

def print_enc_audit_results(audit):
    console.rule("[bold cyan]Kerberos Encryption Audit[/bold cyan]")

    if not audit:
        console.print("  [dim]Encryption audit skipped.[/dim]\n")
        return

    if audit.des_accounts:
        console.print(f"  [bold red]DES Encryption ({len(audit.des_accounts)} account(s)) — CRITICAL:[/bold red]")
        for a in audit.des_accounts[:5]:
            console.print(f"    [red]![/red] {a.account}  ({', '.join(a.enc_types)})")
        if len(audit.des_accounts) > 5:
            console.print(f"    [dim]... and {len(audit.des_accounts) - 5} more[/dim]")
        console.print()

    if audit.rc4_only_accounts:
        console.print(f"  [bold yellow]RC4-Only Accounts ({len(audit.rc4_only_accounts)}):[/bold yellow]")
        for a in audit.rc4_only_accounts[:5]:
            console.print(f"    [yellow]![/yellow] {a.account}  ({', '.join(a.enc_types)})")
        if len(audit.rc4_only_accounts) > 5:
            console.print(f"    [dim]... and {len(audit.rc4_only_accounts) - 5} more[/dim]")
        console.print()

    if audit.weak_dcs:
        console.print(f"  [bold red]DCs with RC4 Enabled ({len(audit.weak_dcs)}):[/bold red]")
        for dc in audit.weak_dcs:
            console.print(f"    [red]![/red] {dc.account}  ({', '.join(dc.enc_types)})")
        console.print()

    if not audit.des_accounts and not audit.rc4_only_accounts and not audit.weak_dcs:
        console.print("  [green]No weak encryption configurations found.[/green]\n")


# ──────────────────────────────────────────────────────────────────────────────
# Domain Trust Results
# ──────────────────────────────────────────────────────────────────────────────

def print_trust_results(trusts):
    console.rule("[bold cyan]Domain Trusts[/bold cyan]")

    if not trusts:
        console.print("  [green]No domain trusts found.[/green]\n")
        return

    table = Table(box=box.SIMPLE_HEAD, header_style="bold cyan")
    table.add_column("Trust Partner", width=30)
    table.add_column("Direction",     width=25)
    table.add_column("Type",          width=20)
    table.add_column("SID Filtering", width=14, justify="center")
    table.add_column("Risk",          width=10)

    for t in trusts:
        risk_color = {"CRITICAL": "red", "HIGH": "red", "MEDIUM": "yellow",
                      "LOW": "green", "INFO": "blue"}.get(t.risk, "white")
        sid = "[green]ON[/green]" if t.sid_filtering else "[red]OFF[/red]"
        table.add_row(
            t.trust_partner,
            t.direction,
            t.trust_type,
            sid,
            f"[{risk_color}]{t.risk}[/{risk_color}]",
        )

    console.print(table)
    if any(t.note for t in trusts):
        for t in trusts:
            if t.note and t.risk in ("CRITICAL", "HIGH"):
                console.print(f"  [red]![/red] {t.trust_partner}: {t.note}")
    console.print()


# ──────────────────────────────────────────────────────────────────────────────
# Summary footer
# ──────────────────────────────────────────────────────────────────────────────

def print_summary(targets: List[Dict], cve_results: list):
    vuln_cves   = sum(1 for r in cve_results if r.vulnerable)
    critical    = sum(1 for t in targets if t.get("severity") == "CRITICAL")
    high        = sum(1 for t in targets if t.get("severity") == "HIGH")

    console.rule("[bold cyan]Scan Summary[/bold cyan]")
    console.print(
        f"  Attack paths identified:  [bold]{len(targets)}[/bold]  "
        f"([red]CRITICAL: {critical}[/red]  [yellow]HIGH: {high}[/yellow])\n"
        f"  Vulnerable CVEs found:    [bold red]{vuln_cves}[/bold red]\n"
    )
    if targets:
        top = targets[0]
        console.print(
            f"  [bold]Recommended first move:[/bold] "
            f"[cyan]{top['attack']}[/cyan] against [white]{top['target']}[/white]\n"
            f"  [green]{top.get('next_step', '').split(chr(10))[0]}[/green]\n"
        )


# ──────────────────────────────────────────────────────────────────────────────
# Hygiene Audit Results
# ──────────────────────────────────────────────────────────────────────────────

def print_hygiene_results(hygiene):
    console.rule("[bold cyan]Defensive Hygiene Audit[/bold cyan]")

    if not hygiene:
        console.print("  [dim]Hygiene audit skipped.[/dim]\n")
        return

    # ── krbtgt Password Age ──
    krb = hygiene.krbtgt_age
    if krb:
        risk_col = {"CRITICAL": "red", "HIGH": "red", "MEDIUM": "yellow", "LOW": "green"}.get(krb.get("risk"), "white")
        console.print(f"  [{risk_col}]krbtgt:[/{risk_col}] {krb.get('detail', 'N/A')}")
        if krb.get("risk") in ("CRITICAL", "HIGH"):
            console.print("    [green]Remediation: Reset krbtgt password TWICE (with replication interval between resets)[/green]")
        console.print()

    # ── LAPS Coverage ──
    laps = hygiene.laps_coverage
    if laps:
        risk_col = {"CRITICAL": "red", "HIGH": "red", "MEDIUM": "yellow", "LOW": "green"}.get(laps.get("risk"), "white")
        console.print(f"  [{risk_col}]LAPS Coverage:[/{risk_col}] {laps.get('detail', 'N/A')}")
        if laps.get("risk") in ("CRITICAL", "HIGH"):
            console.print("    [green]Remediation: Deploy LAPS via GPO to all workstations and member servers[/green]")
        console.print()

    # ── FGPP ──
    fgpp = hygiene.fgpp_audit
    if fgpp:
        risk_col = {"CRITICAL": "red", "HIGH": "red", "MEDIUM": "yellow", "LOW": "green"}.get(fgpp.get("risk"), "white")
        console.print(f"  [{risk_col}]Fine-Grained Password Policies:[/{risk_col}] {fgpp.get('detail', 'N/A')}")
        if fgpp.get("policies"):
            for p in fgpp["policies"]:
                console.print(
                    f"    [cyan]•[/cyan] {p['name']}  min_length={p['min_length']}  "
                    f"complexity={p['complexity_enabled']}  lockout={p['lockout_threshold']}  "
                    f"applies_to={len(p['applies_to'])} object(s)"
                )
        if not fgpp.get("privileged_covered"):
            console.print("    [green]Remediation: Create a strict FGPP (15+ chars, lockout) targeting Domain Admins and Enterprise Admins[/green]")
        console.print()

    # ── SID History ──
    sid = hygiene.sid_history
    if sid:
        console.print(f"  [bold red]SID History Findings ({len(sid)}):[/bold red]")
        for s in sid[:10]:
            risk_col = "red" if s["risk"] == "CRITICAL" else "yellow"
            console.print(f"    [{risk_col}]![/{risk_col}] {s['account']}  {s['detail']}")
        if len(sid) > 10:
            console.print(f"    [dim]... and {len(sid) - 10} more[/dim]")
        console.print("    [green]Remediation: Clear SID History on migrated accounts; investigate same-domain SIDs for backdoors[/green]")
        console.print()

    # ── AdminSDHolder Orphans ──
    orphans = hygiene.adminsdholder_orphans
    if orphans:
        console.print(f"  [bold yellow]AdminSDHolder Orphans ({len(orphans)}):[/bold yellow]")
        for o in orphans[:10]:
            console.print(f"    [yellow]![/yellow] {o['account']}  — {o['detail']}")
        if len(orphans) > 10:
            console.print(f"    [dim]... and {len(orphans) - 10} more[/dim]")
        console.print("    [green]Remediation: Clear adminCount flag on accounts no longer in protected groups[/green]")
        console.print()

    # ── Credential Exposure ──
    creds = hygiene.credential_exposure
    if creds:
        console.print(f"  [bold red]Credentials in AD Attributes ({len(creds)}):[/bold red]")
        for c in creds[:10]:
            risk_col = "red" if c["risk"] == "CRITICAL" else "yellow"
            console.print(f"    [{risk_col}]![/{risk_col}] {c['account']}  ({c['field']} field)  {c['detail']}")
        if len(creds) > 10:
            console.print(f"    [dim]... and {len(creds) - 10} more[/dim]")
        console.print("    [green]Remediation: Remove credentials from AD description/info attributes immediately[/green]")
        console.print()

    # ── PrimaryGroupId ──
    pgid = hygiene.primary_group_abuse
    if pgid:
        console.print(f"  [bold yellow]Non-Default PrimaryGroupId ({len(pgid)}):[/bold yellow]")
        for p in pgid[:10]:
            risk_col = "red" if p["risk"] == "HIGH" else "yellow"
            console.print(f"    [{risk_col}]![/{risk_col}] {p['account']}  {p['detail']}")
        if len(pgid) > 10:
            console.print(f"    [dim]... and {len(pgid) - 10} more[/dim]")
        console.print("    [green]Remediation: Reset primaryGroupId to 513 (Domain Users) unless explicitly required[/green]")
        console.print()

    # ── Stale Computers ──
    stale = hygiene.stale_computers
    if stale:
        console.print(f"  [bold yellow]Stale Computer Accounts ({len(stale)}):[/bold yellow]")
        for s in stale[:10]:
            console.print(f"    [yellow]•[/yellow] {s['account']}  ({s['os']})  inactive {s['last_logon_days']}d")
        if len(stale) > 10:
            console.print(f"    [dim]... and {len(stale) - 10} more[/dim]")
        console.print("    [green]Remediation: Disable and move stale computer accounts to a quarantine OU[/green]")
        console.print()

    # ── Privileged Group Breakdown ──
    groups = hygiene.privileged_groups
    if groups:
        console.print(f"  [bold cyan]Privileged Group Membership Breakdown:[/bold cyan]")
        table = Table(box=box.SIMPLE_HEAD, header_style="bold cyan")
        table.add_column("Group", width=30)
        table.add_column("Members", width=8, justify="center")
        table.add_column("Nested Groups", width=14, justify="center")
        table.add_column("Direct Users", width=30)

        for group_name, members in sorted(groups.items()):
            nested = sum(1 for m in members if m["is_nested_group"])
            direct = [m["account"] for m in members if not m["is_nested_group"]]
            direct_str = ", ".join(direct[:5])
            if len(direct) > 5:
                direct_str += f" +{len(direct) - 5}"
            table.add_row(group_name, str(len(members)), str(nested), direct_str)

        console.print(table)
        console.print()

    # ── Service Account Hygiene ──
    svc = hygiene.service_acct_hygiene
    if svc:
        console.print(f"  [bold yellow]Service Account Password Issues ({len(svc)}):[/bold yellow]")
        for s in svc[:10]:
            risk_col = {"CRITICAL": "red", "HIGH": "red", "MEDIUM": "yellow", "LOW": "green"}.get(s["risk"], "white")
            console.print(f"    [{risk_col}]![/{risk_col}] {s['account']}  {s['detail']}")
        if len(svc) > 10:
            console.print(f"    [dim]... and {len(svc) - 10} more[/dim]")
        console.print("    [green]Remediation: Rotate service account passwords; consider gMSA for automated rotation[/green]")
        console.print()

    # ── Hygiene Score ──
    total = hygiene.finding_count()
    if total == 0:
        console.print("  [bold green]All hygiene checks passed — no findings.[/bold green]\n")
    else:
        console.print(f"  [bold]Total hygiene findings requiring attention: {total}[/bold]\n")

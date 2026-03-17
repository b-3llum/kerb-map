# kerb-map Wiki

<table align="center"><tr><td align="center">

![kerb-map](https://raw.githubusercontent.com/b-3llum/kerb-map/main/assets/banner.png)

</td></tr></table>

**Kerberos Attack Surface Mapper** — Active Directory enumeration, CVE detection, and ranked attack path generation for authorised penetration testing engagements.

---

## Wiki Pages

| Page | Description |
|---|---|
| [Home](Home) | This page — overview and navigation |
| [Installation & Setup](Installation-and-Setup) | All install methods, dependencies, first run |
| [Authentication](Authentication) | Password, Pass-the-Hash, Kerberos ccache |
| [Module Reference](Module-Reference) | Deep dive into every scan module |
| [CVE Detection](CVE-Detection) | Every CVE check explained with exploitation paths |
| [Scoring Engine](Scoring-Engine) | How findings are ranked and prioritised |
| [Output & Reporting](Output-and-Reporting) | Terminal output, JSON, BloodHound, SQLite cache |
| [AD Pentest Methodology](AD-Pentest-Methodology) | Full AD attack chain from recon to DA |
| [Detection & Evasion](Detection-and-Evasion) | Noise profile, evasion techniques, stealth mode |
| [Tooling Comparisons](Tooling-Comparisons) | kerb-map vs nxc, BloodHound, impacket, PowerView |
| [Real Lab Examples](Real-Lab-Examples) | End-to-end walkthroughs against lab environments |
| [Extending kerb-map](Extending-kerb-map) | Writing custom modules and CVE checks |
| [Flag Reference](Flag-Reference) | Complete CLI flag reference |

---

## What is kerb-map?

kerb-map is a post-exploitation Active Directory enumeration tool written in Python. It is designed for penetration testers and red team operators conducting authorised assessments against Windows domain environments.

### The Problem It Solves

A typical AD assessment involves running many separate tools in sequence:

```bash
# The old way — manual, fragmented, no prioritisation
GetUserSPNs.py corp.local/user:pass          # Kerberoastable accounts
GetNPUsers.py corp.local/ -no-pass           # AS-REP roastable
bloodhound-python -d corp.local ...          # Delegation mapping
crackmapexec smb ... --users                 # User enumeration
# Then manually correlate everything...
```

kerb-map consolidates all of this into a single authenticated LDAP session and adds a scoring engine that cross-correlates every finding to tell you exactly what to attack first and how.

```bash
# The kerb-map way
kerb-map -d corp.local -dc 192.168.1.10 -u jsmith -p Password123 --all --cves
```

Output: a ranked priority table with pre-filled exploit commands, ready to execute.

### Design Philosophy

1. **Safe by default** — All enumeration is read-only LDAP. Nothing is modified. RPC probes that generate Windows events are hidden behind `--aggressive`.
2. **Tell you what to do next** — Every finding includes the exact command to run for exploitation.
3. **Build on what exists** — kerb-map orchestrates impacket and ldap3 rather than reimplementing protocols. The value is in the scoring and correlation layer.
4. **Operator workflow first** — Output is designed to be read quickly under time pressure, not academic.

### Architecture Overview

```
┌─────────────────────────────────────────────────────────┐
│                      kerb-map                           │
│                                                         │
│  kerb-map.py / kerb_map/cli.py (CLI + argparse)         │
│       │                                                 │
│       ▼                                                 │
│  LDAPClient ──── Single authenticated session           │
│       │                                                 │
│       ├──► SPNScanner        (Kerberoast surface)       │
│       ├──► ASREPScanner      (no-preauth accounts)      │
│       ├──► DelegationMapper  (all 3 types)              │
│       ├──► UserEnumerator    (policy, trusts, LAPS)     │
│       └──► CVEScanner        (6 CVE/misconfiguration)   │
│                │                                        │
│                ▼                                        │
│           Scorer  ──── cross-correlates everything      │
│                │                                        │
│                ▼                                        │
│        Priority Hit List + Next Steps                   │
│                │                                        │
│                ├──► Rich terminal output                │
│                ├──► JSON export                         │
│                ├──► BloodHound export                   │
│                └──► SQLite cache                        │
└─────────────────────────────────────────────────────────┘
```

### Entry Point Structure

```
kerb-map/
├── kerb-map.py          ← Direct script usage (python kerb-map.py ...)
├── pyproject.toml       ← pip/pipx entry: kerb_map.main:main
└── kerb_map/
    ├── main.py          ← Delegates to cli.py (pip/pipx entry point)
    ├── cli.py           ← Full CLI logic
    └── __main__.py      ← Enables python -m kerb_map
```

---

## Quick Start

```bash
# Install
git clone https://github.com/b-3llum/kerb-map /opt/kerb-map
sudo chown -R $(whoami) /opt/kerb-map   # if cloned with sudo
pipx install /opt/kerb-map

# Basic scan
kerb-map -d corp.local -dc 192.168.1.10 -u jsmith -p Password123

# Full scan with CVEs
kerb-map -d corp.local -dc 192.168.1.10 -u jsmith -p Password123 --all --cves --aggressive -o json
```

---

## Legal Notice

kerb-map is intended exclusively for use in **authorised** security assessments. Use against systems without explicit written permission is illegal. The author assumes no liability for misuse.

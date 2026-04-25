# kerb-map

![kerb-map](https://raw.githubusercontent.com/b-3llum/kerb-map/main/assets/banner.png)

**Active Directory Kerberos Attack Surface Mapper**

![version](https://img.shields.io/badge/version-1.2.0-blue)
![python](https://img.shields.io/badge/python-3.10+-blue)
![platform](https://img.shields.io/badge/platform-Linux-lightgrey)
![license](https://img.shields.io/badge/license-MIT-lightgrey)
[![Manual](https://img.shields.io/badge/Manual-View%20Online-blue)](https://docs.google.com/viewer?url=https://raw.githubusercontent.com/b-3llum/kerb-map/main/kerb-map-manual.docx)
---

## Overview

**kerb-map** is a post-initial-access Active Directory enumeration tool that consolidates every Kerberos-related attack surface into a single authenticated scan session. Rather than running a collection of impacket scripts manually, kerb-map produces a **ranked, prioritised attack path list** with the exact next command to execute — bridging the gap between enumeration and exploitation.

All LDAP queries are read-only. RPC-based CVE probes that generate Windows events are gated behind an explicit `--aggressive` flag.

---

## Modules

### Legacy modules (single LDAP scan)

    --spn          Kerberoastable account discovery & scoring
    --asrep        AS-REP roastable accounts (no creds needed)
    --delegation   Unconstrained / Constrained / RBCD mapping
    --users        Privileged users, policy, DnsAdmins, LAPS
    --encryption   Weak Kerberos encryption audit (RC4/DES)
    --trusts       Domain trust mapping & risk assessment
    --cves         CVE detection (ZeroLogon, noPac, ESC1-8, Certifried...)
    --hygiene      Defensive posture audit (krbtgt age, LAPS coverage,
                   SID History, FGPP, credential exposure, stale machines...)

### v2 plugin modules (`--v2`, auto-discovered)

    DCSync rights              non-default Get-Changes(-All) holders on the domain root
    Shadow Credentials         msDS-KeyCredentialLink writers + KCL inventory
    BadSuccessor               dMSA predecessor-link abuse (CVE-2025-53779)
    Pre-Win2k Compatible Access  Authenticated Users membership in S-1-5-32-554
    GMSA / dMSA + KDS root key   Golden dMSA prereq (Semperis, July 2025)
    Tier-0 ACL audit           DACL walk on AdminSDHolder, DA/EA/SA, adminCount=1
    User ACL audit             lateral edges on every enabled non-Tier-0 user
    OU computer-create         RBCD pivot survival check (post-MAQ=0)
    AD CS Extended             ESC4 / ESC5 / ESC7 / ESC9 / ESC13 / ESC15 (EKUwu)
    Coercion module            PetitPotam / DFSCoerce / PrinterBug surface

### No-creds modules (no `-u`/`-p` needed)

    --timeroast                MS-SNTP machine-account hash recovery (Tervoort)
    --spray                    Lockout-aware password spray (gated, confirms)

### Output

    -o json                    Full structured dump
    -o bloodhound-ce           Real BloodHound CE 5.x ingestible zip + KerbMap edges
    -o csv                     One row per priority target (spreadsheet)
    -o markdown                Operator report (drops into Obsidian)
    -o bloodhound-lite         Legacy custom JSON shape (NOT BH-ingestible)

### Other

    --aggressive               Enable RPC probes (louder — Event 5145)
    --diff <A> <B>             Diff two cached scans (REMOVED / ADDED / UNCHANGED)
    --resume <ID>              Continue an interrupted scan
    --list-resumable           Show in-progress scans

---

## Installation

### Prerequisites
- Python 3.10 or higher
- Network access to TCP 389 (LDAP) on the Domain Controller
- TCP 135 + named pipes required only for `--aggressive` CVE probes

---

### Option A — pipx (recommended)

Installs kerb-map into an isolated virtualenv and exposes the `kerb-map` command globally from any directory.

```bash
# Install pipx if not already present
sudo apt install pipx       # Debian / Kali
sudo pacman -S python-pipx  # Arch
pipx ensurepath

# Clone and install
git clone https://github.com/b-3llum/kerb-map ~/kerb-map
pipx install ~/kerb-map

# Reload shell
source ~/.zshrc   # or ~/.bashrc

# Verify
kerb-map --help
```

> **Note:** If pipx fails due to impacket dependency conflicts, use Option B below.

---

### Option B — shell wrapper (simplest)

```bash
git clone https://github.com/b-3llum/kerb-map ~/kerb-map
pip install -r ~/kerb-map/requirements.txt

sudo bash -c 'printf "#!/usr/bin/env bash\nexec python ~/kerb-map/kerb-map.py \"\$@\"\n" \
  > /usr/local/bin/kerb-map'
sudo chmod +x /usr/local/bin/kerb-map
```

---

### Option C — symlink

```bash
chmod +x ~/kerb-map/kerb-map.py
sudo ln -s ~/kerb-map/kerb-map.py /usr/local/bin/kerb-map
```

---

## Usage

### Authentication

```bash
# Password (interactive prompt — recommended on shared hosts)
kerb-map -d corp.local -dc 192.168.1.10 -u jsmith -p

# Password from stdin (avoids ps aux / shell history exposure)
kerb-map -d corp.local -dc 192.168.1.10 -u jsmith --password-stdin <<< 'Password123'

# Password from environment variable
export KERB_PW='Password123'
kerb-map -d corp.local -dc 192.168.1.10 -u jsmith --password-env KERB_PW

# Password on the command line (legacy — leaks via ps aux on shared hosts)
kerb-map -d corp.local -dc 192.168.1.10 -u jsmith -p Password123

# Pass-the-Hash (LM:NT or NT only) — same -H / --hash-stdin / --hash-env options
kerb-map -d corp.local -dc 192.168.1.10 -u jsmith -H <NT_HASH>

# Kerberos ccache
export KRB5CCNAME=/tmp/jsmith.ccache
kerb-map -d corp.local -dc 192.168.1.10 -u jsmith -k
```

> **Avoid `-p Password123` on shared hosts.** The full command line is visible
> in `ps aux`, shell history (`~/.bash_history`), and audit logs. Use
> `--password-stdin`, `--password-env`, or omit the value to be prompted.

### Common Examples

```bash
# Full scan — all modules + v2 plugin contract
kerb-map -d corp.local -dc 192.168.1.10 -u jsmith -p Password123 --all --v2

# Full scan + aggressive RPC CVE probes + BloodHound CE export
kerb-map -d corp.local -dc 192.168.1.10 -u jsmith -p Password123 \
    --all --v2 --aggressive -o bloodhound-ce --outfile scan.bh.zip

# Stealth mode — LDAP jitter, no RPC probes
kerb-map -d corp.local -dc 192.168.1.10 -u jsmith -p Password123 --stealth

# CVE checks only, just one CVE family
kerb-map -d corp.local -dc 192.168.1.10 -u jsmith -p Password123 \
    --cves --only-cves CVE-2021-42278/42287

# Markdown operator report
kerb-map -d corp.local -dc 192.168.1.10 -u jsmith -p Password123 \
    --all --v2 -o markdown

# Resume an interrupted scan
kerb-map --list-resumable
kerb-map -d corp.local -dc 192.168.1.10 -u jsmith -p Password123 --resume <id>

# Diff two scans (retest workflow)
kerb-map --diff 5 7
```

### No-creds workflows

```bash
# Timeroast — recover machine-account NT hashes via MS-SNTP (no creds)
kerb-map --timeroast -dc 192.168.1.10 \
    --timeroast-rids 1000-2000 --timeroast-out hashes.txt
# Crack with: hashcat -m 31300 hashes.txt rockyou.txt

# Password spray — lockout-aware, requires confirmation
kerb-map --spray -d corp.local -dc 192.168.1.10 -u <known> -p <known> \
    --spray-yes        # skip confirm; for scripted runs
# Or with a pre-built user list (no LDAP discovery needed):
kerb-map --spray -d corp.local -dc 192.168.1.10 \
    --spray-users-file users.txt --spray-passwords-file pw.txt
```

### Verbosity & log capture

```bash
# Quiet: only WARN+ — for cron / log capture
kerb-map -d corp.local -dc 192.168.1.10 -u jsmith -p Password123 -q

# Verbose: per-module debug detail
kerb-map -d corp.local -dc 192.168.1.10 -u jsmith -p Password123 -v

# Wire view: raw LDAP filter logging on every search
kerb-map -d corp.local -dc 192.168.1.10 -u jsmith -p Password123 -vv

# Disable colour for tee logfile.txt
kerb-map -d corp.local -dc 192.168.1.10 -u jsmith -p Password123 \
    --no-color | tee scan.log

# View stored scan history (now with severity histogram + duration)
kerb-map --list-scans
kerb-map --show-scan 3
```

### Full Flag Reference

#### Target / auth

| Flag | Description |
|---|---|
| `-d / --domain` | Target domain (e.g. corp.local) |
| `-dc / --dc-ip` | Domain controller IP |
| `-u / --username` | Domain username |
| `-p / --password [VALUE]` | Plaintext password — omit value to prompt |
| `--password-stdin` | Read password from stdin (recommended) |
| `--password-env VAR` | Read password from environment variable |
| `-H / --hash [VALUE]` | NTLM hash — LM:NT or NT only |
| `--hash-stdin` / `--hash-env VAR` | Same alternatives for the hash |
| `-k / --kerberos` | Use ccache ticket (set KRB5CCNAME first) |

#### Module selection

| Flag | Description |
|---|---|
| `--all` | Run all legacy modules (default) |
| `--spn / --asrep / --delegation / --users / --cves` | Run specific legacy modules |
| `--encryption / --trusts / --hygiene` | Per-module legacy flags |
| `--v2` | Enable v2 plugin modules (DCSync, Shadow Creds, BadSuccessor, Tier-0 ACL, User ACL, OU computer-create, ADCS Extended, GMSA/dMSA, Pre-Win2k, Coercion) |
| `--aggressive` | Enable RPC CVE probes — generates Event 5145 |
| `--list-cves` | Print every CVE check (with CVE-ID + aggressive flag) and exit |
| `--only-cves IDS` | Run only the named CVE checks (comma-separated) |

#### No-creds attacks (no `-u`/`-p` needed)

| Flag | Description |
|---|---|
| `--timeroast` | MS-SNTP machine-account hash recovery (Tervoort/Secura) |
| `--timeroast-rids START-END` | RID range to sweep (default 1000–1500) |
| `--timeroast-rate N` | Packets/sec rate cap (default 180 — Tervoort default) |
| `--timeroast-timeout N` | Per-RID socket timeout in seconds |
| `--timeroast-out FILE` | Append captured hashes to FILE |
| `--spray` | Lockout-aware password spray (gated, requires confirmation) |
| `--spray-users-file FILE` | Spray against SAMs from FILE instead of running ASREP first |
| `--spray-passwords-file FILE` | Use FILE instead of built-in season+year/domain+year wordlist |
| `--spray-rate N` | Seconds between bind attempts (default 1.0) |
| `--spray-yes` | Skip confirmation prompt (for scripted runs) |

#### Output / verbosity

| Flag | Description |
|---|---|
| `-o {json, bloodhound-ce, bloodhound-lite, csv, markdown}` | File output format |
| `--outfile NAME` | Custom output filename |
| `--top N` | Show top N priority targets (default 15) |
| `-v / --verbose` (count) | `-v` adds debug, `-vv` adds raw LDAP filter logging |
| `-q / --quiet` | Only WARN+ — for cron / log capture |
| `--no-color` | Disable ANSI for `tee logfile.txt` workflows |

#### Tuning / transport

| Flag | Description |
|---|---|
| `--stealth` | Add random jitter between LDAP queries |
| `--timeout N` | LDAP connection timeout in seconds (default: 10) |
| `--ldaps / --starttls / --no-tls` | Pin a single LDAP transport (default: LDAPS → StartTLS → SASL → plain) |

#### Scan history & resume

| Flag | Description |
|---|---|
| `--no-cache` | Do not save to local SQLite database |
| `--list-scans` | List cached scans (with severity counts + duration) |
| `--show-scan ID` | Replay findings from a stored scan |
| `--diff A B` | Diff two cached scans (REMOVED / ADDED / UNCHANGED) |
| `--resume ID` | Continue an interrupted scan |
| `--list-resumable` | Show in-progress scans that can be resumed |

#### Maintenance

| Flag | Description |
|---|---|
| `--update` | Pull latest version + reinstall (refuses on dirty tree / detached HEAD) |
| `--update --tag REF` | Pin to a release tag |
| `--update --force` | Bypass dirty-tree / detached-HEAD precheck |

---

## Detection Profile

| Module | Noise | Event IDs | MDI Detection |
|---|---|---|---|
| LDAP enumeration (all safe checks) | LOW | 1644 (if diag logging on) | No |
| Encryption / Trust / Hygiene audits | LOW | 1644 | No |
| GPP Passwords (MS14-025) | LOW | 1644 | No |
| Bronze Bit / Certifried / LDAP Signing | LOW | 1644 | No |
| All v2 plugin modules (DCSync rights, Tier-0 ACL, User ACL, OU computer-create, Shadow Creds, ADCS Extended, GMSA/dMSA, BadSuccessor, Pre-Win2k, Coercion) | LOW | 1644 | No |
| Timeroast (MS-SNTP, no creds) | LOW | NTP request anomaly only | No |
| Kerberoasting w/ AES tickets | MEDIUM | 4769 per ticket | Possible |
| Kerberoasting w/ RC4 tickets | HIGH | 4769 (enc type 0x17) | Yes |
| Password spray (`--spray`) | HIGH | 4625 per failed bind | Yes |
| ZeroLogon RPC probe | HIGH | 5827 / 5828 | Yes |
| PrintNightmare pipe probe | HIGH | 5145 | Yes |
| PetitPotam EFS probe | HIGH | 5145 | Yes |

> **Note:** The `--aggressive` flag enables all HIGH-noise RPC probes. Only use it when your engagement scope explicitly permits noisy testing.

---

## Legal

kerb-map is designed exclusively for use in **authorised** penetration testing engagements and red team operations where written permission has been obtained from the system owner.

Use against systems for which you do not have explicit written authorisation is illegal under the Computer Fraud and Abuse Act (CFAA), the UK Computer Misuse Act, and equivalent legislation worldwide. The author assumes no liability for misuse.

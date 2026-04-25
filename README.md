# kerb-map

![kerb-map](https://raw.githubusercontent.com/b-3llum/kerb-map/main/assets/banner.png)

**Active Directory Kerberos Attack Surface Mapper**

![version](https://img.shields.io/badge/version-1.1.0-blue)
![python](https://img.shields.io/badge/python-3.10+-blue)
![platform](https://img.shields.io/badge/platform-Linux-lightgrey)
![license](https://img.shields.io/badge/license-MIT-lightgrey)
[![Manual](https://img.shields.io/badge/Manual-View%20Online-blue)](https://docs.google.com/viewer?url=https://raw.githubusercontent.com/b-3llum/kerb-map/main/kerb-map-manual.docx)
---

## Overview

**kerb-map** is a post-initial-access Active Directory enumeration tool that consolidates every Kerberos-related attack surface into a single authenticated scan session. Rather than running a collection of impacket scripts manually, kerb-map produces a **ranked, prioritised attack path list** with the exact next command to execute — bridging the gap between enumeration and exploitation.

All LDAP queries are read-only. RPC-based CVE probes that generate Windows events are gated behind an explicit `--aggressive` flag.

---

## Documentation
A full user manual covering all modules, CVE detection methods, detection profile, and engagement workflow is available:

- **[View Manual Online](https://docs.google.com/viewer?url=https://raw.githubusercontent.com/b-3llum/kerb-map/main/kerb-map_v1.1_User_Manual.docx)** — Google Docs viewer (no account required)
- **[View Manual (PDF)](kerb-map-manual.pdf)**

---
## Modules

    --spn          Kerberoastable account discovery & scoring
    --asrep        AS-REP roastable accounts (no creds needed)
    --delegation   Unconstrained / Constrained / RBCD mapping
    --users        Privileged users, policy, DnsAdmins, LAPS
    --encryption   Weak Kerberos encryption audit (RC4/DES)
    --trusts       Domain trust mapping & risk assessment
    --cves         CVE detection (ZeroLogon, noPac, ESC1-8, Certifried...)
    --hygiene      Defensive posture audit (krbtgt age, LAPS coverage,
                   SID History, FGPP, credential exposure, stale machines...)
    --aggressive   Enable RPC probes (louder — Event 5145)
    -o json        Export results to JSON or BloodHound format

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
# Full scan — all modules, safe CVE checks only
kerb-map -d corp.local -dc 192.168.1.10 -u jsmith -p Password123 --all --cves

# Full scan + aggressive RPC CVE probes + JSON export
kerb-map -d corp.local -dc 192.168.1.10 -u jsmith -p Password123 \
    --all --cves --aggressive -o json

# Stealth mode — LDAP jitter, no RPC probes
kerb-map -d corp.local -dc 192.168.1.10 -u jsmith -p Password123 --stealth

# CVE checks only
kerb-map -d corp.local -dc 192.168.1.10 -u jsmith -p Password123 --cves

# View stored scan history
kerb-map --list-scans
kerb-map --show-scan 3
```

### Full Flag Reference

| Flag | Description |
|---|---|
| `-d / --domain` | Target domain (e.g. corp.local) |
| `-dc / --dc-ip` | Domain controller IP |
| `-u / --username` | Domain username |
| `-p / --password` | Plaintext password |
| `-H / --hash` | NTLM hash — LM:NT or NT only |
| `-k / --kerberos` | Use ccache ticket (set KRB5CCNAME first) |
| `--all` | Run all modules (default if no module flag given) |
| `--spn / --asrep / --delegation / --users / --cves` | Run specific modules only |
| `--encryption` | Weak Kerberos encryption audit (RC4/DES on accounts and DCs) |
| `--trusts` | Domain trust enumeration with SID filtering risk assessment |
| `--hygiene` | Defensive hygiene audit (LAPS, krbtgt, SID History, FGPP, stale accounts) |
| `--aggressive` | Enable RPC CVE probes — generates Windows Event 5145 |
| `--stealth` | Add random jitter between LDAP queries |
| `-o json / bloodhound` | Write results to file |
| `--top N` | Show top N priority targets (default 15) |
| `--no-cache` | Do not save to local SQLite database |
| `--timeout N` | LDAP connection timeout in seconds (default: 10) |
| `--outfile NAME` | Custom output filename |
| `--list-scans` | List all cached scans |
| `--show-scan ID` | Replay findings from a stored scan |
| `--update` | Pull latest version from GitHub and reinstall |

---

## Detection Profile

| Module | Noise | Event IDs | MDI Detection |
|---|---|---|---|
| LDAP enumeration (all safe checks) | LOW | 1644 (if diag logging on) | No |
| Encryption audit | LOW | 1644 | No |
| Trust mapping | LOW | 1644 | No |
| Hygiene audit | LOW | 1644 | No |
| GPP Passwords (MS14-025) | LOW | 1644 | No |
| Bronze Bit (CVE-2020-17049) | LOW | 1644 | No |
| Certifried (CVE-2022-26923) | LOW | 1644 | No |
| LDAP Signing check | LOW | 1644 | No |
| Kerberoasting w/ AES tickets | MEDIUM | 4769 per ticket | Possible |
| Kerberoasting w/ RC4 tickets | HIGH | 4769 (enc type 0x17) | Yes |
| ZeroLogon RPC probe | HIGH | 5827 / 5828 | Yes |
| PrintNightmare pipe probe | HIGH | 5145 | Yes |
| PetitPotam EFS probe | HIGH | 5145 | Yes |

> **Note:** The `--aggressive` flag enables all HIGH-noise RPC probes. Only use it when your engagement scope explicitly permits noisy testing.

---

## Legal

kerb-map is designed exclusively for use in **authorised** penetration testing engagements and red team operations where written permission has been obtained from the system owner.

Use against systems for which you do not have explicit written authorisation is illegal under the Computer Fraud and Abuse Act (CFAA), the UK Computer Misuse Act, and equivalent legislation worldwide. The author assumes no liability for misuse.

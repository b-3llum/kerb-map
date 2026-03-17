# Flag Reference

Complete reference for every kerb-map CLI flag.

---

## Target (Required for Live Scan)

| Flag | Description | Example |
|---|---|---|
| `-d / --domain` | Target domain name | `-d corp.local` |
| `-dc / --dc-ip` | Domain controller IP address | `-dc 192.168.1.10` |
| `-u / --username` | Domain username | `-u jsmith` |

---

## Authentication (Pick One)

| Flag | Description | Example |
|---|---|---|
| `-p / --password` | Plaintext password | `-p Password123` |
| `-H / --hash` | NTLM hash — LM:NT or NT only | `-H aad3...:31d6...` |
| `-k / --kerberos` | Use ccache ticket (set `KRB5CCNAME` first) | `-k` |

```bash
# NT hash only (LM auto-padded)
kerb-map -d corp.local -dc 192.168.1.10 -u jsmith -H 31d6cfe0d16ae931b73c59d7e0c089c0

# Kerberos ccache
export KRB5CCNAME=/tmp/jsmith.ccache
kerb-map -d corp.local -dc 192.168.1.10 -u jsmith -k
```

---

## Module Selection

| Flag | Modules Run | Notes |
|---|---|---|
| `--all` | All modules | Default if no module flag given |
| `--spn` | SPN Scanner only | Kerberoastable accounts |
| `--asrep` | AS-REP Scanner only | Pre-auth disabled accounts |
| `--delegation` | Delegation Mapper only | Unconstrained, Constrained, RBCD |
| `--users` | User Enumerator only | Policy, trusts, DnsAdmins, LAPS |
| `--cves` | CVE Scanner only | Safe checks + optionally aggressive |
| `--aggressive` | Adds RPC CVE probes | ZeroLogon, PrintNightmare, PetitPotam — generates Event 5145 |

Flags can be combined:
```bash
# Only Kerberoast surface and CVEs
kerb-map -d corp.local -dc 192.168.1.10 -u jsmith -p pass --spn --cves

# Everything including aggressive CVE probes
kerb-map -d corp.local -dc 192.168.1.10 -u jsmith -p pass --all --cves --aggressive
```

---

## Output

| Flag | Description | Default |
|---|---|---|
| `-o json` | Write full results to JSON file | Off |
| `-o bloodhound` | Write BloodHound-compatible JSON | Off |
| `--outfile <name>` | Override output filename | `kerb-map_<domain>_<ts>.json` |
| `--top <N>` | Show top N priority targets in table | 15 |
| `--no-cache` | Do not save to local SQLite database | Off (saves by default) |

---

## Tuning

| Flag | Description | Default |
|---|---|---|
| `--stealth` | Add 0.8–3.0s random jitter between LDAP queries | Off |
| `--timeout <N>` | LDAP connection timeout in seconds | 10 |

---

## Scan History (No Live Scan Required)

| Flag | Description |
|---|---|
| `--list-scans` | List all scans stored in local cache (`~/.kerb-map/results.db`) |
| `--show-scan <ID>` | Display findings from a previous scan by its ID number |

```bash
kerb-map --list-scans

# Output:
# ID   3  corp.local  DC: 192.168.1.10  Operator: jsmith  2024-03-15T14:30:22
# ID   2  corp.local  DC: 192.168.1.10  Operator: jsmith  2024-03-14T09:15:11

kerb-map --show-scan 3
```

---

## Common Flag Combinations

```bash
# Fast first-look after getting credentials
kerb-map -d corp.local -dc 192.168.1.10 -u jsmith -p pass

# Full engagement scan with everything
kerb-map -d corp.local -dc 192.168.1.10 -u jsmith -p pass \
    --all --cves --aggressive -o json

# Stealth recon — slow, quiet, no RPC
kerb-map -d corp.local -dc 192.168.1.10 -u jsmith -p pass \
    --all --stealth

# Kerberoast surface only — fast, minimal noise
kerb-map -d corp.local -dc 192.168.1.10 -u jsmith -p pass --spn

# CVE check with aggressive probes
kerb-map -d corp.local -dc 192.168.1.10 -u jsmith -p pass \
    --cves --aggressive

# Pass-the-Hash, all modules, BloodHound export
kerb-map -d corp.local -dc 192.168.1.10 -u jsmith \
    -H 31d6cfe0d16ae931b73c59d7e0c089c0 \
    --all --cves -o bloodhound
```

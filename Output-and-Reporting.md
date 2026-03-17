# Output & Reporting

> kerb-map produces output in four forms: Rich terminal output, JSON export, BloodHound-compatible JSON, and a local SQLite scan history cache.

---

## Terminal Output

kerb-map uses the Rich library for structured, colour-coded terminal output. Every run produces the following sections in order:

### 1. Domain Overview

Displays key domain metadata immediately after authentication:

```
Domain Overview
  Domain:              corp.local
  Functional Level:    Windows Server 2016/2019/2022
  Machine Acct Quota:  10
  Min Pwd Length:      7
  Pwd History:         5
  Lockout Threshold:   0   ← (NONE — spray freely)
```

Lockout threshold of 0 is highlighted in red immediately — the most operationally important policy fact.

### 2. Kerberoastable Accounts

```
Kerberoastable Accounts
Account       SPN Types    Pwd Age   RC4   Admin  Score  Description
svc_sql       MSSQLSvc     847d      YES   NO     85
backup_svc    wbem         365d      YES   YES    80     Backup admin
svc_web       HTTP         30d       NO    NO     20
```

### 3. AS-REP Roastable Accounts

```
AS-REP Roastable Accounts
Account       Admin  Description
helpdesk01    no
temp_user     no     Temp account - DELETE
```

### 4. Kerberos Delegation

```
Unconstrained Delegation (2 hosts):
  WEBSERVER01$  [computer]  webserver01.corp.local
  APPSERVER03$  [computer]  appserver03.corp.local

Constrained Delegation (1 account):
  svc_iis  (S4U2Self ENABLED)
  → cifs/fileserver.corp.local
```

### 5. Domain User Analysis

```
Password Policy Risks:
  ! No account lockout — password spraying unrestricted
  ! Min password length is only 7 characters

Privileged Accounts (adminCount=1): 12
  admin.smith  (pwd never expires)
  svc_backup
  ...

DnsAdmins Members (1) — can load DLL on DC as SYSTEM:
  svc_dns

LAPS: LAPS not detected — local admin passwords may be shared
```

### 6. CVE / Misconfiguration Checks

```
CVE / Misconfiguration Checks
CVE                    Name                          Severity   Vulnerable  Detail
CVE-2021-42278/42287   noPac                         CRITICAL   YES         MachineAccountQuota=10
ESC1-ESC8              AD CS Misconfigurations       CRITICAL   YES         1 vulnerable template
CVE-2020-1472          ZeroLogon                     CRITICAL   NO
CVE-2021-34527         PrintNightmare                CRITICAL   YES         Spooler pipe reachable

Exploitation paths for vulnerable findings:
  CVE-2021-42278/42287
    python noPac.py corp.local/jsmith:pass -dc-ip 192.168.1.10 -shell

  ESC1-ESC8
    certipy req -u jsmith@corp.local -p pass -ca CORP-CA -template UserCert -upn administrator@corp.local
```

### 7. Priority Attack Paths

The most important section — the scored, ranked, cross-correlated hit list:

```
⚡ Priority Attack Paths

#   Target              Attack                    Sev       Score  Reason                    Next Step
1   Domain Controller   noPac (CVE-2021-42278)    CRITICAL  98     MachineAccountQuota=10    python noPac.py ...
2   WEBSERVER01$        Unconstrained Delegation  CRITICAL  95     Any auth user → TGT       printerbug.py ...
3   All Domain Users    Password Spray            CRITICAL  85     No account lockout        nxc smb ...
4   svc_dns             DnsAdmins → SYSTEM        HIGH      88     DLL injection on DC       dnscmd ...
5   svc_sql             Kerberoast                CRITICAL  85     RC4 | pwd 847d old        GetUserSPNs.py ...
```

### 8. Scan Summary

```
Scan Summary
  Attack paths identified:  14  (CRITICAL: 5  HIGH: 6)
  Vulnerable CVEs found:    3

  Recommended first move: noPac (CVE-2021-42278/42287) against Domain Controller
  python noPac.py corp.local/jsmith:pass -dc-ip 192.168.1.10 -shell

Scan completed in 8.3s
Results cached (scan ID: 4) — replay with --show-scan 4
```

---

## JSON Export

```bash
kerb-map -d corp.local -dc 192.168.1.10 -u jsmith -p pass -o json

# Custom filename
kerb-map -d corp.local -dc 192.168.1.10 -u jsmith -p pass \
    -o json --outfile day1_recon.json
```

Default filename: `kerb-map_corp.local_20240315_143022.json`

### JSON Structure

```json
{
  "meta": {
    "domain":     "corp.local",
    "dc_ip":      "192.168.1.10",
    "operator":   "jsmith",
    "timestamp":  "2024-03-15T14:30:22",
    "duration_s": 8.3
  },
  "domain_info": {
    "functional_level":      "Windows Server 2016/2019/2022",
    "machine_account_quota": 10,
    "min_pwd_length":        7,
    "lockout_threshold":     0
  },
  "spns": [
    {
      "account":          "svc_sql",
      "spns":             ["MSSQLSvc/sqlserver.corp.local:1433"],
      "password_age_days": 847,
      "rc4_allowed":      true,
      "is_admin":         false,
      "crack_score":      85
    }
  ],
  "asrep": [...],
  "delegations": {
    "unconstrained": [...],
    "constrained":   [...],
    "rbcd":          [...]
  },
  "user_data": {
    "privileged_users": [...],
    "password_policy":  { "risks": [...] },
    "dns_admins":       [...],
    "trusts":           [...],
    "laps_deployed":    { "deployed": false }
  },
  "cves": [
    {
      "cve_id":      "CVE-2021-42278/42287",
      "name":        "noPac / sAMAccountName Spoofing",
      "severity":    "CRITICAL",
      "vulnerable":  true,
      "reason":      "MachineAccountQuota=10 and no patch markers detected",
      "evidence":    { "machine_account_quota": 10, "patch_detected": false },
      "remediation": "Apply KB5008380 + KB5008102...",
      "next_step":   "python noPac.py corp.local/jsmith:pass -dc-ip 192.168.1.10 -shell"
    }
  ],
  "targets": [
    {
      "target":    "Domain Controller",
      "attack":    "noPac (CVE-2021-42278/42287)",
      "priority":  98,
      "severity":  "CRITICAL",
      "reason":    "MachineAccountQuota=10...",
      "next_step": "python noPac.py ...",
      "category":  "cve"
    }
  ]
}
```

**Use cases for JSON output:**
- Parse with `jq` for quick filtering: `jq '.targets[] | select(.severity=="CRITICAL")' results.json`
- Feed into reporting tools (Sysreptor, Ghostwriter, etc.)
- Diff two scans to identify new attack surface that appeared mid-engagement
- Archive evidence for the report

---

## BloodHound Export

```bash
kerb-map -d corp.local -dc 192.168.1.10 -u jsmith -p pass -o bloodhound

# Custom filename
kerb-map -d corp.local -dc 192.168.1.10 -u jsmith -p pass \
    -o bloodhound --outfile corp_kerb.json
```

Writes a BloodHound-compatible JSON file with custom node properties for Kerberoastable and AS-REP Roastable accounts. The file can be dragged into the BloodHound UI for import.

**Properties added to BloodHound nodes:**
- `hasspn: true` — Kerberoastable accounts
- `kerberoastable: true`
- `dontreqpreauth: true` — AS-REP Roastable accounts
- `pwdlastset` — password age in days

This lets BloodHound's attack path queries factor in Kerberoastable accounts as owned/compromised nodes.

---

## SQLite Scan Cache

Every scan is automatically saved to `~/.kerb-map/results.db` unless `--no-cache` is specified.

### List Stored Scans

```bash
kerb-map --list-scans

# Output:
# ID   4  corp.local  DC: 192.168.1.10  Operator: jsmith  2024-03-15T14:30:22  8.3s
# ID   3  corp.local  DC: 192.168.1.10  Operator: jsmith  2024-03-14T09:15:11  7.1s
# ID   2  lab.local   DC: 10.10.10.5    Operator: student  2024-03-13T22:41:05  12.4s
```

### Replay a Previous Scan

```bash
kerb-map --show-scan 4

# Output:
# CRITICAL    noPac (CVE-2021-42278/42287)             Domain Controller
# CRITICAL    Unconstrained Delegation → TGT Capture   WEBSERVER01$
# CRITICAL    Password Spray (no lockout)               All Domain Users
# HIGH        Kerberoast                                svc_sql
# ...
```

No network connection required — reads entirely from the local database.

### Skip Saving

```bash
kerb-map -d corp.local -dc 192.168.1.10 -u jsmith -p pass --no-cache
```

Use this when operating on a shared machine or when you want to avoid leaving scan artefacts.

### Database Location

```bash
ls ~/.kerb-map/results.db

# Manually query with sqlite3
sqlite3 ~/.kerb-map/results.db "SELECT id, domain, timestamp FROM scans;"
sqlite3 ~/.kerb-map/results.db \
    "SELECT target, attack, severity FROM findings WHERE scan_id=4 ORDER BY priority DESC;"
```

---

## Controlling Output Volume

```bash
# Show only top 5 priority targets (default: 15)
kerb-map -d corp.local -dc 192.168.1.10 -u jsmith -p pass --top 5

# Show all findings
kerb-map -d corp.local -dc 192.168.1.10 -u jsmith -p pass --top 100

# Quiet terminal + full JSON (useful for scripting)
kerb-map -d corp.local -dc 192.168.1.10 -u jsmith -p pass \
    --top 0 -o json --outfile results.json 2>/dev/null
```

---

## Using Output in Reports

The JSON output maps directly to report sections:

| JSON field | Report section |
|---|---|
| `domain_info` | Domain overview / scoping table |
| `user_data.password_policy.risks` | Password policy findings |
| `cves[]` where `vulnerable=true` | Critical vulnerabilities |
| `targets[]` by category | Attack paths / findings |
| `delegations` | Delegation misconfiguration findings |
| `user_data.laps_deployed` | LAPS / local admin finding |
| `user_data.trusts` | Domain trust findings |

---

## See Also

- [Scoring Engine](Scoring-Engine) — how the priority list is calculated
- [Flag Reference](Flag-Reference) — output and formatting flags
- [Extending kerb-map](Extending-kerb-map) — adding custom output formats

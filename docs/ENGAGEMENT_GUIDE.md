# Engagement deployment guide

Operator-facing guide for using kerb-map on a real engagement.
This isn't the README — for flag reference see [README.md](../README.md).
This document covers **how to deploy and iterate** during an active
engagement.

## Pre-engagement checklist

Before connecting to client infrastructure:

| Check | Why |
|---|---|
| Authorisation document on hand | Don't run any tool without explicit, written, in-scope permission. |
| Time sync to a clock you trust (or to client DC) | Kerberos breaks at >5 min skew. kerb-map warns but a wrong-time-zone host hits this constantly. |
| Routes to client DC IPs verified (`ping` / `nmap -Pn -p 389,88`) | Save 30 min of debugging "kerb-map hangs" when it's actually firewalled. |
| Cred handling decision: `--password-stdin`, `--password-env`, or interactive prompt | Never `-p Password123` on a shared host — `ps aux` leaks. |
| A dedicated, readable scan output dir on disk (not /tmp) | You'll iterate; outputs accumulate. |
| Local SQLite `~/.kerb-map/results.db` is empty / archived | `--diff` and `--list-scans` get noisy if you're sharing a workstation. |

## First-touch workflow

```bash
# 1. Reachability + service map (NOT kerb-map; nmap)
nmap -Pn -p 88,135,139,389,445,464,636,3268 <DC_IP>

# 2. If you don't have creds yet — try the no-creds attack surface
kerb-map --timeroast -dc <DC_IP> --timeroast-rids 1000-1500 \
    --timeroast-out timeroast.hashes
# crack with: hashcat -m 31300 timeroast.hashes <wordlist>

# 3. Once you have a low-priv user, the first run:
kerb-map -d <DOMAIN> -dc <DC_IP> -u <USER> --password-stdin <<< 'PWD' \
    --all --v2

# 4. Note the scan-id printed on startup — keep it; you'll --resume
#    or --diff against it later.
```

## Cred-handling patterns

```bash
# Most secure (recommended) — no copy-paste leak, no shell history:
echo -n 'Spring2026!' | kerb-map -d corp.local -dc 10.0.0.1 -u jsmith --password-stdin

# Environment variable — useful when scripting:
export ENG_PWD='Spring2026!'
kerb-map -d corp.local -dc 10.0.0.1 -u jsmith --password-env ENG_PWD

# Pass-the-Hash:
kerb-map -d corp.local -dc 10.0.0.1 -u jsmith \
    --hash-stdin <<< 'aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0'

# Kerberos ccache (pivot from compromised host):
export KRB5CCNAME=/tmp/jsmith.ccache
kerb-map -d corp.local -dc 10.0.0.1 -u jsmith -k

# AVOID — visible in `ps aux` and shell history:
# kerb-map -d corp.local -dc 10.0.0.1 -u jsmith -p Spring2026!
```

## Iteration patterns

### Resume after a Ctrl-C / VPN drop

```bash
# Interrupted scan? See what's still resumable:
kerb-map --list-resumable
# Continue where it left off (CVE + v2 modules; legacy modules re-run cheaply):
kerb-map -d corp.local -dc 10.0.0.1 -u jsmith --password-stdin --resume <scan_id> <<< 'PWD'
```

### Retest after a remediation cycle

```bash
# Original scan → ID 5
# After client claims fixes:
kerb-map -d corp.local -dc 10.0.0.1 -u jsmith --password-stdin --all --v2 <<< 'PWD'
# → ID 7
kerb-map --diff 5 7
# REMOVED = they fixed it. ADDED = something new is exposed. UNCHANGED = still vulnerable.
```

### Sharing a finding with the blue team

```bash
# Markdown report — drops into Obsidian / Notion / a Jira ticket cleanly:
kerb-map -d corp.local -dc 10.0.0.1 -u jsmith --password-stdin --all --v2 \
    -o markdown --outfile findings-$(date +%F).md <<< 'PWD'
```

### BloodHound CE for graph analysis

```bash
kerb-map -d corp.local -dc 10.0.0.1 -u jsmith --password-stdin --all --v2 \
    -o bloodhound-ce --outfile scan.bh.zip <<< 'PWD'

# Upload to a running BH CE 5.x:
# Upload via the UI → Settings → File Ingest → Upload Files
# OR via the API:
curl -X POST -F "ingest=@scan.bh.zip" http://bloodhound-ce/api/v2/file-upload
```

## Noise / detection

The README has a [Detection Profile](../README.md#detection-profile)
table per module. The summary:

| Posture | Modules to use | Modules to avoid |
|---|---|---|
| **Maximum stealth** (read-only LDAP) | `--all` (no `--aggressive`), `--v2` | `--aggressive`, `--spray`, Kerberoast w/ RC4 |
| **Engagement-typical** (some 4769 noise OK) | `--all --v2 --cves` | `--aggressive` for the first scan |
| **Lit up — confirmation phase** | `--all --v2 --cves --aggressive` | spray without coordination |

`--stealth` adds 0.4-2.0s random jitter between LDAP queries; useful
under EDR tuning that flags scan-rate signatures.

## Timeouts and rate limits

Defaults are tuned for typical engagements:

| Setting | Default | When to change |
|---|---|---|
| `--timeout` | 10s LDAP connect | Higher on high-RTT VPN / WAN links |
| `--timeroast-rate` | 180 pps (Tervoort default) | Lower on small estates / IDS-paranoid |
| `--timeroast-timeout` | 5s per RID | Higher on slow-DC labs |
| `--spray-rate` | 1.0s between binds | Higher (5-10s) on lockout-paranoid environments |

## What to capture

Every engagement should produce:

1. **The original JSON** (`-o json`) — keep raw evidence; it's what
   the SQLite cache stores anyway.
2. **The Markdown report** (`-o markdown`) — for the report writer.
3. **The BloodHound zip** (`-o bloodhound-ce`) — for the graph analyst.
4. **Any cracked Timeroast hashes** — separately, alongside the
   wordlist used.
5. **Confirmation that the noisy CVEs were authorised**, if you ran
   `--aggressive`.

Store everything under `<engagement>/<DOMAIN>/<YYYY-MM-DD-HH>/`. The
SQLite cache lets you `--diff` between scans across days; the file
exports give you immutable artefacts for the deliverable.

## Common failure modes & fixes

| Symptom | Likely cause | Fix |
|---|---|---|
| "Failed to connect" / hang | LDAP port not reachable | `nmap -p 389 <DC_IP>` — check VPN routes |
| "All LDAP transports failed" | Hardened DC requires LDAPS / signing | Try `--ldaps` explicitly; check certs |
| "KRB_AP_ERR_SKEW" in next_step recipes | Local clock drift | Sync with `sudo ntpdate <DC_IP>` (warning fires automatically) |
| GPP reported INFO instead of HIGH | We don't grep SYSVOL via SMB yet | Manually verify with `Get-GPPPassword.py`; see PR description |
| `LDAP query failed` for `msDS-DelegatedManagedServiceAccount` | Server 2019/2022 — schema lacks the class | Should be silent post-v1.2; if not, file an issue |
| Scan returns 0 v2 findings on a domain you know is vulnerable | sd_control / walk_aces regression | File an issue with `-vv` output; mocked tests can't catch this |
| Resume said "no resumable scan matches" | Pre-v1.2.0 bug — `ResumeState.new()` didn't flush | Should be fixed in v1.2.0; if not, upgrade |

## Cross-domain / forest engagements

If `Trust mapper` flags a SID-filter-disabled trust, kerb-map's
current scope is the bound domain — it does NOT walk into trusted
domains automatically. Run a separate kerb-map invocation with
the partner-domain DC and credentials, then correlate manually.

A future kerb-map version may walk trusts; for now, the BloodHound
CE export from each domain is the easiest way to see the full graph.

## When to file a bug

`kerb-map --version` and your scan log (`-vv` if you can stomach
the noise) — file at https://github.com/b-3llum/kerb-map/issues.
Field-found bugs have been the most valuable input — see PRs
#29 #30 #31 #32 #33 #35 for examples of bugs only a real engagement
surfaced.

# Changelog

All notable changes to kerb-map will be documented in this file.

## [1.2.0] — 2026-04

### Added — new no-creds attacks
- **Timeroast** (`--timeroast`) — Tom Tervoort / Secura's MS-SNTP machine-account hash recovery. Iterates a RID range, sends authenticated NTP requests on UDP 123, captures responses signed with each machine's NT hash, and outputs hashcat mode 31300 hashes. Works **without credentials** — UDP 123 reachability to the DC is the only requirement. Flags: `--timeroast-rids START-END` (default 1000–1500), `--timeroast-rate` (default 180 pps, Tervoort default), `--timeroast-timeout`, `--timeroast-out FILE`.
- **Password spray pre-check** (`--spray`) — generates a season+year/domain+year/stock-password wordlist and sprays via LDAP bind. Lockout-aware: reads `lockoutThreshold` from the domain, truncates the dictionary to `(threshold − 1)` per user so we never trip lockout. Threshold=0 (lockout disabled) sprays the full list. Confirmation prompt summarises the plan + lockout policy + total attempts before any bind. Flags: `--spray-users-file`, `--spray-passwords-file`, `--spray-rate`, `--spray-yes` (skip prompt for scripted runs).

### Added — v2 plugin modules (auto-discovered with `--v2`)
- **DCSync rights** — enumerates principals with `DS-Replication-Get-Changes(-All)` on the domain root; flags any non-default holder.
- **Shadow Credentials** — `msDS-KeyCredentialLink` writers on Tier-0 accounts (Whisker/pywhisker primitive) plus inventory of accounts with KCL set.
- **BadSuccessor** (CVE-2025-53779) — dMSA predecessor-link abuse (Server 2025).
- **Pre-Windows 2000 Compatible Access** — `S-1-5-32-554` membership audit; flags `Authenticated Users` membership (default on legacy installs, allows `net user /domain` from any unprivileged account).
- **GMSA / dMSA inventory + KDS root key audit** — Golden dMSA prerequisite check (Semperis, July 2025): non-default principals with read on `msKds-ProvRootKey` = offline gMSA/dMSA password generation. Schema-tolerant: dMSA query is skipped silently on pre-2025 DCs.
- **Tier-0 ACL audit** — DACL walk on AdminSDHolder, DA/EA/SA/SchemaA, BUILTIN privileged groups, and every adminCount=1 user; recursive group resolution suppresses in-tier writers.
- **User ACL audit** — lateral-movement enumeration on every enabled non-Tier-0 user. Catches BloodHound-style "GenericAll → User" attack edges (e.g. user A → user B WriteDACL) that Tier-0 audit misses.
- **OU computer-create rights** — RBCD pivot survival check. Flags non-default principals with `CreateChild(computer)` on OUs even when `MAQ=0` is enforced; lockout-aware suppression of Authenticated Users on the default Computers container.
- **AD CS Extended (ESC4/5/7/9/13/15)** — extends the legacy ESC1–8 scanner. Coalesces ESC7 ManageCA + ManageCertificates from the same trustee into a single CRITICAL finding.
- **Coercion module** — PetitPotam / DFSCoerce / PrinterBug surface enumeration.

### Added — output formats
- **BloodHound CE** (`-o bloodhound-ce`) — real BH CE 5.x ingestible zip (users / computers / groups / domains JSON + custom `KerbMap*` edges). Replaces the deferred BloodHound integration.
- **CSV** (`-o csv`) — one row per priority target, spreadsheet-friendly.
- **Markdown** (`-o markdown`) — full operator report, drops into Obsidian.

### Added — operator UX
- **Verbosity flags** (`-q / --quiet`, `-v / --verbose`, `-vv`) — wired to a level enum. WARN+ always shown (even `--quiet`). `-vv` adds raw LDAP filter logging on the wire.
- **`--no-color`** — disable ANSI for `tee logfile.txt` workflows; reaches every `Console` instance via a process-wide registry.
- **`--diff <A> <B>`** — diff two cached scans; ADDED / REMOVED / UNCHANGED buckets for retest engagements.
- **`--list-cves` / `--only-cves CVE-A,CVE-B`** — filter the CVE check set.
- **`--resume <ID>` / `--list-resumable`** — partial-scan persistence. Each completed CVE / v2 module flushes findings to `~/.kerb-map/in_progress/<id>.json` before moving on; Ctrl-C / LDAP timeout doesn't lose work. `--list-resumable` shows continuable scans.
- **`--update --tag REF` / `--update --force`** — hardened self-update. Refuses on dirty tree or detached HEAD unless `--force`; `--tag` pins to a release; `git pull --ff-only` so we never silently merge.
- **`--list-scans`** now shows finding counts + severity histogram + duration per scan (e.g. `42 findings (3C/8H/15M/16L/0I)  12.4s`).
- **Auto-substituted placeholders** in `next_step` strings — `<DC_IP>`, `<DOMAIN>`, `<DOMAIN_SID>`, `<DC_FQDN>`, `<DC_HOSTNAME>`, `<DC_NAME>`, `<BASE>` resolved at scan time. Operator-supplied placeholders (`<pass>`, `<ATTACKER_IP>`, `<victim>`) stay literal.
- **Clock skew warning** — SNTP probe of the DC after bind. Loud warning if skew > 300s (Kerberos default tolerance) with three suggested fixes (`ntpdate`, `chronyd`, `faketime`). Catches the "scan succeeded but every Kerberoast / getTGT recipe in the next_step fails with `KRB_AP_ERR_SKEW`" failure mode.

### Fixed — field-validated against a real domain
- `sd_control()` returned `[[Control]]` instead of `[Control]` — every v2 ACL-walking module silently returned zero findings against real DCs. Unit tests didn't catch it because they mocked `walk_aces` / `parse_sd` directly.
- `ldap_client.query()` clobbered the `controls` local variable inside the paging loop, breaking paged searches that use SD controls.
- `walk_aces()` called `sd.get("Dacl")` — impacket's `SR_SECURITY_DESCRIPTOR` doesn't expose `.get()`. Switched to `try: sd["Dacl"]`.
- GPP Passwords no longer false-flags HIGH on every clean domain. Counting `groupPolicyContainer` LDAP entries is not the same as actually grepping XMLs for `cpassword=` — moved to honest INDETERMINATE reporting until SMB-grep is plumbed.
- Resume state file now flushes on `ResumeState.new()` instead of waiting for the first module to complete — the announced scan-id is now actually resumable from any point.
- dMSA query skipped silently on pre-2025 DCs via schema check; no more alarming `LDAP query failed` log line on Server 2019/2022.
- BloodHound exporter rewritten to emit the BH CE 5.x ingest schema (was previously a custom JSON shape masquerading as BH).
- ZeroLogon probe rewritten to the SecuraBV `NetrServerAuthenticate3` shape.
- `_infer_patch_status` removed — patch status from DFL is meaningless; CVE checks now report INDETERMINATE when only LDAP-side preconditions can be checked.

### Fixed — quality of life
- LDAP queries are paged via the RFC 2696 simple paged results control — no more silent truncation past `MaxPageSize`.
- LDAPS / StartTLS auto-fallback chain (LDAPS → StartTLS → signed SASL → plain), with a one-line bind banner showing TLS version + cipher.
- `--password-stdin` / `--password-env` / interactive prompt — passwords no longer required on `argv`.
- Domain SID captured at scan start and substituted into Golden Ticket / SID History / DCSync `next_step` recipes.
- 70%+ unit test coverage on `kerb_map/modules/`; CI runs ruff + pytest + sdist/wheel build on every PR.

## [1.1.0] — 2025

### Added
- **Hygiene Auditor** module (`--hygiene`) — 10 defensive security checks:
  - SID History abuse detection
  - LAPS deployment coverage analysis (legacy + Windows LAPS)
  - krbtgt password age assessment
  - AdminSDHolder orphan detection
  - Fine-Grained Password Policy (FGPP) audit
  - Credential exposure in description/info fields
  - PrimaryGroupId manipulation detection
  - Stale computer account identification
  - Privileged group membership breakdown
  - Service account password hygiene
- **Encryption Auditor** module (`--encryption`) — RC4/DES weakness detection on accounts and DCs
- **Trust Mapper** module (`--trusts`) — domain trust enumeration with SID filtering risk assessment
- **CVE Checks** expanded to 10:
  - noPac (CVE-2021-42278/42287)
  - ZeroLogon (CVE-2020-1472) — aggressive only
  - PrintNightmare (CVE-2021-1675) — aggressive only
  - PetitPotam (CVE-2021-36942) — aggressive only
  - AD CS ESC1-ESC8 certificate abuse
  - GPP Passwords (MS14-025)
  - Bronze Bit (CVE-2020-17049)
  - Certifried (CVE-2022-26923)
  - LDAP Signing enforcement
  - MS14-068 PAC Forgery
- `--update` flag for self-updating via git pull + pipx/pip reinstall
- BloodHound v5 JSON export with custom nodes for delegation, Kerberoast, and hygiene findings
- SQLite scan caching with `--list-scans` and `--show-scan` replay
- Stealth mode (`--stealth`) with LDAP query jitter

### Changed
- Scorer now integrates findings from all modules (encryption, trusts, hygiene)
- Reporter output expanded with remediation guidance for hygiene findings

## [1.0.0] — 2025

### Added
- Initial release
- SPN Scanner — Kerberoastable account discovery with risk scoring
- AS-REP Scanner — pre-authentication disabled accounts
- Delegation Mapper — unconstrained, constrained, and RBCD
- User Enumerator — privileged users, password policy, DnsAdmins, LAPS
- CVE Scanner framework with safe/aggressive separation
- JSON export
- Pass-the-Hash and Kerberos ccache authentication

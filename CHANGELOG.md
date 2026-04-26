# Changelog

All notable changes to kerb-map will be documented in this file.

## [1.2.1] — 2026-04

Lab-driven iteration release. Stand up a Samba 4 AD lab, ingest into a
real BloodHound CE 5.x instance, and watch what breaks — every change
below is something the lab forced into the open.

### Added — BloodHound CE 5.x: real graph edges from KerbMap findings (#39, #40)

- **`_kerbmap_metadata.json` sidecar** — kerb-map findings ship in the
  same zip but under an underscore-prefixed name BH CE skips during
  ingest. Replaces the previous `kerbmap_edges.json` shape, which BH
  CE 5.x rejected with HTTP 500 + "no valid meta tag found", killing
  the *entire* upload (not just the sidecar). Field-bug-validated
  against a running BH CE 5.x docker compose stack.
- **Per-node `Aces` folding** — three finding classes now fold into the
  target node's `Aces` array with SharpHound-recognised `RightName`s,
  so they render as native BH CE edges in the graph (previously
  sidecar-only). Operator pathfinding works without external tooling:
  - `DCSync (full)` → Domain `Aces` with `GetChanges` + `GetChangesAll`
  - `Shadow Credentials (write)` → User `Aces` with `AddKeyCredentialLink`
  - `Tier-0 ACL: <right>` → target `Aces` with `GenericAll` /
    `WriteDacl` / `WriteOwner` / `GenericWrite` / `AddMember` /
    `AddSelf` (kerb-map's `WriteDACL` label maps to BH CE's `WriteDacl`
    — without the case translation, BH CE silently skipped the edge.)
- Sidecar entries carry `folded: bool` so kerb-chain knows which
  findings render in the graph and which don't (ADCS templates, OUs,
  dMSAs need node-type enumeration that's a v1.3 follow-up).
- `COLLECTOR_VERSION` bumped to `2.1.0-aces-fold`.

End-to-end validated against the lab's seeded vulns: `ACCOUNT
OPERATORS → BOB_DA` Tier-0 takeover is now a 1-hop graph edge;
`HELPDESK_OP → BOB_DA` Shadow Creds is a `AddKeyCredentialLink`
edge; `SVC_OLD_ADMIN → LAB.LOCAL` is a full DCSync (both edges).

### Added — GPP cpassword auto-decrypt (#41 — closes gap #9)

- **GPPPasswords now SMB-greps SYSVOL** when credentials are
  available, decrypts `cpassword=` with the MS-published AES-256 key
  (PKCS#7-padded, UTF-16-LE), extracts the sibling `userName=`, and
  returns CRITICAL with the cleartext credential. Previously honest-
  INDETERMINATE since PR #30 — operators had to grep manually with
  smbclient or Get-GPPPassword.
- **CVEBase carries optional credentials** (keyword-only:
  `username` / `password` / `nthash` / `use_kerberos`). CVEScanner
  forwards them to every check; only GPPPasswords uses them today,
  but the plumbing is the same one any future SMB- or RPC-touching
  CVE check would need. Existing 3-arg `CVEBase(ldap, dc_ip, domain)`
  call sites unchanged.
- Without credentials (kerberos-only without GSSAPI-on-SMB plumbing,
  anonymous bind), the check falls through to the prior
  INDETERMINATE behaviour — opt-in, no behavior change for users
  without `-p` / `-H`.
- `cryptography` is **not** a new dep — `pycryptodomex` is a hard
  impacket dep so it's guaranteed importable wherever kerb-map runs.

End-to-end validated against the lab: with a seeded `Groups.xml`
containing `Password1!` encrypted via the public key, kerb-map
reports `CRITICAL  GPP Passwords (cpassword) (MS14-025) — user='helpdesk_admin', cleartext=***. patch_status: confirmed vulnerable via SMB-grep`.

### Fixed — field bugs surfaced by lab + BH CE iteration

- **impacket `openFile` + `readFile` take a numeric `treeId`** (from
  `connectTree`); passing the share name string returned zero bytes
  silently. Switched GPP's `_read_file` to `getFile` which takes the
  share name directly. (#41)
- **Samba's domain provision creates `MACHINE/` (uppercase)** under
  each GPO; the lab seed wrote to `Machine/` — Linux's case-sensitive
  filesystem made these distinct directories. Fixed by writing into
  the existing MACHINE; GPP walker is also case-insensitive on
  filenames so it survives either capitalisation. (#41)
- **GPP username extraction matched `newName=""`** before
  `userName="..."` because `newName` appears earlier in the GPP
  attribute list — operator-facing finding read `user='<unknown>'`
  even with the username right there. Fixed by ranking patterns
  (`userName` > `accountName` > `runAs` > `newName`) and skipping
  empty matches. (#41)
- **`da_alice` missing `adminCount=1` pin** in the lab seed — same
  class as the existing `bob_da` fix: Samba's AdminSDHolder runs
  every 60min, so freshly-added Domain Admins members miss the first
  scan. Without the pin, Shadow Credentials inventory (which only
  reports `adminCount=1`) silently misses the seeded KCL — exactly
  the CRITICAL finding the seed exists to validate. (#39)

### Added — Samba 4 lab compatibility (#37, #38)

- **LDAPS-SIMPLE transport** added to the LDAP fallback chain
  (LDAPS → StartTLS → SASL/Kerberos → LDAPS-SIMPLE → plain). Samba's
  LDAP service rejects NTLM-flavoured binds with
  "session terminated by server"; SIMPLE bind over the same TLS
  socket succeeds. Pass-the-hash callers skip LDAPS-SIMPLE because
  SIMPLE bind needs the plaintext password.
- **Lab seed end-to-end validation** against `vagrant up` from
  scratch — `provision_dc.sh` + `seed_vulnerabilities.sh` stand up a
  signing-relaxed Samba 4 AD with every v1 + v2 attack-surface seed
  in ~5–10 min. Provision script gained `ldb-tools` to apt install
  and `ldap server require strong auth = no` to smb.conf so the
  field-typical Windows AD config is reproduced.
- `delegation_mapper` no longer crashes when an entry has no
  `dNSHostName` — `e.get(...)` doesn't exist on `ldap3.Entry`,
  `"key" in e` does. Same class as the `walk_aces` `.get()` fix from
  PR #32.

### Added — CI matrix + coverage (#37)

- CI now runs the suite on Python 3.10 / 3.11 / 3.12 (was 3.12 only)
  via `.github/workflows/test.yml`. Locally verified with `uv` on
  3.10 / 3.11 / 3.12 — no code changes needed.
- `kerb_map/modules/` aggregate test coverage pushed from 69% to
  **83%**. `hygiene_auditor.py` (663 LOC, 10 sub-modules) is the
  remaining straggler at 13% — tracked as a v1.2.2 follow-up in
  `docs/v1.2-known-gaps.md`.
- New docs:
  - `docs/v1.2-known-gaps.md` — honest scope-vs-shipped accounting,
    11 gaps with the environment / work needed to close each. v1.2.1
    closes gap #2 (BH CE ingest validation) and gap #9 (GPP SMB-grep).
  - `docs/ARCHITECTURE.md`, `docs/MODULE_AUTHORING.md`,
    `docs/ENGAGEMENT_GUIDE.md`.

### Performance baseline (partial — #40 docs update)

First numbers measured against the 1500-stub-user Samba lab:

| Profile         | Wall time | Output zip |
|-----------------|----------:|-----------:|
| `--all` legacy  |     3.6 s |       60 MB |
| `--all --v2`    |    10.2 s |      113 MB |

`--v2` adds 2.8× wall time and 1.9× output size on this lab — driven
by the 6 ACL-walking modules issuing `get_security_descriptor=True`
LDAP queries. Real-estate scaling and tracemalloc instrumentation
remain a v1.3 follow-up (gap #7).

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

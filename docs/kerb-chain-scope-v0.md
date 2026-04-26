# kerb-chain — v0 scope

A separate tool that consumes kerb-map's findings and turns them into
actionable attack chains. This document defines what kerb-chain is
(and isn't), starts the implementation conversation, and pins the
input contract before any code lands.

---

## 1. Input contract

kerb-chain consumes the JSON shape kerb-map writes via
`-o json --outfile <path>` (or via SQLite cache at
`~/.kerb-map/scans.db`, served by `Cache.get_scan(scan_id)`). Both
paths produce the same dict — pinned by `kerb_map/output/exporter.py`
and `kerb_map/db/cache.py` line 78.

### Top-level keys

| Key            | Type                          | Use to kerb-chain |
|----------------|-------------------------------|--------------------|
| `meta`         | `{domain, dc_ip, operator, timestamp, duration_s}` | Bind context |
| `domain_info`  | `{domain, functional_level, fl_int, machine_account_quota, min_pwd_length, pwd_history_length, lockout_threshold, when_created, domain_sid, dc_dns_hostname, is_rodc}` | RODC awareness, MAQ, lockout policy |
| `spns`         | `[{account, spns, password_age_days, rc4_allowed, aes_only, is_admin, is_service, description, last_logon_days, never_logged_in, crack_score, crack_priority}]` | Kerberoast input |
| `asrep`        | `[{account, ...}]` | AS-REP roast input |
| `delegations`  | `{unconstrained: [], constrained: [], rbcd: []}` | Delegation chain input |
| `user_data`    | Privileged users, password policy | Context |
| `enc_audit`    | Weak-encryption results | Downgrade hints |
| `trusts`       | Domain trust topology | Cross-domain pivot |
| `cves`         | `[{cve_id, name, severity, vulnerable, reason, evidence, remediation, next_step, noise_level, references, patch_status}]` | CVE chain inputs |
| `hygiene`      | `{sid_history, laps_coverage, krbtgt_age, adminsdholder_orphans, fgpp_audit, credential_exposure, primary_group_abuse, stale_computers, privileged_groups, service_acct_hygiene}` | Soft-evidence pivots |
| `v2`           | `{adcs-extended, badsuccessor, dcsync, gmsa-kds, ou-create-computer, prewin2k, shadow-creds, tier0-acl, user-acl}` | Per-module raw findings |
| `targets`      | `[{target, attack, severity, priority, reason, next_step, category, mitre, data}]` | **The priority-ranked attack-path list — kerb-chain's primary input** |

### The `targets[]` shape — the canonical input

Every actionable kerb-map finding ends up in `targets`. It's already
priority-sorted, severity-classified, and carries the structured data
needed for chaining:

```
{
  "target":   "svc_old_admin",
  "attack":   "DCSync (full)",
  "severity": "CRITICAL",
  "priority": 95,
  "reason":   "svc_old_admin has Get-Changes, Get-Changes-All, ...",
  "next_step": "secretsdump.py -just-dc-ntlm kerblab2022.local/svc_old_admin:<pass>@192.168.57.22",
  "category": "attack-path",
  "mitre":    "T1003.006",
  "data": {
    "principal_sid":  "S-1-5-21-...-2611",
    "principal_dn":   "CN=svc_old_admin,CN=Users,...",
    "rights_granted": ["Get-Changes", "Get-Changes-All", "Get-Changes-In-Filtered-Set"],
    "domain_sid":     "S-1-5-21-..."
  }
}
```

**The `data` sub-dict is the actionable payload.** Each module shapes
its `data` keys to carry exactly what the next-step recipe needs —
SIDs to forge against, DNs to write to, cert templates to enroll, etc.
kerb-chain reads `attack` to dispatch on chain type and `data` to
parameterize.

### Categories observed in real lab output

```
attack-path   → v2 plugins (DCSync, Shadow Creds, Tier-0 ACL, etc.)
cve           → CVE checks (noPac, GPP, ZeroLogon, ESC1-15, ...)
hygiene       → Defensive findings (LAPS, krbtgt age, ...)
kerberos      → AS-REP, Kerberoast
delegation    → Unconstrained / Constrained / RBCD
encryption    → Weak DC encryption, DES
policy        → Password spray (no lockout)
```

---

## 2. Finding types and canonical chains

Every distinct `attack` type observed in production kerb-map output,
mapped to the canonical chain that finding enables. **Bold** = chain
ends at credential material reusable by other chains.

| kerb-map `attack` | Canonical chain | Output material |
|---|---|---|
| **AS-REP Roast** | `GetNPUsers.py` → `hashcat -m 18200` → reuse | NT hash |
| **Kerberoast** | `GetUserSPNs.py` → `hashcat -m 13100` → reuse | NT hash (for SPN account) |
| **GPP Passwords (cpassword)** | already cleartext in kerb-map output | cleartext password |
| **Shadow Credentials (write access)** | `certipy shadow auto` → cert + NT hash | NT hash + cert |
| **DCSync (full)** | `secretsdump.py -just-dc-ntlm` | all NT hashes incl. krbtgt |
| **DCSync (partial)** | same as full but with `-just-dc-user` per account | NT hashes (whitelisted) |
| **Tier-0 ACL: WriteDACL on Privileged group/user** | `dacledit.py` add member → group membership | DA membership |
| **Tier-0 ACL: WriteDACL on Builtin priv group** | same | DA-equivalent membership |
| **User ACL (lateral)** | `dacledit.py` add member to controllable group → ACL chain hop | step credential |
| **OU computer-create** | `addcomputer.py` → drop machine in OU → RBCD against high-value computer | TGT to target computer |
| **BadSuccessor (CVE-2025-53779)** | `New-ADServiceAccount` dMSA + predecessor link to DA → wait for KDC merge | DA TGT (Server 2025 only) |
| **Unconstrained Delegation → TGT Capture** | `SpoolSample`/`PetitPotam` coerce → `Rubeus monitor` → captured TGT | DC TGT → DCSync |
| **noPac (CVE-2021-42278/42287)** | `addcomputer.py` → `renameMachine` → `getST` impersonation | DA TGT |
| **GMSA reader (msDS-GroupMSAMembership)** | `gMSADumper.py` → password blob → NT hash | gMSA NT hash |
| **GMSA / KDS root key (Golden dMSA)** | `GoldenDMSA` (Semperis) → forged dMSA password → impersonation | any dMSA NT hash |
| **AD CS ESC1** | `certipy req -template VulnerableTemplate -upn Administrator` → cert + NT hash | NT hash |
| **AD CS ESC4** | `certipy template -write` → make ESC1 → enroll | NT hash |
| **AD CS ESC7** | `certipy ca` officer rights → publish ESC1 template → enroll | NT hash |
| **AD CS ESC9 / ESC10** | `certipy req` no SAN check + `certipy auth -altname Administrator` | NT hash |
| **AD CS ESC13** | enroll for OID-linked group → group membership via cert | DA membership |
| **AD CS ESC15 (EKUwu)** | abuse template schema v1 → SAN injection | NT hash |
| **Bronze Bit (CVE-2020-17049)** | `getST -impersonate Administrator -force-forwardable` | impersonated TGT |
| **Certifried (CVE-2022-26923)** | `certipy req` with `dNSHostName` set to DC's | DC machine TGT |
| **MS14-068 (PAC Forgery)** | `ms14-068.py` → forged PAC TGT | DA TGT |
| **ZeroLogon (CVE-2020-1472)** | RPC reset → DC machine account hash → DCSync | krbtgt hash |
| **PrintNightmare / PetitPotam** | coerce DC auth → NTLM relay or unconstrained chain | depends on chain endpoint |
| **Pre-Win2k membership** | enumerate via S-1-5-32-554 — gives `net user /domain` to anonymous | reconnaissance only |
| **LDAP Signing Not Required** | `ntlmrelayx -t ldap://DC --escalate-user` | LDAP write as relayed user |
| **Weak DC Encryption (RC4/DES)** | downgrade Kerberoast / AS-REP for crack speedup | crack-rate boost |
| **Password Spray (no lockout)** | `nxc smb -u users.txt -p passwords.txt --no-bruteforce` | per-account creds |
| **No LAPS — Shared Local Admin** | `nxc smb --local-auth -u Administrator -H <hash>` | lateral via shared local hash |
| **Credential in AD Attribute (description)** | already plaintext in finding | cleartext password |
| **Credential exposure (svc_app pw=)** | same | cleartext password |

---

## 3. v0.1 — smallest viable scope

**Pick one finding. One chain. Suggestion-only. Single input.
Stateless.**

**Recommendation: Shadow Credentials (write access).**

### Why Shadow Credentials

Five candidates pass the "smallest viable" test:

1. **Shadow Credentials (write access)** — single tool (certipy), 4-step
   chain, deterministic output (cert.pfx + NT hash), high operational
   value (often Tier-0 takeover in 1 hop).
2. **DCSync (full)** — single tool (secretsdump), 1-step chain.
   Output is "all the hashes" — too coarse to demonstrate orchestration
   value.
3. **GPP cpassword** — chain is "use the cleartext kerb-map already
   gave you." Too short to demonstrate orchestration value at all.
4. **Kerberoast** — clean tool chain, but the crack step has
   wildly variable runtime (5 sec to 5 days depending on password)
   so demos are awkward.
5. **AS-REP Roast** — same crack-variance problem.

Shadow Credentials wins because it exercises a *real* chain
(parse finding → certipy command → PKINIT → NT hash) where each step
is short, deterministic, and the output is reusable. Demonstrating
orchestration value with a 1-step chain (DCSync) doesn't show what
kerb-chain is *for*.

### v0.1 contract

| Aspect | Choice |
|---|---|
| **Input** | `kerb-map -o json` file path on disk |
| **Output** | Markdown to stdout: per-finding suggested commands + 1-line rationale |
| **Execution** | None. Suggestion text only. Operator copy-pastes. |
| **Findings handled** | Only `attack == "Shadow Credentials (write access)"` |
| **State** | None. Re-running on the same input produces the same output. |
| **Dependencies** | Python stdlib + click (or argparse). No SDK calls, no impacket import, no AD bind. |

### v0.1 user flow

```
kerb-map -o json --outfile scan.json -d corp.local -dc 10.0.0.1 -u op -p pass --all --v2
kerb-chain plan scan.json
# → emits, per Shadow Creds finding:
#
#   ### Shadow Credentials chain — bob_da via helpdesk_op
#
#   helpdesk_op holds WriteProperty(KCL) on bob_da (a Domain Admin).
#   Compromise of helpdesk_op → control of bob_da via PKINIT.
#
#   Chain (3 commands):
#     1. As helpdesk_op, write a key to bob_da's msDS-KeyCredentialLink:
#        certipy shadow auto -u helpdesk_op@kerblab2022.local -p '<helpdesk_op_pw>' -account bob_da
#     2. PKINIT with the cert to obtain bob_da's TGT and NT hash:
#        (printed by certipy as part of step 1)
#     3. Use the NT hash as bob_da:
#        secretsdump.py -hashes :<hash> kerblab2022.local/bob_da@<DC>
```

Output should look like a runbook the operator can read top-to-bottom
and execute mentally before pasting.

---

## 4. v1.0 execution model

**Recommendation: hybrid — suggestion by default, opt-in execution.**

```
kerb-chain plan    scan.json     # default: suggest (current v0.1 behavior)
kerb-chain run    scan.json     # execute: actually invoke each step
kerb-chain run -k scan.json     # execute, only chains tagged --safe (no RPC, no LDAP write)
```

Reasoning:

- **Pure suggestion** ships fast and is operator-friendly but
  underutilizes the orchestration value. Every chain still requires
  the operator to copy commands, edit them, and paste — error-prone
  at the keyboard.
- **Pure execution** is dangerous on engagements. `secretsdump`
  fires Event 5145, `addcomputer` adds an attributable machine
  account, `getST -force-forwardable` is RPC-loud. Running these
  without operator confirmation is malpractice.
- **Hybrid** matches how real operators want to work: see the chain
  as text first, then either (a) execute it after review, or
  (b) pipe it to a different orchestrator. The opt-in flag is a
  hard gate — never auto-execute on default invocation.

The execution path also needs:

- **Per-step confirmation prompt** (default on; `--yes` to suppress
  for CI / lab runs). One y/N per chain step, not per scan.
- **Output capture** — run each step's stdout/stderr through a
  parser that extracts the credential material the chain emits
  (NT hash regex, ccache path, cert thumbprint). Without parsing,
  hybrid is just a typing convenience; with parsing, it's actual
  orchestration.
- **Noise budget flag** — `--noise low|med|high`. Maps to the
  existing kerb-map `noise_level` field on each CVE / finding.
  `low` skips chains tagged loud (PetitPotam, ZeroLogon).

---

## 5. v2.0 stateful tracking

To be *intelligent* — to pick the right next chain based on what's
already been compromised — kerb-chain needs persistent state across
chain steps and across runs. The complexity here is real and the
reason it's deferred to v2.

### State that needs to persist

| State | Why | Storage shape |
|---|---|---|
| **Captured credentials** | Don't re-roast an account whose hash you already have. Use the strongest credential type for each step (TGT > cert > NT hash > cleartext). | `{principal: {nt_hash, aes_key, ccache_path, cert_pfx, cleartext, captured_at, captured_by_chain}}` |
| **Compromised principals** | Who do we currently control? Whose TGT can we forge? Drives "what's reachable from here" decisions. | `set[principal_sid]` + access path graph |
| **Already-walked edges** | An ACL chain hop you took shouldn't be re-suggested. | `set[(source_sid, target_sid, attack_type)]` |
| **Failed attempts** | If `secretsdump bob_da` failed because the account was disabled, don't suggest it again. | `[{principal, attack, error_class, attempted_at}]` |
| **DC reachability** | LDAPS works on DC1 but not DC2. Kerberos auth works against DC1 (cert valid) but not DC2 (cert expired). | `{dc_fqdn: {transports_working, last_probe, kerberos_clock_skew}}` |
| **Time + noise budget** | Engagement window (4 hours), noise quota (≤ 5 high-noise actions). Drives "is this chain worth running NOW?" | `{budget_remaining_s, noise_used, noise_budget}` |
| **Operator constraints** | Out-of-scope OUs, must-not-touch accounts (CEO, CFO), allowed time-of-day windows. | `{out_of_scope_ous, blacklist_principals, time_window}` |

### The hard part isn't storage — it's *graph reasoning*

Stateful kerb-chain becomes:

> "Given everything I currently control + everything kerb-map sees +
> the engagement constraints, what's the lowest-noise / fastest /
> most-reliable next chain step toward (Domain Admin | krbtgt hash |
> specific operator-named target)?"

That's a shortest-path problem on a credential-flow graph where:

- Nodes = principals (users, computers, groups, certs)
- Edges = chains kerb-map can suggest (Shadow Creds write, DCSync
  rights, ACL hop, etc.)
- Edge cost = combination of (noise level × current noise budget,
  expected wall time, success probability based on prior attempts,
  operator-supplied target weight)

This is essentially what BloodHound's pathfinding does, but with
*executable* edges instead of just *visible* ones. A real v2.0
needs:

1. A graph backend (probably re-use BloodHound CE's Neo4j — kerb-map
   already exports there).
2. A pathfinding query that takes a start set (compromised principals)
   and a target set (operator's goal), returns the cheapest path.
3. Per-step credential-capture parsing so the graph stays in sync
   with reality.
4. Replanning after each step — the cheapest path changes as new
   credentials land.

### Why this is deferred past v0.1

The v0 commitment is "produce useful suggestions on a single scan
with no memory." That's already valuable. Stateful planning
multiplies the engineering surface by ~10× and pulls in BloodHound
as a hard dependency. Ship v0.1 → v1.0 standalone; reach for the
graph backend only when operators say "I want this to know what I
already did last week."

---

## Open questions for the author

1. **Repo location.** Same repo as kerb-map (`tools/kerb-chain/`)
   or separate repo (`kerb-chain` cloned alongside)? Separate keeps
   release cadences independent and lets kerb-chain depend on
   kerb-map's JSON output without tight coupling. Same-repo means
   shared CI + easy refactors.

2. **Output format.** Markdown to stdout (default) — also support
   `--out json` (for piping to other tools), `--out playbook`
   (Ansible / Atomic Red Team-style)?

3. **Scope for finding-data shape changes.** If v0.1 surfaces a need
   to change the `data` keys on a kerb-map finding, do we land that
   in kerb-map or wrap with a v0 adapter in kerb-chain? Suggest:
   land in kerb-map — the schema should serve both consumers.

4. **CTF mode.** Should `kerb-chain run --execute --yes` exist for
   automated CTF runs? Useful for kerb-map's own lab validation
   (run a chain, verify the captured credential matches the seed),
   but easy to misuse.

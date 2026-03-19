# kerb-map v1.2 — Defensive Security Improvements Proposal

**Generated:** 2026-03-19
**Context:** Research-driven feature proposals to strengthen kerb-map's defensive posture assessment capabilities. All features use read-only LDAP queries (and optionally SMB reads to SYSVOL) — no DA privileges required.

---

## Summary: 8 New Modules / Sub-modules

| # | Feature | Effort | Impact | New Module? |
|---|---------|--------|--------|-------------|
| 1 | LDAP Security Configuration | Low | High | `ldap_auditor.py` |
| 2 | Kerberos Hardening Assessment | Low | High | Extend `enc_auditor.py` |
| 3 | Service Account Risk Scoring | Medium | High | `svc_risk_scorer.py` |
| 4 | Stale/Orphaned Object Detection | Medium | High | Extend `hygiene_auditor.py` |
| 5 | Tiered Administration Compliance | Medium | Very High | `tier_auditor.py` |
| 6 | GPO Security Baseline Checks | High | Very High | `gpo_baseline.py` |
| 7 | Lateral Movement Path Analysis | High | Very High | `path_analyzer.py` |
| 8 | Azure AD / Entra ID Hybrid Security | Low | High | `hybrid_auditor.py` |

---

## 1. LDAP Security Configuration Audit (`ldap_auditor.py`)

**Why:** LDAP is the backbone of AD. Without signing/channel binding, attackers perform relay attacks (ntlmrelayx). Anonymous binds leak domain info to unauthenticated attackers. Post-2025, Microsoft defaults to requiring LDAP signing on new DCs, but legacy environments remain exposed.

### Checks

| Check | Method | Severity if Fail |
|-------|--------|------------------|
| **LDAP Signing Enforcement** | Parse Default Domain Controllers Policy GPO from SYSVOL (`GptTmpl.inf` → `LDAPServerIntegrity`). Also: attempt simple bind without signing on port 389 (like your existing `ldap_signing.py` CVE check, but more granular) | HIGH |
| **LDAP Channel Binding** | Parse GPO registry value `LdapEnforceChannelBinding` (0=Never, 1=When Supported, 2=Always). Values < 2 = finding | HIGH |
| **Anonymous Bind Detection** | Attempt anonymous LDAP bind (empty DN + empty password) → try reading rootDSE and enumerating objects. Non-destructive active test | CRITICAL |
| **LDAPS Availability** | Test TLS connection on port 636, validate certificate (expiry, SAN coverage) | MEDIUM |
| **Unsigned Bind Test** | Attempt simple bind (not SASL) over 389 without TLS — if it succeeds, signing not enforced (mirrors Event ID 2889) | HIGH |

### LDAP Queries
- GPO container: `(objectClass=groupPolicyContainer)` → get `gPCFileSysPath` for Default Domain Controllers Policy
- DC enumeration: `(userAccountControl:1.2.840.113556.1.4.803:=8192)` (already used elsewhere)
- SYSVOL read: `\\domain\SYSVOL\...\Policies\{GUID}\MACHINE\...\GptTmpl.inf` and `Registry.pol` via impacket SMB

### Report Output
Table: Control Name | Current Status | Expected Status | Risk Level. Plus active test results (anonymous bind: allowed/denied, unsigned bind: allowed/denied, LDAPS: available/cert details).

### Integration
- New CLI flag: `--ldap-security` (also included in `--all`)
- Scorer: Anonymous bind → priority 92, No signing → 85, No channel binding → 80

---

## 2. Kerberos Hardening Assessment (extend `enc_auditor.py`)

**Why:** Beyond RC4/DES detection (which you already do), there are additional Kerberos hardening indicators: gMSA adoption rate, reversible encryption, DES-only UAC flag, and Kerberos policy settings (ticket lifetimes). Post-CVE-2022-37966, Microsoft changed defaults but legacy accounts often retain insecure settings.

### New Checks to Add

| Check | LDAP Query/Attribute | Why It Matters |
|-------|---------------------|----------------|
| **gMSA Adoption Rate** | `(objectClass=msDS-GroupManagedServiceAccount)` — count vs regular SPN-bearing user accounts | gMSAs auto-rotate 120-char passwords; low adoption = manual password management risk |
| **Reversible Encryption Enabled** | `(userAccountControl:1.2.840.113556.1.4.803:=128)` (ENCRYPTED_TEXT_PWD_ALLOWED, 0x80) | Password stored in reversible form — equivalent to plaintext |
| **DES-Only UAC Flag** | `(userAccountControl:1.2.840.113556.1.4.803:=2097152)` (USE_DES_KEY_ONLY, 0x200000) | Trivially crackable tickets |
| **Unset Encryption Types** | Accounts with SPNs where `msDS-SupportedEncryptionTypes` is absent → defaults to RC4 | Silent RC4 exposure, often missed |
| **Kerberos Ticket Lifetimes** | Parse `GptTmpl.inf` from Default Domain Policy for `MaxTicketAge`, `MaxRenewAge`, `MaxServiceAge`, `MaxClockSkew` | Long TGT lifetime = extended persistence window |
| **gMSA Details** | `msDS-ManagedPasswordInterval`, `msDS-GroupMSAMembership`, `servicePrincipalName` on gMSAs | Verify rotation interval and access control |

### Report Output
Encryption posture summary table: Account | Enc Types (decoded) | Has SPN | Is Privileged | Is gMSA | Risk. Statistics: % accounts still using RC4/DES, gMSA adoption percentage, reversible encryption count. Kerberos policy settings vs. recommendations (TGT ≤ 10h, Renewal ≤ 7d).

### Integration
- Extend existing `enc_auditor.py` `EncAuditor` class with new methods
- Add gMSA/reversible/DES-only findings to scorer

---

## 3. Service Account Risk Scoring (`svc_risk_scorer.py`)

**Why:** Service accounts are the #1 target in AD. A single high-privilege SPN account with RC4, old password, and unconstrained delegation = immediate domain compromise. A composite risk score helps defenders prioritize remediation.

### Risk Scoring Model (0-100)

| Factor | Points | Detection |
|--------|--------|-----------|
| Has SPN (kerberoastable) | +10 base | `servicePrincipalName` present |
| RC4 or DES encryption | +15 | `msDS-SupportedEncryptionTypes` bitmask |
| Encryption type not set (defaults RC4) | +15 | Attribute absent |
| Password age > 1 year | +15 | `pwdLastSet` delta |
| Password age > 3 years | +25 | Same, higher threshold |
| Password never expires | +10 | UAC flag 0x10000 |
| Member of privileged group | +20 | Recursive `memberOf` check |
| adminCount=1 | +10 | Direct attribute |
| Unconstrained delegation | +20 | UAC flag 0x80000 |
| Constrained delegation to sensitive service | +10 | `msDS-AllowedToDelegateTo` contains LDAP/CIFS/HOST on DC |
| Not a gMSA | +5 | `objectClass` check |
| High-value SPN type (MSSQL/HTTP/CIFS) | +5 | SPN prefix parse |
| Credentials in description field | +10 | Regex on `description` |
| Enabled but never logged on | +5 | `lastLogonTimestamp` absent/0 |

### Classification
- 0-20: Low | 21-40: Medium | 41-60: High | 61+: Critical

### "Toxic Combinations" Flagging
Explicitly flag accounts with multiple high-risk factors, e.g.: "Domain Admin + SPN + RC4 + 5yr old password" = immediate remediation required.

### Report Output
Ranked table sorted by composite score. Per-account breakdown showing contributing factors. Remediation recommendations per account (switch to gMSA, rotate password, remove from privileged group, enable AES-only).

### Integration
- New CLI flag: `--svc-risk` (also in `--all`)
- Pulls data from existing SPN scanner + delegation mapper + encryption auditor — runs as a scoring overlay after those modules complete
- Top critical accounts fed to scorer

---

## 4. Stale/Orphaned Object Detection (extend `hygiene_auditor.py`)

**Why:** Stale objects silently expand attack surface. Orphaned SIDs in ACLs can be exploited. Abandoned computer accounts are easier to compromise. Empty privileged groups with permissions create unnecessary attack paths.

### New Checks

| Check | LDAP Query | Risk |
|-------|-----------|------|
| **Orphaned ForeignSecurityPrincipals** | `(objectClass=foreignSecurityPrincipal)` in `CN=ForeignSecurityPrincipals` — resolve each against trusted domains; unresolvable = orphaned from defunct trusts | MEDIUM-HIGH |
| **Empty Privileged Groups** | `(&(objectClass=group)(!(member=*))(adminCount=1))` — groups with admin flag but no members | MEDIUM |
| **Stale User Accounts (deep)** | Enabled users where BOTH `lastLogonTimestamp` > 90d AND `pwdLastSet` > 90d — truly abandoned vs. dormant | MEDIUM |
| **Computer Accounts with Old Passwords** | Enabled computers where `pwdLastSet` > 60 days (machine passwords normally rotate every 30d) — indicates broken trust relationship or offline machine | HIGH |
| **Orphaned SIDs in Critical ACLs** | Parse `nTSecurityDescriptor` on domain root, AdminSDHolder, and GPO objects. For each SID in DACL, attempt resolution — unresolvable SIDs = orphaned permissions | HIGH |
| **Stale AD-Integrated DNS Records** | `(objectClass=dnsNode)` under `CN=MicrosoftDNS,DC=DomainDnsZones` — cross-ref A records against computer accounts; DNS entries pointing to deleted machines = dangling records (DNS takeover risk) | MEDIUM |

### Implementation Notes
- Orphaned SID detection: Use impacket's `ldaptypes` to parse `nTSecurityDescriptor`. Cache all domain SIDs first, then check each ACE's SID against the cache. Exclude well-known SIDs (S-1-5-*).
- Focus orphaned SID checks on high-value containers only (domain root, AdminSDHolder, OU roots, GPOs) to keep query count manageable.

### Report Output
Separate tables per category. For orphaned SIDs: show the object, the orphaned SID, and what permissions it had. Count summary + risk rating based on where orphaned permissions exist.

---

## 5. Tiered Administration Model Compliance (`tier_auditor.py`)

**Why:** Without tier separation, a compromised workstation leads directly to domain admin compromise. Microsoft's tiered model / Enterprise Access Model is the foundational AD defensive architecture. Most environments don't implement it — an assessment tool highlights the gaps.

### Checks

| Check | Detection Method | If Missing |
|-------|-----------------|------------|
| **Tier 0 Asset Inventory** | Auto-identify: DCs (`UAC:8192`), ADCS CAs (`pKIEnrollmentService`), AD Connect sync accounts (`MSOL_*`), AZUREADSSOACC, Schema/Enterprise/Domain Admins (recursive), DCSync-capable accounts (parse DACL for replication GUIDs on domain root) | Informational — this is the baseline for other checks |
| **Authentication Policies/Silos** | `(objectClass=msDS-AuthNPolicy)` and `(objectClass=msDS-AuthNPolicySilo)` — if zero exist, no Kerberos-level tier enforcement | CRITICAL |
| **Privileged Account Logon Restrictions** | Check `userWorkstations` attribute on Tier 0 accounts — if empty, no PAW enforcement | HIGH |
| **Cross-Tier SPN Registration** | Tier 0 accounts with SPNs registered on non-DC systems | HIGH |
| **Cross-Tier Group Membership** | Tier 0 group members also in Tier 1/2 administrative groups | MEDIUM |
| **PAW Indicators** | Look for computer accounts matching PAW naming conventions (configurable) + check if any privileged accounts have `logonWorkstation` restrictions | MEDIUM |
| **Separate OU Structure** | Analyze OU tree for Tier 0/1/2 separation — separate OUs with different GPOs linked = tier awareness indicator | LOW-MEDIUM |

### Tier 0 DCSync Detection
Parse DACL on domain root for these extended right GUIDs:
- `DS-Replication-Get-Changes`: `1131f6aa-9c07-11d1-f79f-00c04fc2dcd2`
- `DS-Replication-Get-Changes-All`: `1131f6ad-9c07-11d1-f79f-00c04fc2dcd2`

Any account with both = DCSync-capable. This is a high-value defensive finding.

### Report Output
Compliance matrix: each tier control with Pass/Fail/Partial status. List all Tier 0 accounts with cross-tier violations. Executive summary: overall tier maturity level (None / Partial / Implemented). Count of DCSync-capable accounts.

### Integration
- New CLI flag: `--tier-audit` (also in `--all`)
- Scorer: No AuthN Policies → priority 88, Unrestricted Tier 0 logon → 82, DCSync non-standard accounts → 95

---

## 6. GPO Security Baseline Comparison (`gpo_baseline.py`)

**Why:** GPO misconfigurations are the most common source of domain-wide weakness. CIS benchmarks provide authoritative settings. Deviations = real, measurable risk.

### Implementation Approach
1. Enumerate GPOs: `(objectClass=groupPolicyContainer)` → get `gPCFileSysPath`
2. Read SYSVOL via impacket SMB: parse `GptTmpl.inf` (`[System Access]`, `[Kerberos Policy]`) and `Registry.pol`
3. Compare against built-in CIS Level 1 dictionary

### Key CIS L1 Checks

| Setting | CIS Recommendation | Source File |
|---------|-------------------|-------------|
| MinimumPasswordLength | >= 14 | GptTmpl.inf |
| PasswordComplexity | 1 (enabled) | GptTmpl.inf |
| LockoutBadCount | <= 5 | GptTmpl.inf |
| MaximumPasswordAge | <= 365 days | GptTmpl.inf |
| LM Authentication Level | 5 (NTLMv2 only) | Registry.pol |
| LDAP Client Signing | >= 1 (Negotiate) | Registry.pol |
| WDigest Authentication | 0 (disabled) | Registry.pol |
| CachedLogonsCount | <= 4 | Registry.pol |
| SMB Signing Required | 1 | Registry.pol |
| Restrict Anonymous SAM | 1 | Registry.pol |
| Kerberos AES Only | Disable DES/RC4 | GptTmpl.inf |
| MaxTicketAge | <= 10 hours | GptTmpl.inf |
| MaxRenewAge | <= 7 days | GptTmpl.inf |

### Report Output
Table: Setting Name | GPO Name | Current Value | Expected (CIS L1) | Status (Pass/Fail/Not Configured). Grouped by category. Summary: % of CIS L1 controls met.

### Integration
- New CLI flag: `--gpo-baseline` (also in `--all`)
- Requires SMB read to SYSVOL (any authenticated user has this by default)
- WDigest enabled → Scorer priority 85, No SMB signing → 80, NTLMv1 allowed → 82

---

## 7. Lateral Movement Path Analysis (`path_analyzer.py`)

**Why:** Attackers chain local admin rights, group nesting, and ACL edges to reach Domain Admin. A lightweight LDAP-only graph analysis provides BloodHound-like value without deploying collection agents.

### Data Collection

| Edge Type | Source | Detection |
|-----------|--------|-----------|
| **Group Nesting** | LDAP recursive membership (`memberOf:1.2.840.113556.1.4.1941:=<DN>`) | Build nested graph from each privileged group backwards |
| **GPO-Based Local Admin** | Parse Restricted Groups in `GptTmpl.inf` + GPP `Groups.xml` from SYSVOL | Reveals which domain groups → local Administrators on which OUs |
| **Dangerous ACL Edges** | Parse `nTSecurityDescriptor` on user/group/computer objects | GenericAll, GenericWrite, WriteDACL, WriteOwner, ForceChangePassword, Write to `msDS-AllowedToActOnBehalfOfOtherIdentity` (RBCD), Write to `msDS-KeyCredentialLink` (Shadow Credentials) |
| **AdminCount Orphans** | `(adminCount=1)` accounts not in protected groups | Stale locked-down ACLs on accounts no longer privileged |

### Analysis Logic
1. Build directed graph: nodes = principals + computers, edges = "member of" / "admin on" / "ACL right over"
2. From each Tier 0 asset, BFS backwards to find all principals with a path
3. Count total principals with a path to DA ("blast radius")
4. Identify shortest paths and "chokepoint" accounts/groups — nodes that, if hardened, eliminate the most paths

### Report Output
Summary: total attack paths, blast radius number. Chokepoint table: accounts appearing in most paths. Text-based path representation: `UserA → memberOf → GroupB → GPO local admin → ServerC → GenericAll → Domain Admins`. Actionable recommendations per path.

### Integration
- New CLI flag: `--paths` (also in `--all`)
- Heavy module — consider making it opt-in only (not in `--all`, require explicit `--paths`)
- Top chokepoint accounts → Scorer with priority based on path count

---

## 8. Azure AD / Entra ID Hybrid Security (`hybrid_auditor.py`)

**Why:** Hybrid environments create bidirectional attack paths. The MSOL_ account has DCSync rights by default. AZUREADSSOACC's static password enables Silver Tickets to impersonate any synced user in Entra ID. PTA agents receive cleartext passwords.

### Detection & Checks

| Check | LDAP Query | Severity |
|-------|-----------|----------|
| **MSOL_ Sync Account** | `(sAMAccountName=MSOL_*)` or `(description=*configured to synchronize to tenant*)` — check password age, group membership, DCSync permissions on domain root | HIGH (expected presence, but monitor age/perms) |
| **AZUREADSSOACC** | `(sAMAccountName=AZUREADSSOACC$)` — check `pwdLastSet` (should rotate every 30d, almost never does), `msDS-SupportedEncryptionTypes` (should be AES-only) | CRITICAL if password > 90d |
| **Hybrid Join SCP** | Query `CN=62a0ff2e-97b9-4513-943f-0d221bd30080,CN=Device Registration Configuration,CN=Services,CN=Configuration,...` — `keywords` attribute contains tenant ID | Informational |
| **MSOL_ DCSync Permissions** | Parse DACL on domain root for MSOL_ account's SID — check for `DS-Replication-Get-Changes` + `DS-Replication-Get-Changes-All` GUIDs | Informational (expected but document) |
| **Synced Account Identification** | `(msDS-ExternalDirectoryObjectId=*)` — identifies cloud-synced accounts | Informational |
| **PTA Agent Indicators** | Look for service accounts/computers associated with PTA, check AuthN Policy assignments | MEDIUM |

### Report Output
Hybrid status: detected/not detected + authentication method indicators. Per hybrid account: password age, permissions, risk. AZUREADSSOACC password rotation finding prominently featured. Recommendations: rotate AZUREADSSOACC key, restrict MSOL_ OU placement, treat AD Connect server as Tier 0.

### Integration
- New CLI flag: `--hybrid` (also in `--all`)
- If no hybrid indicators found: "No hybrid join detected — skipping"
- AZUREADSSOACC with old password → Scorer priority 90

---

## Implementation Priority (Recommended Order)

### Phase 1 — Quick Wins (v1.2)
1. **LDAP Security Configuration** — straightforward active tests + GPO parsing, highest ROI
2. **Kerberos Hardening** — mostly new LDAP queries on objects already enumerated
3. **Hybrid Security** — simple detection queries, high impact for hybrid environments

### Phase 2 — Scoring & Detection (v1.3)
4. **Service Account Risk Scoring** — builds on existing SPN/delegation/encryption data
5. **Stale/Orphaned Object Detection** — new queries, simple logic

### Phase 3 — Advanced Analysis (v1.4)
6. **Tiered Administration Compliance** — combines data from multiple modules
7. **GPO Security Baseline** — requires SYSVOL file parsing (GptTmpl.inf, Registry.pol)
8. **Lateral Movement Paths** — most complex, requires graph construction

---

## CLI Changes Summary

New flags for `build_parser()`:
```
--ldap-security    LDAP signing, channel binding, anonymous bind checks
--svc-risk         Service account composite risk scoring
--tier-audit       Tiered administration compliance assessment
--gpo-baseline     GPO settings vs CIS Level 1 benchmarks
--paths            Lateral movement path analysis (heavy — opt-in only)
--hybrid           Azure AD / Entra ID hybrid security checks
```

Extended existing modules (no new flags needed):
- `--encryption` → adds gMSA adoption, reversible encryption, DES-only UAC, ticket lifetimes
- `--hygiene` → adds orphaned objects, empty privileged groups, stale DNS, computer password age

---

## Dependencies

No new pip dependencies needed. All features use:
- `ldap3` — LDAP queries (existing)
- `impacket` — SMB for SYSVOL reads, security descriptor parsing (existing)
- `rich` — console output (existing)
- Standard library: `ssl` for LDAPS testing, `struct` for Registry.pol parsing

---

## Defensive Value Summary

These features shift kerb-map from primarily an **offensive enumeration tool** to a **dual-purpose security assessment platform**:

| Defensive Capability | Modules |
|---------------------|---------|
| **Infrastructure Hardening** | LDAP Security, Kerberos Hardening, GPO Baseline |
| **Account Lifecycle Management** | Stale/Orphaned Detection, Service Account Risk |
| **Privilege Management** | Tier Audit, Lateral Movement Paths |
| **Hybrid Security** | Hybrid Auditor |
| **Compliance Reporting** | GPO Baseline (CIS L1), Tier Audit (Microsoft EA Model) |

The result: defenders can run `kerb-map --all` against their own domain and get a comprehensive security posture report with prioritized remediation guidance — not just "here's what an attacker would target" but "here's what you should fix first and why."

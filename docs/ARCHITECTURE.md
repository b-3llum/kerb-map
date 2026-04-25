# Architecture

This document describes how kerb-map is wired internally — how a scan
flows from `cli.py` to a JSON / BloodHound zip / Markdown report,
where extension points live, and which invariants the codebase
relies on.

## Top-level flow

```
                       ┌─────────────┐
              ┌───────▶│  cli.py     │  argparse → main() → run_scan()
              │        └──────┬──────┘
              │               │
              │               ▼
              │        ┌─────────────┐
              │        │ LDAPClient  │  transport fallback chain:
              │        │             │  LDAPS → StartTLS → SASL/Krb → plain
              │        └──────┬──────┘
              │               │ binds; populates server.info from rootDSE
              │               ▼
              │        ┌─────────────┐
              │        │ get_domain  │  Domain SID, FL, MAQ, dnsHostName,
              │        │ _info()     │  pwd policy bits — all CLI-bound
              │        └──────┬──────┘  consumers read this dict.
              │               │
              │               ▼
              │        ┌─────────────┐
   one        │        │ time_check  │  SNTP probe of dc_ip; warn if skew
   process    │        │             │  > 300s (Kerberos tolerance).
   per scan ──┤        └──────┬──────┘
              │               │
              │               ▼
              │        ┌─────────────┐
              │        │  Legacy     │  SPNScanner / ASREPScanner /
              │        │  modules    │  DelegationMapper / UserEnumerator /
              │        │             │  EncAuditor / TrustMapper / CVEScanner
              │        └──────┬──────┘  / HygieneAuditor — direct LDAP queries,
              │               │          dataclass / dict outputs.
              │               ▼
              │        ┌─────────────┐
              │        │  v2 plugin  │  @register'd Module subclasses,
              │        │  loop       │  auto-discovered via pkgutil.
              │        │  (--v2)     │  Each emits Finding objects.
              │        └──────┬──────┘
              │               │
              │               ▼
              │        ┌─────────────┐
              │        │ Scorer.rank │  Cross-correlates legacy outputs +
              │        │             │  v2 findings into one ranked list[dict].
              │        └──────┬──────┘
              │               │
              │               ▼
              │        ┌─────────────┐
              │        │ substitute  │  Resolve <DC_IP>/<DOMAIN>/<DOMAIN_SID>/
              │        │ _placehold. │  <DC_NAME>/<BASE> in next_step strings.
              │        └──────┬──────┘
              │               │
              │               ▼
              │        ┌─────────────┐
              │        │ Reporter    │  Rich tables to stdout.
              │        │ + exporters │  JSON / BH-CE / CSV / Markdown to file.
              │        └─────────────┘
              │               │
              │               ▼
              │        ┌─────────────┐
              └────────│  Cache /    │  SQLite ~/.kerb-map/results.db.
                       │  Resume     │  --diff / --show-scan / --resume.
                       └─────────────┘
```

## Key invariants

1. **Read-only by default.** Every legacy module + every v2 plugin
   issues only LDAP `search` operations. The CVE scanner has a
   `requires_aggressive` lane (currently ZeroLogon, PrintNightmare,
   PetitPotam) that issues RPC binds. Anything in the aggressive
   lane MUST be gated behind `--aggressive` and MUST emit Win Event
   5145 — operators rely on the noise profile in `README.md` being
   accurate.

2. **No credentials on argv.** `resolve_secret()` accepts
   `--password-stdin`, `--password-env VAR`, interactive prompt, or
   the legacy `-p VALUE` form. New auth modes go through this helper
   so the password is never visible in `ps aux`.

3. **Findings have a single shape.** Every module — legacy or v2 —
   eventually contributes to the unified `targets: list[dict]` that
   the Scorer produces. The dict has these keys:

   ```
   target / attack / severity / priority / reason / next_step /
   category / mitre / data
   ```

   `priority: int 0–100`. `severity: CRITICAL | HIGH | MEDIUM | LOW |
   INFO`. New modules emitting Finding dataclasses get this for free
   via `Finding.as_dict()`.

4. **Domain SID is captured once.** `domain_info["domain_sid"]` is
   read from the `domainDNS` `objectSid` at scan start and substituted
   into Golden-Ticket / SID-history / DCSync `next_step` recipes. A
   regression here would emit `<DOMAIN_SID>` literal in the operator
   output.

5. **SD walks via `acl.py`.** `parse_sd()` + `walk_aces()` +
   `sd_control()` are the canonical entrypoints. Modules MUST go
   through them — direct impacket usage means a future schema /
   protocol drift only needs one fix. The session that found the
   `sd_control()` and `walk_aces()` field bugs is exactly the
   reason these are centralised.

6. **The v2 plugin contract is fixed.** A new module:
   - Subclasses `kerb_map.plugin.Module`
   - Has class attrs: `name`, `flag`, `description`, `category`
   - Implements `def scan(self, ctx: ScanContext) -> ScanResult`
   - Is decorated with `@register`
   - Lives anywhere under `kerb_map.modules`

   `pkgutil.walk_packages` does the discovery; nothing else needs
   to be edited.

## Package layout

```
kerb_map/
  cli.py                     argparse + run_scan() orchestration
  plugin.py                  Module / Finding / ScanContext / ScanResult / @register
  acl.py                     SR_SECURITY_DESCRIPTOR helpers (parse_sd, walk_aces, sd_control,
                             resolve_sids, AceMatch, well-known SID constants)
  ldap_helpers.py            attr() / attrs() / sid_to_str() / is_member_of() / find_chain_members()
  substitute.py              SubstitutionContext + apply_to_findings() (brief §3.5)
  resume.py                  ResumeState + list_resumable() (brief §3.8)
  time_check.py              SNTP-based DC clock-skew probe
  maintenance.py             --update plumbing (precheck, --tag, ff-only)
  diff.py                    --diff between cached scans

  auth/
    ldap_client.py           Transport fallback chain + paged query() + get_domain_info()

  modules/                   Legacy modules (direct LDAP) + v2 plugins (@register)
    spn_scanner.py           Kerberoast scoring
    asrep_scanner.py         AS-REP candidates
    delegation_mapper.py     unconstrained / constrained / RBCD
    user_enumerator.py       privileged users, stale, policy, trusts, LAPS, DnsAdmins, GPOs
    enc_auditor.py           RC4 / DES audit
    trust_mapper.py          Trust risk classifier
    hygiene_auditor.py       10-check defensive audit
    scorer.py                Cross-correlation + priority ranking
    timeroast.py             Tom Tervoort's MS-SNTP no-creds attack
    spray.py                 Lockout-aware password spray
    coercion.py              PetitPotam / DFSCoerce / PrinterBug surface
    cves/                    CVE check framework + per-CVE files
    # v2 plugins (auto-discovered):
    dcsync_rights.py         Get-Changes(-All) holders
    shadow_credentials.py    msDS-KeyCredentialLink writers + KCL inventory
    badsuccessor.py          dMSA predecessor-link abuse (CVE-2025-53779)
    prewin2k.py              S-1-5-32-554 + Authenticated Users membership
    gmsa_kds.py              Golden dMSA prereq (KDS root key DACL)
    tier0_acl.py             AdminSDHolder, DA/EA/SA, adminCount=1 DACL walk
    user_acl.py              Lateral-movement DACL walk on non-Tier-0 users
    ou_computer_create.py    RBCD pivot survival check
    adcs_extended.py         ESC4/5/7/9/13/15 (legacy adcs.py covers ESC1-8)

  output/
    logger.py                Rich-themed Logger singleton with -q/-v/-vv levels
    reporter.py              Rich tables (priority, CVE, hygiene, etc.)
    exporter.py              JSON / Markdown / CSV / BloodHound-Lite
    bloodhound_ce.py         Real BH CE 5.x ingestible zip + KerbMap* edges

  db/
    cache.py                 SQLite-backed scan store (~/.kerb-map/results.db)

tests/                       pytest tree mirroring kerb_map/
lab/                         Vagrantfile + provision_dc.sh + seed_vulnerabilities.sh
docs/                        This file + MODULE_AUTHORING.md + ENGAGEMENT_GUIDE.md +
                             v1.2-known-gaps.md
```

## Test mocking pattern

Every module test mocks LDAP at the `LDAPClient` level — never against
a real DC. The fixture pattern is:

```python
def _entry(values: dict):
    """Synthesise an ldap3.Entry with attribute access (.value) and
    dict-style access ([key]) and string coercion."""
    e = MagicMock()
    e.__contains__ = lambda self, k: k in values
    def _get(self, k):
        v = values[k]
        m = MagicMock()
        m.value = v
        m.__str__ = lambda self: "" if v is None else str(v)
        m.__iter__ = lambda self: iter(v) if isinstance(v, list) else iter([v])
        m.__bool__ = lambda self: bool(v)
        return m
    e.__getitem__ = _get
    return e


def _ldap(entries):
    ldap = MagicMock()
    ldap.query.return_value = entries
    return ldap
```

For modules that walk DACLs, also `monkeypatch.setattr` on
`parse_sd`, `walk_aces`, and `resolve_sids` — those are `import`ed
at module load so the patch needs the fully-qualified name from the
**module under test**, not from `acl.py`.

This pattern catches structural regressions cheaply, but it does NOT
catch real-LDAP-protocol or real-impacket-SD bugs — the
`sd_control()` / `walk_aces()` field bugs that surfaced in the
v1.2 lab test are the canonical example. Field validation is the
necessary complement.

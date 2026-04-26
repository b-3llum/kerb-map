# RESUME-HERE — kerb-map session pickup

Where the last session left off, what's safe to resume from, what's
next.

## Current state

- **Latest tag**: `v1.3.0` (pushed to origin, CHANGELOG entry leads
  with the four headline fixes operators should care about most).
- **Branch**: `main`, clean working tree (only `files/` and `up.pid`
  are untracked, both pre-date this work).
- **CI**: green on every PR through #47.
- **Test count**: 691 pass / 2 skipped.

## What v1.3.0 shipped

Five environments built and exercised end-to-end. Nine kerb-map bugs
+ five lab-seed bugs fixed across PRs #43 → #47:

| PR | Headline |
|---|---|
| #43 | bug-class grep + lab E2E (4 silent-failure fixes) |
| #44 | Key Admins / Enterprise Key Admins false-positive (CRITICAL miscalibration on every Windows DC, hidden by Samba) |
| #45 | RODC detection (silent partial-result fix) |
| #46 | Hardened-LDAP estate diagnosis (actionable error UX) |
| #47 | BadSuccessor schema-presence gate + Win2025 lab |

Full notes: `CHANGELOG.md` (1.3.0 section) and individual PR
descriptions on GitHub.

## Lab state

VirtualBox VMs are powered off. Disks remain on `/home/bellum/VirtualBox VMs/`:

| VM | State on disk | Domain | IP |
|---|---|---|---|
| `kerbmap-dc01` | seeded Samba lab | `lab.local` | 192.168.56.10 |
| `kerb-lab-dc22` | seeded Server 2022 DC | `kerblab2022.local` | 192.168.57.22 |
| `kerb-lab-dc25` | seeded Server 2025 DC | `kerblab2025.local` | 192.168.57.25 |
| `kerb-lab-rodc22` | half-promoted RODC (NTDS won't start) | (joined to `kerblab2022.local`) | 192.168.57.23 |

Bring any back up:

```
cd lab && vagrant up dc01                                            # Samba
cd lab && VAGRANT_VAGRANTFILE=Vagrantfile.win2022 vagrant up dc22    # Server 2022
cd lab && VAGRANT_VAGRANTFILE=Vagrantfile.win2025 vagrant up dc25    # Server 2025
cd lab && VAGRANT_VAGRANTFILE=Vagrantfile.win2022-rodc vagrant up rodc22  # RODC (broken, see below)
```

Default credentials (deterministic):
- Samba `lab.local`: `Administrator` / `LabAdmin1!`
- Win22 `kerblab2022.local`: `Administrator` / `vagrant` (post-promotion)
- Win25 `kerblab2025.local`: `Administrator` / `vagrant`

## Known-incomplete / blocked items

These are real engineering items, not mystery failures. Each names
the specific blocker.

### RODC integration positive path (PR #45 + #47)
- The detection code (`is_rodc` from `rootDSE.isReadOnly` + yellow
  banner in reporter) is unit-pinned with 6 tests. **Code is correct.**
- The lab promotion (`Install-ADDSDomainController -ReadOnlyReplica`)
  consistently fails with "replication operation was terminated
  because the system is shutting down" during the optional-features
  enable step. Pre-staging the RODC account + `-UseExistingAccount`
  hit a parameter-set incompatibility. `-CriticalReplicationOnly`
  doesn't bypass the optional-features step.
- **Pickup path**: either disable AD Recycle Bin on dc22 before
  promoting rodc22, or stand up the RODC against a fresh writable DC
  that hasn't enabled optional features. Lab debug, not kerb-map work.

### dc25 LDAPS cert + signing-required bind
- Server 2025 enforces LDAP signing at a layer below `LDAPServerIntegrity`
  registry — flipping the registry doesn't unhardened it.
- **Pickup path**: install AD CS on dc25 + auto-enroll the LDAPS cert,
  OR scan from a Windows host. Both lab-side. The kerb-map hint
  message (PR #46) correctly fires; that's the deliverable.

### dc25 vs Samba v2-plugin diff
- Couldn't run because of the bind issue above. The BadSuccessor
  schema-presence gate (PR #47) would let it proceed once the bind
  is fixed.

## What's next

### kerb-chain (separate repo)
- Scope doc was written this session, then **moved to its own repo**
  at the user's direction. The doc no longer lives here.
- Next session for that work happens in the kerb-chain repo, starting
  from the scope decisions in that doc.
- v0.1 recommendation in the scope doc: **Shadow Credentials (write
  access)** as the single chain-target. Rationale: clean single-tool
  chain (certipy), 4 deterministic steps, output (NT hash + cert) is
  reusable in subsequent chains.

### kerb-map v1.3.x follow-ups (still here, deferred from v1.3.0)
None of these are blockers — pick up only if a real engagement
surfaces them or the user redirects.

1. **ldap3 GSSAPI signing layer.** Library limit at
   `ldap3/protocol/sasl/kerberos.py` L216 hard-codes
   `NO_SECURITY_LAYER`. Real fix is upstream-ldap3; until then
   PR #46's hint is the operator-facing answer. If the upstream
   fix lands, the hint can be replaced with an actually-working
   SASL bind.
2. **RODC integration test path.** See above. If a future operator
   gets a working RODC, run `kerb-map --all --v2` against it and
   verify: yellow banner fires, partial-result behaviour degrades
   gracefully, no false CRITICALs from missing replica data.
3. **Multi-domain forest validation.** Trust mapper enumerates
   trusts but doesn't pivot through them. Cross-domain attack
   chains (SID History, foreign-security-principal compromise)
   untested.
4. **kerb-chain integration.** Once kerb-chain v0.1 ships, kerb-map's
   JSON output schema may need adjustments based on what the
   consumer actually wants. Prefer landing schema changes in
   kerb-map (one source of truth) over wrapping with adapters.

## Files of interest if resuming

- `docs/v1.2-known-gaps.md` — original gaps doc, still the
  authoritative scope-vs-shipped record. v1.3.0 closed gaps #1
  (most subgaps) and the BadSuccessor edge case under #1.
- `docs/ARCHITECTURE.md` / `MODULE_AUTHORING.md` / `ENGAGEMENT_GUIDE.md`
  — onboarding for new modules.
- `lab/win/seed_vulnerabilities.ps1` — Windows seed, `$Realm` auto-detects
  via `Get-ADDomain` so the same seed runs against any kerblab*.local
  lab. Override via `KERBLAB_REALM` / `KERBLAB_BASEDN` env vars.
- `lab/seed_vulnerabilities.sh` — Samba seed, `STUB_COUNT` env var
  (default 1500) controls scale-test user population.

## Don't redo without re-reading

These were settled in previous sessions and shouldn't be re-litigated
without a new signal:

- The BloodHound CE sidecar approach (`_kerbmap_metadata.json`) +
  per-node `Aces` folding for the 3 finding classes that have
  recognised SharpHound `RightName`s. PR #40. The remaining 13
  finding classes ship as sidecar-only by design — folding them
  needs `CertTemplate` / `OU` / dMSA node enumeration which is
  v2.0 BH-CE work, not a kerb-map gap.
- The hygiene auditor SID-based group lookups (PR #43). Locale-
  portability is fixed; CN-based lookups would re-introduce the
  German / French AD silent-failure.
- The hardened-LDAP hint message wording (PR #46). Operators have
  read it; rewording would force them to relearn the workaround.

## Cleanup state

This session left:
- Working tree clean (only pre-existing untracked items).
- All branches in sync with origin.
- No leftover Python loops, vagrant ssh sessions, monitor processes.
- VirtualBox VMs powered off (disks intact for resume).

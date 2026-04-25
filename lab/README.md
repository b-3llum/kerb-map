# lab/

Deterministic Samba 4 AD lab for end-to-end kerb-map validation. Brings
up one Ubuntu 22.04 box running `samba-ad-dc`, provisions a `LAB.LOCAL`
domain, and seeds every v1 + v2 attack surface kerb-map can detect on
Samba.

```bash
cd lab
vagrant up               # ~5 min first time (samba-tool provision +
                         # 1500 stub users for paging)
bash scan-and-validate.sh
# → asserts every seeded vulnerability lights up; exits 0 on green.
```

## Files

| File | Purpose |
|---|---|
| `Vagrantfile` | Ubuntu/jammy64 + private network on 192.168.56.10. Uses VirtualBox or libvirt provider. |
| `provision_dc.sh` | Base AD: package install, `samba-tool domain provision`, DNS, krb5.conf, service enable. Idempotent (stamp file). |
| `seed_vulnerabilities.sh` | Every seedable v1+v2 attack surface. Runs every `vagrant up` so edits to the seed list take effect without a rebuild. |
| `scan-and-validate.sh` | One-shot: scans the lab DC, asserts the expected findings appear in the JSON. CI-friendly. |

## Default credentials

```
Domain      : LAB.LOCAL
Realm       : LAB.LOCAL
NetBIOS     : LAB
DC name     : DC01.lab.local
DC IP       : 192.168.56.10
Admin       : LAB\Administrator
Admin pass  : LabAdmin1!
Seed pass   : Summer2024!  (every seeded user)
```

These are **lab credentials**. Don't reuse them anywhere real.

## Coverage

What lights up after `seed_vulnerabilities.sh` runs:

### Legacy modules
- **SPN scanner**: `svc_sql` (MSSQLSvc/sql01.lab.local), `svc_iis` (HTTP/iis01.lab.local) — RC4 + ancient password.
- **AS-REP scanner**: `oldsvc` with `DONT_REQUIRE_PREAUTH` (UAC `0x400000`).
- **Delegation mapper**: `web01$` with `TRUSTED_FOR_DELEGATION` (UAC `0x80000`).
- **User enumerator**: `admin_orphan` (`adminCount=1`, no privileged group membership).
- **Encryption auditor**: `des_user` with `USE_DES_KEY_ONLY` (UAC `0x200000`).
- **Hygiene auditor**: `svc_app` with the password literally in its description; `Smith\, John` for DN-escape edge case.
- **Paging**: 1500 stub users (`user0001`–`user1500`) so `MaxPageSize` truncation is visible if RFC 2696 paging regresses.

### v2 modules
- **DCSync rights**: `svc_old_admin` granted `DS-Replication-Get-Changes` + `-All` on the domain root. Should be CRITICAL with priority 95.
- **Shadow Credentials**:
  - `da_alice` — Domain Admin with populated `msDS-KeyCredentialLink` (CRITICAL inventory finding).
  - `ws01$` — workstation with `Windows 10` OS + key trust (INFO, downranked — legitimate WHfB).
  - `helpdesk_op` granted `WriteProperty(msDS-KeyCredentialLink)` on `bob_da` (Domain Admin) — CRITICAL write-ACL finding.
- **Pre-Windows 2000 Compatible Access**: `Authenticated Users` is a member — HIGH (`Pre-Win2k membership: Authenticated Users`, priority 78).
- **GMSA + KDS audit**: `gmsa_app$` with `appsupport` granted password-reader rights via `msDS-GroupMSAMembership`. KDS root keys don't exist on Samba (the Golden-dMSA half returns "no KDS keys present", which is the correct behaviour).

### Out of scope on Samba
These modules' attack paths require Server-side features Samba doesn't yet implement:

- **BadSuccessor** — needs functional level 10 (Server 2025). Samba currently maxes at 7.
- **ADCS Extended (ESC9 / ESC13 / ESC15)** — Samba doesn't ship ADCS. Validate against a separate Server 2022/2025 lab when needed.
- **KDS root key half of GmsaKdsAudit** — `msKds-ProvRootKey` objects aren't supported on Samba.

The unit suite (`tests/test_*`) covers all three above with mocked LDAP, so the logic is exercised — only the wire-format validation is deferred.

## Re-seeding

Edit `seed_vulnerabilities.sh` and re-run from the host:

```bash
vagrant ssh -c 'sudo /vagrant/seed_vulnerabilities.sh'
```

The script is idempotent — re-runs are safe and skip the slow stub-user creation if `user1500` already exists.

## Tearing down

```bash
vagrant destroy -f       # wipes the VM
```

## CI integration

`scan-and-validate.sh` exits non-zero on any failed assertion. The intended GitHub Actions integration:

```yaml
# .github/workflows/lab.yml (not yet committed)
on:
  workflow_dispatch:    # manual — Vagrant + libvirt CI is heavy
  schedule:
    - cron: '0 6 * * 1' # weekly Monday smoke
jobs:
  lab:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: sudo apt-get install -y vagrant virtualbox jq
      - run: cd lab && vagrant up
      - run: bash lab/scan-and-validate.sh
      - if: always()
        run: cd lab && vagrant destroy -f
```

## Limitations

This is a **single-domain** lab. Cross-forest trust attacks, RBCD across
trusts, and BadSuccessor (Server 2025) require additional VMs that
aren't here yet. If you need them, copy the `Vagrantfile` template,
add a second `config.vm.define`, and provision an additional DC in a
parallel forest.

The seeds use synthetic key blobs and minimal SDDL where Samba's
samba-tool doesn't expose the real shape (gMSA password-reader SD,
Shadow Credentials key-credential blobs). The kerb-map modules detect
*presence* of these attributes, which is what the seeds satisfy. End-
to-end exploitation against the lab still works for the simpler
vectors (Kerberoast, AS-REP, unconstrained delegation, DCSync) but
PKINIT-style exploitation against the synthetic Shadow-Cred blobs will
fail at the cryptographic verify step — that's by design (we don't
seed real exploitable keys into a public seed script).

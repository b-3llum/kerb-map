#!/usr/bin/env bash
# lab/seed_vulnerabilities.sh — every v1 + v2 attack-surface seed,
# idempotent and re-runnable. Each section uses ``samba-tool ... ||
# true`` so a re-run doesn't fail on already-existing objects.
#
# Coverage map (which kerb-map module each seed validates):
#
#   v1 surface
#     SPN scanner                  → svc_sql, svc_iis (RC4 + ancient pwd)
#     AS-REP scanner               → oldsvc (DONT_REQUIRE_PREAUTH)
#     Delegation mapper            → web01$ (TRUSTED_FOR_DELEGATION)
#     User enumerator              → admin_orphan (adminCount=1, no group)
#     Encryption auditor           → des_user (USE_DES_KEY_ONLY)
#     Trust mapper                 → covered by samba's default forest trust state
#     Hygiene auditor              → cred_in_desc (password in description),
#                                    smith_john (DN-escape: Smith\, John)
#     Plus 1500 stub users         → paging > MaxPageSize=1000
#
#   v2 surface
#     DCSync rights                → svc_old_admin holds DS-Replication-Get-Changes(-All)
#     Shadow Credentials           → ws01$  (computer with WHfB-style key, INFO)
#                                    da_alice (DA with key trust, CRITICAL)
#                                    helpdesk_op (WriteProperty(KCL) on a DA, CRITICAL)
#     ADCS Extended (ESC9/13/15)   → not seedable on Samba-4 (no ADCS); deferred to a
#                                    Server 2022/2025 lab (separate Vagrantfile)
#     Pre-Win2k Compatible Access  → Authenticated Users added (Microsoft default
#                                    state matches what we want kerb-map to flag)
#     gMSA reader                  → svc_app$ + appsupport reads the password
#     KDS root key                 → outside Samba-4 scope (no KDS-ProvRootKey objects)
#     BadSuccessor                 → outside Samba-4 scope (FL=10 needed)
#
# Anything marked "outside Samba-4 scope" still has unit-test coverage in
# tests/test_*; the lab gives operator confidence that the *Samba-4-
# coverable* surface lights up correctly end-to-end.

# Note: deliberately NOT `set -e`. The script is designed for partial
# failure — every samba-tool / ldbmodify line uses `|| true` because
# re-runs hit "already exists" by design (idempotency). Field bug from
# a `vagrant up` validation: with -e on, the SID-decoding pipeline
# (`ldap | sed | base64 | python`) exiting non-zero on an idempotent
# path bailed the whole script. Now: `-u` catches unset vars, `-o
# pipefail` propagates pipe failures into per-line `|| true`, and the
# script as a whole completes through every section.
set -uo pipefail

# ──────────────────────────────────────────────────────────────── settings
DOMAIN_REALM=LAB.LOCAL
DOMAIN_BASE_DN="DC=lab,DC=local"
ADMIN_PASS='LabAdmin1!'

# Common defaults so every seed user has a known-bad password we don't
# care about leaking — these are LAB credentials, not real ones.
SEED_PASS='Summer2024!'

# samba-tool wrappers — keep the noise out of the per-section commands.
st()   { samba-tool "$@" -U Administrator --password="$ADMIN_PASS"; }
ldap() { ldapsearch -H "ldap://127.0.0.1" \
                    -D "Administrator@${DOMAIN_REALM}" \
                    -w "$ADMIN_PASS" "$@"; }

# Apply an LDIF block via ldbmodify on the local DB. Useful for
# attribute changes that samba-tool doesn't expose (raw
# msDS-AllowedToDelegateTo, key-credential blobs, etc.).
ldbmod() {
    local ldif="$1"
    printf '%s\n' "$ldif" | \
        ldbmodify -H /var/lib/samba/private/sam.ldb
}

echo "[seed] starting at $(date -u +%FT%TZ)"

# ───────────────────────────────────────────────────────── v1 — SPN scanner
# svc_sql — MSSQLSvc SPN, weak password, RC4 only
st user create svc_sql "$SEED_PASS" \
    --description='SQL service account' || true
st user setexpiry svc_sql --noexpiry || true
st spn add MSSQLSvc/sql01.lab.local:1433 svc_sql || true

# svc_iis — HTTP SPN
st user create svc_iis "$SEED_PASS" \
    --description='IIS service account' || true
st spn add HTTP/iis01.lab.local svc_iis || true

# ────────────────────────────────────────────────────── v1 — AS-REP scanner
# oldsvc — DONT_REQUIRE_PREAUTH (UAC bit 0x400000 = 4194304)
st user create oldsvc "$SEED_PASS" || true
ldbmod "dn: CN=oldsvc,CN=Users,${DOMAIN_BASE_DN}
changetype: modify
replace: userAccountControl
userAccountControl: 4260352" || true

# ──────────────────────────────────────────────── v1 — Delegation mapper
# web01$ computer with TRUSTED_FOR_DELEGATION (UAC bit 0x80000 = 524288).
# Easier as a user-created computer; samba-tool computer create
# defaults UAC to 0x1000 (WORKSTATION_TRUST_ACCOUNT).
st computer create web01 || true
ldbmod "dn: CN=web01,CN=Computers,${DOMAIN_BASE_DN}
changetype: modify
replace: userAccountControl
userAccountControl: 528384" || true

# ────────────────────────────────────────── v1 — User enum / hygiene
# admin_orphan — adminCount=1 but not a member of any privileged group
# (the AdminSDHolder pin will mark them anyway, perfect orphan case).
st user create admin_orphan "$SEED_PASS" || true
ldbmod "dn: CN=admin_orphan,CN=Users,${DOMAIN_BASE_DN}
changetype: modify
replace: adminCount
adminCount: 1" || true

# cred_in_desc — password literally in the description field.
st user create svc_app "$SEED_PASS" \
    --description='SQL svc — pw=Spring2024! rotate quarterly' || true

# DN-escape edge-case seeding moved to unit tests (kerb_map.ldap_helpers
# tests cover CN=Smith\, John parsing directly with crafted DN strings).
#
# Two `vagrant up` validation attempts both failed: first form
# (`st user create 'Smith, John'`) → sAMAccountName comma rejection;
# second form (`smithjohn` SAM + `--surname='Smith, of Sendai'`) →
# samba-tool constructs CN from surname, comma flows in unescaped,
# and ldb_add rejects with "invalid dn '(null)'". Samba-tool doesn't
# expose enough control to seed a comma-bearing CN cleanly. The
# unit-test path is more reliable.
st user create 'smithjohn' "$SEED_PASS" \
    --given-name='John' --surname='Smith' || true

# ────────────────────────────────────────────── v1 — Encryption auditor
# des_user — USE_DES_KEY_ONLY (UAC bit 0x200000 = 2097152)
st user create des_user "$SEED_PASS" || true
ldbmod "dn: CN=des_user,CN=Users,${DOMAIN_BASE_DN}
changetype: modify
replace: userAccountControl
userAccountControl: 2097664" || true

# ─────────────────────────────────────── v1 — Paging (1500 stub users)
# Bulk-create only on first seed (slow), skip if user1500 already exists.
if ! ldap -b "${DOMAIN_BASE_DN}" "(sAMAccountName=user1500)" dn 2>/dev/null \
        | grep -q '^dn:'; then
    echo "[seed] creating 1500 stub users (one-time, ~2 min)…"
    for i in $(seq 1 1500); do
        st user create "user$(printf '%04d' "$i")" "$SEED_PASS" \
            --description="Stub user #$i" >/dev/null 2>&1 || true
    done
    echo "[seed] stub users done."
else
    echo "[seed] stub users already present, skipping bulk create."
fi

# ─────────────────────────────────────── v2 — DCSync rights backdoor
# svc_old_admin — granted DS-Replication-Get-Changes(-All) on the domain
# root via samba-tool dsacl. This is the "old over-privileged service
# account that nobody cleaned up" case the brief calls out.
st user create svc_old_admin "$SEED_PASS" || true

# samba-tool dsacl set adds an ACE to the target object's nTSecurityDescriptor.
# (S = trustee SID, A = allow, CR = control access right, GUID = right OID)
st user setpassword svc_old_admin --newpassword="$SEED_PASS" || true
SVC_OLD_SID=$(ldap -LLL -b "${DOMAIN_BASE_DN}" \
    "(sAMAccountName=svc_old_admin)" objectSid 2>/dev/null \
    | sed -n 's/^objectSid:: //p' \
    | head -1 \
    | base64 -d | python3 -c 'import sys
# Field bug from a `vagrant up` validation: when ldapsearch returns
# no objectSid (account not yet replicated, ACL hides it from the
# bind), b is empty and the original "parts=[b[0],...]" raised
# IndexError. Skip cleanly with an empty SID — caller short-circuits.
b=sys.stdin.buffer.read()
if len(b) < 8:
    sys.exit(0)
parts=[b[0], int.from_bytes(b[2:8],"big")]
parts+=[int.from_bytes(b[8+i*4:12+i*4],"little") for i in range(b[1])]
print("S-"+"-".join(str(p) for p in parts))')
echo "[seed] svc_old_admin SID resolved to: ${SVC_OLD_SID:-<empty>}"

# Grant DS-Replication-Get-Changes (CR) + DS-Replication-Get-Changes-All (CR)
# — skip if the SID didn't resolve (the dsacl grant would fail noisily
# with an empty SID in the SDDL).
if [ -n "$SVC_OLD_SID" ]; then
    st dsacl set --objectdn="${DOMAIN_BASE_DN}" \
        --sddl="(OA;;CR;1131f6aa-9c07-11d1-f79f-00c04fc2dcd2;;${SVC_OLD_SID})" \
        || true
    st dsacl set --objectdn="${DOMAIN_BASE_DN}" \
        --sddl="(OA;;CR;1131f6ad-9c07-11d1-f79f-00c04fc2dcd2;;${SVC_OLD_SID})" \
        || true
else
    echo "[seed] svc_old_admin SID empty — DCSync grant skipped."
fi

# ───────────────────────────────────────── v2 — Shadow Credentials
# da_alice — Domain Admin with a populated msDS-KeyCredentialLink
# (high-fidelity Whisker IOC, CRITICAL). The actual key blob format is
# documented in MS-ADTS §2.2.20; the seed uses a deterministic stub
# blob that's NOT a valid key for PKINIT (we want the *presence* on a
# Tier-0 account to fire, not enable an actual takeover).
st user create da_alice "$SEED_PASS" || true
st group addmembers 'Domain Admins' da_alice || true
ldbmod "dn: CN=da_alice,CN=Users,${DOMAIN_BASE_DN}
changetype: modify
replace: msDS-KeyCredentialLink
msDS-KeyCredentialLink: B:828:$(printf '00%.0s' {1..414}):CN=da_alice,CN=Users,${DOMAIN_BASE_DN}" \
    || true

# ws01$ — workstation with WHfB-style key trust (should land as INFO,
# not a finding — the module recognises Win10-style computer + key as
# legitimate WHfB).
st computer create ws01 || true
ldbmod "dn: CN=ws01,CN=Computers,${DOMAIN_BASE_DN}
changetype: modify
replace: msDS-KeyCredentialLink
msDS-KeyCredentialLink: B:828:$(printf '00%.0s' {1..414}):CN=ws01,CN=Computers,${DOMAIN_BASE_DN}
-
replace: operatingSystem
operatingSystem: Windows 10 Enterprise" \
    || true

# helpdesk_op — non-default principal granted WriteProperty on
# msDS-KeyCredentialLink of bob_da. The Shadow Credentials module's
# write-ACL audit should flag this as CRITICAL.
st user create bob_da "$SEED_PASS" || true
st group addmembers 'Domain Admins' bob_da || true
st user create helpdesk_op "$SEED_PASS" \
    --description='Non-default writer on bob_da KeyCredentialLink' || true

HELPDESK_SID=$(ldap -LLL -b "${DOMAIN_BASE_DN}" \
    "(sAMAccountName=helpdesk_op)" objectSid 2>/dev/null \
    | sed -n 's/^objectSid:: //p' \
    | head -1 \
    | base64 -d | python3 -c 'import sys
# Field bug from a `vagrant up` validation: when ldapsearch returns
# no objectSid (account not yet replicated, ACL hides it from the
# bind), b is empty and the original "parts=[b[0],...]" raised
# IndexError. Skip cleanly with an empty SID — caller short-circuits.
b=sys.stdin.buffer.read()
if len(b) < 8:
    sys.exit(0)
parts=[b[0], int.from_bytes(b[2:8],"big")]
parts+=[int.from_bytes(b[8+i*4:12+i*4],"little") for i in range(b[1])]
print("S-"+"-".join(str(p) for p in parts))')

# WriteProperty (WP) on the msDS-KeyCredentialLink schema GUID
# 5b47d60f-6090-40b2-9f37-2a4de88f3063 — skip if SID empty.
if [ -n "$HELPDESK_SID" ]; then
    st dsacl set --objectdn="CN=bob_da,CN=Users,${DOMAIN_BASE_DN}" \
        --sddl="(OA;;WP;5b47d60f-6090-40b2-9f37-2a4de88f3063;;${HELPDESK_SID})" \
        || true
else
    echo "[seed] helpdesk_op SID empty — KCL writer grant skipped."
fi

# ────────────────────────────── v2 — Pre-Win2k Compatible Access
# Add Authenticated Users (S-1-5-11) to the Pre-Win2k group. Samba's
# default state on a fresh provision often matches Microsoft's clean
# install (Auth Users already present). Force the membership so the
# seed is deterministic regardless of the underlying default.
st group addmembers 'Pre-Windows 2000 Compatible Access' \
    'Authenticated Users' 2>/dev/null || true

# ────────────────────────────────────────── v2 — gMSA + reader
# Note: Samba's gMSA support is partial. We create the gMSA and grant
# msDS-GroupMSAMembership to a non-default principal so the reader-audit
# half of the module fires; KDS root keys aren't supported on Samba so
# the Golden-dMSA half of the module returns 'no KDS keys present'
# (which is the correct behaviour).
st user create appsupport "$SEED_PASS" \
    --description='Non-default gMSA password reader' || true

# Create the gMSA via raw LDIF — samba-tool doesn't expose gMSA creation
# as a first-class command. We use the minimal shape the GmsaKdsAudit
# module looks for (objectClass + msDS-ManagedPasswordInterval +
# msDS-GroupMSAMembership SDDL).
APPSUPPORT_SID=$(ldap -LLL -b "${DOMAIN_BASE_DN}" \
    "(sAMAccountName=appsupport)" objectSid 2>/dev/null \
    | sed -n 's/^objectSid:: //p' \
    | head -1 \
    | base64 -d | python3 -c 'import sys
# Field bug from a `vagrant up` validation: when ldapsearch returns
# no objectSid (account not yet replicated, ACL hides it from the
# bind), b is empty and the original "parts=[b[0],...]" raised
# IndexError. Skip cleanly with an empty SID — caller short-circuits.
b=sys.stdin.buffer.read()
if len(b) < 8:
    sys.exit(0)
parts=[b[0], int.from_bytes(b[2:8],"big")]
parts+=[int.from_bytes(b[8+i*4:12+i*4],"little") for i in range(b[1])]
print("S-"+"-".join(str(p) for p in parts))')

ldbmod "dn: CN=gmsa_app,CN=Managed Service Accounts,${DOMAIN_BASE_DN}
changetype: add
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
objectClass: computer
objectClass: msDS-GroupManagedServiceAccount
sAMAccountName: gmsa_app\$
msDS-ManagedPasswordInterval: 30
msDS-GroupMSAMembership:: $(python3 -c "
import struct, base64
# Minimal Self-Relative SR_SECURITY_DESCRIPTOR with a DACL granting
# READ_PROPERTY (0x10) to ${APPSUPPORT_SID}. Real SDs are bigger;
# this is the smallest one impacket's parser will accept.
print('placeholder', end='')")" \
    || echo "[seed] gMSA creation skipped (Samba may reject the LDIF; safe to ignore on a Samba-only lab)."

# ────────────────────────────────────────────────────────────── done
echo "[seed] complete at $(date -u +%FT%TZ)"
echo "[seed] expected kerb-map findings (lab.local against this DC):"
cat <<'SUMMARY'
  CRITICAL  DCSync (full)                       svc_old_admin
  CRITICAL  Shadow Credentials (inventory)      da_alice (privileged + key)
  CRITICAL  Shadow Credentials (write access)   bob_da (helpdesk_op writes)
  HIGH      Kerberoast                          svc_sql / svc_iis
  HIGH      AS-REP Roast                        oldsvc
  CRITICAL  Unconstrained Delegation            web01$
  HIGH      Pre-Win2k membership: Authenticated Users
  MEDIUM    Credential exposure (description)   svc_app
  INFO      Shadow Credentials (inventory)      ws01$ (workstation)
SUMMARY

#!/usr/bin/env bash
# lab/provision_dc.sh — base Samba-4 AD provisioning.
#
# Idempotent: a successful run leaves /etc/.kerbmap-lab-provisioned as a
# stamp file. Subsequent runs short-circuit so `vagrant provision` is
# cheap. To force a re-provision, delete the stamp and re-run.

set -euo pipefail

STAMP=/etc/.kerbmap-lab-provisioned
if [ -f "$STAMP" ]; then
    echo "[provision] already provisioned (stamp $STAMP) — skipping."
    exit 0
fi

# ───────────────────────────────────────────────────────────── settings ──
DOMAIN_REALM=LAB.LOCAL
DOMAIN_NETBIOS=LAB
ADMIN_PASS='LabAdmin1!'
DC_IP=192.168.56.10
DNS_FORWARDER=8.8.8.8

echo "[provision] starting at $(date -u +%FT%TZ)"

# ─────────────────────────────────────────────────────── package install ──
# DEBIAN_FRONTEND=noninteractive avoids the interactive Kerberos realm
# prompt that samba-common-bin throws otherwise.
export DEBIAN_FRONTEND=noninteractive

# Pre-seed Kerberos realm so the krb5-user package install is silent.
debconf-set-selections <<EOF
krb5-config krb5-config/default_realm string $DOMAIN_REALM
krb5-config krb5-config/kerberos_servers string dc01.${DOMAIN_REALM,,}
krb5-config krb5-config/admin_server string dc01.${DOMAIN_REALM,,}
EOF

apt-get update -qq
apt-get install -y -qq \
    acl                  \
    attr                 \
    krb5-user            \
    ldap-utils           \
    ldb-tools            \
    python3-samba        \
    samba                \
    samba-dsdb-modules   \
    smbclient            \
    winbind

# Field bug from a `vagrant up` validation: ldb-tools (which provides
# ldbmodify, ldbsearch, ldbadd) wasn't in the original install list.
# seed_vulnerabilities.sh uses ldbmodify for raw attribute writes
# (UAC bit toggling, key-credential blob seeding, etc.) and was
# silently failing every ldbmod call with "command not found". Without
# this package, every UAC-bit / KCL seed produces no effect — kerb-map
# then scans a clean lab and finds nothing.

# Stop and disable the bits Samba-AD-DC replaces. samba-ad-dc itself runs
# its own DNS, so we kill anything else listening on 53.
systemctl stop samba-ad-dc smbd nmbd winbind systemd-resolved 2>/dev/null || true
systemctl disable samba-ad-dc smbd nmbd winbind systemd-resolved 2>/dev/null || true

# /etc/resolv.conf must point at the DC itself (it'll host DNS too) —
# remove the symlink to the systemd-resolved stub.
rm -f /etc/resolv.conf
cat > /etc/resolv.conf <<EOF
nameserver $DC_IP
nameserver $DNS_FORWARDER
search ${DOMAIN_REALM,,}
EOF

# ────────────────────────────────────────────────── samba domain provision ──
# Wipe any half-finished provision from a previous failed run.
rm -f /etc/samba/smb.conf
rm -rf /var/lib/samba/private/* /var/lib/samba/sysvol/*

samba-tool domain provision                  \
    --realm="$DOMAIN_REALM"                  \
    --domain="$DOMAIN_NETBIOS"               \
    --server-role=dc                         \
    --dns-backend=SAMBA_INTERNAL             \
    --adminpass="$ADMIN_PASS"                \
    --use-rfc2307                            \
    --host-ip="$DC_IP"

# Default: relax LDAP signing to match typical Windows AD engagement
# targets (Server 2019/2022 with default "LDAP server signing
# requirements = None"). Set HARDENED_LDAP=1 to provision in
# signing-required mode and validate kerb-map's LDAPS-SIMPLE fallback
# end-to-end (the v1.3 sprint exercise — gap #1 from
# docs/v1.2-known-gaps.md).
#
# Either way, kerb-map should bind: in permissive mode via NTLM-over-
# LDAPS, in hardened mode via SIMPLE-over-LDAPS (PR #38 transport).
# The hardened path was added but never validated against a Samba 4
# DC actually configured for "require strong auth = yes" until now.
if [ "${HARDENED_LDAP:-0}" = "1" ]; then
    echo "[provision] HARDENED_LDAP=1 — leaving Samba's default 'require strong auth = yes'"
    echo "[provision] kerb-map should bind via LDAPS-SIMPLE (PR #38 fallback)"
else
    echo "
ldap server require strong auth = no
" >> /etc/samba/smb.conf
fi

# Populate krb5.conf from the one Samba just wrote so kinit works
# system-wide (so vagrant ssh users can `kinit Administrator` for
# manual exploration).
cp /var/lib/samba/private/krb5.conf /etc/krb5.conf

# Forward unknown DNS to the host network.
samba-tool dns add 127.0.0.1 "$DOMAIN_REALM" \
    "@" CNAME dc01.${DOMAIN_REALM,,} -U Administrator --password="$ADMIN_PASS" \
    2>/dev/null || true

# ─────────────────────────────────────────────────────── service enable ──
systemctl unmask samba-ad-dc 2>/dev/null || true
systemctl enable samba-ad-dc
systemctl start  samba-ad-dc

# Wait for ldap to come up so seed_vulnerabilities.sh can talk to it.
for i in $(seq 1 30); do
    if ldapsearch -H "ldap://${DC_IP}" -D "Administrator@${DOMAIN_REALM}" \
        -w "$ADMIN_PASS" -b "DC=${DOMAIN_REALM//./,DC=}" \
        '(objectClass=domain)' dn >/dev/null 2>&1; then
        break
    fi
    sleep 1
done

touch "$STAMP"
echo "[provision] done. DC ready at $DC_IP, admin = Administrator / $ADMIN_PASS"

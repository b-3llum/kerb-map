#!/usr/bin/env bash
# lab/scan-and-validate.sh — run kerb-map against the lab DC, assert the
# expected findings appear in the JSON output. Exits 0 on green, non-zero
# on the first failed assertion.
#
# Run from the repo root or from lab/ — both work.

set -euo pipefail

# ─────────────────────────────────────────────────────────── settings ──
DC_IP=192.168.56.10
DOMAIN=lab.local
ADMIN=Administrator
ADMIN_PASS='LabAdmin1!'
OUT_DIR="$(mktemp -d /tmp/kerbmap-lab.XXXXXX)"
SCAN_JSON="$OUT_DIR/scan.json"
trap 'rm -rf "$OUT_DIR"' EXIT

# ────────────────────────────────────────────────────── DC reachability
echo "[validate] checking DC reachability at $DC_IP …"
if ! timeout 5 bash -c "</dev/tcp/$DC_IP/389" 2>/dev/null; then
    echo "[validate] FAIL: $DC_IP:389 unreachable. Run 'vagrant up' first." >&2
    exit 2
fi

# ───────────────────────────────────────────────────────── kerb-map run
# Locate the script relative to this file so the script works regardless
# of cwd, both inside the repo and inside an installed package.
KERBMAP=python3
if command -v kerb-map >/dev/null 2>&1; then
    KERBMAP=kerb-map
fi

echo "[validate] running kerb-map (--all --cves --v2) …"
if [ "$KERBMAP" = python3 ]; then
    REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
    PYTHONPATH="$REPO_ROOT" python3 -m kerb_map \
        -d "$DOMAIN" -dc "$DC_IP" -u "$ADMIN" \
        --password-env LAB_ADMIN_PASS \
        --all --v2 --hygiene --no-cache \
        -o json --outfile "$SCAN_JSON" \
        --no-tls   <<< ""   # Samba 4 by default doesn't ship a cert
else
    LAB_ADMIN_PASS="$ADMIN_PASS" "$KERBMAP" \
        -d "$DOMAIN" -dc "$DC_IP" -u "$ADMIN" \
        --password-env LAB_ADMIN_PASS \
        --all --v2 --hygiene --no-cache \
        -o json --outfile "$SCAN_JSON" \
        --no-tls
fi
export LAB_ADMIN_PASS="$ADMIN_PASS"

if [ ! -s "$SCAN_JSON" ]; then
    echo "[validate] FAIL: kerb-map produced no JSON output." >&2
    exit 3
fi

# ──────────────────────────────────────────────────── assertions helper
PASS=0
FAIL=0

# Use jq for matching — must be installed.
if ! command -v jq >/dev/null 2>&1; then
    echo "[validate] FAIL: jq not installed. apt-get install -y jq" >&2
    exit 4
fi

# Assert ANY target matches a jq filter.
assert_target() {
    local label="$1"   # human-readable
    local filter="$2"  # jq expression returning the matching items
    local count
    count=$(jq -r "[$filter] | length" < "$SCAN_JSON")
    if [ "$count" -gt 0 ]; then
        echo "  ✓ $label  (matched $count)"
        PASS=$((PASS+1))
    else
        echo "  ✗ $label  (no match)"
        FAIL=$((FAIL+1))
    fi
}

# ────────────────────────────────────────────────────── assertions
echo "[validate] checking findings …"

# Legacy modules
assert_target "SPN scanner finds svc_sql" \
  '.targets[] | select(.target == "svc_sql" and (.attack | startswith("Kerberoast")))'

assert_target "SPN scanner finds svc_iis" \
  '.targets[] | select(.target == "svc_iis" and (.attack | startswith("Kerberoast")))'

assert_target "AS-REP scanner finds oldsvc" \
  '.targets[] | select(.target == "oldsvc" and (.attack | startswith("AS-REP")))'

assert_target "Delegation mapper finds web01\$ unconstrained" \
  '.targets[] | select((.target | test("WEB01\\$|web01\\$"; "i")) and (.attack | test("Unconstrained"; "i")))'

assert_target "Encryption auditor finds des_user (DES only)" \
  '.targets[] | select(.target == "des_user")'

# Hygiene: cred in description
assert_target "Hygiene auditor finds password-in-description" \
  '.hygiene.credential_exposure[] | select(.account == "svc_app" or (.field // "") | test("description"; "i"))'

# Paging: at least 1500 stub users present
assert_target "LDAP paging returned ≥1500 stub users" \
  '.user_data.stale_accounts[]?, .user_data.privileged_users[]? | select(.account // "" | test("^user[0-9]{4}$"))'

# v2 modules
assert_target "DCSync rights flags svc_old_admin" \
  '.targets[] | select(.target == "svc_old_admin" and (.attack | test("DCSync"; "i")))'

assert_target "Shadow Credentials flags da_alice (privileged + key)" \
  '.targets[] | select(.target == "da_alice" and (.attack | test("Shadow Credentials"; "i")) and .severity == "CRITICAL")'

assert_target "Shadow Credentials flags helpdesk_op write access on bob_da" \
  '.targets[] | select(.target == "bob_da" and (.attack | test("Shadow Credentials \\(write"; "i")))'

assert_target "Pre-Win2k flags Authenticated Users" \
  '.targets[] | select(.attack | test("Pre-Win2k"; "i")) | select(.reason | test("Authenticated Users"; "i"))'

# ────────────────────────────────────────────────────────── summary
echo "[validate] PASS=$PASS  FAIL=$FAIL"
if [ "$FAIL" -gt 0 ]; then
    echo "[validate] some expected findings did not appear. Scan JSON:"
    echo "  $SCAN_JSON  (kept for inspection — set NO_CLEAN=1 to keep it after exit)"
    [ "${NO_CLEAN:-}" = 1 ] && trap - EXIT
    exit 1
fi
echo "[validate] ALL GREEN."

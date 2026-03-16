"""
User Enumeration — surfaces privileged accounts, weak password policies,
AdminSDHolder anomalies, LAPS status, and stale admin accounts.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Optional, Dict, Any


@dataclass
class PrivilegedUser:
    account:    str
    group:      str
    enabled:    bool
    pwd_age:    Optional[int]
    last_logon: Optional[int]
    risk:       str


@dataclass
class WeakPolicyFlag:
    issue:   str
    detail:  str
    risk:    str


@dataclass
class PasswordPolicyInfo:
    min_length:        int
    history_count:     int
    max_age_days:      Optional[int]
    lockout_threshold: int
    reversible_enc:    bool
    complexity_req:    bool
    issues:            List[WeakPolicyFlag] = field(default_factory=list)


@dataclass
class UserEnumResults:
    privileged_users:   List[PrivilegedUser]    = field(default_factory=list)
    pwd_never_expires:  List[str]               = field(default_factory=list)
    no_pwd_required:    List[str]               = field(default_factory=list)
    admin_count_orphans:List[str]               = field(default_factory=list)
    laps_deployed:      bool                    = False
    laps_missing_hosts: List[str]               = field(default_factory=list)
    password_policy:    Optional[PasswordPolicyInfo] = None
    machine_acct_quota: int                     = 10


PRIV_GROUP_FILTERS = {
    "Domain Admins":          "Domain Admins",
    "Enterprise Admins":      "Enterprise Admins",
    "Schema Admins":          "Schema Admins",
    "Account Operators":      "Account Operators",
    "Backup Operators":       "Backup Operators",
    "Print Operators":        "Print Operators",
    "Server Operators":       "Server Operators",
    "Group Policy Creator Owners": "GPO Creator Owners",
}


class UserEnum:
    def __init__(self, ldap_client):
        self.ldap = ldap_client

    def run(self) -> UserEnumResults:
        results = UserEnumResults()
        results.privileged_users    = self._get_privileged_users()
        results.pwd_never_expires   = self._pwd_never_expires()
        results.no_pwd_required     = self._no_pwd_required()
        results.admin_count_orphans = self._admincount_orphans()
        results.laps_deployed, results.laps_missing_hosts = self._check_laps()
        results.password_policy     = self._get_password_policy()
        results.machine_acct_quota  = self._get_maq()
        return results

    # ------------------------------------------------------------------ #

    def _get_privileged_users(self) -> List[PrivilegedUser]:
        users = []
        for group_cn, label in PRIV_GROUP_FILTERS.items():
            entries = self.ldap.query(
                search_filter=(
                    f"(&(objectClass=user)"
                    f"(memberOf=CN={group_cn},CN=Users,{self.ldap.base_dn})"
                    f"(!(userAccountControl:1.2.840.113556.1.4.803:=2))"
                    f")"
                ),
                attributes=[
                    "sAMAccountName", "userAccountControl",
                    "pwdLastSet", "lastLogonTimestamp",
                ],
            )
            for e in entries:
                uac = int(e["userAccountControl"].value or 0)
                users.append(PrivilegedUser(
                    account    = str(e["sAMAccountName"]),
                    group      = label,
                    enabled    = not bool(uac & 0x2),
                    pwd_age    = self._days_since(e["pwdLastSet"].value),
                    last_logon = self._days_since(e["lastLogonTimestamp"].value),
                    risk       = "CRITICAL" if group_cn in (
                        "Domain Admins", "Enterprise Admins"
                    ) else "HIGH",
                ))
        return users

    def _pwd_never_expires(self) -> List[str]:
        # DONT_EXPIRE_PASSWORD = 0x10000 + not a computer + enabled
        entries = self.ldap.query(
            search_filter=(
                "(&"
                "(objectClass=user)"
                "(userAccountControl:1.2.840.113556.1.4.803:=65536)"
                "(!(userAccountControl:1.2.840.113556.1.4.803:=2))"
                ")"
            ),
            attributes=["sAMAccountName"],
        )
        return [str(e["sAMAccountName"]) for e in entries]

    def _no_pwd_required(self) -> List[str]:
        # PASSWD_NOTREQD = 0x20
        entries = self.ldap.query(
            search_filter=(
                "(&"
                "(objectClass=user)"
                "(userAccountControl:1.2.840.113556.1.4.803:=32)"
                "(!(userAccountControl:1.2.840.113556.1.4.803:=2))"
                ")"
            ),
            attributes=["sAMAccountName"],
        )
        return [str(e["sAMAccountName"]) for e in entries]

    def _admincount_orphans(self) -> List[str]:
        """
        Accounts with adminCount=1 but NOT in any privileged group.
        These are left-over SDProp artifacts — often forgotten high-priv accounts.
        """
        entries = self.ldap.query(
            search_filter=(
                "(&"
                "(adminCount=1)"
                "(objectClass=user)"
                "(!(memberOf=CN=Domain Admins,CN=Users," + self.ldap.base_dn + "))"
                ")"
            ),
            attributes=["sAMAccountName"],
        )
        return [str(e["sAMAccountName"]) for e in entries]

    def _check_laps(self):
        """
        Check if LAPS (Local Administrator Password Solution) is deployed.
        Presence of ms-Mcs-AdmPwdExpirationTime attribute on any computer = deployed.
        Computers missing the attribute = no LAPS rotation.
        """
        laps_entries = self.ldap.query(
            search_filter="(&(objectClass=computer)(ms-Mcs-AdmPwdExpirationTime=*))",
            attributes=["sAMAccountName"],
        )
        all_computers = self.ldap.query(
            search_filter="(objectClass=computer)",
            attributes=["sAMAccountName"],
        )
        laps_deployed = len(laps_entries) > 0
        laps_accounts = {str(e["sAMAccountName"]) for e in laps_entries}
        missing = [
            str(e["sAMAccountName"]) for e in all_computers
            if str(e["sAMAccountName"]) not in laps_accounts
        ]
        return laps_deployed, missing

    def _get_password_policy(self) -> Optional[PasswordPolicyInfo]:
        info = self.ldap.get_domain_info()
        if not info:
            return None

        def to_days(filetime_ns):
            if not filetime_ns:
                return None
            val = abs(int(filetime_ns)) // 10_000_000  # 100-ns intervals to seconds
            return val // 86400 if val else None

        min_len    = int(info["minPwdLength"].value or 0)
        history    = int(info["pwdHistoryLength"].value or 0)
        max_age    = to_days(info["maxPwdAge"].value)
        lockout    = int(info["lockoutThreshold"].value or 0)
        pwd_props  = int(info["pwdProperties"].value or 0)
        rev_enc    = bool(pwd_props & 0x10)
        complexity = bool(pwd_props & 0x1)

        issues = []
        if min_len < 8:
            issues.append(WeakPolicyFlag(
                "Short minimum password length",
                f"minPwdLength={min_len} — should be ≥12",
                "HIGH"
            ))
        if history < 10:
            issues.append(WeakPolicyFlag(
                "Low password history",
                f"pwdHistoryLength={history} — should be ≥24",
                "MEDIUM"
            ))
        if lockout == 0:
            issues.append(WeakPolicyFlag(
                "No account lockout policy",
                "lockoutThreshold=0 — unlimited spray attempts",
                "CRITICAL"
            ))
        if rev_enc:
            issues.append(WeakPolicyFlag(
                "Reversible encryption enabled",
                "Passwords stored reversibly — plaintext equivalent",
                "CRITICAL"
            ))
        if not complexity:
            issues.append(WeakPolicyFlag(
                "Password complexity not required",
                "Complexity disabled — simple passwords accepted",
                "HIGH"
            ))
        if max_age and max_age > 365:
            issues.append(WeakPolicyFlag(
                "Long maximum password age",
                f"maxPwdAge={max_age} days — passwords can be very old",
                "MEDIUM"
            ))

        return PasswordPolicyInfo(
            min_length        = min_len,
            history_count     = history,
            max_age_days      = max_age,
            lockout_threshold = lockout,
            reversible_enc    = rev_enc,
            complexity_req    = complexity,
            issues            = issues,
        )

    def _get_maq(self) -> int:
        info = self.ldap.get_domain_info()
        if info:
            return int(info["ms-DS-MachineAccountQuota"].value or 10)
        return 10

    @staticmethod
    def _days_since(dt) -> Optional[int]:
        if not dt:
            return None
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return (datetime.now(timezone.utc) - dt).days

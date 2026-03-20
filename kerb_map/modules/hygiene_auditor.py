"""
Hygiene Auditor — Defensive AD security checks for infrastructure hardening.

All read-only LDAP queries. Focuses on identifying misconfigurations and
security gaps that defenders should remediate to reduce attack surface.

Checks performed:
  - SID History abuse indicators (same-domain / privileged SIDs)
  - LAPS deployment coverage (% of computers managed)
  - krbtgt password age (Golden Ticket risk window)
  - AdminSDHolder orphans (stale adminCount=1 with no protected group)
  - Fine-Grained Password Policies (FGPP) coverage for privileged accounts
  - Credentials leaked in description/info fields
  - PrimaryGroupId manipulation (hidden group membership)
  - Stale computer accounts (inactive machines)
  - Privileged group membership breakdown
  - Service account password hygiene (SPN accounts with old passwords)
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Any, Optional
import re

from kerb_map.output.logger import Logger

log = Logger()

# Well-known privileged group RIDs
PRIVILEGED_RIDS = {
    "512": "Domain Admins",
    "519": "Enterprise Admins",
    "518": "Schema Admins",
    "516": "Domain Controllers",
}

# Well-known built-in group SIDs (last component)
BUILTIN_PRIVILEGED = {
    "544": "Administrators",
    "548": "Account Operators",
    "549": "Server Operators",
    "550": "Print Operators",
    "551": "Backup Operators",
}

# Patterns that suggest credentials in text fields
CREDENTIAL_PATTERNS = [
    re.compile(r"\bpass(?:word|wd|wrd)?\s*[:=]\s*\S+", re.IGNORECASE),
    re.compile(r"\bpwd\s*[:=]\s*\S+", re.IGNORECASE),
    re.compile(r"\bcred(?:ential)?s?\s*[:=]\s*\S+", re.IGNORECASE),
    re.compile(r"\bsecret\s*[:=]\s*\S+", re.IGNORECASE),
    re.compile(r"\bpin\s*[:=]\s*\d{4,}", re.IGNORECASE),
]

# Default primaryGroupId values
DEFAULT_PRIMARY_GROUPS = {
    513,   # Domain Users
    515,   # Domain Computers
    516,   # Domain Controllers
    521,   # Read-only Domain Controllers
}


@dataclass
class HygieneResult:
    """Container for all hygiene audit findings."""
    sid_history:         List[Dict] = field(default_factory=list)
    laps_coverage:       Dict[str, Any] = field(default_factory=dict)
    krbtgt_age:          Dict[str, Any] = field(default_factory=dict)
    adminsdholder_orphans: List[Dict] = field(default_factory=list)
    fgpp_audit:          Dict[str, Any] = field(default_factory=dict)
    credential_exposure: List[Dict] = field(default_factory=list)
    primary_group_abuse: List[Dict] = field(default_factory=list)
    stale_computers:     List[Dict] = field(default_factory=list)
    privileged_groups:   Dict[str, List[Dict]] = field(default_factory=dict)
    service_acct_hygiene: List[Dict] = field(default_factory=list)

    def finding_count(self) -> int:
        count = 0
        count += len(self.sid_history)
        count += (0 if self.laps_coverage.get("coverage_pct", 100) >= 90 else 1)
        count += (1 if self.krbtgt_age.get("age_days", 0) > 180 else 0)
        count += len(self.adminsdholder_orphans)
        count += (0 if self.fgpp_audit.get("privileged_covered") else 1)
        count += len(self.credential_exposure)
        count += len(self.primary_group_abuse)
        count += (1 if len(self.stale_computers) > 0 else 0)
        count += len(self.service_acct_hygiene)
        return count


class HygieneAuditor:
    def __init__(self, ldap_client):
        self.ldap = ldap_client

    def audit(self) -> HygieneResult:
        log.info("Running defensive hygiene audit...")
        result = HygieneResult()

        result.sid_history          = self._sid_history_audit()
        result.laps_coverage        = self._laps_coverage()
        result.krbtgt_age           = self._krbtgt_password_age()
        result.adminsdholder_orphans= self._adminsdholder_orphans()
        result.fgpp_audit           = self._fgpp_audit()
        result.credential_exposure  = self._credential_exposure()
        result.primary_group_abuse  = self._primary_group_abuse()
        result.stale_computers      = self._stale_computers()
        result.privileged_groups    = self._privileged_group_breakdown()
        result.service_acct_hygiene = self._service_account_hygiene()

        total = result.finding_count()
        log.success(f"Hygiene audit complete — {total} finding(s) require attention")
        return result

    # ──────────────────────────────────────────────────────────────────────
    # SID History Audit
    # ──────────────────────────────────────────────────────────────────────

    def _sid_history_audit(self) -> List[Dict]:
        log.info("Checking for SID History attributes...")
        entries = self.ldap.query(
            search_filter="(sIDHistory=*)",
            attributes=["sAMAccountName", "sIDHistory", "objectSid",
                         "distinguishedName", "objectClass"],
        )
        if not entries:
            log.success("No SID History found — clean")
            return []

        # Extract domain SID from base DN
        domain_sid = self._get_domain_sid()
        results = []
        for e in entries:
            account = str(e["sAMAccountName"])
            obj_classes = [str(c) for c in (e["objectClass"] or [])]
            sid_history = e["sIDHistory"].values if hasattr(e["sIDHistory"], "values") else [e["sIDHistory"].value]

            for sid in (sid_history or []):
                sid_str = str(sid)
                risk = "MEDIUM"
                detail = "SID History present (possible migration artifact)"

                # Same-domain SID = suspicious
                if domain_sid and sid_str.startswith(domain_sid):
                    risk = "CRITICAL"
                    detail = "Same-domain SID in SID History — likely persistence backdoor"

                # Check for privileged RIDs
                rid = sid_str.rsplit("-", 1)[-1] if "-" in sid_str else ""
                if rid in PRIVILEGED_RIDS:
                    risk = "CRITICAL"
                    detail = f"SID History contains {PRIVILEGED_RIDS[rid]} SID — privilege escalation"

                results.append({
                    "account": account,
                    "dn": str(e["distinguishedName"]),
                    "sid_history_entry": sid_str,
                    "is_computer": "computer" in [c.lower() for c in obj_classes],
                    "risk": risk,
                    "detail": detail,
                })

        log.success(f"Found {len(results)} SID History entry/entries across {len(entries)} object(s)")
        return results

    # ──────────────────────────────────────────────────────────────────────
    # LAPS Coverage
    # ──────────────────────────────────────────────────────────────────────

    def _laps_coverage(self) -> Dict[str, Any]:
        log.info("Calculating LAPS deployment coverage...")

        # Total enabled computers (excluding DCs)
        all_computers = self.ldap.query(
            search_filter=(
                "(&(objectClass=computer)"
                "(!(userAccountControl:1.2.840.113556.1.4.803:=2))"
                "(!(primaryGroupID=516)))"
            ),
            attributes=["sAMAccountName"],
        )
        total = len(all_computers)

        if total == 0:
            return {"total_computers": 0, "laps_managed": 0, "coverage_pct": 100,
                    "risk": "INFO", "detail": "No non-DC computers found"}

        # Legacy LAPS
        legacy_laps = self.ldap.query(
            search_filter=(
                "(&(objectClass=computer)"
                "(ms-Mcs-AdmPwdExpirationTime=*)"
                "(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
            ),
            attributes=["sAMAccountName"],
        )

        # Windows LAPS
        win_laps = self.ldap.query(
            search_filter=(
                "(&(objectClass=computer)"
                "(msLAPS-PasswordExpirationTime=*)"
                "(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
            ),
            attributes=["sAMAccountName"],
        )

        # Merge (some may have both)
        managed_names = set()
        for e in legacy_laps:
            managed_names.add(str(e["sAMAccountName"]))
        for e in win_laps:
            managed_names.add(str(e["sAMAccountName"]))
        managed = len(managed_names)

        pct = round((managed / total) * 100, 1) if total else 0
        if pct >= 90:
            risk, detail = "LOW", f"LAPS covers {pct}% of computers ({managed}/{total})"
        elif pct >= 50:
            risk, detail = "MEDIUM", f"LAPS partially deployed — only {pct}% coverage ({managed}/{total})"
        elif managed > 0:
            risk, detail = "HIGH", f"LAPS poorly deployed — {pct}% coverage ({managed}/{total})"
        else:
            risk, detail = "CRITICAL", f"LAPS not deployed — 0/{total} computers managed"

        log.success(f"LAPS coverage: {managed}/{total} ({pct}%)")
        return {
            "total_computers": total,
            "laps_managed": managed,
            "coverage_pct": pct,
            "risk": risk,
            "detail": detail,
        }

    # ──────────────────────────────────────────────────────────────────────
    # krbtgt Password Age
    # ──────────────────────────────────────────────────────────────────────

    def _krbtgt_password_age(self) -> Dict[str, Any]:
        log.info("Checking krbtgt password age...")
        entries = self.ldap.query(
            search_filter="(sAMAccountName=krbtgt)",
            attributes=["pwdLastSet", "sAMAccountName"],
        )
        if not entries:
            return {"age_days": -1, "risk": "MEDIUM",
                    "detail": "Could not query krbtgt account"}

        pwd_last_set = entries[0]["pwdLastSet"].value
        if not pwd_last_set:
            return {"age_days": -1, "risk": "CRITICAL",
                    "detail": "krbtgt password has NEVER been set"}

        if isinstance(pwd_last_set, datetime):
            pwd_dt = pwd_last_set if pwd_last_set.tzinfo else pwd_last_set.replace(tzinfo=timezone.utc)
        else:
            # Windows FILETIME
            pwd_dt = datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(
                microseconds=int(pwd_last_set) // 10
            )

        age = (datetime.now(timezone.utc) - pwd_dt).days

        if age > 365:
            risk = "CRITICAL"
            detail = f"krbtgt password is {age} days old — Golden Ticket valid for extended period"
        elif age > 180:
            risk = "HIGH"
            detail = f"krbtgt password is {age} days old — should rotate every 180 days"
        elif age > 90:
            risk = "MEDIUM"
            detail = f"krbtgt password is {age} days old — consider rotation"
        else:
            risk = "LOW"
            detail = f"krbtgt password is {age} days old — recently rotated"

        log.success(f"krbtgt password age: {age} days")
        return {
            "age_days": age,
            "last_set": pwd_dt.isoformat(),
            "risk": risk,
            "detail": detail,
        }

    # ──────────────────────────────────────────────────────────────────────
    # AdminSDHolder Orphans
    # ──────────────────────────────────────────────────────────────────────

    def _adminsdholder_orphans(self) -> List[Dict]:
        log.info("Detecting AdminSDHolder orphan accounts...")
        # Get all accounts with adminCount=1
        admin_entries = self.ldap.query(
            search_filter="(&(objectClass=user)(adminCount=1)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))",
            attributes=["sAMAccountName", "memberOf", "distinguishedName"],
        )

        # Protected groups — accounts in these groups legitimately have adminCount=1
        protected_group_dns = set()
        for group_name in ["Domain Admins", "Enterprise Admins", "Schema Admins",
                           "Administrators", "Account Operators", "Server Operators",
                           "Print Operators", "Backup Operators", "Replicator",
                           "Domain Controllers", "Read-only Domain Controllers"]:
            entries = self.ldap.query(
                search_filter=f"(&(objectClass=group)(cn={group_name}))",
                attributes=["distinguishedName"],
            )
            for e in entries:
                protected_group_dns.add(str(e["distinguishedName"]).lower())

        orphans = []
        for e in admin_entries:
            member_of = [str(g).lower() for g in (e["memberOf"] or [])]
            in_protected = any(g in protected_group_dns for g in member_of)
            if not in_protected:
                orphans.append({
                    "account": str(e["sAMAccountName"]),
                    "dn": str(e["distinguishedName"]),
                    "groups": [str(g) for g in (e["memberOf"] or [])],
                    "risk": "HIGH",
                    "detail": (
                        "adminCount=1 but not in any protected group — "
                        "possible stale flag or past privilege abuse"
                    ),
                })

        log.success(f"Found {len(orphans)} AdminSDHolder orphan(s)")
        return orphans

    # ──────────────────────────────────────────────────────────────────────
    # Fine-Grained Password Policies
    # ──────────────────────────────────────────────────────────────────────

    def _fgpp_audit(self) -> Dict[str, Any]:
        log.info("Auditing Fine-Grained Password Policies...")
        entries = self.ldap.query(
            search_filter="(objectClass=msDS-PasswordSettings)",
            attributes=[
                "cn", "msDS-MinimumPasswordLength", "msDS-MaximumPasswordAge",
                "msDS-PasswordComplexityEnabled", "msDS-LockoutThreshold",
                "msDS-PSOAppliesTo", "msDS-PasswordSettingsPrecedence",
            ],
            search_base=f"CN=Password Settings Container,CN=System,{self.ldap.base_dn}",
        )

        policies = []
        applies_to_all = set()
        for e in entries:
            applies_to = [str(t) for t in (e["msDS-PSOAppliesTo"] or [])]
            applies_to_all.update(t.lower() for t in applies_to)

            min_len = e["msDS-MinimumPasswordLength"].value
            complexity = e["msDS-PasswordComplexityEnabled"].value
            lockout = e["msDS-LockoutThreshold"].value

            policies.append({
                "name": str(e["cn"]),
                "min_length": int(min_len) if min_len is not None else 0,
                "complexity_enabled": bool(complexity) if complexity is not None else False,
                "lockout_threshold": int(lockout) if lockout is not None else 0,
                "applies_to": applies_to,
                "precedence": int(e["msDS-PasswordSettingsPrecedence"].value or 0),
            })

        # Check if any FGPP targets privileged groups
        priv_group_dns = set()
        for gn in ["Domain Admins", "Enterprise Admins", "Schema Admins", "Administrators"]:
            ge = self.ldap.query(
                search_filter=f"(&(objectClass=group)(cn={gn}))",
                attributes=["distinguishedName"],
            )
            for g in ge:
                priv_group_dns.add(str(g["distinguishedName"]).lower())

        privileged_covered = bool(priv_group_dns & applies_to_all)

        result = {
            "policy_count": len(policies),
            "policies": policies,
            "privileged_covered": privileged_covered,
            "risk": "LOW" if privileged_covered else ("MEDIUM" if policies else "HIGH"),
            "detail": (
                "Fine-Grained Password Policy applied to privileged groups"
                if privileged_covered else
                ("FGPP exists but does not cover privileged groups"
                 if policies else
                 "No Fine-Grained Password Policies defined — all accounts use domain default")
            ),
        }
        log.success(f"Found {len(policies)} FGPP(s), privileged coverage: {privileged_covered}")
        return result

    # ──────────────────────────────────────────────────────────────────────
    # Credential Exposure in Description/Info Fields
    # ──────────────────────────────────────────────────────────────────────

    def _credential_exposure(self) -> List[Dict]:
        log.info("Scanning for credentials in description/info fields...")
        entries = self.ldap.query(
            search_filter="(&(objectClass=user)(|(description=*pass*)(description=*pwd*)(description=*cred*)(info=*pass*)(info=*pwd*)))",
            attributes=["sAMAccountName", "description", "info",
                         "distinguishedName", "adminCount"],
        )

        results = []
        for e in entries:
            desc = str(e["description"].value or "")
            info = str(e["info"].value or "")
            is_admin = bool(int(e["adminCount"].value or 0))

            for text, source in [(desc, "description"), (info, "info")]:
                for pattern in CREDENTIAL_PATTERNS:
                    if pattern.search(text):
                        results.append({
                            "account": str(e["sAMAccountName"]),
                            "dn": str(e["distinguishedName"]),
                            "field": source,
                            "is_admin": is_admin,
                            "risk": "CRITICAL" if is_admin else "HIGH",
                            "detail": f"Possible credential in {source} field"
                                      + (" [PRIVILEGED ACCOUNT]" if is_admin else ""),
                        })
                        break  # one match per field is enough

        log.success(f"Found {len(results)} account(s) with possible credentials in attributes")
        return results

    # ──────────────────────────────────────────────────────────────────────
    # PrimaryGroupId Manipulation
    # ──────────────────────────────────────────────────────────────────────

    def _primary_group_abuse(self) -> List[Dict]:
        log.info("Checking for non-default primaryGroupId values...")
        # Users with non-standard primaryGroupId (not 513 Domain Users)
        entries = self.ldap.query(
            search_filter=(
                "(&(objectCategory=person)(objectClass=user)"
                "(!(primaryGroupID=513))"
                "(!(primaryGroupID=515))"
                "(!(primaryGroupID=516))"
                "(!(primaryGroupID=521))"
                "(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
            ),
            attributes=["sAMAccountName", "primaryGroupID", "distinguishedName"],
        )

        results = []
        for e in entries:
            pgid = int(e["primaryGroupID"].value or 0)
            gid_str = str(pgid)

            # Determine if it's a known privileged group
            group_name = PRIVILEGED_RIDS.get(gid_str, BUILTIN_PRIVILEGED.get(gid_str, f"Group RID {pgid}"))
            is_privileged = gid_str in PRIVILEGED_RIDS or gid_str in BUILTIN_PRIVILEGED

            results.append({
                "account": str(e["sAMAccountName"]),
                "dn": str(e["distinguishedName"]),
                "primary_group_id": pgid,
                "primary_group_name": group_name,
                "risk": "HIGH" if is_privileged else "MEDIUM",
                "detail": (
                    f"primaryGroupId={pgid} ({group_name}) — "
                    "membership hidden from normal group enumeration"
                    + (" — PRIVILEGED GROUP" if is_privileged else "")
                ),
            })

        log.success(f"Found {len(results)} user(s) with non-default primaryGroupId")
        return results

    # ──────────────────────────────────────────────────────────────────────
    # Stale Computer Accounts
    # ──────────────────────────────────────────────────────────────────────

    def _stale_computers(self) -> List[Dict]:
        log.info("Checking for stale computer accounts...")
        # 90 days ago in Windows FILETIME
        threshold_dt = datetime.now(timezone.utc) - timedelta(days=90)
        # Convert to Windows FILETIME (100-nanosecond intervals since 1601-01-01)
        epoch = datetime(1601, 1, 1, tzinfo=timezone.utc)
        threshold_ft = str(int((threshold_dt - epoch).total_seconds() * 10_000_000))

        entries = self.ldap.query(
            search_filter=(
                f"(&(objectClass=computer)"
                f"(!(userAccountControl:1.2.840.113556.1.4.803:=2))"
                f"(!(primaryGroupID=516))"
                f"(lastLogonTimestamp<={threshold_ft}))"
            ),
            attributes=["sAMAccountName", "lastLogonTimestamp",
                         "operatingSystem", "distinguishedName"],
        )

        results = []
        for e in entries:
            os_name = str(e["operatingSystem"].value or "Unknown")
            llt = e["lastLogonTimestamp"].value

            if isinstance(llt, datetime):
                last_dt = llt if llt.tzinfo else llt.replace(tzinfo=timezone.utc)
            elif llt:
                last_dt = epoch + timedelta(microseconds=int(llt) // 10)
            else:
                last_dt = None

            age_days = (datetime.now(timezone.utc) - last_dt).days if last_dt else -1

            results.append({
                "account": str(e["sAMAccountName"]),
                "dn": str(e["distinguishedName"]),
                "os": os_name,
                "last_logon_days": age_days,
                "last_logon": last_dt.isoformat() if last_dt else "Never",
                "risk": "MEDIUM",
                "detail": f"Computer inactive for {age_days}d — running {os_name}",
            })

        # Sort by staleness
        results.sort(key=lambda x: x["last_logon_days"], reverse=True)
        log.success(f"Found {len(results)} stale computer account(s) (>90 days inactive)")
        return results

    # ──────────────────────────────────────────────────────────────────────
    # Privileged Group Membership Breakdown
    # ──────────────────────────────────────────────────────────────────────

    def _privileged_group_breakdown(self) -> Dict[str, List[Dict]]:
        log.info("Enumerating privileged group memberships...")
        groups_to_check = [
            "Domain Admins", "Enterprise Admins", "Schema Admins",
            "Administrators", "Account Operators", "Server Operators",
            "Backup Operators", "Print Operators",
            "DnsAdmins", "Group Policy Creator Owners",
        ]

        breakdown = {}
        for group_name in groups_to_check:
            entries = self.ldap.query(
                search_filter=f"(&(objectClass=group)(cn={group_name}))",
                attributes=["member", "distinguishedName"],
            )
            if not entries:
                continue

            members = []
            for m in (entries[0]["member"] or []):
                m_str = str(m)
                # Resolve to sAMAccountName
                user_entries = self.ldap.query(
                    search_filter=f"(distinguishedName={m_str})",
                    attributes=["sAMAccountName", "objectClass"],
                )
                if user_entries:
                    obj_classes = [str(c).lower() for c in (user_entries[0]["objectClass"] or [])]
                    is_group = "group" in obj_classes
                    members.append({
                        "account": str(user_entries[0]["sAMAccountName"]),
                        "dn": m_str,
                        "is_nested_group": is_group,
                    })
                else:
                    members.append({
                        "account": m_str.split(",")[0].replace("CN=", ""),
                        "dn": m_str,
                        "is_nested_group": False,
                    })

            if members:
                breakdown[group_name] = members

        total_groups = len(breakdown)
        total_members = sum(len(m) for m in breakdown.values())
        log.success(f"Enumerated {total_groups} privileged group(s) with {total_members} total member(s)")
        return breakdown

    # ──────────────────────────────────────────────────────────────────────
    # Service Account Password Hygiene
    # ──────────────────────────────────────────────────────────────────────

    def _service_account_hygiene(self) -> List[Dict]:
        log.info("Checking service account password hygiene...")
        # Service accounts = user accounts with SPNs
        entries = self.ldap.query(
            search_filter=(
                "(&(objectClass=user)(servicePrincipalName=*)"
                "(!(objectClass=computer))"
                "(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
            ),
            attributes=["sAMAccountName", "pwdLastSet", "servicePrincipalName",
                         "adminCount", "distinguishedName",
                         "userAccountControl"],
        )

        epoch = datetime(1601, 1, 1, tzinfo=timezone.utc)
        results = []
        for e in entries:
            pwd_last_set = e["pwdLastSet"].value
            uac = int(e["userAccountControl"].value or 0)
            is_admin = bool(int(e["adminCount"].value or 0))
            pwd_never_expires = bool(uac & 0x10000)

            if isinstance(pwd_last_set, datetime):
                pwd_dt = pwd_last_set if pwd_last_set.tzinfo else pwd_last_set.replace(tzinfo=timezone.utc)
            elif pwd_last_set:
                pwd_dt = epoch + timedelta(microseconds=int(pwd_last_set) // 10)
            else:
                pwd_dt = None

            age_days = (datetime.now(timezone.utc) - pwd_dt).days if pwd_dt else -1

            issues = []
            risk = "LOW"

            if age_days > 365:
                issues.append(f"password is {age_days} days old")
                risk = "HIGH"
            elif age_days > 180:
                issues.append(f"password is {age_days} days old")
                risk = "MEDIUM"

            if pwd_never_expires:
                issues.append("password never expires")
                risk = max(risk, "MEDIUM", key=["LOW", "MEDIUM", "HIGH", "CRITICAL"].index)

            if is_admin:
                issues.append("privileged account with SPN")
                risk = max(risk, "HIGH", key=["LOW", "MEDIUM", "HIGH", "CRITICAL"].index)

            if age_days == -1:
                issues.append("password never set")
                risk = "CRITICAL"

            if issues:
                results.append({
                    "account": str(e["sAMAccountName"]),
                    "dn": str(e["distinguishedName"]),
                    "password_age_days": age_days,
                    "password_never_expires": pwd_never_expires,
                    "is_admin": is_admin,
                    "issues": issues,
                    "risk": risk,
                    "detail": " | ".join(issues),
                })

        results.sort(key=lambda x: ["LOW", "MEDIUM", "HIGH", "CRITICAL"].index(x["risk"]), reverse=True)
        log.success(f"Found {len(results)} service account(s) with hygiene issues")
        return results

    # ──────────────────────────────────────────────────────────────────────
    # Helpers
    # ──────────────────────────────────────────────────────────────────────

    def _get_domain_sid(self) -> Optional[str]:
        """Extract the domain SID prefix (e.g. S-1-5-21-xxx-xxx-xxx)."""
        entries = self.ldap.query(
            search_filter="(objectClass=domainDNS)",
            attributes=["objectSid"],
        )
        if entries:
            sid = entries[0]["objectSid"].value
            if sid:
                return str(sid)
        return None

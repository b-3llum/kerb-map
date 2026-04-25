"""
AS-REP Roasting scanner — finds accounts with Kerberos pre-auth disabled.
These can be attacked without ANY credentials at all.
"""

from dataclasses import asdict, dataclass
from datetime import datetime, timezone


@dataclass
class ASREPAccount:
    account:           str
    password_age_days: int | None
    is_admin:          bool
    is_enabled:        bool
    description:       str
    last_logon_days:   int | None
    crack_score:       int = 0


class ASREPScanner:
    def __init__(self, ldap_client):
        self.ldap = ldap_client

    def scan(self) -> list[ASREPAccount]:
        # DONT_REQUIRE_PREAUTH = 0x400000 (4194304)
        entries = self.ldap.query(
            search_filter=(
                "(&"
                "(userAccountControl:1.2.840.113556.1.4.803:=4194304)"
                "(!(objectClass=computer))"
                ")"
            ),
            attributes=[
                "sAMAccountName", "pwdLastSet", "lastLogonTimestamp",
                "userAccountControl", "memberOf", "description", "adminCount",
            ],
        )

        results = []
        for entry in entries:
            uac        = int(entry["userAccountControl"].value or 0)
            is_enabled = not bool(uac & 0x2)  # ACCOUNTDISABLE flag
            if not is_enabled:
                continue  # skip disabled accounts

            memberships = self._memberships(entry)
            pwd_last    = entry["pwdLastSet"].value
            last_logon  = entry["lastLogonTimestamp"].value

            acct = ASREPAccount(
                account          = str(entry["sAMAccountName"]),
                password_age_days= self._days_since(pwd_last),
                is_admin         = bool(
                    entry["adminCount"].value == 1 or
                    "domain admins" in memberships
                ),
                is_enabled       = is_enabled,
                description      = str(entry["description"].value or ""),
                last_logon_days  = self._days_since(last_logon),
            )
            acct.crack_score = self._score(acct)
            results.append(acct)

        return sorted(
            [asdict(acct) for acct in results],
            key=lambda x: x["crack_score"],
            reverse=True,
        )

    def _score(self, a: ASREPAccount) -> int:
        # No creds needed makes ALL AS-REP targets high priority base
        score = 60
        if a.is_admin:
            score += 25
        if a.password_age_days and a.password_age_days > 365:
            score += 15
        return min(score, 100)

    @staticmethod
    def _days_since(dt) -> int | None:
        if not dt:
            return None
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return (datetime.now(timezone.utc) - dt).days

    @staticmethod
    def _memberships(entry) -> set:
        groups = set()
        for dn in (entry["memberOf"] or []):
            cn = str(dn).split(",")[0].replace("CN=", "").lower()
            groups.add(cn)
        return groups

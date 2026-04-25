"""
SPN Scanner — finds all Kerberoastable accounts and scores them by crackability.
Score factors: encryption type, password age, admin membership, SPN type.
"""

from dataclasses import asdict, dataclass
from datetime import datetime, timezone


@dataclass
class SPNAccount:
    account:          str
    spns:             list[str]
    password_age_days: int | None
    rc4_allowed:      bool
    aes_only:         bool
    is_admin:         bool
    is_service:       bool        # svc_, sql_, etc.
    description:      str
    last_logon_days:  int | None
    never_logged_in:  bool
    crack_score:      int = 0
    crack_priority:   str = ""


ADMIN_GROUPS = {
    "domain admins", "enterprise admins", "schema admins",
    "administrators", "account operators", "backup operators",
    "print operators", "server operators", "group policy creator owners",
}

# SPNs associated with high-value services
HIGH_VALUE_SPNS = {"MSSQLSvc", "kadmin", "HTTP", "WSMAN", "RestrictedKrbHost"}


class SPNScanner:
    def __init__(self, ldap_client):
        self.ldap = ldap_client

    def scan(self) -> list[SPNAccount]:
        entries = self.ldap.query(
            search_filter=(
                "(&"
                "(servicePrincipalName=*)"
                "(!(objectClass=computer))"
                "(!(cn=krbtgt))"
                "(!(userAccountControl:1.2.840.113556.1.4.803:=2))"  # exclude disabled
                ")"
            ),
            attributes=[
                "sAMAccountName", "servicePrincipalName",
                "pwdLastSet", "lastLogonTimestamp",
                "msDS-SupportedEncryptionTypes",
                "memberOf", "userAccountControl",
                "description", "adminCount",
            ],
        )

        results = []
        for entry in entries:
            account = self._parse(entry)
            account.crack_score    = self._score(account)
            account.crack_priority = self._priority_label(account.crack_score)
            results.append(account)

        return sorted(
            [asdict(account) for account in results],
            key=lambda x: x["crack_score"],
            reverse=True,
        )

    # ------------------------------------------------------------------ #

    def _parse(self, entry) -> SPNAccount:
        enc_types    = int(entry["msDS-SupportedEncryptionTypes"].value or 0)
        pwd_last_set = entry["pwdLastSet"].value
        last_logon   = entry["lastLogonTimestamp"].value
        memberships  = self._get_memberships(entry)
        spns         = [str(s) for s in (entry["servicePrincipalName"] or [])]
        account_name = str(entry["sAMAccountName"])

        return SPNAccount(
            account          = account_name,
            spns             = spns,
            password_age_days= self._days_since(pwd_last_set),
            rc4_allowed      = self._supports_rc4(enc_types),
            aes_only         = self._aes_only(enc_types),
            is_admin         = bool(
                entry["adminCount"].value == 1 or
                any(g in memberships for g in ADMIN_GROUPS)
            ),
            is_service       = account_name.lower().startswith(
                ("svc_", "svc-", "service", "sql", "_sa")
            ),
            description      = str(entry["description"].value or ""),
            last_logon_days  = self._days_since(last_logon),
            never_logged_in  = last_logon is None,
        )

    def _score(self, a: SPNAccount) -> int:
        score = 0
        # Encryption type — RC4 is 4x faster to crack than AES in hashcat
        if a.rc4_allowed and not a.aes_only:
            score += 40
        elif a.rc4_allowed:
            score += 20
        # Old password — likely weak/default
        if a.password_age_days is not None:
            if a.password_age_days > 730:
                score += 30
            elif a.password_age_days > 365:
                score += 20
            elif a.password_age_days > 180:
                score += 10
        # Admin membership — high value target
        if a.is_admin:
            score += 20
        # High value SPN type
        if any(spn.split("/")[0] in HIGH_VALUE_SPNS for spn in a.spns):
            score += 10
        # Never logged in — possibly forgotten service account
        if a.never_logged_in:
            score += 5
        return min(score, 100)

    @staticmethod
    def _priority_label(score: int) -> str:
        if score >= 80: return "CRITICAL"
        if score >= 60: return "HIGH"
        if score >= 40: return "MEDIUM"
        return "LOW"

    @staticmethod
    def _supports_rc4(enc_types: int) -> bool:
        return enc_types == 0 or bool(enc_types & 0x4)

    @staticmethod
    def _aes_only(enc_types: int) -> bool:
        return bool(enc_types & 0x18) and not bool(enc_types & 0x4)

    @staticmethod
    def _days_since(dt) -> int | None:
        if not dt:
            return None
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return (datetime.now(timezone.utc) - dt).days

    @staticmethod
    def _get_memberships(entry) -> set:
        groups = set()
        for dn in (entry["memberOf"] or []):
            # Extract CN from DN: CN=Domain Admins,CN=Users,...
            cn = str(dn).split(",")[0].replace("CN=", "").lower()
            groups.add(cn)
        return groups

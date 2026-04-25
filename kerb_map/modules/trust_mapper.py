"""
Trust Mapper — enumerates all domain trusts and flags dangerous configurations.
Bidirectional trusts and forest trusts with SID filtering disabled are high risk.
"""

from dataclasses import dataclass

TRUST_TYPE = {
    1: "DOWNLEVEL (Windows NT)",
    2: "UPLEVEL (Active Directory)",
    3: "MIT (Non-Windows Kerberos)",
    4: "DCE",
}

TRUST_DIRECTION = {
    0: "DISABLED",
    1: "INBOUND  (they trust us)",
    2: "OUTBOUND (we trust them)",
    3: "BIDIRECTIONAL",
}

TRUST_ATTRIBUTES = {
    0x1:  "NON_TRANSITIVE",
    0x2:  "UPLEVEL_ONLY",
    0x4:  "QUARANTINED_DOMAIN (SID Filtering ON)",
    0x8:  "FOREST_TRANSITIVE",
    0x10: "CROSS_ORGANIZATION",
    0x20: "WITHIN_FOREST",
    0x40: "TREAT_AS_EXTERNAL",
    0x80: "USES_RC4_ENCRYPTION",
}


@dataclass
class DomainTrust:
    trust_partner:   str
    direction:       str
    trust_type:      str
    attributes:      list[str]
    sid_filtering:   bool
    is_forest_trust: bool
    is_bidirectional:bool
    risk:            str
    note:            str


class TrustMapper:
    def __init__(self, ldap_client):
        self.ldap = ldap_client

    def map(self) -> list[DomainTrust]:
        entries = self.ldap.query(
            search_filter="(objectClass=trustedDomain)",
            attributes=[
                "name", "trustDirection", "trustType",
                "trustAttributes", "securityIdentifier",
            ],
        )
        return [self._parse(e) for e in entries]

    def _parse(self, entry) -> DomainTrust:
        direction  = int(entry["trustDirection"].value or 0)
        ttype      = int(entry["trustType"].value or 0)
        tattrs_raw = int(entry["trustAttributes"].value or 0)

        tattrs = [
            label for bit, label in TRUST_ATTRIBUTES.items()
            if tattrs_raw & bit
        ]

        sid_filtering   = bool(tattrs_raw & 0x4)
        is_forest       = bool(tattrs_raw & 0x8)
        is_bidir        = (direction == 3)
        uses_rc4        = bool(tattrs_raw & 0x80)

        risk, note = self._assess(is_bidir, is_forest, sid_filtering, uses_rc4)

        return DomainTrust(
            trust_partner    = str(entry["name"]),
            direction        = TRUST_DIRECTION.get(direction, str(direction)),
            trust_type       = TRUST_TYPE.get(ttype, str(ttype)),
            attributes       = tattrs,
            sid_filtering    = sid_filtering,
            is_forest_trust  = is_forest,
            is_bidirectional = is_bidir,
            risk             = risk,
            note             = note,
        )

    @staticmethod
    def _assess(bidir, forest, sid_filter, rc4):
        if forest and not sid_filter:
            return "CRITICAL", "Forest trust with SID filtering OFF — SID history abuse possible"
        if bidir and not sid_filter:
            return "HIGH", "Bidirectional trust without SID filtering"
        if bidir:
            return "MEDIUM", "Bidirectional trust — pivot path if partner domain is compromised"
        if rc4:
            return "LOW", "Trust uses RC4 encryption — weak"
        return "INFO", "Standard trust — review direction"

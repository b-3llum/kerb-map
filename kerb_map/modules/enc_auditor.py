"""
Encryption Auditor — finds accounts and DCs using weak Kerberos encryption.
RC4 (arcfour-hmac) support on DCs and service accounts = faster offline cracking.
"""

from dataclasses import dataclass, field
from typing import List


ENC_TYPES = {
    0x1:  "DES-CBC-CRC",
    0x2:  "DES-CBC-MD5",
    0x4:  "RC4-HMAC",
    0x8:  "AES128-CTS-HMAC-SHA1",
    0x10: "AES256-CTS-HMAC-SHA1",
    0x18: "AES (128+256)",
}


@dataclass
class WeakEncAccount:
    account:   str
    enc_types: List[str]
    rc4_only:  bool
    is_dc:     bool
    risk:      str


@dataclass
class EncAuditResults:
    rc4_only_accounts:    List[WeakEncAccount] = field(default_factory=list)
    des_accounts:         List[WeakEncAccount] = field(default_factory=list)
    weak_dcs:             List[WeakEncAccount] = field(default_factory=list)
    domain_default_rc4:   bool                 = False


class EncAuditor:
    def __init__(self, ldap_client):
        self.ldap = ldap_client

    def audit(self) -> EncAuditResults:
        results = EncAuditResults()

        # All user accounts with explicit enc type set
        user_entries = self.ldap.query(
            search_filter=(
                "(&"
                "(objectClass=user)"
                "(msDS-SupportedEncryptionTypes=*)"
                "(!(userAccountControl:1.2.840.113556.1.4.803:=2))"
                ")"
            ),
            attributes=["sAMAccountName", "msDS-SupportedEncryptionTypes"],
        )

        for e in user_entries:
            enc = int(e["msDS-SupportedEncryptionTypes"].value or 0)
            parsed = self._parse_enc(enc)
            if enc == 0 or (bool(enc & 0x4) and not bool(enc & 0x18)):
                results.rc4_only_accounts.append(WeakEncAccount(
                    account   = str(e["sAMAccountName"]),
                    enc_types = parsed,
                    rc4_only  = True,
                    is_dc     = False,
                    risk      = "HIGH",
                ))
            if bool(enc & 0x3):  # DES in use
                results.des_accounts.append(WeakEncAccount(
                    account   = str(e["sAMAccountName"]),
                    enc_types = parsed,
                    rc4_only  = False,
                    is_dc     = False,
                    risk      = "CRITICAL",
                ))

        # DCs specifically
        dc_entries = self.ldap.query(
            search_filter="(userAccountControl:1.2.840.113556.1.4.803:=8192)",
            attributes=["sAMAccountName", "msDS-SupportedEncryptionTypes"],
        )
        for e in dc_entries:
            enc = int(e["msDS-SupportedEncryptionTypes"].value or 0)
            if enc == 0 or bool(enc & 0x4):
                results.weak_dcs.append(WeakEncAccount(
                    account   = str(e["sAMAccountName"]),
                    enc_types = self._parse_enc(enc),
                    rc4_only  = (enc == 0),
                    is_dc     = True,
                    risk      = "HIGH",
                ))

        # Domain default — if no enc type set, RC4 is allowed by default
        results.domain_default_rc4 = (len(results.rc4_only_accounts) > 0)
        return results

    @staticmethod
    def _parse_enc(enc: int) -> List[str]:
        if enc == 0:
            return ["RC4-HMAC (default — no explicit AES restriction)"]
        return [
            label for bit, label in ENC_TYPES.items()
            if enc & bit
        ]

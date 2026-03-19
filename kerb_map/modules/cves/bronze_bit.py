"""
CVE-2020-17049 — Kerberos Bronze Bit
Bypasses S4U2Self forwardable flag validation, allowing constrained delegation
abuse even when protocol transition is not enabled.
Detection: Check if constrained delegation exists + domain is potentially unpatched.
"""

from kerb_map.modules.cves.cve_base import CVEBase, CVEResult, Severity
from kerb_map.output.logger import Logger

log = Logger()


class BronzeBit(CVEBase):
    CVE_ID = "CVE-2020-17049"
    NAME = "Kerberos Bronze Bit"

    def check(self) -> CVEResult:
        log.info(f"Checking {self.CVE_ID} ({self.NAME})...")
        constrained = self._find_constrained_delegation()
        patched = self._infer_patch_status()

        vulnerable = len(constrained) > 0 and not patched

        return CVEResult(
            cve_id=self.CVE_ID,
            name=self.NAME,
            severity=Severity.HIGH,
            vulnerable=vulnerable,
            reason=(
                f"Found {len(constrained)} constrained delegation account(s) and "
                f"domain appears unpatched — Bronze Bit can bypass forwardable flag"
            ) if vulnerable else (
                f"Found {len(constrained)} constrained delegation account(s) "
                f"but domain appears patched (DFL >= 7)"
                if constrained else "No constrained delegation accounts found"
            ),
            evidence={
                "constrained_accounts": [a for a in constrained[:5]],
                "patch_inferred": patched,
            },
            remediation=(
                "1. Apply KB4598347 on all DCs.\n"
                "2. Set PerformTicketSignature=2 registry key on all DCs.\n"
                "3. Review all constrained delegation configurations."
            ),
            next_step=(
                f"# Exploit Bronze Bit to bypass S4U2Self forwardable check\n"
                f"getST.py -spn <TARGET_SPN> -impersonate Administrator "
                f"-force-forwardable -dc-ip {self.dc_ip} "
                f"{self.domain}/{constrained[0]}:<pass>"
            ) if vulnerable and constrained else "",
            references=["https://blog.netspi.com/cve-2020-17049-kerberos-bronze-bit-theory/"],
        )

    def _find_constrained_delegation(self):
        entries = self.ldap.query(
            search_filter="(msDS-AllowedToDelegateTo=*)",
            attributes=["sAMAccountName"],
        )
        return [str(e["sAMAccountName"]) for e in entries]

    def _infer_patch_status(self) -> bool:
        entries = self.ldap.query(
            search_filter="(objectClass=domainDNS)",
            attributes=["msDS-Behavior-Version"],
        )
        if entries:
            level = int(entries[0]["msDS-Behavior-Version"].value or 0)
            return level >= 7
        return False

"""
CVE-2020-17049 — Kerberos Bronze Bit
Bypasses S4U2Self forwardable flag validation, allowing constrained delegation
abuse even when protocol transition is not enabled.
Detection: Check if constrained delegation exists + domain is potentially unpatched.
"""

from kerb_map.modules.cves.cve_base import (
    PATCH_STATUS_INDETERMINATE,
    CVEBase,
    CVEResult,
    Severity,
)
from kerb_map.output.logger import Logger

log = Logger()


class BronzeBit(CVEBase):
    CVE_ID = "CVE-2020-17049"
    NAME = "Kerberos Bronze Bit"

    def check(self) -> CVEResult:
        log.info(f"Checking {self.CVE_ID} ({self.NAME})...")
        constrained = self._find_constrained_delegation()

        # Brief §2.1: dropped DFL-based patch inference. Without
        # constrained-delegation accounts, the chain isn't possible at
        # all. With them, preconditions are present and the operator
        # must verify the DC patch level via the registry
        # (PerformTicketSignature=2 confirms patched).
        if not constrained:
            return self._not_vulnerable(
                cve_id   = self.CVE_ID,
                name     = self.NAME,
                severity = Severity.INFO,
                reason   = "No constrained delegation accounts found — Bronze Bit not applicable.",
            )

        return CVEResult(
            cve_id       = self.CVE_ID,
            name         = self.NAME,
            severity     = Severity.MEDIUM,   # was HIGH — downgraded until DC registry confirms
            vulnerable   = True,
            reason       = (
                f"Found {len(constrained)} constrained delegation account(s). "
                f"Patch state cannot be determined from LDAP alone — confirm "
                f"PerformTicketSignature=2 on every DC's registry, or attempt "
                f"the -force-forwardable getST.py call as a low-impact probe."
            ),
            evidence     = {
                "constrained_accounts": list(constrained[:5]),
                "constrained_count":    len(constrained),
            },
            remediation  = (
                "1. Apply KB4598347 on all DCs.\n"
                "2. Set PerformTicketSignature=2 registry key on all DCs.\n"
                "3. Review all constrained delegation configurations."
            ),
            next_step    = (
                f"# Exploit Bronze Bit to bypass S4U2Self forwardable check\n"
                f"getST.py -spn <TARGET_SPN> -impersonate Administrator "
                f"-force-forwardable -dc-ip {self.dc_ip} "
                f"{self.domain}/{constrained[0]}:<pass>"
            ),
            references   = ["https://blog.netspi.com/cve-2020-17049-kerberos-bronze-bit-theory/"],
            patch_status = PATCH_STATUS_INDETERMINATE,
        )

    def _find_constrained_delegation(self):
        entries = self.ldap.query(
            search_filter="(msDS-AllowedToDelegateTo=*)",
            attributes=["sAMAccountName"],
        )
        return [str(e["sAMAccountName"]) for e in entries]

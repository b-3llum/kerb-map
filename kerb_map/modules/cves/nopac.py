"""
CVE-2021-42278 + CVE-2021-42287 — noPac / sAMAccountName Spoofing
Any domain user can impersonate a DC and obtain a DA TGT.
Requires: MachineAccountQuota > 0 AND domain unpatched.
Detection: pure LDAP — entirely passive, very low noise.
"""

from .cve_base import (
    PATCH_STATUS_INDETERMINATE,
    CVEBase,
    CVEResult,
    Severity,
)


class NoPac(CVEBase):
    """CVE-2021-42278/42287 — noPac / sAMAccountName Spoofing.

    Brief §2.1: removed the DFL-based ``_infer_patch_status`` heuristic
    that produced both false positives (modern unpatched domain reported
    patched) and false negatives (legacy DFL with all KBs applied
    reported vulnerable). The check now reports honestly:

      - MachineAccountQuota > 0 → preconditions present, severity HIGH,
        patch_status = INDETERMINATE. The operator runs noPac.py to
        confirm.
      - MachineAccountQuota = 0 → exploitation infeasible regardless of
        patch state, severity INFO.
    """

    def check(self) -> CVEResult:
        quota = self._get_maq()
        precondition_present = quota > 0

        if not precondition_present:
            return CVEResult(
                cve_id       = "CVE-2021-42278/42287",
                name         = "noPac — sAMAccountName Spoofing",
                severity     = Severity.INFO,
                vulnerable   = False,
                reason       = (
                    f"MachineAccountQuota={quota} — domain users cannot "
                    f"create machine accounts, so the precondition for "
                    f"the noPac chain is absent."
                ),
                evidence     = {"ms_ds_machine_account_quota": quota},
                remediation  = "MAQ=0 already enforced; nothing to do.",
                next_step    = "",
                noise_level  = "LOW",
                patch_status = "N/A (precondition absent)",
            )

        return CVEResult(
            cve_id       = "CVE-2021-42278/42287",
            name         = "noPac — sAMAccountName Spoofing",
            severity     = Severity.HIGH,    # was CRITICAL — downgraded until probe confirms
            vulnerable   = True,             # precondition holds → assume vulnerable until proven otherwise
            reason       = (
                f"MachineAccountQuota={quota} — domain users can create "
                f"machine accounts. Patch state cannot be determined from "
                f"LDAP alone; run noPac.py to confirm exploitability before "
                f"reporting."
            ),
            evidence     = {"ms_ds_machine_account_quota": quota},
            remediation  = (
                "1. Apply KB5008380 and KB5008102 on all DCs.\n"
                "2. Set ms-DS-MachineAccountQuota = 0 via ADSI Edit or AD PowerShell:\n"
                "   Set-ADDomain -Identity . -Replace @{'ms-DS-MachineAccountQuota'='0'}"
            ),
            next_step    = (
                f"# Verify patch status and exploit in one shot:\n"
                f"python3 noPac.py {self.domain}/lowpriv_user:Password "
                f"-dc-ip {self.dc_ip} -shell\n"
                f"# OR scanner-only:\n"
                f"python3 scanner.py {self.domain}/lowpriv_user:Password "
                f"-dc-ip {self.dc_ip}"
            ),
            noise_level  = "LOW",
            patch_status = PATCH_STATUS_INDETERMINATE,
        )

    def _get_maq(self) -> int:
        entries = self.ldap.query(
            "(objectClass=domainDNS)",
            ["ms-DS-MachineAccountQuota"]
        )
        if entries:
            val = entries[0]["ms-DS-MachineAccountQuota"].value
            return int(val) if val is not None else 10
        return 10  # AD default

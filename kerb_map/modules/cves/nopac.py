"""
CVE-2021-42278 + CVE-2021-42287 — noPac / sAMAccountName Spoofing
Any domain user can impersonate a DC and obtain a DA TGT.
Requires: MachineAccountQuota > 0 AND domain unpatched.
Detection: pure LDAP — entirely passive, very low noise.
"""

from .cve_base import CVEBase, CVEResult, Severity


class NoPac(CVEBase):
    def check(self) -> CVEResult:
        quota   = self._get_maq()
        patched = self._infer_patch_status()

        vulnerable = quota > 0 and not patched

        return CVEResult(
            cve_id      = "CVE-2021-42278/42287",
            name        = "noPac — sAMAccountName Spoofing",
            severity    = Severity.CRITICAL,
            vulnerable  = vulnerable,
            reason      = (
                f"MachineAccountQuota={quota} (domain users can create machine accounts) "
                f"and patch not detected"
            ) if vulnerable else (
                f"MachineAccountQuota={quota} or patch indicators present"
            ),
            evidence    = {
                "ms_ds_machine_account_quota": quota,
                "patch_inferred":             patched,
            },
            remediation = (
                "1. Apply KB5008380 and KB5008102 on all DCs.\n"
                "2. Set ms-DS-MachineAccountQuota = 0 via ADSI Edit or AD PowerShell:\n"
                "   Set-ADDomain -Identity . -Replace @{'ms-DS-MachineAccountQuota'='0'}"
            ),
            next_step   = (
                f"python noPac.py {self.domain}/lowpriv_user:Password "
                f"-dc-ip {self.dc_ip} -shell\n"
                f"# OR\n"
                f"python scanner.py {self.domain}/lowpriv_user:Password "
                f"-dc-ip {self.dc_ip}"
            ) if vulnerable else "",
            noise_level = "LOW",
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

    def _infer_patch_status(self) -> bool:
        """
        KB5008380 adds validation that rejects sAMAccountName ending in '$'
        for non-computer objects. We infer patch state from domain behavior version
        and when the domain was last updated. Not 100% reliable — treat as indicator.
        """
        entries = self.ldap.query(
            "(objectClass=domainDNS)",
            ["msDS-Behavior-Version", "whenChanged"]
        )
        if not entries:
            return False
        level = int(entries[0]["msDS-Behavior-Version"].value or 0)
        # DFL 7 = Windows Server 2016 mode — required for patch to fully apply
        return level >= 7

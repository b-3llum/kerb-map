r"""
MS14-025 — Group Policy Preferences (GPP) Passwords.

Field bug (real-domain test): the original check just counted
``groupPolicyContainer`` LDAP entries and reported "HIGH vulnerable"
when any GPO existed. Every domain has at least the Default Domain
Policy and Default Domain Controllers Policy GPOs, so this fired on
every clean domain — a false positive that made the operator
distrust the rest of the priority table.

The real vulnerability is GPOs that contain ``cpassword="..."`` in
GPP XML files (Groups.xml, ScheduledTasks.xml, Services.xml,
DataSources.xml) under ``\\<DC>\SYSVOL\<domain>\Policies\{GUID}\``.
Confirming requires reading those XMLs over SMB. Until the CVE
infrastructure carries operator credentials past the LDAP layer
(planned), kerb-map cannot do that grep itself.

So this check now:
  * lists discovered GPOs as evidence (still useful intel)
  * marks ``vulnerable=False, severity=INFO``
  * sets ``patch_status=INDETERMINATE``
  * tells the operator the exact commands to grep SYSVOL themselves

The brief §2.1 pattern of honest INDETERMINATE reporting (used by
NoPac and ZeroLogon) applies here.
"""

from kerb_map.modules.cves.cve_base import (
    PATCH_STATUS_INDETERMINATE,
    CVEBase,
    CVEResult,
    Severity,
)
from kerb_map.output.logger import Logger

log = Logger()


class GPPPasswords(CVEBase):
    CVE_ID = "MS14-025"
    NAME = "GPP Passwords (cpassword)"

    def check(self) -> CVEResult:
        log.info(f"Checking {self.CVE_ID} ({self.NAME})...")
        gpos = self._find_gpos()
        evidence = {"gpo_count": len(gpos), "gpo_paths": gpos[:5]}

        if not gpos:
            return CVEResult(
                cve_id=self.CVE_ID,
                name=self.NAME,
                severity=Severity.INFO,
                vulnerable=False,
                reason="No GPOs visible via LDAP — SYSVOL likely empty.",
                evidence=evidence,
                remediation="N/A",
                next_step="",
            )

        return CVEResult(
            cve_id=self.CVE_ID,
            name=self.NAME,
            severity=Severity.INFO,
            vulnerable=False,
            reason=(
                f"Found {len(gpos)} GPO(s) in SYSVOL — kerb-map cannot grep "
                f"the XML files for `cpassword=` without SMB credentials "
                f"(plumbing planned). Manually verify; default Domain Policy "
                f"GPOs alone are not vulnerable."
            ),
            evidence=evidence,
            remediation=(
                "1. Apply KB2962486 on all systems.\n"
                "2. Delete existing GPP XML files containing cpassword from SYSVOL.\n"
                "3. Reset any passwords that were stored in GPP."
            ),
            next_step=(
                f"# Grep SYSVOL for cpassword from a Linux box:\n"
                f"smbclient -U '{self.domain}\\<USER>%<PASS>' "
                f"//{self.dc_ip}/SYSVOL -c 'recurse ON; mask *.xml; prompt OFF; mget *' "
                f"&& grep -r 'cpassword=' .\n"
                f"# OR PowerShell on a domain-joined host:\n"
                f"Get-GPPPassword   # PowerSploit\n"
                f"# OR impacket:\n"
                f"Get-GPPPassword.py {self.domain}/<USER>:<PASS>@{self.dc_ip}"
            ),
            patch_status=PATCH_STATUS_INDETERMINATE,
            references=[
                "https://support.microsoft.com/en-us/topic/"
                "ms14-025-vulnerability-in-group-policy-preferences-could-allow-"
                "elevation-of-privilege-may-13-2014-"
                "60734e15-af79-26ca-ea53-8cd617073c30",
            ],
        )

    def _find_gpos(self):
        entries = self.ldap.query(
            search_filter="(objectClass=groupPolicyContainer)",
            attributes=["displayName", "gPCFileSysPath"],
        )
        paths = []
        for e in entries:
            path = str(e["gPCFileSysPath"].value or "")
            name = str(e["displayName"].value or "Unknown GPO")
            if path:
                paths.append(f"{name}: {path}")
        return paths

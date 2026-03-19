"""
MS14-025 — Group Policy Preferences (GPP) Passwords
GPOs created before KB2962486 may store passwords encrypted with a publicly known AES key.
Detection: LDAP query for groupPolicyContainer objects, check gPCFileSysPath for SYSVOL paths.
"""

from kerb_map.modules.cves.cve_base import CVEBase, CVEResult, Severity
from kerb_map.output.logger import Logger

log = Logger()


class GPPPasswords(CVEBase):
    CVE_ID = "MS14-025"
    NAME = "GPP Passwords (cpassword)"

    def check(self) -> CVEResult:
        log.info(f"Checking {self.CVE_ID} ({self.NAME})...")
        gpos = self._find_gpos()
        vulnerable = len(gpos) > 0

        return CVEResult(
            cve_id=self.CVE_ID,
            name=self.NAME,
            severity=Severity.HIGH,
            vulnerable=vulnerable,
            reason=(
                f"Found {len(gpos)} GPO(s) in SYSVOL — check for cpassword in XML files "
                f"(Groups.xml, ScheduledTasks.xml, Services.xml, DataSources.xml)"
            ) if vulnerable else "No GPOs found or SYSVOL not reachable via LDAP",
            evidence={"gpo_count": len(gpos), "gpo_paths": gpos[:5]},
            remediation=(
                "1. Apply KB2962486 on all systems.\n"
                "2. Delete existing GPP XML files containing cpassword from SYSVOL:\n"
                "   Get-GPPPassword (PowerSploit)\n"
                "3. Reset any passwords that were stored in GPP."
            ),
            next_step=(
                f"# Extract GPP passwords from SYSVOL\n"
                f"Get-GPPPassword\n"
                f"# OR with impacket\n"
                f"Get-GPPPassword.py {self.domain}/user:pass@{self.dc_ip}"
            ) if vulnerable else "",
            references=["https://support.microsoft.com/en-us/topic/ms14-025-vulnerability-in-group-policy-preferences-could-allow-elevation-of-privilege-may-13-2014-60734e15-af79-26ca-ea53-8cd617073c30"],
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

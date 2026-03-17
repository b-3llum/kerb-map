"""CVE-2014-6324 — MS14-068 PAC Forgery"""

from kerb_map.modules.cves.cve_base import CVEBase, CVEResult, Severity
from kerb_map.output.logger import Logger

log = Logger()


class MS14068(CVEBase):
    CVE_ID = "CVE-2014-6324"
    NAME   = "MS14-068 (PAC Forgery)"

    def check(self) -> CVEResult:
        log.info(f"Checking {self.CVE_ID} ({self.NAME})...")
        fl = self._fl()
        vulnerable = fl < 6
        return CVEResult(
            cve_id=self.CVE_ID, name=self.NAME, severity=Severity.CRITICAL,
            vulnerable=vulnerable,
            reason=(f"Domain functional level {fl} suggests pre-2014 patch state"
                    if vulnerable else f"Domain functional level {fl} — likely patched"),
            evidence={"functional_level": fl},
            remediation="Apply MS14-068 (KB3011780) on all Domain Controllers.",
            next_step=(
                f"ms14-068.py -u lowpriv@{self.domain} -p Password -s <USER_SID> -d {self.dc_ip}\n"
                f"goldenPac.py {self.domain}/lowpriv:Password@<DC_HOSTNAME>"
            ) if vulnerable else "",
            references=["https://technet.microsoft.com/library/security/ms14-068"],
        )

    def _fl(self):
        entries = self.ldap.query(
            search_filter="(objectClass=domainDNS)",
            attributes=["msDS-Behavior-Version"],
        )
        return int(entries[0]["msDS-Behavior-Version"].value or 0) if entries else 0

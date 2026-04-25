"""
CVE-2022-26923 — Certifried (AD CS + Machine Account Abuse)
Any domain user can create a machine account (if MAQ > 0), request a certificate
with the machine's dNSHostName set to a DC, and authenticate as the DC.
Detection: Check AD CS enrollment services exist + MachineAccountQuota > 0.
"""

from kerb_map.modules.cves.cve_base import (
    PATCH_STATUS_INDETERMINATE,
    CVEBase,
    CVEResult,
    Severity,
)
from kerb_map.output.logger import Logger

log = Logger()


class Certifried(CVEBase):
    CVE_ID = "CVE-2022-26923"
    NAME = "Certifried (AD CS Machine Account Abuse)"

    def check(self) -> CVEResult:
        log.info(f"Checking {self.CVE_ID} ({self.NAME})...")
        adcs_present = self._check_adcs()
        maq = self._get_maq()

        # Brief §2.1: dropped DFL-based patch inference. Without ADCS
        # the chain isn't possible at all; with ADCS + MAQ>0 the
        # preconditions are present and the operator must confirm patch
        # state via certipy or by checking the CA host's patch level.
        if not adcs_present:
            return self._not_vulnerable(
                cve_id   = self.CVE_ID,
                name     = self.NAME,
                severity = Severity.INFO,
                reason   = "AD CS not deployed in this domain — Certifried not applicable.",
            )
        if maq <= 0:
            return CVEResult(
                cve_id       = self.CVE_ID,
                name         = self.NAME,
                severity     = Severity.INFO,
                vulnerable   = False,
                reason       = (
                    f"AD CS deployed but MachineAccountQuota={maq} — "
                    f"domain users cannot create the machine account "
                    f"required for the chain."
                ),
                evidence     = {"adcs_present": True, "machine_account_quota": maq},
                remediation  = "MAQ=0 already enforced; precondition absent.",
                next_step    = "",
                patch_status = "N/A (precondition absent)",
            )

        return CVEResult(
            cve_id       = self.CVE_ID,
            name         = self.NAME,
            severity     = Severity.HIGH,    # was CRITICAL — downgraded until certipy confirms
            vulnerable   = True,
            reason       = (
                f"AD CS is deployed AND MachineAccountQuota={maq} — "
                f"preconditions for Certifried are present. Patch state "
                f"cannot be determined from LDAP alone; run certipy to "
                f"confirm exploitability."
            ),
            evidence     = {
                "adcs_present":          True,
                "machine_account_quota": maq,
            },
            remediation  = (
                "1. Apply May 2022 security updates (KB5014754) on all DCs.\n"
                "2. Set ms-DS-MachineAccountQuota = 0.\n"
                "3. Enable strong certificate mapping enforcement."
            ),
            next_step    = (
                f"# Create machine account, set dNSHostName to DC, request cert\n"
                f"certipy account create -u user@{self.domain} -p pass "
                f"-dc-ip {self.dc_ip} -user FAKE$ -dns <DC_FQDN>\n"
                f"certipy req -u FAKE$@{self.domain} -p pass "
                f"-ca <CA_NAME> -template Machine -dc-ip {self.dc_ip}\n"
                f"certipy auth -pfx dc.pfx -dc-ip {self.dc_ip}"
            ),
            references   = ["https://research.ifcr.dk/certifried-active-directory-domain-privilege-escalation-cve-2022-26923-9e098fe298f4"],
            patch_status = PATCH_STATUS_INDETERMINATE,
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


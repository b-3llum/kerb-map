"""CVE Scanner — orchestrates all CVE/misconfiguration checks."""

from typing import List
from kerb_map.modules.cves.cve_base import CVEResult, Severity, SEVERITY_ORDER
from kerb_map.modules.cves.zerologon      import ZeroLogon
from kerb_map.modules.cves.nopac          import NoPac
from kerb_map.modules.cves.printnightmare import PrintNightmare, PetitPotam
from kerb_map.modules.cves.adcs           import ADCSAudit
from kerb_map.modules.cves.ms14_068       import MS14068
from kerb_map.output.logger import Logger

log = Logger()


class CVEScanner:
    def __init__(self, ldap_client, dc_ip, domain):
        self._safe  = [NoPac(ldap_client,dc_ip,domain),
                       ADCSAudit(ldap_client,dc_ip,domain),
                       MS14068(ldap_client,dc_ip,domain)]
        self._loud  = [ZeroLogon(ldap_client,dc_ip,domain),
                       PrintNightmare(ldap_client,dc_ip,domain),
                       PetitPotam(ldap_client,dc_ip,domain)]

    def run(self, aggressive=False) -> List[CVEResult]:
        checks = self._safe + (self._loud if aggressive else [])
        if not aggressive:
            log.warn("RPC CVE checks skipped — use --aggressive to enable (louder)")

        results = []
        for check in checks:
            try:
                r = check.check()
                results.append(r)
                if r.vulnerable:
                    log.critical(f"VULNERABLE: {r.cve_id} — {r.name}")
                else:
                    log.success(f"Not vulnerable: {r.name}")
            except Exception as e:
                log.error(f"{check.__class__.__name__} failed: {e}")

        results.sort(key=lambda r: (0 if r.vulnerable else 1,
                                    -SEVERITY_ORDER.get(r.severity, 0)))
        return results

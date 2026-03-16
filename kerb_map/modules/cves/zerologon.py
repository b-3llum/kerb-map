"""
CVE-2020-1472 — ZeroLogon
Netlogon elevation of privilege allowing machine account password reset.
Detection: non-destructive Netlogon RPC challenge probe + domain level check.
Noise: MEDIUM — generates Netlogon RPC traffic, patched DCs log the rejection.
"""

from .cve_base import CVEBase, CVEResult, Severity

try:
    from impacket.dcerpc.v5 import nrpc, transport
    IMPACKET_AVAILABLE = True
except ImportError:
    IMPACKET_AVAILABLE = False


class ZeroLogon(CVEBase):
    def check(self) -> CVEResult:
        ldap_indicator = self._check_domain_level()
        rpc_indicator  = self._probe_netlogon() if IMPACKET_AVAILABLE else False

        vulnerable = ldap_indicator or rpc_indicator

        reasons = []
        if ldap_indicator:
            reasons.append("Domain functional level suggests pre-Nov-2020 patch state")
        if rpc_indicator:
            reasons.append("Netlogon RPC accepted malformed ServerAuthenticate3 challenge")
        if not IMPACKET_AVAILABLE:
            reasons.append("impacket not available — RPC probe skipped; LDAP-only check")

        return CVEResult(
            cve_id      = "CVE-2020-1472",
            name        = "ZeroLogon",
            severity    = Severity.CRITICAL,
            vulnerable  = vulnerable,
            reason      = " | ".join(reasons) if reasons else "Not vulnerable",
            evidence    = {
                "domain_level_indicator": ldap_indicator,
                "rpc_probe":              rpc_indicator,
                "impacket_available":     IMPACKET_AVAILABLE,
            },
            remediation = (
                "Apply KB4557222 and subsequent Netlogon patches. "
                "Enforce FullSecureChannelProtection=1 via Group Policy."
            ),
            next_step   = (
                "# Verify (non-destructive)\n"
                "python zerologon_tester.py <DC_NAME> <DC_IP>\n\n"
                "# Exploit (destructive — lab only)\n"
                f"python cve-2020-1472-exploit.py <DC_NAME> {self.dc_ip}\n"
                f"secretsdump.py -no-pass -just-dc {self.domain}/<DC_NAME>$@{self.dc_ip}"
            ) if vulnerable else "",
            noise_level = "MEDIUM",
        )

    def _check_domain_level(self) -> bool:
        entries = self.ldap.query(
            "(objectClass=domainDNS)",
            ["msDS-Behavior-Version"]
        )
        if entries:
            level = int(entries[0]["msDS-Behavior-Version"].value or 0)
            # DFL below 7 (2016 level) is a weak indicator only
            return level < 6
        return False

    def _probe_netlogon(self) -> bool:
        """
        Non-destructive: send a zeroed-out ClientChallenge.
        Patched DCs return STATUS_ACCESS_DENIED immediately.
        Unpatched DCs may return a valid ServerChallenge.
        Does NOT modify any account or password.
        """
        try:
            binding = f"ncacn_ip_tcp:{self.dc_ip}[135]"
            rpct = transport.DCERPCTransportFactory(binding)
            dce  = rpct.get_dce_rpc()
            dce.connect()
            dce.bind(nrpc.MSRPC_UUID_NRPC)

            req = nrpc.NetrServerReqChallenge()
            req["PrimaryName"]     = f"{self.dc_ip}\x00"
            req["ComputerName"]    = "PROBE\x00"
            req["ClientChallenge"] = b"\x00" * 8

            resp = dce.request(req)
            return resp["ErrorCode"] == 0
        except Exception:
            return False

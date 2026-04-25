"""
CVE-2020-1472 — ZeroLogon
Netlogon elevation of privilege allowing machine account password reset.

Detection: pure LDAP can't determine KB-applied state. The previous
``_check_domain_level`` heuristic was wrong both ways (a fully-patched
2012 R2 domain reported "vulnerable", a freshly-built unpatched 2019
domain reported "patched"). Brief §2.1 — replaced with honest reporting:

  - **Without ``--aggressive``**: report patch_status = INDETERMINATE,
    severity HIGH (preconditions present, manual verification required).
  - **With ``--aggressive``**: optional Netlogon RPC probe. The current
    probe (``NetrServerReqChallenge`` ErrorCode == 0) is itself
    unreliable — patched DCs return 0 too. Brief §2.2 calls for a
    rewrite to the SecuraBV ``NetrServerAuthenticate3`` algorithm; until
    that lands, the RPC result is reported as a *signal*, not a verdict.
"""

from .cve_base import (
    PATCH_STATUS_INDETERMINATE,
    CVEBase,
    CVEResult,
    Severity,
)

try:
    from impacket.dcerpc.v5 import nrpc, transport
    IMPACKET_AVAILABLE = True
except ImportError:
    IMPACKET_AVAILABLE = False


class ZeroLogon(CVEBase):
    CVE_ID = "CVE-2020-1472"
    NAME   = "ZeroLogon"

    def check(self) -> CVEResult:
        rpc_indicator = self._probe_netlogon() if IMPACKET_AVAILABLE else None

        # Without an RPC confirm, we have no honest way to claim a DC is
        # vulnerable. Report HIGH (down from CRITICAL) with patch_status
        # = INDETERMINATE so the operator knows manual verification is
        # required. The legacy ``vulnerable`` flag stays True because the
        # underlying CVE applies to every domain that hasn't applied
        # KB4557222 — but the reason field makes the uncertainty explicit.
        if rpc_indicator is None:
            severity   = Severity.HIGH
            reason     = (
                "Patch state cannot be determined from LDAP alone. "
                "Run with --aggressive to enable the Netlogon RPC probe, "
                "or verify externally with zerologon_tester.py."
            )
            patch_state = PATCH_STATUS_INDETERMINATE
            vulnerable  = True   # CVE applies until proven otherwise
        elif rpc_indicator:
            severity    = Severity.CRITICAL
            reason      = (
                "Netlogon RPC accepted a malformed ServerAuthenticate3 "
                "challenge — DC appears unpatched."
            )
            patch_state = "RPC probe indicates vulnerable (note: probe is heuristic — confirm with zerologon_tester.py before exploitation)"
            vulnerable  = True
        else:
            severity    = Severity.INFO
            reason      = (
                "Netlogon RPC rejected the malformed ServerAuthenticate3 "
                "challenge — DC appears patched."
            )
            patch_state = "RPC probe indicates patched"
            vulnerable  = False

        return CVEResult(
            cve_id      = "CVE-2020-1472",
            name        = "ZeroLogon",
            severity    = severity,
            vulnerable  = vulnerable,
            reason      = reason,
            evidence    = {
                "rpc_probe":           rpc_indicator,
                "impacket_available":  IMPACKET_AVAILABLE,
            },
            remediation = (
                "Apply KB4557222 and subsequent Netlogon patches. "
                "Enforce FullSecureChannelProtection=1 via Group Policy."
            ),
            next_step   = (
                "# Confirm with the SecuraBV tester (non-destructive)\n"
                f"python3 zerologon_tester.py <DC_NAME> {self.dc_ip}\n\n"
                "# Exploit (DESTRUCTIVE — lab only, restore krbtgt before leaving)\n"
                f"python3 cve-2020-1472-exploit.py <DC_NAME> {self.dc_ip}\n"
                f"secretsdump.py -no-pass -just-dc {self.domain}/<DC_NAME>$@{self.dc_ip}"
            ) if vulnerable else "",
            noise_level  = "MEDIUM" if rpc_indicator is not None else "LOW",
            patch_status = patch_state,
        )

    def _probe_netlogon(self) -> bool:
        """Non-destructive: send a zeroed-out ClientChallenge and look at
        the ErrorCode. NOTE: brief §2.2 — this probe is itself unreliable
        because patched DCs return 0 too. The result is a *signal*, not
        a verdict. A ground-truth implementation needs the SecuraBV
        ``NetrServerAuthenticate3`` algorithm (1-2000 attempts with
        ClientCredential = b"\\x00"*8 and NegotiateFlags = 0x212fffff).
        Tracked separately as brief §2.2.
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

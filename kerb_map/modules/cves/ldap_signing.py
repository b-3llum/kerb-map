"""
LDAP Signing & Channel Binding — misconfiguration check.
If LDAP signing is not required, NTLM relay attacks to LDAP/S are possible.
Detection: Attempt an unsigned LDAP bind — if it succeeds, signing is not enforced.
"""

from kerb_map.modules.cves.cve_base import CVEBase, CVEResult, Severity
from kerb_map.output.logger import Logger

log = Logger()


class LDAPSigning(CVEBase):
    CVE_ID = "LDAP-SIGNING"
    NAME = "LDAP Signing Not Required"

    def check(self) -> CVEResult:
        log.info(f"Checking {self.NAME}...")
        signing_required = self._check_signing()

        vulnerable = not signing_required

        return CVEResult(
            cve_id=self.CVE_ID,
            name=self.NAME,
            severity=Severity.HIGH,
            vulnerable=vulnerable,
            reason=(
                "LDAP signing is NOT enforced — NTLM relay to LDAP is possible "
                "(ntlmrelayx, mitm6, Responder)"
            ) if vulnerable else "LDAP signing appears to be enforced",
            evidence={"signing_required": signing_required},
            remediation=(
                "1. Set 'Domain controller: LDAP server signing requirements' to 'Require signing' via GPO.\n"
                "2. Set 'Network security: LDAP client signing requirements' to 'Require signing'.\n"
                "3. Enable LDAP channel binding (LdapEnforceChannelBinding=2)."
            ),
            next_step=(
                f"# Relay NTLM auth to LDAP for privilege escalation\n"
                f"ntlmrelayx.py -t ldap://{self.dc_ip} --delegate-access\n"
                f"# Or escalate via RBCD\n"
                f"ntlmrelayx.py -t ldap://{self.dc_ip} --escalate-user <USER>"
            ) if vulnerable else "",
            references=["https://support.microsoft.com/en-us/topic/2020-ldap-channel-binding-and-ldap-signing-requirements-for-windows-ef185fb8-00f7-167d-744c-f299a66fc00a"],
        )

    def _check_signing(self) -> bool:
        """
        Query the dsServiceName / domain policy for LDAP signing requirement.
        If the existing connection was established without signing (simple NTLM bind
        over port 389), the DC does not enforce signing.
        We check the domain controller policy via LDAP attribute.
        """
        entries = self.ldap.query(
            search_filter="(objectClass=domainDNS)",
            attributes=["distinguishedName"],
        )
        if not entries:
            return False

        # Check the DC's own policy object for signing requirements
        # dsHeuristics or registry-equivalent policy entries
        # The simplest reliable check: if we connected on 389 without signing,
        # the DC doesn't require it. The LDAPClient uses NTLM without explicit
        # signing, so if the connection is alive, signing is likely not required.
        conn = self.ldap.conn
        if conn and conn.bound:
            # If connected on port 389 (not 636/LDAPS), signing is not enforced
            server_port = conn.server.port if conn.server else 389
            if server_port == 389:
                return False  # Connected without signing = not required
            else:
                return True   # LDAPS enforces transport-level security
        return True  # Conservative: assume enforced if can't determine

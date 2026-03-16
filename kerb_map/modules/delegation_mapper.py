"""
Delegation Mapper — maps all three delegation types.

  Unconstrained  : TRUSTED_FOR_DELEGATION (0x80000) — any auth hands over TGT
  Constrained    : msDS-AllowedToDelegateTo — specific SPNs only
  RBCD           : msDS-AllowedToActOnBehalfOfOtherIdentity — on the target object
"""

from dataclasses import dataclass, field
from typing import List


@dataclass
class UnconstrainedHost:
    account:      str
    is_dc:        bool
    os:           str
    risk:         str = "CRITICAL"
    note:         str = "Any authenticating user surrenders their TGT here"


@dataclass
class ConstrainedAccount:
    account:            str
    allowed_to_delegate: List[str]
    protocol_transition: bool   # S4U2Self enabled — worse
    risk:               str = "HIGH"


@dataclass
class RBCDTarget:
    target_account: str
    note:           str = "RBCD configured — check who holds write access to this attribute"
    risk:           str = "HIGH"


@dataclass
class DelegationResults:
    unconstrained: List[UnconstrainedHost] = field(default_factory=list)
    constrained:   List[ConstrainedAccount] = field(default_factory=list)
    rbcd:          List[RBCDTarget] = field(default_factory=list)


class DelegationMapper:
    def __init__(self, ldap_client):
        self.ldap = ldap_client

    def map_all(self) -> DelegationResults:
        return DelegationResults(
            unconstrained = self._find_unconstrained(),
            constrained   = self._find_constrained(),
            rbcd          = self._find_rbcd(),
        )

    # ------------------------------------------------------------------ #

    def _find_unconstrained(self) -> List[UnconstrainedHost]:
        """
        TRUSTED_FOR_DELEGATION = 0x80000.
        Filter out DCs (primaryGroupID=516) — they always have this.
        """
        entries = self.ldap.query(
            search_filter=(
                "(&"
                "(userAccountControl:1.2.840.113556.1.4.803:=524288)"
                "(!(primaryGroupID=516))"   # not a DC
                "(!(userAccountControl:1.2.840.113556.1.4.803:=2))"  # not disabled
                ")"
            ),
            attributes=["sAMAccountName", "operatingSystem", "primaryGroupID"],
        )
        results = []
        for e in entries:
            results.append(UnconstrainedHost(
                account = str(e["sAMAccountName"]),
                is_dc   = False,
                os      = str(e["operatingSystem"].value or "unknown"),
            ))
        return results

    def _find_constrained(self) -> List[ConstrainedAccount]:
        entries = self.ldap.query(
            search_filter="(msDS-AllowedToDelegateTo=*)",
            attributes=[
                "sAMAccountName", "msDS-AllowedToDelegateTo", "userAccountControl"
            ],
        )
        results = []
        for e in entries:
            uac  = int(e["userAccountControl"].value or 0)
            # TRUSTED_TO_AUTH_FOR_DELEGATION = 0x1000000 → S4U2Self
            proto_transition = bool(uac & 0x1000000)
            spns = [str(s) for s in (e["msDS-AllowedToDelegateTo"] or [])]
            results.append(ConstrainedAccount(
                account             = str(e["sAMAccountName"]),
                allowed_to_delegate = spns,
                protocol_transition = proto_transition,
                risk = "CRITICAL" if proto_transition else "HIGH",
            ))
        return results

    def _find_rbcd(self) -> List[RBCDTarget]:
        entries = self.ldap.query(
            search_filter="(msDS-AllowedToActOnBehalfOfOtherIdentity=*)",
            attributes=["sAMAccountName"],
        )
        return [
            RBCDTarget(target_account=str(e["sAMAccountName"]))
            for e in entries
        ]

"""
Base class for all CVE / misconfiguration checks.
Every check returns a standardised CVEResult dataclass.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    INFO     = "INFO"


SEVERITY_ORDER = {
    Severity.CRITICAL: 5,
    Severity.HIGH:     4,
    Severity.MEDIUM:   3,
    Severity.LOW:      2,
    Severity.INFO:     1,
}


# Patch-status sentinels. Brief §2.1: kerb-map has no honest way to
# infer KB-applied state from LDAP, so the previous DFL-based heuristic
# was wrong both ways. Use these strings in CVEResult.evidence so the
# JSON / wire format carries the operator-readable state without us
# having to plumb a third boolean.
PATCH_STATUS_INDETERMINATE = "indeterminate (cannot be inferred from LDAP)"
PATCH_STATUS_RPC_CONFIRMED_VULNERABLE = "RPC probe confirms vulnerable"
PATCH_STATUS_RPC_CONFIRMED_PATCHED    = "RPC probe confirms patched"


@dataclass
class CVEResult:
    cve_id:      str
    name:        str
    severity:    Severity
    vulnerable:  bool
    reason:      str
    evidence:    dict[str, Any]
    remediation: str
    next_step:   str
    noise_level: str  = "LOW"   # LOW / MEDIUM / HIGH
    references:  list[str] = field(default_factory=list)
    # Brief §2.1: distinguish "we observed the vulnerability" from
    # "the preconditions are present but we couldn't confirm patch status."
    # The Scorer downgrades indeterminate findings so they don't dominate
    # the priority table.
    patch_status: str = PATCH_STATUS_INDETERMINATE

    def to_dict(self) -> dict[str, Any]:
        return {
            "cve_id":       self.cve_id,
            "name":         self.name,
            "severity":     self.severity.value,
            "vulnerable":   self.vulnerable,
            "reason":       self.reason,
            "evidence":     self.evidence,
            "remediation":  self.remediation,
            "next_step":    self.next_step,
            "noise_level":  self.noise_level,
            "references":   self.references,
            "patch_status": self.patch_status,
        }


class CVEBase(ABC):
    def __init__(self, ldap_client, dc_ip: str, domain: str,
                 *, username: str | None = None,
                 password: str | None = None,
                 nthash: str | None = None,
                 use_kerberos: bool = False):
        self.ldap         = ldap_client
        self.dc_ip        = dc_ip
        self.domain       = domain
        # Optional operator credentials. Most checks ignore them; GPP
        # uses them to open an SMB session against SYSVOL and grep
        # the GPP XMLs for `cpassword=`. Keyword-only so the existing
        # 3-arg construction sites stay valid.
        self.username     = username
        self.password     = password
        self.nthash       = nthash
        self.use_kerberos = use_kerberos

    @abstractmethod
    def check(self) -> CVEResult:
        pass

    def _not_vulnerable(self, cve_id: str, name: str, severity: Severity, reason: str) -> CVEResult:
        """Return a standard CVEResult for non-vulnerable / skipped checks."""
        return CVEResult(
            cve_id=cve_id,
            name=name,
            severity=severity,
            vulnerable=False,
            reason=reason,
            evidence={},
            remediation="N/A",
            next_step="",
        )

    @property
    def name(self) -> str:
        return self.__class__.__name__

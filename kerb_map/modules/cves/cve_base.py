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
    references:  list[str] = field(default_factory=list)  # Fix: was missing, caused unexpected kwarg crash

    def to_dict(self) -> dict[str, Any]:
        """Fix: callers in cli.py call r.to_dict() — dataclass has no such method by default."""
        return {
            "cve_id":      self.cve_id,
            "name":        self.name,
            "severity":    self.severity.value,   # serialize enum to string
            "vulnerable":  self.vulnerable,
            "reason":      self.reason,
            "evidence":    self.evidence,
            "remediation": self.remediation,
            "next_step":   self.next_step,
            "noise_level": self.noise_level,
            "references":  self.references,
        }


class CVEBase(ABC):
    def __init__(self, ldap_client, dc_ip: str, domain: str):
        self.ldap   = ldap_client
        self.dc_ip  = dc_ip
        self.domain = domain

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

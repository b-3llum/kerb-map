"""
Base class for all CVE / misconfiguration checks.
Every check returns a standardised CVEResult dataclass.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, Any, List


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
    evidence:    Dict[str, Any]
    remediation: str
    next_step:   str
    noise_level: str  = "LOW"   # LOW / MEDIUM / HIGH
    references:  List[str] = field(default_factory=list)  # Fix: was missing, caused unexpected kwarg crash

    def to_dict(self) -> Dict[str, Any]:
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

    @property
    def name(self) -> str:
        return self.__class__.__name__

"""MS14-068 (CVE-2014-6324) — PAC forgery patch-state heuristic.

Honest reporting: we infer patch state from the domain functional
level (FL ≥ 6 = Server 2008R2+ which only ship the patched code),
which is a heuristic. Tests pin the FL boundary."""

from unittest.mock import MagicMock

from kerb_map.modules.cves.cve_base import Severity
from kerb_map.modules.cves.ms14_068 import MS14068


def _entry(fl):
    e = MagicMock()
    e.__contains__ = lambda self, k: k == "msDS-Behavior-Version"
    def _get(self, k):
        m = MagicMock()
        m.value = fl
        return m
    e.__getitem__ = _get
    return e


def _ldap(entries):
    ldap = MagicMock()
    ldap.query.return_value = entries
    return ldap


def test_low_fl_flagged_vulnerable():
    """FL=2 (Server 2003) → predates the MS14-068 patch."""
    r = MS14068(_ldap([_entry(2)]), "10.0.0.1", "corp.local").check()
    assert r.vulnerable is True
    assert r.severity == Severity.CRITICAL
    assert "ms14-068.py" in r.next_step
    assert "lowpriv@corp.local" in r.next_step


def test_high_fl_marked_clean():
    """FL=7 (2016/19/22) → patch baseline; no DC running pre-patch."""
    r = MS14068(_ldap([_entry(7)]), "10.0.0.1", "corp.local").check()
    assert r.vulnerable is False
    assert r.next_step == ""


def test_fl_boundary_at_6():
    """FL<6 vulnerable, FL≥6 not. Pin the cutoff."""
    assert MS14068(_ldap([_entry(5)]), "10.0.0.1", "x").check().vulnerable is True
    assert MS14068(_ldap([_entry(6)]), "10.0.0.1", "x").check().vulnerable is False


def test_no_domain_dns_entry_treats_as_fl_zero():
    """No domainDNS object found → FL=0 → flagged. Defensive — better
    a false positive the operator can dismiss than a false clean."""
    r = MS14068(_ldap([]), "10.0.0.1", "x").check()
    assert r.vulnerable is True

"""CVE Scanner — orchestrates all CVE/misconfiguration checks.

Brief §3.7: operators want to skip ZeroLogon (their EDR fires) but
still run noPac. ``run(only=...)`` accepts a set of CVE IDs to filter
the check list; ``list_checks()`` enumerates every available check
for the ``--list-cves`` CLI command.
"""


from kerb_map.modules.cves.adcs import ADCSAudit
from kerb_map.modules.cves.bronze_bit import BronzeBit
from kerb_map.modules.cves.certifried import Certifried
from kerb_map.modules.cves.cve_base import SEVERITY_ORDER, CVEBase, CVEResult
from kerb_map.modules.cves.gpp_passwords import GPPPasswords
from kerb_map.modules.cves.ldap_signing import LDAPSigning
from kerb_map.modules.cves.ms14_068 import MS14068
from kerb_map.modules.cves.nopac import NoPac
from kerb_map.modules.cves.printnightmare import PetitPotam, PrintNightmare
from kerb_map.modules.cves.zerologon import ZeroLogon
from kerb_map.output.logger import Logger

log = Logger()


class CVEScanner:
    """Orchestrates CVE checks. Each check is a CVEBase subclass with a
    ``CVE_ID`` and ``NAME`` class attribute. Checks land in one of two
    buckets: passive (always runs) or aggressive (RPC-touching, gated
    behind ``--aggressive``)."""

    SAFE_CHECKS = (NoPac, ADCSAudit, MS14068, GPPPasswords,
                   BronzeBit, Certifried, LDAPSigning)

    AGGRESSIVE_CHECKS = (ZeroLogon, PrintNightmare, PetitPotam)

    def __init__(self, ldap_client, dc_ip, domain,
                 *, username: str | None = None,
                 password: str | None = None,
                 nthash: str | None = None,
                 use_kerberos: bool = False):
        self.ldap   = ldap_client
        self.dc_ip  = dc_ip
        self.domain = domain
        creds = dict(username=username, password=password,
                     nthash=nthash, use_kerberos=use_kerberos)
        self._safe  = [c(ldap_client, dc_ip, domain, **creds)
                       for c in self.SAFE_CHECKS]
        self._loud  = [c(ldap_client, dc_ip, domain, **creds)
                       for c in self.AGGRESSIVE_CHECKS]

    def run(
        self,
        aggressive: bool = False,
        only: set[str] | None = None,
    ) -> list[CVEResult]:
        """Run every check in scope.

        ``only`` is a set of CVE IDs (case-insensitive). When non-empty,
        only checks whose ``CVE_ID`` matches one of the entries are
        executed. Combines with ``aggressive`` — if the operator wants
        ``--only-cves CVE-2020-1472`` (ZeroLogon) without ``--aggressive``,
        the check is filtered out and a warning printed.
        """
        checks = list(self._safe)
        if aggressive:
            checks.extend(self._loud)
        else:
            log.warn("RPC CVE checks skipped — use --aggressive to enable (louder)")

        if only:
            wanted_lower = {x.lower() for x in only}
            kept   = [c for c in checks if _check_id(c).lower() in wanted_lower]
            dropped = [c for c in checks if _check_id(c).lower() not in wanted_lower]
            checks = kept
            if dropped:
                log.info(
                    f"--only-cves filtered out: {', '.join(_check_id(c) for c in dropped)}"
                )
            # If the operator named an aggressive check but didn't pass
            # --aggressive, surface that mismatch — easy to forget.
            if not aggressive:
                missing_aggressive = wanted_lower & {c.CVE_ID.lower() for c in self.AGGRESSIVE_CHECKS}
                if missing_aggressive:
                    log.warn(
                        f"--only-cves named aggressive checks ({', '.join(missing_aggressive)}) "
                        f"but --aggressive was not passed — these are skipped."
                    )

        results: list[CVEResult] = []
        for check in checks:
            try:
                r = check.check()
                results.append(r)
                if r.vulnerable:
                    log.critical(f"VULNERABLE: {r.cve_id} — {r.name}")
                else:
                    log.success(f"Not vulnerable: {r.name}")
            except Exception as e:
                log.error(f"{check.__class__.__name__} failed: {e}")

        results.sort(
            key=lambda r: (0 if r.vulnerable else 1,
                           -SEVERITY_ORDER.get(r.severity, 0))
        )
        return results

    @classmethod
    def list_checks(cls) -> list[dict]:
        """Enumerate every available check for ``--list-cves``.
        Returns a list of dicts so the caller can render however it
        wants (Rich table, plain text, JSON for kerb-chain)."""
        out: list[dict] = []
        for check_cls in cls.SAFE_CHECKS:
            out.append({
                "cve_id":              _class_id(check_cls),
                "name":                _class_name(check_cls),
                "requires_aggressive": False,
            })
        for check_cls in cls.AGGRESSIVE_CHECKS:
            out.append({
                "cve_id":              _class_id(check_cls),
                "name":                _class_name(check_cls),
                "requires_aggressive": True,
            })
        return out


# ────────────────────────────────────────────────────────────────────── #
#  ID / name resolution                                                  #
# ────────────────────────────────────────────────────────────────────── #


def _class_id(check_cls: type[CVEBase]) -> str:
    """Class-level CVE_ID, falling back to the class name. Every check
    in CVEScanner.SAFE_CHECKS / AGGRESSIVE_CHECKS now sets CVE_ID, but
    keep the fallback so a future check class doesn't crash --list-cves."""
    return getattr(check_cls, "CVE_ID", None) or check_cls.__name__


def _class_name(check_cls: type[CVEBase]) -> str:
    return getattr(check_cls, "NAME", None) or check_cls.__name__


def _check_id(check: CVEBase) -> str:
    return _class_id(type(check))

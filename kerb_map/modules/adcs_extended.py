"""
ADCS Extended — ESC9, ESC13, ESC15 (EKUwu / CVE-2024-49019).

The bundled CVE module covers ESC1/2/3/8 well; the brief's §2.3
audit + the 2026 landscape research both flagged ESC9, ESC13, and
ESC15 as the gaps that matter most. Each is a passive LDAP read
against ``CN=Certificate Templates,CN=Public Key Services,
CN=Services,CN=Configuration,DC=...`` plus a per-template ACL walk.

The three checks share one query and one ACL pass per template, so
the module costs one extra LDAP round-trip vs. the existing ADCS
module — not three.

──────────────────────────────────────────────────────────────────────
ESC9 — CT_FLAG_NO_SECURITY_EXTENSION
──────────────────────────────────────────────────────────────────────

A template with ``msPKI-Enrollment-Flag`` bit ``0x80`` set
(``CT_FLAG_NO_SECURITY_EXTENSION``) skips the szOID_NTDS_CA_SECURITY_EXT
extension that Microsoft added in the May 2022 ADCS hardening. With
the extension absent, an attacker who can write ``userPrincipalName``
on a target account can change UPN → admin's UPN, enroll, then revert.

Detection here is the *template* side; the writeable-UPN side is the
Shadow-Credentials-style ACL check. We flag any enrollable template
with the bit set so the operator can grep for accounts they own with
``WriteProperty`` on UPN.

──────────────────────────────────────────────────────────────────────
ESC13 — msDS-OIDToGroupLink abuse
──────────────────────────────────────────────────────────────────────

A template with ``msPKI-Certificate-Policy`` containing an OID that
maps to a privileged AD group via ``msDS-OIDToGroupLink`` confers that
group's privileges to anyone who enrolls. Authentication via the
issued cert grants the group SID in the PAC.

Detection: cross-reference template policy OIDs against the OID
container's ``msDS-OIDToGroupLink`` entries; if any link target is a
privileged group, the template is ESC13.

──────────────────────────────────────────────────────────────────────
ESC15 / EKUwu — CVE-2024-49019
──────────────────────────────────────────────────────────────────────

V1 templates (e.g. WebServer) accept attacker-supplied Application
Policies in the CSR, overriding the template's intended EKUs. An
attacker enrols WebServer, supplies ``Client Authentication`` as the
Application Policy, and gets a cert that authenticates them as any
account they specified in the SAN.

Detection: any v1 template (``msPKI-Template-Schema-Version`` = 1)
where Domain/Authenticated Users have Enroll. The patch (April 2024)
removed the override path; defenders need to know which templates
*were* abusable so they can confirm the CA host is patched.

Reference:
- https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc
- https://swisskyrepo.github.io/InternalAllTheThings/active-directory/ad-adcs-esc/
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
from kerb_map.ldap_helpers import attr, attrs
from kerb_map.plugin import Finding, Module, ScanContext, ScanResult, register

# msPKI-Enrollment-Flag bits we care about.
CT_FLAG_NO_SECURITY_EXTENSION = 0x80   # the ESC9 marker

# Authenticated Users / Domain Users — the populations that matter for
# "anyone in the domain can enrol this".
PUBLIC_ENROLMENT_SIDS = {
    "S-1-5-11",  # Authenticated Users
    "S-1-1-0",   # Everyone
}
# Plus the domain-relative "Domain Users" (RID 513). Resolved later.

# The Enrollment-Rights extended-right GUID. An ACE granting CONTROL_ACCESS
# with this GUID = the trustee can enrol in the template.
EXT_RIGHT_ENROLL = "0e10c968-78fb-11d2-90d4-00c04f79dc55"


@register
class AdcsExtended(Module):
    name        = "AD CS Extended (ESC9/ESC13/ESC15)"
    flag        = "adcs-extended"
    description = "Detect ESC9 (no-security-ext), ESC13 (OIDToGroupLink), ESC15 (EKUwu/CVE-2024-49019)"
    category    = "cve"
    in_default_run = True

    def scan(self, ctx: ScanContext) -> ScanResult:
        templates = self._fetch_templates(ctx)
        if not templates:
            return ScanResult(raw={
                "applicable": False,
                "reason":     "no certificate templates found (ADCS not deployed in this domain)",
            })

        oid_links = self._fetch_oid_to_group_links(ctx)

        findings: list[Finding] = []
        per_template: list[dict] = []

        # Build the set of "public" enrolment SIDs. Domain Users RID is
        # 513; only resolvable when we know the domain SID.
        public_sids = set(PUBLIC_ENROLMENT_SIDS)
        if ctx.domain_sid:
            public_sids.add(f"{ctx.domain_sid}-513")

        for tpl in templates:
            tpl_name = attr(tpl, "cn") or attr(tpl, "displayName") or "<unknown>"
            tpl_dn   = attr(tpl, "distinguishedName") or ""
            schema   = _to_int(attr(tpl, "msPKI-Template-Schema-Version"))
            enroll_flag = _to_int(attr(tpl, "msPKI-Enrollment-Flag")) or 0
            policy_oids = [str(p) for p in attrs(tpl, "msPKI-Certificate-Policy")]

            # Walk the template's DACL once for all three checks.
            sd = parse_sd(attr(tpl, "nTSecurityDescriptor"))
            enrolment_trustees: set[str] = set()
            if sd is not None:
                for ace in walk_aces(sd, object_dn=tpl_dn):
                    if self._grants_enrolment(ace):
                        enrolment_trustees.add(ace.trustee_sid)

            public_enrolable = bool(enrolment_trustees & public_sids)

            row = {
                "name":             tpl_name,
                "distinguishedName": tpl_dn,
                "schema_version":   schema,
                "enroll_flag":      enroll_flag,
                "policy_oids":      policy_oids,
                "enrolment_trustees": sorted(enrolment_trustees),
                "public_enrolable": public_enrolable,
                "esc9":             False,
                "esc13":            False,
                "esc15":            False,
                "esc13_groups":     [],
            }

            # ── ESC9 ───────────────────────────────────────────────
            if (enroll_flag & CT_FLAG_NO_SECURITY_EXTENSION) and public_enrolable:
                row["esc9"] = True
                findings.append(Finding(
                    target=tpl_name,
                    attack="AD CS ESC9 (no security extension)",
                    severity="HIGH",
                    priority=82,
                    reason=(
                        f"Template '{tpl_name}' has CT_FLAG_NO_SECURITY_EXTENSION "
                        f"(0x80) AND is publicly enrolable. Operator with WriteProperty "
                        f"on userPrincipalName of a target account can change UPN to "
                        f"admin@..., enrol, revert — issued cert authenticates as admin."
                    ),
                    next_step=(
                        f"# 1. Find a target account where you have WriteProperty(UPN)\n"
                        f"# 2. As that account: certipy account update -username <victim>"
                        f" -upn 'administrator@{ctx.domain}'\n"
                        f"# 3. certipy req -ca <CA> -template '{tpl_name}'"
                        f" -u <victim>@{ctx.domain} -p <pass>\n"
                        f"# 4. Revert UPN, then certipy auth -pfx <victim>.pfx"
                    ),
                    category="cve",
                    mitre="T1649",   # Steal or Forge Authentication Certificates
                    data={
                        "template_dn":   tpl_dn,
                        "enroll_flag":   hex(enroll_flag),
                        "domain_sid":    ctx.domain_sid,
                    },
                ))

            # ── ESC13 ──────────────────────────────────────────────
            esc13_groups = [
                {"oid": oid, "group": grp}
                for oid in policy_oids
                for grp in oid_links.get(oid, [])
                if grp.get("privileged")
            ]
            if esc13_groups and public_enrolable:
                row["esc13"] = True
                row["esc13_groups"] = esc13_groups
                joined_groups = ", ".join(g["group"]["name"] for g in esc13_groups)
                findings.append(Finding(
                    target=tpl_name,
                    attack="AD CS ESC13 (OIDToGroupLink)",
                    severity="CRITICAL",
                    priority=92,
                    reason=(
                        f"Template '{tpl_name}' carries policy OID(s) linked to "
                        f"privileged group(s): {joined_groups}. Anyone who can "
                        f"enrol gets that group's privileges in the cert PAC."
                    ),
                    next_step=(
                        f"# certipy req -ca <CA> -template '{tpl_name}' "
                        f"-u <op>@{ctx.domain} -p <pass>\n"
                        f"# certipy auth -pfx <op>.pfx → TGT carries the linked "
                        f"group SID in the PAC."
                    ),
                    category="cve",
                    mitre="T1649",
                    data={
                        "template_dn":   tpl_dn,
                        "policy_oids":   policy_oids,
                        "linked_groups": esc13_groups,
                        "domain_sid":    ctx.domain_sid,
                    },
                ))

            # ── ESC15 / EKUwu ──────────────────────────────────────
            if schema == 1 and public_enrolable:
                row["esc15"] = True
                findings.append(Finding(
                    target=tpl_name,
                    attack="AD CS ESC15 / EKUwu (CVE-2024-49019)",
                    severity="HIGH",
                    priority=80,
                    reason=(
                        f"Template '{tpl_name}' is schema v1 AND publicly enrolable. "
                        f"On unpatched CAs, attacker can supply Application Policies "
                        f"in the CSR (e.g. Client Authentication) overriding template "
                        f"EKUs and enrol as any account named in the SAN. CVE-2024-49019."
                    ),
                    next_step=(
                        f"# Patched April 2024 cumulative — confirm the CA host is\n"
                        f"# at the patched build before assuming this is exploitable.\n"
                        f"# certipy req -ca <CA> -template '{tpl_name}' -upn "
                        f"administrator@{ctx.domain} \\\n"
                        f"#   -application-policies '1.3.6.1.5.5.7.3.2' "
                        f"-u <op>@{ctx.domain} -p <pass>"
                    ),
                    category="cve",
                    mitre="T1649",
                    data={
                        "template_dn":     tpl_dn,
                        "schema_version":  schema,
                        "domain_sid":      ctx.domain_sid,
                    },
                ))

            per_template.append(row)

        # Resolve the trustee SIDs for the raw output so the operator
        # can read it without a SID-translation tool.
        all_trustees = {sid for row in per_template for sid in row["enrolment_trustees"]}
        names = resolve_sids(ctx.ldap, all_trustees, ctx.base_dn) if all_trustees else {}
        for row in per_template:
            row["enrolment_trustee_names"] = [
                names.get(sid, {}).get("sAMAccountName") or sid
                for sid in row["enrolment_trustees"]
            ]

        summary = {
            "templates_total": len(per_template),
            "esc9_count":      sum(1 for r in per_template if r["esc9"]),
            "esc13_count":     sum(1 for r in per_template if r["esc13"]),
            "esc15_count":     sum(1 for r in per_template if r["esc15"]),
        }

        return ScanResult(
            raw={
                "applicable":  True,
                "templates":   per_template,
                "oid_links":   oid_links,
                "summary":     summary,
            },
            findings=findings,
        )

    # ------------------------------------------------------------------ #
    #  Fetchers                                                          #
    # ------------------------------------------------------------------ #

    def _fetch_templates(self, ctx: ScanContext) -> list:
        return ctx.ldap.query_config(
            search_filter="(objectClass=pKICertificateTemplate)",
            attributes=[
                "cn", "displayName", "distinguishedName",
                "msPKI-Template-Schema-Version",
                "msPKI-Enrollment-Flag",
                "msPKI-Certificate-Policy",
                "msPKI-Certificate-Name-Flag",
                "pKIExtendedKeyUsage",
                "nTSecurityDescriptor",
            ],
        ) if hasattr(ctx.ldap, "query_config") else self._fallback_templates(ctx)

    def _fallback_templates(self, ctx: ScanContext) -> list:
        # If we ever drop query_config from LDAPClient, fall back to
        # an explicit Configuration-NC search base.
        return ctx.ldap.query(
            search_filter="(objectClass=pKICertificateTemplate)",
            attributes=[
                "cn", "displayName", "distinguishedName",
                "msPKI-Template-Schema-Version",
                "msPKI-Enrollment-Flag",
                "msPKI-Certificate-Policy",
                "nTSecurityDescriptor",
            ],
            search_base=f"CN=Configuration,{ctx.base_dn}",
            controls=sd_control(),
        )

    def _fetch_oid_to_group_links(self, ctx: ScanContext) -> dict[str, list[dict]]:
        """Map OID → [{name, dn, sid, privileged}] from the OID container.
        Empty when no OIDs are configured (the common-case clean enterprise)."""
        entries = ctx.ldap.query_config(
            search_filter="(objectClass=msPKI-Enterprise-Oid)",
            attributes=["msPKI-Cert-Template-OID", "msDS-OIDToGroupLink",
                        "displayName"],
        ) if hasattr(ctx.ldap, "query_config") else []

        out: dict[str, list[dict]] = {}
        if not entries:
            return out

        # Resolve linked-group DNs in one batch.
        all_links: set[str] = set()
        for e in entries:
            for link in attrs(e, "msDS-OIDToGroupLink"):
                if link:
                    all_links.add(str(link))
        group_info: dict[str, dict] = {}
        for dn in all_links:
            hits = ctx.ldap.query(
                search_filter="(objectClass=group)",
                attributes=["sAMAccountName", "objectSid", "adminCount"],
                search_base=dn,
            )
            if hits:
                h = hits[0]
                from kerb_map.ldap_helpers import sid_to_str
                group_info[dn] = {
                    "name":       attr(h, "sAMAccountName") or "",
                    "sid":        sid_to_str(attr(h, "objectSid")),
                    "admincount": attr(h, "adminCount") == 1,
                }

        for e in entries:
            oid = attr(e, "msPKI-Cert-Template-OID")
            if not oid:
                continue
            row: list[dict] = []
            for dn in attrs(e, "msDS-OIDToGroupLink"):
                if not dn:
                    continue
                gi = group_info.get(str(dn), {"name": str(dn), "sid": None, "admincount": False})
                privileged = (
                    gi["admincount"]
                    or (gi["sid"] and is_well_known_privileged(gi["sid"]))
                )
                row.append({
                    "dn":         str(dn),
                    "name":       gi["name"],
                    "sid":        gi["sid"],
                    "privileged": bool(privileged),
                })
            out[str(oid)] = row
        return out

    # ------------------------------------------------------------------ #
    #  ACE predicates                                                    #
    # ------------------------------------------------------------------ #

    @staticmethod
    def _grants_enrolment(ace) -> bool:
        """ACE grants enrolment if it has GenericAll, GenericWrite, OR
        the Enrollment extended right (CONTROL_ACCESS + GUID match,
        or CONTROL_ACCESS with no GUID = all extended rights)."""
        if ace.has_right(ADS_RIGHT_GENERIC_ALL | ADS_RIGHT_GENERIC_WRITE):
            return True
        if not ace.has_right(ADS_RIGHT_DS_CONTROL_ACCESS):
            return False
        if ace.object_type_guid is None:
            return True
        return ace.object_type_guid.lower() == EXT_RIGHT_ENROLL


def _to_int(value) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None

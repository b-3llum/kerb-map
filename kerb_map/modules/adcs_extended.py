"""
ADCS Extended — ESC4, ESC5, ESC7, ESC9, ESC13, ESC15 (EKUwu / CVE-2024-49019).

Combined with the legacy ADCS module's ESC1/2/3/8 coverage, this
brings kerb-map to ESC1–15 (skipping ESC6 which needs RPC-level CA
registry reads — tracked separately).

Each ESC variant is a passive LDAP read; the three groups are:

  Template-level (one DACL walk per template):
    ESC4   — dangerous template ACLs (write rights to non-admins)
    ESC9   — CT_FLAG_NO_SECURITY_EXTENSION + public enrol
    ESC13  — msPKI-Certificate-Policy linked to privileged group
    ESC15  — v1 schema templates publicly enrolable (EKUwu / CVE-2024-49019)

  PKI container-level:
    ESC5   — dangerous ACLs on CN=Public Key Services container
             (and CN=Certificate Templates / CN=Enrollment Services)

  CA-level:
    ESC7   — ManageCA / ManageCertificates extended rights granted to
             non-admin principals on a pKIEnrollmentService object

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
    ADS_RIGHT_WRITE_DAC,
    ADS_RIGHT_WRITE_OWNER,
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

# Extended-right GUIDs for ADCS-specific control access.
EXT_RIGHT_ENROLL              = "0e10c968-78fb-11d2-90d4-00c04f79dc55"
# ESC7 — CA-level extended rights. An ACE granting CONTROL_ACCESS with
# either GUID lets the trustee become a CA admin (ManageCA) or approve
# their own pending certs (ManageCertificates).
EXT_RIGHT_MANAGE_CA           = "7fb2d3d0-f86c-49aa-94e0-dbf3acec92be"
EXT_RIGHT_MANAGE_CERTIFICATES = "0e10c969-78fb-11d2-90d4-00c04f79dc55"


# Write rights that = ESC4 (template) / ESC5 (container) takeover.
# Listed in severity-priority order so first match wins.
DANGEROUS_WRITE_RIGHTS: list[tuple[str, int, str, int]] = [
    # (label,           mask,                     severity,   priority)
    ("GenericAll",      ADS_RIGHT_GENERIC_ALL,    "CRITICAL", 95),
    ("WriteDACL",       ADS_RIGHT_WRITE_DAC,      "CRITICAL", 93),
    ("WriteOwner",      ADS_RIGHT_WRITE_OWNER,    "CRITICAL", 92),
    ("GenericWrite",    ADS_RIGHT_GENERIC_WRITE,  "HIGH",     85),
]


def _classify_write_ace(ace) -> dict | None:
    """Return {label, severity, priority} if the ACE grants any of the
    dangerous write rights, None otherwise. First match wins."""
    for label, mask, severity, priority in DANGEROUS_WRITE_RIGHTS:
        if ace.has_right(mask):
            return {"label": label, "severity": severity, "priority": priority}
    return None


def _grants_ca_extended_right(ace, guid: str) -> bool:
    """ACE grants the named CA-level extended right. Mirrors
    AceMatch.has_extended_right but inlined to keep this module
    self-contained."""
    if ace.has_right(ADS_RIGHT_GENERIC_ALL):
        return True
    if not ace.has_right(ADS_RIGHT_DS_CONTROL_ACCESS):
        return False
    if ace.object_type_guid is None:
        return True   # CONTROL_ACCESS without GUID = all extended rights
    return ace.object_type_guid.lower() == guid.lower()


@register
class AdcsExtended(Module):
    name        = "AD CS Extended (ESC4/5/7/9/13/15)"
    flag        = "adcs-extended"
    description = "Detect ESC4 (template ACL), ESC5 (PKI container ACL), ESC7 (CA officer rights), ESC9 (no-security-ext), ESC13 (OIDToGroupLink), ESC15 (EKUwu/CVE-2024-49019)"
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

        # Collect every non-default write-trustee SID across all
        # templates / containers / CAs so the resolve_sids call below
        # batches name lookups instead of hitting the DC per-finding.
        all_write_sids: set[str] = set()

        for tpl in templates:
            tpl_name = attr(tpl, "cn") or attr(tpl, "displayName") or "<unknown>"
            tpl_dn   = attr(tpl, "distinguishedName") or ""
            schema   = _to_int(attr(tpl, "msPKI-Template-Schema-Version"))
            enroll_flag = _to_int(attr(tpl, "msPKI-Enrollment-Flag")) or 0
            policy_oids = [str(p) for p in attrs(tpl, "msPKI-Certificate-Policy")]

            # Walk the template's DACL once for both enrolment-rights
            # collection (ESC9/13/15 inputs) AND the ESC4 write-ACL audit.
            sd = parse_sd(attr(tpl, "nTSecurityDescriptor"))
            enrolment_trustees: set[str] = set()
            esc4_writers:    list[dict] = []
            if sd is not None:
                for ace in walk_aces(sd, object_dn=tpl_dn):
                    if self._grants_enrolment(ace):
                        enrolment_trustees.add(ace.trustee_sid)
                    write_class = _classify_write_ace(ace)
                    if write_class and not is_well_known_privileged(ace.trustee_sid):
                        esc4_writers.append({
                            "trustee_sid": ace.trustee_sid,
                            **write_class,
                        })
                        all_write_sids.add(ace.trustee_sid)

            public_enrolable = bool(enrolment_trustees & public_sids)

            row = {
                "name":             tpl_name,
                "distinguishedName": tpl_dn,
                "schema_version":   schema,
                "enroll_flag":      enroll_flag,
                "policy_oids":      policy_oids,
                "enrolment_trustees": sorted(enrolment_trustees),
                "public_enrolable": public_enrolable,
                "esc4":             bool(esc4_writers),
                "esc4_writers":     esc4_writers,
                "esc9":             False,
                "esc13":            False,
                "esc15":            False,
                "esc13_groups":     [],
            }

            # ── ESC4 ───────────────────────────────────────────────
            for writer in esc4_writers:
                findings.append(Finding(
                    target=tpl_name,
                    attack=f"AD CS ESC4: {writer['label']} on template",
                    severity=writer["severity"],
                    priority=writer["priority"],
                    reason=(
                        f"Non-default principal {writer['trustee_sid']} "
                        f"holds {writer['label']} on template '{tpl_name}'. "
                        f"They can rewrite the template DACL or modify "
                        f"enrol-by-name flags → convert any template into "
                        f"an ESC1 (subject-supplied SAN) backdoor."
                    ),
                    next_step=(
                        f"# As the writer principal, modify the template:\n"
                        f"certipy template -u <writer>@{ctx.domain} -p <pass> "
                        f"-template '{tpl_name}' -save-old\n"
                        f"# Or via dacledit:\n"
                        f"dacledit.py -action write -rights FullControl "
                        f"-principal <writer> -target-dn '{tpl_dn}' "
                        f"{ctx.domain}/<op>:<pass>"
                    ),
                    category="cve",
                    mitre="T1649",
                    data={
                        "template_dn":   tpl_dn,
                        "writer_sid":    writer["trustee_sid"],
                        "right":         writer["label"],
                        "domain_sid":    ctx.domain_sid,
                    },
                ))

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

        # ── ESC5 — PKI container DACL audit ────────────────────
        esc5_rows, esc5_findings = self._audit_pki_containers(ctx, all_write_sids)
        findings.extend(esc5_findings)

        # ── ESC7 — CA officer rights ───────────────────────────
        ca_rows, esc7_findings, esc7_writer_sids = self._audit_ca_officer_rights(ctx)
        findings.extend(esc7_findings)
        all_write_sids.update(esc7_writer_sids)

        # Resolve every collected trustee SID (enrolment + ESC4 + ESC5
        # + ESC7) in one batched LDAP query so the per-finding name
        # rendering doesn't fan out.
        all_trustees = {sid for row in per_template for sid in row["enrolment_trustees"]}
        all_trustees.update(all_write_sids)
        names = resolve_sids(ctx.ldap, all_trustees, ctx.base_dn) if all_trustees else {}
        for row in per_template:
            row["enrolment_trustee_names"] = [
                names.get(sid, {}).get("sAMAccountName") or sid
                for sid in row["enrolment_trustees"]
            ]
            row["esc4_writer_names"] = [
                names.get(w["trustee_sid"], {}).get("sAMAccountName") or w["trustee_sid"]
                for w in row["esc4_writers"]
            ]
        # Patch the reason / data of every finding that referenced a
        # SID — the friendly name is more useful for operators reading
        # the JSON / terminal output.
        for f in findings:
            wsid = (f.data or {}).get("writer_sid")
            if wsid:
                friendly = names.get(wsid, {}).get("sAMAccountName") or wsid
                f.data["writer_sam"] = friendly
                f.reason = f.reason.replace(wsid, friendly)

        summary = {
            "templates_total":   len(per_template),
            "esc4_count":        sum(1 for r in per_template if r["esc4"]),
            "esc5_count":        sum(1 for r in esc5_rows if r["esc5"]),
            "esc7_count":        sum(1 for r in ca_rows  if r["esc7"]),
            "esc9_count":        sum(1 for r in per_template if r["esc9"]),
            "esc13_count":       sum(1 for r in per_template if r["esc13"]),
            "esc15_count":       sum(1 for r in per_template if r["esc15"]),
        }

        return ScanResult(
            raw={
                "applicable":     True,
                "templates":      per_template,
                "pki_containers": esc5_rows,
                "ca_objects":     ca_rows,
                "oid_links":      oid_links,
                "summary":        summary,
            },
            findings=findings,
        )

    # ------------------------------------------------------------------ #
    #  ESC5 — PKI container ACL audit                                    #
    # ------------------------------------------------------------------ #

    def _audit_pki_containers(
        self, ctx: ScanContext, all_write_sids: set[str]
    ) -> tuple[list[dict], list[Finding]]:
        """Walk DACLs on the three PKI container objects:
          CN=Public Key Services,CN=Services,CN=Configuration
          CN=Certificate Templates,CN=Public Key Services,...
          CN=Enrollment Services,CN=Public Key Services,...

        Anyone with WriteDACL/WriteOwner/GenericAll/GenericWrite on
        these can re-DACL every template / register a rogue CA / etc.
        """
        if not hasattr(ctx.ldap, "query_config"):
            return [], []

        container_dns = [
            f"CN=Public Key Services,CN=Services,CN=Configuration,{ctx.base_dn}",
            f"CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,{ctx.base_dn}",
            f"CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,{ctx.base_dn}",
        ]

        rows:     list[dict] = []
        findings: list[Finding] = []

        for cdn in container_dns:
            entries = ctx.ldap.query(
                search_filter="(objectClass=*)",
                attributes=["distinguishedName", "nTSecurityDescriptor"],
                search_base=cdn,
                controls=sd_control(),
            )
            if not entries:
                continue
            e = entries[0]
            sd = parse_sd(attr(e, "nTSecurityDescriptor"))
            writers: list[dict] = []
            if sd is not None:
                for ace in walk_aces(sd, object_dn=cdn):
                    cls = _classify_write_ace(ace)
                    if cls and not is_well_known_privileged(ace.trustee_sid):
                        writers.append({"trustee_sid": ace.trustee_sid, **cls})
                        all_write_sids.add(ace.trustee_sid)
            rows.append({
                "container_dn": cdn,
                "esc5":         bool(writers),
                "writers":      writers,
            })
            container_label = cdn.split(",")[0].replace("CN=", "")
            for w in writers:
                findings.append(Finding(
                    target=container_label,
                    attack=f"AD CS ESC5: {w['label']} on PKI container",
                    severity=w["severity"],
                    priority=w["priority"],
                    reason=(
                        f"Non-default principal {w['trustee_sid']} holds "
                        f"{w['label']} on the PKI container '{container_label}'. "
                        f"This grants effective control over every certificate "
                        f"template / CA / enrolment service registered there — "
                        f"convert into ESC4 against any template, or register a "
                        f"rogue Enrollment Service entry."
                    ),
                    next_step=(
                        f"# Confirm with certipy / dacledit:\n"
                        f"dacledit.py -action read -target-dn '{cdn}' "
                        f"{ctx.domain}/<op>:<pass>\n"
                        f"# As the writer, re-DACL a template:\n"
                        f"certipy template -u <writer>@{ctx.domain} -p <pass> "
                        f"-template <name> -save-old"
                    ),
                    category="cve",
                    mitre="T1649",
                    data={
                        "container_dn": cdn,
                        "writer_sid":   w["trustee_sid"],
                        "right":        w["label"],
                        "domain_sid":   ctx.domain_sid,
                    },
                ))
        return rows, findings

    # ------------------------------------------------------------------ #
    #  ESC7 — CA officer rights                                          #
    # ------------------------------------------------------------------ #

    def _audit_ca_officer_rights(
        self, ctx: ScanContext
    ) -> tuple[list[dict], list[Finding], set[str]]:
        """Walk DACLs on every pKIEnrollmentService (CA) object. Look
        for non-admin principals with ManageCA or ManageCertificates
        extended rights — those are CA officers who can take over the
        CA or approve their own pending certs."""
        if not hasattr(ctx.ldap, "query_config"):
            return [], [], set()

        cas = ctx.ldap.query_config(
            search_filter="(objectClass=pKIEnrollmentService)",
            attributes=["cn", "displayName", "distinguishedName",
                        "nTSecurityDescriptor"],
        )

        rows:     list[dict] = []
        findings: list[Finding] = []
        writer_sids: set[str] = set()

        for ca in cas:
            ca_name = attr(ca, "cn") or attr(ca, "displayName") or "<CA>"
            ca_dn   = attr(ca, "distinguishedName") or ""
            sd      = parse_sd(attr(ca, "nTSecurityDescriptor"))
            # Coalesce by trustee SID — one principal can hold ManageCA
            # and ManageCertificates as two separate ACEs and we need to
            # see them together to escalate to CRITICAL.
            officers_by_sid: dict[str, set[str]] = {}
            if sd is not None:
                for ace in walk_aces(sd, object_dn=ca_dn):
                    if is_well_known_privileged(ace.trustee_sid):
                        continue
                    if _grants_ca_extended_right(ace, EXT_RIGHT_MANAGE_CA):
                        officers_by_sid.setdefault(ace.trustee_sid, set()).add("ManageCA")
                    if _grants_ca_extended_right(ace, EXT_RIGHT_MANAGE_CERTIFICATES):
                        officers_by_sid.setdefault(ace.trustee_sid, set()).add("ManageCertificates")

            officers: list[dict] = []
            for sid, rights_set in officers_by_sid.items():
                # Stable order: ManageCA before ManageCertificates.
                ordered = [r for r in ("ManageCA", "ManageCertificates") if r in rights_set]
                officers.append({"trustee_sid": sid, "rights": ordered})
                writer_sids.add(sid)

            rows.append({
                "ca_name":  ca_name,
                "ca_dn":    ca_dn,
                "esc7":     bool(officers),
                "officers": officers,
            })

            for off in officers:
                # Both rights together = full CA admin (the worst case).
                # Either alone is still an ESC7 path (officer can issue
                # certs to themselves / approve pending → ESC4-style).
                both = len(off["rights"]) == 2
                severity = "CRITICAL" if both else "HIGH"
                priority = 94 if both else 85
                findings.append(Finding(
                    target=ca_name,
                    attack=f"AD CS ESC7: CA officer rights ({', '.join(off['rights'])})",
                    severity=severity,
                    priority=priority,
                    reason=(
                        f"Non-default principal {off['trustee_sid']} holds "
                        f"{', '.join(off['rights'])} on CA '{ca_name}'. "
                        + (
                            "Combined rights = full CA administrator — can "
                            "issue arbitrary certs, change templates, take "
                            "ownership of the CA."
                            if both else
                            "ManageCA alone permits modifying CA configuration "
                            "and adding officers — escalate by granting yourself "
                            "ManageCertificates, then issue arbitrary certs."
                            if "ManageCA" in off["rights"] else
                            "ManageCertificates alone permits issuing certs "
                            "for any pending request and re-issuing rejected "
                            "ones — convert into ESC4 against any template."
                        )
                    ),
                    next_step=(
                        f"# Issue a cert for any UPN as CA officer:\n"
                        f"certipy ca -u <officer>@{ctx.domain} -p <pass> "
                        f"-ca '{ca_name}' -issue-cert <reqid> "
                        f"-dc-ip {ctx.dc_ip}\n"
                        f"# Or take over the CA:\n"
                        f"certipy ca -u <officer>@{ctx.domain} -p <pass> "
                        f"-ca '{ca_name}' -add-officer <officer> "
                        f"-dc-ip {ctx.dc_ip}"
                    ),
                    category="cve",
                    mitre="T1649",
                    data={
                        "ca_name":     ca_name,
                        "ca_dn":       ca_dn,
                        "writer_sid":  off["trustee_sid"],
                        "rights":      off["rights"],
                        "domain_sid":  ctx.domain_sid,
                    },
                ))
        return rows, findings, writer_sids

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

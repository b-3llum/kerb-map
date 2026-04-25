"""
Shadow Credentials enumeration (msDS-KeyCredentialLink).

Two complementary checks:

  1. **Inventory.** Every account whose ``msDS-KeyCredentialLink`` is
     populated. On a clean enterprise this is Windows Hello for Business
     devices and *nothing else*; a populated value on a service account,
     a Tier-0 user, or a computer that has no WHfB device is a high-fidelity
     IOC for prior Whisker abuse (or, occasionally, legacy WHfB cleanup
     debris worth removing).

  2. **ACL audit.** Principals with WriteProperty on
     ``msDS-KeyCredentialLink`` (schema GUID
     5b47d60f-6090-40b2-9f37-2a4de88f3063), GenericAll, or GenericWrite
     on accounts they don't own. Anyone who can write that attribute can
     attach a key, request a PKINIT TGT, and walk in as the target.

Each check runs once across the directory rather than once per account
so a domain with 50k users still produces a single LDAP round-trip per
check (paging takes care of >MaxPageSize).

Reference:
- Whisker (Elad Shamir): https://github.com/eladshamir/Whisker
- SpecterOps overview: https://posts.specterops.io/shadow-credentials-...
- Brief §4.1
"""

from __future__ import annotations

from kerb_map.acl import (
    ATTR_KEY_CREDENTIAL_LINK,
    is_well_known_privileged,
    parse_sd,
    resolve_sids,
    sd_control,
    walk_aces,
)
from kerb_map.ldap_helpers import attr, attrs, cn_from_dn, uac_has
from kerb_map.plugin import Finding, Module, ScanContext, ScanResult, register

# Privileged group RIDs whose membership escalates the severity of an
# inventory finding. We don't recurse memberOf chains here — that's the
# Hygiene Auditor's job — but flat membership in any of these is enough
# to call the finding CRITICAL on its own.
PRIVILEGED_RIDS = (512, 516, 518, 519, 520)


@register
class ShadowCredentials(Module):
    name = "Shadow Credentials"
    flag = "shadow-creds"
    description = "Inventory msDS-KeyCredentialLink + audit who can write it"
    category = "attack-path"
    in_default_run = True

    def scan(self, ctx: ScanContext) -> ScanResult:
        inventory = self._inventory_populated_keys(ctx)
        acl_findings, acl_raw = self._audit_write_access(ctx)

        findings: list[Finding] = []
        for acct in inventory:
            findings.append(self._finding_for_inventory_entry(ctx, acct))
        findings.extend(acl_findings)

        return ScanResult(
            raw={
                "populated_accounts": inventory,
                "write_access":       acl_raw,
                "summary": {
                    "with_keys":          len(inventory),
                    "privileged_with_keys": sum(1 for a in inventory if a["privileged"]),
                    "non_default_writers":  len(acl_findings),
                },
            },
            findings=findings,
        )

    # ------------------------------------------------------------------ #
    #  1. Inventory: who has populated msDS-KeyCredentialLink            #
    # ------------------------------------------------------------------ #

    def _inventory_populated_keys(self, ctx: ScanContext) -> list[dict]:
        entries = ctx.ldap.query(
            search_filter="(msDS-KeyCredentialLink=*)",
            attributes=[
                "sAMAccountName", "distinguishedName", "objectClass",
                "userAccountControl", "memberOf", "msDS-KeyCredentialLink",
                "primaryGroupID", "objectSid", "operatingSystem",
            ],
        )
        out: list[dict] = []
        for e in entries:
            sam = attr(e, "sAMAccountName") or cn_from_dn(attr(e, "distinguishedName") or "")
            klinks = attrs(e, "msDS-KeyCredentialLink")
            object_classes = attrs(e, "objectClass")
            is_computer = "computer" in [str(c).lower() for c in object_classes]
            is_user = "user" in [str(c).lower() for c in object_classes] and not is_computer
            uac = attr(e, "userAccountControl")

            primary_rid = attr(e, "primaryGroupID")
            primary_priv = primary_rid in PRIVILEGED_RIDS if isinstance(primary_rid, int) else False

            mof = [str(g).lower() for g in attrs(e, "memberOf")]
            member_priv = any(
                f"cn={g}" in dn for dn in mof
                for g in ("domain admins", "enterprise admins", "schema admins",
                          "administrators", "account operators", "backup operators")
            )
            disabled = uac_has(uac, "ACCOUNTDISABLE")
            os_name = attr(e, "operatingSystem")

            out.append({
                "sAMAccountName":    sam,
                "distinguishedName": attr(e, "distinguishedName"),
                "is_computer":       is_computer,
                "is_user":           is_user,
                "key_count":         len(klinks),
                "disabled":          disabled,
                "operating_system":  os_name,
                "primary_priv":      primary_priv,
                "member_priv":       member_priv,
                "privileged":        primary_priv or member_priv,
            })
        return out

    def _finding_for_inventory_entry(self, ctx: ScanContext, acct: dict) -> Finding:
        sam = acct["sAMAccountName"]
        if acct["privileged"]:
            sev, prio = "CRITICAL", 90
            reason = (
                f"{sam} is in a privileged group AND has a populated "
                f"msDS-KeyCredentialLink — high-fidelity Whisker IOC or "
                f"a Tier-0 account using WHfB (which it shouldn't be)."
            )
        elif acct["is_computer"] and (acct["operating_system"] or "").startswith("Windows 10"):
            # WHfB on workstations is normal. Down-rank to INFO so the
            # operator can still see the inventory but it's not a finding.
            sev, prio = "INFO", 10
            reason = f"{sam} is a workstation with WHfB-style key trust (likely benign)."
        else:
            sev, prio = "HIGH", 70
            reason = (
                f"{sam} has {acct['key_count']} entry/entries in "
                f"msDS-KeyCredentialLink. Check whether this account is "
                f"meant to use WHfB; if not, this is a backdoor."
            )

        return Finding(
            target=sam,
            attack="Shadow Credentials (inventory)",
            severity=sev,
            priority=prio,
            reason=reason,
            next_step=(
                f"# Inspect the key entries with pyWhisker:\n"
                f"pywhisker.py -d {ctx.domain} -u <op_user> -p <pass> "
                f"--target {sam} --action list"
            ),
            category="attack-path",
            mitre="T1556.007",  # Modify Authentication Process: Hybrid Identity
            data={
                "key_count":   acct["key_count"],
                "privileged":  acct["privileged"],
                "is_computer": acct["is_computer"],
                "domain_sid":  ctx.domain_sid,
            },
        )

    # ------------------------------------------------------------------ #
    #  2. ACL audit: who can write msDS-KeyCredentialLink                #
    # ------------------------------------------------------------------ #

    def _audit_write_access(self, ctx: ScanContext) -> tuple[list[Finding], list[dict]]:
        """For each privileged account, walk its DACL and look for
        WriteProperty(msDS-KeyCredentialLink) / GenericWrite / GenericAll
        granted to a non-well-known principal.

        We restrict the audit to privileged accounts only (adminCount=1
        + Domain Admins / Enterprise Admins members) because a full-domain
        ACL audit is expensive and the high-value attack target here is
        Tier-0. Brief §4.6 covers the broader audit; this is the focused
        slice that matters most.
        """
        targets = ctx.ldap.query(
            search_filter="(&(objectClass=user)(adminCount=1)"
                          "(!(userAccountControl:1.2.840.113556.1.4.803:=2)))",
            attributes=["sAMAccountName", "distinguishedName", "objectSid",
                        "nTSecurityDescriptor"],
            controls=sd_control(),
        )

        findings: list[Finding] = []
        raw: list[dict] = []
        # Collect every non-well-known principal we see writing to a
        # KeyCredentialLink so we can resolve their names in one batch.
        deferred: list[tuple[dict, str]] = []  # (target_info, writer_sid)

        for e in targets:
            target_sam = attr(e, "sAMAccountName")
            target_dn  = attr(e, "distinguishedName")
            sd = parse_sd(attr(e, "nTSecurityDescriptor"))
            if sd is None:
                continue
            for ace in walk_aces(sd, object_dn=target_dn):
                if not ace.has_write_property(ATTR_KEY_CREDENTIAL_LINK):
                    continue
                if is_well_known_privileged(ace.trustee_sid):
                    continue
                deferred.append(({
                    "target_sam": target_sam,
                    "target_dn":  target_dn,
                }, ace.trustee_sid))

        if not deferred:
            return [], []

        sid_set = {s for _, s in deferred}
        names = resolve_sids(ctx.ldap, sid_set, ctx.base_dn)

        for target_info, writer_sid in deferred:
            writer = names.get(writer_sid, {})
            writer_sam = writer.get("sAMAccountName") or writer_sid
            raw.append({
                "target":        target_info["target_sam"],
                "target_dn":     target_info["target_dn"],
                "writer_sid":    writer_sid,
                "writer_sam":    writer_sam,
            })
            findings.append(Finding(
                target=target_info["target_sam"],
                attack="Shadow Credentials (write access)",
                severity="CRITICAL",
                priority=92,
                reason=(
                    f"{writer_sam} can write msDS-KeyCredentialLink on "
                    f"{target_info['target_sam']} (privileged account) — "
                    f"compromise of {writer_sam} = compromise of "
                    f"{target_info['target_sam']} via PKINIT."
                ),
                next_step=(
                    f"# As {writer_sam}, attach a key to {target_info['target_sam']}\n"
                    f"pywhisker.py -d {ctx.domain} -u {writer_sam} -p <pass> "
                    f"--target {target_info['target_sam']} --action add\n"
                    f"# Then PKINIT to get a TGT and the NT hash:\n"
                    f"gettgtpkinit.py -cert-pfx {target_info['target_sam']}.pfx "
                    f"-pfx-pass <pfx_pass> {ctx.domain}/{target_info['target_sam']} "
                    f"{target_info['target_sam']}.ccache"
                ),
                category="attack-path",
                mitre="T1556.007",
                data={
                    "writer_sid": writer_sid,
                    "writer_sam": writer_sam,
                    "target_dn":  target_info["target_dn"],
                    "domain_sid": ctx.domain_sid,
                },
            ))

        return findings, raw

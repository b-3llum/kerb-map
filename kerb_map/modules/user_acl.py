"""
User ACL audit — lateral-movement enumeration (field gap).

Field finding from a real-domain test (shibuya.jujutsu.local):
``choso`` had GenericAll on ``itadori`` (per the SQL-injection-leaked
notes, confirmed in the actual DACL with full-control mask 0xf01ff).
Neither account is Tier-0, so the existing :class:`Tier0AclAudit`
module — which only walks DACLs on AdminSDHolder, DA/EA/SA/SchemaA,
adminCount=1 users, and BUILTIN privileged groups — silently missed it.

That's the BloodHound-style "AddMember / GenericAll → User" attack
edge, and it's the bread-and-butter of lateral-movement on real
estates. This module fills the gap by widening the target set to
**every enabled non-Tier-0 user account**.

Severity is one tier below Tier-0 (HIGH instead of CRITICAL,
priority cap 75 instead of 95) — compromising user A and pivoting
to user B is meaningful but not domain-takeover. The Scorer's sort
keeps the Tier-0 findings on top.

Output is capped (default 100 findings) so this doesn't flood the
priority table on estates with thousands of users. Operators can
read raw output for the full list.

What this catches that existing modules don't
---------------------------------------------
* GenericAll / WriteDACL / WriteOwner / GenericWrite from non-default
  principals on regular user accounts (the "lateral edge" gap).
* WriteProperty on dangerous attributes — covered piecemeal:
    - msDS-KeyCredentialLink → ShadowCredentials module already
      flags Tier-0 targets; non-Tier-0 lands here.
    - servicePrincipalName → targeted Kerberoast (TargetedKerberoast)
    - userAccountControl → could enable DONT_REQUIRE_PREAUTH
"""

from __future__ import annotations

from kerb_map.acl import (
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
from kerb_map.ldap_helpers import attr, sid_to_str
from kerb_map.plugin import Finding, Module, ScanContext, ScanResult, register

# servicePrincipalName attribute schema GUID — used by targeted-Kerberoast
# pivots when an attacker can write SPN onto a victim account.
ATTR_SPN = "f3a64788-5306-11d1-a9c5-0000f80367c1"

# BUILTIN groups that hold dangerous rights on every regular user *by
# AD's default install*. Tier0AclAudit already flags membership of
# these groups as a tier-0 finding; surfacing every user they can
# rewrite would flood the priority table with one finding per user.
DEFAULT_PRIVILEGED_BUILTIN_SIDS = {
    "S-1-5-32-548",   # Account Operators — full ctrl on non-protected users by design
    "S-1-5-32-549",   # Server Operators
    "S-1-5-32-550",   # Print Operators
    "S-1-5-32-551",   # Backup Operators
}

# Per-right severity bucketing for *non-Tier-0 user* targets. Lower than
# Tier-0 (HIGH not CRITICAL) since pwning a regular user is a lateral
# pivot, not domain takeover.
USER_RIGHT_SEVERITY: list[tuple[str, int, str, int]] = [
    # (label,            mask,                              severity,  priority)
    ("GenericAll",       ADS_RIGHT_GENERIC_ALL,             "HIGH",    75),
    ("WriteDACL",        ADS_RIGHT_WRITE_DAC,               "HIGH",    74),
    ("WriteOwner",       ADS_RIGHT_WRITE_OWNER,             "HIGH",    73),
    ("GenericWrite",     ADS_RIGHT_GENERIC_WRITE,           "MEDIUM",  60),
]

# Cap output so a 5k-user estate with permissive ACLs doesn't bury the
# Tier-0 / CVE findings that are higher value.
DEFAULT_MAX_FINDINGS = 100


@register
class UserAclAudit(Module):
    name        = "User ACL audit (lateral movement)"
    flag        = "user-acl"
    description = "Enumerate non-default writers on every enabled non-Tier-0 user (lateral edges)"
    category    = "attack-path"
    in_default_run = True

    def scan(self, ctx: ScanContext) -> ScanResult:
        users = self._enumerate_users(ctx)
        if not users:
            return ScanResult(raw={
                "applicable": False,
                "reason":     "no enabled non-Tier-0 users enumerated",
            })

        deferred:    list[tuple[dict, dict]] = []   # (target, ace_match)
        writer_sids: set[str] = set()

        for tgt in users:
            sd = parse_sd(tgt.get("nTSecurityDescriptor"))
            if sd is None:
                continue
            for ace in walk_aces(sd, object_dn=tgt["dn"]):
                # Skip self-ACL — every user has a Self ACE on themselves
                # for password change etc., not interesting here.
                if ace.trustee_sid == tgt.get("sid"):
                    continue
                if is_well_known_privileged(ace.trustee_sid):
                    continue
                if ace.trustee_sid in DEFAULT_PRIVILEGED_BUILTIN_SIDS:
                    continue
                classification = _classify_user_ace(ace)
                if classification is None:
                    continue
                deferred.append((tgt, {"ace": ace, "class": classification}))
                writer_sids.add(ace.trustee_sid)

        if not deferred:
            return ScanResult(raw={
                "applicable": True,
                "audited":    len(users),
                "summary":    {"audited": len(users), "findings": 0},
            })

        names = resolve_sids(ctx.ldap, writer_sids, ctx.base_dn)

        findings:    list[Finding] = []
        raw_entries: list[dict]    = []
        truncated = False

        for tgt, match in deferred:
            ace        = match["ace"]
            classified = match["class"]
            wsid       = ace.trustee_sid
            winfo      = names.get(wsid, {})
            wsam       = winfo.get("sAMAccountName") or wsid
            wdn        = winfo.get("distinguishedName") or ""

            entry = {
                "target":     tgt["sam"],
                "target_dn":  tgt["dn"],
                "target_sid": tgt.get("sid"),
                "writer_sid": wsid,
                "writer_sam": wsam,
                "right":      classified["label"],
            }
            raw_entries.append(entry)

            if len(findings) >= DEFAULT_MAX_FINDINGS:
                truncated = True
                continue

            findings.append(Finding(
                target=tgt["sam"],
                attack=f"User ACL: {classified['label']} → {tgt['sam']}",
                severity=classified["severity"],
                priority=classified["priority"],
                reason=(
                    f"{wsam} holds {classified['label']} on {tgt['sam']} "
                    f"(non-Tier-0 user, non-default writer). Lateral pivot: "
                    f"compromise of {wsam} = takeover of {tgt['sam']} → "
                    f"any access {tgt['sam']} has."
                ),
                next_step=_next_step(classified["label"], wsam, tgt, ctx),
                category="attack-path",
                mitre="T1078.002",
                data={
                    "writer_sid":  wsid,
                    "writer_sam":  wsam,
                    "writer_dn":   wdn,
                    "target_dn":   tgt["dn"],
                    "target_sid":  tgt.get("sid"),
                    "target_sam":  tgt["sam"],
                    "right":       classified["label"],
                    "domain_sid":  ctx.domain_sid,
                },
            ))

        return ScanResult(
            raw={
                "applicable": True,
                "audited":    len(users),
                "entries":    raw_entries,
                "summary": {
                    "audited":          len(users),
                    "findings":         len(findings),
                    "raw_entry_count":  len(raw_entries),
                    "truncated":        truncated,
                },
            },
            findings=findings,
        )

    # ------------------------------------------------------------------ #
    #  Targets — enabled, non-Tier-0 users                                #
    # ------------------------------------------------------------------ #

    def _enumerate_users(self, ctx: ScanContext) -> list[dict]:
        """Every enabled user account that's NOT adminCount=1 (those are
        owned by Tier0AclAudit) and NOT a computer object. We use the
        userAccountControl bitwise NOT-DISABLED filter (UAC bit 0x2)."""
        entries = ctx.ldap.query(
            search_filter=(
                "(&(objectClass=user)"
                "(!(objectClass=computer))"
                "(!(adminCount=1))"
                "(!(userAccountControl:1.2.840.113556.1.4.803:=2))"
                ")"
            ),
            attributes=["sAMAccountName", "distinguishedName", "objectSid",
                        "nTSecurityDescriptor"],
            controls=sd_control(),
        )
        out: list[dict] = []
        for e in entries:
            sid_str = sid_to_str(attr(e, "objectSid"))
            out.append({
                "sam":   attr(e, "sAMAccountName") or "?",
                "dn":    attr(e, "distinguishedName") or "",
                "sid":   sid_str,
                "nTSecurityDescriptor": attr(e, "nTSecurityDescriptor"),
            })
        return out


# ────────────────────────────────────────────────────────────────────── #
#  ACE classification — same model as tier0_acl, lower severity          #
# ────────────────────────────────────────────────────────────────────── #


def _classify_user_ace(ace) -> dict | None:
    """Map an ACE on a regular-user account to {label, severity, priority}
    if it grants a dangerous-from-pivot right. Returns None otherwise.

    Field-relevant detail: real DACLs often carry an *expanded* full-
    control mask (0xf01ff) instead of the literal GENERIC_ALL bit
    (0x10000000). The expanded form includes WRITE_DAC + WRITE_OWNER,
    so the WRITE_DAC check below catches it — even though the ACE
    doesn't have the GENERIC_ALL flag set."""
    for label, mask, severity, priority in USER_RIGHT_SEVERITY:
        if ace.has_right(mask):
            return {"label": label, "severity": severity, "priority": priority}

    # WriteProperty on servicePrincipalName — targeted Kerberoast.
    if ace.has_write_property(ATTR_SPN):
        return {"label": "WriteProperty(SPN)", "severity": "MEDIUM", "priority": 65}

    return None


def _next_step(right: str, wsam: str, tgt: dict, ctx: ScanContext) -> str:
    """Right-specific exploitation recipe. Targets are always users,
    never groups, so the recipes diverge from tier0_acl's."""
    domain    = ctx.domain
    target    = tgt["sam"]
    target_dn = tgt["dn"]

    if right in ("GenericAll", "WriteDACL", "WriteOwner"):
        return (
            f"# As {wsam}, with {right} on {target}:\n"
            f"# Reset their password (or add Shadow Credentials):\n"
            f"net rpc password '{target}' '<new_pass>' "
            f"-U '{domain}\\{wsam}%<pass>' -S {ctx.dc_ip}\n"
            f"# OR Shadow Credentials (cleaner, no audit trail):\n"
            f"pywhisker.py -d {domain} -u {wsam} -p <pass> "
            f"--target {target} --action add"
        )

    if right == "GenericWrite":
        return (
            f"# As {wsam}, with GenericWrite on {target}:\n"
            f"# Set a fake SPN on {target} for targeted Kerberoast:\n"
            f"targetedKerberoast.py -v -d {domain} -u {wsam} -p <pass>"
        )

    if right == "WriteProperty(SPN)":
        return (
            f"# As {wsam}, write SPN onto {target}, then Kerberoast:\n"
            f"# 1. Set fake SPN:\n"
            f"#    Set-DomainObject -Identity {target} "
            f"-Set @{{serviceprincipalname='krbtgt/<fake>'}}\n"
            f"# 2. Kerberoast:\n"
            f"GetUserSPNs.py {domain}/{wsam}:<pass> -dc-ip {ctx.dc_ip} "
            f"-request-user {target}"
        )

    return f"# Investigate {right} on {target} ({target_dn}) via BloodHound."

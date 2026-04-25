"""
Pre-Windows 2000 Compatible Access audit.

The local-domain group ``Pre-Windows 2000 Compatible Access``
(``S-1-5-32-554``) was created so legacy NT4 trust relationships could
read parts of AD. Microsoft *still* pre-populates fresh installs of
Server 2022 / 2025 with ``Authenticated Users`` already a member —
which is enough to make:

  * ``net user /domain`` (or any RID-cycling trick) work for any
    authenticated user, including coerced auth from a phished workstation
  * Anonymous reads possible if ``dsHeuristics`` flips bit 7

This module surfaces three kinds of findings, ordered loud → quiet:

  1. **Anonymous Logon** (``S-1-5-7``) inside the group → CRITICAL.
     Anyone on the wire can dump the directory.
  2. **Authenticated Users** (``S-1-5-11``) or **Everyone**
     (``S-1-1-0``) inside the group → HIGH. The Microsoft-default
     state on a clean install; leaving it that way after migrating
     off legacy trusts is the actual misconfiguration.
  3. **Any non-default principal** in the group → MEDIUM. A specific
     account or group added later — the operator probably did it
     intentionally, but worth surfacing.

Also reads ``dsHeuristics`` (the LDAP server's behaviour string at
``CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,...``).
Bit 7 == ``2`` permits anonymous LDAP binds — flagged as CRITICAL when
combined with Authenticated/Everyone in the Pre-Win2k group.

Reference:
- Semperis: Security Risks of Pre-Windows 2000 Compatibility on Windows 2022
- MS-ADTS §3.1.1.4.5 (the dsHeuristics string)
"""

from __future__ import annotations

from kerb_map.ldap_helpers import attr, attrs, sid_to_str
from kerb_map.plugin import Finding, Module, ScanContext, ScanResult, register

# Well-known SIDs we look for inside the Pre-Win2k group.
SID_ANONYMOUS_LOGON     = "S-1-5-7"
SID_EVERYONE            = "S-1-1-0"
SID_AUTHENTICATED_USERS = "S-1-5-11"

DEFAULT_RISKY_SIDS = {SID_ANONYMOUS_LOGON, SID_EVERYONE, SID_AUTHENTICATED_USERS}


# Friendly names for raw output.
SID_NAMES = {
    SID_ANONYMOUS_LOGON:     "Anonymous Logon",
    SID_EVERYONE:            "Everyone",
    SID_AUTHENTICATED_USERS: "Authenticated Users",
}


@register
class PreWin2kAccess(Module):
    name = "Pre-Windows 2000 Compatible Access"
    flag = "prewin2k"
    description = "Detect Authenticated/Anonymous in BUILTIN\\Pre-Windows 2000 Compatible Access"
    category = "hygiene"
    in_default_run = True

    def scan(self, ctx: ScanContext) -> ScanResult:
        # The Pre-Win2k group lives in CN=Builtin under the domain root.
        # objectSid is constant (S-1-5-32-554) but we filter by SID
        # rather than DN to be robust against renamed Builtin OUs.
        prewin2k_entries = ctx.ldap.query(
            search_filter="(&(objectClass=group)(cn=Pre-Windows 2000 Compatible Access))",
            attributes=["distinguishedName", "objectSid", "member"],
            search_base=f"CN=Builtin,{ctx.base_dn}",
        )

        if not prewin2k_entries:
            # Some operators rename or remove the Builtin Pre-Win2k group;
            # try a domain-wide fallback by SID.
            prewin2k_entries = ctx.ldap.query(
                search_filter="(objectSid=S-1-5-32-554)",
                attributes=["distinguishedName", "objectSid", "member"],
            )

        if not prewin2k_entries:
            return ScanResult(raw={
                "applicable": False,
                "reason":     "BUILTIN\\Pre-Windows 2000 Compatible Access not found",
            })

        group_entry = prewin2k_entries[0]
        member_dns  = [str(m) for m in attrs(group_entry, "member")]
        members     = self._resolve_members(ctx, member_dns)

        ds_heuristics = self._read_ds_heuristics(ctx)

        # Bucket members.
        risky_sids:    list[dict] = []
        non_default:   list[dict] = []
        for m in members:
            if m["sid"] in DEFAULT_RISKY_SIDS:
                risky_sids.append(m)
            elif m["sam"]:  # only count actually-resolved entries
                non_default.append(m)

        findings: list[Finding] = []

        for m in risky_sids:
            sid = m["sid"]
            friendly = SID_NAMES.get(sid, sid)
            if sid == SID_ANONYMOUS_LOGON:
                sev, prio = "CRITICAL", 95
                rationale = (
                    f"BUILTIN\\Pre-Windows 2000 Compatible Access contains "
                    f"{friendly} — *unauthenticated* readers can enumerate the "
                    f"directory. RID cycling and full anonymous user/group dumps "
                    f"work without credentials."
                )
                next_step = (
                    f"# Confirm with rpcclient (no creds):\n"
                    f"rpcclient -U '' -N {ctx.dc_ip} -c 'enumdomusers'\n"
                    f"# Or nxc:\n"
                    f"nxc smb {ctx.dc_ip} -u '' -p '' --rid-brute"
                )
            else:
                # Authenticated Users / Everyone — the Microsoft default.
                sev, prio = "HIGH", 78
                rationale = (
                    f"BUILTIN\\Pre-Windows 2000 Compatible Access contains "
                    f"{friendly}. Any authenticated principal can run "
                    f"``net user /domain``-style enumeration even from an "
                    f"unprivileged account; this is the Microsoft default on "
                    f"clean Server 2022/2025 installs and rarely necessary "
                    f"after the NT4 era."
                )
                next_step = (
                    f"# Validate enumeration is open with the operator account:\n"
                    f"nxc smb {ctx.dc_ip} -u {{operator_user}} -p {{operator_pass}} "
                    f"--users\n"
                    f"# Remediate (PowerShell on a DC):\n"
                    f"# Remove-ADGroupMember 'Pre-Windows 2000 Compatible Access' "
                    f"-Members 'Authenticated Users'"
                )

            findings.append(Finding(
                target="BUILTIN\\Pre-Windows 2000 Compatible Access",
                attack=f"Pre-Win2k membership: {friendly}",
                severity=sev,
                priority=prio,
                reason=rationale,
                next_step=next_step,
                category="hygiene",
                mitre="T1087.002",   # Account Discovery: Domain Account
                data={
                    "member_sid":    sid,
                    "member_name":   friendly,
                    "ds_heuristics": ds_heuristics,
                    "domain_sid":    ctx.domain_sid,
                },
            ))

        # Compound finding: Authenticated Users in Pre-Win2k AND
        # dsHeuristics permits anonymous binds → escalate to CRITICAL.
        if (
            ds_heuristics_allows_anonymous(ds_heuristics)
            and any(m["sid"] in (SID_EVERYONE, SID_AUTHENTICATED_USERS) for m in risky_sids)
        ):
            findings.append(Finding(
                target="dsHeuristics + Pre-Win2k",
                attack="Anonymous LDAP binds enabled with permissive Pre-Win2k",
                severity="CRITICAL",
                priority=96,
                reason=(
                    "dsHeuristics character 7 = '2' (anonymous LDAP binds "
                    "permitted) AND Pre-Windows 2000 Compatible Access "
                    "includes Authenticated Users / Everyone. The combination "
                    "yields full unauthenticated directory reads."
                ),
                next_step=(
                    f"# Check unauthenticated read directly:\n"
                    f"ldapsearch -x -H ldap://{ctx.dc_ip} -b '{ctx.base_dn}' "
                    f"'(objectClass=user)' sAMAccountName"
                ),
                category="hygiene",
                mitre="T1087.002",
                data={
                    "ds_heuristics": ds_heuristics,
                    "domain_sid":    ctx.domain_sid,
                },
            ))

        if non_default:
            findings.append(Finding(
                target="BUILTIN\\Pre-Windows 2000 Compatible Access",
                attack="Pre-Win2k group has non-default members",
                severity="MEDIUM",
                priority=55,
                reason=(
                    f"{len(non_default)} non-default principal(s) in the "
                    f"Pre-Win2k group: "
                    f"{', '.join(m['sam'] for m in non_default[:5])}"
                    f"{'…' if len(non_default) > 5 else ''}. Probably intentional, "
                    f"but worth confirming with the AD owner."
                ),
                next_step=(
                    "# Review:\n"
                    "# Get-ADGroupMember 'Pre-Windows 2000 Compatible Access' "
                    "| Select-Object Name, ObjectClass"
                ),
                category="hygiene",
                mitre="T1087.002",
                data={
                    "members":      non_default,
                    "domain_sid":   ctx.domain_sid,
                },
            ))

        return ScanResult(
            raw={
                "applicable":     True,
                "members":        members,
                "ds_heuristics":  ds_heuristics,
                "summary": {
                    "members_total":     len(members),
                    "default_risky":     len(risky_sids),
                    "non_default":       len(non_default),
                    "anonymous_present": any(m["sid"] == SID_ANONYMOUS_LOGON for m in risky_sids),
                    "auth_users_present": any(m["sid"] == SID_AUTHENTICATED_USERS for m in risky_sids),
                },
            },
            findings=findings,
        )

    # ------------------------------------------------------------------ #
    #  Helpers                                                           #
    # ------------------------------------------------------------------ #

    def _resolve_members(self, ctx: ScanContext, member_dns: list[str]) -> list[dict]:
        """Resolve each member DN to {sid, sam}. Foreign-security-principal
        entries (well-known SIDs like Authenticated Users) are CN=<SID>
        entries; we extract the SID from the CN directly when the
        objectClass is foreignSecurityPrincipal."""
        out: list[dict] = []
        for dn in member_dns:
            entries = ctx.ldap.query(
                search_filter="(objectClass=*)",
                attributes=["sAMAccountName", "objectSid", "objectClass", "cn"],
                search_base=dn,
            )
            if not entries:
                # Couldn't resolve; record the DN so the operator sees something.
                out.append({"sid": "", "sam": "", "dn": dn})
                continue
            e = entries[0]
            obj_classes = [str(c).lower() for c in attrs(e, "objectClass")]
            if "foreignsecurityprincipal" in obj_classes:
                # The CN of a foreignSecurityPrincipal entry is the SID
                # in string form. Easier than parsing the binary objectSid.
                cn = attr(e, "cn") or ""
                if cn.startswith("S-"):
                    out.append({"sid": cn, "sam": SID_NAMES.get(cn, cn), "dn": dn})
                    continue
            sid = sid_to_str(attr(e, "objectSid")) or ""
            sam = attr(e, "sAMAccountName") or attr(e, "cn") or ""
            out.append({"sid": sid, "sam": sam, "dn": dn})
        return out

    def _read_ds_heuristics(self, ctx: ScanContext) -> str | None:
        if not hasattr(ctx.ldap, "query_config"):
            return None
        entries = ctx.ldap.query_config(
            search_filter="(objectClass=nTDSService)",
            attributes=["dSHeuristics"],
        )
        if not entries:
            return None
        return attr(entries[0], "dSHeuristics")


def ds_heuristics_allows_anonymous(value: str | None) -> bool:
    """MS-ADTS §3.1.1.4.5: character 7 (1-indexed; index 6 in Python)
    of dSHeuristics = '2' enables anonymous LDAP binds. Returns False
    on any other state, including missing/malformed strings."""
    if not value:
        return False
    s = str(value)
    return len(s) >= 7 and s[6] == "2"

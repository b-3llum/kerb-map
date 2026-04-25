"""
OU computer-create rights audit (brief §4.7).

Default AD lets every authenticated user create up to MAQ machine
accounts via Authenticated Users → CreateChild(computer) on
CN=Computers,DC=...; that's the RBCD on-ramp every CRTE student knows.
The defensive hardening is to set MAQ=0, which kills *that* path — but
operators routinely grant CreateChild on bespoke OUs to helpdesk or
service accounts, and those grants survive the hardening.

This module walks the DACL on every OU + the default Computers
container and flags non-default principals with:

  - GenericAll               (full container takeover → CRITICAL)
  - CreateChild(computer)    (RBCD pivot enabled → HIGH)
  - CreateChild(any class)   (subsumes computer creation → HIGH)

The Authenticated Users → CreateChild(computer) ACE on CN=Computers is
the MAQ pathway. We don't re-flag it here — the existing NoPac /
Certifried checks already light up MAQ>0 as a separate finding, and
double-flagging would just spam the report.

Suppression:
  - Well-known privileged SIDs (Domain Admins, SYSTEM, EAs, DCs, etc.)
  - S-1-5-32-548 (Account Operators) — holds CreateChild by design;
    Account Operator membership is the Tier-0 audit's job, not ours.

Each finding emits a ``KerbMapCreateComputerOu`` BloodHound CE custom
edge so operators can ``MATCH (u)-[:KerbMapCreateComputerOu]->(ou)``
to recover the graph.

References:
- https://www.thehacker.recipes/ad/movement/dacl/grant-rights
- BloodHound's `AddAllowedToAct` edge — same class of pre-condition
  but checked from the other direction (target side).
"""

from __future__ import annotations

from kerb_map.acl import (
    ADS_RIGHT_DS_CREATE_CHILD,
    ADS_RIGHT_GENERIC_ALL,
    OBJECT_CLASS_COMPUTER,
    is_well_known_privileged,
    parse_sd,
    resolve_sids,
    sd_control,
    walk_aces,
)
from kerb_map.ldap_helpers import attr
from kerb_map.plugin import Finding, Module, ScanContext, ScanResult, register

# Account Operators — has CreateChild on Users/Computers/Groups by
# default. Tier-0 ACL audit owns the "is Account Operators membership
# itself a finding" question; here we just suppress the noise.
SID_ACCOUNT_OPERATORS = "S-1-5-32-548"

# Authenticated Users — when this principal holds CreateChild(computer)
# on the default CN=Computers container, that's the MAQ pathway and
# the NoPac / Certifried scanners already report it. Skip from this
# module to avoid double-flagging.
SID_AUTHENTICATED_USERS = "S-1-5-11"


@register
class OuComputerCreate(Module):
    name        = "OU computer-create rights"
    flag        = "ou-create-computer"
    description = "Walk OU DACLs for non-default principals with CreateChild(computer) — RBCD pivot survives MAQ=0"
    category    = "attack-path"
    in_default_run = True

    # ------------------------------------------------------------------ #
    #  Entry                                                              #
    # ------------------------------------------------------------------ #

    def scan(self, ctx: ScanContext) -> ScanResult:
        targets = self._enumerate_targets(ctx)
        if not targets:
            return ScanResult(raw={
                "applicable": False,
                "reason":     "no OUs or default Computers container enumerated",
            })

        maq = self._maq(ctx)

        deferred:    list[tuple[dict, dict]] = []
        writer_sids: set[str] = set()

        for tgt in targets:
            sd = parse_sd(tgt.get("nTSecurityDescriptor"))
            if sd is None:
                continue
            for ace in walk_aces(sd, object_dn=tgt["dn"]):
                if _suppress(ace.trustee_sid, tgt, maq):
                    continue
                classified = _classify_ace(ace)
                if classified is None:
                    continue
                deferred.append((tgt, {"ace": ace, "class": classified}))
                writer_sids.add(ace.trustee_sid)

        if not deferred:
            return ScanResult(raw={
                "applicable": True,
                "audited":    [t["dn"] for t in targets],
                "summary":    {"audited": len(targets), "findings": 0,
                               "machine_account_quota": maq},
            })

        names = resolve_sids(ctx.ldap, writer_sids, ctx.base_dn)

        findings:    list[Finding] = []
        raw_entries: list[dict]    = []

        for tgt, match in deferred:
            ace        = match["ace"]
            classified = match["class"]
            wsid       = ace.trustee_sid
            winfo      = names.get(wsid, {})
            wsam       = winfo.get("sAMAccountName") or wsid
            wdn        = winfo.get("distinguishedName") or ""

            findings.append(Finding(
                target=tgt["name"],
                attack=f"OU computer-create: {classified['label']}",
                severity=classified["severity"],
                priority=classified["priority"],
                reason=(
                    f"{wsam} holds {classified['label']} on "
                    f"{tgt['kind']} '{tgt['name']}'. "
                    + (
                        "MAQ=0 is enforced domain-wide, but this ACE survives "
                        "the hardening — anyone compromising this principal can "
                        "still create a machine account in this container and "
                        "use it as the RBCD pivot."
                        if maq == 0 else
                        f"MAQ={maq} domain-wide, so any user can already "
                        f"create up to {maq} machines via the default "
                        f"pathway; this ACE is informational unless MAQ "
                        f"is later set to 0."
                    )
                ),
                next_step=_next_step(classified["label"], wsam, tgt, ctx, maq),
                category="attack-path",
                mitre="T1078.002",
                data={
                    "writer_sid":  wsid,
                    "writer_sam":  wsam,
                    "writer_dn":   wdn,
                    "target_dn":   tgt["dn"],
                    "target_name": tgt["name"],
                    "target_kind": tgt["kind"],
                    "right":       classified["label"],
                    "maq":         maq,
                    "domain_sid":  ctx.domain_sid,
                },
            ))
            raw_entries.append({
                "target":     tgt["name"],
                "target_dn":  tgt["dn"],
                "writer_sid": wsid,
                "writer_sam": wsam,
                "right":      classified["label"],
            })

        return ScanResult(
            raw={
                "applicable": True,
                "audited":    [t["dn"] for t in targets],
                "entries":    raw_entries,
                "summary": {
                    "audited":               len(targets),
                    "findings":              len(findings),
                    "machine_account_quota": maq,
                },
            },
            findings=findings,
        )

    # ------------------------------------------------------------------ #
    #  Targets                                                            #
    # ------------------------------------------------------------------ #

    def _enumerate_targets(self, ctx: ScanContext) -> list[dict]:
        out: list[dict] = []

        # Every OU under base_dn — paged read of the whole DIT.
        ous = ctx.ldap.query(
            search_filter="(objectClass=organizationalUnit)",
            attributes=["ou", "distinguishedName", "nTSecurityDescriptor"],
            controls=sd_control(),
        )
        for e in ous:
            dn = attr(e, "distinguishedName") or ""
            out.append({
                "name": attr(e, "ou") or _last_rdn(dn) or "<OU>",
                "dn":   dn,
                "kind": "OU",
                "is_default_computers": False,
                "nTSecurityDescriptor": attr(e, "nTSecurityDescriptor"),
            })

        # Default CN=Computers container — not an OU but holds machines
        # by default and is where MAQ-driven creates land.
        comp = ctx.ldap.query(
            search_filter="(&(objectClass=container)(cn=Computers))",
            attributes=["cn", "distinguishedName", "nTSecurityDescriptor"],
            search_base=ctx.base_dn,
            controls=sd_control(),
        )
        for e in comp:
            dn = attr(e, "distinguishedName") or ""
            out.append({
                "name": attr(e, "cn") or "Computers",
                "dn":   dn,
                "kind": "Container",
                "is_default_computers": True,
                "nTSecurityDescriptor": attr(e, "nTSecurityDescriptor"),
            })

        return out

    # ------------------------------------------------------------------ #
    #  MAQ                                                                #
    # ------------------------------------------------------------------ #

    def _maq(self, ctx: ScanContext) -> int:
        """Pull the domain-wide MachineAccountQuota from the resolved
        domain_info (the LDAP client populates it during get_domain_info).
        Default to 10 (the AD default) when unknown — that's the
        worst-case for "is this finding informational or actionable?"
        decisioning."""
        info = ctx.domain_info or {}
        val  = info.get("machine_account_quota")
        if val is None:
            return 10
        try:
            return int(val)
        except (TypeError, ValueError):
            return 10


# ────────────────────────────────────────────────────────────────────── #
#  ACE classification                                                    #
# ────────────────────────────────────────────────────────────────────── #


def _classify_ace(ace) -> dict | None:
    """Return {label, severity, priority} for ACEs that grant the
    ability to create a computer in the container, else None."""
    # GenericAll = full container takeover.
    if ace.has_right(ADS_RIGHT_GENERIC_ALL):
        return {"label": "GenericAll", "severity": "CRITICAL", "priority": 90}

    # CreateChild — either explicit on the computer object class, or
    # un-typed (applies to all classes, includes computer).
    if ace.has_right(ADS_RIGHT_DS_CREATE_CHILD):
        if ace.object_type_guid is None:
            return {"label": "CreateChild(any)", "severity": "HIGH", "priority": 84}
        if ace.object_type_guid.lower() == OBJECT_CLASS_COMPUTER:
            return {"label": "CreateChild(computer)", "severity": "HIGH", "priority": 86}

    return None


def _suppress(sid: str | None, tgt: dict, maq: int) -> bool:
    """SIDs we never flag for OU-create:
      - Well-known privileged (DA / EA / SYSTEM / DCs / BUILTIN\\Admins)
      - Account Operators (designed to hold CreateChild)
      - Authenticated Users on the default CN=Computers container
        (that's the MAQ pathway; NoPac / Certifried scanners report it
        from the MAQ angle, double-flagging here is noise).
    """
    if not sid:
        return True
    if is_well_known_privileged(sid):
        return True
    if sid == SID_ACCOUNT_OPERATORS:
        return True
    if sid == SID_AUTHENTICATED_USERS and tgt.get("is_default_computers"):
        return True
    return False


# ────────────────────────────────────────────────────────────────────── #
#  Recipes                                                                #
# ────────────────────────────────────────────────────────────────────── #


def _next_step(right: str, wsam: str, tgt: dict, ctx: ScanContext, maq: int) -> str:
    """Operator-facing recipe. Builds the impacket addcomputer.py call
    targeted at this OU specifically; --computer-pass placeholder so
    kerb-chain can fill it in."""
    domain  = ctx.domain
    dc_ip   = ctx.dc_ip
    ou_dn   = tgt["dn"]

    if maq == 0:
        intro = (
            f"# MAQ=0 enforced — but {wsam} can still create machines\n"
            f"# in {tgt['name']} via {right} on this container.\n"
        )
    else:
        intro = (
            f"# MAQ={maq}, so creation works without the ACE; this is\n"
            f"# the post-hardening pivot. As {wsam}:\n"
        )

    return (
        intro +
        f"impacket-addcomputer -dc-ip {dc_ip} "
        f"-computer-name 'PIVOT$' -computer-pass '<pwd>' "
        f"-baseDN '{ou_dn}' "
        f"-method LDAPS '{domain}/{wsam}:<pass>'\n"
        f"# Then RBCD: set msDS-AllowedToActOnBehalfOfOtherIdentity\n"
        f"# on a Tier-0 box to PIVOT$, S4U2Self/S4U2Proxy as admin."
    )


def _last_rdn(dn: str) -> str:
    """Best-effort: pull the leftmost RDN value for naming. Uses simple
    split because OU names rarely contain escaped commas; if they do,
    the worst case is a slightly less pretty 'name' field."""
    if not dn:
        return ""
    head = dn.split(",", 1)[0]
    if "=" in head:
        return head.split("=", 1)[1]
    return head

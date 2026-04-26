"""
BloodHound CE 5.x compatible exporter.

Replaces the deferred §1.6 option-(a) of the brief — produces an
actually-ingestible zip rather than the BloodHound-Lite custom shape.

Output is a single ``*.zip`` containing four JSON files:

  ``users.json``     ``computers.json``     ``groups.json``     ``domains.json``

Each follows the BloodHound CE collector format:
- ``meta``: {type, count, version, methods, collectorversion}
- ``data``: list of node dicts with ObjectIdentifier (full S-1-5-21-...),
  Properties, Aces, plus type-specific arrays (Members for groups,
  HasSIDHistory for users, etc.)

kerb-map findings ship in a sidecar ``_kerbmap_metadata.json`` inside
the same zip — NOT as BH-CE-renderable graph edges (yet). The
sidecar is for kerb-chain / external tooling; BH CE skips it during
ingest because the underscore-prefixed name doesn't match a known
SharpHound type.

Field bug from a real BH CE 5.x ingest (verified end-to-end against
a running container): the previous shape — a top-level
``kerbmap_edges.json`` with ``meta.type="kerbmap_edges"`` — caused
BH CE to reject the *entire upload* with HTTP 500 + "no valid meta
tag found". BH CE's ingester only accepts the canonical SharpHound
types (users / computers / groups / domains / gpos / ous /
containers / aiacas / rootcas / etc.).

The right long-term fix is to fold each finding into the affected
node's ``Aces`` array using a SharpHound-recognised ``RightName``
(e.g. ``GenericAll``, ``WriteDacl``, ``AddKeyCredentialLink``,
``GetChangesAll``). That's tracked as a v1.2.x follow-up; doing it
right needs per-finding mapping + node-side merge logic.

The 4 standard JSONs (users/computers/groups/domains) DO ingest
cleanly — verified by Cypher queries against the loaded graph
(operators can use BH CE's normal pathfinding immediately, just
without the KerbMap-specific edges). Sidecar gives kerb-chain a
machine-readable view of what kerb-map found for orchestration.

Reference: https://bloodhound.specterops.io/collect-data/json-formats
"""

from __future__ import annotations

import datetime
import json
import zipfile
from pathlib import Path
from typing import Any

from kerb_map.ldap_helpers import attr, attrs, sid_to_str
from kerb_map.output.logger import Logger

log = Logger()


COLLECTOR_NAME    = "kerb-map"
COLLECTOR_VERSION = "2.0.0-foundation"
SCHEMA_VERSION    = 6  # BloodHound CE 5.x ingestion schema


# ────────────────────────────────────────────────────────────────────── #
#  Public API                                                            #
# ────────────────────────────────────────────────────────────────────── #


class BloodHoundCEExporter:
    """Build a BloodHound CE-ingestible zip from a kerb-map scan.

    Usage:

        exporter = BloodHoundCEExporter(ldap, domain="corp.local",
                                        domain_sid="S-1-5-21-...")
        exporter.add_findings(scan_result)        # extend with attack edges
        exporter.export("scan.bloodhound.zip")    # write the zip
    """

    def __init__(self, ldap, *, domain: str, domain_sid: str | None,
                 base_dn: str, dc_dnshostname: str | None = None):
        self.ldap = ldap
        self.domain = domain.upper()
        self.domain_sid = domain_sid
        self.base_dn = base_dn
        self.dc_dnshostname = dc_dnshostname or domain.lower()
        self._extra_edges: list[dict] = []

    # ------------------------------------------------------------------ #
    #  Findings → custom edges                                           #
    # ------------------------------------------------------------------ #

    def add_findings(self, findings: list) -> None:
        """Translate kerb-map findings into BH custom edges.

        Each finding's ``data`` dict carries the SIDs / DNs needed to
        attach the edge to the right graph nodes. Findings without
        enough graph context (no principal_sid / no target SID) are
        skipped quietly — they still appear in the JSON report and the
        terminal output, just not as graph edges.
        """
        for f in findings:
            data = (f.data or {}) if hasattr(f, "data") else (f.get("data") or {})
            attack = f.attack if hasattr(f, "attack") else f.get("attack", "")
            target = f.target if hasattr(f, "target") else f.get("target", "")

            # ── DCSync rights (DCSyncRights module) ─────────────
            if attack == "DCSync (full)" and data.get("principal_sid"):
                self._extra_edges.append({
                    "source": data["principal_sid"],
                    "target": self.domain_sid or self.domain,
                    "edge":   "KerbMapDCSyncBy",
                    "props":  {"rights": data.get("rights_granted", [])},
                })
            # ── Shadow Credentials (write-ACL only — inventory       ──
            #     findings carry no graph endpoints worth an edge)
            elif attack.startswith("Shadow Credentials") and data.get("writer_sid"):
                self._extra_edges.append({
                    "source": data["writer_sid"],
                    "target": data.get("target_dn") or "",
                    "edge":   "KerbMapAddKeyCredentialLink",
                    "props":  {},
                })
            # ── BadSuccessor (BadSuccessor module) ──────────────
            elif attack == "BadSuccessor (staged)" and data.get("dmsa_dn"):
                self._extra_edges.append({
                    "source": data["dmsa_dn"],
                    "target": ", ".join(data.get("predecessors", [])),
                    "edge":   "KerbMapBadSuccessor",
                    "props":  {"state": data.get("delegated_msa_state")},
                })
            elif attack == "BadSuccessor (writable OU)" and data.get("principal_sid"):
                self._extra_edges.append({
                    "source": data["principal_sid"],
                    "target": data.get("ou_dn") or "",
                    "edge":   "KerbMapCanCreateDMSA",
                    "props":  {},
                })
            # ── ADCS Extended (AdcsExtended module) ─────────────
            #
            # Each ESC variant becomes its own edge type so a BloodHound
            # operator can write a Cypher query like
            #   MATCH (u:User)-[:KerbMapEsc13]->(t) RETURN u, t
            # to find every account that can enrol in an ESC13 template
            # without having to grep the JSON.
            # ── ESC4 — non-admin write on a template ────────────
            elif attack.startswith("AD CS ESC4") and data.get("writer_sid"):
                self._extra_edges.append({
                    "source": data["writer_sid"],
                    "target": data.get("template_dn") or "",
                    "edge":   "KerbMapEsc4",
                    "props":  {"right": data.get("right")},
                })
            # ── ESC5 — non-admin write on a PKI container ───────
            elif attack.startswith("AD CS ESC5") and data.get("writer_sid"):
                self._extra_edges.append({
                    "source": data["writer_sid"],
                    "target": data.get("container_dn") or "",
                    "edge":   "KerbMapEsc5",
                    "props":  {"right": data.get("right")},
                })
            # ── ESC7 — CA officer rights ────────────────────────
            elif attack.startswith("AD CS ESC7") and data.get("writer_sid"):
                self._extra_edges.append({
                    "source": data["writer_sid"],
                    "target": data.get("ca_dn") or "",
                    "edge":   "KerbMapEsc7",
                    "props":  {"rights": data.get("rights", [])},
                })
            elif attack.startswith("AD CS ESC9"):
                if data.get("template_dn"):
                    self._extra_edges.append({
                        "source": data["template_dn"],
                        "target": self.domain_sid or self.domain,
                        "edge":   "KerbMapEsc9",
                        "props":  {"enroll_flag": data.get("enroll_flag")},
                    })
            elif attack.startswith("AD CS ESC13"):
                # One edge per linked privileged group so each is queryable.
                for grp in data.get("linked_groups", []):
                    if data.get("template_dn") and grp.get("sid"):
                        self._extra_edges.append({
                            "source": data["template_dn"],
                            "target": grp["sid"],
                            "edge":   "KerbMapEsc13LinkedTo",
                            "props":  {"oid": grp.get("oid"),
                                       "group_name": grp["group"]["name"]
                                                    if isinstance(grp.get("group"), dict)
                                                    else grp.get("group")},
                        })
            elif attack.startswith("AD CS ESC15") or "EKUwu" in attack:
                if data.get("template_dn"):
                    self._extra_edges.append({
                        "source": data["template_dn"],
                        "target": self.domain_sid or self.domain,
                        "edge":   "KerbMapEsc15",
                        "props":  {"schema_version": data.get("schema_version")},
                    })
            # ── Pre-Win2k (PreWin2kAccess module) ───────────────
            elif attack.startswith("Pre-Win2k membership") and data.get("member_sid"):
                self._extra_edges.append({
                    "source": data["member_sid"],
                    "target": "S-1-5-32-554",   # well-known BUILTIN group SID
                    "edge":   "KerbMapPreWin2kMember",
                    "props":  {"member_name": data.get("member_name")},
                })
            elif attack == "Anonymous LDAP binds enabled with permissive Pre-Win2k":
                # Compound finding — attach to the domain so it shows
                # as a domain-level critical in the graph.
                self._extra_edges.append({
                    "source": "S-1-5-32-554",
                    "target": self.domain_sid or self.domain,
                    "edge":   "KerbMapAnonymousLdapEnabled",
                    "props":  {"ds_heuristics": data.get("ds_heuristics")},
                })
            # ── Golden dMSA prereq (GmsaKdsAudit module) ────────
            elif attack.startswith("Golden dMSA prerequisite"):
                # One edge per extra reader so each reader is queryable
                # individually — Cypher: MATCH (p)-[:KerbMapKdsReadable]->(k)
                for sid in data.get("extra_reader_sids", []):
                    self._extra_edges.append({
                        "source": sid,
                        "target": data.get("kds_key_cn") or "kds-root",
                        "edge":   "KerbMapKdsReadable",
                        "props":  {},
                    })
            elif attack == "gMSA password readable by non-default principal":
                for sid in data.get("extra_reader_sids", []):
                    self._extra_edges.append({
                        "source": sid,
                        "target": target,            # the gMSA's sAMAccountName
                        "edge":   "KerbMapGmsaReader",
                        "props":  {},
                    })
            # ── Tier-0 ACL audit (Tier0AclAudit module) ─────────
            #
            # Right-specific edge labels so a CRTE-style "find every
            # writer of Domain Admins" query is one Cypher hop:
            #   MATCH (u)-[:KerbMapWriteAcl]->(t {samaccountname:'Domain Admins'})
            #   RETURN u, t.right
            elif attack.startswith("Tier-0 ACL:") and data.get("writer_sid"):
                target_id = data.get("target_sid") or data.get("target_dn") or ""
                self._extra_edges.append({
                    "source": data["writer_sid"],
                    "target": target_id,
                    "edge":   "KerbMapWriteAcl",
                    "props":  {
                        "right":       data.get("right"),
                        "target_kind": data.get("target_kind"),
                    },
                })
            # ── OU computer-create (OuComputerCreate module) ────
            #
            # The "post-MAQ-hardening RBCD pivot" edge — operators can
            # MATCH (u)-[:KerbMapCreateComputerOu]->(ou) to find every
            # principal that can drop a machine account into an OU.
            elif attack.startswith("OU computer-create") and data.get("writer_sid"):
                self._extra_edges.append({
                    "source": data["writer_sid"],
                    "target": data.get("target_dn") or "",
                    "edge":   "KerbMapCreateComputerOu",
                    "props":  {
                        "right":       data.get("right"),
                        "target_kind": data.get("target_kind"),
                        "maq":         data.get("maq"),
                    },
                })

    # ------------------------------------------------------------------ #
    #  Collection → zip                                                  #
    # ------------------------------------------------------------------ #

    def export(self, path: str) -> Path:
        users     = self._collect_users()
        computers = self._collect_computers()
        groups    = self._collect_groups()
        domains   = self._collect_domain()

        out = Path(path)
        with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("users.json",     json.dumps(_wrap("users",     users), indent=2))
            zf.writestr("computers.json", json.dumps(_wrap("computers", computers), indent=2))
            zf.writestr("groups.json",    json.dumps(_wrap("groups",    groups), indent=2))
            zf.writestr("domains.json",   json.dumps(_wrap("domains",   domains), indent=2))
            # Field bug from a real BH CE 5.x ingest: emitting our
            # findings as a top-level "kerbmap_edges.json" with
            # meta.type="kerbmap_edges" caused BH CE to reject the
            # *entire* file with HTTP 500 + "no valid meta tag found"
            # — BH CE's ingester only accepts the canonical SharpHound
            # types (users/computers/groups/domains/gpos/ous/
            # containers/aiacas/rootcas/etc.). Folding our findings
            # into per-node ``Aces`` arrays is the right long-term fix
            # (tracked as v1.2.x follow-up); for now we write the
            # findings to a sidecar with a name BH CE doesn't try to
            # ingest, so the zip is fully ingestible AND the operator
            # / external tooling (kerb-chain) can still read the raw
            # KerbMap* edges from the zip.
            if self._extra_edges:
                zf.writestr(
                    "_kerbmap_metadata.json",
                    json.dumps({
                        "meta": {
                            "type":             "kerbmap_metadata",
                            "count":            len(self._extra_edges),
                            "version":          SCHEMA_VERSION,
                            "collectorversion": COLLECTOR_VERSION,
                            "_note": (
                                "Sidecar, not BH CE-ingestible. "
                                "Per-node Aces folding is the long-term "
                                "fix; see docs/v1.2-known-gaps.md."
                            ),
                        },
                        "data": self._extra_edges,
                    }, indent=2),
                )

        log.success(
            f"BloodHound CE zip → {out.resolve()} "
            f"({len(users)} users, {len(computers)} computers, "
            f"{len(groups)} groups; {len(self._extra_edges)} kerb-map edges in sidecar)"
        )
        return out

    # ------------------------------------------------------------------ #
    #  Per-type collectors                                               #
    # ------------------------------------------------------------------ #

    def _collect_users(self) -> list[dict]:
        entries = self.ldap.query(
            search_filter="(&(objectClass=user)(!(objectClass=computer)))",
            attributes=[
                "sAMAccountName", "objectSid", "distinguishedName",
                "userAccountControl", "servicePrincipalName",
                "memberOf", "primaryGroupID", "adminCount",
                "pwdLastSet", "lastLogonTimestamp", "description",
                "sIDHistory", "msDS-AllowedToDelegateTo",
            ],
        )
        out: list[dict] = []
        for e in entries:
            sid = sid_to_str(attr(e, "objectSid"))
            if not sid:
                continue
            sam = attr(e, "sAMAccountName") or ""
            dn  = attr(e, "distinguishedName") or ""
            uac = attr(e, "userAccountControl") or 0
            spns = attrs(e, "servicePrincipalName")
            primary_rid = attr(e, "primaryGroupID")
            primary_sid = (f"{self.domain_sid}-{primary_rid}"
                           if self.domain_sid and isinstance(primary_rid, int) else None)

            out.append({
                "ObjectIdentifier": sid,
                "Properties": {
                    "name":             f"{sam.upper()}@{self.domain}",
                    "domain":           self.domain,
                    "domainsid":        self.domain_sid,
                    "samaccountname":   sam,
                    "distinguishedname": dn,
                    "description":      attr(e, "description"),
                    "enabled":          not bool(int(uac) & 0x2),
                    "hasspn":           bool(spns),
                    "dontreqpreauth":   bool(int(uac) & 0x400000),
                    "passwordnotreqd":  bool(int(uac) & 0x20),
                    "admincount":       attr(e, "adminCount") == 1,
                    "serviceprincipalnames": [str(s) for s in spns],
                    "lastlogontimestamp":  _ft_to_unix(attr(e, "lastLogonTimestamp")),
                    "pwdlastset":          _ft_to_unix(attr(e, "pwdLastSet")),
                    "sidhistory":          [sid_to_str(s) for s in attrs(e, "sIDHistory") if s],
                    "allowedtodelegate":   [str(t) for t in attrs(e, "msDS-AllowedToDelegateTo")],
                    "trustedtoauth":       bool(int(uac) & 0x1000000),
                    "unconstraineddelegation": bool(int(uac) & 0x80000),
                },
                "PrimaryGroupSID": primary_sid,
                "Aces":            [],
                "AllowedToDelegate": [],
                "HasSIDHistory":   [],
                "SPNTargets":      [],
                "IsDeleted":       False,
                "IsACLProtected":  False,
            })
        return out

    def _collect_computers(self) -> list[dict]:
        entries = self.ldap.query(
            search_filter="(objectClass=computer)",
            attributes=[
                "sAMAccountName", "objectSid", "distinguishedName",
                "dNSHostName", "userAccountControl",
                "msDS-AllowedToDelegateTo",
                "msDS-AllowedToActOnBehalfOfOtherIdentity",
                "operatingSystem", "primaryGroupID", "lastLogonTimestamp",
            ],
        )
        out: list[dict] = []
        for e in entries:
            sid = sid_to_str(attr(e, "objectSid"))
            if not sid:
                continue
            sam = attr(e, "sAMAccountName") or ""
            uac = attr(e, "userAccountControl") or 0
            primary_rid = attr(e, "primaryGroupID")
            primary_sid = (f"{self.domain_sid}-{primary_rid}"
                           if self.domain_sid and isinstance(primary_rid, int) else None)
            out.append({
                "ObjectIdentifier": sid,
                "Properties": {
                    "name":             f"{sam.upper().rstrip('$')}.{self.domain}",
                    "domain":           self.domain,
                    "domainsid":        self.domain_sid,
                    "samaccountname":   sam,
                    "distinguishedname": attr(e, "distinguishedName"),
                    "operatingsystem":  attr(e, "operatingSystem"),
                    "enabled":          not bool(int(uac) & 0x2),
                    "unconstraineddelegation": bool(int(uac) & 0x80000),
                    "trustedtoauth":    bool(int(uac) & 0x1000000),
                    "allowedtodelegate": [str(t) for t in attrs(e, "msDS-AllowedToDelegateTo")],
                    "lastlogontimestamp":  _ft_to_unix(attr(e, "lastLogonTimestamp")),
                },
                "PrimaryGroupSID":  primary_sid,
                "Aces":             [],
                "AllowedToDelegate": [],
                "AllowedToAct":     [],
                "Sessions":         {"Results": [], "Collected": False},
                "PrivilegedSessions": {"Results": [], "Collected": False},
                "RegistrySessions": {"Results": [], "Collected": False},
                "LocalAdmins":      {"Results": [], "Collected": False},
                "RemoteDesktopUsers": {"Results": [], "Collected": False},
                "DcomUsers":        {"Results": [], "Collected": False},
                "PSRemoteUsers":    {"Results": [], "Collected": False},
                "Status":           None,
                "IsDeleted":        False,
                "IsACLProtected":   False,
            })
        return out

    def _collect_groups(self) -> list[dict]:
        entries = self.ldap.query(
            search_filter="(objectClass=group)",
            attributes=["sAMAccountName", "objectSid", "distinguishedName",
                        "member", "adminCount"],
        )
        out: list[dict] = []
        for e in entries:
            sid = sid_to_str(attr(e, "objectSid"))
            if not sid:
                continue
            sam = attr(e, "sAMAccountName") or ""
            members: list[dict] = []
            for member_dn in attrs(e, "member"):
                members.append({
                    "ObjectIdentifier": str(member_dn),  # DN — collector resolves to SID
                    "ObjectType":       "Base",
                })
            out.append({
                "ObjectIdentifier": sid,
                "Properties": {
                    "name":             f"{sam.upper()}@{self.domain}",
                    "domain":           self.domain,
                    "domainsid":        self.domain_sid,
                    "samaccountname":   sam,
                    "distinguishedname": attr(e, "distinguishedName"),
                    "admincount":       attr(e, "adminCount") == 1,
                },
                "Members":  members,
                "Aces":     [],
                "IsDeleted": False,
                "IsACLProtected": False,
            })
        return out

    def _collect_domain(self) -> list[dict]:
        if not self.domain_sid:
            return []
        return [{
            "ObjectIdentifier": self.domain_sid,
            "Properties": {
                "name":             self.domain,
                "domain":           self.domain,
                "domainsid":        self.domain_sid,
                "distinguishedname": self.base_dn,
                "functionallevel":  "Unknown",  # filled by collector if domain_info is available elsewhere
            },
            "Trusts":          [],
            "Links":           [],
            "ChildObjects":    [],
            "Aces":            [],
            "GPOChanges": {
                "LocalAdmins": [], "RemoteDesktopUsers": [],
                "DcomUsers":   [], "PSRemoteUsers":      [],
                "AffectedComputers": [],
            },
            "IsDeleted":       False,
            "IsACLProtected":  False,
        }]


# ────────────────────────────────────────────────────────────────────── #
#  Helpers                                                               #
# ────────────────────────────────────────────────────────────────────── #


def _wrap(type_name: str, data: list[dict]) -> dict[str, Any]:
    return {
        "meta": {
            "type":             type_name,
            "count":            len(data),
            "version":          SCHEMA_VERSION,
            "methods":          0,           # we don't implement collection methods
            "collectorversion": COLLECTOR_VERSION,
            "collectortimestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        },
        "data": data,
    }


def _ft_to_unix(value: Any) -> int:
    """Convert a Windows FILETIME (or already-converted int) to a Unix
    epoch seconds value. Returns -1 for missing/never-set, matching
    SharpHound's convention."""
    if value is None:
        return -1
    if isinstance(value, datetime.datetime):
        return int(value.timestamp())
    try:
        v = int(value)
    except (TypeError, ValueError):
        return -1
    if v <= 0:
        return -1
    # FILETIME (100ns since 1601) → Unix epoch seconds
    return (v - 116444736000000000) // 10_000_000

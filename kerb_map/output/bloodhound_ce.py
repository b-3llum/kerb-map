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

KerbMap findings are emitted two ways for the same zip:

1. **Folded into the target node's ``Aces`` array** when the finding
   maps cleanly to a SharpHound-recognised ``RightName`` (e.g.
   ``GenericAll``, ``WriteDacl``, ``AddKeyCredentialLink``,
   ``GetChangesAll``). These render as native edges in BH CE — the
   operator's "shortest path to Domain Admin" now traverses
   kerb-map's findings without any extra tooling. Currently three
   finding classes fold:

   - ``DCSync rights``  → Domain node Aces with ``GetChanges`` +
     ``GetChangesAll`` (full DCSync needs both)
   - ``Shadow Credentials write`` → target user's Aces with
     ``AddKeyCredentialLink``
   - ``Tier-0 ACL``     → target's Aces with the right's SharpHound
     equivalent (``GenericAll`` / ``WriteDacl`` / ``WriteOwner`` /
     ``GenericWrite`` / ``AddMember`` / ``AddSelf``)

2. **Sidecar ``_kerbmap_metadata.json``** (underscore prefix → BH CE
   skips during ingest) carries every finding-as-edge for kerb-chain
   / external tooling. Each entry has a ``folded`` field indicating
   whether it also became a graph ACE. Findings whose target isn't a
   collected node (ADCS templates, OUs, dMSAs) are sidecar-only
   because BH CE's standard schema doesn't include those node types.

Field bug history that shaped this design:

- A previous shape — a top-level ``kerbmap_edges.json`` with
  ``meta.type="kerbmap_edges"`` — caused BH CE to reject the *entire
  upload* with HTTP 500 + "no valid meta tag found". BH CE's ingester
  only accepts the canonical SharpHound types (users / computers /
  groups / domains / gpos / ous / containers / aiacas / rootcas /
  etc.). The fix landed in two parts: (a) underscore-prefixed sidecar
  name so BH CE skips the file, (b) per-node Aces folding so
  KerbMap findings become *real* graph edges instead of metadata.

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
COLLECTOR_VERSION = "2.1.0-aces-fold"
SCHEMA_VERSION    = 6  # BloodHound CE 5.x ingestion schema


# ────────────────────────────────────────────────────────────────────── #
#  Aces-folding map                                                      #
# ────────────────────────────────────────────────────────────────────── #
#
# Translates kerb-map internal labels to SharpHound RightName(s).
# Multi-value entries (DCSync) emit one ACE per RightName so the
# folded edge matches what SharpHound itself would emit if it had
# walked the same DACL.
#
# Right names not in this map => folding skipped, sidecar-only.
# (e.g. CreateChild, ReadGMSAPassword, ManageCA — known to BH CE but
# not currently emitted by any kerb-map finding with a SID-resolvable
# target node.)

_RIGHT_NAME_MAP: dict[str, list[str]] = {
    # Tier-0 ACL labels (kerb_map.modules.tier0_acl.RIGHT_SEVERITY)
    "GenericAll":             ["GenericAll"],
    "WriteDACL":              ["WriteDacl"],   # SharpHound camel-case
    "WriteOwner":             ["WriteOwner"],
    "GenericWrite":           ["GenericWrite"],
    "WriteProperty(member)":  ["AddMember"],
    "Self (AddSelf)":         ["AddSelf"],
    # User ACL labels share the Tier-0 vocabulary; no extras needed.
}


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
            # ── User ACL audit (UserAclAudit module) ────────────
            #
            # Same edge type as Tier-0 ACL — both modules find DACL
            # writers, just on different target sets (Tier-0 walks
            # privileged accounts; User walks every enabled non-Tier-0
            # user for lateral-movement edges). Field bug surfaced by
            # the v1.3 sprint bug-class grep: user_acl findings used
            # to be silently dropped from the export — neither folded
            # into Aces nor present in the sidecar — because no branch
            # matched ``attack.startswith("User ACL:")``.
            elif attack.startswith("User ACL:") and data.get("writer_sid"):
                target_id = data.get("target_sid") or data.get("target_dn") or ""
                self._extra_edges.append({
                    "source": data["writer_sid"],
                    "target": target_id,
                    "edge":   "KerbMapWriteAcl",
                    "props":  {
                        "right":       data.get("right"),
                        "target_kind": "user",
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

        folded = self._fold_extra_edges(users, computers, groups, domains)

        out = Path(path)
        with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("users.json",     json.dumps(_wrap("users",     users), indent=2))
            zf.writestr("computers.json", json.dumps(_wrap("computers", computers), indent=2))
            zf.writestr("groups.json",    json.dumps(_wrap("groups",    groups), indent=2))
            zf.writestr("domains.json",   json.dumps(_wrap("domains",   domains), indent=2))
            # Sidecar carries the full edge list for kerb-chain. Each
            # entry is annotated with ``folded: bool`` so external
            # readers can distinguish edges that ALSO render in the
            # graph (folded=true) from edges that exist only here
            # (folded=false — typically because the target isn't a
            # collected SharpHound node type, e.g. ADCS template, OU,
            # dMSA). See module docstring for the field bug history
            # behind the underscore-prefixed filename.
            if self._extra_edges:
                zf.writestr(
                    "_kerbmap_metadata.json",
                    json.dumps({
                        "meta": {
                            "type":             "kerbmap_metadata",
                            "count":            len(self._extra_edges),
                            "folded":           folded,
                            "version":          SCHEMA_VERSION,
                            "collectorversion": COLLECTOR_VERSION,
                            "_note": (
                                "Sidecar, not BH CE-ingestible. "
                                "Edges with folded=true ALSO appear "
                                "as ACEs on the target node and "
                                "render in BH CE."
                            ),
                        },
                        "data": self._extra_edges,
                    }, indent=2),
                )

        log.success(
            f"BloodHound CE zip → {out.resolve()} "
            f"({len(users)} users, {len(computers)} computers, "
            f"{len(groups)} groups; {len(self._extra_edges)} kerb-map edges, "
            f"{folded} folded into graph)"
        )
        return out

    # ------------------------------------------------------------------ #
    #  Aces folding                                                      #
    # ------------------------------------------------------------------ #

    def _fold_extra_edges(self, users: list[dict], computers: list[dict],
                          groups: list[dict], domains: list[dict]) -> int:
        """Fold KerbMap findings into target nodes' Aces arrays so they
        render as native BH CE edges. Returns the count of edges folded.

        Each input edge is annotated in place with ``folded: bool`` so
        the sidecar caller can report which subset became graph edges.
        Folding is idempotent and dedupes (PrincipalSID, RightName) per
        node — multiple findings against the same target with the same
        right collapse to a single ACE.
        """
        # SID → node lookup (one dict across all node types — SIDs are
        # globally unique within a domain so collisions are impossible).
        by_sid: dict[str, dict] = {}
        # DN → node lookup so edges with target_dn-only (Shadow Creds,
        # Tier-0 ACL fallback) can resolve.
        by_dn: dict[str, dict] = {}
        for collection in (users, computers, groups, domains):
            for node in collection:
                sid = node.get("ObjectIdentifier")
                if sid:
                    by_sid[sid] = node
                dn = (node.get("Properties") or {}).get("distinguishedname")
                if dn:
                    by_dn[dn.lower()] = node

        folded_count = 0
        for edge in self._extra_edges:
            edge_type = edge.get("edge", "")
            target = edge.get("target", "") or ""
            source = edge.get("source", "") or ""
            props = edge.get("props") or {}

            right_names = self._resolve_right_names(edge_type, props)
            if not right_names:
                edge["folded"] = False
                continue

            target_node = by_sid.get(target) or by_dn.get(target.lower())
            if target_node is None:
                edge["folded"] = False
                continue

            if not source.startswith("S-1-"):
                # Only SID principals fold; DN sources (e.g.
                # KerbMapBadSuccessor source=dMSA DN) can't be ACE
                # principals.
                edge["folded"] = False
                continue

            principal_type = self._principal_type_for_sid(source, by_sid)
            aces = target_node.setdefault("Aces", [])
            seen = {(a.get("PrincipalSID"), a.get("RightName")) for a in aces}
            for right_name in right_names:
                key = (source, right_name)
                if key in seen:
                    continue
                aces.append({
                    "PrincipalSID":  source,
                    "PrincipalType": principal_type,
                    "RightName":     right_name,
                    "IsInherited":   False,
                })
                seen.add(key)
            edge["folded"] = True
            folded_count += 1

        return folded_count

    @staticmethod
    def _resolve_right_names(edge_type: str, props: dict) -> list[str]:
        """Edge type → list of SharpHound RightNames to emit.

        DCSync needs both GetChanges and GetChangesAll for a
        SharpHound ingest to recognise it as full DCSync — emitting
        one without the other gets you the partial-DCSync edge,
        which doesn't build the same paths.
        """
        if edge_type == "KerbMapDCSyncBy":
            return ["GetChanges", "GetChangesAll"]
        if edge_type == "KerbMapAddKeyCredentialLink":
            return ["AddKeyCredentialLink"]
        if edge_type == "KerbMapWriteAcl":
            label = props.get("right") or ""
            return _RIGHT_NAME_MAP.get(label, [])
        return []

    @staticmethod
    def _principal_type_for_sid(sid: str, by_sid: dict[str, dict]) -> str:
        """Look up the principal node and return its BH CE type tag.

        Used to populate the ACE's PrincipalType so BH CE can
        render edges from the right node kind. Falls back to "Base"
        when the principal isn't in the collected set (e.g. a
        cross-domain SID we didn't enumerate).
        """
        node = by_sid.get(sid)
        if node is None:
            return "Base"
        # Identify by which list it lives in via the type-specific
        # arrays — cheap and unambiguous.
        if "SPNTargets" in node or "HasSIDHistory" in node:
            return "User"
        if "Sessions" in node:
            return "Computer"
        if "Members" in node:
            return "Group"
        if "Trusts" in node:
            return "Domain"
        return "Base"

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

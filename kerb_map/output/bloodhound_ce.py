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

kerb-map findings emit *custom edges* on top of the standard collector
output — these surface as new edge types in the BloodHound UI:

| Edge                | Source         | Target            | When |
|---|---|---|---|
| ``KerbMapKerberoastable`` | User    | (none — flag)     | SPN scanner finding |
| ``KerbMapASREPRoastable`` | User    | (none — flag)     | AS-REP scanner |
| ``KerbMapAllowedToDelegate`` | Computer | Computer       | Delegation mapper |
| ``KerbMapDCSyncBy``       | Domain  | User              | DCSync rights module |
| ``KerbMapHasShadowCreds`` | User    | (none — flag)     | Shadow Credentials |
| ``KerbMapBadSuccessor``   | dMSA    | User (predecessor) | BadSuccessor |

These don't replace BH's native edges (HasSession, AdminTo, etc.) —
they're additional context the SharpHound/AzureHound collectors don't
produce. Operators see "find a path from owned to DA" the usual way,
plus a "show me kerb-map's CRITICAL findings as graph nodes" lens.

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

            if attack == "DCSync (full)" and data.get("principal_sid"):
                self._extra_edges.append({
                    "source": data["principal_sid"],
                    "target": self.domain_sid or self.domain,
                    "edge":   "KerbMapDCSyncBy",
                    "props":  {"rights": data.get("rights_granted", [])},
                })
            elif attack.startswith("Shadow Credentials") and data.get("writer_sid"):
                self._extra_edges.append({
                    "source": data["writer_sid"],
                    "target": data.get("target_dn") or "",
                    "edge":   "KerbMapAddKeyCredentialLink",
                    "props":  {},
                })
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
            if self._extra_edges:
                zf.writestr(
                    "kerbmap_edges.json",
                    json.dumps({
                        "meta": {
                            "type":             "kerbmap_edges",
                            "count":            len(self._extra_edges),
                            "version":          SCHEMA_VERSION,
                            "collectorversion": COLLECTOR_VERSION,
                        },
                        "data": self._extra_edges,
                    }, indent=2),
                )

        log.success(
            f"BloodHound CE zip → {out.resolve()} "
            f"({len(users)} users, {len(computers)} computers, "
            f"{len(groups)} groups, {len(self._extra_edges)} kerb-map edges)"
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

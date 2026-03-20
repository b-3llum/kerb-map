"""
Export — JSON and BloodHound-compatible output writers.
"""

import json
import datetime
from pathlib import Path
from typing import Dict, Any, List

from kerb_map.output.logger import Logger

log = Logger()


def _default(obj):
    """JSON serialiser for non-serialisable types."""
    if isinstance(obj, datetime.datetime):
        return obj.isoformat()
    if isinstance(obj, datetime.timedelta):
        return str(obj)
    if isinstance(obj, bytes):
        return obj.hex()
    return str(obj)


class JSONExporter:
    def export(self, data: Dict[str, Any], path: str) -> None:
        out = Path(path)
        with out.open("w") as f:
            json.dump(data, f, indent=2, default=_default)
        log.success(f"JSON report written → {out.resolve()}")


class BloodHoundExporter:
    """
    Writes a BloodHound-compatible JSON file with custom nodes/edges
    for delegation and Kerberoastable accounts.
    BloodHound ingests nodes of type: User, Computer, Group, Domain.
    Custom edges we add: Kerberoastable, ASREPRoastable, AllowedToDelegate.
    """

    def export(self, data: Dict[str, Any], path: str) -> None:
        bh = {
            "meta": {
                "methods": 0,
                "type": "users",
                "count": 0,
                "version": 5,
            },
            "data": [],
        }

        nodes = []
        domain = data.get("meta", {}).get("domain", "UNKNOWN").upper()

        # Kerberoastable users
        for spn in data.get("spns", []):
            nodes.append({
                "ObjectIdentifier": f"{domain}\\{spn['account']}",
                "ObjectType": "User",
                "Properties": {
                    "name":          f"{spn['account'].upper()}@{domain}",
                    "kerberoastable": True,
                    "hasspn":        True,
                    "pwdlastset":    spn.get("password_age_days"),
                    "description":   spn.get("description", ""),
                },
                "Aces": [],
            })

        # AS-REP roastable users
        for user in data.get("asrep", []):
            nodes.append({
                "ObjectIdentifier": f"{domain}\\{user['account']}",
                "ObjectType": "User",
                "Properties": {
                    "name":            f"{user['account'].upper()}@{domain}",
                    "dontreqpreauth":  True,
                },
                "Aces": [],
            })

        # Unconstrained delegation computers
        delegations = data.get("delegations", {})
        for d in delegations.get("unconstrained", []):
            nodes.append({
                "ObjectIdentifier": f"{domain}\\{d['account']}",
                "ObjectType": "Computer",
                "Properties": {
                    "name":                    f"{d['account'].upper()}@{domain}",
                    "unconstraineddelegation":  True,
                    "dnshostname":             d.get("dns_name", ""),
                },
                "Aces": [],
            })

        # Constrained delegation
        for d in delegations.get("constrained", []):
            nodes.append({
                "ObjectIdentifier": f"{domain}\\{d['account']}",
                "ObjectType": "User",
                "Properties": {
                    "name":                f"{d['account'].upper()}@{domain}",
                    "allowedtodelegate":   d.get("allowed_to", []),
                    "trustedtoauth":       d.get("protocol_transition", False),
                },
                "Aces": [],
            })

        # RBCD targets
        for d in delegations.get("rbcd", []):
            nodes.append({
                "ObjectIdentifier": f"{domain}\\{d['target']}",
                "ObjectType": "Computer",
                "Properties": {
                    "name":        f"{d['target'].upper()}@{domain}",
                    "rbcd":        True,
                    "dnshostname": d.get("dns_name", ""),
                },
                "Aces": [],
            })

        # Hygiene findings — credential exposure
        hygiene = data.get("hygiene", {})
        for c in hygiene.get("credential_exposure", []):
            nodes.append({
                "ObjectIdentifier": f"{domain}\\{c['account']}",
                "ObjectType": "User",
                "Properties": {
                    "name":               f"{c['account'].upper()}@{domain}",
                    "credentialexposed":   True,
                    "exposurefield":       c.get("field", ""),
                    "admincount":          c.get("is_admin", False),
                },
                "Aces": [],
            })

        # Hygiene findings — SID History abuse
        for s in hygiene.get("sid_history", []):
            obj_type = "Computer" if s.get("is_computer") else "User"
            nodes.append({
                "ObjectIdentifier": f"{domain}\\{s['account']}",
                "ObjectType": obj_type,
                "Properties": {
                    "name":            f"{s['account'].upper()}@{domain}",
                    "sidhistory":      [s.get("sid_history_entry", "")],
                    "sidhistoryrisk":  s.get("risk", "MEDIUM"),
                },
                "Aces": [],
            })

        # Hygiene findings — service account hygiene issues
        for svc in hygiene.get("service_acct_hygiene", []):
            nodes.append({
                "ObjectIdentifier": f"{domain}\\{svc['account']}",
                "ObjectType": "User",
                "Properties": {
                    "name":              f"{svc['account'].upper()}@{domain}",
                    "hasspn":            True,
                    "passwordagedays":   svc.get("password_age_days"),
                    "pwdneverexpires":   svc.get("password_never_expires", False),
                    "hygienerisk":       svc.get("risk", "LOW"),
                },
                "Aces": [],
            })

        # Trust relationships
        for t in data.get("trusts", []):
            nodes.append({
                "ObjectIdentifier": f"{t.get('partner', t.get('trusted_domain', 'UNKNOWN')).upper()}",
                "ObjectType": "Domain",
                "Properties": {
                    "name":          t.get("partner", t.get("trusted_domain", "UNKNOWN")).upper(),
                    "trustdirection": t.get("direction", "Unknown"),
                    "sidfiltering":  t.get("sid_filtering", True),
                    "trustrisk":     t.get("risk", "MEDIUM"),
                },
                "Aces": [],
            })

        # Deduplicate nodes by ObjectIdentifier (keep first occurrence)
        seen = set()
        unique_nodes = []
        for node in nodes:
            oid = node["ObjectIdentifier"]
            if oid not in seen:
                seen.add(oid)
                unique_nodes.append(node)

        bh["data"]         = unique_nodes
        bh["meta"]["count"]= len(unique_nodes)

        out = Path(path)
        with out.open("w") as f:
            json.dump(bh, f, indent=2, default=_default)

        log.success(f"BloodHound JSON written → {out.resolve()} ({len(nodes)} nodes)")

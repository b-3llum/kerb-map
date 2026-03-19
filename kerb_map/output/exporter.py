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

        bh["data"]         = nodes
        bh["meta"]["count"]= len(nodes)

        out = Path(path)
        with out.open("w") as f:
            json.dump(bh, f, indent=2, default=_default)

        log.success(f"BloodHound JSON written → {out.resolve()} ({len(nodes)} nodes)")

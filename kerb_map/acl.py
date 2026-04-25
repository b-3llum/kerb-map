"""
nTSecurityDescriptor parsing helpers.

Modern AD attack paths almost all reduce to "who has dangerous ACE X
on object Y" — DCSync (DS-Replication-Get-Changes / -All on the domain
root), Shadow Credentials (WriteProperty on msDS-KeyCredentialLink),
BadSuccessor (CreateChild/WriteProperty on dMSA-allowed OUs), AdminSDHolder
ACL pins. This module wraps impacket's binary parser into something the
scanner modules can use without each one re-implementing the walk.
"""

from __future__ import annotations

from dataclasses import dataclass

from impacket.ldap.ldaptypes import (
    SR_SECURITY_DESCRIPTOR,
)
from ldap3.protocol.microsoft import security_descriptor_control

from kerb_map.ldap_helpers import sid_to_str

# ────────────────────────────────────────────────────────────────────── #
#  Well-known control rights                                             #
# ────────────────────────────────────────────────────────────────────── #


# Schema GUIDs (extended rights) we care about. All lowercase hex, no braces.
DS_REPLICATION_GET_CHANGES     = "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"
DS_REPLICATION_GET_CHANGES_ALL = "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"
DS_REPLICATION_GET_CHANGES_IN_FILTERED_SET = "89e95b76-444d-4c62-991a-0facbeda640c"

# Property-set / attribute schema GUIDs.
ATTR_KEY_CREDENTIAL_LINK = "5b47d60f-6090-40b2-9f37-2a4de88f3063"  # msDS-KeyCredentialLink
ATTR_USER_ACCOUNT_CONTROL = "bf967a68-0de6-11d0-a285-00aa003049e2"
ATTR_MEMBER               = "bf9679c0-0de6-11d0-a285-00aa003049e2"

# Object class GUIDs.
OBJECT_CLASS_USER     = "bf967aba-0de6-11d0-a285-00aa003049e2"
OBJECT_CLASS_COMPUTER = "bf967a86-0de6-11d0-a285-00aa003049e2"
OBJECT_CLASS_DMSA     = "0feb936f-47b3-49f2-9386-1dedc2c23765"  # msDS-DelegatedManagedServiceAccount


# Standard access rights (from MS-ADTS / WinNT.h)
ADS_RIGHT_GENERIC_ALL          = 0x10000000
ADS_RIGHT_GENERIC_WRITE        = 0x40000000
ADS_RIGHT_WRITE_DAC            = 0x00040000
ADS_RIGHT_WRITE_OWNER          = 0x00080000
ADS_RIGHT_DS_CONTROL_ACCESS    = 0x00000100  # extended right
ADS_RIGHT_DS_WRITE_PROP        = 0x00000020
ADS_RIGHT_DS_CREATE_CHILD      = 0x00000001
ADS_RIGHT_DS_DELETE_CHILD      = 0x00000002
ADS_RIGHT_DS_SELF              = 0x00000008

DANGEROUS_GENERIC_RIGHTS = (
    ADS_RIGHT_GENERIC_ALL
    | ADS_RIGHT_GENERIC_WRITE
    | ADS_RIGHT_WRITE_DAC
    | ADS_RIGHT_WRITE_OWNER
)


# ACE type codes
ACE_TYPE_ALLOWED         = 0x00
ACE_TYPE_ALLOWED_OBJECT  = 0x05
ACE_TYPE_DENIED          = 0x01
ACE_TYPE_DENIED_OBJECT   = 0x06


# Well-known SIDs that "should" have dangerous rights — used to filter
# out the noise so the operator only sees real misconfigurations.
WELL_KNOWN_PRIVILEGED_SIDS_SUFFIX = {
    "-512",  # Domain Admins
    "-516",  # Domain Controllers
    "-518",  # Schema Admins
    "-519",  # Enterprise Admins
    "-521",  # Read-only Domain Controllers
}
WELL_KNOWN_PRIVILEGED_SIDS_FULL = {
    "S-1-5-18",       # LocalSystem
    "S-1-5-32-544",   # BUILTIN\Administrators
    "S-1-5-9",        # Enterprise Domain Controllers
}


def is_well_known_privileged(sid: str | None) -> bool:
    """True for SIDs that are *expected* to hold powerful AD rights —
    Domain Admins, Domain Controllers, Enterprise Admins, BUILTIN
    Administrators. Everyone else with the same right is a finding."""
    if not sid:
        return False
    if sid in WELL_KNOWN_PRIVILEGED_SIDS_FULL:
        return True
    return any(sid.endswith(suffix) for suffix in WELL_KNOWN_PRIVILEGED_SIDS_SUFFIX)


# ────────────────────────────────────────────────────────────────────── #
#  LDAP control                                                          #
# ────────────────────────────────────────────────────────────────────── #


# SDFlags: 0x07 = OWNER + GROUP + DACL. We don't ask for SACL (0x10)
# because reading it requires SE_SECURITY_NAME and most operator
# accounts don't have it; asking would fail the whole search.
SD_FLAGS_OWNER_GROUP_DACL = 0x07


def sd_control(flags: int = SD_FLAGS_OWNER_GROUP_DACL) -> list:
    """LDAP control list to pass to ``conn.search`` so the DC actually
    returns the requested SD components instead of stripping them."""
    return [security_descriptor_control(criticality=True, sdflags=flags)]


# ────────────────────────────────────────────────────────────────────── #
#  ACE walker                                                            #
# ────────────────────────────────────────────────────────────────────── #


@dataclass
class AceMatch:
    """One ACE on one object that matched a caller's predicate."""

    object_dn:        str
    trustee_sid:      str
    access_mask:      int
    object_type_guid: str | None    # extended-right / property GUID, lower-case
    ace_type:         int

    def has_right(self, right: int) -> bool:
        return bool(self.access_mask & right)

    def has_extended_right(self, guid: str) -> bool:
        """True if this ACE grants the named extended right (or generic-all)."""
        if self.has_right(ADS_RIGHT_GENERIC_ALL):
            return True
        if not self.has_right(ADS_RIGHT_DS_CONTROL_ACCESS):
            return False
        if self.object_type_guid is None:
            return True  # no object-type → applies to all
        return self.object_type_guid.lower() == guid.lower()

    def has_write_property(self, attr_guid: str | None = None) -> bool:
        if self.has_right(ADS_RIGHT_GENERIC_ALL | ADS_RIGHT_GENERIC_WRITE):
            return True
        if not self.has_right(ADS_RIGHT_DS_WRITE_PROP):
            return False
        if attr_guid is None or self.object_type_guid is None:
            return True
        return self.object_type_guid.lower() == attr_guid.lower()


def parse_sd(raw: bytes | None) -> SR_SECURITY_DESCRIPTOR | None:
    """Parse a raw nTSecurityDescriptor blob. Returns None on garbage."""
    if not raw:
        return None
    try:
        sd = SR_SECURITY_DESCRIPTOR()
        sd.fromString(raw)
        return sd
    except Exception:
        return None


def walk_aces(sd: SR_SECURITY_DESCRIPTOR, object_dn: str = "") -> list[AceMatch]:
    """Yield every allowed-style ACE on ``sd`` as an ``AceMatch``.
    Skips deny ACEs — the caller almost never wants those for finding
    enumeration. Returns a list (not a generator) so callers can re-walk.
    """
    if sd is None:
        return []
    out: list[AceMatch] = []
    dacl = sd.get("Dacl")
    if dacl is None:
        return out
    for ace in dacl["Data"]:
        ace_type = ace["AceType"]
        if ace_type not in (ACE_TYPE_ALLOWED, ACE_TYPE_ALLOWED_OBJECT):
            continue
        ace_data = ace["Ace"]
        sid_obj = ace_data["Sid"]
        sid_bytes = sid_obj.getData() if hasattr(sid_obj, "getData") else bytes(sid_obj)
        sid_str = sid_to_str(sid_bytes)
        access_mask = int(ace_data["Mask"]["Mask"])
        object_guid = None
        if ace_type == ACE_TYPE_ALLOWED_OBJECT:
            # ACE_OBJECT_TYPE_PRESENT = 0x01
            flags = int(ace_data["Flags"])
            if flags & 0x01:
                guid_bytes = ace_data["ObjectType"]
                object_guid = _format_guid(bytes(guid_bytes))
        out.append(AceMatch(
            object_dn=object_dn,
            trustee_sid=sid_str or "<unknown-sid>",
            access_mask=access_mask,
            object_type_guid=object_guid,
            ace_type=ace_type,
        ))
    return out


def _format_guid(b: bytes) -> str:
    """Render a 16-byte little-endian GUID as the canonical hyphenated
    lower-case string (matches the schema GUIDs above)."""
    if len(b) != 16:
        return ""
    parts = [
        b[3::-1].hex(),                  # data1: 4 bytes, little-endian
        b[5:3:-1].hex(),                 # data2: 2 bytes, little-endian
        b[7:5:-1].hex(),                 # data3: 2 bytes, little-endian
        b[8:10].hex(),                   # data4: 2 bytes, big-endian
        b[10:16].hex(),                  # data4: 6 bytes, big-endian
    ]
    return "-".join(parts)


# ────────────────────────────────────────────────────────────────────── #
#  SID resolution                                                        #
# ────────────────────────────────────────────────────────────────────── #


def resolve_sids(ldap_client, sids: set[str], base_dn: str) -> dict[str, dict]:
    """Look up each SID in the directory and return a map
    sid → {sAMAccountName, distinguishedName, objectClass}.

    Built-in / well-known SIDs that don't live in the directory return
    a friendly name from the local table instead of an LDAP miss.
    """
    out: dict[str, dict] = {}
    queryable: list[str] = []
    for sid in sids:
        friendly = WELL_KNOWN_FRIENDLY.get(sid)
        if friendly:
            out[sid] = {"sAMAccountName": friendly, "distinguishedName": "", "objectClass": "well-known"}
        else:
            queryable.append(sid)

    if queryable:
        # Single OR-filter query — much cheaper than N round-trips.
        sid_filters = "".join(f"(objectSid={_sid_to_ldap_filter(s)})" for s in queryable)
        entries = ldap_client.query(
            search_filter=f"(|{sid_filters})",
            attributes=["sAMAccountName", "distinguishedName", "objectClass", "objectSid"],
            search_base=base_dn,
        )
        for e in entries:
            try:
                this_sid = sid_to_str(e["objectSid"].value)
                out[this_sid] = {
                    "sAMAccountName":    str(e["sAMAccountName"].value) if "sAMAccountName" in e else "",
                    "distinguishedName": str(e["distinguishedName"].value) if "distinguishedName" in e else "",
                    "objectClass":       list(e["objectClass"].values) if "objectClass" in e else [],
                }
            except Exception:
                continue

    # Anything still unresolved: include the bare SID so the operator at
    # least sees there's an unknown principal with the right.
    for sid in sids:
        out.setdefault(sid, {"sAMAccountName": sid, "distinguishedName": "", "objectClass": "unresolved"})
    return out


def _sid_to_ldap_filter(sid: str) -> str:
    """Convert an S-1-5-21-... string back into the escaped binary form
    LDAP filters need: ``\\01\\05\\00\\00...``."""
    parts = sid.split("-")
    if len(parts) < 3 or parts[0] != "S":
        return sid  # garbage in, garbage out
    revision = int(parts[1])
    auth = int(parts[2])
    sub_auths = [int(p) for p in parts[3:]]
    raw = bytes([revision, len(sub_auths)])
    raw += auth.to_bytes(6, "big")
    for sub in sub_auths:
        raw += sub.to_bytes(4, "little")
    return "".join(f"\\{b:02x}" for b in raw)


# Built-in / well-known SID → friendly name. Keep tight; the Hygiene
# Auditor and the Reporter already render these themselves elsewhere,
# but ACL output is much less readable without inline names.
WELL_KNOWN_FRIENDLY = {
    "S-1-1-0":      "Everyone",
    "S-1-5-7":      "Anonymous Logon",
    "S-1-5-9":      "Enterprise Domain Controllers",
    "S-1-5-11":     "Authenticated Users",
    "S-1-5-18":     "LocalSystem",
    "S-1-5-32-544": "BUILTIN\\Administrators",
    "S-1-5-32-545": "BUILTIN\\Users",
    "S-1-5-32-548": "BUILTIN\\Account Operators",
    "S-1-5-32-549": "BUILTIN\\Server Operators",
    "S-1-5-32-550": "BUILTIN\\Print Operators",
    "S-1-5-32-551": "BUILTIN\\Backup Operators",
    "S-1-5-32-554": "BUILTIN\\Pre-Windows 2000 Compatible Access",
}

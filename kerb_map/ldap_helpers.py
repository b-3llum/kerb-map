"""
Shared LDAP utilities. New modules should reach for these instead of
re-implementing entry parsing, time conversion, or DN handling.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

# ────────────────────────────────────────────────────────────────────── #
#  Entry attribute access                                                #
# ────────────────────────────────────────────────────────────────────── #


def attr(entry: Any, name: str, default: Any = None) -> Any:
    """Safe ``entry[name].value`` — returns ``default`` if the attribute is
    missing or any access raises. Use everywhere so a stray
    ``LDAPKeyError`` can't take down a whole module."""
    try:
        if name in entry:
            v = entry[name].value
            return v if v is not None else default
    except Exception:
        pass
    return default


def attrs(entry: Any, name: str) -> list[Any]:
    """Like ``attr`` but always returns a list — handles single-valued and
    multi-valued attributes uniformly."""
    v = attr(entry, name)
    if v is None:
        return []
    if isinstance(v, list):
        return v
    return [v]


# ────────────────────────────────────────────────────────────────────── #
#  Windows / FILETIME conversions                                        #
# ────────────────────────────────────────────────────────────────────── #


_FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)


def filetime_to_dt(value: Any) -> datetime | None:
    """Convert a Windows FILETIME (int 100-ns ticks since 1601) or an
    already-converted datetime to a UTC datetime. Returns None for 0 or
    unparseable input."""
    if value is None:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    try:
        ticks = int(value)
    except (TypeError, ValueError):
        return None
    if ticks <= 0:
        return None
    try:
        return _FILETIME_EPOCH + timedelta(microseconds=ticks // 10)
    except OverflowError:
        return None


def days_since(value: Any) -> int | None:
    """Days between ``value`` (FILETIME or datetime) and now, or None."""
    dt = filetime_to_dt(value)
    if dt is None:
        return None
    return (datetime.now(timezone.utc) - dt).days


def dt_to_filetime(dt: datetime) -> int:
    """Inverse — datetime → FILETIME ticks. Used to build LDAP filters
    against ``lastLogonTimestamp`` / ``pwdLastSet`` thresholds."""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    delta = dt - _FILETIME_EPOCH
    return int(delta.total_seconds() * 10_000_000)


# ────────────────────────────────────────────────────────────────────── #
#  DN handling                                                           #
# ────────────────────────────────────────────────────────────────────── #


def _unescape_rdn_value(value: str) -> str:
    """RFC 4514 §2.4 unescape — collapse ``\\,`` → ``,``, ``\\+`` → ``+``,
    ``\\\\`` → ``\\`` etc. Hex pairs ``\\HH`` become the byte they encode."""
    out: list[str] = []
    i = 0
    while i < len(value):
        ch = value[i]
        if ch != "\\" or i + 1 >= len(value):
            out.append(ch)
            i += 1
            continue
        nxt = value[i + 1]
        if i + 2 < len(value) and _is_hex(nxt) and _is_hex(value[i + 2]):
            try:
                out.append(bytes.fromhex(value[i + 1:i + 3]).decode("utf-8", "replace"))
                i += 3
                continue
            except ValueError:
                pass
        out.append(nxt)
        i += 2
    return "".join(out)


def _is_hex(c: str) -> bool:
    return c in "0123456789abcdefABCDEF"


def cn_from_dn(dn: str) -> str:
    """Extract the leftmost CN/OU value from a DN, handling escaped
    commas (``Smith\\, John``). Falls back to a naïve split if ldap3's
    parser is unavailable. Always returns the unescaped display value."""
    if not dn:
        return ""
    try:
        from ldap3.utils.dn import parse_dn
        rdns = parse_dn(dn)
        if rdns:
            return _unescape_rdn_value(rdns[0][1])
    except Exception:
        pass
    head = dn.split(",", 1)[0]
    if "=" in head:
        return _unescape_rdn_value(head.split("=", 1)[1])
    return head


# ────────────────────────────────────────────────────────────────────── #
#  userAccountControl bits                                               #
# ────────────────────────────────────────────────────────────────────── #


UAC = {
    "ACCOUNTDISABLE":            0x000002,
    "DONT_REQUIRE_PREAUTH":      0x400000,
    "TRUSTED_FOR_DELEGATION":    0x080000,
    "TRUSTED_TO_AUTH_FOR_DELEGATION": 0x1000000,
    "WORKSTATION_TRUST_ACCOUNT": 0x001000,
    "SERVER_TRUST_ACCOUNT":      0x002000,
    "DONT_EXPIRE_PASSWORD":      0x010000,
    "PASSWORD_EXPIRED":          0x800000,
    "USE_DES_KEY_ONLY":          0x200000,
}


def uac_has(value: Any, bit: int | str) -> bool:
    """``uac_has(entry_uac, 'DONT_REQUIRE_PREAUTH')`` or numeric bit."""
    if value is None:
        return False
    try:
        v = int(value)
    except (TypeError, ValueError):
        return False
    if isinstance(bit, str):
        bit = UAC.get(bit, 0)
    return bool(v & bit)


# ────────────────────────────────────────────────────────────────────── #
#  Domain SID helpers                                                    #
# ────────────────────────────────────────────────────────────────────── #


def sid_to_str(sid: bytes | str | None) -> str | None:
    """Render a binary SID as ``S-1-5-21-...``. Accepts bytes, strings
    that already look like SIDs, or None."""
    if sid is None:
        return None
    if isinstance(sid, str) and sid.startswith("S-"):
        return sid
    if not isinstance(sid, (bytes, bytearray)):
        return None
    if len(sid) < 8:
        return None
    revision = sid[0]
    sub_auth_count = sid[1]
    auth = int.from_bytes(sid[2:8], "big")
    parts = [f"S-{revision}-{auth}"]
    for i in range(sub_auth_count):
        start = 8 + i * 4
        if start + 4 > len(sid):
            break
        parts.append(str(int.from_bytes(sid[start:start + 4], "little")))
    return "-".join(parts)


def is_domain_sid(sid: str | None) -> bool:
    """True for a domain-or-below SID (``S-1-5-21-...``); False for
    well-known SIDs like Domain Admins-relative-id-only or builtin."""
    return bool(sid) and sid.startswith("S-1-5-21-")

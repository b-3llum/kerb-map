"""
Clock-skew detection against a target DC (field-bug fix).

Field finding (real-domain test, shibuya.jujutsu.local): kerb-map
ran an authenticated scan cleanly, then every Kerberos-dependent
follow-up step from the next_step recipes (Kerberoast, getTGT,
secretsdump --use-vss, etc.) silently failed with
``KRB_AP_ERR_SKEW(Clock skew too great)`` because the operator's
local clock was 8h59m behind the DC.

LDAP NTLM is permissive about time. Kerberos is not — Windows enforces
a default 5-minute tolerance. The tool used to scan happily, hand the
operator a recipe, then leave them confused when impacket's getST.py
failed inside their next_step.

This module probes the DC's NTP service once after bind and returns
the offset in seconds. ``KERBEROS_TOLERANCE_SECONDS = 300`` matches
the Microsoft default; CLI surfaces a loud warning + actionable fix
above that threshold.

NTP probe is the standard 48-byte SNTPv3 request (RFC 4330 §4) — no
auth header, no MS-SNTP key id. Falls back gracefully when NTP is
firewalled (returns None — caller logs an info, no warning).
"""

from __future__ import annotations

import socket
import struct
import time

NTP_PORT = 123
NTP_TIMEOUT = 3.0
NTP_EPOCH_OFFSET = 2208988800           # seconds 1900-01-01 → 1970-01-01
KERBEROS_TOLERANCE_SECONDS = 300        # Microsoft default; >300s breaks Kerberos


def query_dc_skew(dc_ip: str, *, timeout: float = NTP_TIMEOUT) -> int | None:
    """Return DC time minus local time, in seconds (positive = DC ahead).
    None if NTP didn't answer (port closed / firewalled / packet loss).

    Single round-trip — we don't sync, we just measure. Operator is
    on the hook for whatever fix they apply (faketime, sudo date,
    chrony, etc.)."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        # SNTPv3 client request: LI=0, VN=3, Mode=3 → byte 0x1b.
        sock.sendto(b"\x1b" + b"\x00" * 47, (dc_ip, NTP_PORT))
        local_recv = time.time()
        data = sock.recv(48)
    except (TimeoutError, OSError):
        return None
    finally:
        sock.close()

    if len(data) < 48:
        return None
    # Bytes 40..43 = transmit timestamp seconds (NTP epoch, big-endian).
    secs_1900 = struct.unpack("!I", data[40:44])[0]
    if not secs_1900:
        return None
    dc_unix = secs_1900 - NTP_EPOCH_OFFSET
    return int(dc_unix - local_recv)


def format_skew_warning(skew_seconds: int, *, dc_ip: str) -> str:
    """One-liner the CLI prints when skew exceeds Kerberos tolerance."""
    direction = "ahead of" if skew_seconds > 0 else "behind"
    abs_s = abs(skew_seconds)
    h, rem = divmod(abs_s, 3600)
    m, s = divmod(rem, 60)
    parts = []
    if h: parts.append(f"{h}h")
    if m: parts.append(f"{m}m")
    parts.append(f"{s}s")
    return (
        f"Clock skew with {dc_ip}: DC is {' '.join(parts)} {direction} local "
        f"(>{KERBEROS_TOLERANCE_SECONDS}s tolerance). LDAP/NTLM still works, "
        f"but every Kerberos recipe in the next_step output (Kerberoast, "
        f"getTGT, getST, secretsdump --use-vss) will fail with KRB_AP_ERR_SKEW. "
        f"Fix one of:\n"
        f"  sudo ntpdate {dc_ip}                 # one-shot sync\n"
        f"  sudo chronyd -q 'server {dc_ip} iburst'\n"
        f"  faketime '<DC time>' <impacket-cmd>  # wrapper, no root needed"
    )


def is_skew_excessive(skew_seconds: int | None) -> bool:
    """True when the skew exceeds Kerberos tolerance. None (NTP didn't
    answer) is not "excessive" — we don't have data to make a call."""
    if skew_seconds is None:
        return False
    return abs(skew_seconds) > KERBEROS_TOLERANCE_SECONDS

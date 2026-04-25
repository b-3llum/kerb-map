"""Timeroast — no-creds machine-account hash recovery (brief §4.5).

Pin the wire format and the iteration contract using a fake socket.
A regression in either would either burn cycles for no captures
(broken request packet) or silently lose hashes (broken response
parsing) — both lab-test-only failure modes that unit tests catch
much earlier.
"""

import socket
import struct
from collections import deque
from typing import Any

import pytest

from kerb_map.modules.timeroast import (
    MACHINE_ACCOUNT_FLAG,
    NTP_PORT,
    NTP_PREFIX,
    RESPONSE_LENGTH,
    TimeroastHash,
    build_request,
    parse_rid_range,
    timeroast,
)

# ────────────────────────────────────── fake socket ─


class FakeSocket:
    """Pretends to be a UDP socket. Records sendto() calls and pops
    from a queue of pre-canned responses for recvfrom(). Set a
    response to ``"timeout"`` to simulate a non-responding RID."""

    def __init__(self, responses):
        self.sent: list[tuple[bytes, tuple]] = []
        self.queue = deque(responses)
        self.closed = False

    def sendto(self, data, addr):
        self.sent.append((data, addr))

    def recvfrom(self, _bufsize):
        if not self.queue:
            raise TimeoutError("queue empty")
        item = self.queue.popleft()
        if item == "timeout":
            raise TimeoutError("simulated")
        return item, ("dc", NTP_PORT)

    def settimeout(self, _t): pass

    def close(self): self.closed = True


def _build_response(rid: int, mac: bytes = b"M" * 16,
                    ntp: bytes | None = None) -> bytes:
    """Build a 68-byte canned MS-SNTP response for the given RID."""
    ntp = ntp if ntp is not None else b"N" * 48
    key_id = struct.pack("<I", rid | MACHINE_ACCOUNT_FLAG)
    return ntp + key_id + mac


# ────────────────────────────────────── request builder ─


def test_build_request_is_68_bytes():
    """Wrong size = the DC discards the packet — no responses, silent
    failure. Pin the size."""
    assert len(build_request(1100)) == 68


def test_build_request_has_machine_flag_in_key_id():
    """Without the high bit, the DC interprets the key as a regular
    user account RID — wrong NT hash → unverifiable response."""
    pkt = build_request(1100)
    key_id = struct.unpack("<I", pkt[48:52])[0]
    assert key_id & MACHINE_ACCOUNT_FLAG
    assert (key_id & ~MACHINE_ACCOUNT_FLAG) == 1100


def test_build_request_starts_with_known_prefix():
    """The 48-byte NTP control packet prefix is the lit-from-Tervoort
    constant. Pin it so a refactor doesn't subtly drift."""
    assert build_request(1100).startswith(NTP_PREFIX)


def test_build_request_pads_zero_mac():
    """The trailing 16 bytes are zeros — we're asking the DC to fill
    in the MAC. A stale value here would hash differently and the
    cracked output would be junk."""
    assert build_request(1100)[52:68] == b"\x00" * 16


# ────────────────────────────────────── response parser ─


def test_response_round_trips_to_hashcat_format():
    """The headline output: $sntp-ms$<mac-hex>$<ntp-hex> — hashcat 31300.
    A change in this format means every captured hash from the field
    becomes uncrackable."""
    raw = _build_response(rid=1100, mac=bytes.fromhex("aa" * 16),
                          ntp=bytes.fromhex("bb" * 48))
    parsed = TimeroastHash.from_response(raw)
    assert parsed is not None
    assert parsed.rid == 1100
    assert parsed.hashcat == f"$sntp-ms${'aa' * 16}${'bb' * 48}"


def test_response_strips_machine_flag_from_displayed_rid():
    """The wire RID has the high bit set; the human-facing RID doesn't.
    Operators report 'RID 1100', not 'RID 2147484748'."""
    raw = _build_response(rid=512)
    parsed = TimeroastHash.from_response(raw)
    assert parsed.rid == 512
    # Confirm the wire form would differ.
    wire_key_id = struct.unpack("<I", raw[48:52])[0]
    assert wire_key_id != 512


def test_response_rejects_short_packet():
    """Some DCs occasionally reply with unauthenticated NTP (no MAC) —
    those are 48 bytes, not 68. Skip them rather than emitting a hash
    that has no MAC component."""
    too_short = b"\x00" * 48
    assert TimeroastHash.from_response(too_short) is None


def test_response_length_constant_matches_format():
    """If anyone changes the wire format, the constant tracks it.
    Tests fail loudly rather than silently truncating real data."""
    assert RESPONSE_LENGTH == 48 + 4 + 16


# ────────────────────────────────────── RID range parser ─


def test_parse_rid_range_pair():
    r = parse_rid_range("1000-1500")
    assert r.start == 1000
    assert r.stop  == 1501       # range is exclusive on stop


def test_parse_rid_range_single():
    """Single int is OK — operator wants exactly one RID."""
    r = parse_rid_range("500")
    assert list(r) == [500]


def test_parse_rid_range_handles_whitespace():
    r = parse_rid_range("  1000-1500  ")
    assert r.start == 1000


def test_parse_rid_range_rejects_inverted_range():
    """Start > end is operator typo, not a valid empty range. Surface
    early rather than silently skipping all RIDs."""
    with pytest.raises(ValueError):
        parse_rid_range("1500-1000")


def test_parse_rid_range_rejects_garbage():
    with pytest.raises(ValueError):
        parse_rid_range("not-a-rid")


# ────────────────────────────────────── iteration contract ─


def _no_sleep(_):
    """Patch in for time.sleep so tests run instantly."""


@pytest.fixture(autouse=True)
def fast_sleep(monkeypatch):
    """Tests should not actually wait for the rate cap."""
    import kerb_map.modules.timeroast as tm
    monkeypatch.setattr(tm.time, "sleep", _no_sleep)


def test_timeroast_yields_one_hash_per_response():
    """RIDs that get a response → emit a TimeroastHash. RIDs that
    timeout → silent skip (the typical case for non-machine RIDs)."""
    fake = FakeSocket([
        _build_response(rid=1000),
        "timeout",
        _build_response(rid=1002),
    ])
    out = list(timeroast("dc", range(1000, 1003),
                          rate=1000, timeout=0.01,
                          socket_factory=lambda: fake))
    assert len(out) == 2
    assert out[0].rid == 1000
    assert out[1].rid == 1002


def test_timeroast_sends_one_request_per_rid():
    """Even silent RIDs must get a packet — operator chose the range."""
    fake = FakeSocket(["timeout"] * 3)
    list(timeroast("dc", range(1000, 1003),
                   rate=1000, timeout=0.01,
                   socket_factory=lambda: fake))
    assert len(fake.sent) == 3
    # Each packet was the right length and hit port 123.
    for data, addr in fake.sent:
        assert len(data) == 68
        assert addr == ("dc", NTP_PORT)


def test_timeroast_closes_socket_even_on_exception():
    """Resource hygiene: KeyboardInterrupt must not leak the UDP socket.
    The CLI wraps for KeyboardInterrupt, but the helper itself shouldn't
    leave the FD dangling either way."""
    class ExplodingSocket:
        sent = []
        closed = False
        def sendto(self, *a):
            raise OSError("nic gone")
        def recvfrom(self, _): return b"", ()
        def settimeout(self, _): pass
        def close(self): ExplodingSocket.closed = True

    with pytest.raises(OSError):
        list(timeroast("dc", range(1000, 1001),
                       socket_factory=lambda: ExplodingSocket()))
    assert ExplodingSocket.closed is True


def test_timeroast_skips_malformed_responses():
    """A truncated response from a confused DC must not poison the
    output — drop it and continue with the next RID."""
    fake = FakeSocket([
        b"\x00" * 47,   # wrong length, gets dropped by parser
        _build_response(rid=1001),
    ])
    out = list(timeroast("dc", range(1000, 1002),
                          rate=1000, timeout=0.01,
                          socket_factory=lambda: fake))
    assert len(out) == 1
    assert out[0].rid == 1001

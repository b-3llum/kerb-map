"""Clock-skew detection (field bug — silent Kerberos failure mode).

Pin the SNTP packet shape, the skew calculation, the warning copy,
and the timeout-tolerant fallback. Network is mocked via socket
monkeypatch — never hits a real DC.
"""

from unittest.mock import MagicMock

import pytest

from kerb_map import time_check as tc

# ────────────────────────────────────── fake socket ─


class FakeSocket:
    """Minimal UDP socket stand-in. ``responses`` is a single bytes
    payload to deliver, or an exception class to raise on recv."""

    def __init__(self, response):
        self.response = response
        self.sent: list = []
        self.closed = False

    def settimeout(self, _t): pass
    def sendto(self, data, addr): self.sent.append((data, addr))

    def recv(self, _bufsize):
        if isinstance(self.response, type) and issubclass(self.response, BaseException):
            raise self.response("simulated")
        return self.response

    def close(self): self.closed = True


def _ntp_response(secs_since_1900: int) -> bytes:
    """Build a 48-byte SNTPv3 server reply with the transmit-timestamp
    field set. We only need bytes 40..43 to round-trip — the rest can
    be zeroes for the parser."""
    pkt = bytearray(48)
    pkt[40] = (secs_since_1900 >> 24) & 0xff
    pkt[41] = (secs_since_1900 >> 16) & 0xff
    pkt[42] = (secs_since_1900 >> 8)  & 0xff
    pkt[43] =  secs_since_1900        & 0xff
    return bytes(pkt)


@pytest.fixture
def install_socket(monkeypatch):
    """Replace socket.socket so query_dc_skew uses our fake."""
    state: dict = {"sock": None}
    def factory(family=None, type=None):
        return state["sock"]
    monkeypatch.setattr(tc.socket, "socket", lambda f, t: state["sock"])
    return state


# ────────────────────────────────────── packet shape ─


def test_query_sends_48_byte_sntpv3_request(install_socket, monkeypatch):
    """RFC 4330: client request is 48 bytes, first byte 0x1b
    (LI=0, VN=3, Mode=3=client). Wrong byte = NTP server may ignore."""
    monkeypatch.setattr(tc.time, "time", lambda: 1700000000.0)
    install_socket["sock"] = FakeSocket(_ntp_response(1700000000 + tc.NTP_EPOCH_OFFSET))
    tc.query_dc_skew("10.0.0.1")
    sent = install_socket["sock"].sent
    assert len(sent) == 1
    data, addr = sent[0]
    assert len(data)  == 48
    assert data[0]    == 0x1b
    assert data[1:48] == b"\x00" * 47
    assert addr == ("10.0.0.1", 123)


# ────────────────────────────────────── skew arithmetic ─


def test_zero_skew_when_dc_matches_local(install_socket, monkeypatch):
    """Local time = DC time → return 0. Off-by-one here would false-warn
    on every well-synced engagement."""
    monkeypatch.setattr(tc.time, "time", lambda: 1700000000.0)
    install_socket["sock"] = FakeSocket(_ntp_response(1700000000 + tc.NTP_EPOCH_OFFSET))
    assert tc.query_dc_skew("10.0.0.1") == 0


def test_positive_skew_when_dc_is_ahead(install_socket, monkeypatch):
    """DC at T+1000s, local at T → +1000."""
    monkeypatch.setattr(tc.time, "time", lambda: 1700000000.0)
    install_socket["sock"] = FakeSocket(
        _ntp_response(1700000000 + 1000 + tc.NTP_EPOCH_OFFSET)
    )
    assert tc.query_dc_skew("10.0.0.1") == 1000


def test_negative_skew_when_dc_is_behind(install_socket, monkeypatch):
    """DC at T-1000s, local at T → -1000."""
    monkeypatch.setattr(tc.time, "time", lambda: 1700000000.0)
    install_socket["sock"] = FakeSocket(
        _ntp_response(1700000000 - 1000 + tc.NTP_EPOCH_OFFSET)
    )
    assert tc.query_dc_skew("10.0.0.1") == -1000


def test_field_case_skew_8h59m_renders_correctly(install_socket, monkeypatch):
    """Reproduce the actual field finding — DC was 32398s ahead.
    A regression that mishandles the magnitude would warn for 9s
    instead of 9h, which the operator would dismiss."""
    monkeypatch.setattr(tc.time, "time", lambda: 1700000000.0)
    install_socket["sock"] = FakeSocket(
        _ntp_response(1700000000 + 32398 + tc.NTP_EPOCH_OFFSET)
    )
    skew = tc.query_dc_skew("10.10.10.10")
    assert skew == 32398
    assert tc.is_skew_excessive(skew)
    msg = tc.format_skew_warning(skew, dc_ip="10.10.10.10")
    assert "8h"   in msg
    assert "59m"  in msg
    assert "ahead" in msg
    assert "ntpdate 10.10.10.10" in msg


# ────────────────────────────────────── network failure tolerance ─


def test_timeout_returns_none_not_crash(install_socket):
    """NTP often firewalled. Don't raise — caller treats None as
    "couldn't measure, proceed quietly"."""
    install_socket["sock"] = FakeSocket(TimeoutError)
    assert tc.query_dc_skew("10.0.0.1") is None


def test_oserror_returns_none(install_socket):
    """Connection refused / network unreachable / etc."""
    install_socket["sock"] = FakeSocket(OSError)
    assert tc.query_dc_skew("10.0.0.1") is None


def test_short_packet_returns_none(install_socket, monkeypatch):
    """DC sent something but truncated — parser must reject, not
    return garbage."""
    monkeypatch.setattr(tc.time, "time", lambda: 1700000000.0)
    install_socket["sock"] = FakeSocket(b"\x00" * 40)
    assert tc.query_dc_skew("10.0.0.1") is None


def test_zero_timestamp_returns_none(install_socket, monkeypatch):
    """All-zero transmit timestamp = "server has no time" (rare but
    seen on broken NTP daemons). Treat as no-data."""
    monkeypatch.setattr(tc.time, "time", lambda: 1700000000.0)
    install_socket["sock"] = FakeSocket(_ntp_response(0))
    assert tc.query_dc_skew("10.0.0.1") is None


def test_socket_always_closed(install_socket):
    """FD hygiene — even when recv raises, close() runs."""
    install_socket["sock"] = FakeSocket(TimeoutError)
    tc.query_dc_skew("10.0.0.1")
    assert install_socket["sock"].closed is True


# ────────────────────────────────────── threshold gate ─


def test_skew_within_tolerance_not_excessive():
    """Microsoft default Kerberos tolerance is 5 minutes."""
    assert tc.is_skew_excessive(0)    is False
    assert tc.is_skew_excessive(299)  is False
    assert tc.is_skew_excessive(-299) is False
    assert tc.is_skew_excessive(300)  is False  # equal → still tolerated


def test_skew_exceeds_tolerance_in_either_direction():
    assert tc.is_skew_excessive(301)   is True
    assert tc.is_skew_excessive(-301)  is True
    assert tc.is_skew_excessive(32398) is True


def test_none_skew_is_not_excessive():
    """No measurement → can't claim excessive. Don't warn from absence."""
    assert tc.is_skew_excessive(None) is False


# ────────────────────────────────────── warning copy ─


def test_warning_includes_actionable_fixes():
    """Operator needs to know HOW to fix it, not just THAT it's broken.
    Pin the three suggested paths so a refactor doesn't drop one."""
    msg = tc.format_skew_warning(32398, dc_ip="dc.lab.local")
    assert "ntpdate"  in msg
    assert "chronyd"  in msg
    assert "faketime" in msg


def test_warning_includes_dc_ip():
    """Operator needs the IP in the recipe to copy-paste."""
    msg = tc.format_skew_warning(400, dc_ip="10.10.10.10")
    assert "10.10.10.10" in msg


def test_warning_direction_words_match_sign():
    ahead  = tc.format_skew_warning(1000,  dc_ip="dc")
    behind = tc.format_skew_warning(-1000, dc_ip="dc")
    assert "ahead"  in ahead
    assert "behind" in behind

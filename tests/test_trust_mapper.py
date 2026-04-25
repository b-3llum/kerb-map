"""Trust mapper — bit-decode trustedDomain entries into a risk-ranked list.

The risk model is the operator-facing payoff (CRITICAL forest-trust-with-
SID-filtering-OFF beats every other classification), so the assessment
ladder + bit decoding both deserve regression coverage.
"""

from unittest.mock import MagicMock

from kerb_map.modules.trust_mapper import (
    TRUST_ATTRIBUTES,
    TRUST_DIRECTION,
    TRUST_TYPE,
    DomainTrust,
    TrustMapper,
)


def _entry(values: dict):
    e = MagicMock()
    e.__contains__ = lambda self, k: k in values
    def _get(self, k):
        v = values[k]
        m = MagicMock()
        m.value = v
        m.__str__ = lambda self: "" if v is None else str(v)
        return m
    e.__getitem__ = _get
    return e


def _trust(name="OTHER.LOCAL", direction=3, ttype=2, tattrs=0):
    return _entry({
        "name":              name,
        "trustDirection":    direction,
        "trustType":         ttype,
        "trustAttributes":   tattrs,
        "securityIdentifier": None,
    })


def _ldap(entries):
    ldap = MagicMock()
    ldap.query.return_value = entries
    return ldap


# ────────────────────────────────────── _assess ladder ─


def test_forest_trust_no_sid_filter_is_critical():
    """The headline finding: forest trust + SID filtering off = SID
    history injection across the trust. The Scorer pulls this to the
    top of the priority table."""
    risk, note = TrustMapper._assess(bidir=True, forest=True,
                                     sid_filter=False, rc4=False)
    assert risk == "CRITICAL"
    assert "SID history" in note


def test_forest_trust_with_sid_filter_drops_severity():
    """When SID filtering is ON, the forest trust isn't the headline
    — the bidirectional bit pulls it to MEDIUM (still a pivot path,
    not domain takeover)."""
    risk, note = TrustMapper._assess(bidir=True, forest=True,
                                     sid_filter=True, rc4=False)
    assert risk == "MEDIUM"


def test_bidirectional_no_sid_filter_is_high():
    risk, note = TrustMapper._assess(bidir=True, forest=False,
                                     sid_filter=False, rc4=False)
    assert risk == "HIGH"
    assert "Bidirectional" in note


def test_bidirectional_with_sid_filter_is_medium():
    risk, note = TrustMapper._assess(bidir=True, forest=False,
                                     sid_filter=True, rc4=False)
    assert risk == "MEDIUM"


def test_rc4_only_no_other_flags_is_low():
    """RC4 trust without bidirectional/forest exposure is weak crypto
    but not actively exploitable from the operator's seat."""
    risk, note = TrustMapper._assess(bidir=False, forest=False,
                                     sid_filter=False, rc4=True)
    assert risk == "LOW"
    assert "RC4" in note


def test_default_trust_is_info():
    """Outbound-only trust with SID filtering is the safe baseline."""
    risk, note = TrustMapper._assess(bidir=False, forest=False,
                                     sid_filter=True, rc4=False)
    assert risk == "INFO"


# ────────────────────────────────────── bit decoding ─


def test_parse_decodes_attribute_bits():
    """Bit OR of multiple attribute bits should produce the labelled
    list — pin so a refactor doesn't drop a label."""
    # 0x4 (QUARANTINED/SID-Filter) | 0x8 (FOREST_TRANSITIVE)
    e = _trust(tattrs=0x4 | 0x8)
    t = TrustMapper(_ldap([e]))._parse(e)
    assert "QUARANTINED_DOMAIN (SID Filtering ON)" in t.attributes
    assert "FOREST_TRANSITIVE" in t.attributes
    assert t.sid_filtering is True
    assert t.is_forest_trust is True


def test_parse_unknown_direction_renders_raw_int():
    """Unknown direction integer (e.g. a future code) falls back to
    the raw string — don't crash."""
    e = _trust(direction=99)
    t = TrustMapper(_ldap([e]))._parse(e)
    assert t.direction == "99"


def test_parse_unknown_type_renders_raw_int():
    e = _trust(ttype=99)
    t = TrustMapper(_ldap([e]))._parse(e)
    assert t.trust_type == "99"


def test_parse_handles_null_attributes():
    """trustAttributes can be missing/null on weirdly-configured
    trusts — must not blow up."""
    e = _trust(tattrs=None)
    t = TrustMapper(_ldap([e]))._parse(e)
    assert t.attributes == []
    assert t.sid_filtering is False
    assert t.is_forest_trust is False


# ────────────────────────────────────── map orchestration ─


def test_map_returns_one_dataclass_per_entry():
    a = _trust(name="A.LOCAL", direction=3, tattrs=0x8)
    b = _trust(name="B.LOCAL", direction=2, tattrs=0)
    out = TrustMapper(_ldap([a, b])).map()
    assert len(out) == 2
    assert all(isinstance(t, DomainTrust) for t in out)
    assert {t.trust_partner for t in out} == {"A.LOCAL", "B.LOCAL"}


def test_map_empty_when_no_trusts():
    """Single-domain forest with no trusts → empty list, not crash."""
    assert TrustMapper(_ldap([])).map() == []


def test_map_uses_correct_ldap_filter():
    """Pin the filter — drift here would query the wrong objectClass
    and silently return empty."""
    ldap = _ldap([])
    TrustMapper(ldap).map()
    captured = ldap.query.call_args.kwargs
    assert "(objectClass=trustedDomain)" in captured["search_filter"]


# ────────────────────────────────────── label tables ─


def test_trust_direction_labels_cover_known_codes():
    """If MS adds a new direction code we want to see the raw int
    in the output (covered above), but the existing four must stay
    pinned."""
    assert TRUST_DIRECTION[0] == "DISABLED"
    assert "INBOUND"  in TRUST_DIRECTION[1]
    assert "OUTBOUND" in TRUST_DIRECTION[2]
    assert TRUST_DIRECTION[3] == "BIDIRECTIONAL"


def test_trust_attribute_bits_cover_sid_filter_and_forest():
    """The two bits that drive risk classification — pin them so a
    rename or value drift would surface immediately."""
    assert TRUST_ATTRIBUTES[0x4] == "QUARANTINED_DOMAIN (SID Filtering ON)"
    assert TRUST_ATTRIBUTES[0x8] == "FOREST_TRANSITIVE"


def test_trust_type_labels_cover_uplevel_and_mit():
    assert "UPLEVEL"  in TRUST_TYPE[2]
    assert "MIT"      in TRUST_TYPE[3]

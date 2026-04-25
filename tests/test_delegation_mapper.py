"""Delegation mapper — three Kerberos-delegation flavours.

The output dict shape is what scorer.py / reporter.py / BloodHound CE
all consume, so the contract for the keys (account / type / detail /
next_step / target / dns_name / allowed_to / protocol_transition)
deserves regression coverage.
"""

from unittest.mock import MagicMock

from kerb_map.modules.delegation_mapper import DelegationMapper


def _entry(values: dict):
    e = MagicMock()
    e.__contains__ = lambda self, k: k in values
    def _get(self, k):
        v = values[k]
        m = MagicMock()
        m.value = v
        m.__str__ = lambda self: "" if v is None else str(v)
        m.__iter__ = lambda self: iter(v) if isinstance(v, list) else iter([v])
        m.__bool__ = lambda self: bool(v)
        return m
    e.__getitem__ = _get
    e.get = lambda k, default=None: e[k] if k in values else default
    return e


def _ldap(unconstr=(), constr=(), rbcd=()):
    """Three queries fire in order: unconstrained, constrained, rbcd."""
    ldap = MagicMock()
    queue = [list(unconstr), list(constr), list(rbcd)]
    ldap.query.side_effect = lambda **_: queue.pop(0)
    return ldap


# ────────────────────────────────────── unconstrained ─


def test_unconstrained_computer_account_renders_correctly():
    """Account ending in '$' → type=Computer; recipe references the
    DNS hostname for SpoolSample-style coercion."""
    e = _entry({
        "sAMAccountName":   "WEB01$",
        "operatingSystem":  "Windows Server 2019",
        "dNSHostName":      "web01.corp.local",
        "primaryGroupID":   515,
    })
    out = DelegationMapper(_ldap(unconstr=[e])).map_all()
    u = out["unconstrained"]
    assert len(u) == 1
    assert u[0]["account"]  == "WEB01$"
    assert u[0]["type"]     == "Computer"
    assert u[0]["dns_name"] == "web01.corp.local"
    assert "Server 2019" in u[0]["os"]
    assert "TGT" in u[0]["detail"]
    assert "SpoolSample" in u[0]["next_step"]


def test_unconstrained_user_account_typed_user():
    """Non-$ account → type=User. Operator filters on this when
    deciding which recipe to use."""
    e = _entry({
        "sAMAccountName":   "svc_legacy",
        "operatingSystem":  None,
        "dNSHostName":      None,
        "primaryGroupID":   513,
    })
    out = DelegationMapper(_ldap(unconstr=[e])).map_all()
    assert out["unconstrained"][0]["type"] == "User"


def test_unconstrained_filter_excludes_dcs_and_disabled():
    """0x80000 = TRUSTED_FOR_DELEGATION, but DCs (primaryGroupID=516)
    have it set by design and disabled accounts can't auth — both
    excluded so the operator only sees actionable targets."""
    ldap = _ldap()
    DelegationMapper(ldap).map_all()
    f = ldap.query.call_args_list[0].kwargs["search_filter"]
    assert ":1.2.840.113556.1.4.803:=524288" in f      # TRUSTED_FOR_DELEGATION
    assert "(!(primaryGroupID=516))"            in f   # DCs out
    assert ":1.2.840.113556.1.4.803:=2"         in f   # disabled mention (negated)


def test_unconstrained_handles_missing_optional_attrs():
    """operatingSystem / dNSHostName missing on the entry → strings
    default rather than crash."""
    e = _entry({
        "sAMAccountName":   "PRINTER$",
        "primaryGroupID":   515,
    })
    out = DelegationMapper(_ldap(unconstr=[e])).map_all()
    u = out["unconstrained"][0]
    assert u["dns_name"] == ""
    assert u["os"]       == "unknown"


# ────────────────────────────────────── constrained ─


def test_constrained_with_protocol_transition_flagged():
    """0x1000000 = TRUSTED_TO_AUTH_FOR_DELEGATION → S4U2Self →
    impersonate any user. The 'protocol_transition: True' flag is
    what scorer.py uses to bump severity to HIGH."""
    e = _entry({
        "sAMAccountName":             "svc_app",
        "msDS-AllowedToDelegateTo":   ["HTTP/web.corp.local", "HTTP/api.corp.local"],
        "userAccountControl":         0x1000000,
    })
    out = DelegationMapper(_ldap(constr=[e])).map_all()
    c = out["constrained"][0]
    assert c["account"] == "svc_app"
    assert c["protocol_transition"] is True
    assert "S4U2Self" in c["detail"]
    assert "getST.py" in c["next_step"]
    assert "HTTP/web.corp.local" in c["next_step"]


def test_constrained_without_protocol_transition_distinct():
    """No 0x1000000 bit → standard constrained delegation. Detail
    text drops the S4U2Self mention so the operator doesn't think
    they have impersonation."""
    e = _entry({
        "sAMAccountName":             "svc_app",
        "msDS-AllowedToDelegateTo":   ["MSSQL/db.corp.local"],
        "userAccountControl":         0x0,
    })
    out = DelegationMapper(_ldap(constr=[e])).map_all()
    c = out["constrained"][0]
    assert c["protocol_transition"] is False
    assert "S4U2Self" not in c["detail"]


def test_constrained_with_no_targets_renders_empty_recipe():
    """Edge: msDS-AllowedToDelegateTo present but empty list. Don't
    crash on empty allowed_to[0] indexing."""
    e = _entry({
        "sAMAccountName":             "broken_svc",
        "msDS-AllowedToDelegateTo":   [],
        "userAccountControl":         0x0,
    })
    out = DelegationMapper(_ldap(constr=[e])).map_all()
    assert out["constrained"][0]["next_step"] == ""
    assert out["constrained"][0]["allowed_to"] == []


# ────────────────────────────────────── RBCD ─


def test_rbcd_target_uses_sam_not_dn():
    """scorer.py reads d['target'] — pin that key. (Old dataclass
    used 'target_account', drift here would silently lose RBCD
    findings from the priority table.)"""
    e = _entry({
        "sAMAccountName": "FILE01$",
        "dNSHostName":    "file01.corp.local",
    })
    out = DelegationMapper(_ldap(rbcd=[e])).map_all()
    r = out["rbcd"][0]
    assert r["target"]   == "FILE01$"
    assert r["dns_name"] == "file01.corp.local"
    assert "RBCD" in r["detail"]
    assert "addcomputer.py" in r["next_step"]
    assert "FAKE$" in r["next_step"]


def test_rbcd_handles_missing_dnshostname():
    """Computer with no dNSHostName → recipe falls back to SAM."""
    e = _entry({
        "sAMAccountName": "OLDFILE$",
    })
    out = DelegationMapper(_ldap(rbcd=[e])).map_all()
    r = out["rbcd"][0]
    assert r["dns_name"] == ""
    assert "OLDFILE$" in r["next_step"]


def test_rbcd_uses_aaba_filter():
    """msDS-AllowedToActOnBehalfOfOtherIdentity is the canonical RBCD
    attribute. Pin the filter."""
    ldap = _ldap()
    DelegationMapper(ldap).map_all()
    f = ldap.query.call_args_list[2].kwargs["search_filter"]
    assert "msDS-AllowedToActOnBehalfOfOtherIdentity=*" in f


# ────────────────────────────────────── orchestration ─


def test_map_all_returns_three_keyed_buckets():
    """The dict shape is the contract — scorer.py and reporter.py
    both call delegations.get('unconstrained', []), etc."""
    out = DelegationMapper(_ldap()).map_all()
    assert set(out.keys()) == {"unconstrained", "constrained", "rbcd"}
    assert all(isinstance(v, list) for v in out.values())


def test_empty_domain_returns_empty_buckets():
    """Single-purpose service estate with no delegation → all three
    lists empty, no crash."""
    out = DelegationMapper(_ldap()).map_all()
    assert out["unconstrained"] == []
    assert out["constrained"]   == []
    assert out["rbcd"]          == []

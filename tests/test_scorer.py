"""Scorer cross-correlates findings into a unified ranked attack list.

Every input source has its own branch; this module is mostly that
ladder of conditional translations. The tests pin two contracts:

  1. Each input source produces the right (target, attack, severity,
     priority, category) shape — a regression here would silently
     mis-rank findings in the operator's report.
  2. The dedup-and-sort tail keeps higher-priority entries when two
     sources flag the same (target, attack) — operators only see one
     line per attack path.
"""

from types import SimpleNamespace

import pytest

from kerb_map.modules.scorer import Scorer

# ────────────────────────────────────── helpers ─


def _empty_inputs():
    """Minimal kwargs for Scorer.rank — every list empty so individual
    tests only have to fill in the bucket they care about."""
    return {
        "spns":         [],
        "asrep":        [],
        "delegations":  {"unconstrained": [], "constrained": [], "rbcd": []},
        "cve_results":  [],
        "user_data":    {},
        "enc_audit":    None,
        "trusts":       None,
        "hygiene":      None,
    }


def _by_attack(targets, prefix):
    return [t for t in targets if t["attack"].startswith(prefix)]


# ────────────────────────────────────── _score_to_sev ─


@pytest.mark.parametrize("score,expected", [
    (100, "CRITICAL"),
    (80,  "CRITICAL"),
    (79,  "HIGH"),
    (60,  "HIGH"),
    (59,  "MEDIUM"),
    (40,  "MEDIUM"),
    (39,  "LOW"),
    (0,   "LOW"),
])
def test_score_to_sev_boundaries(score, expected):
    """Severity bucketing is the report's colour mapping. A boundary
    drift would silently re-class findings (e.g. score=80 → HIGH not
    CRITICAL would hide a real CRITICAL from the operator's eye)."""
    assert Scorer()._score_to_sev(score) == expected


# ────────────────────────────────────── _spn_reason ─


def test_spn_reason_default_when_no_flags():
    assert Scorer()._spn_reason({}) == "Standard SPN account"


def test_spn_reason_concatenates_every_flag():
    spn = {"rc4_allowed": True, "password_age_days": 800,
           "is_admin": True, "never_logged_in": True}
    out = Scorer()._spn_reason(spn)
    assert "RC4 allowed"           in out
    assert "800d"                  in out
    assert "ADMIN GROUP MEMBER"    in out
    assert "never logged in"       in out


def test_spn_reason_age_threshold_is_one_year():
    """Password age <= 365 days is not surprising on enterprise hosts —
    don't include it in the reason."""
    young = Scorer()._spn_reason({"password_age_days": 365})
    old   = Scorer()._spn_reason({"password_age_days": 366})
    assert "365d" not in young
    assert "366d" in old


# ────────────────────────────────────── SPN bucket ─


def test_spn_emits_kerberoast_target():
    spn = {"account": "svc_sql", "crack_score": 85,
           "rc4_allowed": True, "is_admin": False}
    out = Scorer().rank(spns=[spn], **{k: v for k, v in _empty_inputs().items() if k != "spns"})
    krb = _by_attack(out, "Kerberoast")
    assert len(krb) == 1
    assert krb[0]["target"]   == "svc_sql"
    assert krb[0]["severity"] == "CRITICAL"
    assert krb[0]["priority"] == 85
    assert "svc_sql.hash" in krb[0]["next_step"]
    assert krb[0]["category"] == "kerberos"


# ────────────────────────────────────── AS-REP bucket ─


def test_asrep_admin_is_critical():
    user = {"account": "oldsvc", "crack_score": 70, "is_admin": True}
    args = _empty_inputs()
    args["asrep"] = [user]
    out = Scorer().rank(**args)
    asrep = _by_attack(out, "AS-REP Roast")
    assert len(asrep) == 1
    assert asrep[0]["severity"] == "CRITICAL"
    assert "[ADMIN]" in asrep[0]["reason"]


def test_asrep_non_admin_is_high():
    user = {"account": "joe", "crack_score": 50, "is_admin": False}
    args = _empty_inputs()
    args["asrep"] = [user]
    out = Scorer().rank(**args)
    assert out[0]["severity"] == "HIGH"
    assert "[ADMIN]" not in out[0]["reason"]


# ────────────────────────────────────── Delegation buckets ─


def test_unconstrained_delegation_is_critical_priority_95():
    args = _empty_inputs()
    args["delegations"]["unconstrained"] = [{
        "account": "WEB01$", "detail": "TRUSTED_FOR_DELEGATION",
        "next_step": "tgsrelay magic",
    }]
    out = Scorer().rank(**args)
    assert out[0]["attack"].startswith("Unconstrained Delegation")
    assert out[0]["priority"] == 95
    assert out[0]["severity"] == "CRITICAL"


def test_constrained_with_protocol_transition_is_high():
    """S4U2Self + S4U2Proxy = the operator can act as anyone. Without
    protocol_transition it's the cheaper variant we don't surface."""
    args = _empty_inputs()
    args["delegations"]["constrained"] = [
        {"account": "svc_a", "protocol_transition": True,
         "detail": "S4U2Self", "next_step": "..."},
        {"account": "svc_b", "protocol_transition": False,
         "detail": "no PT",  "next_step": "..."},
    ]
    out = Scorer().rank(**args)
    cd = _by_attack(out, "Constrained Delegation")
    assert len(cd) == 1
    assert cd[0]["target"] == "svc_a"


def test_rbcd_emits_target_with_high_severity():
    args = _empty_inputs()
    args["delegations"]["rbcd"] = [{
        "target": "FILE01", "detail": "AllowedToActOnBehalfOf",
        "next_step": "rbcd attack",
    }]
    out = Scorer().rank(**args)
    rbcd = _by_attack(out, "RBCD")
    assert rbcd[0]["target"]   == "FILE01"
    assert rbcd[0]["severity"] == "HIGH"
    assert rbcd[0]["priority"] == 70


# ────────────────────────────────────── CVE bucket ─


def _cve(name="ZeroLogon", cve_id="CVE-2020-1472", severity="CRITICAL",
         vulnerable=True, reason="...", next_step="cmd1\ncmd2"):
    """Quack like a CVEResult — scorer reads .name / .cve_id /
    .severity.value / .vulnerable / .reason / .next_step."""
    return SimpleNamespace(
        name=name, cve_id=cve_id, vulnerable=vulnerable,
        severity=SimpleNamespace(value=severity),
        reason=reason, next_step=next_step,
    )


def test_cve_only_vulnerable_findings_promoted():
    """Non-vulnerable CVE results are still part of the report but
    don't flow into the priority list — that's the dedicated CVE
    table's job."""
    args = _empty_inputs()
    args["cve_results"] = [_cve(vulnerable=False), _cve(vulnerable=True)]
    out = Scorer().rank(**args)
    cves = _by_attack(out, "ZeroLogon")
    assert len(cves) == 1


def test_cve_severity_maps_to_priority():
    """CRITICAL=98, HIGH=85, MEDIUM=60, anything else=50. The mapping
    is what makes vulnerable CVEs jump to the top."""
    args = _empty_inputs()
    args["cve_results"] = [
        _cve(name="A", cve_id="CVE-1", severity="CRITICAL"),
        _cve(name="B", cve_id="CVE-2", severity="HIGH"),
        _cve(name="C", cve_id="CVE-3", severity="MEDIUM"),
        _cve(name="D", cve_id="CVE-4", severity="LOW"),
    ]
    out = Scorer().rank(**args)
    pr = {t["attack"].split(" (")[0]: t["priority"] for t in out}
    assert pr["A"] == 98
    assert pr["B"] == 85
    assert pr["C"] == 60
    assert pr["D"] == 50


def test_cve_next_step_is_first_line_only():
    """The priority table is a one-liner per finding — multi-line
    next_step would explode the table layout."""
    args = _empty_inputs()
    args["cve_results"] = [_cve(next_step="line one\nline two\nline three")]
    out = Scorer().rank(**args)
    assert out[0]["next_step"] == "line one"


def test_cve_empty_next_step_does_not_crash():
    args = _empty_inputs()
    args["cve_results"] = [_cve(next_step="")]
    out = Scorer().rank(**args)
    assert out[0]["next_step"] == ""


# ────────────────────────────────────── user_data buckets ─


def test_password_policy_lockout_risk_promoted_to_spray_target():
    args = _empty_inputs()
    args["user_data"] = {"password_policy": {"risks": ["No lockout configured"]}}
    out = Scorer().rank(**args)
    spray = _by_attack(out, "Password Spray")
    assert len(spray) == 1
    assert spray[0]["severity"] == "CRITICAL"


def test_password_policy_non_lockout_risks_ignored():
    """Only lockout-flavoured risks become spray candidates here. Other
    policy risks land in the hygiene section, not priority targets."""
    args = _empty_inputs()
    args["user_data"] = {"password_policy": {"risks": ["weak min length"]}}
    out = Scorer().rank(**args)
    assert _by_attack(out, "Password Spray") == []


def test_dns_admins_become_dnsadmin_targets():
    args = _empty_inputs()
    args["user_data"] = {"dns_admins": [
        {"account": "dnsadm", "detail": "member of DnsAdmins"},
    ]}
    out = Scorer().rank(**args)
    da = _by_attack(out, "DnsAdmins")
    assert da[0]["target"]   == "dnsadm"
    assert da[0]["priority"] == 88


def test_high_risk_trust_in_user_data_promoted():
    args = _empty_inputs()
    args["user_data"] = {"trusts": [
        {"trusted_domain": "OTHER.LOCAL", "risk": "HIGH",
         "detail": "SID filtering disabled"},
    ]}
    out = Scorer().rank(**args)
    trust = _by_attack(out, "Trust Abuse")
    assert trust[0]["target"] == "OTHER.LOCAL"


def test_low_risk_trust_in_user_data_ignored():
    """Operator-noise filter: only HIGH-risk trusts surface here."""
    args = _empty_inputs()
    args["user_data"] = {"trusts": [
        {"trusted_domain": "OK.LOCAL", "risk": "LOW", "detail": "..."},
    ]}
    out = Scorer().rank(**args)
    assert _by_attack(out, "Trust Abuse") == []


# ────────────────────────────────────── encryption / trusts / hygiene ─


def test_encryption_audit_emits_weak_dc_and_des_findings():
    args = _empty_inputs()
    args["enc_audit"] = SimpleNamespace(
        weak_dcs=[SimpleNamespace(account="DC01$", enc_types=["RC4"])],
        des_accounts=[SimpleNamespace(account="legacy", enc_types=["DES-CBC-MD5"])],
        rc4_only_accounts=[],
    )
    out = Scorer().rank(**args)
    assert _by_attack(out, "Weak DC Encryption")
    assert _by_attack(out, "DES Encryption")


def test_des_accounts_capped_at_5_lines():
    """Operator-noise cap: more than 5 DES accounts means a noisy estate
    where we'd swamp the priority list. Cap so the high-impact items
    stay visible."""
    args = _empty_inputs()
    args["enc_audit"] = SimpleNamespace(
        weak_dcs=[],
        des_accounts=[SimpleNamespace(account=f"u{i}", enc_types=["DES"])
                      for i in range(10)],
        rc4_only_accounts=[],
    )
    out = Scorer().rank(**args)
    assert len(_by_attack(out, "DES Encryption")) == 5


def test_critical_trust_from_trustmapper_promoted():
    args = _empty_inputs()
    args["trusts"] = [SimpleNamespace(
        trust_partner="EVIL.LOCAL", direction="bidirectional",
        risk="CRITICAL", note="SID filtering off",
    )]
    out = Scorer().rank(**args)
    t = _by_attack(out, "Trust Abuse")
    assert t[0]["priority"] == 90


def test_low_risk_trust_from_trustmapper_skipped():
    args = _empty_inputs()
    args["trusts"] = [SimpleNamespace(
        trust_partner="OK.LOCAL", direction="outbound",
        risk="LOW", note="...",
    )]
    out = Scorer().rank(**args)
    assert _by_attack(out, "Trust Abuse") == []


def _hygiene(**overrides):
    """Default empty hygiene; tests fill in the field they exercise."""
    return SimpleNamespace(**{
        "sid_history":         [],
        "krbtgt_age":          {},
        "credential_exposure": [],
        "primary_group_abuse": [],
        "laps_coverage":       {},
        "stale_computers":     [],
        "privileged_groups":   {},
        "service_acct_hygiene":[],
        **overrides,
    })


def test_hygiene_critical_sid_history_promoted():
    args = _empty_inputs()
    args["hygiene"] = _hygiene(sid_history=[
        {"account": "svc_a", "risk": "CRITICAL", "detail": "same-domain SID history"},
    ])
    out = Scorer().rank(**args)
    assert _by_attack(out, "SID History")


def test_hygiene_stale_krbtgt_promoted_with_severity_priority_split():
    args = _empty_inputs()
    args["hygiene"] = _hygiene(krbtgt_age={
        "risk": "CRITICAL", "detail": "krbtgt 2 years old",
    })
    out = Scorer().rank(**args)
    g = _by_attack(out, "Golden Ticket")
    assert g[0]["priority"] == 92
    assert g[0]["severity"] == "CRITICAL"


def test_hygiene_credential_exposure_admin_higher_priority():
    """Admin accounts with creds in description = pre-owned; non-admin
    is still bad but lower priority. The 90 vs 72 split has to hold."""
    args = _empty_inputs()
    args["hygiene"] = _hygiene(credential_exposure=[
        {"account": "admin",  "is_admin": True,  "field": "description",
         "risk": "CRITICAL", "detail": "..."},
        {"account": "joe",    "is_admin": False, "field": "info",
         "risk": "HIGH",     "detail": "..."},
    ])
    out = Scorer().rank(**args)
    by_target = {t["target"]: t for t in _by_attack(out, "Credential in AD")}
    assert by_target["admin"]["priority"] == 90
    assert by_target["joe"]["priority"]   == 72


def test_hygiene_laps_critical_promoted():
    args = _empty_inputs()
    args["hygiene"] = _hygiene(laps_coverage={
        "risk": "CRITICAL", "detail": "0% of workstations have LAPS",
    })
    out = Scorer().rank(**args)
    assert _by_attack(out, "No LAPS")


# ────────────────────────────────────── sort + dedup ─


def test_targets_sorted_by_priority_descending():
    args = _empty_inputs()
    args["spns"] = [
        {"account": "low",  "crack_score": 30, "is_admin": False},
        {"account": "high", "crack_score": 95, "is_admin": True},
        {"account": "mid",  "crack_score": 60, "is_admin": False},
    ]
    out = Scorer().rank(**args)
    priorities = [t["priority"] for t in out]
    assert priorities == sorted(priorities, reverse=True)


def test_dedup_keeps_first_occurrence_of_target_attack_pair():
    """If two sources flag the same (target, attack) — e.g. SID History
    in user_data AND hygiene — the operator should see one line, not
    two. Pin the behaviour: first wins (which means highest-priority
    after the sort)."""
    args = _empty_inputs()
    args["delegations"]["unconstrained"] = [
        {"account": "WEB01$", "detail": "first",  "next_step": "1"},
        {"account": "WEB01$", "detail": "second", "next_step": "2"},
    ]
    out = Scorer().rank(**args)
    web = _by_attack(out, "Unconstrained Delegation")
    assert len(web) == 1


def test_empty_inputs_returns_empty_list():
    """Defensive: a clean estate still returns [], not a crash."""
    assert Scorer().rank(**_empty_inputs()) == []

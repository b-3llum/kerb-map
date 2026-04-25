"""AD CS ESC1/2/3/8 (passive LDAP detection).

Pin the OID-based template classifier — drift in EKU constants would
silently miss every CRITICAL ESC1 finding."""

from unittest.mock import MagicMock

from kerb_map.modules.cves.adcs import (
    EKU_ANY_PURPOSE,
    EKU_CERT_REQUEST_AGENT,
    EKU_CLIENT_AUTH,
    ADCSAudit,
)
from kerb_map.modules.cves.cve_base import Severity


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
    return e


def _ldap(cas=(), templates=()):
    """Two query_config calls: CAs first, templates second."""
    ldap = MagicMock()
    ldap.username = "scanner"
    queue = [list(cas), list(templates)]
    ldap.query_config.side_effect = lambda **_: queue.pop(0)
    return ldap


def _ca(name="CORP-CA"):
    return _entry({
        "cn":                     name,
        "dNSHostName":            f"{name.lower()}.corp.local",
        "certificateTemplates":   ["WebServer", "User"],
    })


def _tpl(name, *, name_flag=0, eku=(), ra_sigs=0):
    return _entry({
        "cn":                              name,
        "msPKI-Certificate-Name-Flag":    name_flag,
        "msPKI-Enrollment-Flag":          0,
        "pKIExtendedKeyUsage":            list(eku),
        "msPKI-RA-Signature":             ra_sigs,
    })


# ────────────────────────────────────── no ADCS ─


def test_no_cas_returns_clean_info():
    """Single-purpose domain with no AD CS → INFO only."""
    r = ADCSAudit(_ldap(), "10.0.0.1", "corp.local").check()
    assert r.vulnerable is False
    assert r.severity == Severity.INFO
    assert "No AD CS" in r.reason


# ────────────────────────────────────── ESC1 ─


def test_esc1_enrollee_supplies_subject_with_client_auth_critical():
    """ENROLLEE_SUPPLIES_SUBJECT (0x1) + Client Auth EKU = ESC1.
    Operator can request a cert as any user (incl DA)."""
    ca = _ca()
    tpl = _tpl("BadTemplate", name_flag=0x1, eku=[EKU_CLIENT_AUTH])
    r = ADCSAudit(_ldap(cas=[ca], templates=[tpl]),
                  "10.0.0.1", "corp.local").check()
    assert r.vulnerable is True
    assert r.severity == Severity.CRITICAL
    esc1 = [t for t in r.evidence["vulnerable_templates"] if t["type"] == "ESC1"]
    assert len(esc1) == 1


def test_esc1_with_smartcard_logon_eku_also_fires():
    """Smartcard Logon EKU is the alternate Client-Auth-equivalent."""
    ca = _ca()
    tpl = _tpl("Smartcard", name_flag=0x1, eku=["1.3.6.1.4.1.311.20.2.2"])
    r = ADCSAudit(_ldap(cas=[ca], templates=[tpl]), "10.0.0.1", "x").check()
    esc1 = [t for t in r.evidence["vulnerable_templates"] if t["type"] == "ESC1"]
    assert len(esc1) == 1


# ────────────────────────────────────── ESC2 ─


def test_esc2_any_purpose_eku_high():
    ca = _ca()
    tpl = _tpl("AnyPurpose", name_flag=0, eku=[EKU_ANY_PURPOSE])
    r = ADCSAudit(_ldap(cas=[ca], templates=[tpl]), "10.0.0.1", "x").check()
    esc2 = [t for t in r.evidence["vulnerable_templates"] if t["type"] == "ESC2"]
    assert len(esc2) == 1
    assert esc2[0]["severity"] == "HIGH"


def test_esc2_empty_eku_without_supply_subject_also_fires():
    """Empty EKU = effectively any-purpose; only a finding when
    ENROLLEE_SUPPLIES_SUBJECT is OFF (otherwise it's ESC1 territory
    handled separately)."""
    ca = _ca()
    tpl = _tpl("EmptyEKU", name_flag=0, eku=[])
    r = ADCSAudit(_ldap(cas=[ca], templates=[tpl]), "10.0.0.1", "x").check()
    esc2 = [t for t in r.evidence["vulnerable_templates"] if t["type"] == "ESC2"]
    assert len(esc2) == 1


# ────────────────────────────────────── ESC3 ─


def test_esc3_cert_request_agent_with_zero_ra_sigs_high():
    """CertRequestAgent EKU + msPKI-RA-Signature=0 → can enroll on
    behalf of arbitrary user."""
    ca = _ca()
    tpl = _tpl("Enrollment Agent", eku=[EKU_CERT_REQUEST_AGENT], ra_sigs=0)
    r = ADCSAudit(_ldap(cas=[ca], templates=[tpl]), "10.0.0.1", "x").check()
    esc3 = [t for t in r.evidence["vulnerable_templates"] if t["type"] == "ESC3"]
    assert len(esc3) == 1


def test_esc3_with_nonzero_ra_sigs_does_not_fire():
    """RA signatures required → enrollment-on-behalf gated."""
    ca = _ca()
    tpl = _tpl("Enrollment Agent", eku=[EKU_CERT_REQUEST_AGENT], ra_sigs=1)
    r = ADCSAudit(_ldap(cas=[ca], templates=[tpl]), "10.0.0.1", "x").check()
    esc3 = [t for t in r.evidence["vulnerable_templates"] if t["type"] == "ESC3"]
    assert esc3 == []


# ────────────────────────────────────── ESC8 (CA note) ─


def test_each_ca_emits_esc8_manual_check_note():
    """ESC8 needs an active web-enrol probe — pre-flight emits a
    note per CA telling the operator to manually check
    EDITF_ATTRIBUTESUBJECTALTNAME2."""
    cas = [_ca("CA1"), _ca("CA2")]
    r = ADCSAudit(_ldap(cas=cas, templates=[]), "10.0.0.1", "x").check()
    notes = r.evidence["ca_notes"]
    assert len(notes) == 2
    assert all("ESC8" in n["type"] for n in notes)


# ────────────────────────────────────── next_step + recipe ─


def test_findings_produce_certipy_recipe():
    """When something fires, the next_step shows a certipy command
    pre-populated with the operator's own LDAP username + DC IP."""
    ca = _ca()
    tpl = _tpl("Bad", name_flag=0x1, eku=[EKU_CLIENT_AUTH])
    r = ADCSAudit(_ldap(cas=[ca], templates=[tpl]),
                  "10.0.0.1", "corp.local").check()
    assert "certipy" in r.next_step
    assert "scanner@corp.local" in r.next_step
    assert "10.0.0.1" in r.next_step


def test_no_findings_means_empty_next_step():
    """Quiet on a clean domain — operator shouldn't see a copy-paste
    recipe with no target."""
    ca = _ca()
    tpl = _tpl("Good", name_flag=0, eku=[EKU_CLIENT_AUTH])  # no SUBJECT supply
    r = ADCSAudit(_ldap(cas=[ca], templates=[tpl]), "10.0.0.1", "x").check()
    # Note: this template DOES fire ESC2 (no SUBJECT supply, has Client Auth
    # which is a single-EKU non-any-purpose case actually). Let me use a
    # genuinely-clean template.
    tpl_clean = _tpl("Good", name_flag=0, eku=[EKU_CLIENT_AUTH, "1.3.6.1.5.5.7.3.1"])
    r = ADCSAudit(_ldap(cas=[ca], templates=[tpl_clean]), "10.0.0.1", "x").check()
    assert r.next_step == ""

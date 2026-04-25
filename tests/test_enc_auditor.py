"""Encryption auditor — RC4-only accounts and weak-cipher DCs.

The bit decoder powers the operator-facing labels and the RC4-only
classification (which kerb-map uses to flag fast-cracking targets),
so its quirks deserve regression coverage.
"""

from unittest.mock import MagicMock

from kerb_map.modules.enc_auditor import (
    ENC_TYPES,
    EncAuditor,
    EncAuditResults,
    WeakEncAccount,
)


def _entry(sam, enc):
    e = MagicMock()
    e.__contains__ = lambda self, k: k in {"sAMAccountName", "msDS-SupportedEncryptionTypes"}
    def _get(self, k):
        v = sam if k == "sAMAccountName" else enc
        m = MagicMock()
        m.value = v
        m.__str__ = lambda self: str(v) if v is not None else ""
        return m
    e.__getitem__ = _get
    return e


def _ldap(user_entries, dc_entries):
    """Two queries: users (with msDS-SupportedEncryptionTypes set), then DCs."""
    ldap = MagicMock()
    queue = [user_entries, dc_entries]
    ldap.query.side_effect = lambda **_: queue.pop(0)
    return ldap


# ────────────────────────────────────── _parse_enc ─


def test_parse_enc_zero_means_default_rc4():
    """msDS-SupportedEncryptionTypes=0 means "no explicit restriction"
    which AD treats as RC4-HMAC by default. The label has to make that
    history visible — operators looking at "0" alone wouldn't know."""
    out = EncAuditor._parse_enc(0)
    assert len(out) == 1
    assert "RC4" in out[0]
    assert "default" in out[0]


def test_parse_enc_decodes_aes_combined_bit():
    """0x18 is the AES (128+256) shorthand bit — the table maps it as
    one label rather than expanding to AES128+AES256, so a single
    'AES (128+256)' line shows in the operator table."""
    out = EncAuditor._parse_enc(0x18)
    assert "AES (128+256)" in out


def test_parse_enc_decodes_individual_bits():
    """RC4 + AES256 (the common 'modern' combo) → both labels."""
    out = EncAuditor._parse_enc(0x4 | 0x10)
    assert "RC4-HMAC" in out
    assert "AES256-CTS-HMAC-SHA1" in out


def test_parse_enc_decodes_des():
    """DES bits are deprecated — but accounts still using them happen."""
    out = EncAuditor._parse_enc(0x1 | 0x2)
    assert "DES-CBC-CRC" in out
    assert "DES-CBC-MD5" in out


# ────────────────────────────────────── audit() user channel ─


def test_user_with_enc_zero_is_rc4_only():
    """enc=0 → RC4-only flag fires — that's the headline finding for
    a Kerberoast target on a modern estate."""
    e = _entry("svc_legacy", 0)
    out = EncAuditor(_ldap([e], [])).audit()
    assert len(out.rc4_only_accounts) == 1
    assert out.rc4_only_accounts[0].account == "svc_legacy"
    assert out.rc4_only_accounts[0].rc4_only is True
    assert out.rc4_only_accounts[0].risk == "HIGH"


def test_user_with_rc4_and_aes_is_not_rc4_only():
    """RC4 + AES256 means the operator can request either — not RC4-only."""
    e = _entry("svc_modern", 0x4 | 0x10)
    out = EncAuditor(_ldap([e], [])).audit()
    assert out.rc4_only_accounts == []


def test_user_with_rc4_and_aes_combined_bit_not_flagged():
    """0x18 (AES 128+256) plus 0x4 (RC4) — has AES, so not RC4-only."""
    e = _entry("svc_modern2", 0x4 | 0x18)
    out = EncAuditor(_ldap([e], [])).audit()
    assert out.rc4_only_accounts == []


def test_user_with_des_bit_lands_in_des_bucket_critical():
    """DES is trivially crackable — CRITICAL irrespective of other bits."""
    e = _entry("legacy_unix", 0x1 | 0x10)   # DES-CBC-CRC + AES256
    out = EncAuditor(_ldap([e], [])).audit()
    assert len(out.des_accounts) == 1
    assert out.des_accounts[0].risk == "CRITICAL"


def test_user_with_aes_only_clean():
    """AES-only account → neither bucket fires."""
    e = _entry("svc_clean", 0x18)
    out = EncAuditor(_ldap([e], [])).audit()
    assert out.rc4_only_accounts == []
    assert out.des_accounts == []


# ────────────────────────────────────── audit() DC channel ─


def test_dc_with_rc4_flagged_high():
    """DC supporting RC4 → downgrade attacks possible. HIGH."""
    e = _entry("DC01$", 0x4 | 0x18)   # RC4 + AES
    out = EncAuditor(_ldap([], [e])).audit()
    assert len(out.weak_dcs) == 1
    assert out.weak_dcs[0].account == "DC01$"
    assert out.weak_dcs[0].risk == "HIGH"
    assert out.weak_dcs[0].is_dc is True


def test_dc_with_enc_zero_marked_rc4_only():
    """DC default (no enc set) defaults to RC4 — flagged."""
    e = _entry("OLD-DC$", 0)
    out = EncAuditor(_ldap([], [e])).audit()
    assert out.weak_dcs[0].rc4_only is True


def test_dc_with_aes_only_clean():
    e = _entry("CLEAN-DC$", 0x18)
    out = EncAuditor(_ldap([], [e])).audit()
    assert out.weak_dcs == []


# ────────────────────────────────────── domain_default_rc4 flag ─


def test_domain_default_rc4_set_when_any_user_rc4_only():
    """If ANY user account is RC4-only, the domain has the default
    RC4 fallback enabled — the report uses this to surface a domain-
    wide warning."""
    e = _entry("svc_legacy", 0)
    out = EncAuditor(_ldap([e], [])).audit()
    assert out.domain_default_rc4 is True


def test_domain_default_rc4_clear_when_no_user_rc4_only():
    """Empty user channel → no signal of legacy default."""
    out = EncAuditor(_ldap([], [])).audit()
    assert out.domain_default_rc4 is False


# ────────────────────────────────────── filter shape ─


def test_user_query_excludes_disabled_accounts():
    """Disabled accounts can't be Kerberoasted anyway — filter them
    out so the operator sees only actionable targets."""
    ldap = _ldap([], [])
    EncAuditor(ldap).audit()
    # First call is the user query.
    user_filter = ldap.query.call_args_list[0].kwargs["search_filter"]
    assert "userAccountControl:1.2.840.113556.1.4.803:=2" in user_filter
    assert "(!(" in user_filter   # negated


def test_dc_query_uses_uac_dc_bit():
    """0x2000 = SERVER_TRUST_ACCOUNT (DC) — the second query targets
    DC accounts specifically via that UAC bit."""
    ldap = _ldap([], [])
    EncAuditor(ldap).audit()
    dc_filter = ldap.query.call_args_list[1].kwargs["search_filter"]
    assert ":1.2.840.113556.1.4.803:=8192" in dc_filter   # 8192 = 0x2000


# ────────────────────────────────────── label tables ─


def test_enc_types_table_covers_des_rc4_aes():
    """Pin the canonical table so a refactor doesn't drop a label
    and silently miss a real cipher in the operator's report."""
    assert ENC_TYPES[0x1]  == "DES-CBC-CRC"
    assert ENC_TYPES[0x2]  == "DES-CBC-MD5"
    assert ENC_TYPES[0x4]  == "RC4-HMAC"
    assert ENC_TYPES[0x8]  == "AES128-CTS-HMAC-SHA1"
    assert ENC_TYPES[0x10] == "AES256-CTS-HMAC-SHA1"

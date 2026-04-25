"""
Core LDAP client — handles all auth methods and exposes a clean query interface.
Supports: password, NTLM hash (PtH), Kerberos ccache.

Transport: tries LDAPS → StartTLS → (signed SASL, if Kerberos) → plain LDAP
unless a specific transport is pinned via the ``transport`` argument.
Hardened DCs (``ldap server require strong auth = yes``) refuse the plain
389 bind, so the auto-fallback chain prevents an immediate hard fail.
"""

import random
import ssl
import time

from ldap3 import ALL, KERBEROS, NTLM, SASL, SUBTREE, Connection, Server, Tls
from ldap3.core.exceptions import LDAPBindError, LDAPException, LDAPSocketOpenError
from rich.console import Console

console = Console()


# Transport modes, in default fallback order.
TRANSPORT_LDAPS    = "ldaps"     # LDAPS on 636 (TLS from the start)
TRANSPORT_STARTTLS = "starttls"  # plain 389 → StartTLS upgrade → bind
TRANSPORT_SIGNED   = "signed"    # SASL/GSS-API (Kerberos only) — channel signed
TRANSPORT_PLAIN    = "plain"     # plain 389, simple/NTLM bind — last resort

_DEFAULT_CHAIN = (TRANSPORT_LDAPS, TRANSPORT_STARTTLS, TRANSPORT_SIGNED, TRANSPORT_PLAIN)


class LDAPAuthError(Exception):
    pass


class LDAPClient:
    def __init__(
        self,
        dc_ip:        str,
        domain:       str,
        username:     str,
        password:     str | None = None,
        hashes:       str | None = None,
        use_kerberos: bool = False,
        use_ssl:      bool = False,           # kept for back-compat
        transport:    str | None = None,      # one of TRANSPORT_*; None = auto
        stealth:      bool = False,
        timeout:      int  = 10,
    ):
        self.dc_ip          = dc_ip
        self.domain         = domain
        self.username       = username
        self.base_dn        = self._to_base_dn(domain)
        self.stealth        = stealth
        self.timeout        = timeout
        self.transport_used: str | None = None
        self._query_count   = 0

        if use_ssl and transport is None:
            transport = TRANSPORT_LDAPS  # honour legacy use_ssl=True callers

        self.conn = self._connect(username, password, hashes, use_kerberos, transport)

    # ------------------------------------------------------------------ #
    #  Connection                                                          #
    # ------------------------------------------------------------------ #

    def _connect(self, username, password, hashes, use_kerberos, transport):
        if transport is not None:
            chain = (transport,)
        else:
            chain = tuple(
                t for t in _DEFAULT_CHAIN
                # SASL signing requires a Kerberos cred — skip otherwise.
                if t != TRANSPORT_SIGNED or use_kerberos
            )

        errors: list[str] = []
        for t in chain:
            try:
                conn = self._open(t, username, password, hashes, use_kerberos)
            except LDAPSocketOpenError as e:
                # Wrong port / no listener — try the next transport.
                errors.append(f"{t}: {e}")
                continue
            except LDAPBindError as e:
                # If a transport is pinned, surface the bind failure verbatim.
                if len(chain) == 1:
                    raise LDAPAuthError(f"Authentication failed ({t}): {e}") from e
                errors.append(f"{t}: {e}")
                continue
            except LDAPException as e:
                errors.append(f"{t}: {e}")
                continue

            self.transport_used = t
            self._announce_bind(t, conn)
            return conn

        raise LDAPAuthError(
            "All LDAP transports failed:\n  " + "\n  ".join(errors)
        )

    def _open(self, transport, username, password, hashes, use_kerberos):
        """Build, connect, and bind a Connection over the given transport."""
        if transport == TRANSPORT_LDAPS:
            port, use_ssl, do_starttls = 636, True, False
        elif transport == TRANSPORT_STARTTLS:
            port, use_ssl, do_starttls = 389, False, True
        elif transport in (TRANSPORT_SIGNED, TRANSPORT_PLAIN):
            port, use_ssl, do_starttls = 389, False, False
        else:
            raise ValueError(f"unknown transport: {transport!r}")

        tls = Tls(validate=ssl.CERT_NONE) if (use_ssl or do_starttls) else None
        server = Server(
            self.dc_ip,
            port=port,
            use_ssl=use_ssl,
            tls=tls,
            get_info=ALL,
            connect_timeout=self.timeout,
        )

        if use_kerberos:
            auth_kwargs = dict(authentication=SASL, sasl_mechanism=KERBEROS)
        elif hashes:
            lm, nt = self._split_hash(hashes)
            auth_kwargs = dict(
                user=f"{self.domain}\\{username}",
                password=f"{lm}:{nt}",
                authentication=NTLM,
            )
        else:
            auth_kwargs = dict(
                user=f"{self.domain}\\{username}",
                password=password,
                authentication=NTLM,
            )

        if do_starttls:
            conn = Connection(server, auto_bind=False, **auth_kwargs)
            if not conn.start_tls():
                raise LDAPException(
                    f"StartTLS upgrade refused by {self.dc_ip}: {conn.last_error}"
                )
            if not conn.bind():
                raise LDAPBindError(conn.last_error or "bind failed after StartTLS")
            return conn

        return Connection(server, auto_bind=True, **auth_kwargs)

    def _announce_bind(self, transport, conn):
        ident = f"{self.domain}\\{self.username}"
        if transport in (TRANSPORT_LDAPS, TRANSPORT_STARTTLS):
            tls_desc = self._describe_tls(conn)
            label = "LDAPS" if transport == TRANSPORT_LDAPS else "StartTLS"
            console.print(
                f"[green][+] {label} bind successful — {tls_desc}[/green]  {ident}"
            )
        elif transport == TRANSPORT_SIGNED:
            console.print(
                f"[green][+] Signed LDAP bind (SASL/Kerberos) successful[/green]  {ident}"
            )
        else:  # plain
            console.print(
                f"[yellow][!] Plain LDAP bind on 389 — channel is unencrypted "
                f"and unsigned[/yellow]  {ident}"
            )

    def _describe_tls(self, conn):
        """Best-effort 'TLS 1.3, peer DC01.corp.local' string for the banner."""
        try:
            sock = conn.socket
            ver  = sock.version() if sock and hasattr(sock, "version") else None
            host = self.dc_ip
            if ver:
                return f"{ver}, peer {host}"
        except Exception:
            pass
        return "TLS established"

    @staticmethod
    def _split_hash(hashes: str):
        if ":" in hashes:
            lm, nt = hashes.split(":", 1)
        else:
            lm = "aad3b435b51404eeaad3b435b51404ee"
            nt = hashes
        return lm, nt

    # ------------------------------------------------------------------ #
    #  Query Interface                                                     #
    # ------------------------------------------------------------------ #

    # RFC 2696 simple paged results control OID — Windows DCs cap each
    # response at MaxPageSize (default 1000). Without paging, every query
    # against a domain with >1000 matching objects silently truncates.
    _PAGED_RESULTS_OID = "1.2.840.113556.1.4.319"

    def query(
        self,
        search_filter: str,
        attributes:    list[str],
        search_base:   str | None = None,
        size_limit:    int = 0,
        page_size:     int = 1000,
        controls:      list | None = None,
    ):
        """Core query. Pages results past the server's MaxPageSize so large
        domains are not silently truncated. Returns a flat list of
        ``ldap3.Entry`` objects (same shape callers already expect).
        """
        if self.stealth:
            time.sleep(random.uniform(0.4, 2.0))

        base = search_base or self.base_dn
        self._query_count += 1

        collected: list = []
        cookie = None
        try:
            while True:
                self.conn.search(
                    search_base=base,
                    search_filter=search_filter,
                    search_scope=SUBTREE,
                    attributes=attributes,
                    size_limit=size_limit,
                    paged_size=page_size,
                    paged_cookie=cookie,
                    controls=controls,
                )
                collected.extend(self.conn.entries)

                controls = (self.conn.result or {}).get("controls") or {}
                cookie = (
                    controls.get(self._PAGED_RESULTS_OID, {})
                            .get("value", {})
                            .get("cookie")
                )
                if not cookie:
                    break
            return collected
        except LDAPException as e:
            console.print(f"[yellow][!] LDAP query failed ({search_filter[:50]}): {e}[/yellow]")
            return collected

    def query_config(self, search_filter: str, attributes: list[str]):
        """Query the Configuration naming context — needed for AD CS, schema."""
        config_base = f"CN=Configuration,{self.base_dn}"
        return self.query(search_filter, attributes, search_base=config_base)

    def get_domain_info(self):
        """
        Fix: previously returned a raw ldap3 entry object, but reporter.py calls
        info.get('domain', ...) etc. — ldap3 entries have no .get() method.
        Now returns a plain dict with friendly keys matching reporter.py's expectations.
        """
        entries = self.query(
            "(objectClass=domainDNS)",
            [
                "dc", "distinguishedName", "msDS-Behavior-Version",
                "ms-DS-MachineAccountQuota", "minPwdLength",
                "maxPwdAge", "minPwdAge", "pwdHistoryLength",
                "lockoutThreshold", "lockoutDuration", "pwdProperties",
                "whenCreated", "objectSid",
            ]
        )
        if not entries:
            return {}
        e = entries[0]

        def _int(attr):
            try:
                v = e[attr].value
                return int(v) if v is not None else None
            except Exception:
                return None

        def _str(attr):
            try:
                v = e[attr].value
                return str(v) if v is not None else None
            except Exception:
                return None

        FL_MAP = {
            0:  "Windows 2000",
            1:  "Windows Server 2003 interim",
            2:  "Windows Server 2003",
            3:  "Windows Server 2008",
            4:  "Windows Server 2008 R2",
            5:  "Windows Server 2012",
            6:  "Windows Server 2012 R2",
            7:  "Windows Server 2016/2019/2022",
            10: "Windows Server 2025",
        }
        fl = _int("msDS-Behavior-Version") or 0

        # Domain SID — needed to substitute <DOMAIN_SID> in next_step
        # templates (Golden Ticket forge, SID History, DCSync), to render
        # ACL principals as S-1-5-21-... in the BloodHound CE exporter,
        # and to gate "is this a domain principal" checks in DCSync /
        # Shadow Credentials enumeration.
        from kerb_map.ldap_helpers import sid_to_str
        domain_sid = sid_to_str(e["objectSid"].value) if "objectSid" in e else None

        return {
            "domain":                self.domain,
            "functional_level":      FL_MAP.get(fl, str(fl)),
            "fl_int":                fl,
            "machine_account_quota": _int("ms-DS-MachineAccountQuota"),
            "min_pwd_length":        _int("minPwdLength"),
            "pwd_history_length":    _int("pwdHistoryLength"),
            "lockout_threshold":     _int("lockoutThreshold"),
            "when_created":          _str("whenCreated"),
            "domain_sid":            domain_sid,
        }

    def close(self):
        if self.conn:
            try:
                self.conn.unbind()
            except Exception as e:
                # Swallowed because close() is best-effort during cleanup, but
                # surface at debug so an operator can still see what happened.
                console.print(f"[dim]LDAP unbind on close() raised: {e}[/dim]")

    @staticmethod
    def _to_base_dn(domain: str) -> str:
        return ",".join(f"DC={part}" for part in domain.split("."))

    @property
    def query_count(self):
        return self._query_count

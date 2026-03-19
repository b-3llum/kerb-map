"""
Core LDAP client — handles all auth methods and exposes a clean query interface.
Supports: password, NTLM hash (PtH), Kerberos ccache.
"""

import ssl
import time
import random
from typing import Optional, List

from ldap3 import (
    Server, Connection, ALL, NTLM, SASL, KERBEROS,
    SUBTREE, Tls
)
from ldap3.core.exceptions import LDAPException, LDAPBindError, LDAPSocketOpenError
from rich.console import Console

console = Console()


class LDAPAuthError(Exception):
    pass


class LDAPClient:
    def __init__(
        self,
        dc_ip:        str,
        domain:       str,
        username:     str,
        password:     Optional[str] = None,
        hashes:       Optional[str] = None,
        use_kerberos: bool = False,
        use_ssl:      bool = False,
        stealth:      bool = False,
        timeout:      int  = 10,
    ):
        self.dc_ip        = dc_ip
        self.domain       = domain
        self.username     = username
        self.base_dn      = self._to_base_dn(domain)
        self.stealth      = stealth
        self.timeout      = timeout
        self._query_count = 0
        self.conn         = self._connect(username, password, hashes, use_kerberos, use_ssl)

    # ------------------------------------------------------------------ #
    #  Connection                                                          #
    # ------------------------------------------------------------------ #

    def _connect(self, username, password, hashes, use_kerberos, use_ssl):
        try:
            tls = Tls(validate=ssl.CERT_NONE) if use_ssl else None
            server = Server(
                self.dc_ip,
                port=636 if use_ssl else 389,
                use_ssl=use_ssl,
                tls=tls,
                get_info=ALL,
                connect_timeout=self.timeout,
            )

            if use_kerberos:
                conn = Connection(
                    server,
                    authentication=SASL,
                    sasl_mechanism=KERBEROS,
                    auto_bind=True,
                )
            elif hashes:
                lm, nt = self._split_hash(hashes)
                conn = Connection(
                    server,
                    user=f"{self.domain}\\{username}",
                    password=f"{lm}:{nt}",
                    authentication=NTLM,
                    auto_bind=True,
                )
            else:
                conn = Connection(
                    server,
                    user=f"{self.domain}\\{username}",
                    password=password,
                    authentication=NTLM,
                    auto_bind=True,
                )

            console.print(f"[green][+] LDAP bind successful — {self.domain}\\{username}[/green]")
            return conn

        except LDAPBindError as e:
            raise LDAPAuthError(f"Authentication failed: {e}")
        except LDAPSocketOpenError as e:
            raise LDAPAuthError(f"Cannot reach DC at {self.dc_ip}: {e}")
        except Exception as e:
            raise LDAPAuthError(f"LDAP connection error: {e}")

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

    def query(
        self,
        search_filter: str,
        attributes:    List[str],
        search_base:   Optional[str] = None,
        size_limit:    int = 0,
    ):
        """Core query — stealth mode injects random jitter between calls."""
        if self.stealth:
            time.sleep(random.uniform(0.4, 2.0))

        base = search_base or self.base_dn
        self._query_count += 1

        try:
            self.conn.search(
                search_base=base,
                search_filter=search_filter,
                search_scope=SUBTREE,
                attributes=attributes,
                size_limit=size_limit,
            )
            return self.conn.entries
        except LDAPException as e:
            console.print(f"[yellow][!] LDAP query failed ({search_filter[:50]}): {e}[/yellow]")
            return []

    def query_config(self, search_filter: str, attributes: List[str]):
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
                "whenCreated",
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
            0: "Windows 2000",
            1: "Windows Server 2003 interim",
            2: "Windows Server 2003",
            3: "Windows Server 2008",
            4: "Windows Server 2008 R2",
            5: "Windows Server 2012",
            6: "Windows Server 2012 R2",
            7: "Windows Server 2016/2019/2022",
        }
        fl = _int("msDS-Behavior-Version") or 0

        return {
            "domain":                self.domain,
            "functional_level":      FL_MAP.get(fl, str(fl)),
            "machine_account_quota": _int("ms-DS-MachineAccountQuota"),
            "min_pwd_length":        _int("minPwdLength"),
            "pwd_history_length":    _int("pwdHistoryLength"),
            "lockout_threshold":     _int("lockoutThreshold"),
            "when_created":          _str("whenCreated"),
        }

    def close(self):
        if self.conn:
            try:
                self.conn.unbind()
            except Exception:
                pass

    @staticmethod
    def _to_base_dn(domain: str) -> str:
        return ",".join(f"DC={part}" for part in domain.split("."))

    @property
    def query_count(self):
        return self._query_count

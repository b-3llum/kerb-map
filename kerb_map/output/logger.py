"""
Logger — Rich-powered terminal output.
Centralised so every module imports the same instance.
"""

import datetime

from rich.console import Console
from rich.theme import Theme

_theme = Theme({
    "info":    "bold cyan",
    "success": "bold green",
    "warn":    "bold yellow",
    "error":   "bold red",
    "critical":"bold white on red",
})

console = Console(theme=_theme)


class Logger:
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def _ts(self):
        return datetime.datetime.now().strftime("%H:%M:%S")

    def info(self, msg):
        console.print(f"[dim]{self._ts()}[/dim] [info]\\[*][/info] {msg}")

    def success(self, msg):
        console.print(f"[dim]{self._ts()}[/dim] [success]\\[+][/success] {msg}")

    def warn(self, msg):
        console.print(f"[dim]{self._ts()}[/dim] [warn]\\[!][/warn] {msg}")

    def error(self, msg):
        console.print(f"[dim]{self._ts()}[/dim] [error]\\[-][/error] {msg}")

    def critical(self, msg):
        console.print(f"[dim]{self._ts()}[/dim] [critical]\\[!!][/critical] {msg}")

    def section(self, title):
        console.rule(f"[bold cyan]{title}[/bold cyan]")

    def blank(self):
        console.print()

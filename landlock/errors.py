"""The two ways this package stops: a refusal for what it will not do, and a fault for what broke.

A Refused carries one sentence in .why that starts with "REFUSED: ".
A Fault carries one sentence in .why that starts with "FAULT: ".
The two never inherit from each other, so a caller can tell them apart.
Nothing here prints; the command line decides what to show.
"""

from __future__ import annotations


class _Stop(Exception):
    """Shared shape: a sentence in .why that always begins with the class prefix."""

    PREFIX = ""

    def __init__(self, why: object = "") -> None:
        text = str(why).strip()
        if not text.startswith(self.PREFIX):
            text = self.PREFIX + text
        self.why = text
        super().__init__(text)

    def __str__(self) -> str:
        return self.why


class Refused(_Stop):
    """An act the package will not do, with the reason in .why."""

    PREFIX = "REFUSED: "


class Fault(_Stop):
    """Something that broke while the package was working, with the reason in .why."""

    PREFIX = "FAULT: "

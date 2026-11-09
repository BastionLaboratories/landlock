"""Landlock changes one file safely: it pins the old bytes, rehearses the change, needs an approval, swaps the file in, and can roll back.

The names Refused, Fault, Pin, sha256_of and check load at once. The names that
live in sibling modules (load_config, verify, rollback, recover) load the first
time they are used, so a missing sibling raises ImportError only when its name
is asked for.

The functions pin, approve, rehearse and land are never re-exported: they share
their module's name, and the package attribute would flip between the module
and the function by import order. Reach them with "from landlock.pin import
pin" and likewise for the others.
"""

from __future__ import annotations

import importlib
from typing import Any

from .errors import Fault, Refused
from .pin import Pin, check, sha256_of

__version__ = "0.1.2"

# name -> (sibling module, attribute in that module)
_LAZY = {
    "load_config": ("config", "load_config"),
    "verify": ("approve", "verify"),
    "rollback": ("land", "rollback"),
    "recover": ("land", "recover"),
}

__all__ = [
    "__version__",
    "Refused",
    "Fault",
    "Pin",
    "sha256_of",
    "check",
    *_LAZY,
]


def __getattr__(name: str) -> Any:
    """Load a re-exported name from its sibling module the first time it is used."""
    target = _LAZY.get(name)
    if target is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    module = importlib.import_module(f".{target[0]}", __name__)
    value = getattr(module, target[1])
    globals()[name] = value
    return value


def __dir__() -> list[str]:
    return sorted(set(globals()) | set(_LAZY))

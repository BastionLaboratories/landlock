"""Reads and checks the settings file that names the folders software may change, where records go, and which tests run.

One TOML file describes a home: the roots (folders whose files may be
replaced), the path of the receipts file, the path of the secret file, the test
command for each file (or a default), the files whose tests must pass after a
change to another file (dependents), and the walls (time and load limits).

Every path in the settings must be absolute. The receipts file and the secret
file must live outside every root, and every key of the dependents map or of
the per-path tests map must sit inside a root. Anything else is refused with a
one-sentence reason that starts with "REFUSED: ".

Example file:

    roots = ["/srv/app"]
    receipts = "/var/lib/landlock/receipts.jsonl"
    secret = "/etc/landlock/secret"

    [tests]
    default = ["python3", "-m", "pytest", "-q"]

    [tests.by_path]
    "/srv/app/core.py" = ["python3", "-m", "pytest", "-q", "tests/test_core.py"]

    [dependents]
    "/srv/app/core.py" = ["/srv/app/api.py"]

    [walls]
    test_wall_s = 300
    load_max = 48.0
    approval_ttl_s = 86400
    rehearse_extra_dirs = []
    rehearse_ro_dirs = ["/srv/shared/lib"]

The wall rehearse_ro_dirs (optional; absent unless given) lists absolute
folders that a rehearsal shows read-only at their own paths, never copied; they
may lie outside every root because nothing can be written through them, and an
entry of the hidden home folder (a link, a per-user package folder) is shown
again at the path as written. The wall rehearse_extra_dirs, kept for configs
written before it, lists absolute folders inside a root that a rehearsal shows
the same way (read-only, never copied). The loader refuses a relative entry, an
entry that climbs with '..', or an entry that exists and is not a folder; a
rehearsal also refuses an entry that does not exist, the home folder whole, or
a link that would show the home through another path. The receipts file and
the secret file must be two different files. The other walls are numbers above
zero.
"""

from __future__ import annotations

import json
import os
import tomllib
from dataclasses import dataclass, field

from .errors import Refused

DEFAULT_WALLS = {
    "test_wall_s": 300,
    "load_max": 48.0,
    "approval_ttl_s": 86400,
    "rehearse_extra_dirs": [],
}
_OPTIONAL_WALLS = ("rehearse_ro_dirs",)  # because: walls kept in a config only when it names them, so a 0.1.0 config reads back unchanged
_NUMERIC_WALLS = ("test_wall_s", "load_max", "approval_ttl_s")

_TOP_KEYS = ("roots", "receipts", "secret", "tests", "dependents", "walls")
_TESTS_KEYS = ("default", "by_path")


def _refuse(why: str) -> Refused:
    return Refused("REFUSED: " + why)


def _text_path(value, label: str) -> str:
    """Return value as an absolute path string, or refuse."""
    if isinstance(value, os.PathLike):
        value = os.fspath(value)
    if not isinstance(value, str) or not value:
        raise _refuse(f"{label} must be a non-empty path string, got {value!r}")
    if "\x00" in value:
        raise _refuse(f"{label} must not contain a NUL character")
    if not os.path.isabs(value):
        raise _refuse(f"{label} must be an absolute path, got {value!r}")
    return value


def _within(base: str, path: str) -> bool:
    """True when path (links resolved) is base itself or lies below it."""
    base_real = os.path.realpath(base)
    path_real = os.path.realpath(path)
    try:
        return os.path.commonpath([base_real, path_real]) == base_real
    except ValueError:
        return False


def _in_any(roots, path: str) -> bool:
    return any(_within(root, path) for root in roots)


def _argv(value, label: str) -> list:
    if not isinstance(value, (list, tuple)) or not value:
        raise _refuse(f"{label} must be a non-empty list of strings")
    out = []
    for item in value:
        if not isinstance(item, str) or not item:
            raise _refuse(f"{label} must hold only non-empty strings, got {item!r}")
        out.append(item)
    return out


def _number(value, label: str):
    if isinstance(value, bool) or not isinstance(value, (int, float)) or value <= 0:
        raise _refuse(f"{label} must be a number above zero, got {value!r}")
    return value


@dataclass
class Config:
    """The checked settings of one home (see the module docstring)."""

    roots: list
    receipts: str
    secret: str
    tests: dict = field(default_factory=dict)
    dependents: dict = field(default_factory=dict)
    walls: dict = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not isinstance(self.roots, (list, tuple)) or not self.roots:
            raise _refuse("roots must be a non-empty list of folders")
        roots = []
        for item in self.roots:
            root = _text_path(item, "a root")
            if not os.path.isdir(root):
                raise _refuse(f"a root is not a directory: {root}")
            roots.append(root)
        self.roots = roots

        self.receipts = _text_path(self.receipts, "receipts")
        self.secret = _text_path(self.secret, "secret")
        if _in_any(self.roots, self.receipts):
            raise _refuse(f"receipts must live outside every root: {self.receipts}")
        if _in_any(self.roots, self.secret):
            raise _refuse(f"secret must live outside every root: {self.secret}")
        if os.path.realpath(self.receipts) == os.path.realpath(self.secret):
            raise _refuse(f"receipts and secret must be two different files: {self.receipts}")

        self.tests = self._check_tests(self.tests)
        self.dependents = self._check_dependents(self.dependents)
        self.walls = self._check_walls(self.walls)

    def _check_tests(self, tests) -> dict:
        if tests is None:
            tests = {}
        if not isinstance(tests, dict):
            raise _refuse("tests must be a table with default and by_path")
        for key in tests:
            if key not in _TESTS_KEYS:
                raise _refuse(f"unknown key in tests: {key!r}")
        default = tests.get("default")
        default = [] if default in (None, [], ()) else _argv(default, "tests.default")
        by_path_in = tests.get("by_path")
        if by_path_in is None:
            by_path_in = {}
        if not isinstance(by_path_in, dict):
            raise _refuse("tests.by_path must be a table of path to command")
        by_path = {}
        for key, argv in by_path_in.items():
            path = _text_path(key, "a tests.by_path key")
            if not _in_any(self.roots, path):
                raise _refuse(f"a tests.by_path key is outside the roots: {path}")
            by_path[path] = _argv(argv, f"tests.by_path[{path}]")
        return {"default": default, "by_path": by_path}

    def _check_dependents(self, dependents) -> dict:
        if dependents is None:
            dependents = {}
        if not isinstance(dependents, dict):
            raise _refuse("dependents must be a table of path to list of paths")
        out = {}
        for key, listed in dependents.items():
            path = _text_path(key, "a dependents key")
            if not _in_any(self.roots, path):
                raise _refuse(f"a dependents key is outside the roots: {path}")
            if not isinstance(listed, (list, tuple)):
                raise _refuse(f"dependents[{path}] must be a list of paths")
            kept = []
            for item in listed:
                dep = _text_path(item, "a dependent")
                if not _in_any(self.roots, dep):
                    raise _refuse(f"a dependent is outside the roots: {dep}")
                kept.append(dep)
            out[path] = kept
        return out

    def _check_walls(self, walls) -> dict:
        if walls is None:
            walls = {}
        if not isinstance(walls, dict):
            raise _refuse("walls must be a table")
        for key in walls:
            if key not in DEFAULT_WALLS and key not in _OPTIONAL_WALLS:
                raise _refuse(f"unknown wall: {key!r}")
        merged = dict(DEFAULT_WALLS)
        merged.update(walls)
        for key in _NUMERIC_WALLS:
            _number(merged[key], f"walls.{key}")
        merged["load_max"] = float(merged["load_max"])
        merged["rehearse_extra_dirs"] = self._check_extra_dirs(merged["rehearse_extra_dirs"])
        if "rehearse_ro_dirs" in merged:
            merged["rehearse_ro_dirs"] = self._check_ro_dirs(merged["rehearse_ro_dirs"])
        return merged

    def _check_ro_dirs(self, listed) -> list:
        """Absolute folders shown read-only in a rehearsal; they may lie outside the roots."""
        if not isinstance(listed, (list, tuple)):
            raise _refuse("walls.rehearse_ro_dirs must be a list of folders")
        out = []
        for item in listed:
            path = _text_path(item, "a walls.rehearse_ro_dirs entry")
            if os.pardir in path.split(os.sep):
                raise _refuse(f"a walls.rehearse_ro_dirs entry must not climb with '..': {path}")
            if os.path.exists(path) and not os.path.isdir(path):
                raise _refuse(f"a walls.rehearse_ro_dirs entry is not a directory: {path}")
            out.append(path)
        return out

    def _check_extra_dirs(self, listed) -> list:
        if not isinstance(listed, (list, tuple)):
            raise _refuse("walls.rehearse_extra_dirs must be a list of folders")
        out = []
        for item in listed:
            path = _text_path(item, "a walls.rehearse_extra_dirs entry")
            if not _in_any(self.roots, path):
                raise _refuse(f"a walls.rehearse_extra_dirs entry is outside the roots: {path}")
            if os.path.exists(path) and not os.path.isdir(path):
                raise _refuse(f"a walls.rehearse_extra_dirs entry is not a directory: {path}")
            out.append(path)
        return out

    def to_dict(self) -> dict:
        return {
            "roots": list(self.roots),
            "receipts": self.receipts,
            "secret": self.secret,
            "tests": {
                "default": list(self.tests["default"]),
                "by_path": {k: list(v) for k, v in self.tests["by_path"].items()},
            },
            "dependents": {k: list(v) for k, v in self.dependents.items()},
            "walls": {
                k: (list(v) if isinstance(v, list) else v) for k, v in self.walls.items()
            },
        }

    @classmethod
    def from_dict(cls, data) -> "Config":
        if not isinstance(data, dict):
            raise _refuse("a config must be a table of settings")
        for key in data:
            if key not in _TOP_KEYS:
                raise _refuse(f"unknown config key: {key!r}")
        for key in ("roots", "receipts", "secret"):
            if key not in data:
                raise _refuse(f"the config is missing the key: {key}")
        return cls(
            roots=data["roots"],
            receipts=data["receipts"],
            secret=data["secret"],
            tests=data.get("tests", {}),
            dependents=data.get("dependents", {}),
            walls=data.get("walls", {}),
        )

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True)

    @classmethod
    def from_json(cls, s) -> "Config":
        if isinstance(s, (bytes, bytearray)):
            s = bytes(s).decode("utf-8", errors="replace")
        if isinstance(s, str):
            try:
                data = json.loads(s)
            except ValueError as exc:
                raise _refuse(f"the config JSON does not parse: {exc}") from exc
        else:
            data = s
        return cls.from_dict(data)


def load_config(path) -> Config:
    """Read the TOML settings file at path and return the checked Config."""
    path = os.fspath(path)
    try:
        with open(path, "rb") as handle:
            data = tomllib.load(handle)
    except FileNotFoundError as exc:
        raise _refuse(f"the config file does not exist: {path}") from exc
    except IsADirectoryError as exc:
        raise _refuse(f"the config path is a directory: {path}") from exc
    except PermissionError as exc:
        raise _refuse(f"the config file cannot be read: {path}") from exc
    except tomllib.TOMLDecodeError as exc:
        raise _refuse(f"the config file is not valid TOML: {exc}") from exc
    return Config.from_dict(data)


def inside_roots(cfg: Config, path) -> bool:
    """True when path (links resolved) lies inside one of the roots."""
    path = _text_path(path, "path")
    return _in_any(cfg.roots, path)


def tests_for(cfg: Config, path) -> list:
    """The test command for path: its by_path entry, else the default."""
    path = _text_path(path, "path")
    if not _in_any(cfg.roots, path):
        raise _refuse(f"path is outside every root: {path}")
    want = os.path.realpath(path)
    for key, argv in cfg.tests["by_path"].items():
        if os.path.realpath(key) == want:
            return list(argv)
    if cfg.tests["default"]:
        return list(cfg.tests["default"])
    raise _refuse(f"no test command is set for: {path}")

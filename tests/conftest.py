"""Shared test helpers that give every test a fresh writable folder, a matching config, and a private secret file.

The fixtures named by the contract:

- tmp_root: an absolute, resolved, writable directory that the config treats as
  its only root (the place files may be landed into).
- cfg: a Config loaded through landlock.config.load_config from a TOML file
  written beside the root, never inside it. roots=[tmp_root]; the receipts file
  and the secret path live in a sibling "keep" directory; the default test
  command is a passing python3 -c argv; the walls are short.
- secret_file: the secret named by cfg, written with mode 0600 (the cfg fixture
  names the path but does not create the file, so a test can see the refusal
  for a missing secret simply by not asking for this fixture).

One more helper, make_cfg, builds a Config with extra tests or dependents for
tests that need them; cfg is make_cfg() with no extras.

Everything stays inside pytest's tmp_path.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

# Make the package importable when pytest runs from a plain checkout.
_TREE = Path(__file__).resolve().parent.parent
if str(_TREE) not in sys.path:
    sys.path.insert(0, str(_TREE))

PASSING_ARGV = ["python3", "-c", "import sys; sys.exit(0)"]
FAILING_ARGV = ["python3", "-c", "import sys; sys.exit(1)"]

SHORT_WALLS = {
    "test_wall_s": 60,
    # A high ceiling so a busy test machine never trips the load check.
    "load_max": 100000.0,
    "approval_ttl_s": 3600,
}


_TOML_ESCAPES = {
    "\\": "\\\\",
    '"': '\\"',
    "\b": "\\b",
    "\t": "\\t",
    "\n": "\\n",
    "\f": "\\f",
    "\r": "\\r",
}


def _toml_str(value: str) -> str:
    """Quote a text value as a TOML basic string, escaping backslashes, quotes, newlines and every control character."""
    out = []
    for ch in value:
        if ch in _TOML_ESCAPES:
            out.append(_TOML_ESCAPES[ch])
        elif ord(ch) < 0x20 or ord(ch) == 0x7F:
            out.append("\\u%04X" % ord(ch))
        else:
            out.append(ch)
    return '"' + "".join(out) + '"'


def _toml_list(values) -> str:
    return "[" + ", ".join(_toml_str(str(v)) for v in values) + "]"


def _toml_value(value) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return repr(value)
    if isinstance(value, (list, tuple)):
        return _toml_list(value)
    return _toml_str(str(value))


def render_toml(roots, receipts, secret, default_argv, by_path, dependents, walls) -> str:
    """Write the config keys of the contract as TOML text."""
    lines = [
        "roots = " + _toml_list(roots),
        "receipts = " + _toml_str(str(receipts)),
        "secret = " + _toml_str(str(secret)),
        "",
        "[tests]",
        "default = " + _toml_list(default_argv),
        "",
        "[tests.by_path]",
    ]
    for key, argv in by_path.items():
        lines.append(_toml_str(str(key)) + " = " + _toml_list(argv))
    lines += ["", "[dependents]"]
    for key, paths in dependents.items():
        lines.append(_toml_str(str(key)) + " = " + _toml_list(paths))
    lines += ["", "[walls]"]
    for key, value in walls.items():
        lines.append(key + " = " + _toml_value(value))
    return "\n".join(lines) + "\n"


@pytest.fixture
def tmp_root(tmp_path) -> Path:
    """A writable directory that the config names as its only root."""
    root = (tmp_path / "root").resolve()
    root.mkdir(parents=True, exist_ok=True)
    return root


@pytest.fixture
def keep_dir(tmp_path) -> Path:
    """The sibling directory outside the root that holds receipts, secret and config."""
    keep = (tmp_path / "keep").resolve()
    keep.mkdir(parents=True, exist_ok=True)
    return keep


@pytest.fixture
def make_cfg(tmp_root, keep_dir):
    """Build a Config through load_config, with optional by_path tests, dependents or walls."""
    counter = {"n": 0}

    def _make(default=None, by_path=None, dependents=None, walls=None, name=None):
        from landlock.config import load_config

        counter["n"] += 1
        merged_walls = dict(SHORT_WALLS)
        if walls:
            merged_walls.update(walls)
        text = render_toml(
            roots=[tmp_root],
            receipts=keep_dir / "receipts.jsonl",
            secret=keep_dir / "secret",
            default_argv=list(default) if default is not None else list(PASSING_ARGV),
            by_path=dict(by_path or {}),
            dependents=dict(dependents or {}),
            walls=merged_walls,
        )
        path = keep_dir / (name or "landlock_%d.toml" % counter["n"])
        path.write_text(text, encoding="utf-8")
        return load_config(str(path))

    return _make


@pytest.fixture
def cfg(make_cfg):
    """A Config whose only root is tmp_root, receipts and secret in the sibling keep dir."""
    return make_cfg(name="landlock.toml")


@pytest.fixture
def secret_file(keep_dir) -> Path:
    """The secret file the cfg fixture names, written with mode 0600."""
    path = keep_dir / "secret"
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, os.urandom(32).hex().encode("ascii"))
        os.fsync(fd)
    finally:
        os.close(fd)
    os.chmod(str(path), 0o600)
    return path

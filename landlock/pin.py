"""Pin a file's exact bytes by recording its sha256, size and time, then check later whether the bytes have moved.

Every later step of the installer takes a Pin and never a bare path, so a
change made after the pin is noticed and refused. Only the bytes count: a file
rewritten with the same bytes still passes the check.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from dataclasses import dataclass
from datetime import datetime, timezone

from .errors import Refused

_HEX64 = re.compile(r"[0-9a-f]{64}")
_CHUNK = 1024 * 1024
_FIELDS = ("path", "sha256", "size", "mtime_ns", "pinned_at")


def _now_utc() -> str:
    """The clock as an ISO-8601 UTC string with seconds."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _absolute(path: object) -> str:
    """The path as text, refused unless it is a non-empty absolute path."""
    if not isinstance(path, (str, os.PathLike)):
        raise Refused(f"a path must be text or a path object, not {type(path).__name__}")
    text = os.fspath(path)
    if not isinstance(text, str):
        raise Refused("a path must be text, not bytes")
    if not text or "\0" in text:
        raise Refused(f"a path must be a non-empty text without a NUL byte: {text!r}")
    if not os.path.isabs(text):
        raise Refused(f"a path must be absolute: {text}")
    return text


def _measure(path: object) -> tuple[str, str, int, int]:
    """Read the whole file once and return (path text, sha256, size, mtime_ns)."""
    text = _absolute(path)
    flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(text, flags)
    except (FileNotFoundError, NotADirectoryError):
        raise Refused(f"file not found: {text}") from None
    except IsADirectoryError:
        raise Refused(f"not a regular file: {text}") from None
    except PermissionError:
        raise Refused(f"file cannot be read, permission denied: {text}") from None
    except OSError as exc:
        raise Refused(f"file cannot be read ({exc.strerror or type(exc).__name__}): {text}") from None
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode):
            raise Refused(f"not a regular file: {text}")
        digest = hashlib.sha256()
        total = 0
        while True:
            chunk = os.read(fd, _CHUNK)
            if not chunk:
                break
            digest.update(chunk)
            total += len(chunk)
        after = os.fstat(fd)
    except OSError as exc:
        raise Refused(f"file cannot be read ({exc.strerror or type(exc).__name__}): {text}") from None
    finally:
        os.close(fd)
    if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns) or total != after.st_size:
        raise Refused(f"file changed while it was being read: {text}")
    return text, digest.hexdigest(), total, after.st_mtime_ns


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


@dataclass(frozen=True)
class Pin:
    """A file's exact bytes at one moment: {path, sha256, size, mtime_ns, pinned_at}."""

    path: str
    sha256: str
    size: int
    mtime_ns: int
    pinned_at: str

    def to_dict(self) -> dict:
        """The pin as a plain dict."""
        return {name: getattr(self, name) for name in _FIELDS}

    def to_json(self) -> str:
        """The pin as one JSON text with sorted keys."""
        return json.dumps(self.to_dict(), sort_keys=True)

    @classmethod
    def from_dict(cls, data: object) -> "Pin":
        """Build a Pin from a plain dict, refusing anything malformed."""
        if not isinstance(data, dict):
            raise Refused("a pin must be a JSON object")
        missing = [name for name in _FIELDS if name not in data]
        if missing:
            raise Refused(f"a pin is missing the key {missing[0]}")
        extra = sorted(str(name) for name in data if name not in _FIELDS)
        if extra:
            raise Refused(f"a pin has an unexpected key {extra[0]}")
        path = data["path"]
        if not isinstance(path, str) or not path or "\0" in path or not os.path.isabs(path):
            raise Refused("a pin needs an absolute path")
        sha = data["sha256"]
        if not isinstance(sha, str) or not _HEX64.fullmatch(sha):
            raise Refused("a pin needs a lowercase sha256 of 64 hex digits")
        size = data["size"]
        if not _is_int(size) or size < 0:
            raise Refused("a pin needs a size that is a whole number of zero or more")
        mtime_ns = data["mtime_ns"]
        if not _is_int(mtime_ns) or mtime_ns < 0:
            raise Refused("a pin needs an mtime_ns that is a whole number of zero or more")
        pinned_at = data["pinned_at"]
        if not isinstance(pinned_at, str) or not pinned_at:
            raise Refused("a pin needs a pinned_at clock")
        return cls(path, sha, size, mtime_ns, pinned_at)

    @classmethod
    def from_json(cls, text: object) -> "Pin":
        """Build a Pin from JSON text (a dict is accepted too), refusing anything malformed."""
        if isinstance(text, dict):
            return cls.from_dict(text)
        if not isinstance(text, (str, bytes, bytearray)):
            raise Refused("a pin must be given as JSON text")
        try:
            data = json.loads(text)
        except (ValueError, UnicodeDecodeError):
            raise Refused("a pin must be valid JSON") from None
        return cls.from_dict(data)


def sha256_of(path: object) -> str:
    """The lowercase sha256 hex digest of the file's bytes; refuses a relative, missing or non-file path."""
    return _measure(path)[1]


def pin(path: object) -> Pin:
    """Record the file's sha256, size and modified time now."""
    text, digest, size, mtime_ns = _measure(path)
    return Pin(text, digest, size, mtime_ns, _now_utc())


def check(p: Pin) -> Pin:
    """Confirm the file still has the pinned bytes and return the same pin; refuse if it is missing or moved."""
    if not isinstance(p, Pin):
        raise Refused("check needs a Pin")
    _, digest, _, _ = _measure(p.path)
    if digest != p.sha256:
        raise Refused(
            f"the bytes moved since the pin of {p.path}: pinned sha256 {p.sha256}, now sha256 {digest}"
        )
    return p

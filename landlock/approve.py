"""Signed approvals that tie one exact candidate file to one pinned target under the operator's secret key.

An approval is an HMAC-SHA256 over the target path, the candidate's sha256,
the pin's sha256 and the issue and expiry clocks, keyed by the raw bytes of
the operator's secret file. The secret file must exist, be a regular file
owned by the running user with mode 0600, and lie outside every root the
config names. One approval covers exactly one candidate byte string for one
pinned state of one target; verify() refuses anything else.

Record shape (contract): {id, target, candidate_sha256, pin_sha256,
issued_at, expires_at, mac} where
  id  = sha256(target + candidate_sha256 + issued_at)[:16]
  mac = HMAC-SHA256(secret bytes, "landlock-v1\\n" + target + "\\n"
        + candidate_sha256 + "\\n" + pin_sha256 + "\\n" + issued_at
        + "\\n" + expires_at), lowercase hex.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import stat
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from landlock.config import inside_roots
from landlock.errors import Refused
from landlock.pin import Pin

__all__ = ["Approval", "approve", "verify"]

_MAC_DOMAIN = "landlock-v1"
_FIELDS = ("id", "target", "candidate_sha256", "pin_sha256", "issued_at", "expires_at", "mac")
_HEX64 = re.compile(r"[0-9a-f]{64}")
_HEX16 = re.compile(r"[0-9a-f]{16}")
_DEFAULT_TTL_S = 86400
_FUTURE_SKEW_S = 300


# ---------------------------------------------------------------- the record

@dataclass(frozen=True)
class Approval:
    """One signed approval record, exactly the contract's fields."""

    id: str
    target: str
    candidate_sha256: str
    pin_sha256: str
    issued_at: str
    expires_at: str
    mac: str

    def to_dict(self) -> dict[str, str]:
        return {name: getattr(self, name) for name in _FIELDS}

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True)

    @classmethod
    def from_json(cls, s: str | bytes | dict[str, Any]) -> Approval:
        if isinstance(s, dict):
            data: Any = s
        else:
            if isinstance(s, (bytes, bytearray)):
                try:
                    s = bytes(s).decode("utf-8")
                except UnicodeDecodeError:
                    raise Refused("REFUSED: the approval record is not UTF-8 text.") from None
            if not isinstance(s, str):
                raise Refused("REFUSED: the approval record is not JSON text.")
            try:
                data = json.loads(s)
            except ValueError:
                raise Refused("REFUSED: the approval record is not valid JSON.") from None
        if not isinstance(data, dict):
            raise Refused("REFUSED: the approval record is not a JSON object.")
        missing = [name for name in _FIELDS if name not in data]
        if missing:
            raise Refused(f"REFUSED: the approval record lacks the field(s) {', '.join(missing)}.")
        extra = sorted(str(k) for k in data if k not in _FIELDS)
        if extra:
            raise Refused(f"REFUSED: the approval record carries unknown field(s) {', '.join(extra)}.")
        approval = cls(**{name: data[name] for name in _FIELDS})
        _check_shape(approval)
        return approval


# ---------------------------------------------------------------- small helpers

def _now() -> datetime:
    """The current UTC clock at whole seconds (tests may replace this)."""
    return datetime.now(UTC).replace(microsecond=0)


def _iso(dt: datetime) -> str:
    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_clock(value: Any, field: str) -> datetime:
    if not isinstance(value, str):
        raise Refused(f"REFUSED: the approval's {field} is not a clock string.")
    try:
        dt = datetime.fromisoformat(value)
    except ValueError:
        raise Refused(f"REFUSED: the approval's {field} is not an ISO-8601 clock.") from None
    if dt.tzinfo is None or dt.utcoffset() != timedelta(0):
        raise Refused(f"REFUSED: the approval's {field} is not a UTC clock.")
    return dt


def _hex64(value: Any, what: str) -> str:
    if not isinstance(value, str) or not _HEX64.fullmatch(value):
        raise Refused(f"REFUSED: the {what} is not a lowercase sha256 hex digest.")
    return value


def _approval_id(target: str, candidate_sha256: str, issued_at: str) -> str:
    return hashlib.sha256((target + candidate_sha256 + issued_at).encode("utf-8")).hexdigest()[:16]


def _mac(secret: bytes, target: str, candidate_sha256: str, pin_sha256: str,
         issued_at: str, expires_at: str) -> str:
    message = f"{_MAC_DOMAIN}\n{target}\n{candidate_sha256}\n{pin_sha256}\n{issued_at}\n{expires_at}"
    return hmac.new(secret, message.encode("utf-8"), hashlib.sha256).hexdigest()


def _check_shape(a: Approval) -> None:
    for name in _FIELDS:
        if not isinstance(getattr(a, name), str):
            raise Refused(f"REFUSED: the approval's {name} is not a string.")
    if not _HEX16.fullmatch(a.id):
        raise Refused("REFUSED: the approval id is not 16 lowercase hex characters.")
    if not os.path.isabs(a.target):
        raise Refused("REFUSED: the approval's target is not an absolute path.")
    _hex64(a.candidate_sha256, "approval's candidate sha256")
    _hex64(a.pin_sha256, "approval's pin sha256")
    _hex64(a.mac, "approval's mac")
    _parse_clock(a.issued_at, "issued_at")
    _parse_clock(a.expires_at, "expires_at")


def _pin_fields(p: Pin | dict[str, Any]) -> tuple[str, str]:
    if isinstance(p, dict):
        path, sha = p.get("path"), p.get("sha256")
    else:
        path, sha = getattr(p, "path", None), getattr(p, "sha256", None)
    if isinstance(path, os.PathLike):
        path = os.fspath(path)
    if not isinstance(path, str) or not os.path.isabs(path):
        raise Refused("REFUSED: the pin's path is not an absolute path.")
    return path, _hex64(sha, "pin's sha256")


def _wall(cfg: Any, name: str, default: Any) -> Any:
    walls = getattr(cfg, "walls", None)
    if isinstance(walls, dict):
        return walls.get(name, default)
    if walls is None:
        return default
    return getattr(walls, name, default)


def _ttl(cfg: Any, ttl_s: Any) -> int:
    value = _wall(cfg, "approval_ttl_s", _DEFAULT_TTL_S) if ttl_s is None else ttl_s
    if isinstance(value, bool) or not isinstance(value, (int, float)) or value != int(value):
        raise Refused("REFUSED: the approval lifetime must be a whole number of seconds.")
    if int(value) < 1:
        raise Refused("REFUSED: the approval lifetime must be at least one second.")
    return int(value)


def _inside_any_root(cfg: Any, path: str) -> bool:
    real = os.path.realpath(path)
    for root in getattr(cfg, "roots", None) or ():
        root_real = os.path.realpath(os.fspath(root))
        try:
            if os.path.commonpath([real, root_real]) == root_real:
                return True
        except ValueError:
            continue
    return bool(inside_roots(cfg, path))


def _secret_bytes(cfg: Any) -> bytes:
    """Read the secret file after checking it exists, is 0600, ours, and outside every root."""
    path = getattr(cfg, "secret", None)
    if isinstance(path, os.PathLike):
        path = os.fspath(path)
    if not isinstance(path, str) or not os.path.isabs(path):
        raise Refused("REFUSED: the secret path in the config is not an absolute path.")
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        raise Refused("REFUSED: the secret file does not exist.") from None
    except OSError:
        raise Refused("REFUSED: the secret file cannot be examined.") from None
    if stat.S_ISLNK(st.st_mode):
        raise Refused("REFUSED: the secret file is a symbolic link; a regular file is required.")
    if not stat.S_ISREG(st.st_mode):
        raise Refused("REFUSED: the secret file is not a regular file.")
    mode = stat.S_IMODE(st.st_mode)
    if mode != 0o600:
        raise Refused(f"REFUSED: the secret file must have mode 0600, found {mode:04o}.")
    if hasattr(os, "getuid") and st.st_uid != os.getuid():
        raise Refused("REFUSED: the secret file is not owned by the user running landlock.")
    if _inside_any_root(cfg, path):
        raise Refused("REFUSED: the secret file lies inside a root; keep it outside every root.")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(path, flags)
    except OSError:
        raise Refused("REFUSED: the secret file cannot be opened for reading.") from None
    try:
        fst = os.fstat(fd)
        if (fst.st_dev, fst.st_ino) != (st.st_dev, st.st_ino) or stat.S_IMODE(fst.st_mode) != 0o600:
            raise Refused("REFUSED: the secret file changed while it was being read.")
        chunks = []
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            chunks.append(chunk)
    finally:
        os.close(fd)
    data = b"".join(chunks)
    if not data:
        raise Refused("REFUSED: the secret file is empty.")
    return data


# ---------------------------------------------------------------- the public names

def approve(cfg: Any, p: Pin, candidate_sha256: str, ttl_s: int | None = None) -> Approval:
    """Sign an approval for exactly these candidate bytes over this pinned target."""
    target, pin_sha = _pin_fields(p)
    candidate = _hex64(candidate_sha256, "candidate sha256")
    if not _inside_any_root(cfg, target):
        raise Refused("REFUSED: the target lies outside every root in the config.")
    ttl = _ttl(cfg, ttl_s)
    secret = _secret_bytes(cfg)
    issued = _now()
    issued_at = _iso(issued)
    expires_at = _iso(issued + timedelta(seconds=ttl))
    return Approval(
        id=_approval_id(target, candidate, issued_at),
        target=target,
        candidate_sha256=candidate,
        pin_sha256=pin_sha,
        issued_at=issued_at,
        expires_at=expires_at,
        mac=_mac(secret, target, candidate, pin_sha, issued_at, expires_at),
    )


def verify(cfg: Any, a: Approval, p: Pin, candidate_sha256: str) -> Approval:
    """Return the approval when it is genuine, unexpired and bound to this pin and candidate."""
    if isinstance(a, (str, bytes, bytearray, dict)):
        a = Approval.from_json(a)
    if not isinstance(a, Approval):
        raise Refused("REFUSED: the approval is not an approval record.")
    _check_shape(a)
    target, pin_sha = _pin_fields(p)
    candidate = _hex64(candidate_sha256, "candidate sha256")
    secret = _secret_bytes(cfg)
    expected = _mac(secret, a.target, a.candidate_sha256, a.pin_sha256, a.issued_at, a.expires_at)
    if not hmac.compare_digest(expected, a.mac):
        raise Refused("REFUSED: the approval's signature does not verify under the secret file.")
    if not hmac.compare_digest(_approval_id(a.target, a.candidate_sha256, a.issued_at), a.id):
        raise Refused("REFUSED: the approval id does not match its signed fields.")
    issued = _parse_clock(a.issued_at, "issued_at")
    expires = _parse_clock(a.expires_at, "expires_at")
    if expires <= issued:
        raise Refused("REFUSED: the approval expires no later than it was issued.")
    now = _now()
    if issued > now + timedelta(seconds=_FUTURE_SKEW_S):
        raise Refused("REFUSED: the approval was issued in the future.")
    if now >= expires:
        raise Refused(f"REFUSED: the approval expired at {a.expires_at}.")
    if a.target != target:
        raise Refused("REFUSED: the approval names a different target than the pin.")
    if a.pin_sha256 != pin_sha:
        raise Refused("REFUSED: the pinned bytes moved; the pin's sha256 differs from the approval's.")
    if a.candidate_sha256 != candidate:
        raise Refused("REFUSED: the approval covers different candidate bytes.")
    return a

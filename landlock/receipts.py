"""PLAIN: Keeps a record of every act as JSON rows in an append-only file, and checks that each landing starts from the bytes the last one left.

One row is written per act (pin, rehearse, approve, land, rollback, recover).
Rows are appended whole and synced to disk. Nothing is ever rewritten.
The chain check reads the rows back and refuses when a landing's starting
bytes do not match what the previous landing, rollback or recovery left.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import asdict, dataclass, fields, replace
from datetime import datetime, timezone

from .errors import Fault, Refused

try:  # POSIX advisory lock; the package targets Linux, so this is always present there
    import fcntl
except ImportError:  # pragma: no cover
    fcntl = None

ACTS = ("pin", "rehearse", "approve", "land", "rollback", "recover")
VERDICTS = ("DONE", "REFUSED", "FAULT", "WOULD-LAND", "WOULD-REFUSE")
CHAIN_ACTS = ("land", "rollback", "recover")
DRY_VERDICTS = ("WOULD-LAND", "WOULD-REFUSE")

_REQUIRED = ("ts", "request_id", "act", "path", "verdict")
_DIGEST_FIELDS = ("sha_before", "sha_after")
_HEX64 = re.compile(r"[0-9a-f]{64}")


def now_ts() -> str:
    """The current clock as an ISO-8601 UTC string with seconds."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_ts(ts: object) -> datetime:
    if not isinstance(ts, str) or not ts:
        raise Refused("REFUSED: a clock must be an ISO-8601 UTC string with seconds")
    try:
        parsed = datetime.fromisoformat(ts)
    except ValueError:
        raise Refused(f"REFUSED: the clock {ts!r} is not an ISO-8601 UTC string with seconds") from None
    if parsed.tzinfo is None or parsed.utcoffset() is None or parsed.utcoffset().total_seconds() != 0:
        raise Refused(f"REFUSED: the clock {ts!r} is not in UTC")
    return parsed


def request_id(path: str, ts: str) -> str:
    """The base name of the path, a dash, and the clock as YYYYmmddTHHMMSS."""
    if not isinstance(path, str) or not path:
        raise Refused("REFUSED: a request id needs a path")
    return os.path.basename(path) + "-" + _parse_ts(ts).strftime("%Y%m%dT%H%M%S")


@dataclass(frozen=True)
class Row:
    """One receipt: what was done, to which file, from which bytes to which bytes."""

    ts: str = ""
    request_id: str = ""
    act: str = ""
    path: str = ""
    sha_before: str = ""
    sha_after: str = ""
    verdict: str = ""
    why: str = ""
    elder: str = ""
    approval_id: str = ""

    def validate(self) -> "Row":
        """Refuse a row that breaks the contract's shapes; return the row."""
        for f in fields(self):
            if not isinstance(getattr(self, f.name), str):
                raise Refused(f"REFUSED: the receipt field {f.name} must be a string")
        for name in _REQUIRED:
            if not getattr(self, name):
                raise Refused(f"REFUSED: the receipt field {name} is empty")
        _parse_ts(self.ts)
        if self.act not in ACTS:
            raise Refused(f"REFUSED: the act {self.act!r} is not one of {', '.join(ACTS)}")
        if self.verdict not in VERDICTS:
            raise Refused(f"REFUSED: the verdict {self.verdict!r} is not one of {', '.join(VERDICTS)}")
        if not os.path.isabs(self.path):
            raise Refused(f"REFUSED: the receipt path {self.path!r} is not absolute")
        if self.elder and not os.path.isabs(self.elder):
            raise Refused(f"REFUSED: the elder path {self.elder!r} is not absolute")
        for name in _DIGEST_FIELDS:
            value = getattr(self, name)
            if value and not _HEX64.fullmatch(value):
                raise Refused(f"REFUSED: the receipt field {name} is not a lowercase sha256 hex digest")
        return self

    def to_json(self) -> str:
        """The row as a JSON string on a single line."""
        return json.dumps(asdict(self), separators=(",", ":"), sort_keys=False)

    @classmethod
    def from_json(cls, s: "str | dict") -> "Row":
        """Build a validated row from a JSON string or a dict."""
        if isinstance(s, (str, bytes)):
            try:
                data = json.loads(s)
            except ValueError:
                raise Refused("REFUSED: a receipt row is not valid JSON") from None
        else:
            data = s
        if not isinstance(data, dict):
            raise Refused("REFUSED: a receipt row must be a JSON object")
        known = {f.name for f in fields(cls)}
        extra = sorted(set(data) - known)
        if extra:
            raise Refused(f"REFUSED: a receipt row carries unknown fields: {', '.join(extra)}")
        missing = [name for name in _REQUIRED if name not in data]
        if missing:
            raise Refused(f"REFUSED: a receipt row lacks the fields: {', '.join(missing)}")
        return cls(**data).validate()


def _receipts_path(cfg) -> str:
    path = getattr(cfg, "receipts", None)
    if not isinstance(path, str) or not os.path.isabs(path):
        raise Refused("REFUSED: the config names no absolute receipts path")
    return path


def _fsync_dir(directory: str) -> None:
    fd = os.open(directory, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def append(cfg, row: Row) -> Row:
    """Add one row to the end of the receipts file; flush and fsync it; return it.

    An empty ts is filled from the clock and an empty request_id from the path
    and ts. The file is created with mode 0600 and never rewritten.
    """
    if not isinstance(row, Row):
        raise Refused("REFUSED: only a Row can be appended to the receipts")
    path = _receipts_path(cfg)
    if not row.ts:
        row = replace(row, ts=now_ts())
    if not row.request_id and os.path.isabs(row.path):
        row = replace(row, request_id=request_id(row.path, row.ts))
    row.validate()
    data = (row.to_json() + "\n").encode("utf-8")

    directory = os.path.dirname(path)
    os.makedirs(directory, mode=0o700, exist_ok=True)
    fd = os.open(path, os.O_RDWR | os.O_APPEND | os.O_CREAT, 0o600)
    try:
        if fcntl is not None:
            fcntl.flock(fd, fcntl.LOCK_EX)
        size = os.fstat(fd).st_size
        if size > 0 and os.pread(fd, 1, size - 1) != b"\n":
            raise Fault("FAULT: the receipts file does not end in a newline; a write was cut short")
        view = memoryview(data)
        while view:
            written = os.write(fd, view)
            view = view[written:]
        os.fsync(fd)
        if size == 0:
            _fsync_dir(directory)
    finally:
        os.close(fd)
    return row


def _same_path(a: str, b: str) -> bool:
    return os.path.normpath(a) == os.path.normpath(b)


def rows(cfg, path: "str | None" = None) -> "list[Row]":
    """Every row in the receipts file, in order; only those for path when given."""
    if path is not None and not os.path.isabs(path):
        raise Refused(f"REFUSED: the path {path!r} is not absolute")
    receipts = _receipts_path(cfg)
    try:
        with open(receipts, "rb") as handle:
            raw = handle.read()
    except FileNotFoundError:
        return []
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise Refused("REFUSED: the receipts file is not valid UTF-8") from None
    lines = text.split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    out: "list[Row]" = []
    for number, line in enumerate(lines, start=1):
        try:
            row = Row.from_json(line)
        except Refused as exc:
            raise Refused(f"{exc.why} (receipts line {number})") from None
        if path is None or _same_path(row.path, path):
            out.append(row)
    return out


def verify_chain(cfg, path: "str | None" = None) -> int:
    """Count the rows checked, or refuse on a gap in the chain of landings.

    Among the land, rollback and recover rows of a path that measured their
    result (a sha_after) and were not rehearsals, each sha_before must equal
    the previous such row's sha_after. With no path, every path is checked.
    """
    chosen = rows(cfg, path)
    last_after: "dict[str, str]" = {}
    for row in chosen:
        if row.act not in CHAIN_ACTS or row.verdict in DRY_VERDICTS or not row.sha_after:
            continue
        key = os.path.normpath(row.path)
        previous = last_after.get(key)
        if previous is not None and row.sha_before != previous:
            raise Refused(
                f"REFUSED: the receipts chain has a gap for {row.path}: the {row.act} row at "
                f"{row.ts} starts from sha_before {row.sha_before or '(empty)'} but the previous "
                f"row's sha_after is {previous}"
            )
        last_after[key] = row.sha_after
    return len(chosen)

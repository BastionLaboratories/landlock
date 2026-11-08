"""The command line: pin a file, rehearse a change, approve it, land it, roll it back, recover a crash, and read the receipts.

Every command prints one verdict line first, then any detail:
    PINNED <path> <sha>          WOULD LAND / WOULD REFUSE: <why>
    APPROVED <approval id>       LANDED <path> <sha_after>
    ROLLED BACK <path> <sha>     RECOVERED <path> <sha_after>
    ROWS <n>                     VERIFIED <n> rows
    REFUSED: <why>               FAULT: <why>
Exit codes: 0 an act done, 2 a refusal, 3 a fault.

The config file comes from --config, else the LANDLOCK_CONFIG environment
variable, else ./landlock.toml. Every path typed on the command line is
made absolute before it is used. The sibling modules are loaded when a
command runs, not when this file is imported. This is the only module of
the package that prints.
"""

from __future__ import annotations

import argparse
import dataclasses
import datetime
import importlib
import json
import os
import sys
from typing import Any, Sequence

PREFIX = "REFUSED: "
FAULT_PREFIX = "FAULT: "
EXIT_DONE = 0
EXIT_REFUSED = 2
EXIT_FAULT = 3
DEFAULT_CONFIG = "landlock.toml"
CONFIG_ENV = "LANDLOCK_CONFIG"


class _Usage(Exception):
    """A command line that does not parse; reported as a refusal."""


class _Parser(argparse.ArgumentParser):
    """An argument parser that raises instead of printing usage and exiting."""

    def error(self, message: str) -> None:  # type: ignore[override]
        raise _Usage(message)


# ---------------------------------------------------------------- helpers


def _mod(name: str) -> Any:
    """Load a sibling module of the package by its name, at call time."""
    package = __package__ or "landlock"
    return importlib.import_module(package + "." + name)


def _flat(text: object) -> str:
    """Fold any text onto one line."""
    return " ".join(str(text).split())


def _refused(why: str) -> Exception:
    """Build the package's refusal with a one-line why carrying the prefix."""
    why = _flat(why)
    if not why.startswith(PREFIX):
        why = PREFIX + why
    return _mod("errors").Refused(why)


def _say(line: str, *details: str) -> None:
    """Print the verdict line, then each detail line."""
    print(line)
    for detail in details:
        if detail:
            print(detail)


def _field(rec: Any, name: str, default: Any = None) -> Any:
    """Read one field from a record, whether it is an object or a dict."""
    if isinstance(rec, dict):
        return rec.get(name, default)
    return getattr(rec, name, default)


def _record_dict(rec: Any) -> dict:
    """Turn a record into a plain dict through its to_json."""
    if isinstance(rec, dict):
        return dict(rec)
    to_json = getattr(rec, "to_json", None)
    if callable(to_json):
        out = to_json()
        if isinstance(out, (str, bytes)):
            return json.loads(out)
        return dict(out)
    if dataclasses.is_dataclass(rec) and not isinstance(rec, type):
        return dataclasses.asdict(rec)
    return dict(vars(rec))


def _record_from(cls: Any, data: dict) -> Any:
    """Build a record of the given class from a plain dict through its from_json."""
    return cls.from_json(json.dumps(data))


def _now() -> str:
    """The present clock as an ISO-8601 UTC string with seconds."""
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _abs(path: str) -> str:
    """Make a typed path absolute."""
    return os.path.abspath(os.path.expanduser(path))


def _write_atomic(path: str, text: str) -> None:
    """Write text to a file by temp in the same folder, fsync, and one rename."""
    folder = os.path.dirname(path) or "."
    temp = os.path.join(folder, "." + os.path.basename(path) + ".tmp_" + str(os.getpid()))
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp, path)
    except BaseException:
        if os.path.exists(temp):
            os.unlink(temp)
        raise
    dir_fd = os.open(folder, os.O_RDONLY)
    try:
        os.fsync(dir_fd)
    finally:
        os.close(dir_fd)


# ---------------------------------------------------------------- config and paths


def _config_path(ns: argparse.Namespace) -> str:
    """Resolve the config file: --config, else the environment, else ./landlock.toml."""
    raw = getattr(ns, "config", None) or os.environ.get(CONFIG_ENV) or DEFAULT_CONFIG
    return _abs(raw)


def _load_config(ns: argparse.Namespace) -> Any:
    """Load the config, refusing when the file is absent or unreadable."""
    path = _config_path(ns)
    if not os.path.isfile(path):
        raise _refused(
            "no config file at " + path + "; pass --config or set " + CONFIG_ENV + "."
        )
    errors = _mod("errors")
    try:
        return _mod("config").load_config(path)
    except (errors.Refused, errors.Fault):
        raise
    except (ValueError, OSError) as exc:
        raise _refused("the config file at " + path + " could not be read: " + _flat(exc))


def _target(cfg: Any, raw: str) -> str:
    """The absolute target path, refused when it lies outside every root."""
    path = _abs(raw)
    if not _mod("config").inside_roots(cfg, path):
        raise _refused(path + " is outside every root in the config.")
    return path


def _candidate(raw: str, target: str) -> str:
    """The absolute candidate path, refused when it is not a file or is the target itself."""
    path = _abs(raw)
    if not os.path.isfile(path):
        raise _refused("the candidate " + path + " is not a file.")
    if os.path.realpath(path) == os.path.realpath(target):
        raise _refused("the candidate is the live target itself.")
    return path


def _receipt(cfg: Any, act: str, path: str, sha_before: str, sha_after: str,
             verdict: str, why: str = "", elder: str = "", approval_id: str = "") -> None:
    """Append one receipt row for an act this command line performed itself."""
    receipts = _mod("receipts")
    ts = _now()
    row = {
        "ts": ts,
        "request_id": receipts.request_id(path, ts),
        "act": act,
        "path": path,
        "sha_before": sha_before,
        "sha_after": sha_after,
        "verdict": verdict,
        "why": why,
        "elder": elder,
        "approval_id": approval_id,
    }
    receipts.append(cfg, _record_from(receipts.Row, row))


def _row_outcome(row: Any, done_line: str) -> int:
    """Print the verdict of a row returned by land, rollback or recover; give its exit code."""
    verdict = _field(row, "verdict")
    why = _flat(_field(row, "why", "") or "")
    detail = json.dumps(_record_dict(row), sort_keys=True)
    if verdict == "DONE":
        _say(done_line, detail)
        return EXIT_DONE
    if verdict == "REFUSED":
        if not why.startswith(PREFIX):
            why = PREFIX + (why or "the act was refused.")
        _say(why, detail)
        return EXIT_REFUSED
    if not why.startswith(FAULT_PREFIX):
        why = FAULT_PREFIX + (why or "the act ended with verdict " + str(verdict) + ".")
    _say(why, detail)
    return EXIT_FAULT


# ---------------------------------------------------------------- commands


def _cmd_pin(ns: argparse.Namespace) -> int:
    cfg = _load_config(ns)
    target = _target(cfg, ns.path)
    p = _mod("pin").pin(target)
    sha = _field(p, "sha256")
    _receipt(cfg, "pin", target, sha, sha, "DONE")
    _say("PINNED " + target + " " + sha, json.dumps(_record_dict(p), sort_keys=True))
    return EXIT_DONE


def _cmd_rehearse(ns: argparse.Namespace) -> int:
    cfg = _load_config(ns)
    target = _target(cfg, ns.path)
    candidate = _candidate(ns.candidate, target)
    pin = _mod("pin")
    p = pin.pin(target)
    sha = _field(p, "sha256")
    cand_sha = pin.sha256_of(candidate)
    errors = _mod("errors")
    try:
        verdict = _mod("rehearse").rehearse(cfg, p, candidate)
    except errors.Refused as exc:
        _receipt(cfg, "rehearse", target, sha, sha, "REFUSED",
                 why=_flat(getattr(exc, "why", exc)))
        raise
    output = _field(verdict, "output", "") or ""
    after = pin.sha256_of(target)
    if _field(verdict, "would_land") is True:
        _receipt(cfg, "rehearse", target, sha, after, "WOULD-LAND",
                 why="candidate " + cand_sha)
        _say("WOULD LAND", output.rstrip("\n"))
        return EXIT_DONE
    why = _flat(_field(verdict, "why", "") or "")
    if why.startswith(PREFIX):
        why = why[len(PREFIX):]
    why = why or "the tests did not pass."
    _receipt(cfg, "rehearse", target, sha, after, "WOULD-REFUSE", why=why)
    _say("WOULD REFUSE: " + why, output.rstrip("\n"))
    return EXIT_REFUSED


def _approval_out(ns: argparse.Namespace, cfg: Any, target: str, candidate: str) -> str:
    """Where the approval goes, refused when the write could replace anything but an old approval.

    The approval file may not be the secret, the receipts, the config, the
    target or the candidate, may not lie inside any root, and an existing file
    there is replaced only when it is itself an approval record.
    """
    out = _abs(ns.out) if ns.out else candidate + ".approval.json"
    real = os.path.realpath(out)
    guarded = (
        ("the secret file", cfg.secret),
        ("the receipts file", cfg.receipts),
        ("the config file", _config_path(ns)),
        ("the target", target),
        ("the candidate", candidate),
    )
    for name, path in guarded:
        if real == os.path.realpath(path):
            raise _refused("the approval file " + out + " is " + name + "; an approval is never written over it.")
    if _mod("config").inside_roots(cfg, out):
        raise _refused("the approval file " + out + " lies inside a root; pass --out with a path outside every root.")
    if os.path.isdir(out):
        raise _refused("the approval file " + out + " is a folder.")
    if not os.path.isdir(os.path.dirname(out)):
        raise _refused("the folder for the approval file " + out + " does not exist.")
    if os.path.lexists(out):
        if os.path.islink(out) or not os.path.isfile(out):
            raise _refused("the approval file " + out + " exists and is not a regular file; it is never replaced.")
        errors = _mod("errors")
        try:
            with open(out, "r", encoding="utf-8") as handle:
                _mod("approve").Approval.from_json(handle.read())
        except (errors.Refused, ValueError, OSError):
            raise _refused(
                "the approval file " + out + " already holds a file that is not an approval record; it is never replaced."
            ) from None
    return out


def _cmd_approve(ns: argparse.Namespace) -> int:
    if ns.ttl is not None and ns.ttl <= 0:
        raise _refused("--ttl must be a positive number of seconds.")
    cfg = _load_config(ns)
    target = _target(cfg, ns.path)
    candidate = _candidate(ns.candidate, target)
    out = _approval_out(ns, cfg, target, candidate)
    pin = _mod("pin")
    p = pin.pin(target)
    cand_sha = pin.sha256_of(candidate)
    a = _mod("approve").approve(cfg, p, cand_sha, ttl_s=ns.ttl)
    data = _record_dict(a)
    _write_atomic(out, json.dumps(data, sort_keys=True, indent=1) + "\n")
    approval_id = _field(a, "id")
    sha = _field(p, "sha256")
    _receipt(cfg, "approve", target, sha, sha, "DONE",
             why="candidate " + cand_sha, approval_id=approval_id)
    _say("APPROVED " + approval_id, "written to " + out)
    return EXIT_DONE


def _read_approval(path: str) -> Any:
    """Read an approval file, refusing one that is missing or not an approval."""
    if not os.path.isfile(path):
        raise _refused("the approval file " + path + " does not exist.")
    approve = _mod("approve")
    errors = _mod("errors")
    try:
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
        if not isinstance(data, dict):
            raise ValueError("not a JSON object")
        return _record_from(approve.Approval, data)
    except (errors.Refused, errors.Fault):
        raise
    except (ValueError, TypeError, KeyError, OSError) as exc:
        raise _refused("the approval file " + path + " is not a readable approval: " + _flat(exc))


def _cmd_land(ns: argparse.Namespace) -> int:
    if not ns.approval:
        raise _refused("land needs --approval <file>; nothing lands without a signed approval.")
    cfg = _load_config(ns)
    target = _target(cfg, ns.path)
    candidate = _candidate(ns.candidate, target)
    a = _read_approval(_abs(ns.approval))
    p = _mod("pin").pin(target)
    row = _mod("land").land(cfg, p, candidate, a)
    return _row_outcome(row, "LANDED " + target + " " + str(_field(row, "sha_after")))


def _cmd_rollback(ns: argparse.Namespace) -> int:
    cfg = _load_config(ns)
    target = _target(cfg, ns.path)
    row = _mod("land").rollback(cfg, target)
    return _row_outcome(row, "ROLLED BACK " + target + " " + str(_field(row, "sha_after")))


def _cmd_recover(ns: argparse.Namespace) -> int:
    cfg = _load_config(ns)
    journal = _abs(ns.journal)
    if not os.path.isfile(journal):
        raise _refused("the journal " + journal + " does not exist.")
    row = _mod("land").recover(cfg, journal)
    path = str(_field(row, "path"))
    return _row_outcome(row, "RECOVERED " + path + " " + str(_field(row, "sha_after")))


def _cmd_receipts(ns: argparse.Namespace) -> int:
    cfg = _load_config(ns)
    path = _abs(ns.path) if ns.path else None
    found = _mod("receipts").rows(cfg, path)
    lines = [json.dumps(_record_dict(r), sort_keys=True) for r in found]
    _say("ROWS " + str(len(found)), *lines)
    return EXIT_DONE


def _cmd_verify(ns: argparse.Namespace) -> int:
    cfg = _load_config(ns)
    path = _abs(ns.path) if ns.path else None
    receipts = _mod("receipts")
    read = receipts.verify_chain(cfg, path)
    chain_acts = getattr(receipts, "CHAIN_ACTS", ("land", "rollback", "recover"))
    chained = sum(
        1 for r in receipts.rows(cfg, path)
        if _field(r, "act") in chain_acts and _field(r, "sha_after")
        and _field(r, "verdict") not in ("WOULD-LAND", "WOULD-REFUSE")
    )
    _say("VERIFIED " + str(chained) + " rows",
         str(chained) + " chain rows of " + str(read) + " rows read")
    return EXIT_DONE


# ---------------------------------------------------------------- the parser


def _parser() -> _Parser:
    common = _Parser(add_help=False)
    common.add_argument("--config", default=argparse.SUPPRESS,
                        help="the config file (default $" + CONFIG_ENV + ", else ./" + DEFAULT_CONFIG + ")")

    top = _Parser(prog="landlock",
                  description="Pin, rehearse, approve and land a file change, with rollback.")
    top.add_argument("--config", default=None,
                     help="the config file (default $" + CONFIG_ENV + ", else ./" + DEFAULT_CONFIG + ")")
    subs = top.add_subparsers(dest="cmd", metavar="command", required=True)

    s = subs.add_parser("pin", parents=[common], help="record a file's exact bytes")
    s.add_argument("path")
    s.set_defaults(run=_cmd_pin)

    s = subs.add_parser("rehearse", parents=[common], help="test a candidate away from the live file")
    s.add_argument("path")
    s.add_argument("candidate")
    s.set_defaults(run=_cmd_rehearse)

    s = subs.add_parser("approve", parents=[common], help="sign an approval for one candidate")
    s.add_argument("path")
    s.add_argument("candidate")
    s.add_argument("--ttl", type=int, default=None, help="seconds the approval stays valid")
    s.add_argument("--out", default=None, help="where to write the approval (default <candidate>.approval.json)")
    s.set_defaults(run=_cmd_approve)

    s = subs.add_parser("land", parents=[common], help="swap the candidate in, with rollback on failure")
    s.add_argument("path")
    s.add_argument("candidate")
    s.add_argument("--approval", default=None, help="the approval file written by approve")
    s.set_defaults(run=_cmd_land)

    s = subs.add_parser("rollback", parents=[common], help="put the elder copy back")
    s.add_argument("path")
    s.set_defaults(run=_cmd_rollback)

    s = subs.add_parser("recover", parents=[common], help="finish or undo a landing a crash cut short")
    s.add_argument("journal")
    s.set_defaults(run=_cmd_recover)

    s = subs.add_parser("receipts", parents=[common], help="list the receipt rows")
    s.add_argument("path", nargs="?", default=None)
    s.set_defaults(run=_cmd_receipts)

    s = subs.add_parser("verify", parents=[common], help="check the receipt chain has no gap")
    s.add_argument("path", nargs="?", default=None)
    s.set_defaults(run=_cmd_verify)
    return top


# ---------------------------------------------------------------- the entry


def _report(exc: BaseException) -> int:
    """Print the one line for an exception and give its exit code."""
    try:
        errors = _mod("errors")
        refused_cls, fault_cls = errors.Refused, errors.Fault
    except Exception:  # the errors module itself could not load
        refused_cls = fault_cls = ()
    if refused_cls and isinstance(exc, refused_cls):
        why = _flat(getattr(exc, "why", None) or exc)
        if not why.startswith(PREFIX):
            why = PREFIX + why
        print(why)
        return EXIT_REFUSED
    if fault_cls and isinstance(exc, fault_cls):
        why = _flat(getattr(exc, "why", None) or exc)
        if not why.startswith(FAULT_PREFIX):
            why = FAULT_PREFIX + why
        print(why)
        return EXIT_FAULT
    print(FAULT_PREFIX + type(exc).__name__ + ": " + _flat(exc))
    return EXIT_FAULT


def main(argv: Sequence[str] | None = None) -> int:
    """Run one command; return 0 on an act done, 2 on a refusal, 3 on a fault."""
    args = list(sys.argv[1:] if argv is None else argv)
    try:
        try:
            ns = _parser().parse_args(args)
        except SystemExit as stop:  # --help prints and stops cleanly
            return stop.code if isinstance(stop.code, int) else EXIT_DONE
        return ns.run(ns)
    except _Usage as exc:
        print(PREFIX + _flat(exc))
        return EXIT_REFUSED
    except KeyboardInterrupt:
        print(FAULT_PREFIX + "interrupted.")
        return EXIT_FAULT
    except Exception as exc:
        return _report(exc)


if __name__ == "__main__":
    sys.exit(main())

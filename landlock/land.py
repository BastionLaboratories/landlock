"""Swap a pinned file for approved new bytes in one atomic move, keep the old copy beside it, test what depends on it, and undo the swap by itself when that fails.

land: under a lock on the target, check the load, verify the approval (used
once only), check the pin, run the policies and resolve every dependent's
test command; then make sure the receipts name the verified old bytes
(writing a pin row only when nothing names them yet), lay the elder
copy beside the target, write the candidate to a temp file in the same
folder, fsync it and rename it over the target in one call, run the
dependents' tests, and measure the live file again. A failing dependent, or
live bytes other than the candidate's after the tests, puts the elder back.
A journal beside the target records each step, so recover can undo a landing
that a kill cut short. Recover never lands forward: it only puts the elder
back to bytes the receipts already name, or confirms a landing whose DONE row
stands. rollback puts the newest finished landing's elder back. Every outcome
appends one receipt row.

Refusals found before anything is written raise Refused (after their row is
appended, carrying sha_before only). Outcomes after the first write come back
as the returned row: DONE, REFUSED (a dependent failed and the landing was
undone) or FAULT (something broke; the undo was attempted and the why says
how it went). Nothing here prints.
"""

from __future__ import annotations

import datetime
import hashlib
import json
import os
import re
import stat
import subprocess
import time

from .approve import verify
from .config import inside_roots, tests_for
from .errors import Fault, Refused
from .pin import check
from .policy import run as run_policies
from .receipts import Row, append, request_id, rows

STEPS = ("elder-laid", "temp-written", "replaced", "tests-done")
JOURNAL_KEYS = (
    "target", "elder", "candidate_sha256", "sha_before", "step", "started_at", "approval_id",
)
CHAIN_ACTS = ("land", "rollback", "recover")
DRY_VERDICTS = ("WOULD-LAND", "WOULD-REFUSE")

_DEFAULT_WALL_S = 300.0
_DEFAULT_LOAD_MAX = 48.0
_STALE_EXTRA_S = 60.0
_CHUNK = 1024 * 1024
_HEX64 = re.compile(r"[0-9a-f]{64}")
_JOURNAL_NAME = re.compile(r"\.landlock_journal_(.+)\.json")


# ---------------------------------------------------------------- small helpers


def _now() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def _iso(moment: datetime.datetime) -> str:
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def _field(obj, name: str, default=None):
    """One field of a record, whether it is a class instance or a plain dict."""
    if isinstance(obj, dict):
        return obj.get(name, default)
    return getattr(obj, name, default)


def _flat(text) -> str:
    """Fold any text onto a single line."""
    return " ".join(str(text).split())


def _bare(exc: BaseException) -> str:
    """The reason inside an exception, without its REFUSED or FAULT prefix."""
    text = _flat(getattr(exc, "why", "") or exc or type(exc).__name__)
    for prefix in ("REFUSED: ", "FAULT: "):
        text = text.removeprefix(prefix)
    return text or type(exc).__name__


def _why_of(exc: BaseException) -> str:
    return getattr(exc, "why", "") or str(exc)


def _sha_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _read(path: str) -> bytes:
    """The whole file, refusing to follow a symbolic link or read a non-file."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise Fault(f"FAULT: {path} is not a regular file")
        chunks = []
        while True:
            chunk = os.read(fd, _CHUNK)
            if not chunk:
                break
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        os.close(fd)


def _measure(path) -> str:
    """The sha256 of the file now, or an empty string when it cannot be read."""
    if not isinstance(path, str) or not os.path.isabs(path):
        return ""
    try:
        return _sha_bytes(_read(path))
    except (OSError, Fault):
        return ""


def _fsync_dir(folder: str) -> None:
    fd = os.open(folder, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _write_new(path: str, data: bytes, mode: int) -> None:
    """Write data to a private temp name, set its mode, fsync it, leave it in place."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW | os.O_CLOEXEC
    fd = os.open(path, flags, 0o600)
    try:
        view = memoryview(data)
        while view:
            written = os.write(fd, view)
            view = view[written:]
        os.fchmod(fd, mode)
        os.fsync(fd)
    finally:
        os.close(fd)


def _put(path: str, data: bytes, mode: int, temp: str) -> None:
    """Write a file atomically: temp in the same folder, fsync, rename, fsync the folder."""
    _write_new(temp, data, mode)
    os.replace(temp, path)
    _fsync_dir(os.path.dirname(path))


def _unlink(path: str) -> None:
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass


# ---------------------------------------------------------------- names beside the target


def _temp_path(target: str) -> str:
    folder, base = os.path.split(target)
    return os.path.join(folder, f".landlock_tmp_{base}_{os.getpid()}")


def _journal_path(target: str) -> str:
    folder, base = os.path.split(target)
    return os.path.join(folder, f".landlock_journal_{base}.json")


def _journal_temp(target: str) -> str:
    folder, base = os.path.split(target)
    return os.path.join(folder, f".landlock_jtmp_{base}_{os.getpid()}")


def _lock_path(target: str) -> str:
    folder, base = os.path.split(target)
    return os.path.join(folder, f".landlock_lock_{base}")


def _stray_temps(target: str) -> list[str]:
    """Every temp a landing of this target may have left, whatever process wrote it."""
    folder, base = os.path.split(target)
    pattern = re.compile(re.escape(f".landlock_tmp_{base}_") + r"\d+")
    try:
        names = sorted(os.listdir(folder))
    except OSError:
        return []
    return [os.path.join(folder, name) for name in names if pattern.fullmatch(name)]


def _elder_path(target: str, moment: datetime.datetime) -> str:
    """<basename>.pre_land_<YYYYmmdd_HHMMSS> beside the target, never over an older elder."""
    base = f"{target}.pre_land_{moment.strftime('%Y%m%d_%H%M%S')}"
    path, n = base, 2
    while os.path.lexists(path):
        path = f"{base}_{n}"
        n += 1
    return path


def _write_journal(target: str, body: dict) -> None:
    data = (json.dumps(body, sort_keys=True) + "\n").encode("utf-8")
    _put(_journal_path(target), data, 0o600, _journal_temp(target))


def _remove_journal(target: str) -> None:
    _unlink(_journal_path(target))
    _fsync_dir(os.path.dirname(target))


# ---------------------------------------------------------------- config readings


def _walls(cfg):
    return _field(cfg, "walls", None) or {}


def _wall_s(cfg) -> float:
    value = _field(_walls(cfg), "test_wall_s", _DEFAULT_WALL_S)
    try:
        value = float(value)
    except (TypeError, ValueError):
        return _DEFAULT_WALL_S
    return value if value > 0 else _DEFAULT_WALL_S


def _load_max(cfg) -> float:
    value = _field(_walls(cfg), "load_max", _DEFAULT_LOAD_MAX)
    try:
        return float(value)
    except (TypeError, ValueError):
        return _DEFAULT_LOAD_MAX


def _dependents(cfg, target: str) -> list[str]:
    deps = _field(cfg, "dependents", None) or {}
    if not isinstance(deps, dict):
        return []
    found = deps.get(target)
    if found is None:
        norm = os.path.normpath(target)
        for key, value in deps.items():
            if os.path.normpath(str(key)) == norm:
                found = value
                break
    return [str(path) for path in (found or [])]


def _test_plans(cfg, target: str) -> list[tuple[str, list[str]]]:
    """Every dependent with its test command, resolved before anything is written."""
    plans = []
    for dep in _dependents(cfg, target):
        argv = [str(arg) for arg in (tests_for(cfg, dep) or [])]
        if not argv:
            raise Refused(f"REFUSED: no test command is set for the dependent {dep} of {target}")
        plans.append((dep, argv))
    return plans


def _pin_dict(p) -> dict:
    to_dict = getattr(p, "to_dict", None)
    if callable(to_dict):
        return dict(to_dict())
    if isinstance(p, dict):
        return dict(p)
    raw = p.to_json()
    return json.loads(raw) if isinstance(raw, (str, bytes)) else dict(raw)


# ---------------------------------------------------------------- the load wall


def _load_average() -> float | None:
    """The one-minute load average of this machine, or None when the platform cannot say."""
    try:
        return float(os.getloadavg()[0])
    except (OSError, AttributeError):
        return None


def _check_load(cfg) -> None:
    load = _load_average()
    limit = _load_max(cfg)
    if load is not None and load > limit:
        raise Refused(
            f"REFUSED: the one-minute load average is {load:g}, above the wall load_max of {limit:g}"
        )


# ---------------------------------------------------------------- the lock


def _take_lock(cfg, target: str) -> str:
    """Create the target's lock file, or refuse naming the age of the one that stands."""
    lock = _lock_path(target)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
    try:
        fd = os.open(lock, flags, 0o600)
    except FileExistsError:
        try:
            age = max(0.0, time.time() - os.lstat(lock).st_mtime)
        except OSError:
            age = 0.0
        stale_after = _wall_s(cfg) + _STALE_EXTRA_S
        why = (
            f"REFUSED: a lock stands at {lock}, {age:.0f} s old, so another act on {target} "
            f"is running"
        )
        if age > stale_after:
            why += (
                f"; it is older than {stale_after:g} s and looks stale, but only a person may "
                f"remove it once sure nothing runs"
            )
        raise Refused(why) from None
    try:
        os.write(fd, f"{os.getpid()} {_iso(_now())}\n".encode("ascii"))
    finally:
        os.close(fd)
    return lock


# ---------------------------------------------------------------- receipts


def _receipt(cfg, act: str, path, verdict: str, why: str = "", sha_before: str = "",
             sha_after: str = "", elder: str = "", approval_id: str = ""):
    """Append one receipt row; a path that is not absolute cannot carry a row and is skipped."""
    if not isinstance(path, str) or not os.path.isabs(path):
        return None
    ts = _iso(_now())
    row = Row(
        ts=ts,
        request_id=request_id(path, ts),
        act=act,
        path=path,
        sha_before=sha_before,
        sha_after=sha_after,
        verdict=verdict,
        why=_flat(why),
        elder=elder,
        approval_id=approval_id,
    )
    return append(cfg, row)


def _chain_rows(history) -> list:
    return [
        r for r in history
        if _field(r, "act") in CHAIN_ACTS
        and _field(r, "verdict") not in DRY_VERDICTS
        and _field(r, "sha_after")
    ]


def _named(cfg, target: str, sha: str, approval_id: str) -> bool:
    """True when the receipts name sha as bytes the target may hold now.

    Named are: the result of the newest chain row, any DONE pin or approve row
    written after it, and the starting bytes of a measured land row of this
    very approval (a landing that faulted after its swap).
    """
    history = rows(cfg, target)
    trusted: set[str] = set()
    for r in history:
        act, verdict = _field(r, "act"), _field(r, "verdict")
        if act in CHAIN_ACTS and verdict not in DRY_VERDICTS and _field(r, "sha_after"):
            trusted = {_field(r, "sha_after")}
            if approval_id and act == "land" and _field(r, "approval_id") == approval_id:
                trusted.add(_field(r, "sha_before"))
        elif act in ("pin", "approve") and verdict == "DONE":
            trusted.update(x for x in (_field(r, "sha_before"), _field(r, "sha_after")) if x)
    return sha in trusted


def _done_landing_of(cfg, target: str, candidate_sha: str, approval_id: str) -> bool:
    for r in rows(cfg, target):
        if (
            _field(r, "act") == "land"
            and _field(r, "verdict") == "DONE"
            and _field(r, "sha_after") == candidate_sha
            and (not approval_id or _field(r, "approval_id") == approval_id)
        ):
            return True
    return False


# ---------------------------------------------------------------- shared checks


def _check_place(cfg, target) -> None:
    """Refuse a target that is not absolute, outside the roots, a link, or not a file."""
    if not isinstance(target, str) or not target or not os.path.isabs(target):
        raise Refused(f"REFUSED: the target {target!r} is not an absolute path")
    if not inside_roots(cfg, target):
        raise Refused(f"REFUSED: {target} lies outside every root the config names")
    if os.path.islink(target):
        raise Refused(f"REFUSED: {target} is a symbolic link, and a landing never follows one")
    if not os.path.isfile(target):
        raise Refused(f"REFUSED: {target} is not an existing regular file")


def _check_no_journal(target: str) -> None:
    journal = _journal_path(target)
    if os.path.lexists(journal):
        raise Refused(
            f"REFUSED: an unfinished landing journal stands at {journal}; run recover on it first"
        )


def _read_candidate(candidate_path, target: str) -> bytes:
    if not isinstance(candidate_path, (str, os.PathLike)):
        raise Refused("REFUSED: the candidate must be given as a path")
    path = os.path.abspath(os.fspath(candidate_path))
    if os.path.normpath(path) == os.path.normpath(target):
        raise Refused(f"REFUSED: the candidate {path} is the live target itself")
    try:
        return _read(path)
    except FileNotFoundError:
        raise Refused(f"REFUSED: the candidate {path} does not exist") from None
    except Fault:
        raise Refused(f"REFUSED: the candidate {path} is not a regular file") from None
    except OSError as exc:
        reason = exc.strerror or type(exc).__name__
        raise Refused(f"REFUSED: the candidate {path} cannot be read ({reason})") from None


# ---------------------------------------------------------------- putting the old bytes back


def _restore(target: str, elder: str, sha_before: str, mode: int) -> None:
    """A fresh copy of the elder renamed over the target, then verified at sha_before."""
    if not elder or os.path.islink(elder) or not os.path.isfile(elder):
        raise Fault(f"FAULT: the elder copy {elder or '(none)'} is missing, so {target} cannot be restored")
    data = _read(elder)
    if _sha_bytes(data) != sha_before:
        raise Fault(f"FAULT: the elder copy {elder} does not hold the old bytes {sha_before}")
    _put(target, data, mode, _temp_path(target))
    after = _measure(target)
    if after != sha_before:
        raise Fault(f"FAULT: after restoring {target} its sha256 is {after or '(unreadable)'}, not {sha_before}")


def _settle(target: str, elder: str, sha_before: str, candidate_sha: str, mode: int,
            keep_forward: bool) -> tuple[str, str]:
    """Bring a stopped landing to a verified state; return (expected sha, what was done).

    keep_forward is true only when a DONE row already records the candidate as
    landed; otherwise the only move allowed is backward, to the elder.
    """
    for temp in _stray_temps(target):
        _unlink(temp)
    live = _measure(target)
    if keep_forward:
        if live == candidate_sha:
            return candidate_sha, "the landing had finished and its DONE row stands; the new bytes stay"
        raise Fault(
            f"FAULT: {target} holds sha256 {live or '(unreadable)'}, not the landed {candidate_sha}"
        )
    if live == sha_before:
        return sha_before, "the live file still held its old bytes; any temp was removed"
    if live == candidate_sha:
        _restore(target, elder, sha_before, mode)
        return sha_before, "the new bytes had been swapped in; the elder copy was put back"
    raise Fault(
        f"FAULT: {target} holds sha256 {live or '(unreadable)'}, neither the old {sha_before} "
        f"nor the new {candidate_sha}"
    )


# ---------------------------------------------------------------- the dependents' tests


def _run_dependents(plans, target: str, wall: float) -> str:
    """An empty string when every dependent's tests pass; else the refusal naming the first that failed."""
    for dep, argv in plans:
        folder = os.path.dirname(dep)
        if not os.path.isdir(folder):
            folder = os.path.dirname(target)
        try:
            done = subprocess.run(
                argv,
                cwd=folder,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                timeout=wall,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return (
                f"REFUSED: the tests of the dependent {dep} ran past the wall of {wall:g} s, "
                f"so the landing of {target} was rolled back"
            )
        if done.returncode != 0:
            return (
                f"REFUSED: the tests of the dependent {dep} failed with exit code {done.returncode}, "
                f"so the landing of {target} was rolled back"
            )
    return ""


# ---------------------------------------------------------------- land


def land(cfg, p, candidate_path, a, policies=()):
    """Land the candidate over the pinned file under a verified approval; return the receipt row."""
    target = _field(p, "path", "") or ""
    approval_id = str(_field(a, "id", "") or "")

    def refused(exc):
        _receipt(cfg, "land", target, "REFUSED", _why_of(exc), _measure(target), "", "", approval_id)

    def faulted_before(exc):
        return _receipt(
            cfg, "land", target, "FAULT",
            f"FAULT: the landing of {target} broke before anything was written "
            f"({type(exc).__name__}: {_bare(exc)})",
            _measure(target), "", "", approval_id,
        )

    try:
        _check_place(cfg, target)
        _check_load(cfg)
        lock = _take_lock(cfg, target)
    except Refused as exc:
        refused(exc)
        raise
    except Exception as exc:
        return faulted_before(exc)
    try:
        return _land_locked(cfg, p, candidate_path, a, policies, target, approval_id,
                            refused, faulted_before)
    finally:
        _unlink(lock)


def _land_locked(cfg, p, candidate_path, a, policies, target, approval_id, refused, faulted_before):
    # Every check before anything is written.
    try:
        _check_no_journal(target)
        candidate = _read_candidate(candidate_path, target)
        candidate_sha = _sha_bytes(candidate)
        verify(cfg, a, p, candidate_sha)
        if approval_id and any(
            _field(r, "act") == "land" and _field(r, "verdict") == "DONE"
            and _field(r, "approval_id") == approval_id
            for r in rows(cfg, target)
        ):
            raise Refused(
                f"REFUSED: the approval {approval_id} was already used by a finished landing of "
                f"{target}; an approval lands once"
            )
        check(p)
        run_policies(list(policies or ()), {
            "act": "land",
            "target": target,
            "candidate_sha256": candidate_sha,
            "pin": _pin_dict(p),
        })
        plans = _test_plans(cfg, target)
        mode = stat.S_IMODE(os.stat(target).st_mode)
        live = _read(target)
        sha_before = str(_field(p, "sha256", ""))
        if _sha_bytes(live) != sha_before:
            raise Refused(f"REFUSED: the bytes of {target} moved after the pin check")
        if candidate_sha == sha_before:
            raise Refused(f"REFUSED: the candidate's bytes equal the live bytes of {target}; nothing to land")
    except Refused as exc:
        refused(exc)
        raise
    except Exception as exc:
        return faulted_before(exc)

    def receipt(verdict, why):
        return _receipt(cfg, "land", target, verdict, why, sha_before, _measure(target), elder, approval_id)

    moment = _now()
    folder = os.path.dirname(target)
    journal = {
        "target": target,
        "elder": "",
        "candidate_sha256": candidate_sha,
        "sha_before": sha_before,
        "step": "",
        "started_at": _iso(moment),
        "approval_id": approval_id,
    }
    step = None
    elder = ""
    done_row = None
    try:
        # The verified old bytes must stand named in the receipts, where recover can
        # trust them; a pin row is written only when nothing there names them yet.
        if not _named(cfg, target, sha_before, ""):
            _receipt(cfg, "pin", target, "DONE", "", sha_before, sha_before, "", approval_id)

        elder = _elder_path(target, moment)
        journal["elder"] = elder
        _put(elder, live, mode, _temp_path(target))
        step = "elder-laid"
        _write_journal(target, dict(journal, step=step))

        temp = _temp_path(target)
        _write_new(temp, candidate, mode)
        step = "temp-written"
        _write_journal(target, dict(journal, step=step))

        os.replace(temp, target)
        _fsync_dir(folder)
        step = "replaced"
        _write_journal(target, dict(journal, step=step))

        failing = _run_dependents(plans, target, _wall_s(cfg))
        if failing:
            _restore(target, elder, sha_before, mode)
            _remove_journal(target)
            return receipt("REFUSED", failing)

        after = _measure(target)
        if after != candidate_sha:
            names = ", ".join(dep for dep, _ in plans) or "(none)"
            _restore(target, elder, sha_before, mode)
            _remove_journal(target)
            return receipt(
                "FAULT",
                f"FAULT: after the tests of the dependents ({names}) {target} held sha256 "
                f"{after or '(unreadable)'} instead of the approved candidate's {candidate_sha}, "
                f"so the elder was put back",
            )

        step = "tests-done"
        _write_journal(target, dict(journal, step=step))
        done_row = receipt("DONE", "")
        _remove_journal(target)
        return done_row
    except Exception as exc:
        if done_row is not None:
            # The landing stands and is recorded; only its journal is left for recover to clear.
            return done_row
        why = (
            f"FAULT: the landing of {target} broke after step {step or 'none'} "
            f"({type(exc).__name__}: {_bare(exc)})"
        )
        try:
            expected, _ = _settle(target, elder, sha_before, candidate_sha, mode, keep_forward=False)
            if _measure(target) != expected:
                raise Fault(f"FAULT: {target} did not verify at {expected} after the undo")
            _remove_journal(target)
            why += "; the old bytes were put back and verified"
        except Exception as undo_exc:
            why += (
                f"; the undo also broke ({_bare(undo_exc)}), so the journal stays at "
                f"{_journal_path(target)} for recover"
            )
        return receipt("FAULT", why)


# ---------------------------------------------------------------- rollback


def rollback(cfg, path):
    """Put back the elder copy of the newest finished landing of path; return the receipt row."""
    target = os.fspath(path) if isinstance(path, (str, os.PathLike)) else path

    def refused(exc):
        _receipt(cfg, "rollback", target, "REFUSED", _why_of(exc), _measure(target))

    try:
        _check_place(cfg, target)
        lock = _take_lock(cfg, target)
    except Refused as exc:
        refused(exc)
        raise
    except Exception as exc:
        return _receipt(
            cfg, "rollback", target, "FAULT",
            f"FAULT: the rollback of {target} broke before anything was written "
            f"({type(exc).__name__}: {_bare(exc)})",
            _measure(target),
        )
    try:
        return _rollback_locked(cfg, target, refused)
    finally:
        _unlink(lock)


def _rollback_locked(cfg, target, refused):
    live_before = _measure(target)
    try:
        _check_no_journal(target)
        landed = [
            r for r in rows(cfg, target)
            if _field(r, "act") == "land" and _field(r, "verdict") == "DONE" and _field(r, "elder")
        ]
        if not landed:
            raise Refused(f"REFUSED: the receipts hold no finished landing of {target} to roll back")
        last = landed[-1]
        landed_sha = _field(last, "sha_after", "")
        old_sha = _field(last, "sha_before", "")
        elder = _field(last, "elder", "")
        if live_before != landed_sha:
            raise Refused(
                f"REFUSED: {target} no longer holds the bytes its newest landing left ({landed_sha}), "
                f"so a rollback would overwrite a later change"
            )
        if not elder or os.path.islink(elder) or not os.path.isfile(elder):
            raise Refused(f"REFUSED: the elder copy {elder or '(none)'} of the newest landing of {target} is missing")
        if _measure(elder) != old_sha:
            raise Refused(f"REFUSED: the elder copy {elder} no longer holds the old bytes {old_sha}")
        mode = stat.S_IMODE(os.stat(target).st_mode)
    except Refused as exc:
        refused(exc)
        raise
    except Exception as exc:
        return _receipt(
            cfg, "rollback", target, "FAULT",
            f"FAULT: the rollback of {target} broke before anything was written "
            f"({type(exc).__name__}: {_bare(exc)})",
            live_before,
        )

    def receipt(verdict, why):
        return _receipt(cfg, "rollback", target, verdict, why, live_before, _measure(target), elder)

    try:
        for temp in _stray_temps(target):
            _unlink(temp)
        _restore(target, elder, old_sha, mode)
        return receipt("DONE", "")
    except Exception as exc:
        for temp in _stray_temps(target):
            _unlink(temp)
        return receipt("FAULT", f"FAULT: the rollback of {target} broke ({type(exc).__name__}: {_bare(exc)})")


# ---------------------------------------------------------------- recover


def _target_of_journal(journal_path) -> str:
    """The target a journal's file name speaks for, or an empty string."""
    if not isinstance(journal_path, str) or not os.path.isabs(journal_path):
        return ""
    folder, name = os.path.split(journal_path)
    match = _JOURNAL_NAME.fullmatch(name)
    return os.path.join(folder, match.group(1)) if match else ""


def _load_journal(cfg, journal_path: str) -> dict:
    """Read and check a journal; refuse anything that is not a landing journal inside the roots."""
    if not os.path.isabs(journal_path):
        raise Refused(f"REFUSED: the journal path {journal_path!r} is not absolute")
    folder, name = os.path.split(journal_path)
    match = _JOURNAL_NAME.fullmatch(name)
    if not match:
        raise Refused(f"REFUSED: {journal_path} is not named like a landing journal")
    if os.path.islink(journal_path):
        raise Refused(f"REFUSED: the journal {journal_path} is a symbolic link")
    try:
        raw = _read(journal_path)
    except FileNotFoundError:
        raise Refused(f"REFUSED: no journal stands at {journal_path}") from None
    except (OSError, Fault):
        raise Refused(f"REFUSED: the journal {journal_path} cannot be read") from None
    try:
        body = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise Refused(f"REFUSED: the journal {journal_path} is not valid JSON") from None
    if not isinstance(body, dict):
        raise Refused(f"REFUSED: the journal {journal_path} is not a JSON object")
    # approval_id joined the shape later; a journal without it reads as naming no approval.
    body.setdefault("approval_id", "")
    missing = [key for key in JOURNAL_KEYS if key not in body]
    if missing:
        raise Refused(f"REFUSED: the journal {journal_path} lacks {', '.join(missing)}")
    if any(not isinstance(body[key], str) for key in JOURNAL_KEYS):
        raise Refused(f"REFUSED: every field of the journal {journal_path} must be text")
    if body["step"] not in STEPS:
        raise Refused(f"REFUSED: the journal {journal_path} names an unknown step {body['step']!r}")
    for key in ("sha_before", "candidate_sha256"):
        if not _HEX64.fullmatch(body[key]):
            raise Refused(f"REFUSED: the journal {journal_path} carries a {key} that is not a sha256")
    target = body["target"]
    if not os.path.isabs(target) or os.path.dirname(target) != folder or os.path.basename(target) != match.group(1):
        raise Refused(f"REFUSED: the journal {journal_path} names a target that does not sit beside it")
    elder = body["elder"]
    if (
        not os.path.isabs(elder)
        or os.path.dirname(elder) != folder
        or not os.path.basename(elder).startswith(os.path.basename(target) + ".pre_land_")
    ):
        raise Refused(f"REFUSED: the journal {journal_path} names an elder that is not beside its target")
    if not inside_roots(cfg, target):
        raise Refused(f"REFUSED: {target} lies outside every root the config names")
    if os.path.islink(target):
        raise Refused(f"REFUSED: {target} is a symbolic link, and a recovery never follows one")
    return body


def _record_cut_off_landing(cfg, body: dict, live: str) -> None:
    """A landing killed after its swap never wrote its row; write it now so the chain has no gap."""
    target = body["target"]
    chain = _chain_rows(rows(cfg, target))
    if chain and _field(chain[-1], "sha_after") == live:
        return
    _receipt(
        cfg, "land", target, "FAULT",
        f"FAULT: a landing of {target} was cut off after step {body['step']} before it wrote "
        f"its receipt; recover found its journal",
        body["sha_before"], live, body["elder"], body["approval_id"],
    )


def recover(cfg, journal_path):
    """Undo, or confirm, the landing an unfinished journal describes; return the receipt row."""
    jp = os.fspath(journal_path) if isinstance(journal_path, (str, os.PathLike)) else journal_path
    if not isinstance(jp, str):
        raise Refused("REFUSED: the journal must be given as a path")
    named_target = _target_of_journal(jp)

    def refused(exc, target=named_target):
        _receipt(cfg, "recover", target, "REFUSED", _why_of(exc), _measure(target))

    try:
        body = _load_journal(cfg, jp)
        lock = _take_lock(cfg, body["target"])
    except Refused as exc:
        refused(exc)
        raise
    try:
        return _recover_locked(cfg, jp, refused)
    finally:
        _unlink(lock)


def _recover_locked(cfg, jp, refused):
    try:
        body = _load_journal(cfg, jp)  # read again under the lock
    except Refused as exc:
        refused(exc)
        raise
    target, elder, step = body["target"], body["elder"], body["step"]
    sha_before, candidate_sha = body["sha_before"], body["candidate_sha256"]
    approval_id = body["approval_id"]
    live_before = _measure(target)

    def receipt(verdict, why):
        return _receipt(cfg, "recover", target, verdict, why, live_before, _measure(target), elder)

    try:
        keep_forward = (
            step == "tests-done"
            and live_before == candidate_sha
            and _done_landing_of(cfg, target, candidate_sha, approval_id)
        )
        moves = not keep_forward and live_before == candidate_sha and live_before != sha_before
        if moves and not _named(cfg, target, sha_before, approval_id):
            raise Refused(
                f"REFUSED: the journal {jp} would move {target} to bytes {sha_before} that no DONE "
                f"row and no approval in the receipts names; nothing was changed, and the elder "
                f"{elder} stays for a person to judge"
            )
    except Refused as exc:
        refused(exc, target)
        raise
    except Exception as exc:
        return receipt(
            "FAULT",
            f"FAULT: the journal {jp} could not be judged ({type(exc).__name__}: {_bare(exc)}); "
            f"it stays for another recover",
        )

    try:
        if moves:
            _record_cut_off_landing(cfg, body, live_before)
        if os.path.isfile(elder) and not os.path.islink(elder):
            mode = stat.S_IMODE(os.stat(elder).st_mode)
        elif os.path.isfile(target):
            mode = stat.S_IMODE(os.stat(target).st_mode)
        else:
            mode = 0o600
        expected, done = _settle(target, elder, sha_before, candidate_sha, mode, keep_forward)
        after = _measure(target)
        if after != expected:
            raise Fault(f"FAULT: {target} did not verify at {expected} after the recovery")
        _unlink(jp)
        _fsync_dir(os.path.dirname(jp))
        return receipt("DONE", f"the landing stopped after step {step}; {done}")
    except Exception as exc:
        return receipt(
            "FAULT",
            f"FAULT: the journal {jp} at step {step} could not be settled "
            f"({type(exc).__name__}: {_bare(exc)}); it stays for another recover",
        )

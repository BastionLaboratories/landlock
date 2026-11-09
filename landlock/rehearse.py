"""Try a new version of a file inside a sealed sandbox that shows the new bytes at the file's own path, and report whether its tests pass.

Nothing is copied and the live file is never written. The candidate bytes go
into one scratch file under a fresh temporary folder, with the live file's
mode, and the file's test command runs inside bubblewrap:

- the whole machine is mounted read-only;
- the target's folder is mounted read-only over its own path, and the scratch
  file is mounted OVER the live file's path (a file over a file; and over every
  other path a shown folder gives the live file), so a
  test that reaches the file by its absolute path, an absolute import, or
  through its working folder sees the candidate; its siblings show as they
  are, read-only; a private file beside the target that this user cannot read
  is no fault, and the size of the folder does not matter;
- a write to the live path lands in the scratch file and is thrown away with
  it; a write anywhere else in the folder is refused by the kernel (read-only
  file system); TMPDIR is a fresh writable folder;
- the user's real home folder is replaced by a fresh empty memory-backed
  folder, which is also HOME;
- walls.rehearse_ro_dirs lists absolute folders that are mounted read-only
  over their own paths, never copied; they may lie outside every root because
  nothing can be written through them; an entry is written without '..' and is
  never the home folder whole; an entry whose written and resolved paths both
  lie at or below the target's folder is skipped, a repeat is skipped, and
  every mount is laid outer folder first, so an entry under the hidden home
  (a link to a data folder, a per-user package folder) is shown again at the
  path as written; a link hidden under the home is followed for its contents
  and mounted at its own written path, so a test that reaches a folder through
  the link finds it; a link whose spelling stays visible (on the machine or in
  another shown folder) is left as it is and its folder is mounted at its
  resolved path, where the link leads;
- walls.rehearse_extra_dirs (absolute, inside a root; kept for configs written
  before rehearse_ro_dirs) is mounted read-only the same way, never copied;
- the configured secret and receipts files are hidden behind an empty file at
  every path the sandbox would show them, their own paths and every path a
  shown folder (a link spelling included) gives them;
- there is no network, the child dies with its parent, and it gets a new session;
- the run stops at the time wall (walls.test_wall_s).

The candidate likewise shows at the live file's real path and at every other
path a shown folder gives it, so a test that reaches the target through a
listed link reads the candidate too.

Bubblewrap is required: without the bwrap program on PATH the rehearsal is
refused. It is also refused when the one-minute load average is above
walls.load_max, when the temporary folder lies inside a root, when the target
is a symbolic link, when a folder named by a wall is not an absolute existing
folder, climbs with '..', is the home folder whole or is a link that would show
the home through another path, or when one of the caller's policies says no. A test command that
names the live file, a path inside a root, or the secret or receipts paths is
refused before anything runs; that screen only catches plain mistakes, and the
read-only sandbox is what actually keeps the live file safe. The answer is a
Verdict that carries the child's whole output.
"""

from __future__ import annotations

import json
import os
import shutil
import signal
import stat
import subprocess
import tempfile
from collections.abc import Mapping
from dataclasses import dataclass

from landlock import policy as _policy
from landlock.config import inside_roots, tests_for
from landlock.errors import Refused
from landlock.pin import check, sha256_of

DEFAULT_TEST_WALL_S = 300  # because: the contract's default walls.test_wall_s when a config gives none
DEFAULT_LOAD_MAX = 48.0  # because: the contract's default walls.load_max when a config gives none
_FALLBACK_PATH = "/usr/local/bin:/usr/bin:/bin"  # because: the usual system PATH when the caller's PATH is empty
_REAP_WAIT_S = 10  # because: seconds to collect a killed child's last output before giving up on it


@dataclass(frozen=True)
class Verdict:
    """The rehearsal's answer: {would_land, output, why}."""

    would_land: bool
    output: str
    why: str

    def to_dict(self) -> dict:
        """The verdict as a plain dict."""
        return {"would_land": self.would_land, "output": self.output, "why": self.why}

    def to_json(self) -> str:
        """The verdict as one JSON text with sorted keys."""
        return json.dumps(self.to_dict(), sort_keys=True)

    @classmethod
    def from_dict(cls, data: object) -> "Verdict":
        """Build a Verdict from a plain dict, refusing anything malformed."""
        if not isinstance(data, dict):
            raise Refused("REFUSED: a verdict must be a JSON object.")
        for name in ("would_land", "output", "why"):
            if name not in data:
                raise Refused(f"REFUSED: a verdict is missing the key {name}.")
        if not isinstance(data["would_land"], bool):
            raise Refused("REFUSED: a verdict needs would_land as true or false.")
        if not isinstance(data["output"], str) or not isinstance(data["why"], str):
            raise Refused("REFUSED: a verdict needs output and why as text.")
        return cls(data["would_land"], data["output"], data["why"])

    @classmethod
    def from_json(cls, text: object) -> "Verdict":
        """Build a Verdict from JSON text (a dict is accepted too)."""
        if isinstance(text, dict):
            return cls.from_dict(text)
        if not isinstance(text, (str, bytes, bytearray)):
            raise Refused("REFUSED: a verdict must be given as JSON text.")
        try:
            data = json.loads(text)
        except (ValueError, UnicodeDecodeError):
            raise Refused("REFUSED: a verdict must be valid JSON.") from None
        return cls.from_dict(data)


def _field(obj: object, name: str, default: object = None) -> object:
    """Read a field from a record that is either an object or a plain dict."""
    if isinstance(obj, Mapping):
        return obj.get(name, default)
    return getattr(obj, name, default)


def _walls_value(cfg: object, name: str, default: object) -> object:
    walls = _field(cfg, "walls", None)
    if walls is None:
        return default
    return _field(walls, name, default)


def _bwrap() -> str:
    """The absolute path of bwrap on PATH, or a refusal (bubblewrap is required)."""
    found = shutil.which("bwrap")
    if not found:
        raise Refused(
            "REFUSED: bubblewrap is required to rehearse a change and no bwrap program was found on PATH."
        )
    return os.path.abspath(found)


def _load_1m() -> float:
    """The machine's one-minute load average, read from the platform."""
    return os.getloadavg()[0]


def _check_load(cfg: object) -> None:
    """Refuse when the one-minute load average is above walls.load_max."""
    limit = _walls_value(cfg, "load_max", DEFAULT_LOAD_MAX)
    if isinstance(limit, bool) or not isinstance(limit, (int, float)) or limit <= 0:
        raise Refused(f"REFUSED: walls.load_max must be a number above zero, got {limit!r}.")
    try:
        load = _load_1m()
    except OSError:
        raise Refused("REFUSED: the one-minute load average cannot be read on this machine.") from None
    if load > limit:
        raise Refused(
            f"REFUSED: the one-minute load average {load:.2f} is above walls.load_max {limit}; "
            "rehearse again when the machine is quieter."
        )


def _wall(cfg: object) -> float:
    """The time wall in seconds for one test run."""
    value = _walls_value(cfg, "test_wall_s", DEFAULT_TEST_WALL_S)
    if isinstance(value, bool) or not isinstance(value, (int, float)) or value <= 0:
        raise Refused(f"REFUSED: the test wall must be a number of seconds above zero, got {value!r}.")
    return value


def _roots(cfg: object) -> list[str]:
    roots = _field(cfg, "roots", None) or []
    return [os.fspath(r) for r in roots]


def _named_paths(path: str) -> set[str]:
    """A path as written and with links resolved, both without a trailing slash."""
    names = {path.rstrip(os.sep) or os.sep, os.path.realpath(path).rstrip(os.sep) or os.sep}
    return {n for n in names if n}


def _below(base: str, path: str) -> bool:
    """True when path is base itself or lies below it (both already normalized)."""
    try:
        return os.path.commonpath([base, path]) == base
    except ValueError:
        return False


def _depth(path: str) -> int:
    """How many names deep a normalized absolute path is; the root folder is 0."""
    return len([part for part in path.split(os.sep) if part])


def _screen(cfg: object, live: str, argv: list) -> list[str]:
    """Refuse a test command that names the live file, a root, or the config's private paths."""
    if not isinstance(argv, (list, tuple)) or not argv:
        raise Refused(f"REFUSED: no test command is set for {live}.")
    live_names = _named_paths(live)
    root_names = set()
    for root in _roots(cfg):
        root_names |= _named_paths(root)
    private = {}
    for key in ("secret", "receipts"):
        value = _field(cfg, key, None)
        if value:
            for name in _named_paths(os.fspath(value)):
                private[name] = key
    out = []
    for arg in argv:
        if not isinstance(arg, str) or not arg:
            raise Refused(f"REFUSED: every word of the test command must be non-empty text, got {arg!r}.")
        for name in live_names:
            if name in arg:
                raise Refused(
                    f"REFUSED: the test command names the live target {live}; a rehearsal never reaches the live file."
                )
        for name in root_names:
            if name == os.sep:
                continue
            if arg == name or (name + os.sep) in arg:
                raise Refused(
                    f"REFUSED: the test command names a path inside the root {name}; a rehearsal reaches the target only through its sandbox."
                )
        for name, key in private.items():
            if name in arg:
                raise Refused(f"REFUSED: the test command names the config's {key} path {name}.")
        if os.path.isabs(arg) and inside_roots(cfg, arg):
            raise Refused(
                f"REFUSED: the test command names {arg}, which lies inside a root; a rehearsal reaches the target only through its sandbox."
            )
        out.append(arg)
    return out


def _temp_parent(cfg: object) -> str:
    """The folder that will hold the rehearsal's scratch; refused when it lies inside a root."""
    where = os.path.realpath(tempfile.gettempdir())
    if inside_roots(cfg, where):
        raise Refused(
            f"REFUSED: the temporary folder {where} lies inside a root, so the scratch would sit among "
            "the files it guards; point TMPDIR outside every root."
        )
    return where


def _wall_list(cfg: object, name: str) -> list:
    """The raw list a folder wall holds (empty when unset), refusing anything that is not a list."""
    raw = _walls_value(cfg, name, None)
    if raw is None:
        return []
    if isinstance(raw, str) or not isinstance(raw, (list, tuple)):
        raise Refused(f"REFUSED: walls.{name} must be a list of folders.")
    return list(raw)


def _absolute_folder(name: str, item: object) -> str:
    """An entry of a folder wall as an absolute existing folder, normalized as written; refused otherwise."""
    if isinstance(item, os.PathLike):
        item = os.fspath(item)
    if not isinstance(item, str) or not item or "\x00" in item or not os.path.isabs(item):
        raise Refused(f"REFUSED: walls.{name} holds {item!r}, which is not an absolute path.")
    if not os.path.exists(item):
        raise Refused(f"REFUSED: walls.{name} names {item}, which does not exist.")
    if not os.path.isdir(item):
        raise Refused(f"REFUSED: walls.{name} names {item}, which is not a folder.")
    return os.path.normpath(item)


def _refuse_whole_home(name: str, written: str, real: str, real_home: str | None) -> None:
    """Refuse a folder wall entry that is the real home folder itself, by either spelling."""
    if real_home and real_home in (written, real):
        raise Refused(
            f"REFUSED: walls.{name} names {written}, which is your home folder whole; "
            "list the entries of it a test needs."
        )


def _mount_view(mounts: list, path: str) -> str | None:
    """The host path that a sandbox path shows under the planned folder mounts, or None when a memory folder hides it.

    mounts is a list of (sandbox path, host folder or None for a memory folder)
    in the order bubblewrap lays them; the machine itself is read-only at its own
    paths beneath them, and the last mount over a path wins.
    """
    host: str | None = path
    for dest, source in mounts:
        if _below(dest, path):
            if source is None:
                host = None
            else:
                rel = os.path.relpath(path, dest)
                host = source if rel == os.curdir else os.path.join(source, rel)
    return host


def _spellings(mounts: list, real_target: str) -> list[str]:
    """Every sandbox path that shows the host file real_target under the planned folder mounts (its own path and every alias a mount gives it)."""
    out: list[str] = []
    for dest, source in [(os.sep, os.sep)] + list(mounts):
        if source is None:
            continue
        real_source = os.path.realpath(source)
        if not _below(real_source, real_target):
            continue
        rel = os.path.relpath(real_target, real_source)
        name = dest if rel == os.curdir else os.path.normpath(os.path.join(dest, rel))
        host = _mount_view(mounts, name)
        if host is not None and os.path.realpath(host) == real_target and name not in out:
            out.append(name)
    return out


def _ordered(plan: list) -> list:
    """Mounts sorted so an outer folder is laid before the folders and files inside it: (sandbox path, host source, rank)."""
    return sorted(plan, key=lambda m: (_depth(m[0]), m[2]))


def _shown_mounts(cfg: object, folder: str, real_home: str | None) -> list[tuple[str, str]]:
    """The read-only folder mounts beside the target's folder, as (sandbox path, host folder), checked.

    walls.rehearse_extra_dirs: inside a root, mounted at the resolved path (as in
    0.1.0). walls.rehearse_ro_dirs: anywhere, written without '..', never the home
    folder whole. An entry is skipped when both its written and its resolved
    path lie at or below the target's folder (that folder already shows it), and
    a repeat is skipped. An entry spelled through a link is mounted at the path as
    written when that spelling lies hidden under the memory folder over the home
    (the link cannot be seen there, so its path is made a folder); when the
    written spelling stays visible in the sandbox (on the read-only machine or
    inside another shown folder) the link itself is still there, so the folder
    is mounted at its resolved path and the link leads to it. A link whose
    resolved folder holds the home, mounted at a path other than its own, would
    show the home past its memory folder and is refused.
    """
    base = [(real_home, None, 0)] if real_home else []
    planned: list[tuple[str, str]] = []

    def known(dest: str) -> bool:
        return any(dest == d for d, _ in planned) or dest == folder

    for item in _wall_list(cfg, "rehearse_extra_dirs"):
        path = _absolute_folder("rehearse_extra_dirs", item)
        if not inside_roots(cfg, path):
            raise Refused(f"REFUSED: walls.rehearse_extra_dirs names {path}, which lies outside every root.")
        real = os.path.realpath(path)
        _refuse_whole_home("rehearse_extra_dirs", path, real, real_home)
        if _below(folder, real) or known(real):
            continue
        planned.append((real, real))

    entries = []
    for item in _wall_list(cfg, "rehearse_ro_dirs"):
        if isinstance(item, os.PathLike):
            item = os.fspath(item)
        if isinstance(item, str) and os.pardir in item.split(os.sep):
            raise Refused(
                f"REFUSED: walls.rehearse_ro_dirs holds {item}, which climbs with '..'; write the folder's path without it."
            )
        written = _absolute_folder("rehearse_ro_dirs", item)
        real = os.path.realpath(written)
        _refuse_whole_home("rehearse_ro_dirs", written, real, real_home)
        entries.append((written, real))

    for written, real in sorted(entries, key=lambda e: _depth(e[0])):
        if _below(folder, written) and _below(folder, real):
            continue
        dest = written
        if written != real:
            sofar = [(d, s) for d, s, _ in _ordered(base + [(d, s, 1) for d, s in planned] + [(folder, folder, 2)])]
            if _mount_view(sofar, os.path.dirname(written)) is not None:
                dest = real
        if dest != real and real_home and _below(real, real_home):
            raise Refused(
                f"REFUSED: walls.rehearse_ro_dirs names {written}, a link to {real}, which would show your home "
                "folder through another path; list the entries of the home a test needs."
            )
        if known(dest):
            continue
        planned.append((dest, real))
    return planned


def _place_candidate(candidate: str, dest: str, mode: int) -> None:
    """Write the candidate bytes into a new scratch file at dest with the live file's mode, never through a link."""
    with open(candidate, "rb") as src:
        data = src.read()
    fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        view = memoryview(data)
        while view:
            written = os.write(fd, view)
            view = view[written:]
        os.fchmod(fd, mode)
    finally:
        os.close(fd)


def _real_home() -> str | None:
    """The user's real home folder when it can be hidden, else None."""
    home = os.path.realpath(os.path.expanduser("~"))
    if not os.path.isabs(home) or home == os.sep or not os.path.isdir(home):
        return None
    return home


def _sandbox_argv(
    bwrap: str,
    folder: str,
    live_path: str,
    scratch_file: str,
    shown: list[tuple[str, str]],
    real_home: str | None,
    tmp: str,
    spare_home: str,
    mask: str,
    hidden: list[str],
    argv: list[str],
) -> list[str]:
    """The bwrap command line: machine read-only, shown folders read-only, the candidate at every spelling of the live path, the private files masked at every spelling, empty HOME, no network."""
    cmd = [
        bwrap,
        "--unshare-all",
        "--die-with-parent",
        "--new-session",
        "--ro-bind", "/", "/",
        "--dev", "/dev",
        "--proc", "/proc",
    ]
    # (sandbox path, host source or None for a memory folder, rank): outer folders first.
    plan = []
    if real_home:
        plan.append((real_home, None, 0))
    for dest, source in shown:
        plan.append((dest, source, 1))
    plan.append((folder, folder, 2))
    plan = _ordered(plan)
    folders = [(dest, source) for dest, source, _ in plan]
    # The candidate over the live path and over every other path a shown folder gives it.
    for name in _spellings(folders, live_path):
        plan.append((name, scratch_file, 3))
    for dest, source, rank in _ordered(plan):
        if source is None:
            cmd += ["--tmpfs", dest]
        elif rank == 3:
            cmd += ["--bind", source, dest]
        else:
            cmd += ["--ro-bind", source, dest]
    cmd += ["--bind", tmp, tmp]
    home = real_home or spare_home
    if not real_home:
        cmd += ["--tmpfs", spare_home]
    masked: list[str] = []
    for path in hidden:
        for name in _spellings(folders, os.path.realpath(path)):
            if name not in masked:
                masked.append(name)
                cmd += ["--ro-bind", mask, name]
    cmd += [
        "--chdir", folder,
        "--clearenv",
        "--setenv", "PATH", os.environ.get("PATH") or _FALLBACK_PATH,
        "--setenv", "HOME", home,
        "--setenv", "TMPDIR", tmp,
        "--setenv", "LANG", "C.UTF-8",
        "--",
    ]
    return cmd + list(argv)


def _run(cmd: list[str], wall: float) -> tuple[int | None, str]:
    """Run the sandbox under the wall; (exit code or None on the wall, whole output)."""
    proc = subprocess.Popen(
        cmd,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        start_new_session=True,
    )
    try:
        out, _ = proc.communicate(timeout=wall)
        return proc.returncode, out.decode("utf-8", errors="replace")
    except subprocess.TimeoutExpired:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            proc.kill()
        try:
            out, _ = proc.communicate(timeout=_REAP_WAIT_S)
        except subprocess.TimeoutExpired:
            proc.kill()
            out, _ = proc.communicate()
        return None, (out or b"").decode("utf-8", errors="replace")


def _pin_dict(p: object) -> dict:
    if hasattr(p, "to_dict"):
        return p.to_dict()
    return json.loads(p.to_json())


def rehearse(cfg, p, candidate_path, policies=()) -> Verdict:
    """Test the candidate shown over the live file's path inside bubblewrap; nothing is copied and the live file is never written."""
    bwrap = _bwrap()
    _check_load(cfg)
    check(p)
    live = os.fspath(p.path)
    if not inside_roots(cfg, live):
        raise Refused(f"REFUSED: the target {live} lies outside every root.")

    if not isinstance(candidate_path, (str, os.PathLike)):
        raise Refused("REFUSED: the candidate must be given as a path.")
    candidate = os.path.abspath(os.fspath(candidate_path))
    if not os.path.isfile(candidate):
        raise Refused(f"REFUSED: the candidate is not a readable file: {candidate}")

    folder = os.path.realpath(os.path.dirname(live))
    base = os.path.basename(live)
    live_path = os.path.join(folder, base)
    if os.path.islink(live_path) or not os.path.isfile(live_path):
        raise Refused(
            f"REFUSED: the target {live} is not a plain file (a symbolic link is never followed); "
            "the candidate is shown only over a plain file."
        )
    parent = _temp_parent(cfg)
    real_home = _real_home()
    shown = _shown_mounts(cfg, folder, real_home)
    argv = _screen(cfg, live, tests_for(cfg, live))
    wall = _wall(cfg)

    _policy.run(
        policies,
        {"act": "rehearse", "target": live, "candidate_sha256": sha256_of(candidate), "pin": _pin_dict(p)},
    )

    hidden = []
    for key in ("secret", "receipts"):
        value = _field(cfg, key, None)
        if value and os.path.isfile(os.fspath(value)):
            hidden.append(os.fspath(value))
    mode = stat.S_IMODE(os.stat(live_path).st_mode)

    top = tempfile.mkdtemp(prefix="landlock_rehearse_", dir=parent)
    try:
        scratch_file = os.path.join(top, "candidate")
        tmp = os.path.join(top, "tmp")
        spare_home = os.path.join(top, "home")
        mask = os.path.join(top, "mask")
        os.mkdir(tmp, 0o700)
        os.mkdir(spare_home, 0o700)
        fd = os.open(mask, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o400)
        os.close(fd)
        _place_candidate(candidate, scratch_file, mode)

        cmd = _sandbox_argv(
            bwrap, folder, live_path, scratch_file, shown, real_home, tmp, spare_home, mask, hidden, argv
        )
        code, output = _run(cmd, wall)
    finally:
        shutil.rmtree(top, ignore_errors=True)

    check(p)
    if code is None:
        return Verdict(False, output, f"the tests ran past the wall of {wall} seconds (walls.test_wall_s) and were stopped")
    if code == 0:
        return Verdict(True, output, "the tests passed with the candidate shown at the live path")
    if code < 0:
        return Verdict(False, output, f"the tests were stopped by signal {-code}")
    return Verdict(False, output, f"the tests exited {code}")

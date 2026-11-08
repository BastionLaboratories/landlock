"""Try a new version of a file in a throwaway copy of its folder, inside a sealed sandbox, and report whether its tests pass.

The rehearsal never writes the live file. It copies the live file's folder into
a fresh temporary folder, puts the candidate bytes where the live file sits in
that copy, and runs the file's test command inside bubblewrap:

- the whole machine is mounted read-only;
- the copy is mounted OVER the live folder's own path, so a test that reaches
  the file by its absolute path, an absolute import, or a sibling file sees the
  candidate and never the old bytes (the real folder is untouched);
- folders a test needs outside the target's folder are named in
  walls.rehearse_extra_dirs (absolute, inside a root); each is copied and
  mounted over its own path the same way;
- the user's real home folder is replaced by a fresh empty memory-backed
  folder, which is also HOME;
- the configured secret and receipts files are hidden behind an empty file;
- there is no network, the child dies with its parent, and it gets a new session;
- the run stops at the time wall (walls.test_wall_s).

Bubblewrap is required: without the bwrap program on PATH the rehearsal is
refused. It is also refused when the one-minute load average is above
walls.load_max, when the temporary folder lies inside a root, or when one of
the caller's policies says no. A test command that names the live file, a
path inside a root, or the secret or receipts paths is refused before anything
runs; that screen only catches plain mistakes, and the read-only sandbox is
what actually keeps the live file safe. The answer is a Verdict that carries
the child's whole output.
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
from landlock.errors import Fault, Refused
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
    """True when path is base itself or lies below it (both already resolved)."""
    try:
        return os.path.commonpath([base, path]) == base
    except ValueError:
        return False


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
                    f"REFUSED: the test command names a path inside the root {name}; a rehearsal runs only in its scratch copy."
                )
        for name, key in private.items():
            if name in arg:
                raise Refused(f"REFUSED: the test command names the config's {key} path {name}.")
        if os.path.isabs(arg) and inside_roots(cfg, arg):
            raise Refused(
                f"REFUSED: the test command names {arg}, which lies inside a root; a rehearsal runs only in its scratch copy."
            )
        out.append(arg)
    return out


def _temp_parent(cfg: object) -> str:
    """The folder that will hold the scratch copies; refused when it lies inside a root."""
    where = os.path.realpath(tempfile.gettempdir())
    if inside_roots(cfg, where):
        raise Refused(
            f"REFUSED: the temporary folder {where} lies inside a root, so the copy would hold itself; "
            "point TMPDIR outside every root."
        )
    return where


def _extra_dirs(cfg: object, folder: str) -> list[str]:
    """The checked walls.rehearse_extra_dirs, resolved, without the target's own folder or folders under it."""
    raw = _walls_value(cfg, "rehearse_extra_dirs", None)
    if raw is None:
        return []
    if isinstance(raw, str) or not isinstance(raw, (list, tuple)):
        raise Refused("REFUSED: walls.rehearse_extra_dirs must be a list of folders.")
    out = []
    for item in raw:
        if isinstance(item, os.PathLike):
            item = os.fspath(item)
        if not isinstance(item, str) or not item or not os.path.isabs(item):
            raise Refused(f"REFUSED: walls.rehearse_extra_dirs holds {item!r}, which is not an absolute path.")
        if not os.path.isdir(item):
            raise Refused(f"REFUSED: walls.rehearse_extra_dirs names {item}, which is not a folder.")
        if not inside_roots(cfg, item):
            raise Refused(f"REFUSED: walls.rehearse_extra_dirs names {item}, which lies outside every root.")
        real = os.path.realpath(item)
        if _below(folder, real) or real in out:
            continue
        out.append(real)
    return out


def _skip_special(folder: str, names: list[str]) -> list[str]:
    """Leave out anything that is not a plain file, a folder or a link (pipes, sockets, devices)."""
    skipped = []
    for name in names:
        try:
            mode = os.lstat(os.path.join(folder, name)).st_mode
        except OSError:
            skipped.append(name)
            continue
        if not (stat.S_ISREG(mode) or stat.S_ISDIR(mode) or stat.S_ISLNK(mode)):
            skipped.append(name)
    return skipped


def _copy(src: str, dest: str) -> None:
    try:
        shutil.copytree(src, dest, symlinks=True, ignore=_skip_special)
    except (OSError, shutil.Error) as exc:
        raise Fault(f"FAULT: the folder {src} could not be copied for the rehearsal: {exc}") from None


def _place_candidate(candidate: str, dest: str, mode: int) -> None:
    """Write the candidate bytes at dest inside the scratch copy, never through a link."""
    if os.path.lexists(dest):
        if os.path.isdir(dest) and not os.path.islink(dest):
            shutil.rmtree(dest)
        else:
            os.unlink(dest)
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
    work: str,
    extras: list[tuple[str, str]],
    tmp: str,
    spare_home: str,
    mask: str,
    hidden: list[str],
    argv: list[str],
) -> list[str]:
    """The bwrap command line: machine read-only, copies over their own paths, empty HOME, no network."""
    cmd = [
        bwrap,
        "--unshare-all",
        "--die-with-parent",
        "--new-session",
        "--ro-bind", "/", "/",
        "--dev", "/dev",
        "--proc", "/proc",
    ]
    real_home = _real_home()
    # (path, rank, args): outer folders are mounted before the folders inside them.
    mounts = []
    if real_home:
        mounts.append((real_home, 0, ["--tmpfs", real_home]))
    for copy, dest in extras:
        mounts.append((dest, 1, ["--bind", copy, dest]))
    mounts.append((folder, 2, ["--bind", work, folder]))
    mounts.sort(key=lambda m: (len(m[0].rstrip(os.sep).split(os.sep)), m[1]))
    for _, _, args in mounts:
        cmd += args
    cmd += ["--bind", tmp, tmp]
    home = real_home or spare_home
    if not real_home:
        cmd += ["--tmpfs", spare_home]
    for path in hidden:
        if real_home and _below(real_home, os.path.realpath(path)):
            continue
        cmd += ["--ro-bind", mask, path]
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
    """Test the candidate in a scratch copy of the target's folder inside bubblewrap; the live file is never written."""
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
    parent = _temp_parent(cfg)
    extras = _extra_dirs(cfg, folder)
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
    mode = stat.S_IMODE(os.stat(live).st_mode)

    top = tempfile.mkdtemp(prefix="landlock_rehearse_", dir=parent)
    try:
        work = os.path.join(top, "work")
        tmp = os.path.join(top, "tmp")
        spare_home = os.path.join(top, "home")
        mask = os.path.join(top, "mask")
        _copy(folder, work)
        copies = []
        for n, extra in enumerate(extras):
            copy = os.path.join(top, f"extra_{n}")
            _copy(extra, copy)
            copies.append((copy, extra))
        os.mkdir(tmp, 0o700)
        os.mkdir(spare_home, 0o700)
        fd = os.open(mask, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o400)
        os.close(fd)
        _place_candidate(candidate, os.path.join(work, base), mode)

        cmd = _sandbox_argv(bwrap, folder, work, copies, tmp, spare_home, mask, hidden, argv)
        code, output = _run(cmd, wall)
    finally:
        shutil.rmtree(top, ignore_errors=True)

    check(p)
    if code is None:
        return Verdict(False, output, f"the tests ran past the wall of {wall} seconds (walls.test_wall_s) and were stopped")
    if code == 0:
        return Verdict(True, output, "the tests passed in the scratch copy")
    if code < 0:
        return Verdict(False, output, f"the tests were stopped by signal {-code}")
    return Verdict(False, output, f"the tests exited {code}")

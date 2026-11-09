"""Checks that a rehearsal shows the new bytes at the live path inside bubblewrap, copies nothing, and never touches the live file.

Refusals come first, each matched by its exact "REFUSED: " opening words; then
the verdicts that say the change would not land; then the positive road.
Every file a test makes stays under pytest's tmp_path: the rehearsal's own
temporary folder is pointed at tmp_path/scratch for every test.
"""

from __future__ import annotations

import hashlib
import importlib
import os
import shutil
import sys
import tempfile
import time
from pathlib import Path

import pytest
from landlock.errors import Refused
from landlock.pin import pin
from landlock.rehearse import Verdict, rehearse

rehearse_mod = importlib.import_module("landlock.rehearse")

OLD = b"VALUE = 'old'\n"
NEW = b"VALUE = 'new'\n"

needs_bwrap = pytest.mark.skipif(
    shutil.which("bwrap") is None,
    reason="bubblewrap is required for rehearse and is not on PATH",
)


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def code(*statements: str) -> list[str]:
    """A python3 -c argv from simple statements joined by semicolons (the TOML test config holds no newline)."""
    return [sys.executable if os.path.isabs(sys.executable) else "python3", "-c", "; ".join(statements)]


def hex_of(path: Path) -> str:
    """A path spelled in hex, so a test can reach it without naming it in the argv."""
    return str(path).encode("utf-8").hex()


def probe(tmp_path: Path, body: str, *args: str) -> list[str]:
    """A test command that runs a small script kept under tmp_path/probes (outside every root), with its arguments."""
    where = tmp_path / "probes"
    where.mkdir(exist_ok=True)
    script = where / ("probe_%d.py" % len(list(where.iterdir())))
    script.write_text(body, encoding="utf-8")
    python = sys.executable if os.path.isabs(sys.executable) else "python3"
    return [python, str(script), *args]


WRITE_REFUSED = (
    "import errno\n"
    "def write_refused(path):\n"
    "    try:\n"
    "        with open(path, 'a') as handle:\n"
    "            handle.write('x')\n"
    "    except OSError as exc:\n"
    "        return exc.errno == errno.EROFS\n"
    "    return False\n"
)


@pytest.fixture(autouse=True)
def scratch(tmp_path, monkeypatch) -> Path:
    """The rehearsal's temporary folders go under tmp_path/scratch, never the system temp."""
    where = tmp_path / "scratch"
    where.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(where))
    return where


@pytest.fixture
def live(tmp_root) -> Path:
    """The live file inside the root, with a sibling the tests can look for."""
    path = tmp_root / "app.py"
    path.write_bytes(OLD)
    (tmp_root / "helper.txt").write_bytes(b"sibling\n")
    return path


@pytest.fixture
def candidate(tmp_path) -> Path:
    """The candidate bytes in a staging folder outside the root."""
    stage = tmp_path / "stage"
    stage.mkdir()
    path = stage / "app.py"
    path.write_bytes(NEW)
    return path


# ---------------------------------------------------------------- must fail


def test_refuses_a_malformed_verdict_record():
    with pytest.raises(Refused) as caught:
        Verdict.from_json('{"would_land": "yes", "output": "", "why": ""}')
    assert caught.value.why.startswith("REFUSED: a verdict needs would_land")
    with pytest.raises(Refused) as caught:
        Verdict.from_json("not json")
    assert caught.value.why.startswith("REFUSED: a verdict must be valid JSON")


def test_refuses_without_bubblewrap(cfg, live, candidate, tmp_path, monkeypatch, scratch):
    empty = tmp_path / "empty_bin"
    empty.mkdir()
    monkeypatch.setenv("PATH", str(empty))
    p = pin(str(live))
    with pytest.raises(Refused) as caught:
        rehearse(cfg, p, str(candidate))
    assert caught.value.why.startswith("REFUSED: bubblewrap is required")
    assert live.read_bytes() == OLD
    assert list(scratch.iterdir()) == []


def test_refuses_an_empty_path_too(cfg, live, candidate, monkeypatch):
    monkeypatch.setenv("PATH", "")
    monkeypatch.chdir(live.parent)
    with pytest.raises(Refused) as caught:
        rehearse(cfg, pin(str(live)), str(candidate))
    assert caught.value.why.startswith("REFUSED: bubblewrap is required")


@needs_bwrap
def test_refuses_a_test_command_that_names_the_live_target(make_cfg, live, candidate, scratch):
    cfg = make_cfg(default=["cat", str(live)])
    with pytest.raises(Refused) as caught:
        rehearse(cfg, pin(str(live)), str(candidate))
    assert caught.value.why.startswith("REFUSED: the test command names the live target")
    assert live.read_bytes() == OLD
    # Refused before any run: no scratch copy was ever made.
    assert list(scratch.iterdir()) == []


@needs_bwrap
def test_refuses_the_live_target_hidden_inside_code(make_cfg, live, candidate, scratch):
    cfg = make_cfg(default=code("open(%r, 'w').write('x')" % str(live)))
    with pytest.raises(Refused) as caught:
        rehearse(cfg, pin(str(live)), str(candidate))
    assert caught.value.why.startswith("REFUSED: the test command names the live target")
    assert live.read_bytes() == OLD
    assert list(scratch.iterdir()) == []


@needs_bwrap
def test_refuses_a_test_command_that_names_a_path_inside_a_root(make_cfg, live, candidate, tmp_root, scratch):
    other = tmp_root / "other.txt"
    other.write_bytes(b"other\n")
    cfg = make_cfg(default=["cat", str(other)])
    with pytest.raises(Refused) as caught:
        rehearse(cfg, pin(str(live)), str(candidate))
    assert caught.value.why.startswith("REFUSED: the test command names a path inside the root")
    assert list(scratch.iterdir()) == []


@needs_bwrap
def test_refuses_a_test_command_that_names_the_root_itself(make_cfg, live, candidate, tmp_root, scratch):
    cfg = make_cfg(default=["ls", str(tmp_root)])
    with pytest.raises(Refused) as caught:
        rehearse(cfg, pin(str(live)), str(candidate))
    assert caught.value.why.startswith("REFUSED: the test command names a path inside the root")
    assert list(scratch.iterdir()) == []


@needs_bwrap
def test_refuses_a_test_command_that_names_the_secret(make_cfg, live, candidate, secret_file, scratch):
    cfg = make_cfg(default=["cat", str(secret_file)])
    with pytest.raises(Refused) as caught:
        rehearse(cfg, pin(str(live)), str(candidate))
    assert caught.value.why.startswith("REFUSED: the test command names the config's secret path")
    assert list(scratch.iterdir()) == []


@needs_bwrap
def test_refuses_a_moved_pin(cfg, live, candidate, scratch):
    p = pin(str(live))
    live.write_bytes(b"VALUE = 'moved'\n")
    with pytest.raises(Refused) as caught:
        rehearse(cfg, p, str(candidate))
    assert caught.value.why.startswith("REFUSED: the bytes moved")
    assert list(scratch.iterdir()) == []


@needs_bwrap
def test_refuses_a_missing_candidate(cfg, live, tmp_path, scratch):
    with pytest.raises(Refused) as caught:
        rehearse(cfg, pin(str(live)), str(tmp_path / "stage" / "nothing.py"))
    assert caught.value.why.startswith("REFUSED: the candidate is not a readable file")
    assert list(scratch.iterdir()) == []


@needs_bwrap
def test_refuses_a_target_outside_every_root(cfg, candidate, tmp_path, scratch):
    outside = tmp_path / "outside"
    outside.mkdir()
    stray = outside / "app.py"
    stray.write_bytes(OLD)
    with pytest.raises(Refused) as caught:
        rehearse(cfg, pin(str(stray)), str(candidate))
    assert caught.value.why.startswith("REFUSED: the target ")
    assert "outside every root" in caught.value.why
    assert list(scratch.iterdir()) == []


@needs_bwrap
def test_refuses_when_the_load_is_over_the_wall(cfg, live, candidate, monkeypatch, scratch):
    monkeypatch.setattr(rehearse_mod, "_load_1m", lambda: 99.5)
    cfg.walls["load_max"] = 4.0
    with pytest.raises(Refused) as caught:
        rehearse(cfg, pin(str(live)), str(candidate))
    assert caught.value.why.startswith("REFUSED: the one-minute load average 99.50 is above walls.load_max 4.0")
    assert list(scratch.iterdir()) == []


@needs_bwrap
def test_refuses_when_the_load_cannot_be_read(cfg, live, candidate, monkeypatch, scratch):
    def broken() -> float:
        raise OSError("no load average here")

    monkeypatch.setattr(rehearse_mod, "_load_1m", broken)
    with pytest.raises(Refused) as caught:
        rehearse(cfg, pin(str(live)), str(candidate))
    assert caught.value.why.startswith("REFUSED: the one-minute load average cannot be read")
    assert list(scratch.iterdir()) == []


@needs_bwrap
def test_refuses_a_temporary_folder_inside_a_root(cfg, live, candidate, tmp_root, monkeypatch):
    inside = tmp_root / "tmp_inside"
    inside.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(inside))
    with pytest.raises(Refused) as caught:
        rehearse(cfg, pin(str(live)), str(candidate))
    assert caught.value.why.startswith("REFUSED: the temporary folder")
    assert list(inside.iterdir()) == []


@needs_bwrap
def test_refuses_when_a_policy_says_no(cfg, live, candidate, scratch):
    def no_today(event: dict) -> tuple[bool, str]:
        return False, "no rehearsals today"

    with pytest.raises(Refused) as caught:
        rehearse(cfg, pin(str(live)), str(candidate), policies=[no_today])
    assert caught.value.why == "REFUSED: no rehearsals today"
    assert list(scratch.iterdir()) == []


@needs_bwrap
def test_refuses_extra_dirs_outside_every_root(cfg, live, candidate, tmp_path, scratch):
    outside = tmp_path / "outside_dir"
    outside.mkdir()
    cfg.walls["rehearse_extra_dirs"] = [str(outside)]
    with pytest.raises(Refused) as caught:
        rehearse(cfg, pin(str(live)), str(candidate))
    assert caught.value.why.startswith("REFUSED: walls.rehearse_extra_dirs names")
    assert "outside every root" in caught.value.why
    assert list(scratch.iterdir()) == []


@needs_bwrap
def test_refuses_extra_dirs_that_are_not_absolute_folders(cfg, live, candidate, tmp_root, scratch):
    cfg.walls["rehearse_extra_dirs"] = ["relative/tests"]
    with pytest.raises(Refused) as caught:
        rehearse(cfg, pin(str(live)), str(candidate))
    assert caught.value.why.startswith("REFUSED: walls.rehearse_extra_dirs holds")
    cfg.walls["rehearse_extra_dirs"] = [str(tmp_root / "helper.txt")]
    with pytest.raises(Refused) as caught:
        rehearse(cfg, pin(str(live)), str(candidate))
    assert caught.value.why.startswith("REFUSED: walls.rehearse_extra_dirs names")
    assert "not a folder" in caught.value.why
    cfg.walls["rehearse_extra_dirs"] = str(tmp_root)
    with pytest.raises(Refused) as caught:
        rehearse(cfg, pin(str(live)), str(candidate))
    assert caught.value.why.startswith("REFUSED: walls.rehearse_extra_dirs must be a list of folders")
    assert list(scratch.iterdir()) == []


@needs_bwrap
def test_refuses_ro_dirs_that_are_relative_missing_or_files(cfg, live, candidate, tmp_path, scratch):
    cfg.walls["rehearse_ro_dirs"] = ["relative/lib"]
    with pytest.raises(Refused) as caught:
        rehearse(cfg, pin(str(live)), str(candidate))
    assert caught.value.why == "REFUSED: walls.rehearse_ro_dirs holds 'relative/lib', which is not an absolute path."
    missing = tmp_path / "not_there"
    cfg.walls["rehearse_ro_dirs"] = [str(missing)]
    with pytest.raises(Refused) as caught:
        rehearse(cfg, pin(str(live)), str(candidate))
    assert caught.value.why == f"REFUSED: walls.rehearse_ro_dirs names {missing}, which does not exist."
    plain = tmp_path / "plain.txt"
    plain.write_bytes(b"a file\n")
    cfg.walls["rehearse_ro_dirs"] = [str(plain)]
    with pytest.raises(Refused) as caught:
        rehearse(cfg, pin(str(live)), str(candidate))
    assert caught.value.why == f"REFUSED: walls.rehearse_ro_dirs names {plain}, which is not a folder."
    dangling = tmp_path / "dangling"
    os.symlink(str(missing), str(dangling))
    cfg.walls["rehearse_ro_dirs"] = [str(dangling)]
    with pytest.raises(Refused) as caught:
        rehearse(cfg, pin(str(live)), str(candidate))
    assert caught.value.why == f"REFUSED: walls.rehearse_ro_dirs names {dangling}, which does not exist."
    cfg.walls["rehearse_ro_dirs"] = str(tmp_path)
    with pytest.raises(Refused) as caught:
        rehearse(cfg, pin(str(live)), str(candidate))
    assert caught.value.why == "REFUSED: walls.rehearse_ro_dirs must be a list of folders."
    assert live.read_bytes() == OLD
    assert list(scratch.iterdir()) == []


@needs_bwrap
def test_refuses_the_home_folder_listed_whole(cfg, live, candidate, tmp_path, monkeypatch, scratch):
    home = tmp_path / "home"
    home.mkdir()
    (home / "private.txt").write_bytes(b"private\n")
    monkeypatch.setenv("HOME", str(home))
    alias = tmp_path / "home_alias"
    os.symlink(str(home), str(alias))
    for entry in (str(home), str(home) + "/", str(alias)):
        cfg.walls["rehearse_ro_dirs"] = [entry]
        with pytest.raises(Refused) as caught:
            rehearse(cfg, pin(str(live)), str(candidate))
        assert caught.value.why.startswith("REFUSED: walls.rehearse_ro_dirs names ")
        assert "which is your home folder whole" in caught.value.why
    assert list(scratch.iterdir()) == []


@needs_bwrap
def test_refuses_a_link_that_would_show_the_home_through_another_path(cfg, live, candidate, tmp_path, monkeypatch, scratch):
    outer = tmp_path / "outer"
    home = outer / "home"
    home.mkdir(parents=True)
    monkeypatch.setenv("HOME", str(home))
    up = home / "up"
    os.symlink(str(outer), str(up))
    cfg.walls["rehearse_ro_dirs"] = [str(up)]
    with pytest.raises(Refused) as caught:
        rehearse(cfg, pin(str(live)), str(candidate))
    assert caught.value.why == (
        f"REFUSED: walls.rehearse_ro_dirs names {up}, a link to {outer}, which would show your home "
        "folder through another path; list the entries of the home a test needs."
    )
    assert list(scratch.iterdir()) == []


@needs_bwrap
def test_refuses_a_ro_dir_that_climbs_with_dotdot(cfg, live, candidate, tmp_path, scratch):
    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()
    entry = str(tmp_path / "a") + "/../b"
    cfg.walls["rehearse_ro_dirs"] = [entry]
    with pytest.raises(Refused) as caught:
        rehearse(cfg, pin(str(live)), str(candidate))
    assert caught.value.why == (
        f"REFUSED: walls.rehearse_ro_dirs holds {entry}, which climbs with '..'; write the folder's path without it."
    )
    assert list(scratch.iterdir()) == []


@needs_bwrap
def test_refuses_a_target_that_is_a_symbolic_link(cfg, tmp_root, candidate, scratch):
    real = tmp_root / "real.py"
    real.write_bytes(OLD)
    link = tmp_root / "app.py"
    os.symlink(str(real), str(link))
    with pytest.raises(Refused) as caught:
        rehearse(cfg, pin(str(link)), str(candidate))
    assert caught.value.why.startswith(f"REFUSED: the target {link} is not a plain file")
    assert real.read_bytes() == OLD
    assert list(scratch.iterdir()) == []


@needs_bwrap
def test_the_live_path_inside_the_sandbox_shows_the_candidate(make_cfg, live, candidate):
    # The argv spells the live path and its folder in hex, so it passes the
    # screen. Opened by its absolute path, or imported through its absolute
    # folder, the file must show the candidate, never the old bytes.
    cfg = make_cfg(
        default=code(
            "import sys",
            "target = bytes.fromhex(sys.argv[1]).decode()",
            "folder = bytes.fromhex(sys.argv[2]).decode()",
            "body = open(target, 'rb').read()",
            "print('absolute read', body)",
            "assert body == %r, body" % NEW,
            "sys.path.insert(0, folder)",
            "import app",
            "print('absolute import', app.VALUE, app.__file__ == target)",
            "assert app.VALUE == 'new', app.VALUE",
        )
        + [hex_of(live), hex_of(live.parent)]
    )
    p = pin(str(live))
    v = rehearse(cfg, p, str(candidate))
    assert v.would_land is True, v.output
    assert "absolute import new True" in v.output
    assert live.read_bytes() == OLD
    assert pin(str(live)).sha256 == p.sha256


@needs_bwrap
def test_a_write_to_the_live_path_lands_in_the_copy_never_the_live_file(make_cfg, live, candidate):
    cfg = make_cfg(
        default=code(
            "import sys",
            "target = bytes.fromhex(sys.argv[1]).decode()",
            "open(target, 'w').write('overwritten')",
            "print('wrote', open(target).read())",
        )
        + [hex_of(live)]
    )
    p = pin(str(live))
    v = rehearse(cfg, p, str(candidate))
    assert v.would_land is True, v.output
    assert "wrote overwritten" in v.output
    assert live.read_bytes() == OLD
    assert pin(str(live)).sha256 == p.sha256


@needs_bwrap
def test_a_write_elsewhere_in_the_root_fails_read_only(make_cfg, tmp_root, candidate):
    # The target sits in a sub-folder; the rest of the root is read-only.
    pkg = tmp_root / "pkg"
    pkg.mkdir()
    target = pkg / "app.py"
    target.write_bytes(OLD)
    elsewhere = tmp_root / "elsewhere.txt"
    elsewhere.write_bytes(b"keep\n")
    cfg = make_cfg(
        default=code(
            "import sys",
            "open(bytes.fromhex(sys.argv[1]).decode(), 'w').write('overwritten')",
        )
        + [hex_of(elsewhere)]
    )
    p = pin(str(target))
    v = rehearse(cfg, p, str(candidate))
    assert v.would_land is False
    assert "Read-only file system" in v.output
    assert v.why.startswith("the tests exited ")
    assert elsewhere.read_bytes() == b"keep\n"
    assert target.read_bytes() == OLD


@needs_bwrap
def test_a_test_past_the_wall_would_refuse_naming_the_wall(make_cfg, live, candidate):
    cfg = make_cfg(
        default=code("import time", "print('started', flush=True)", "time.sleep(60)"),
        walls={"test_wall_s": 1},
    )
    began = time.monotonic()
    v = rehearse(cfg, pin(str(live)), str(candidate))
    assert time.monotonic() - began < 30
    assert v.would_land is False
    assert "wall" in v.why
    assert "test_wall_s" in v.why
    assert "started" in v.output
    assert live.read_bytes() == OLD


@needs_bwrap
def test_a_failing_test_would_refuse_with_its_exit_code(make_cfg, live, candidate):
    cfg = make_cfg(default=code("import sys", "print('it broke')", "sys.exit(3)"))
    v = rehearse(cfg, pin(str(live)), str(candidate))
    assert v.would_land is False
    assert v.why == "the tests exited 3"
    assert "it broke" in v.output
    assert live.read_bytes() == OLD


# ---------------------------------------------------------------- positive road


@needs_bwrap
def test_a_passing_test_would_land_with_its_output(make_cfg, live, candidate, tmp_root, scratch):
    cfg = make_cfg(
        default=code(
            "import os, sys",
            "body = open('app.py', 'rb').read()",
            "assert body == %r, body" % NEW,
            "assert open('helper.txt', 'rb').read() == b'sibling\\n'",
            # 0.1.1 (show, never copy): the target's folder is read-only, so a
            # new file beside the target cannot be made (the mount is read-only).
            "assert os.statvfs('.').f_flag & os.ST_RDONLY, 'the folder is writable'",
            "assert not os.access('.', os.W_OK), 'the folder is writable'",
            "home = os.environ['HOME']",
            "assert home == bytes.fromhex(sys.argv[1]).decode(), home",
            "assert os.listdir(home) == [], os.listdir(home)",
            "open(os.path.join(home, 'h'), 'w').write('ok')",
            "tmp = os.environ['TMPDIR']",
            "open(os.path.join(tmp, 't'), 'w').write('ok')",
            "print('saw the candidate')",
        )
        + [os.path.realpath(os.path.expanduser("~")).encode("utf-8").hex()]
    )
    p = pin(str(live))
    before = sorted(x.name for x in tmp_root.iterdir())
    v = rehearse(cfg, p, str(candidate))
    assert v.would_land is True, v.output
    assert "saw the candidate" in v.output
    assert live.read_bytes() == OLD
    assert pin(str(live)).sha256 == p.sha256 == sha(OLD)
    # The live folder gained nothing and the scratch copy is gone.
    assert sorted(x.name for x in tmp_root.iterdir()) == before
    assert list(scratch.iterdir()) == []
    assert candidate.read_bytes() == NEW


@needs_bwrap
def test_the_sandbox_has_no_network(make_cfg, live, candidate):
    cfg = make_cfg(
        default=code(
            "import socket",
            "names = sorted(n for _, n in socket.if_nameindex())",
            "print('links', names)",
            "assert names == ['lo'], names",
        )
    )
    v = rehearse(cfg, pin(str(live)), str(candidate))
    assert v.would_land is True, v.output
    assert "links ['lo']" in v.output


RECORD_LOCK_FOLDER = "/tmp/bastion_record_locks"  # because: the one folder a ledger road locks every temp-root record under, whatever the process's TMPDIR; since 0.1.2 the rehearsal shows it private and writable


@needs_bwrap
def test_a_lock_is_made_in_the_record_lock_folder_and_the_machine_folder_is_untouched(make_cfg, live, candidate, tmp_path):
    # Since 0.1.2: a test that writes a record under the temp root makes its
    # lock in the one record-lock folder, never under TMPDIR. Inside the
    # rehearsal that folder is private and writable (0.1.1 refused the lock:
    # read-only file system); the machine's folder never sees the lock.
    folder = Path(RECORD_LOCK_FOLDER)
    made_here = not os.path.lexists(folder)
    sentinel = None
    if made_here:
        # A clean machine (the suite's own sandbox) has no such folder: it is
        # made here as the ledger road makes it, with a sentinel the rehearsal
        # must not see; both are removed when the test ends.
        folder.mkdir()
        folder.chmod(0o1777)
        sentinel = folder / ("sentinel_%d" % os.getpid())
        sentinel.write_bytes(b"machine\n")
    name = "landlock_probe_%d_%d.lock" % (os.getpid(), time.monotonic_ns())
    try:
        body = (
            "import os, sys\n"
            "folder, name = sys.argv[1], sys.argv[2]\n"
            "fd = os.open(os.path.join(folder, name), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)\n"
            "os.write(fd, b'held')\n"
            "os.close(fd)\n"
            "seen = sorted(os.listdir(folder))\n"
            "assert seen == [name], seen\n"
            "print('made the lock in a private folder')\n"
        )
        cfg = make_cfg(default=probe(tmp_path, body, str(folder), name))
        v = rehearse(cfg, pin(str(live)), str(candidate))
        assert v.would_land is True, v.output
        assert "made the lock in a private folder" in v.output
        assert not os.path.lexists(folder / name)
        if sentinel is not None:
            assert sentinel.read_bytes() == b"machine\n"
            assert sorted(os.listdir(folder)) == [sentinel.name]
        assert rehearse_mod.RECORD_LOCK_FOLDER == RECORD_LOCK_FOLDER
    finally:
        if made_here:
            if sentinel is not None and sentinel.exists():
                sentinel.unlink()
            # The folder this test made goes only when it is empty; a lock another
            # writer laid there meanwhile keeps it standing, as the shared folder.
            if not os.listdir(folder):
                folder.rmdir()


@needs_bwrap
def test_an_absent_record_lock_folder_stays_absent_and_the_rehearsal_still_runs(
    make_cfg, live, candidate, tmp_path, monkeypatch
):
    # bwrap cannot make a mount point under the read-only machine ("Can't mkdir
    # ...: Read-only file system"), so on a machine with no record-lock folder
    # nothing is mounted there: the rehearsal still starts and runs, the path
    # stays read-only as before 0.1.2, and the machine still has no such folder.
    absent = tmp_path / "no_record_lock_folder"
    monkeypatch.setattr(rehearse_mod, "RECORD_LOCK_FOLDER", str(absent))
    body = (
        "import errno, os, sys\n"
        "folder = sys.argv[1]\n"
        "try:\n"
        "    os.makedirs(folder)\n"
        "except OSError as exc:\n"
        "    assert exc.errno == errno.EROFS, exc\n"
        "    print('the absent folder stays read-only')\n"
        "else:\n"
        "    sys.exit('the absent folder was made inside the rehearsal')\n"
    )
    cfg = make_cfg(default=probe(tmp_path, body, str(absent)))
    v = rehearse(cfg, pin(str(live)), str(candidate))
    assert v.would_land is True, v.output
    assert "the absent folder stays read-only" in v.output
    assert not os.path.lexists(absent)


@needs_bwrap
def test_the_secret_reads_empty_inside_the_sandbox(make_cfg, live, candidate, secret_file):
    assert secret_file.read_bytes()
    cfg = make_cfg(
        default=code(
            "import sys",
            "data = open(bytes.fromhex(sys.argv[1]).decode(), 'rb').read()",
            "print('secret bytes', len(data))",
        )
        + [hex_of(secret_file)]
    )
    v = rehearse(cfg, pin(str(live)), str(candidate))
    assert v.would_land is True, v.output
    assert "secret bytes 0" in v.output


@needs_bwrap
def test_the_receipts_read_empty_inside_the_sandbox(make_cfg, live, candidate, keep_dir):
    receipts = keep_dir / "receipts.jsonl"
    receipts.write_bytes(b'{"row": 1}\n')
    cfg = make_cfg(
        default=code(
            "import sys",
            "data = open(bytes.fromhex(sys.argv[1]).decode(), 'rb').read()",
            "print('receipts bytes', len(data))",
        )
        + [hex_of(receipts)]
    )
    v = rehearse(cfg, pin(str(live)), str(candidate))
    assert v.would_land is True, v.output
    assert "receipts bytes 0" in v.output
    assert receipts.read_bytes() == b'{"row": 1}\n'


@needs_bwrap
def test_a_policy_that_allows_sees_the_rehearse_event(cfg, live, candidate):
    seen = []

    def allow(event: dict) -> tuple[bool, str]:
        seen.append(event)
        return True, ""

    p = pin(str(live))
    v = rehearse(cfg, p, str(candidate), policies=[allow])
    assert v.would_land is True, v.output
    assert len(seen) == 1
    assert seen[0]["act"] == "rehearse"
    assert seen[0]["target"] == str(live)
    assert seen[0]["candidate_sha256"] == sha(NEW)
    assert seen[0]["pin"]["sha256"] == sha(OLD)


@needs_bwrap
def test_extra_dirs_are_shown_read_only_at_their_own_paths(make_cfg, tmp_root, candidate, scratch):
    # The target lives in root/pkg and its tests in root/tests, a sibling folder.
    # Since 0.1.1 an extra dir is shown read-only and never copied (R15).
    pkg = tmp_root / "pkg"
    pkg.mkdir()
    target = pkg / "app.py"
    target.write_bytes(OLD)
    tests_dir = tmp_root / "tests"
    tests_dir.mkdir()
    (tests_dir / "check.py").write_text(
        "import errno, os, sys\n"
        "here = os.path.dirname(os.path.abspath(__file__))\n"
        "sys.path.insert(0, os.path.join(here, '..', 'pkg'))\n"
        "import app\n"
        "assert app.VALUE == 'new', app.VALUE\n"
        "try:\n"
        "    open(os.path.join(here, 'wrote_by_test.txt'), 'w').write('ok')\n"
        "    raise SystemExit('the extra dir took a write')\n"
        "except OSError as e:\n"
        "    assert e.errno == errno.EROFS, e\n"
        "    refused = e.errno\n"
        "print('sibling tests saw', app.VALUE, 'write refused', refused)\n",
        encoding="utf-8",
    )
    cfg = make_cfg(default=["python3", "../tests/check.py"])
    cfg.walls["rehearse_extra_dirs"] = [str(tests_dir)]
    p = pin(str(target))
    v = rehearse(cfg, p, str(candidate))
    assert v.would_land is True, v.output
    assert "sibling tests saw new write refused 30" in v.output
    assert target.read_bytes() == OLD
    assert sorted(x.name for x in tests_dir.iterdir()) == ["check.py"]
    assert list(scratch.iterdir()) == []


# ---------------------------------------------------------------- 0.1.1: show, never copy


@needs_bwrap
def test_a_read_through_the_window_works_and_a_write_is_refused_by_the_kernel(
    make_cfg, live, candidate, tmp_path, monkeypatch
):
    # The window sits under a hidden home, outside every root: without the wall it would not be seen at all.
    home = tmp_path / "home"
    shared = home / "shared"
    shared.mkdir(parents=True)
    (shared / "data.txt").write_bytes(b"shared data\n")
    monkeypatch.setenv("HOME", str(home))
    cfg = make_cfg(
        default=probe(
            tmp_path,
            WRITE_REFUSED
            + "import os, sys\n"
            "shared = sys.argv[1]\n"
            "print('read', open(os.path.join(shared, 'data.txt')).read().strip())\n"
            "print('write existing refused', write_refused(os.path.join(shared, 'data.txt')))\n"
            "print('write new refused', write_refused(os.path.join(shared, 'new.txt')))\n",
            str(shared),
        ),
        walls={"rehearse_ro_dirs": [str(shared)]},
    )
    v = rehearse(cfg, pin(str(live)), str(candidate))
    assert v.would_land is True, v.output
    assert "read shared data" in v.output
    assert "write existing refused True" in v.output
    assert "write new refused True" in v.output
    assert sorted(x.name for x in shared.iterdir()) == ["data.txt"]
    assert (shared / "data.txt").read_bytes() == b"shared data\n"


@needs_bwrap
def test_the_live_file_is_never_the_candidate(make_cfg, live, candidate, tmp_root, tmp_path):
    sub = tmp_root / "sub"
    sub.mkdir()
    (sub / "deep.txt").write_bytes(b"deep\n")

    def snapshot() -> dict:
        return {
            str(path.relative_to(tmp_root)): (path.read_bytes(), path.stat().st_mode)
            for path in sorted(tmp_root.rglob("*"))
            if path.is_file()
        }

    before = snapshot()
    held = live.stat()
    cfg = make_cfg(
        default=probe(
            tmp_path,
            "import sys\n"
            "target = bytes.fromhex(sys.argv[1]).decode()\n"
            "assert open(target, 'rb').read() == %r\n"
            "with open(target, 'wb') as handle:\n"
            "    handle.write(b'scribbled over')\n"
            "assert open(target, 'rb').read() == b'scribbled over'\n"
            "print('scribbled the shown file')\n" % NEW,
            hex_of(live),
        )
    )
    p = pin(str(live))
    v = rehearse(cfg, p, str(candidate))
    assert v.would_land is True, v.output
    assert "scribbled the shown file" in v.output
    # The real folder's bytes, byte for byte, and the live file's identity are unchanged.
    assert snapshot() == before
    assert live.read_bytes() == OLD
    after = live.stat()
    assert (after.st_ino, after.st_size, after.st_mtime_ns) == (held.st_ino, held.st_size, held.st_mtime_ns)
    assert pin(str(live)).sha256 == p.sha256 == sha(OLD)
    assert candidate.read_bytes() == NEW


@needs_bwrap
def test_a_path_under_a_hidden_home_stays_hidden(make_cfg, live, candidate, tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    (home / "private.txt").write_bytes(b"private\n")
    (home / "other").mkdir()
    (home / "other" / "o.txt").write_bytes(b"other\n")
    shown = home / "shown"
    shown.mkdir()
    (shown / "s.txt").write_bytes(b"shown\n")
    monkeypatch.setenv("HOME", str(home))
    cfg = make_cfg(
        default=probe(
            tmp_path,
            "import os, sys\n"
            "home = sys.argv[1]\n"
            "print('home lists', sorted(os.listdir(home)))\n"
            "print('private seen', os.path.exists(os.path.join(home, 'private.txt')))\n"
            "print('other seen', os.path.exists(os.path.join(home, 'other', 'o.txt')))\n"
            "print('shown reads', open(os.path.join(home, 'shown', 's.txt')).read().strip())\n",
            str(home),
        ),
        walls={"rehearse_ro_dirs": [str(shown)]},
    )
    v = rehearse(cfg, pin(str(live)), str(candidate))
    assert v.would_land is True, v.output
    assert "home lists ['shown']" in v.output
    assert "private seen False" in v.output
    assert "other seen False" in v.output
    assert "shown reads shown" in v.output


@needs_bwrap
def test_a_symlinked_ro_dir_resolves_at_the_path_as_written(make_cfg, live, candidate, tmp_path, monkeypatch):
    # A link in the hidden home leads to a folder that is itself hidden; named
    # as written, the link's path shows the folder, and the folder's own path stays hidden.
    home = tmp_path / "home"
    real = home / "data_real"
    real.mkdir(parents=True)
    (real / "seam.py").write_text("SEAM = 'found'\n", encoding="utf-8")
    link = home / "data"
    os.symlink(str(real), str(link))
    monkeypatch.setenv("HOME", str(home))
    cfg = make_cfg(
        default=probe(
            tmp_path,
            "import os, sys\n"
            "link, real, home = sys.argv[1:4]\n"
            "sys.path.insert(0, link)\n"
            "import seam\n"
            "print('seam', seam.SEAM)\n"
            "print('real seen', os.path.exists(real))\n"
            "print('home lists', sorted(os.listdir(home)))\n",
            str(link),
            str(real),
            str(home),
        ),
        walls={"rehearse_ro_dirs": [str(link)]},
    )
    v = rehearse(cfg, pin(str(live)), str(candidate))
    assert v.would_land is True, v.output
    assert "seam found" in v.output
    assert "real seen False" in v.output
    assert "home lists ['data']" in v.output
    assert os.path.islink(link)


@needs_bwrap
def test_an_unreadable_private_file_beside_the_target_is_no_fault(make_cfg, live, candidate, tmp_root):
    private = tmp_root / "private.bin"
    private.write_bytes(b"not for this user\n")
    locked = tmp_root / "locked"
    locked.mkdir()
    (locked / "inner.txt").write_bytes(b"inner\n")
    private.chmod(0)
    locked.chmod(0)
    try:
        cfg = make_cfg(
            default=code(
                "import os",
                "print('names', sorted(os.listdir('.')))",
                "print('shown', open(%r).read().strip())" % live.name,
            )
        )
        v = rehearse(cfg, pin(str(live)), str(candidate))
    finally:
        locked.chmod(0o700)
        private.chmod(0o600)
    assert v.would_land is True, v.output
    assert "names %r" % sorted([live.name, "helper.txt", "locked", "private.bin"]) in v.output
    assert "shown VALUE = 'new'" in v.output
    assert private.read_bytes() == b"not for this user\n"
    assert live.read_bytes() == OLD


@needs_bwrap
def test_the_secret_stays_masked_inside_a_folder_shown_back_into_the_home(
    make_cfg, live, candidate, tmp_path, monkeypatch
):
    home = tmp_path / "home"
    conf = home / "conf"
    conf.mkdir(parents=True)
    secret = conf / "secret"
    fd = os.open(str(secret), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    os.write(fd, b"0123456789abcdef")
    os.close(fd)
    (conf / "settings.txt").write_bytes(b"open setting\n")
    monkeypatch.setenv("HOME", str(home))
    cfg = make_cfg(
        default=probe(
            tmp_path,
            "import os, sys\n"
            "conf = sys.argv[1]\n"
            "secret = bytes.fromhex(sys.argv[2]).decode()\n"
            "print('setting', open(os.path.join(conf, 'settings.txt')).read().strip())\n"
            "print('secret bytes', len(open(secret, 'rb').read()))\n",
            str(conf),
            hex_of(secret),
        ),
        walls={"rehearse_ro_dirs": [str(conf)]},
    )
    cfg.secret = str(secret)
    v = rehearse(cfg, pin(str(live)), str(candidate))
    assert v.would_land is True, v.output
    assert "setting open setting" in v.output
    assert "secret bytes 0" in v.output
    assert secret.read_bytes() == b"0123456789abcdef"


@needs_bwrap
def test_ro_dirs_are_laid_outer_first_and_skip_the_target_folder(
    make_cfg, tmp_root, live, candidate, tmp_path, monkeypatch
):
    pkg = tmp_root / "pkg"
    pkg.mkdir()
    target = pkg / live.name
    target.write_bytes(OLD)
    below = pkg / "below"
    below.mkdir()
    shared = tmp_path / "shared"
    shared.mkdir()
    cfg = make_cfg(
        walls={"rehearse_ro_dirs": [str(shared), str(pkg), str(below), str(shared) + "/", str(tmp_root)]}
    )
    seen = []

    def fake_run(cmd, wall):
        seen.append(list(cmd))
        return 0, ""

    monkeypatch.setattr(rehearse_mod, "_run", fake_run)
    v = rehearse(cfg, pin(str(target)), str(candidate))
    assert v.would_land is True
    cmd = seen[0]
    binds = [tuple(cmd[i:i + 3]) for i in range(len(cmd) - 2) if cmd[i] in ("--ro-bind", "--bind")]
    dests = [b[2] for b in binds]
    assert dests.count(str(shared)) == 1
    assert str(below) not in dests
    assert dests.count(str(pkg)) == 1
    assert ("--ro-bind", str(pkg), str(pkg)) in binds
    assert dests.index(str(tmp_root)) < dests.index(str(pkg)) < dests.index(str(target))
    flag, source, _ = binds[dests.index(str(target))]
    assert flag == "--bind" and source != str(target) and os.path.basename(source) == "candidate"
    # Nothing was copied: the only binds whose source is the rehearsal's scratch are the candidate and TMPDIR.
    scratch_sources = [b[1] for b in binds if b[1].startswith(str(tmp_path / "scratch"))]
    assert len(scratch_sources) == 2


@needs_bwrap
def test_a_window_over_the_targets_root_still_shows_the_candidate_with_its_mode(make_cfg, tmp_root, live, candidate):
    pkg = tmp_root / "pkg"
    pkg.mkdir()
    target = pkg / live.name
    target.write_bytes(OLD)
    target.chmod(0o640)
    cfg = make_cfg(
        default=code(
            "import os, sys",
            "target = bytes.fromhex(sys.argv[1]).decode()",
            "body = open(target, 'rb').read()",
            "assert body == %r, body" % NEW,
            "print('candidate shown with mode', oct(os.stat(target).st_mode & 0o777))",
        )
        + [hex_of(target)],
        walls={"rehearse_ro_dirs": [str(tmp_root)]},
    )
    v = rehearse(cfg, pin(str(target)), str(candidate))
    assert v.would_land is True, v.output
    assert "candidate shown with mode 0o640" in v.output
    assert target.read_bytes() == OLD


MASK_PROBE = (
    "import os, sys\n"
    "folder = bytes.fromhex(sys.argv[1]).decode()\n"
    "name = sys.argv[2]\n"
    "print('folder lists', sorted(os.listdir(folder)))\n"
    "print('private bytes', len(open(os.path.join(folder, name), 'rb').read()))\n"
)


@needs_bwrap
def test_the_secret_stays_masked_through_a_link_spelled_folder(make_cfg, live, candidate, tmp_path, monkeypatch):
    # The folder is listed by a link spelling, the secret configured by its real path.
    home = tmp_path / "home"
    conf = home / "conf"
    conf.mkdir(parents=True)
    secret = conf / "secret"
    secret.write_bytes(b"0123456789abcdef0123456789abcdef")
    secret.chmod(0o600)
    link = home / "conf_link"
    os.symlink(str(conf), str(link))
    monkeypatch.setenv("HOME", str(home))
    cfg = make_cfg(default=probe(tmp_path, MASK_PROBE, hex_of(link), "secret"), walls={"rehearse_ro_dirs": [str(link)]})
    cfg.secret = str(secret)
    v = rehearse(cfg, pin(str(live)), str(candidate))
    assert v.would_land is True, v.output
    assert "folder lists ['secret']" in v.output
    assert "private bytes 0" in v.output
    assert secret.read_bytes() == b"0123456789abcdef0123456789abcdef"


@needs_bwrap
def test_the_secret_outside_the_home_stays_masked_through_a_listed_link(make_cfg, live, candidate, tmp_path, monkeypatch):
    keys = tmp_path / "keys"
    keys.mkdir()
    secret = keys / "secret"
    secret.write_bytes(b"0123456789abcdef0123456789abcdef")
    secret.chmod(0o600)
    home = tmp_path / "home"
    home.mkdir()
    link = home / "keys_link"
    os.symlink(str(keys), str(link))
    monkeypatch.setenv("HOME", str(home))
    cfg = make_cfg(default=probe(tmp_path, MASK_PROBE, hex_of(link), "secret"), walls={"rehearse_ro_dirs": [str(link)]})
    cfg.secret = str(secret)
    v = rehearse(cfg, pin(str(live)), str(candidate))
    assert v.would_land is True, v.output
    assert "private bytes 0" in v.output


@needs_bwrap
def test_the_receipts_stay_masked_through_a_link_spelled_folder(make_cfg, live, candidate, tmp_path, monkeypatch):
    home = tmp_path / "home"
    keep = home / "keep"
    keep.mkdir(parents=True)
    receipts = keep / "receipts.jsonl"
    receipts.write_bytes(b'{"row": 1, "act": "land"}\n')
    link = home / "keep_link"
    os.symlink(str(keep), str(link))
    monkeypatch.setenv("HOME", str(home))
    cfg = make_cfg(
        default=probe(tmp_path, MASK_PROBE, hex_of(link), "receipts.jsonl"), walls={"rehearse_ro_dirs": [str(link)]}
    )
    cfg.receipts = str(receipts)
    v = rehearse(cfg, pin(str(live)), str(candidate))
    assert v.would_land is True, v.output
    assert "folder lists ['receipts.jsonl']" in v.output
    assert "private bytes 0" in v.output
    assert receipts.read_bytes() == b'{"row": 1, "act": "land"}\n'


@needs_bwrap
def test_the_candidate_shows_through_a_listed_link_into_the_target_folder(
    make_cfg, tmp_root, live, candidate, tmp_path, monkeypatch
):
    # A link in the hidden home leads into the root; every road through it reads the candidate.
    pkg = tmp_root / "pkg"
    pkg.mkdir()
    target = pkg / live.name
    target.write_bytes(OLD)
    home = tmp_path / "home"
    home.mkdir()
    link = home / "data"
    os.symlink(str(tmp_root), str(link))
    monkeypatch.setenv("HOME", str(home))
    module = os.path.splitext(live.name)[0]
    cfg = make_cfg(
        default=probe(
            tmp_path,
            "import os, subprocess, sys\n"
            "link_pkg = bytes.fromhex(sys.argv[1]).decode()\n"
            "name, module = sys.argv[2:4]\n"
            "print('link read', open(os.path.join(link_pkg, name), 'rb').read())\n"
            "ran = subprocess.run([sys.executable, '-c', 'exec(open(%r).read()); print(VALUE)' % os.path.join(link_pkg, name)],\n"
            "                     capture_output=True, text=True)\n"
            "print('link run', ran.stdout.strip())\n"
            "os.chdir(link_pkg)\n"
            "sys.path.insert(0, os.getcwd())\n"
            "imported = __import__(module)\n"
            "print('link import', imported.VALUE)\n",
            hex_of(link / "pkg"),
            live.name,
            module,
        ),
        walls={"rehearse_ro_dirs": [str(link)]},
    )
    v = rehearse(cfg, pin(str(target)), str(candidate))
    assert v.would_land is True, v.output
    assert "link read %r" % NEW in v.output
    assert "link run new" in v.output
    assert "link import new" in v.output
    assert target.read_bytes() == OLD


@needs_bwrap
def test_a_link_inside_the_target_folder_listed_by_its_link_spelling_is_shown(
    make_cfg, live, candidate, tmp_root, tmp_path, monkeypatch
):
    home = tmp_path / "home"
    ext_real = home / "ext_real"
    ext_real.mkdir(parents=True)
    (ext_real / "e.txt").write_bytes(b"ext\n")
    monkeypatch.setenv("HOME", str(home))
    ext = tmp_root / "ext"
    os.symlink(str(ext_real), str(ext))
    cfg = make_cfg(
        default=code("print('read through ext', open('ext/e.txt').read().strip())"),
        walls={"rehearse_ro_dirs": [str(ext)]},
    )
    v = rehearse(cfg, pin(str(live)), str(candidate))
    assert v.would_land is True, v.output
    assert "read through ext ext" in v.output


@needs_bwrap
def test_a_visible_link_outside_the_home_stays_a_link_and_leads_to_its_folder(
    make_cfg, live, candidate, tmp_path, monkeypatch
):
    home = tmp_path / "home"
    inner = home / "inner"
    inner.mkdir(parents=True)
    (inner / "i.txt").write_bytes(b"inner\n")
    (home / "private.txt").write_bytes(b"private\n")
    monkeypatch.setenv("HOME", str(home))
    outside = tmp_path / "outside_link"
    os.symlink(str(inner), str(outside))
    cfg = make_cfg(
        default=probe(
            tmp_path,
            "import os, sys\n"
            "link, home = sys.argv[1:3]\n"
            "print('still a link', os.path.islink(link))\n"
            "print('reads', open(os.path.join(link, 'i.txt')).read().strip())\n"
            "print('home lists', sorted(os.listdir(home)))\n",
            str(outside),
            str(home),
        ),
        walls={"rehearse_ro_dirs": [str(outside)]},
    )
    v = rehearse(cfg, pin(str(live)), str(candidate))
    assert v.would_land is True, v.output
    assert "still a link True" in v.output
    assert "reads inner" in v.output
    assert "home lists ['inner']" in v.output


@needs_bwrap
def test_the_verdict_carries_the_output_whole(make_cfg, live, candidate):
    cfg = make_cfg(default=code("import sys", "sys.stdout.write('x' * 300000)", "sys.stderr.write('tail-of-stderr')"))
    v = rehearse(cfg, pin(str(live)), str(candidate))
    assert v.would_land is True
    assert v.output.count("x") >= 300000
    assert "tail-of-stderr" in v.output


def test_the_verdict_record_round_trips():
    v = Verdict(False, "out\n", "the tests exited 1")
    assert Verdict.from_json(v.to_json()) == v
    assert Verdict.from_json(v.to_dict()) == v

"""Checks that a rehearsal tests the new bytes in a throwaway copy inside bubblewrap and never touches the live file.

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
            "open('made_by_test.txt', 'w').write('ok')",
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
def test_extra_dirs_are_copied_and_shown_at_their_own_paths(make_cfg, tmp_root, candidate, scratch):
    # The target lives in root/pkg and its tests in root/tests, a sibling folder.
    pkg = tmp_root / "pkg"
    pkg.mkdir()
    target = pkg / "app.py"
    target.write_bytes(OLD)
    tests_dir = tmp_root / "tests"
    tests_dir.mkdir()
    (tests_dir / "check.py").write_text(
        "import os, sys\n"
        "here = os.path.dirname(os.path.abspath(__file__))\n"
        "sys.path.insert(0, os.path.join(here, '..', 'pkg'))\n"
        "import app\n"
        "assert app.VALUE == 'new', app.VALUE\n"
        "open(os.path.join(here, 'wrote_by_test.txt'), 'w').write('ok')\n"
        "print('sibling tests saw', app.VALUE)\n",
        encoding="utf-8",
    )
    cfg = make_cfg(default=["python3", "../tests/check.py"])
    cfg.walls["rehearse_extra_dirs"] = [str(tests_dir)]
    p = pin(str(target))
    v = rehearse(cfg, p, str(candidate))
    assert v.would_land is True, v.output
    assert "sibling tests saw new" in v.output
    assert target.read_bytes() == OLD
    assert sorted(x.name for x in tests_dir.iterdir()) == ["check.py"]
    assert list(scratch.iterdir()) == []


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

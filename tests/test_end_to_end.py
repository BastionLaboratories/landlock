"""Walks the whole road from pinning a file to landing and rolling it back, through the library and the command line.

Must-fail cases come first:
- the road refuses at land when the approval was issued for other bytes;
- the road rolls back when a dependent's test fails, and the receipts chain
  still verifies;
- a planted journal whose live file matches nothing it expects is not cleared.
Then the positive road: pin, rehearse, approve, land with one dependent,
receipts verify, rollback, and recovery from planted journals; once through the
public names and once more through cli.main, with the live bytes checked at
every step.

Every file these tests touch lives under pytest's tmp_path.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
from pathlib import Path

import pytest

from conftest import FAILING_ARGV, PASSING_ARGV

OLD = b"VALUE = 1\n"
NEW = b"VALUE = 2\n"
OTHER = b"VALUE = 3\n"
DEP = b"def check():\n    return True\n"

needs_bwrap = pytest.mark.skipif(
    shutil.which("bwrap") is None,
    reason="bubblewrap is required for rehearse and is not on PATH",
)


# ---------------------------------------------------------------- helpers


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def field(obj, key):
    """Read a record field whether the record is a plain dict or a class."""
    if isinstance(obj, dict):
        return obj[key]
    return getattr(obj, key)


def why_of(exc) -> str:
    """The refusal sentence of a Refused or Fault."""
    return getattr(exc, "why", None) or str(exc)


def write_bytes(path: Path, data: bytes) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return path


@pytest.fixture
def stage(tmp_path) -> Path:
    """A folder outside every root where candidates wait."""
    folder = (tmp_path / "stage").resolve()
    folder.mkdir(parents=True, exist_ok=True)
    return folder


@pytest.fixture
def target(tmp_root) -> Path:
    return write_bytes(tmp_root / "app.py", OLD)


@pytest.fixture
def dependent(tmp_root) -> Path:
    return write_bytes(tmp_root / "uses_app.py", DEP)


def land_rows(cfg, path: Path):
    from landlock.receipts import rows

    return [r for r in rows(cfg, str(path)) if field(r, "act") == "land"]


def elders_of(path: Path):
    return sorted(path.parent.glob(path.name + ".pre_land_*"))


def run_cli(capsys, argv):
    """Run cli.main and return (exit code, first verdict line, whole stdout)."""
    from landlock.cli import main

    code = main([str(a) for a in argv])
    captured = capsys.readouterr()
    text = captured.out if captured.out.strip() else captured.err
    lines = [line for line in text.splitlines() if line.strip()]
    first = lines[0] if lines else ""
    return code, first, captured.out


@pytest.fixture
def cli_env(monkeypatch, tmp_path, keep_dir):
    """Point the command line at a config file in the keep dir through the environment."""

    def _use(config_name: str):
        monkeypatch.setenv("LANDLOCK_CONFIG", str(keep_dir / config_name))

    monkeypatch.chdir(tmp_path)
    return _use


# ------------------------------------------------- must-fail cases first


def test_land_refuses_an_approval_issued_for_other_bytes(cfg, secret_file, target, stage):
    from landlock.approve import approve
    from landlock.errors import Refused
    from landlock.land import land
    from landlock.pin import pin

    approved = write_bytes(stage / "approved.py", NEW)
    swapped = write_bytes(stage / "swapped.py", OTHER)

    p = pin(str(target))
    a = approve(cfg, p, sha(approved.read_bytes()))
    assert target.read_bytes() == OLD

    # Refused before any write: land raises, after appending its REFUSED row (R9),
    # and that row carries sha_before only (R8).
    with pytest.raises(Refused) as caught:
        land(cfg, p, str(swapped), a)
    assert why_of(caught.value).startswith("REFUSED: ")
    landed = land_rows(cfg, target)
    assert len(landed) == 1
    assert field(landed[0], "verdict") == "REFUSED"
    assert field(landed[0], "why").startswith("REFUSED: ")
    assert field(landed[0], "sha_before") == sha(OLD)
    assert field(landed[0], "sha_after") == ""

    # The live bytes never moved and no elder was laid for the refused landing.
    assert target.read_bytes() == OLD
    assert elders_of(target) == []
    assert not list(target.parent.glob(".landlock_tmp_*"))
    assert not list(target.parent.glob(".landlock_journal_*"))


def test_cli_land_refuses_an_approval_issued_for_other_bytes(
    make_cfg, secret_file, target, stage, capsys, cli_env
):
    make_cfg(name="cli_other.toml")
    cli_env("cli_other.toml")
    approved = write_bytes(stage / "approved.py", NEW)
    swapped = write_bytes(stage / "swapped.py", OTHER)

    code, line, _ = run_cli(capsys, ["approve", target, approved])
    assert code == 0 and line.startswith("APPROVED ")
    approval_file = Path(str(approved) + ".approval.json")
    assert approval_file.is_file()

    code, line, _ = run_cli(capsys, ["land", target, swapped, "--approval", approval_file])
    assert code == 2
    assert line.startswith("REFUSED: ")
    assert target.read_bytes() == OLD


def test_failing_dependent_rolls_back_and_the_chain_verifies(
    make_cfg, secret_file, target, dependent, stage
):
    from landlock.approve import approve
    from landlock.land import land
    from landlock.pin import pin
    from landlock.receipts import verify_chain

    cfg = make_cfg(
        by_path={str(dependent): FAILING_ARGV},
        dependents={str(target): [str(dependent)]},
    )
    candidate = write_bytes(stage / "app.py", NEW)

    p = pin(str(target))
    a = approve(cfg, p, sha(NEW))

    # Refused after the first write: land returns its REFUSED row (R9), never raises.
    returned = land(cfg, p, str(candidate), a)
    assert field(returned, "act") == "land"
    assert field(returned, "verdict") == "REFUSED"
    assert str(dependent) in field(returned, "why")

    # The live bytes equal the elder again.
    assert target.read_bytes() == OLD
    elders = elders_of(target)
    assert len(elders) == 1 and elders[0].read_bytes() == OLD

    # One land row, verdict REFUSED, naming the dependent, sha_after measured as the old bytes.
    landed = land_rows(cfg, target)
    assert len(landed) == 1
    row = landed[0]
    assert field(row, "verdict") == "REFUSED"
    assert str(dependent) in field(row, "why")
    assert field(row, "sha_before") == sha(OLD)
    assert field(row, "sha_after") == sha(OLD)
    assert row == returned

    # No temp or journal left behind; the receipts chain verifies.
    assert not list(target.parent.glob(".landlock_tmp_*"))
    assert not list(target.parent.glob(".landlock_journal_*"))
    assert verify_chain(cfg, str(target)) >= 1


def test_recover_keeps_a_journal_whose_live_file_matches_nothing(cfg, target, stage):
    from landlock.land import recover
    from landlock.receipts import rows

    # A landing killed after the temp write, but the live file was then changed by hand:
    # recovery cannot verify the live bytes against sha_before, so the journal must stay.
    elder = write_bytes(target.parent / (target.name + ".pre_land_planted"), OLD)
    write_bytes(target.parent / (".landlock_tmp_%s_%d" % (target.name, os.getpid())), NEW)
    target.write_bytes(OTHER)
    journal = plant_journal(target, elder, step="temp-written")

    # A recovery that cannot settle returns its FAULT row; it does not raise.
    returned = recover(cfg, str(journal))
    assert field(returned, "act") == "recover"
    assert field(returned, "verdict") == "FAULT"
    assert field(returned, "why").startswith("FAULT: ")

    assert journal.exists(), "a journal is removed only after the live bytes verify"
    assert target.read_bytes() != NEW, "the candidate never reaches the live path"
    recovered = [r for r in rows(cfg, str(target)) if field(r, "act") == "recover"]
    assert recovered and recovered[-1] == returned


def test_recover_refuses_a_journal_whose_old_bytes_no_row_names(cfg, target):
    from landlock.errors import Refused
    from landlock.land import recover
    from landlock.receipts import rows

    # No receipt names the old bytes, so the journal has no authority to move the
    # live file to them (R3): recover refuses before any write and changes nothing.
    elder = write_bytes(target.parent / (target.name + ".pre_land_planted"), OLD)
    target.write_bytes(NEW)
    journal = plant_journal(target, elder, step="replaced")

    with pytest.raises(Refused) as caught:
        recover(cfg, str(journal))
    assert why_of(caught.value).startswith("REFUSED: ")

    assert target.read_bytes() == NEW
    assert elder.read_bytes() == OLD
    assert journal.exists()
    recovered = [r for r in rows(cfg, str(target)) if field(r, "act") == "recover"]
    assert len(recovered) == 1 and field(recovered[0], "verdict") == "REFUSED"


# ----------------------------------------------------- the positive road


def test_conftest_quotes_awkward_text_for_toml():
    import tomllib

    from conftest import _toml_str

    awkward = 'a\\b "c"\nd\re\tf\x01g\x7fh'
    assert tomllib.loads("k = " + _toml_str(awkward))["k"] == awkward


def plant_journal(target: Path, elder: Path, step: str) -> Path:
    from datetime import datetime, timezone

    started_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    # The journal shape per R3 carries the approval id and the candidate digest;
    # the id is built the way the contract builds an approval id.
    approval_id = sha((str(target) + sha(NEW) + started_at).encode("utf-8"))[:16]
    body = {
        "target": str(target),
        "elder": str(elder),
        "candidate_sha256": sha(NEW),
        "sha_before": sha(OLD),
        "step": step,
        "started_at": started_at,
        "approval_id": approval_id,
    }
    path = target.parent / (".landlock_journal_%s.json" % target.name)
    path.write_text(json.dumps(body), encoding="utf-8")
    return path


def name_old_bytes(cfg, target: Path) -> str:
    """Pin the live file through the library and append its DONE pin row, as a real landing does first."""
    from landlock.pin import pin
    from landlock.receipts import Row, append

    p = pin(str(target))
    assert field(p, "sha256") == sha(target.read_bytes())
    append(
        cfg,
        Row(
            act="pin",
            path=str(target),
            sha_before=field(p, "sha256"),
            sha_after=field(p, "sha256"),
            verdict="DONE",
        ),
    )
    return field(p, "sha256")


@needs_bwrap
def test_positive_road_through_the_public_names(
    make_cfg, secret_file, target, dependent, stage
):
    import landlock
    from landlock.approve import approve, verify
    from landlock.land import land, rollback
    from landlock.pin import check, pin
    from landlock.receipts import rows, verify_chain
    from landlock.rehearse import rehearse

    assert landlock.__version__ == "0.1.1"
    cfg = make_cfg(
        by_path={str(dependent): PASSING_ARGV},
        dependents={str(target): [str(dependent)]},
    )
    candidate = write_bytes(stage / "app.py", NEW)

    # PIN
    p = pin(str(target))
    assert field(p, "path") == str(target)
    assert field(p, "sha256") == sha(OLD)
    assert field(p, "size") == len(OLD)
    assert field(check(p), "sha256") == sha(OLD)
    assert target.read_bytes() == OLD

    # REHEARSE (inside bubblewrap; the live file untouched)
    v = rehearse(cfg, p, str(candidate))
    assert field(v, "would_land") is True
    assert target.read_bytes() == OLD

    # APPROVE
    a = approve(cfg, p, sha(NEW))
    assert field(a, "target") == str(target)
    assert field(a, "candidate_sha256") == sha(NEW)
    assert field(a, "pin_sha256") == sha(OLD)
    assert field(verify(cfg, a, p, sha(NEW)), "id") == field(a, "id")
    assert target.read_bytes() == OLD

    # LAND with one passing dependent
    row = land(cfg, p, str(candidate), a)
    assert field(row, "verdict") == "DONE"
    assert field(row, "act") == "land"
    assert field(row, "sha_before") == sha(OLD)
    assert field(row, "sha_after") == sha(NEW)
    assert field(row, "approval_id") == field(a, "id")
    assert target.read_bytes() == NEW
    elder = Path(field(row, "elder"))
    assert elder.parent == target.parent
    assert elder.name.startswith(target.name + ".pre_land_")
    assert elder.read_bytes() == OLD
    assert not list(target.parent.glob(".landlock_tmp_*"))
    assert not list(target.parent.glob(".landlock_journal_*"))

    # VERIFY the receipts chain
    assert verify_chain(cfg, str(target)) >= 1
    assert target.read_bytes() == NEW

    # ROLLBACK to the elder
    back = rollback(cfg, str(target))
    assert field(back, "verdict") == "DONE"
    assert field(back, "act") == "rollback"
    assert field(back, "sha_after") == sha(OLD)
    assert target.read_bytes() == OLD
    assert verify_chain(cfg, str(target)) >= 2

    acts = [field(r, "act") for r in rows(cfg, str(target))]
    assert acts.index("land") < acts.index("rollback")


def test_recover_a_journal_planted_after_the_replace_restores_the_elder(cfg, target):
    from landlock.land import recover
    from landlock.receipts import verify_chain

    # The old bytes stand named in the receipts before the landing began (R3).
    assert name_old_bytes(cfg, target) == sha(OLD)

    # A landing killed after the rename and before the dependents' tests finished.
    elder = write_bytes(target.parent / (target.name + ".pre_land_planted"), OLD)
    target.write_bytes(NEW)
    journal = plant_journal(target, elder, step="replaced")

    row = recover(cfg, str(journal))
    assert field(row, "verdict") == "DONE"
    assert field(row, "act") == "recover"
    assert field(row, "sha_after") == sha(OLD)
    assert target.read_bytes() == OLD
    assert not journal.exists()
    assert verify_chain(cfg, str(target)) >= 1


def test_recover_a_journal_planted_after_the_temp_write_keeps_the_live_file(cfg, target):
    from landlock.land import recover

    # A landing killed between the temp write and the rename.
    assert name_old_bytes(cfg, target) == sha(OLD)
    elder = write_bytes(target.parent / (target.name + ".pre_land_planted"), OLD)
    write_bytes(target.parent / (".landlock_tmp_%s_%d" % (target.name, os.getpid())), NEW)
    journal = plant_journal(target, elder, step="temp-written")

    row = recover(cfg, str(journal))
    assert field(row, "verdict") == "DONE"
    assert target.read_bytes() == OLD
    assert not list(target.parent.glob(".landlock_tmp_%s_*" % target.name))
    assert not journal.exists()


@needs_bwrap
def test_positive_road_through_the_command_line(
    make_cfg, secret_file, target, dependent, stage, capsys, cli_env
):
    make_cfg(
        by_path={str(dependent): PASSING_ARGV},
        dependents={str(target): [str(dependent)]},
        name="cli.toml",
    )
    cli_env("cli.toml")
    candidate = write_bytes(stage / "app.py", NEW)
    seen = []

    code, line, _ = run_cli(capsys, ["pin", target])
    assert code == 0
    assert line == "PINNED %s %s" % (target, sha(OLD))
    assert target.read_bytes() == OLD
    seen.append(line.split()[0])

    code, line, out = run_cli(capsys, ["rehearse", target, candidate])
    assert code == 0, out
    assert line == "WOULD LAND"
    assert target.read_bytes() == OLD
    seen.append(line)

    code, line, _ = run_cli(capsys, ["approve", target, candidate])
    assert code == 0
    assert line.startswith("APPROVED ")
    approval_file = Path(str(candidate) + ".approval.json")
    approval = json.loads(approval_file.read_text(encoding="utf-8"))
    assert line == "APPROVED %s" % approval["id"]
    assert approval["candidate_sha256"] == sha(NEW)
    assert target.read_bytes() == OLD
    seen.append(line.split()[0])

    code, line, out = run_cli(capsys, ["land", target, candidate, "--approval", approval_file])
    assert code == 0, out
    assert line == "LANDED %s %s" % (target, sha(NEW))
    assert target.read_bytes() == NEW
    seen.append(line.split()[0])

    code, line, _ = run_cli(capsys, ["verify", target])
    assert code == 0
    assert line.startswith("VERIFIED ") and line.endswith(" rows")
    assert int(line.split()[1]) >= 1
    assert target.read_bytes() == NEW
    seen.append(line.split()[0])

    code, line, _ = run_cli(capsys, ["rollback", target])
    assert code == 0
    assert line == "ROLLED BACK %s %s" % (target, sha(OLD))
    assert target.read_bytes() == OLD
    seen.append(" ".join(line.split()[:2]))

    assert seen == ["PINNED", "WOULD LAND", "APPROVED", "LANDED", "VERIFIED", "ROLLED BACK"]

    code, line, _ = run_cli(capsys, ["receipts", target])
    assert code == 0

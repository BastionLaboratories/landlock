"""Tests that the landing swaps a file safely, undoes itself when dependents fail, and recovers from a kill at any step.

Must-fail cases come first (each refusal asserted by its exact "REFUSED: "
prefix), then the positive road: a green landing, then its rollback.
A "kill" is simulated by raising an exception the landing does not catch
(a BaseException), so no undo runs and the disk is left as a killed process
would leave it (only the lock is let go, as a person would after a kill).
Where each shape stands: refusals before any write raise Refused; outcomes
after the first write come back as the returned row.
"""

from __future__ import annotations

import datetime
import hashlib
import importlib
import json
import os
import subprocess
import sys
import time

import pytest

from landlock.errors import Refused

# The modules are fetched by their full dotted names (the package never
# re-exports the functions that share a module's name).
approve_mod = importlib.import_module("landlock.approve")
land_mod = importlib.import_module("landlock.land")
pin_mod = importlib.import_module("landlock.pin")
receipts_mod = importlib.import_module("landlock.receipts")

PASS_ARGV = [sys.executable, "-c", "import sys; sys.exit(0)"]
FAIL_ARGV = [sys.executable, "-c", "import sys; sys.exit(1)"]

OLD = b"print('the old body')\n"
NEW = b"print('the new body')\n"
EVIL = b"print('bytes nobody approved')\n"
ROGUE = b"ROGUE = 1\n"


class _Kill(BaseException):
    """Stands for a kill: the landing catches Exception only, so nothing is undone."""


def _started() -> str:
    """A start clock read at run time, as a journal carries it."""
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _f(obj, name):
    """Read one field of a record whether it is a class or a plain dict."""
    if isinstance(obj, dict):
        return obj[name]
    return getattr(obj, name)


def _setup(tmp_root, keep_dir, data=OLD, cand=NEW, name="body.py"):
    """A live file inside the root and a candidate outside it."""
    target = tmp_root / name
    target.write_bytes(data)
    candidate = keep_dir / (name + ".candidate")
    candidate.write_bytes(cand)
    return str(target), str(candidate)


def _approved(cfg, target, candidate):
    p = pin_mod.pin(target)
    with open(candidate, "rb") as fh:
        cand_sha = _sha(fh.read())
    a = approve_mod.approve(cfg, p, cand_sha)
    return p, a


def _with_dependent(make_cfg, tmp_root, target, argv, walls=None):
    dep = str(tmp_root / "uses_body.py")
    with open(dep, "w", encoding="utf-8") as fh:
        fh.write("import body\n")
    cfg = make_cfg(by_path={dep: argv}, dependents={target: [dep]}, walls=walls)
    return cfg, dep


def _strays(folder, base):
    """Every elder, temp, journal and lock the landing may leave beside the target."""
    names = sorted(os.listdir(folder))
    elders = [n for n in names if n.startswith(base + ".pre_land_")]
    temps = [n for n in names if n.startswith(".landlock_tmp_" + base + "_")]
    journals = [n for n in names if n == ".landlock_journal_" + base + ".json"]
    locks = [n for n in names if n == ".landlock_lock_" + base]
    return elders, temps, journals + locks


def _pin_row(cfg, path, sha):
    """A pin row as the command line writes one, naming bytes the target held."""
    ts = _started()
    receipts_mod.append(cfg, receipts_mod.Row(
        ts=ts, request_id=receipts_mod.request_id(str(path), ts), act="pin", path=str(path),
        sha_before=sha, sha_after=sha, verdict="DONE",
    ))


def _plant_journal(target, elder, step, sha_before, candidate_sha):
    journal = target.parent / (".landlock_journal_" + target.name + ".json")
    journal.write_text(json.dumps({
        "target": str(target), "elder": str(elder), "candidate_sha256": candidate_sha,
        "sha_before": sha_before, "step": step, "started_at": _started(), "approval_id": "",
    }), encoding="utf-8")
    return journal


def _last(cfg, path):
    return receipts_mod.rows(cfg, str(path))[-1]


# ---------------------------------------------------------------- must fail: before any write (raises)


def test_bad_approval_refuses_before_any_write(cfg, secret_file, tmp_root, keep_dir):
    target, candidate = _setup(tmp_root, keep_dir)
    p, a = _approved(cfg, target, candidate)
    d = json.loads(a.to_json())
    d["mac"] = "0" * 64
    forged = approve_mod.Approval.from_json(json.dumps(d))
    with pytest.raises(Refused) as info:
        land_mod.land(cfg, p, candidate, forged)
    assert info.value.why.startswith("REFUSED: ")
    assert _strays(str(tmp_root), "body.py") == ([], [], [])
    with open(target, "rb") as fh:
        assert fh.read() == OLD
    row = _last(cfg, target)
    assert _f(row, "verdict") == "REFUSED" and _f(row, "act") == "land"
    assert _f(row, "why").startswith("REFUSED: ")
    # A row refused before any write carries sha_before only.
    assert _f(row, "sha_before") == _sha(OLD) and _f(row, "sha_after") == ""


def test_approval_for_other_bytes_refuses(cfg, secret_file, tmp_root, keep_dir):
    target, candidate = _setup(tmp_root, keep_dir)
    p, a = _approved(cfg, target, candidate)
    with open(candidate, "wb") as fh:
        fh.write(EVIL)
    with pytest.raises(Refused) as info:
        land_mod.land(cfg, p, candidate, a)
    assert info.value.why.startswith("REFUSED: ")
    assert _strays(str(tmp_root), "body.py") == ([], [], [])
    with open(target, "rb") as fh:
        assert fh.read() == OLD


def test_moved_pin_refuses_before_any_write(cfg, secret_file, tmp_root, keep_dir):
    target, candidate = _setup(tmp_root, keep_dir)
    p, a = _approved(cfg, target, candidate)
    with open(target, "wb") as fh:
        fh.write(b"print('someone else edited this')\n")
    with pytest.raises(Refused) as info:
        land_mod.land(cfg, p, candidate, a)
    assert info.value.why.startswith("REFUSED: ")
    assert _strays(str(tmp_root), "body.py") == ([], [], [])
    row = _last(cfg, target)
    assert _f(row, "verdict") == "REFUSED" and _f(row, "sha_after") == ""


def test_policy_refusal_stops_before_any_write(cfg, secret_file, tmp_root, keep_dir):
    target, candidate = _setup(tmp_root, keep_dir)
    p, a = _approved(cfg, target, candidate)
    seen = []

    def hold_all(event):
        seen.append(event)
        return False, "REFUSED: the test policy holds every landing"

    with pytest.raises(Refused) as info:
        land_mod.land(cfg, p, candidate, a, policies=[hold_all])
    assert info.value.why.startswith("REFUSED: ")
    assert "the test policy holds every landing" in info.value.why
    assert seen and seen[0]["act"] == "land" and seen[0]["target"] == target
    assert seen[0]["candidate_sha256"] == _sha(NEW)
    assert _strays(str(tmp_root), "body.py") == ([], [], [])
    row = _last(cfg, target)
    assert _f(row, "verdict") == "REFUSED"
    assert "the test policy holds every landing" in _f(row, "why")


def test_standing_journal_refuses_a_new_landing(cfg, secret_file, tmp_root, keep_dir):
    target, candidate = _setup(tmp_root, keep_dir)
    p, a = _approved(cfg, target, candidate)
    journal = tmp_root / ".landlock_journal_body.py.json"
    journal.write_text("{}", encoding="utf-8")
    with pytest.raises(Refused) as info:
        land_mod.land(cfg, p, candidate, a)
    assert info.value.why.startswith("REFUSED: ")
    assert "journal" in info.value.why
    with open(target, "rb") as fh:
        assert fh.read() == OLD


def test_load_over_the_wall_refuses_naming_both_numbers(cfg, secret_file, tmp_root, keep_dir, monkeypatch):
    target, candidate = _setup(tmp_root, keep_dir)
    p, a = _approved(cfg, target, candidate)
    monkeypatch.setattr(land_mod, "_load_average", lambda: 999999.0)
    with pytest.raises(Refused) as info:
        land_mod.land(cfg, p, candidate, a)
    assert info.value.why.startswith("REFUSED: ")
    assert "999999" in info.value.why and "100000" in info.value.why
    assert _strays(str(tmp_root), "body.py") == ([], [], [])


def test_second_landing_on_the_same_approval_refuses(cfg, secret_file, tmp_root, keep_dir):
    target, candidate = _setup(tmp_root, keep_dir)
    p, a = _approved(cfg, target, candidate)
    assert _f(land_mod.land(cfg, p, candidate, a), "verdict") == "DONE"
    assert _f(land_mod.rollback(cfg, target), "verdict") == "DONE"
    again = pin_mod.pin(target)  # the old bytes again, so the approval itself still verifies
    with pytest.raises(Refused) as info:
        land_mod.land(cfg, again, candidate, a)
    assert info.value.why.startswith("REFUSED: ")
    assert _f(a, "id") in info.value.why
    with open(target, "rb") as fh:
        assert fh.read() == OLD


def test_standing_lock_refuses_and_a_stale_one_still_refuses(cfg, secret_file, tmp_root, keep_dir):
    target, candidate = _setup(tmp_root, keep_dir)
    p, a = _approved(cfg, target, candidate)
    lock = tmp_root / ".landlock_lock_body.py"
    lock.write_text("4242\n", encoding="utf-8")
    with pytest.raises(Refused) as info:
        land_mod.land(cfg, p, candidate, a)
    assert info.value.why.startswith("REFUSED: ") and "lock" in info.value.why
    old = time.time() - 100000
    os.utime(lock, (old, old))
    with pytest.raises(Refused) as info:
        land_mod.land(cfg, p, candidate, a)
    assert info.value.why.startswith("REFUSED: ") and "stale" in info.value.why
    assert lock.exists()  # only a person removes it
    with open(target, "rb") as fh:
        assert fh.read() == OLD


def test_dependent_without_a_test_command_refuses_before_the_swap(make_cfg, secret_file, tmp_root, keep_dir, monkeypatch):
    target, candidate = _setup(tmp_root, keep_dir)
    cfg, dep = _with_dependent(make_cfg, tmp_root, target, PASS_ARGV)
    p, a = _approved(cfg, target, candidate)
    monkeypatch.setattr(land_mod, "tests_for", lambda cfg, path: [])
    with pytest.raises(Refused) as info:
        land_mod.land(cfg, p, candidate, a)
    assert info.value.why.startswith("REFUSED: ") and dep in info.value.why
    assert _strays(str(tmp_root), "body.py") == ([], [], [])


def test_a_candidate_equal_to_the_live_bytes_refuses(cfg, secret_file, tmp_root, keep_dir):
    target, candidate = _setup(tmp_root, keep_dir, cand=OLD)
    p, a = _approved(cfg, target, candidate)
    with pytest.raises(Refused) as info:
        land_mod.land(cfg, p, candidate, a)
    assert info.value.why.startswith("REFUSED: ")
    assert _strays(str(tmp_root), "body.py") == ([], [], [])


# ---------------------------------------------------------------- must fail: after the swap (returned rows)


def test_red_dependent_rolls_back(make_cfg, secret_file, tmp_root, keep_dir):
    target, candidate = _setup(tmp_root, keep_dir)
    cfg, dep = _with_dependent(make_cfg, tmp_root, target, FAIL_ARGV)
    p, a = _approved(cfg, target, candidate)
    row = land_mod.land(cfg, p, candidate, a)
    assert _f(row, "verdict") == "REFUSED"
    assert _f(row, "why").startswith("REFUSED: ")
    assert dep in _f(row, "why")
    elder = _f(row, "elder")
    assert elder and os.path.exists(elder)
    with open(target, "rb") as fh:
        live = fh.read()
    with open(elder, "rb") as fh:
        assert fh.read() == live == OLD
    assert _f(row, "sha_before") == _sha(OLD)
    assert _f(row, "sha_after") == _sha(OLD)
    elders, temps, rest = _strays(str(tmp_root), "body.py")
    assert len(elders) == 1 and temps == [] and rest == []


def test_dependent_that_rewrites_the_target_faults_and_restores(make_cfg, secret_file, tmp_root, keep_dir):
    target, candidate = _setup(tmp_root, keep_dir)
    rewrite = [sys.executable, "-c", "open(%r, 'wb').write(%r)" % (target, ROGUE)]
    cfg, dep = _with_dependent(make_cfg, tmp_root, target, rewrite)
    p, a = _approved(cfg, target, candidate)
    row = land_mod.land(cfg, p, candidate, a)
    assert _f(row, "verdict") == "FAULT"
    assert _f(row, "why").startswith("FAULT: ")
    assert _sha(ROGUE) in _f(row, "why") and _sha(NEW) in _f(row, "why")
    with open(target, "rb") as fh:
        assert fh.read() == OLD
    assert _f(row, "sha_after") == _sha(OLD)
    elders, temps, rest = _strays(str(tmp_root), "body.py")
    assert len(elders) == 1 and temps == [] and rest == []


def test_dependent_past_the_wall_rolls_back(make_cfg, secret_file, tmp_root, keep_dir):
    target, candidate = _setup(tmp_root, keep_dir)
    slow = [sys.executable, "-c", "import time; time.sleep(30)"]
    cfg, dep = _with_dependent(make_cfg, tmp_root, target, slow, walls={"test_wall_s": 1})
    p, a = _approved(cfg, target, candidate)
    row = land_mod.land(cfg, p, candidate, a)
    assert _f(row, "verdict") == "REFUSED"
    assert dep in _f(row, "why")
    with open(target, "rb") as fh:
        assert fh.read() == OLD


def test_unlaunchable_dependent_faults_and_rolls_back(make_cfg, secret_file, tmp_root, keep_dir):
    target, candidate = _setup(tmp_root, keep_dir)
    cfg, dep = _with_dependent(make_cfg, tmp_root, target, [str(keep_dir / "no_such_program")])
    p, a = _approved(cfg, target, candidate)
    row = land_mod.land(cfg, p, candidate, a)
    assert _f(row, "verdict") == "FAULT"
    assert _f(row, "why").startswith("FAULT: ")
    with open(target, "rb") as fh:
        assert fh.read() == OLD
    elders, temps, rest = _strays(str(tmp_root), "body.py")
    assert len(elders) == 1 and temps == [] and rest == []


# ---------------------------------------------------------------- must fail: kills and recovery


def test_kill_between_temp_and_rename_recovers(cfg, secret_file, tmp_root, keep_dir, monkeypatch):
    target, candidate = _setup(tmp_root, keep_dir)
    p, a = _approved(cfg, target, candidate)
    real_replace = os.replace

    def killing_replace(src, dst, *args, **kwargs):
        if os.fspath(dst) == target:
            raise _Kill()
        return real_replace(src, dst, *args, **kwargs)

    monkeypatch.setattr(land_mod.os, "replace", killing_replace)
    with pytest.raises(_Kill):
        land_mod.land(cfg, p, candidate, a)
    monkeypatch.setattr(land_mod.os, "replace", real_replace)

    elders, temps, rest = _strays(str(tmp_root), "body.py")
    assert len(elders) == 1 and len(temps) == 1 and rest == [".landlock_journal_body.py.json"]
    journal = os.path.join(str(tmp_root), rest[0])
    with open(journal, encoding="utf-8") as fh:
        j = json.load(fh)
    assert j["step"] == "temp-written"
    assert set(j) == {
        "target", "elder", "candidate_sha256", "sha_before", "step", "started_at", "approval_id",
    }
    assert j["approval_id"] == _f(a, "id")
    with open(target, "rb") as fh:
        assert fh.read() == OLD

    row = land_mod.recover(cfg, journal)
    assert _f(row, "verdict") == "DONE" and _f(row, "act") == "recover"
    assert _f(row, "sha_after") == _sha(OLD)
    with open(target, "rb") as fh:
        assert fh.read() == OLD
    elders, temps, rest = _strays(str(tmp_root), "body.py")
    assert temps == [] and rest == []


def test_hand_laid_temp_written_journal_recovers(cfg, tmp_root):
    """The brief's own simulation: a journal at temp-written with the temp on disk."""
    target = tmp_root / "conf.txt"
    target.write_bytes(OLD)
    elder = tmp_root / "conf.txt.pre_land_stamp"
    elder.write_bytes(OLD)
    temp = tmp_root / ".landlock_tmp_conf.txt_4242"
    temp.write_bytes(NEW)
    journal = _plant_journal(target, elder, "temp-written", _sha(OLD), _sha(NEW))
    row = land_mod.recover(cfg, str(journal))
    assert _f(row, "verdict") == "DONE"
    assert not temp.exists() and not journal.exists()
    assert target.read_bytes() == OLD


def test_kill_after_rename_recovers_to_elder(make_cfg, secret_file, tmp_root, keep_dir, monkeypatch):
    target, candidate = _setup(tmp_root, keep_dir)
    cfg, dep = _with_dependent(make_cfg, tmp_root, target, PASS_ARGV)
    p, a = _approved(cfg, target, candidate)

    def killing_run(*args, **kwargs):
        raise _Kill()

    monkeypatch.setattr(land_mod.subprocess, "run", killing_run)
    with pytest.raises(_Kill):
        land_mod.land(cfg, p, candidate, a)
    monkeypatch.setattr(land_mod.subprocess, "run", subprocess.run)

    elders, temps, rest = _strays(str(tmp_root), "body.py")
    assert len(elders) == 1 and temps == [] and rest == [".landlock_journal_body.py.json"]
    journal = os.path.join(str(tmp_root), rest[0])
    with open(journal, encoding="utf-8") as fh:
        assert json.load(fh)["step"] == "replaced"
    with open(target, "rb") as fh:
        assert fh.read() == NEW

    row = land_mod.recover(cfg, journal)
    assert _f(row, "verdict") == "DONE"
    with open(target, "rb") as fh:
        assert fh.read() == OLD
    assert not os.path.exists(journal)
    assert os.path.exists(os.path.join(str(tmp_root), elders[0]))
    # The cut-off landing gets its row, so the chain carries no gap.
    assert receipts_mod.verify_chain(cfg, target) >= 2


def test_recover_during_a_landing_refuses_on_the_lock(make_cfg, secret_file, tmp_root, keep_dir, monkeypatch):
    target, candidate = _setup(tmp_root, keep_dir)
    cfg, dep = _with_dependent(make_cfg, tmp_root, target, PASS_ARGV)
    p, a = _approved(cfg, target, candidate)
    journal = str(tmp_root / ".landlock_journal_body.py.json")
    whys = []
    real_run = subprocess.run

    def run_with_intruders(*args, **kwargs):
        for act in (lambda: land_mod.recover(cfg, journal), lambda: land_mod.rollback(cfg, target)):
            try:
                act()
            except Refused as exc:
                whys.append(exc.why)
        return real_run(*args, **kwargs)

    monkeypatch.setattr(land_mod.subprocess, "run", run_with_intruders)
    row = land_mod.land(cfg, p, candidate, a)
    assert len(whys) == 2
    assert all(w.startswith("REFUSED: ") and "lock" in w for w in whys)
    assert _f(row, "verdict") == "DONE"
    with open(target, "rb") as fh:
        assert fh.read() == NEW


def test_planted_journal_that_would_move_to_unnamed_bytes_refuses_loud(cfg, tmp_root):
    target = tmp_root / "app.py"
    target.write_bytes(NEW)
    _pin_row(cfg, target, _sha(OLD))  # the honest history names only the old bytes
    evil_elder = tmp_root / "app.py.pre_land_evil"
    evil_elder.write_bytes(EVIL)
    journal = _plant_journal(target, evil_elder, "replaced", _sha(EVIL), _sha(NEW))
    with pytest.raises(Refused) as info:
        land_mod.recover(cfg, str(journal))
    assert info.value.why.startswith("REFUSED: ")
    assert _sha(EVIL) in info.value.why
    assert target.read_bytes() == NEW
    assert journal.exists()
    row = _last(cfg, target)
    assert _f(row, "act") == "recover" and _f(row, "verdict") == "REFUSED"


def test_planted_tests_done_journal_without_a_done_row_never_keeps_forward(cfg, tmp_root):
    target = tmp_root / "conf.txt"
    target.write_bytes(NEW)
    elder = tmp_root / "conf.txt.pre_land_stamp"
    elder.write_bytes(OLD)
    journal = _plant_journal(target, elder, "tests-done", _sha(OLD), _sha(NEW))
    with pytest.raises(Refused) as info:
        land_mod.recover(cfg, str(journal))
    assert info.value.why.startswith("REFUSED: ")
    assert target.read_bytes() == NEW and journal.exists()


def test_recover_refuses_a_missing_journal(cfg, tmp_root):
    with pytest.raises(Refused) as info:
        land_mod.recover(cfg, str(tmp_root / ".landlock_journal_none.json"))
    assert info.value.why.startswith("REFUSED: ")
    # The refusal is filed under the target the journal's name speaks for.
    row = _last(cfg, tmp_root / "none")
    assert _f(row, "act") == "recover" and _f(row, "verdict") == "REFUSED"


def test_recover_refuses_a_journal_outside_the_roots(cfg, keep_dir):
    outside = keep_dir / "body.py"
    outside.write_bytes(NEW)
    elder = keep_dir / "body.py.pre_land_x"
    elder.write_bytes(OLD)
    journal = _plant_journal(outside, elder, "replaced", _sha(OLD), _sha(NEW))
    with pytest.raises(Refused) as info:
        land_mod.recover(cfg, str(journal))
    assert info.value.why.startswith("REFUSED: ")
    assert outside.read_bytes() == NEW


def test_recover_faults_when_the_elder_is_gone(cfg, tmp_root):
    target = tmp_root / "conf.txt"
    target.write_bytes(NEW)
    _pin_row(cfg, target, _sha(OLD))
    journal = _plant_journal(target, tmp_root / "conf.txt.pre_land_gone", "replaced", _sha(OLD), _sha(NEW))
    row = land_mod.recover(cfg, str(journal))
    assert _f(row, "verdict") == "FAULT"
    assert _f(row, "why").startswith("FAULT: ")
    assert journal.exists()  # kept for a later recover once the elder is found
    assert target.read_bytes() == NEW


def test_rollback_without_a_landing_refuses(cfg, tmp_root):
    target = tmp_root / "never_landed.py"
    target.write_bytes(OLD)
    with pytest.raises(Refused) as info:
        land_mod.rollback(cfg, str(target))
    assert info.value.why.startswith("REFUSED: ")
    assert target.read_bytes() == OLD


def test_rollback_refuses_when_live_moved_since_landing(cfg, secret_file, tmp_root, keep_dir):
    target, candidate = _setup(tmp_root, keep_dir)
    p, a = _approved(cfg, target, candidate)
    row = land_mod.land(cfg, p, candidate, a)
    assert _f(row, "verdict") == "DONE"
    with open(target, "wb") as fh:
        fh.write(b"print('edited after the landing')\n")
    with pytest.raises(Refused) as info:
        land_mod.rollback(cfg, target)
    assert info.value.why.startswith("REFUSED: ")
    with open(target, "rb") as fh:
        assert fh.read() == b"print('edited after the landing')\n"


# ---------------------------------------------------------------- positive road


def test_green_landing_then_rollback(make_cfg, secret_file, tmp_root, keep_dir):
    target, candidate = _setup(tmp_root, keep_dir)
    os.chmod(target, 0o640)
    cfg, dep = _with_dependent(make_cfg, tmp_root, target, PASS_ARGV)
    p, a = _approved(cfg, target, candidate)

    row = land_mod.land(cfg, p, candidate, a)
    assert _f(row, "verdict") == "DONE"
    assert _f(row, "act") == "land"
    assert _f(row, "path") == target
    assert _f(row, "sha_before") == _sha(OLD)
    assert _f(row, "sha_after") == _sha(NEW)
    assert _f(row, "approval_id") == _f(a, "id")
    with open(target, "rb") as fh:
        assert fh.read() == NEW
    assert os.stat(target).st_mode & 0o777 == 0o640
    elder = _f(row, "elder")
    assert os.path.dirname(elder) == str(tmp_root)
    assert os.path.basename(elder).startswith("body.py.pre_land_")
    with open(elder, "rb") as fh:
        assert fh.read() == OLD
    elders, temps, rest = _strays(str(tmp_root), "body.py")
    assert len(elders) == 1 and temps == [] and rest == []

    back = land_mod.rollback(cfg, target)
    assert _f(back, "verdict") == "DONE"
    assert _f(back, "act") == "rollback"
    assert _f(back, "sha_before") == _sha(NEW)
    assert _f(back, "sha_after") == _sha(OLD)
    assert _f(back, "elder") == elder
    with open(target, "rb") as fh:
        assert fh.read() == OLD
    assert os.path.exists(elder)
    assert _strays(str(tmp_root), "body.py")[1:] == ([], [])
    assert receipts_mod.verify_chain(cfg, target) >= 2


def test_landing_with_no_dependents_is_done(cfg, secret_file, tmp_root, keep_dir):
    target, candidate = _setup(tmp_root, keep_dir)
    p, a = _approved(cfg, target, candidate)
    row = land_mod.land(cfg, p, candidate, a)
    assert _f(row, "verdict") == "DONE"
    with open(target, "rb") as fh:
        assert fh.read() == NEW


def test_kill_after_the_done_row_keeps_the_landing_and_rollback_still_works(cfg, secret_file, tmp_root, keep_dir, monkeypatch):
    target, candidate = _setup(tmp_root, keep_dir)
    p, a = _approved(cfg, target, candidate)

    def killing_remove(target_path):
        raise _Kill()

    monkeypatch.setattr(land_mod, "_remove_journal", killing_remove)
    with pytest.raises(_Kill):
        land_mod.land(cfg, p, candidate, a)
    monkeypatch.undo()

    journal = tmp_root / ".landlock_journal_body.py.json"
    assert json.loads(journal.read_text(encoding="utf-8"))["step"] == "tests-done"
    row = land_mod.recover(cfg, str(journal))
    assert _f(row, "verdict") == "DONE"
    with open(target, "rb") as fh:
        assert fh.read() == NEW
    assert not journal.exists()

    back = land_mod.rollback(cfg, target)
    assert _f(back, "verdict") == "DONE"
    with open(target, "rb") as fh:
        assert fh.read() == OLD

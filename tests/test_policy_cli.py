"""Tests for the policy hooks and the command line: every refusal first, then the working road."""

from __future__ import annotations

import hashlib
import importlib
import json
import os
import shutil
import tempfile
from datetime import datetime, timezone

import pytest

from landlock.errors import Refused

cli = importlib.import_module("landlock.cli")
policy = importlib.import_module("landlock.policy")

OLD = b"value = 1\n"
NEW = b"value = 2\n"


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _event(tmp_path, act="land"):
    target = str(tmp_path / "root" / "app.py")
    return {
        "act": act,
        "target": target,
        "candidate_sha256": "a" * 64,
        "pin": {"path": target, "sha256": "b" * 64, "size": 1, "mtime_ns": 1,
                "pinned_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")},
    }


def _run(capsys, *argv):
    """Run the command line; return (exit code, printed lines)."""
    code = cli.main(list(argv))
    out = capsys.readouterr().out
    return code, out.splitlines()


@pytest.fixture
def conf(cfg, keep_dir):
    """The path of the TOML file the cfg fixture was loaded from."""
    path = keep_dir / "landlock.toml"
    assert path.is_file()
    return str(path)


@pytest.fixture
def target(tmp_root):
    path = tmp_root / "app.py"
    path.write_bytes(OLD)
    return path


@pytest.fixture
def candidate(tmp_path):
    folder = tmp_path / "incoming"
    folder.mkdir()
    path = folder / "app.py"
    path.write_bytes(NEW)
    return path


@pytest.fixture(autouse=True)
def _no_env_config(monkeypatch, tmp_path):
    """No test reads a config from the environment or the working folder by accident."""
    monkeypatch.delenv("LANDLOCK_CONFIG", raising=False)
    monkeypatch.chdir(tmp_path)


# ====================================================== MUST FAIL: the policy hooks


def test_policy_false_refuses_with_exactly_that_why(tmp_path):
    why = "REFUSED: nothing lands on a frozen branch."
    with pytest.raises(Refused) as caught:
        policy.run([lambda e: (False, why)], _event(tmp_path))
    assert caught.value.why == why


def test_policy_bare_why_gets_the_refusal_prefix(tmp_path):
    with pytest.raises(Refused) as caught:
        policy.run([lambda e: (False, "the change window is closed.")], _event(tmp_path))
    assert caught.value.why == "REFUSED: the change window is closed."


def test_policy_first_refusal_stops_the_rest(tmp_path):
    called = []

    def later(event):
        called.append(event)
        return (True, "")

    with pytest.raises(Refused) as caught:
        policy.run([lambda e: (True, ""), lambda e: (False, "REFUSED: second says no."), later],
                   _event(tmp_path))
    assert caught.value.why == "REFUSED: second says no."
    assert called == []


def test_policy_multiline_why_is_folded_to_one_line(tmp_path):
    with pytest.raises(Refused) as caught:
        policy.run([lambda e: (False, "REFUSED: first part\nsecond part")], _event(tmp_path))
    assert caught.value.why == "REFUSED: first part second part"


@pytest.mark.parametrize("result", [True, None, "ok", (True,), [True, ""], (True, "", "x")])
def test_policy_result_not_a_pair_refuses(tmp_path, result):
    with pytest.raises(Refused) as caught:
        policy.run([lambda e: result], _event(tmp_path))
    assert caught.value.why.startswith("REFUSED: policy ")
    assert "did not return an (allowed, why) pair" in caught.value.why


@pytest.mark.parametrize("allowed", [1, 0, "yes", "", None])
def test_policy_allowed_not_a_bool_refuses(tmp_path, allowed):
    with pytest.raises(Refused) as caught:
        policy.run([lambda e: (allowed, "")], _event(tmp_path))
    assert caught.value.why.startswith("REFUSED: policy ")
    assert "not True or False" in caught.value.why


@pytest.mark.parametrize("why", ["", "   ", None, "REFUSED: ", 7])
def test_policy_refusal_without_a_reason_refuses_anyway(tmp_path, why):
    with pytest.raises(Refused) as caught:
        policy.run([lambda e: (False, why)], _event(tmp_path))
    assert caught.value.why.startswith("REFUSED: policy ")
    assert "without giving a reason" in caught.value.why


def test_policy_not_callable_refuses(tmp_path):
    with pytest.raises(Refused) as caught:
        policy.run(["not a function"], _event(tmp_path))
    assert caught.value.why == "REFUSED: a policy in the list is not callable."


def test_policy_event_with_unknown_act_refuses(tmp_path):
    with pytest.raises(Refused) as caught:
        policy.run([], _event(tmp_path, act="pin"))
    assert caught.value.why == "REFUSED: the policy event act must be rehearse or land."


def test_policy_event_missing_keys_refuses(tmp_path):
    event = _event(tmp_path)
    del event["pin"]
    del event["candidate_sha256"]
    with pytest.raises(Refused) as caught:
        policy.run([], event)
    assert caught.value.why == "REFUSED: the policy event lacks candidate_sha256, pin."


def test_policy_event_not_a_dict_refuses():
    with pytest.raises(Refused) as caught:
        policy.run([], ["land"])
    assert caught.value.why == "REFUSED: a policy event must be a dict."


def test_policy_that_raises_is_not_swallowed(tmp_path):
    def broken(event):
        raise RuntimeError("the policy itself broke")

    with pytest.raises(RuntimeError):
        policy.run([broken], _event(tmp_path))


# ====================================================== MUST FAIL: the command line


def test_cli_no_config_file_exits_2_with_one_refused_line(capsys, target):
    code, lines = _run(capsys, "pin", str(target))
    assert code == 2
    assert len(lines) == 1
    assert lines[0].startswith("REFUSED: no config file at ")
    assert lines[0].endswith("; pass --config or set LANDLOCK_CONFIG.")


def test_cli_config_from_environment_missing_exits_2(capsys, monkeypatch, tmp_path, target):
    monkeypatch.setenv("LANDLOCK_CONFIG", str(tmp_path / "nowhere.toml"))
    code, lines = _run(capsys, "pin", str(target))
    assert code == 2
    assert lines == ["REFUSED: no config file at " + str(tmp_path / "nowhere.toml")
                     + "; pass --config or set LANDLOCK_CONFIG."]


def test_cli_config_not_valid_toml_exits_2(capsys, tmp_path, target):
    bad = tmp_path / "bad.toml"
    bad.write_text("roots = [\n", encoding="utf-8")
    code, lines = _run(capsys, "--config", str(bad), "pin", str(target))
    assert code == 2
    assert len(lines) == 1
    assert lines[0].startswith("REFUSED: the config file is not valid TOML")


def test_cli_land_without_approval_exits_2(capsys, conf, target, candidate):
    code, lines = _run(capsys, "land", str(target), str(candidate), "--config", conf)
    assert code == 2
    assert lines == ["REFUSED: land needs --approval <file>; nothing lands without a signed approval."]
    assert target.read_bytes() == OLD


def test_cli_land_without_approval_refuses_before_the_config(capsys, target, candidate):
    code, lines = _run(capsys, "land", str(target), str(candidate))
    assert code == 2
    assert lines == ["REFUSED: land needs --approval <file>; nothing lands without a signed approval."]


def test_cli_unknown_subcommand_exits_2(capsys):
    code, lines = _run(capsys, "launch")
    assert code == 2
    assert len(lines) == 1
    assert lines[0].startswith("REFUSED: ")
    assert "invalid choice" in lines[0]


def test_cli_no_subcommand_exits_2(capsys):
    code, lines = _run(capsys)
    assert code == 2
    assert len(lines) == 1
    assert lines[0].startswith("REFUSED: ")


def test_cli_missing_argument_exits_2(capsys, conf):
    code, lines = _run(capsys, "--config", conf, "approve")
    assert code == 2
    assert len(lines) == 1
    assert lines[0].startswith("REFUSED: ")


def test_cli_pin_outside_every_root_exits_2(capsys, conf, tmp_path):
    outside = tmp_path / "elsewhere.py"
    outside.write_bytes(OLD)
    code, lines = _run(capsys, "--config", conf, "pin", str(outside))
    assert code == 2
    assert lines == ["REFUSED: " + str(outside) + " is outside every root in the config."]


def test_cli_pin_missing_file_exits_2(capsys, conf, tmp_root):
    code, lines = _run(capsys, "--config", conf, "pin", str(tmp_root / "absent.py"))
    assert code == 2
    assert lines == ["REFUSED: file not found: " + str(tmp_root / "absent.py")]


def test_cli_approve_without_secret_exits_2(capsys, conf, target, candidate):
    code, lines = _run(capsys, "--config", conf, "approve", str(target), str(candidate))
    assert code == 2
    assert lines == ["REFUSED: the secret file does not exist."]
    assert not os.path.exists(str(candidate) + ".approval.json")


def test_cli_approve_candidate_missing_exits_2(capsys, conf, secret_file, target, tmp_path):
    code, lines = _run(capsys, "--config", conf, "approve", str(target), str(tmp_path / "none.py"))
    assert code == 2
    assert lines == ["REFUSED: the candidate " + str(tmp_path / "none.py") + " is not a file."]


def test_cli_approve_candidate_is_target_exits_2(capsys, conf, secret_file, target):
    code, lines = _run(capsys, "--config", conf, "approve", str(target), str(target))
    assert code == 2
    assert lines == ["REFUSED: the candidate is the live target itself."]


@pytest.mark.parametrize("ttl", ["0", "-5"])
def test_cli_approve_ttl_not_positive_exits_2(capsys, conf, secret_file, target, candidate, ttl):
    code, lines = _run(capsys, "--config", conf, "approve", str(target), str(candidate), "--ttl", ttl)
    assert code == 2
    assert lines == ["REFUSED: --ttl must be a positive number of seconds."]


def test_cli_approve_out_naming_the_target_exits_2(capsys, conf, secret_file, target, candidate):
    code, lines = _run(capsys, "--config", conf, "approve", str(target), str(candidate),
                       "--out", str(target))
    assert code == 2
    assert lines == ["REFUSED: the approval file " + str(target)
                     + " is the target; an approval is never written over it."]
    assert target.read_bytes() == OLD


def test_cli_approve_out_naming_the_secret_exits_2_and_keeps_the_key(capsys, conf, secret_file, target, candidate):
    key = secret_file.read_bytes()
    code, lines = _run(capsys, "--config", conf, "approve", str(target), str(candidate),
                       "--out", str(secret_file))
    assert code == 2
    assert lines == ["REFUSED: the approval file " + str(secret_file)
                     + " is the secret file; an approval is never written over it."]
    assert secret_file.read_bytes() == key


def test_cli_approve_out_naming_the_receipts_exits_2_and_keeps_the_rows(
        capsys, conf, cfg, secret_file, target, candidate):
    code, _ = _run(capsys, "--config", conf, "pin", str(target))
    assert code == 0
    receipts_path = cfg.receipts
    before = open(receipts_path, "rb").read()
    code, lines = _run(capsys, "--config", conf, "approve", str(target), str(candidate),
                       "--out", receipts_path)
    assert code == 2
    assert lines == ["REFUSED: the approval file " + receipts_path
                     + " is the receipts file; an approval is never written over it."]
    assert open(receipts_path, "rb").read() == before
    code, lines = _run(capsys, "--config", conf, "verify")
    assert code == 0, lines


def test_cli_approve_out_naming_the_config_exits_2(capsys, conf, secret_file, target, candidate):
    before = open(conf, "rb").read()
    code, lines = _run(capsys, "--config", conf, "approve", str(target), str(candidate),
                       "--out", conf)
    assert code == 2
    assert lines == ["REFUSED: the approval file " + conf
                     + " is the config file; an approval is never written over it."]
    assert open(conf, "rb").read() == before


def test_cli_approve_out_over_a_file_that_is_not_an_approval_exits_2(
        capsys, conf, secret_file, target, candidate, tmp_path):
    notes = tmp_path / "notes.txt"
    notes.write_text("keep me\n", encoding="utf-8")
    code, lines = _run(capsys, "--config", conf, "approve", str(target), str(candidate),
                       "--out", str(notes))
    assert code == 2
    assert lines == ["REFUSED: the approval file " + str(notes)
                     + " already holds a file that is not an approval record; it is never replaced."]
    assert notes.read_text(encoding="utf-8") == "keep me\n"


def test_cli_approve_out_inside_a_root_exits_2(capsys, conf, secret_file, target, candidate, tmp_root):
    out = tmp_root / "approval.json"
    code, lines = _run(capsys, "--config", conf, "approve", str(target), str(candidate),
                       "--out", str(out))
    assert code == 2
    assert lines == ["REFUSED: the approval file " + str(out)
                     + " lies inside a root; pass --out with a path outside every root."]
    assert not out.exists()


def test_cli_approve_default_out_inside_a_root_exits_2(capsys, conf, secret_file, target, tmp_root):
    inside = tmp_root / "next.py"
    inside.write_bytes(NEW)
    code, lines = _run(capsys, "--config", conf, "approve", str(target), str(inside))
    assert code == 2
    assert lines == ["REFUSED: the approval file " + str(inside) + ".approval.json"
                     + " lies inside a root; pass --out with a path outside every root."]
    assert sorted(os.listdir(tmp_root)) == ["app.py", "next.py"]


def test_cli_land_with_unreadable_approval_exits_2(capsys, conf, secret_file, target, candidate, tmp_path):
    bad = tmp_path / "bad.approval.json"
    bad.write_text("{not json", encoding="utf-8")
    code, lines = _run(capsys, "--config", conf, "land", str(target), str(candidate),
                       "--approval", str(bad))
    assert code == 2
    assert len(lines) == 1
    assert lines[0].startswith("REFUSED: the approval file " + str(bad) + " is not a readable approval")
    assert target.read_bytes() == OLD


def test_cli_land_with_approval_missing_a_field_exits_2(capsys, conf, secret_file, target, candidate, tmp_path):
    bad = tmp_path / "short.approval.json"
    bad.write_text(json.dumps({"id": "0" * 16}), encoding="utf-8")
    code, lines = _run(capsys, "--config", conf, "land", str(target), str(candidate),
                       "--approval", str(bad))
    assert code == 2
    assert len(lines) == 1
    assert lines[0].startswith("REFUSED: the approval record lacks the field(s) ")
    assert target.read_bytes() == OLD


def test_cli_land_with_absent_approval_file_exits_2(capsys, conf, target, candidate, tmp_path):
    code, lines = _run(capsys, "--config", conf, "land", str(target), str(candidate),
                       "--approval", str(tmp_path / "absent.json"))
    assert code == 2
    assert lines == ["REFUSED: the approval file " + str(tmp_path / "absent.json") + " does not exist."]


def test_cli_land_with_approval_for_other_bytes_exits_2(capsys, conf, secret_file, target, candidate):
    code, _ = _run(capsys, "--config", conf, "approve", str(target), str(candidate))
    assert code == 0
    candidate.write_bytes(b"value = 3\n")
    code, lines = _run(capsys, "--config", conf, "land", str(target), str(candidate),
                       "--approval", str(candidate) + ".approval.json")
    assert code == 2
    assert lines[0] == "REFUSED: the approval covers different candidate bytes."
    assert target.read_bytes() == OLD


def test_cli_land_after_the_live_bytes_moved_exits_2(capsys, conf, secret_file, target, candidate):
    code, _ = _run(capsys, "--config", conf, "approve", str(target), str(candidate))
    assert code == 0
    target.write_bytes(b"value = 9\n")
    code, lines = _run(capsys, "--config", conf, "land", str(target), str(candidate),
                       "--approval", str(candidate) + ".approval.json")
    assert code == 2
    assert lines[0] == "REFUSED: the pinned bytes moved; the pin's sha256 differs from the approval's."
    assert target.read_bytes() == b"value = 9\n"


def test_cli_recover_missing_journal_exits_2(capsys, conf, tmp_root):
    journal = tmp_root / ".landlock_journal_app.py.json"
    code, lines = _run(capsys, "--config", conf, "recover", str(journal))
    assert code == 2
    assert lines == ["REFUSED: the journal " + str(journal) + " does not exist."]


def test_cli_verify_chain_gap_exits_2(capsys, conf, cfg, target):
    receipts = importlib.import_module("landlock.receipts")

    path = str(target)
    for before, after in (("1" * 64, "2" * 64), ("3" * 64, "4" * 64)):
        receipts.append(cfg, receipts.Row(act="land", path=path, sha_before=before,
                                          sha_after=after, verdict="DONE"))
    code, lines = _run(capsys, "--config", conf, "verify", path)
    assert code == 2
    assert len(lines) == 1
    assert lines[0].startswith("REFUSED: the receipts chain has a gap for " + path)


def test_cli_unexpected_exception_is_a_fault_exit_3(capsys, conf, target, monkeypatch):
    pin_mod = importlib.import_module("landlock.pin")

    def boom(path):
        raise RuntimeError("disk on fire")

    monkeypatch.setattr(pin_mod, "pin", boom)
    code, lines = _run(capsys, "--config", conf, "pin", str(target))
    assert code == 3
    assert lines == ["FAULT: RuntimeError: disk on fire"]


# ====================================================== THE POSITIVE ROAD


def test_policy_all_allow_passes_and_each_sees_its_own_copy(tmp_path):
    event = _event(tmp_path)
    seen = []

    def meddler(e):
        seen.append(dict(e))
        e["target"] = "/changed"
        e["pin"]["sha256"] = "c" * 64
        return (True, "")

    def watcher(e):
        seen.append(dict(e))
        return (True, "fine")

    assert policy.run([meddler, watcher], event) is None
    assert seen[1]["target"] == event["target"]
    assert seen[1]["pin"]["sha256"] == "b" * 64
    assert event["target"].endswith("app.py")


def test_policy_empty_list_passes(tmp_path):
    assert policy.run([], _event(tmp_path, act="rehearse")) is None
    assert policy.run((), _event(tmp_path)) is None


def test_cli_help_exits_0(capsys):
    code = cli.main(["--help"])
    out = capsys.readouterr().out
    assert code == 0
    assert "rehearse" in out and "rollback" in out


def test_cli_pin_prints_pinned_and_exits_0(capsys, conf, cfg, target):
    code, lines = _run(capsys, "--config", conf, "pin", str(target))
    assert code == 0
    assert lines[0] == "PINNED " + str(target) + " " + _sha(OLD)
    detail = json.loads(lines[1])
    assert detail["path"] == str(target) and detail["sha256"] == _sha(OLD)
    receipts = importlib.import_module("landlock.receipts")

    rows = receipts.rows(cfg, str(target))
    assert [(r.act, r.verdict, r.sha_before) for r in rows] == [("pin", "DONE", _sha(OLD))]


def test_cli_config_after_the_subcommand(capsys, conf, target):
    code, lines = _run(capsys, "pin", str(target), "--config", conf)
    assert code == 0
    assert lines[0] == "PINNED " + str(target) + " " + _sha(OLD)


def test_cli_config_from_environment(capsys, monkeypatch, conf, target):
    monkeypatch.setenv("LANDLOCK_CONFIG", conf)
    code, lines = _run(capsys, "pin", str(target))
    assert code == 0
    assert lines[0] == "PINNED " + str(target) + " " + _sha(OLD)


def test_cli_config_default_in_working_folder(capsys, monkeypatch, conf, keep_dir, target):
    monkeypatch.chdir(keep_dir)
    code, lines = _run(capsys, "pin", str(target))
    assert code == 0
    assert lines[0] == "PINNED " + str(target) + " " + _sha(OLD)


def test_cli_relative_config_is_made_absolute_against_the_working_folder(
        capsys, monkeypatch, conf, keep_dir, target):
    monkeypatch.chdir(keep_dir)
    code, lines = _run(capsys, "--config", "landlock.toml", "pin", str(target))
    assert code == 0, lines
    assert lines[0] == "PINNED " + str(target) + " " + _sha(OLD)
    monkeypatch.setenv("LANDLOCK_CONFIG", "landlock.toml")
    code, lines = _run(capsys, "pin", str(target))
    assert code == 0, lines


def test_cli_approve_replaces_an_old_approval_at_out(capsys, conf, secret_file, target, candidate, tmp_path):
    out = tmp_path / "approval.json"
    code, _ = _run(capsys, "--config", conf, "approve", str(target), str(candidate), "--out", str(out))
    assert code == 0
    code, lines = _run(capsys, "--config", conf, "approve", str(target), str(candidate),
                       "--out", str(out), "--ttl", "120")
    assert code == 0, lines
    data = json.loads(out.read_text(encoding="utf-8"))
    assert lines[0] == "APPROVED " + data["id"]


def test_cli_relative_paths_are_made_absolute(capsys, monkeypatch, conf, tmp_root, target):
    monkeypatch.chdir(tmp_root)
    code, lines = _run(capsys, "--config", conf, "pin", "app.py")
    assert code == 0
    assert lines[0] == "PINNED " + str(target) + " " + _sha(OLD)


def test_cli_approve_writes_out_and_prints_approved(capsys, conf, cfg, secret_file, target, candidate, tmp_path):
    out = tmp_path / "approval.json"
    code, lines = _run(capsys, "--config", conf, "approve", str(target), str(candidate),
                       "--out", str(out), "--ttl", "600")
    assert code == 0
    data = json.loads(out.read_text(encoding="utf-8"))
    assert lines[0] == "APPROVED " + data["id"]
    assert lines[1] == "written to " + str(out)
    assert data["target"] == str(target)
    assert data["candidate_sha256"] == _sha(NEW)
    assert data["pin_sha256"] == _sha(OLD)
    assert oct(os.stat(out).st_mode & 0o777) == oct(0o600)
    assert target.read_bytes() == OLD
    assert sorted(os.listdir(tmp_path / "incoming")) == ["app.py"]
    approve = importlib.import_module("landlock.approve")
    pin_mod = importlib.import_module("landlock.pin")
    receipts = importlib.import_module("landlock.receipts")

    a = approve.Approval.from_json(out.read_text(encoding="utf-8"))
    assert approve.verify(cfg, a, pin_mod.pin(str(target)), _sha(NEW)) == a
    rows = receipts.rows(cfg, str(target))
    assert [(r.act, r.verdict, r.approval_id) for r in rows] == [("approve", "DONE", data["id"])]


def test_cli_approve_default_out_beside_the_candidate(capsys, conf, secret_file, target, candidate):
    code, lines = _run(capsys, "--config", conf, "approve", str(target), str(candidate))
    assert code == 0, lines
    out = str(candidate) + ".approval.json"
    data = json.loads(open(out, encoding="utf-8").read())
    assert lines[0] == "APPROVED " + data["id"]
    assert lines[1] == "written to " + out


def test_cli_land_verify_receipts_rollback_road(capsys, conf, cfg, secret_file, target, candidate):
    code, lines = _run(capsys, "--config", conf, "approve", str(target), str(candidate))
    assert code == 0
    approval = str(candidate) + ".approval.json"

    code, lines = _run(capsys, "--config", conf, "land", str(target), str(candidate),
                       "--approval", approval)
    assert code == 0, lines
    assert lines[0] == "LANDED " + str(target) + " " + _sha(NEW)
    assert target.read_bytes() == NEW

    code, lines = _run(capsys, "--config", conf, "verify", str(target))
    assert code == 0
    assert lines[0] == "VERIFIED 1 rows"
    assert lines[1] == "1 chain rows of 2 rows read"

    code, lines = _run(capsys, "--config", conf, "receipts", str(target))
    assert code == 0
    acts = [json.loads(line)["act"] for line in lines[1:]]
    assert lines[0] == "ROWS " + str(len(acts))
    assert acts[:2] == ["approve", "land"]

    code, lines = _run(capsys, "--config", conf, "rollback", str(target))
    assert code == 0, lines
    assert lines[0] == "ROLLED BACK " + str(target) + " " + _sha(OLD)
    assert target.read_bytes() == OLD

    code, lines = _run(capsys, "--config", conf, "verify")
    assert code == 0
    assert lines[0] == "VERIFIED 2 rows"


def test_cli_receipts_on_an_empty_ledger(capsys, conf):
    code, lines = _run(capsys, "--config", conf, "receipts")
    assert code == 0
    assert lines == ["ROWS 0"]


@pytest.mark.skipif(shutil.which("bwrap") is None, reason="bubblewrap is not installed")
def test_cli_rehearse_prints_would_land(capsys, monkeypatch, conf, cfg, target, candidate, tmp_path):
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(scratch))
    code, lines = _run(capsys, "--config", conf, "rehearse", str(target), str(candidate))
    assert code == 0, lines
    assert lines[0] == "WOULD LAND"
    assert target.read_bytes() == OLD
    receipts = importlib.import_module("landlock.receipts")

    rows = receipts.rows(cfg, str(target))
    assert [(r.act, r.verdict) for r in rows] == [("rehearse", "WOULD-LAND")]

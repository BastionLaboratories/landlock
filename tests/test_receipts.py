"""Tests that the receipts file refuses bad rows and broken chains first, then appends, reads and verifies rows correctly."""

import json
import os
import stat
import sys
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

_TREE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _TREE not in sys.path:
    sys.path.insert(0, _TREE)

from landlock import receipts  # noqa: E402
from landlock.errors import Fault, Refused  # noqa: E402
from landlock.receipts import Row, append, request_id, rows, verify_chain  # noqa: E402

A = "a" * 64
B = "b" * 64
C = "c" * 64
D = "d" * 64
BASE = datetime.now(timezone.utc).replace(microsecond=0)
TS1 = BASE.strftime("%Y-%m-%dT%H:%M:%SZ")
TS2 = (BASE + timedelta(seconds=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
TS3 = (BASE + timedelta(seconds=2)).strftime("%Y-%m-%dT%H:%M:%SZ")
COMPACT1 = BASE.strftime("%Y%m%dT%H%M%S")


@pytest.fixture
def rcfg(tmp_path):
    """A stand-in config that carries only the receipts path, inside tmp_path."""
    return SimpleNamespace(receipts=str(tmp_path / "state" / "receipts.jsonl"))


@pytest.fixture
def target(tmp_path):
    return str(tmp_path / "root" / "body.py")


def mk(target, act="land", before=A, after=B, verdict="DONE", ts=TS1, **kw):
    return Row(ts=ts, request_id=request_id(target, ts), act=act, path=target,
               sha_before=before, sha_after=after, verdict=verdict, **kw)


def why_of(exc_info):
    return exc_info.value.why


# ---------------------------------------------------------------- must fail first

def test_chain_gap_refuses_naming_both_digests(rcfg, target):
    append(rcfg, mk(target, before=A, after=B, ts=TS1))
    append(rcfg, mk(target, before=C, after=D, ts=TS2))
    with pytest.raises(Refused) as ei:
        verify_chain(rcfg, target)
    why = why_of(ei)
    assert why.startswith("REFUSED: the receipts chain has a gap")
    assert B in why and C in why
    assert target in why


def test_chain_gap_between_land_and_rollback_refuses(rcfg, target):
    append(rcfg, mk(target, act="land", before=A, after=B, ts=TS1))
    append(rcfg, mk(target, act="rollback", before=C, after=A, ts=TS2))
    with pytest.raises(Refused) as ei:
        verify_chain(rcfg, target)
    assert why_of(ei).startswith("REFUSED: the receipts chain has a gap")


def test_chain_gap_with_empty_sha_before_refuses(rcfg, target):
    append(rcfg, mk(target, before=A, after=B, ts=TS1))
    append(rcfg, mk(target, before="", after=C, ts=TS2))
    with pytest.raises(Refused) as ei:
        verify_chain(rcfg, target)
    assert why_of(ei).startswith("REFUSED: the receipts chain has a gap")
    assert "(empty)" in why_of(ei)


def test_chain_gap_found_with_no_path_given(rcfg, target):
    append(rcfg, mk(target, before=A, after=B, ts=TS1))
    append(rcfg, mk(target, before=C, after=D, ts=TS2))
    with pytest.raises(Refused) as ei:
        verify_chain(rcfg)
    assert why_of(ei).startswith("REFUSED: the receipts chain has a gap")


def test_relative_path_refuses_at_append(rcfg):
    row = Row(ts=TS1, request_id="body.py-" + COMPACT1, act="pin", path="relative/body.py",
              verdict="DONE")
    with pytest.raises(Refused) as ei:
        append(rcfg, row)
    assert why_of(ei).startswith("REFUSED: the receipt path")
    assert not os.path.exists(rcfg.receipts)


def test_relative_elder_refuses_at_append(rcfg, target):
    with pytest.raises(Refused) as ei:
        append(rcfg, mk(target, elder="body.py.pre_land"))
    assert why_of(ei).startswith("REFUSED: the elder path")
    assert not os.path.exists(rcfg.receipts)


def test_unknown_act_refuses(rcfg, target):
    with pytest.raises(Refused) as ei:
        append(rcfg, mk(target, act="delete"))
    assert why_of(ei).startswith("REFUSED: the act")


def test_unknown_verdict_refuses(rcfg, target):
    with pytest.raises(Refused) as ei:
        append(rcfg, mk(target, verdict="MAYBE"))
    assert why_of(ei).startswith("REFUSED: the verdict")


@pytest.mark.parametrize("bad", ["abc", "A" * 64, "g" * 64, "a" * 63, "a" * 65])
def test_bad_digest_refuses(rcfg, target, bad):
    with pytest.raises(Refused) as ei:
        append(rcfg, mk(target, after=bad))
    assert why_of(ei).startswith("REFUSED: the receipt field sha_after")


def test_bad_clock_refuses(rcfg, target):
    row = Row(ts="yesterday", request_id="x", act="pin", path=target, verdict="DONE")
    with pytest.raises(Refused) as ei:
        append(rcfg, row)
    assert why_of(ei).startswith("REFUSED: the clock")


def test_non_utc_clock_refuses(rcfg, target):
    plus_two = BASE.astimezone(timezone(timedelta(hours=2))).isoformat()
    row = Row(ts=plus_two, request_id="x", act="pin", path=target, verdict="DONE")
    with pytest.raises(Refused) as ei:
        append(rcfg, row)
    assert why_of(ei).startswith("REFUSED: the clock")


def test_non_string_field_refuses(rcfg, target):
    row = Row(ts=TS1, request_id="x", act="pin", path=target, verdict="DONE", why=5)
    with pytest.raises(Refused) as ei:
        append(rcfg, row)
    assert why_of(ei).startswith("REFUSED: the receipt field why must be a string")


def test_append_refuses_a_non_row(rcfg):
    with pytest.raises(Refused) as ei:
        append(rcfg, {"act": "pin"})
    assert why_of(ei).startswith("REFUSED: only a Row")


def test_append_refuses_a_config_with_no_receipts_path():
    with pytest.raises(Refused) as ei:
        append(SimpleNamespace(), mk("/x/body.py"))
    assert why_of(ei).startswith("REFUSED: the config names no absolute receipts path")


def test_append_refuses_a_relative_receipts_path(target):
    with pytest.raises(Refused) as ei:
        append(SimpleNamespace(receipts="receipts.jsonl"), mk(target))
    assert why_of(ei).startswith("REFUSED: the config names no absolute receipts path")


def test_request_id_refuses_a_bad_clock():
    with pytest.raises(Refused) as ei:
        request_id("/x/body.py", "not-a-time")
    assert why_of(ei).startswith("REFUSED: the clock")


def test_request_id_refuses_an_empty_path():
    with pytest.raises(Refused) as ei:
        request_id("", TS1)
    assert why_of(ei).startswith("REFUSED: a request id needs a path")


def test_rows_refuses_a_relative_path_filter(rcfg):
    with pytest.raises(Refused) as ei:
        rows(rcfg, "body.py")
    assert why_of(ei).startswith("REFUSED: the path")


def test_verify_chain_refuses_a_relative_path(rcfg):
    with pytest.raises(Refused) as ei:
        verify_chain(rcfg, "body.py")
    assert why_of(ei).startswith("REFUSED: the path")


def _plant(rcfg, text):
    os.makedirs(os.path.dirname(rcfg.receipts), exist_ok=True)
    with open(rcfg.receipts, "w", encoding="utf-8") as handle:
        handle.write(text)


def test_rows_refuses_a_line_that_is_not_json_naming_its_number(rcfg, target):
    good = mk(target).to_json()
    _plant(rcfg, good + "\n" + "{not json\n")
    with pytest.raises(Refused) as ei:
        rows(rcfg)
    assert why_of(ei).startswith("REFUSED: a receipt row is not valid JSON")
    assert "receipts line 2" in why_of(ei)


def test_rows_refuses_a_row_with_unknown_fields(rcfg, target):
    data = json.loads(mk(target).to_json())
    data["extra"] = "x"
    _plant(rcfg, json.dumps(data) + "\n")
    with pytest.raises(Refused) as ei:
        rows(rcfg)
    assert why_of(ei).startswith("REFUSED: a receipt row carries unknown fields: extra")


def test_rows_refuses_a_row_missing_required_fields(rcfg, target):
    data = json.loads(mk(target).to_json())
    del data["act"]
    _plant(rcfg, json.dumps(data) + "\n")
    with pytest.raises(Refused) as ei:
        rows(rcfg)
    assert why_of(ei).startswith("REFUSED: a receipt row lacks the fields: act")


def test_rows_refuses_a_blank_line_in_the_middle(rcfg, target):
    good = mk(target).to_json()
    _plant(rcfg, good + "\n\n" + good + "\n")
    with pytest.raises(Refused) as ei:
        rows(rcfg)
    assert why_of(ei).startswith("REFUSED: a receipt row is not valid JSON")


def test_rows_refuses_a_row_that_is_not_an_object(rcfg):
    _plant(rcfg, "[1, 2]\n")
    with pytest.raises(Refused) as ei:
        rows(rcfg)
    assert why_of(ei).startswith("REFUSED: a receipt row must be a JSON object")


def test_rows_refuses_a_file_that_is_not_utf8(rcfg):
    os.makedirs(os.path.dirname(rcfg.receipts), exist_ok=True)
    with open(rcfg.receipts, "wb") as handle:
        handle.write(b"\xff\xfe\n")
    with pytest.raises(Refused) as ei:
        rows(rcfg)
    assert why_of(ei).startswith("REFUSED: the receipts file is not valid UTF-8")


def test_a_hand_edited_row_with_a_relative_path_refuses_on_read(rcfg, target):
    data = json.loads(mk(target).to_json())
    data["path"] = "body.py"
    _plant(rcfg, json.dumps(data) + "\n")
    with pytest.raises(Refused) as ei:
        verify_chain(rcfg)
    assert why_of(ei).startswith("REFUSED: the receipt path")


def test_a_torn_tail_is_a_fault_and_nothing_is_added(rcfg, target):
    append(rcfg, mk(target))
    with open(rcfg.receipts, "ab") as handle:
        handle.write(b'{"ts":')
    before = open(rcfg.receipts, "rb").read()
    with pytest.raises(Fault) as ei:
        append(rcfg, mk(target, ts=TS2, before=B, after=C))
    assert ei.value.why.startswith("FAULT: the receipts file does not end in a newline")
    assert open(rcfg.receipts, "rb").read() == before


def test_from_json_refuses_a_non_json_string():
    with pytest.raises(Refused) as ei:
        Row.from_json("nope")
    assert why_of(ei).startswith("REFUSED: a receipt row is not valid JSON")


# ---------------------------------------------------------------- the positive road

def test_three_rows_appended_rows_in_order_and_chain_counts_three(rcfg, target):
    first = mk(target, act="pin", before="", after=A, ts=TS1)
    second = mk(target, act="land", before=A, after=B, ts=TS2)
    third = mk(target, act="rollback", before=B, after=A, ts=TS3, elder=target + ".pre_land_x")
    for row in (first, second, third):
        append(rcfg, row)
    got = rows(rcfg)
    assert got == [first, second, third]
    assert [r.act for r in got] == ["pin", "land", "rollback"]
    assert verify_chain(rcfg, target) == 3


def test_file_is_created_0600_with_one_json_line_per_row(rcfg, target):
    append(rcfg, mk(target, ts=TS1))
    append(rcfg, mk(target, before=B, after=C, ts=TS2))
    assert stat.S_IMODE(os.stat(rcfg.receipts).st_mode) == 0o600
    with open(rcfg.receipts, "rb") as handle:
        raw = handle.read()
    assert raw.endswith(b"\n")
    lines = raw.split(b"\n")[:-1]
    assert len(lines) == 2
    for line in lines:
        assert isinstance(json.loads(line), dict)


def test_file_mode_is_0600_even_under_a_loose_umask(rcfg, target):
    old = os.umask(0)
    try:
        append(rcfg, mk(target))
    finally:
        os.umask(old)
    assert stat.S_IMODE(os.stat(rcfg.receipts).st_mode) == 0o600


def test_append_flushes_and_fsyncs_the_file(rcfg, target, monkeypatch):
    calls = []
    real = os.fsync
    monkeypatch.setattr(receipts.os, "fsync", lambda fd: (calls.append(fd), real(fd))[1])
    append(rcfg, mk(target))
    assert len(calls) >= 1
    on_disk = open(rcfg.receipts, "rb").read()
    assert on_disk.endswith(b"\n") and len(on_disk) > 2


def test_append_creates_the_parent_folder(rcfg, target):
    assert not os.path.exists(os.path.dirname(rcfg.receipts))
    append(rcfg, mk(target))
    assert os.path.isfile(rcfg.receipts)


def test_append_returns_the_row(rcfg, target):
    row = mk(target)
    assert append(rcfg, row) == row


def test_append_fills_an_empty_clock_and_request_id(rcfg, target):
    out = append(rcfg, Row(act="pin", path=target, sha_after=A, verdict="DONE"))
    assert out.ts and out.ts.endswith("Z")
    assert out.request_id == request_id(target, out.ts)
    assert rows(rcfg) == [out]


def test_rows_of_a_missing_file_is_empty_and_chain_counts_zero(rcfg, target):
    assert rows(rcfg) == []
    assert rows(rcfg, target) == []
    assert verify_chain(rcfg, target) == 0


def test_rows_filters_by_path(rcfg, tmp_path):
    one = str(tmp_path / "root" / "one.py")
    two = str(tmp_path / "root" / "two.py")
    append(rcfg, mk(one, ts=TS1))
    append(rcfg, mk(two, ts=TS2))
    append(rcfg, mk(one, before=B, after=C, ts=TS3))
    assert len(rows(rcfg)) == 3
    assert [r.path for r in rows(rcfg, one)] == [one, one]
    assert [r.path for r in rows(rcfg, two)] == [two]
    assert verify_chain(rcfg, one) == 2
    assert verify_chain(rcfg, two) == 1
    assert verify_chain(rcfg) == 3


def test_rows_filter_ignores_a_redundant_path_spelling(rcfg, target):
    append(rcfg, mk(target))
    spelled = os.path.join(os.path.dirname(target), ".", os.path.basename(target))
    assert len(rows(rcfg, spelled)) == 1


def test_chains_of_different_paths_do_not_mix(rcfg, tmp_path):
    one = str(tmp_path / "root" / "one.py")
    two = str(tmp_path / "root" / "two.py")
    append(rcfg, mk(one, before=A, after=B, ts=TS1))
    append(rcfg, mk(two, before=C, after=D, ts=TS2))
    assert verify_chain(rcfg) == 2


def test_chain_follows_land_then_rollback_then_recover(rcfg, target):
    append(rcfg, mk(target, act="land", before=A, after=B, ts=TS1))
    append(rcfg, mk(target, act="rollback", before=B, after=A, ts=TS2))
    append(rcfg, mk(target, act="recover", before=A, after=A, ts=TS3))
    assert verify_chain(rcfg, target) == 3


def test_a_refused_land_that_left_the_bytes_alone_keeps_the_chain(rcfg, target):
    append(rcfg, mk(target, act="land", before=A, after=B, ts=TS1))
    append(rcfg, mk(target, act="land", before=B, after=B, verdict="REFUSED", ts=TS2,
                    why="REFUSED: an approval expired"))
    append(rcfg, mk(target, act="land", before=B, after=C, ts=TS3))
    assert verify_chain(rcfg, target) == 3


def test_rows_that_measured_no_result_are_skipped_by_the_chain(rcfg, target):
    append(rcfg, mk(target, act="land", before=A, after=B, ts=TS1))
    append(rcfg, mk(target, act="land", before=D, after="", verdict="REFUSED", ts=TS2,
                    why="REFUSED: the pin moved"))
    append(rcfg, mk(target, act="land", before=B, after=C, ts=TS3))
    assert verify_chain(rcfg, target) == 3


def test_rehearsal_and_dry_rows_never_break_the_chain(rcfg, target):
    append(rcfg, mk(target, act="land", before=A, after=B, ts=TS1))
    append(rcfg, mk(target, act="rehearse", before=D, after=D, verdict="WOULD-LAND", ts=TS2))
    append(rcfg, mk(target, act="land", before=D, after=D, verdict="WOULD-REFUSE", ts=TS2))
    append(rcfg, mk(target, act="approve", before=C, after=C, ts=TS2))
    append(rcfg, mk(target, act="land", before=B, after=C, ts=TS3))
    assert verify_chain(rcfg, target) == 5


def test_a_first_landing_may_start_from_any_digest(rcfg, target):
    append(rcfg, mk(target, before=D, after=A))
    assert verify_chain(rcfg, target) == 1


def test_row_json_round_trip(target):
    row = mk(target, elder=target + ".pre_land_x", why="all green", approval_id="0123456789abcdef")
    text = row.to_json()
    assert "\n" not in text
    assert json.loads(text) == {
        "ts": TS1, "request_id": row.request_id, "act": "land", "path": target,
        "sha_before": A, "sha_after": B, "verdict": "DONE", "why": "all green",
        "elder": target + ".pre_land_x", "approval_id": "0123456789abcdef",
    }
    assert Row.from_json(text) == row
    assert Row.from_json(json.loads(text)) == row


def test_row_from_json_defaults_the_optional_fields(target):
    text = json.dumps({"ts": TS1, "request_id": "r", "act": "pin", "path": target, "verdict": "DONE"})
    row = Row.from_json(text)
    assert (row.sha_before, row.sha_after, row.why, row.elder, row.approval_id) == ("", "", "", "", "")


def test_request_id_shape():
    assert request_id("/x/y/body.py", TS1) == "body.py-" + COMPACT1
    assert request_id("/x/y/body.py", BASE.isoformat()) == "body.py-" + COMPACT1


def test_now_ts_is_a_utc_clock_with_seconds():
    stamp = receipts.now_ts()
    assert len(stamp) == 20 and stamp.endswith("Z") and stamp[10] == "T"
    assert request_id("/x/body.py", stamp).startswith("body.py-")


def test_a_row_may_carry_a_why_with_newlines_and_quotes_and_stay_one_line(rcfg, target):
    row = mk(target, why='REFUSED: a "failing" test\nnamed /x/dep.py')
    append(rcfg, row)
    assert open(rcfg.receipts, "rb").read().count(b"\n") == 1
    assert rows(rcfg) == [row]


def test_many_appends_keep_every_row_whole(rcfg, target):
    sha = [format(i, "064x") for i in range(1, 26)]
    chain = [mk(target, before=sha[i], after=sha[i + 1], ts=TS1) for i in range(24)]
    for row in chain:
        append(rcfg, row)
    assert rows(rcfg) == chain
    assert verify_chain(rcfg, target) == 24

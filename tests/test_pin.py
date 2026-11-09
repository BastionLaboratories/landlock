"""Checks that the pin refuses what it must refuse, then that it records and confirms a file's bytes exactly.

PLAIN: These tests prove the pin turns away a missing file, a relative path, a file whose bytes changed and a damaged record, and then prove it records a file's bytes and confirms them again.

The refusals come first, each asserted by its exact "REFUSED: " prefix.
Every file the tests touch lives inside pytest's tmp_path.
"""

from __future__ import annotations

import hashlib
import json
import os
import pickle
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import pytest

_TREE = str(Path(__file__).resolve().parent.parent)
if _TREE not in sys.path:
    sys.path.insert(0, _TREE)

import landlock  # noqa: E402
from landlock.errors import Fault, Refused  # noqa: E402
from landlock.pin import Pin, check, pin, sha256_of  # noqa: E402

PREFIX = "REFUSED: "
SHA_A = "a" * 64


def refusal(callable_, *args):
    """Call it, insist it raises Refused with the house prefix, and return the sentence."""
    with pytest.raises(Refused) as caught:
        callable_(*args)
    why = caught.value.why
    assert why.startswith(PREFIX), why
    assert str(caught.value) == why
    return why


def make(tmp_path: Path, name: str = "target.txt", data: bytes = b"elder bytes\n") -> Path:
    path = tmp_path / name
    path.write_bytes(data)
    return path


def now_iso() -> str:
    """The clock read at run time, shaped as the contract's ISO-8601 UTC string."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def good_dict(tmp_path: Path) -> dict:
    return {
        "path": str(tmp_path / "file.txt"),
        "sha256": SHA_A,
        "size": 12,
        "mtime_ns": time.time_ns(),
        "pinned_at": now_iso(),
    }


# ---------------------------------------------------------------- must fail first


def test_pin_of_missing_file_refuses_not_found(tmp_path):
    why = refusal(pin, str(tmp_path / "absent.txt"))
    assert why.startswith("REFUSED: file not found")
    assert "absent.txt" in why


def test_sha256_of_missing_file_refuses_not_found(tmp_path):
    why = refusal(sha256_of, str(tmp_path / "absent.txt"))
    assert why.startswith("REFUSED: file not found")


def test_path_under_a_regular_file_refuses_not_found(tmp_path):
    target = make(tmp_path)
    why = refusal(pin, str(target / "below"))
    assert why.startswith("REFUSED: file not found")


def test_check_of_deleted_file_refuses_not_found(tmp_path):
    target = make(tmp_path)
    p = pin(str(target))
    target.unlink()
    why = refusal(check, p)
    assert why.startswith("REFUSED: file not found")
    assert str(target) in why


def test_check_after_bytes_moved_names_both_digests(tmp_path):
    target = make(tmp_path, data=b"before")
    p = pin(str(target))
    target.write_bytes(b"after!")  # same size, different bytes
    why = refusal(check, p)
    assert why.startswith("REFUSED: the bytes moved")
    assert p.sha256 in why
    assert hashlib.sha256(b"after!").hexdigest() in why
    assert str(target) in why


def test_check_after_file_grew_names_both_digests(tmp_path):
    target = make(tmp_path, data=b"short")
    p = pin(str(target))
    target.write_bytes(b"short and longer")
    why = refusal(check, p)
    assert p.sha256 in why
    assert hashlib.sha256(b"short and longer").hexdigest() in why


def test_check_after_file_emptied_refuses(tmp_path):
    target = make(tmp_path)
    p = pin(str(target))
    target.write_bytes(b"")
    why = refusal(check, p)
    assert hashlib.sha256(b"").hexdigest() in why


@pytest.mark.parametrize("relative", ["target.txt", "./target.txt", "sub/target.txt", "../target.txt"])
def test_pin_of_relative_path_refuses(relative):
    why = refusal(pin, relative)
    assert why.startswith("REFUSED: a path must be absolute")
    assert relative in why


def test_sha256_of_relative_path_refuses():
    why = refusal(sha256_of, "target.txt")
    assert why.startswith("REFUSED: a path must be absolute")


def test_relative_path_refuses_even_when_the_file_exists_here(tmp_path, monkeypatch):
    make(tmp_path)
    monkeypatch.chdir(tmp_path)
    refusal(pin, "target.txt")


def test_check_of_pin_with_relative_path_refuses():
    refusal(check, Pin("target.txt", SHA_A, 1, 1, now_iso()))


def test_empty_path_refuses():
    refusal(pin, "")


def test_path_with_a_nul_byte_refuses(tmp_path):
    refusal(pin, str(tmp_path) + os.sep + "with\0nul")


def test_path_of_wrong_type_refuses(tmp_path):
    target = make(tmp_path)
    for bad in (None, 7, os.fsencode(str(target)), [str(target)]):
        refusal(pin, bad)


def test_directory_refuses(tmp_path):
    why = refusal(pin, str(tmp_path))
    assert why.startswith("REFUSED: not a regular file")


def test_check_of_something_that_is_not_a_pin_refuses():
    why = refusal(check, "not a pin")
    assert why.startswith("REFUSED: check needs a Pin")


def test_from_json_invalid_text_refuses():
    why = refusal(Pin.from_json, "{not json")
    assert why.startswith("REFUSED: a pin must be valid JSON")


def test_from_json_wrong_type_refuses():
    refusal(Pin.from_json, 12)


@pytest.mark.parametrize("text", ["[]", "3", '"x"', "null"])
def test_from_json_not_an_object_refuses(text):
    why = refusal(Pin.from_json, text)
    assert "JSON object" in why


def test_from_json_missing_key_refuses_naming_it(tmp_path):
    data = good_dict(tmp_path)
    del data["size"]
    why = refusal(Pin.from_json, json.dumps(data))
    assert "size" in why


def test_from_json_extra_key_refuses_naming_it(tmp_path):
    data = good_dict(tmp_path)
    data["surprise"] = 1
    why = refusal(Pin.from_json, json.dumps(data))
    assert "surprise" in why


@pytest.mark.parametrize(
    "key,value",
    [
        ("path", "relative/path"),
        ("path", ""),
        ("path", 5),
        ("sha256", "A" * 64),  # uppercase is not the lowercase digest
        ("sha256", "a" * 63),
        ("sha256", "g" * 64),
        ("sha256", 12),
        ("size", -1),
        ("size", True),
        ("size", 1.5),
        ("size", "3"),
        ("mtime_ns", -1),
        ("mtime_ns", False),
        ("mtime_ns", "1"),
        ("pinned_at", ""),
        ("pinned_at", 20),
    ],
)
def test_from_json_bad_field_refuses(tmp_path, key, value):
    data = good_dict(tmp_path)
    data[key] = value
    refusal(Pin.from_json, json.dumps(data))
    refusal(Pin.from_dict, data)


def test_refused_and_fault_wear_their_prefix_and_stay_apart():
    r = Refused("no good")
    f = Fault("broke")
    assert r.why == "REFUSED: no good" and str(r) == "REFUSED: no good"
    assert f.why == "FAULT: broke" and str(f) == "FAULT: broke"
    assert not isinstance(f, Refused) and not isinstance(r, Fault)
    assert isinstance(r, Exception) and isinstance(f, Exception)


def test_prefix_is_never_doubled():
    assert Refused("REFUSED: already").why == "REFUSED: already"
    assert Fault("FAULT: already").why == "FAULT: already"
    assert Refused(Refused("x")).why == "REFUSED: x"


def test_errors_survive_pickling():
    for err in (Refused("a"), Fault("b")):
        back = pickle.loads(pickle.dumps(err))
        assert type(back) is type(err) and back.why == err.why


def test_unknown_package_name_is_an_attribute_error():
    with pytest.raises(AttributeError):
        landlock.no_such_name  # noqa: B018


# ---------------------------------------------------------------- the positive road


def test_sha256_matches_hashlib(tmp_path):
    target = make(tmp_path, data=b"abc")
    assert sha256_of(str(target)) == hashlib.sha256(b"abc").hexdigest()
    assert sha256_of(str(target)) == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"


def test_sha256_of_empty_file(tmp_path):
    target = make(tmp_path, data=b"")
    assert sha256_of(str(target)) == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


def test_sha256_of_file_larger_than_one_chunk(tmp_path):
    data = os.urandom(2 * 1024 * 1024 + 123)
    target = make(tmp_path, data=data)
    assert sha256_of(str(target)) == hashlib.sha256(data).hexdigest()
    assert pin(str(target)).size == len(data)


def test_pin_records_path_digest_size_mtime_and_clock(tmp_path):
    target = make(tmp_path, data=b"hello")
    p = pin(str(target))
    assert isinstance(p, Pin)
    assert p.path == str(target)
    assert p.sha256 == hashlib.sha256(b"hello").hexdigest()
    assert re.fullmatch(r"[0-9a-f]{64}", p.sha256)
    assert p.size == 5
    assert p.mtime_ns == target.stat().st_mtime_ns
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", p.pinned_at)


def test_pin_accepts_a_path_object(tmp_path):
    target = make(tmp_path)
    p = pin(target)
    assert p.path == str(target)
    assert sha256_of(target) == p.sha256


def test_pin_never_changes_the_file(tmp_path):
    target = make(tmp_path)
    before = (target.read_bytes(), target.stat().st_mtime_ns)
    check(pin(str(target)))
    assert (target.read_bytes(), target.stat().st_mtime_ns) == before


def test_pin_then_check_returns_an_equal_pin(tmp_path):
    target = make(tmp_path)
    p = pin(str(target))
    again = check(p)
    assert again == p
    assert again.to_json() == p.to_json()


def test_check_passes_when_the_same_bytes_are_rewritten(tmp_path):
    target = make(tmp_path, data=b"same")
    p = pin(str(target))
    target.write_bytes(b"same")
    later = p.mtime_ns + 5_000_000_000
    os.utime(target, ns=(later, later))
    assert check(p) == p


def test_two_pins_of_the_same_bytes_share_the_digest(tmp_path):
    one = make(tmp_path, "one.txt", b"twice")
    two = make(tmp_path, "two.txt", b"twice")
    assert pin(str(one)).sha256 == pin(str(two)).sha256


def test_to_json_round_trips(tmp_path):
    p = pin(str(make(tmp_path)))
    text = p.to_json()
    assert isinstance(text, str)
    assert json.loads(text) == p.to_dict()
    assert list(json.loads(text)) == sorted(json.loads(text))
    assert Pin.from_json(text) == p
    assert Pin.from_json(text).to_json() == text


def test_from_json_accepts_bytes_and_dict(tmp_path):
    p = pin(str(make(tmp_path)))
    assert Pin.from_json(p.to_json().encode()) == p
    assert Pin.from_json(p.to_dict()) == p
    assert Pin.from_dict(p.to_dict()) == p


def test_to_dict_has_exactly_the_contract_keys(tmp_path):
    p = pin(str(make(tmp_path)))
    assert set(p.to_dict()) == {"path", "sha256", "size", "mtime_ns", "pinned_at"}


def test_pin_is_frozen_and_hashable(tmp_path):
    p = pin(str(make(tmp_path)))
    with pytest.raises(Exception):
        p.sha256 = SHA_A  # type: ignore[misc]
    assert hash(p) == hash(Pin.from_json(p.to_json()))


def test_round_tripped_pin_still_checks(tmp_path):
    target = make(tmp_path)
    revived = Pin.from_json(pin(str(target)).to_json())
    assert check(revived) == revived
    target.write_bytes(b"moved")
    refusal(check, revived)


# ---------------------------------------------------------------- the package face


def test_version_is_the_contract_version():
    assert landlock.__version__ == "0.1.2"


def test_package_reexports_the_names_this_piece_owns():
    assert landlock.Refused is Refused
    assert landlock.Fault is Fault
    assert landlock.Pin is Pin
    assert landlock.sha256_of is sha256_of
    assert landlock.check is check


def test_package_names_are_all_listed():
    for name in ("Refused", "Fault", "Pin", "sha256_of", "check", "load_config", "verify", "rollback", "recover"):
        assert name in landlock.__all__
        assert name in dir(landlock)


@pytest.mark.parametrize("name", ["pin", "approve", "rehearse", "land"])
def test_same_named_functions_are_never_reexported(name):
    assert name not in landlock.__all__
    assert name not in landlock._LAZY
    # the attribute is the module (once imported) or absent, never a function
    attr = getattr(landlock, name, None)
    assert attr is None or isinstance(attr, type(sys))


@pytest.mark.parametrize("name", ["load_config", "verify", "rollback", "recover"])
def test_sibling_names_load_lazily_or_raise_import_error(name):
    try:
        value = getattr(landlock, name)
    except ImportError:
        return  # the sibling module is not cut yet: only use of the name fails
    assert callable(value)

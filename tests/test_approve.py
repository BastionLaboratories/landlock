"""Tests that signed approvals refuse a wrong secret file, a forged or expired record, or moved bytes.

Must-fail cases come first, each asserted by its exact "REFUSED: " prefix;
the positive road (approve, verify, round-trip through JSON) comes last.
Every file touched lives under pytest's tmp_path through the conftest
fixtures tmp_root, cfg and secret_file.
"""

from __future__ import annotations

import hashlib
import hmac
import importlib
import json
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest

from landlock.approve import Approval, approve, verify
from landlock.errors import Refused
from landlock.pin import pin

# The package binds the name "approve" to the function, so reach the module itself here.
approve_mod = importlib.import_module("landlock.approve")

_CFG_FIELDS = ("roots", "receipts", "secret", "tests", "dependents", "walls")


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _with(cfg, **changes):
    """A stand-in config carrying cfg's fields with some changed (no validation)."""
    fields = {name: getattr(cfg, name, None) for name in _CFG_FIELDS}
    fields.update(changes)
    return SimpleNamespace(**fields)


def _why(excinfo) -> str:
    err = excinfo.value
    return getattr(err, "why", None) or str(err)


@pytest.fixture
def env(cfg, secret_file, tmp_root):
    """A cfg whose secret file stands at 0600, a pinned target inside the root, and a candidate digest."""
    secret = Path(os.fspath(cfg.secret))
    if not secret.exists():
        cfg = _with(cfg, secret=os.fspath(secret_file))
        secret = Path(os.fspath(secret_file))
    assert (secret.stat().st_mode & 0o777) == 0o600
    target = Path(os.fspath(tmp_root)) / "body.txt"
    target.write_bytes(b"the old bytes\n")
    candidate = _sha(b"the new bytes\n")
    return SimpleNamespace(cfg=cfg, secret=secret, target=target, pin=pin(str(target)), candidate=candidate)


# ================================================================ must-fail first

@pytest.mark.parametrize("mode", [0o644, 0o640, 0o400, 0o700])
def test_secret_with_mode_other_than_0600_refuses_approve(env, mode):
    os.chmod(env.secret, mode)
    try:
        with pytest.raises(Refused) as e:
            approve(env.cfg, env.pin, env.candidate)
        assert _why(e).startswith("REFUSED: the secret file must have mode 0600, found ")
    finally:
        os.chmod(env.secret, 0o600)


def test_secret_with_mode_other_than_0600_refuses_verify(env):
    a = approve(env.cfg, env.pin, env.candidate)
    os.chmod(env.secret, 0o644)
    try:
        with pytest.raises(Refused) as e:
            verify(env.cfg, a, env.pin, env.candidate)
        assert _why(e).startswith("REFUSED: the secret file must have mode 0600, found 0644")
    finally:
        os.chmod(env.secret, 0o600)


def test_secret_inside_a_root_refuses(env, tmp_root):
    inside = Path(os.fspath(tmp_root)) / "secret.key"
    inside.write_bytes(b"k" * 32)
    os.chmod(inside, 0o600)
    cfg = _with(env.cfg, secret=str(inside))
    with pytest.raises(Refused) as e:
        approve(cfg, env.pin, env.candidate)
    assert _why(e).startswith("REFUSED: the secret file lies inside a root")


def test_secret_inside_a_root_refuses_verify(env, tmp_root):
    a = approve(env.cfg, env.pin, env.candidate)
    inside = Path(os.fspath(tmp_root)) / "secret.key"
    inside.write_bytes(env.secret.read_bytes())
    os.chmod(inside, 0o600)
    with pytest.raises(Refused) as e:
        verify(_with(env.cfg, secret=str(inside)), a, env.pin, env.candidate)
    assert _why(e).startswith("REFUSED: the secret file lies inside a root")


def test_missing_secret_refuses(env, tmp_path):
    cfg = _with(env.cfg, secret=str(tmp_path / "no_such_secret.key"))
    with pytest.raises(Refused) as e:
        approve(cfg, env.pin, env.candidate)
    assert _why(e).startswith("REFUSED: the secret file does not exist")


def test_empty_secret_refuses(env, tmp_path):
    empty = tmp_path / "empty_secret.key"
    empty.write_bytes(b"")
    os.chmod(empty, 0o600)
    with pytest.raises(Refused) as e:
        approve(_with(env.cfg, secret=str(empty)), env.pin, env.candidate)
    assert _why(e).startswith("REFUSED: the secret file is empty")


def test_relative_secret_path_refuses(env):
    with pytest.raises(Refused) as e:
        approve(_with(env.cfg, secret="secret.key"), env.pin, env.candidate)
    assert _why(e).startswith("REFUSED: the secret path in the config is not an absolute path")


def test_mac_does_not_verify_when_one_secret_byte_changes(env):
    a = approve(env.cfg, env.pin, env.candidate)
    data = bytearray(env.secret.read_bytes())
    data[0] ^= 0x01
    env.secret.write_bytes(bytes(data))
    assert (env.secret.stat().st_mode & 0o777) == 0o600
    with pytest.raises(Refused) as e:
        verify(env.cfg, a, env.pin, env.candidate)
    assert _why(e).startswith("REFUSED: the approval's signature does not verify under the secret file")


@pytest.mark.parametrize("field", ["target", "candidate_sha256", "pin_sha256", "issued_at", "expires_at", "mac"])
def test_any_altered_signed_field_refuses(env, field):
    a = approve(env.cfg, env.pin, env.candidate)
    record = a.to_dict()
    if field == "target":
        record[field] = record[field] + ".other"
    elif field in ("issued_at", "expires_at"):
        clock = datetime.fromisoformat(record[field]) + timedelta(seconds=1)
        record[field] = clock.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    else:
        record[field] = ("0" if record[field][0] != "0" else "1") + record[field][1:]
    forged = Approval.from_json(json.dumps(record))
    with pytest.raises(Refused) as e:
        verify(env.cfg, forged, env.pin, env.candidate)
    assert _why(e).startswith("REFUSED: the approval's signature does not verify under the secret file")


def test_altered_id_refuses(env):
    a = approve(env.cfg, env.pin, env.candidate)
    record = a.to_dict()
    record["id"] = ("0" if record["id"][0] != "0" else "1") + record["id"][1:]
    with pytest.raises(Refused) as e:
        verify(env.cfg, Approval.from_json(record), env.pin, env.candidate)
    assert _why(e).startswith("REFUSED: the approval id does not match its signed fields")


def test_expired_approval_refuses(env, monkeypatch):
    a = approve(env.cfg, env.pin, env.candidate, ttl_s=60)
    expires = datetime.fromisoformat(a.expires_at)
    monkeypatch.setattr(approve_mod, "_now", lambda: expires)
    with pytest.raises(Refused) as e:
        verify(env.cfg, a, env.pin, env.candidate)
    assert _why(e).startswith(f"REFUSED: the approval expired at {a.expires_at}")
    monkeypatch.setattr(approve_mod, "_now", lambda: expires + timedelta(days=3))
    with pytest.raises(Refused) as e:
        verify(env.cfg, a, env.pin, env.candidate)
    assert _why(e).startswith("REFUSED: the approval expired at ")


def test_approval_from_the_future_refuses(env, monkeypatch):
    a = approve(env.cfg, env.pin, env.candidate)
    issued = datetime.fromisoformat(a.issued_at)
    monkeypatch.setattr(approve_mod, "_now", lambda: issued - timedelta(hours=1))
    with pytest.raises(Refused) as e:
        verify(env.cfg, a, env.pin, env.candidate)
    assert _why(e).startswith("REFUSED: the approval was issued in the future")


def test_moved_bytes_under_the_approval_refuse(env):
    a = approve(env.cfg, env.pin, env.candidate)
    env.target.write_bytes(b"someone else's bytes\n")
    fresh = pin(str(env.target))
    assert fresh.sha256 != env.pin.sha256
    with pytest.raises(Refused) as e:
        verify(env.cfg, a, fresh, env.candidate)
    assert _why(e).startswith("REFUSED: the pinned bytes moved; the pin's sha256 differs from the approval's")


def test_candidate_mismatch_refuses(env):
    a = approve(env.cfg, env.pin, env.candidate)
    with pytest.raises(Refused) as e:
        verify(env.cfg, a, env.pin, _sha(b"different candidate bytes\n"))
    assert _why(e).startswith("REFUSED: the approval covers different candidate bytes")


def test_target_mismatch_refuses(env, tmp_root):
    a = approve(env.cfg, env.pin, env.candidate)
    other = Path(os.fspath(tmp_root)) / "other_body.txt"
    other.write_bytes(env.target.read_bytes())
    other_pin = pin(str(other))
    assert other_pin.sha256 == env.pin.sha256
    with pytest.raises(Refused) as e:
        verify(env.cfg, a, other_pin, env.candidate)
    assert _why(e).startswith("REFUSED: the approval names a different target than the pin")


def test_target_outside_every_root_refuses(env, tmp_path):
    outside_dir = tmp_path / "outside_every_root"
    outside_dir.mkdir()
    outside = outside_dir / "body.txt"
    outside.write_bytes(b"x\n")
    with pytest.raises(Refused) as e:
        approve(env.cfg, pin(str(outside)), env.candidate)
    assert _why(e).startswith("REFUSED: the target lies outside every root in the config")


@pytest.mark.parametrize("bad", ["", "ABC", "A" * 64, "g" * 64, "a" * 63, None])
def test_candidate_that_is_not_a_digest_refuses(env, bad):
    with pytest.raises(Refused) as e:
        approve(env.cfg, env.pin, bad)
    assert _why(e).startswith("REFUSED: the candidate sha256 is not a lowercase sha256 hex digest")


@pytest.mark.parametrize("ttl", [0, -5, 1.5, True, "60"])
def test_bad_lifetime_refuses(env, ttl):
    with pytest.raises(Refused) as e:
        approve(env.cfg, env.pin, env.candidate, ttl_s=ttl)
    assert _why(e).startswith("REFUSED: the approval lifetime must be ")


@pytest.mark.parametrize("text, prefix", [
    ("not json", "REFUSED: the approval record is not valid JSON"),
    ("[1, 2]", "REFUSED: the approval record is not a JSON object"),
    ("{}", "REFUSED: the approval record lacks the field(s) "),
])
def test_malformed_record_refuses(text, prefix):
    with pytest.raises(Refused) as e:
        Approval.from_json(text)
    assert _why(e).startswith(prefix)


def test_record_with_unknown_or_bad_fields_refuses(env):
    record = approve(env.cfg, env.pin, env.candidate).to_dict()
    with pytest.raises(Refused) as e:
        Approval.from_json(json.dumps({**record, "extra": "x"}))
    assert _why(e).startswith("REFUSED: the approval record carries unknown field(s) extra")
    with pytest.raises(Refused) as e:
        Approval.from_json(json.dumps({**record, "id": "short"}))
    assert _why(e).startswith("REFUSED: the approval id is not 16 lowercase hex characters")
    with pytest.raises(Refused) as e:
        Approval.from_json(json.dumps({**record, "target": "relative/body.txt"}))
    assert _why(e).startswith("REFUSED: the approval's target is not an absolute path")
    with pytest.raises(Refused) as e:
        Approval.from_json(json.dumps({**record, "expires_at": "tomorrow"}))
    assert _why(e).startswith("REFUSED: the approval's expires_at is not an ISO-8601 clock")
    with pytest.raises(Refused) as e:
        Approval.from_json(json.dumps({**record, "issued_at": record["issued_at"].rstrip("Z")}))
    assert _why(e).startswith("REFUSED: the approval's issued_at is not a UTC clock")


def test_unsigned_approval_refuses(env):
    record = approve(env.cfg, env.pin, env.candidate).to_dict()
    record["mac"] = "0" * 64
    with pytest.raises(Refused) as e:
        verify(env.cfg, Approval.from_json(record), env.pin, env.candidate)
    assert _why(e).startswith("REFUSED: the approval's signature does not verify under the secret file")


# ================================================================ the positive road

def test_approve_then_verify_returns_the_approval(env):
    a = approve(env.cfg, env.pin, env.candidate)
    assert isinstance(a, Approval)
    assert verify(env.cfg, a, env.pin, env.candidate) == a
    assert a.target == str(env.target)
    assert a.candidate_sha256 == env.candidate
    assert a.pin_sha256 == env.pin.sha256


def test_id_and_mac_follow_the_contract_formulas(env):
    a = approve(env.cfg, env.pin, env.candidate)
    assert a.id == hashlib.sha256((a.target + a.candidate_sha256 + a.issued_at).encode()).hexdigest()[:16]
    message = "landlock-v1\n" + a.target + "\n" + a.candidate_sha256 + "\n" + a.pin_sha256 + "\n" \
        + a.issued_at + "\n" + a.expires_at
    assert a.mac == hmac.new(env.secret.read_bytes(), message.encode(), hashlib.sha256).hexdigest()


def test_clocks_are_utc_seconds_and_lifetime_comes_from_walls(env):
    a = approve(env.cfg, env.pin, env.candidate)
    issued = datetime.fromisoformat(a.issued_at)
    expires = datetime.fromisoformat(a.expires_at)
    assert issued.utcoffset() == timedelta(0) and issued.microsecond == 0
    walls = env.cfg.walls
    ttl = walls.get("approval_ttl_s", 86400) if isinstance(walls, dict) else getattr(walls, "approval_ttl_s", 86400)
    assert (expires - issued) == timedelta(seconds=ttl)


def test_explicit_lifetime_is_honored(env, monkeypatch):
    a = approve(env.cfg, env.pin, env.candidate, ttl_s=120)
    issued = datetime.fromisoformat(a.issued_at)
    assert datetime.fromisoformat(a.expires_at) - issued == timedelta(seconds=120)
    monkeypatch.setattr(approve_mod, "_now", lambda: issued + timedelta(seconds=119))
    assert verify(env.cfg, a, env.pin, env.candidate) == a


def test_json_round_trip_still_verifies(env):
    a = approve(env.cfg, env.pin, env.candidate)
    text = a.to_json()
    assert set(json.loads(text)) == {"id", "target", "candidate_sha256", "pin_sha256", "issued_at", "expires_at", "mac"}
    back = Approval.from_json(text)
    assert back == a
    assert Approval.from_json(text.encode("utf-8")) == a
    assert verify(env.cfg, back, env.pin, env.candidate) == a


def test_round_trip_through_a_file_still_verifies(env, tmp_path):
    a = approve(env.cfg, env.pin, env.candidate)
    out = tmp_path / "candidate.approval.json"
    out.write_text(a.to_json(), encoding="utf-8")
    back = Approval.from_json(out.read_text(encoding="utf-8"))
    assert verify(env.cfg, back, env.pin, env.candidate) == a


def test_same_candidate_reapproved_later_gets_a_fresh_id(env, monkeypatch):
    first = approve(env.cfg, env.pin, env.candidate)
    later = datetime.fromisoformat(first.issued_at) + timedelta(seconds=5)
    monkeypatch.setattr(approve_mod, "_now", lambda: later)
    second = approve(env.cfg, env.pin, env.candidate)
    assert second.id != first.id and second.mac != first.mac
    assert verify(env.cfg, first, env.pin, env.candidate) == first
    assert verify(env.cfg, second, env.pin, env.candidate) == second

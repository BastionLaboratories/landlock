"""Checks that the settings file loader refuses every bad setting and reads a good one correctly."""

import json
import os

import pytest

from landlock.config import Config, inside_roots, load_config
from landlock.config import tests_for as get_tests

DEFAULT_ARGV = ["python3", "-c", "import sys; sys.exit(0)"]


def _s(value):
    """A TOML basic string (JSON strings are valid TOML for plain text)."""
    return json.dumps(value)


def _list(values):
    return "[" + ", ".join(_s(v) for v in values) + "]"


class Home:
    """A throwaway home under tmp_path: one root, with receipts and secret beside it."""

    def __init__(self, base):
        self.root = str(base / "root")
        self.side = str(base / "side")
        os.makedirs(self.root)
        os.makedirs(self.side)
        self.receipts = os.path.join(self.side, "receipts.jsonl")
        self.secret = os.path.join(self.side, "secret")
        self.toml_path = str(base / "landlock.toml")

    def target(self, name="core.py"):
        return os.path.join(self.root, name)

    def write(self, text):
        with open(self.toml_path, "w", encoding="utf-8") as handle:
            handle.write(text)
        return self.toml_path

    def toml(self, roots=None, receipts=None, secret=None, extra=""):
        roots = [self.root] if roots is None else roots
        receipts = self.receipts if receipts is None else receipts
        secret = self.secret if secret is None else secret
        head = f"roots = {_list(roots)}\nreceipts = {_s(receipts)}\nsecret = {_s(secret)}\n"
        return self.write(head + extra)


@pytest.fixture
def home(tmp_path):
    return Home(tmp_path)


def _refusal(call):
    """Run call, return the refusal's one-sentence why (fails the test if none)."""
    from landlock.errors import Refused

    with pytest.raises(Refused) as caught:
        call()
    return caught.value.why


# ---------------------------------------------------------------- must fail first


def test_relative_receipts_refuses(home):
    path = home.toml(receipts="receipts.jsonl")
    assert _refusal(lambda: load_config(path)).startswith("REFUSED: receipts must be an absolute path")


def test_relative_secret_refuses(home):
    path = home.toml(secret="secret")
    assert _refusal(lambda: load_config(path)).startswith("REFUSED: secret must be an absolute path")


def test_relative_root_refuses(home):
    path = home.toml(roots=["root"])
    assert _refusal(lambda: load_config(path)).startswith("REFUSED: a root must be an absolute path")


def test_relative_by_path_key_refuses(home):
    path = home.toml(extra=f"[tests]\ndefault = {_list(DEFAULT_ARGV)}\n[tests.by_path]\n\"core.py\" = {_list(DEFAULT_ARGV)}\n")
    assert _refusal(lambda: load_config(path)).startswith("REFUSED: a tests.by_path key must be an absolute path")


def test_relative_dependents_key_refuses(home):
    path = home.toml(extra=f"[dependents]\n\"core.py\" = {_list([home.target('api.py')])}\n")
    assert _refusal(lambda: load_config(path)).startswith("REFUSED: a dependents key must be an absolute path")


def test_relative_dependent_value_refuses(home):
    path = home.toml(extra=f"[dependents]\n{_s(home.target())} = [\"api.py\"]\n")
    assert _refusal(lambda: load_config(path)).startswith("REFUSED: a dependent must be an absolute path")


def test_root_that_is_not_a_directory_refuses(home, tmp_path):
    missing = str(tmp_path / "nowhere")
    path = home.toml(roots=[missing])
    assert _refusal(lambda: load_config(path)) == f"REFUSED: a root is not a directory: {missing}"


def test_root_that_is_a_file_refuses(home, tmp_path):
    plain = tmp_path / "plain.txt"
    plain.write_text("x", encoding="utf-8")
    path = home.toml(roots=[str(plain)])
    assert _refusal(lambda: load_config(path)).startswith("REFUSED: a root is not a directory: ")


def test_empty_roots_refuses(home):
    path = home.toml(roots=[])
    assert _refusal(lambda: load_config(path)).startswith("REFUSED: roots must be a non-empty list")


def test_receipts_inside_a_root_refuses(home):
    inside = os.path.join(home.root, "receipts.jsonl")
    path = home.toml(receipts=inside)
    assert _refusal(lambda: load_config(path)).startswith("REFUSED: receipts must live outside every root")


def test_secret_inside_a_root_refuses(home):
    inside = os.path.join(home.root, "deep", "secret")
    path = home.toml(secret=inside)
    assert _refusal(lambda: load_config(path)).startswith("REFUSED: secret must live outside every root")


def test_receipts_reaching_into_a_root_by_dotdot_refuses(home):
    sneaky = os.path.join(home.side, "..", "root", "receipts.jsonl")
    path = home.toml(receipts=sneaky)
    assert _refusal(lambda: load_config(path)).startswith("REFUSED: receipts must live outside every root")


def test_secret_reaching_into_a_root_by_a_link_refuses(home, tmp_path):
    link = tmp_path / "side" / "viaroot"
    os.symlink(home.root, link)
    path = home.toml(secret=str(link / "secret"))
    assert _refusal(lambda: load_config(path)).startswith("REFUSED: secret must live outside every root")


def test_dependents_key_outside_roots_refuses(home, tmp_path):
    outside = str(tmp_path / "side" / "other.py")
    path = home.toml(extra=f"[dependents]\n{_s(outside)} = {_list([home.target('api.py')])}\n")
    assert _refusal(lambda: load_config(path)) == f"REFUSED: a dependents key is outside the roots: {outside}"


def test_dependent_value_outside_roots_refuses(home, tmp_path):
    outside = str(tmp_path / "side" / "other.py")
    path = home.toml(extra=f"[dependents]\n{_s(home.target())} = {_list([outside])}\n")
    assert _refusal(lambda: load_config(path)) == f"REFUSED: a dependent is outside the roots: {outside}"


def test_by_path_key_outside_roots_refuses(home, tmp_path):
    outside = str(tmp_path / "side" / "other.py")
    path = home.toml(extra=f"[tests]\ndefault = {_list(DEFAULT_ARGV)}\n[tests.by_path]\n{_s(outside)} = {_list(DEFAULT_ARGV)}\n")
    assert _refusal(lambda: load_config(path)) == f"REFUSED: a tests.by_path key is outside the roots: {outside}"


def test_by_path_key_escaping_a_root_by_dotdot_refuses(home):
    sneaky = os.path.join(home.root, "..", "side", "x.py")
    path = home.toml(extra=f"[tests.by_path]\n{_s(sneaky)} = {_list(DEFAULT_ARGV)}\n")
    assert _refusal(lambda: load_config(path)).startswith("REFUSED: a tests.by_path key is outside the roots")


def test_missing_config_file_refuses(tmp_path):
    missing = str(tmp_path / "absent.toml")
    assert _refusal(lambda: load_config(missing)) == f"REFUSED: the config file does not exist: {missing}"


def test_directory_as_config_file_refuses(tmp_path):
    assert _refusal(lambda: load_config(str(tmp_path))).startswith("REFUSED: the config path is a directory")


def test_bad_toml_refuses(home):
    path = home.write("roots = [\n")
    assert _refusal(lambda: load_config(path)).startswith("REFUSED: the config file is not valid TOML")


def test_missing_required_key_refuses(home):
    path = home.write(f"roots = {_list([home.root])}\nreceipts = {_s(home.receipts)}\n")
    assert _refusal(lambda: load_config(path)) == "REFUSED: the config is missing the key: secret"


def test_unknown_top_key_refuses(home):
    path = home.toml(extra="colour = \"blue\"\n")
    assert _refusal(lambda: load_config(path)).startswith("REFUSED: unknown config key")


def test_unknown_wall_refuses(home):
    path = home.toml(extra="[walls]\nspeed = 3\n")
    assert _refusal(lambda: load_config(path)).startswith("REFUSED: unknown wall")


def test_wall_of_zero_refuses(home):
    path = home.toml(extra="[walls]\ntest_wall_s = 0\n")
    assert _refusal(lambda: load_config(path)).startswith("REFUSED: walls.test_wall_s must be a number above zero")


def test_wall_that_is_text_refuses(home):
    path = home.toml(extra="[walls]\nload_max = \"high\"\n")
    assert _refusal(lambda: load_config(path)).startswith("REFUSED: walls.load_max must be a number above zero")


def test_extra_dirs_relative_entry_refuses(home):
    path = home.toml(extra="[walls]\nrehearse_extra_dirs = [\"lib\"]\n")
    assert _refusal(lambda: load_config(path)).startswith("REFUSED: a walls.rehearse_extra_dirs entry must be an absolute path")


def test_extra_dirs_entry_outside_roots_refuses(home, tmp_path):
    outside = str(tmp_path / "side")
    path = home.toml(extra=f"[walls]\nrehearse_extra_dirs = {_list([outside])}\n")
    assert _refusal(lambda: load_config(path)) == f"REFUSED: a walls.rehearse_extra_dirs entry is outside the roots: {outside}"


def test_extra_dirs_entry_escaping_by_dotdot_refuses(home):
    sneaky = os.path.join(home.root, "..", "side")
    path = home.toml(extra=f"[walls]\nrehearse_extra_dirs = {_list([sneaky])}\n")
    assert _refusal(lambda: load_config(path)).startswith("REFUSED: a walls.rehearse_extra_dirs entry is outside the roots")


def test_extra_dirs_entry_that_is_a_file_refuses(home):
    plain = home.target("plain.txt")
    with open(plain, "w", encoding="utf-8") as handle:
        handle.write("x")
    path = home.toml(extra=f"[walls]\nrehearse_extra_dirs = {_list([plain])}\n")
    assert _refusal(lambda: load_config(path)) == f"REFUSED: a walls.rehearse_extra_dirs entry is not a directory: {plain}"


def test_extra_dirs_not_a_list_refuses(home):
    path = home.toml(extra=f"[walls]\nrehearse_extra_dirs = {_s(home.root)}\n")
    assert _refusal(lambda: load_config(path)) == "REFUSED: walls.rehearse_extra_dirs must be a list of folders"


def test_extra_dirs_entry_that_is_not_text_refuses(home):
    path = home.toml(extra="[walls]\nrehearse_extra_dirs = [4]\n")
    assert _refusal(lambda: load_config(path)).startswith("REFUSED: a walls.rehearse_extra_dirs entry must be a non-empty path string")


def test_other_walls_stay_numeric_when_a_list_is_given(home):
    path = home.toml(extra=f"[walls]\ntest_wall_s = {_list([home.root])}\n")
    assert _refusal(lambda: load_config(path)).startswith("REFUSED: walls.test_wall_s must be a number above zero")


def test_empty_argv_refuses(home):
    path = home.toml(extra=f"[tests.by_path]\n{_s(home.target())} = []\n")
    assert _refusal(lambda: load_config(path)).startswith("REFUSED: tests.by_path[")


def test_argv_with_a_non_string_refuses(home):
    path = home.toml(extra="[tests]\ndefault = [\"python3\", 4]\n")
    assert _refusal(lambda: load_config(path)).startswith("REFUSED: tests.default must hold only non-empty strings")


def test_unknown_tests_key_refuses(home):
    path = home.toml(extra="[tests]\nbogus = [\"x\"]\n")
    assert _refusal(lambda: load_config(path)).startswith("REFUSED: unknown key in tests")


def test_direct_construction_is_checked_too(home):
    with pytest.raises(Exception) as caught:
        Config(roots=[home.root], receipts="relative.jsonl", secret=home.secret)
    assert caught.value.why.startswith("REFUSED: receipts must be an absolute path")


def test_from_json_checks_what_it_reads(home):
    bad = json.dumps({"roots": [home.root], "receipts": os.path.join(home.root, "r"), "secret": home.secret})
    assert _refusal(lambda: Config.from_json(bad)).startswith("REFUSED: receipts must live outside every root")


def test_from_json_that_does_not_parse_refuses():
    assert _refusal(lambda: Config.from_json("{not json")).startswith("REFUSED: the config JSON does not parse")


def test_inside_roots_with_relative_path_refuses(home):
    cfg = load_config(home.toml())
    assert _refusal(lambda: inside_roots(cfg, "core.py")).startswith("REFUSED: path must be an absolute path")


def test_tests_for_with_relative_path_refuses(home):
    cfg = load_config(home.toml())
    assert _refusal(lambda: get_tests(cfg, "core.py")).startswith("REFUSED: path must be an absolute path")


def test_tests_for_outside_the_roots_refuses(home, tmp_path):
    cfg = load_config(home.toml(extra=f"[tests]\ndefault = {_list(DEFAULT_ARGV)}\n"))
    outside = str(tmp_path / "side" / "other.py")
    assert _refusal(lambda: get_tests(cfg, outside)) == f"REFUSED: path is outside every root: {outside}"


def test_tests_for_with_no_command_anywhere_refuses(home):
    cfg = load_config(home.toml())
    target = home.target()
    assert _refusal(lambda: get_tests(cfg, target)) == f"REFUSED: no test command is set for: {target}"


# ------------------------------------------------------------------ the positive road


def test_positive_road_by_path_wins_over_default(home):
    core = home.target("core.py")
    api = home.target("api.py")
    other = home.target("other.py")
    by_path_argv = ["python3", "-m", "pytest", "-q", "tests/test_core.py"]
    path = home.toml(
        extra=(
            f"[tests]\ndefault = {_list(DEFAULT_ARGV)}\n"
            f"[tests.by_path]\n{_s(core)} = {_list(by_path_argv)}\n"
            f"[dependents]\n{_s(core)} = {_list([api])}\n"
        )
    )
    cfg = load_config(path)
    assert cfg.roots == [home.root]
    assert cfg.receipts == home.receipts
    assert cfg.secret == home.secret
    assert cfg.dependents == {core: [api]}
    assert get_tests(cfg, core) == by_path_argv
    assert get_tests(cfg, api) == DEFAULT_ARGV
    assert get_tests(cfg, other) == DEFAULT_ARGV


def test_tests_for_returns_a_copy(home):
    cfg = load_config(home.toml(extra=f"[tests]\ndefault = {_list(DEFAULT_ARGV)}\n"))
    got = get_tests(cfg, home.target())
    got.append("--extra")
    assert get_tests(cfg, home.target()) == DEFAULT_ARGV


def test_by_path_matches_through_a_dotdot_spelling(home):
    core = home.target("core.py")
    argv = ["run-core-tests"]
    cfg = load_config(home.toml(extra=f"[tests]\ndefault = {_list(DEFAULT_ARGV)}\n[tests.by_path]\n{_s(core)} = {_list(argv)}\n"))
    spelled = os.path.join(home.root, "sub", "..", "core.py")
    assert get_tests(cfg, spelled) == argv


def test_wall_defaults(home):
    cfg = load_config(home.toml())
    assert cfg.walls == {"test_wall_s": 300, "load_max": 48.0, "approval_ttl_s": 86400, "rehearse_extra_dirs": []}
    assert isinstance(cfg.walls["load_max"], float)


def test_walls_can_be_overridden_one_at_a_time(home):
    cfg = load_config(home.toml(extra="[walls]\ntest_wall_s = 60\nload_max = 12\n"))
    assert cfg.walls == {"test_wall_s": 60, "load_max": 12.0, "approval_ttl_s": 86400, "rehearse_extra_dirs": []}


def test_extra_dirs_loads_existing_and_not_yet_existing_folders(home):
    lib = os.path.join(home.root, "lib")
    os.makedirs(lib)
    later = os.path.join(home.root, "later")
    cfg = load_config(home.toml(extra=f"[walls]\nrehearse_extra_dirs = {_list([lib, later])}\n"))
    assert cfg.walls["rehearse_extra_dirs"] == [lib, later]
    assert cfg.walls["test_wall_s"] == 300


def test_extra_dirs_survive_the_json_round_trip(home):
    lib = os.path.join(home.root, "lib")
    os.makedirs(lib)
    cfg = load_config(home.toml(extra=f"[walls]\nrehearse_extra_dirs = {_list([lib])}\n"))
    assert json.loads(cfg.to_json())["walls"]["rehearse_extra_dirs"] == [lib]
    assert cfg.to_dict()["walls"]["rehearse_extra_dirs"] == [lib]
    again = Config.from_json(cfg.to_json())
    assert again == cfg
    assert again.walls["rehearse_extra_dirs"] == [lib]
    assert Config.from_dict(cfg.to_dict()) == cfg


def test_to_dict_hands_out_a_copy_of_the_extra_dirs(home):
    lib = os.path.join(home.root, "lib")
    cfg = load_config(home.toml(extra=f"[walls]\nrehearse_extra_dirs = {_list([lib])}\n"))
    cfg.to_dict()["walls"]["rehearse_extra_dirs"].append("x")
    assert cfg.walls["rehearse_extra_dirs"] == [lib]


def test_a_config_with_only_the_three_paths_loads(home):
    cfg = load_config(home.toml())
    assert cfg.tests == {"default": [], "by_path": {}}
    assert cfg.dependents == {}


def test_inside_roots(home, tmp_path):
    cfg = load_config(home.toml())
    assert inside_roots(cfg, home.root) is True
    assert inside_roots(cfg, home.target()) is True
    assert inside_roots(cfg, os.path.join(home.root, "a", "b", "c.py")) is True
    assert inside_roots(cfg, home.receipts) is False
    assert inside_roots(cfg, str(tmp_path)) is False


def test_inside_roots_is_not_fooled_by_a_name_prefix(home, tmp_path):
    sibling = str(tmp_path / "root_but_not")
    os.makedirs(sibling)
    cfg = load_config(home.toml())
    assert inside_roots(cfg, os.path.join(sibling, "x.py")) is False


def test_inside_roots_is_not_fooled_by_dotdot(home):
    cfg = load_config(home.toml())
    assert inside_roots(cfg, os.path.join(home.root, "..", "side", "x.py")) is False


def test_inside_roots_follows_links_out_of_a_root(home):
    os.symlink(home.side, os.path.join(home.root, "exit"))
    cfg = load_config(home.toml())
    assert inside_roots(cfg, os.path.join(home.root, "exit", "x.py")) is False


def test_two_roots(home, tmp_path):
    second = str(tmp_path / "second")
    os.makedirs(second)
    cfg = load_config(home.toml(roots=[home.root, second]))
    assert inside_roots(cfg, os.path.join(second, "x.py")) is True
    assert inside_roots(cfg, home.target()) is True


def test_json_round_trip(home):
    core = home.target("core.py")
    api = home.target("api.py")
    cfg = load_config(
        home.toml(
            extra=(
                f"[tests]\ndefault = {_list(DEFAULT_ARGV)}\n"
                f"[tests.by_path]\n{_s(core)} = [\"one\", \"two\"]\n"
                f"[dependents]\n{_s(core)} = {_list([api])}\n"
                "[walls]\ntest_wall_s = 90\n"
            )
        )
    )
    text = cfg.to_json()
    assert isinstance(text, str)
    assert json.loads(text)["walls"]["test_wall_s"] == 90
    again = Config.from_json(text)
    assert again == cfg
    assert again.to_json() == text


def test_json_round_trip_of_a_bare_config(home):
    cfg = load_config(home.toml())
    assert Config.from_json(cfg.to_json()) == cfg


def test_direct_construction_fills_the_defaults(home):
    cfg = Config(roots=[home.root], receipts=home.receipts, secret=home.secret)
    assert cfg.walls == {"test_wall_s": 300, "load_max": 48.0, "approval_ttl_s": 86400, "rehearse_extra_dirs": []}
    assert cfg.tests == {"default": [], "by_path": {}}
    assert cfg.dependents == {}


def test_direct_construction_with_path_objects(home, tmp_path):
    cfg = Config(
        roots=[tmp_path / "root"],
        receipts=tmp_path / "side" / "receipts.jsonl",
        secret=tmp_path / "side" / "secret",
        tests={"default": DEFAULT_ARGV},
    )
    assert cfg.roots == [home.root]
    assert get_tests(cfg, home.target()) == DEFAULT_ARGV


def test_a_relative_config_file_path_is_allowed(home, tmp_path, monkeypatch):
    home.toml()
    monkeypatch.chdir(tmp_path)
    cfg = load_config("landlock.toml")
    assert cfg.roots == [home.root]


def test_the_loader_writes_nothing(home, tmp_path):
    path = home.toml()
    before = sorted(str(p) for p in tmp_path.rglob("*"))
    load_config(path)
    assert sorted(str(p) for p in tmp_path.rglob("*")) == before
    assert not os.path.exists(home.receipts)
    assert not os.path.exists(home.secret)

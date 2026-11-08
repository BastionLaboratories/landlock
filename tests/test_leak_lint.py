"""Tests for the word check that keeps a private list of names out of every file in a folder.

Must-fail cases come first: each refusal is observed and asserted by its exact
"REFUSED: " prefix, and every check asserts the planted word is never printed.
Then the positive road: a clean folder passes, binary files and the .git and
__pycache__ folders are skipped, paths given to --skip are left unread, and the
real list (when the LEAK_LINT_FORBIDDEN environment variable names it; the
comma-separated LEAK_LINT_SKIP names paths to leave unread) holds at least a
thousand rules and the check's own output carries none of them.
"""

import importlib.util
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

TOOL = Path(__file__).resolve().parent.parent / "tools" / "leak_lint.py"

# Made-up words that no real text holds.
TOKEN_WORD = "zorblaxquid"
SUBSTRING_WORD = "quuxfrobnitz"


def _load_tool():
    spec = importlib.util.spec_from_file_location("leak_lint_under_test", TOOL)
    module = importlib.util.module_from_spec(spec)
    keep = sys.dont_write_bytecode
    sys.dont_write_bytecode = True
    try:
        spec.loader.exec_module(module)
    finally:
        sys.dont_write_bytecode = keep
    return module


lint = _load_tool()


def _write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def _list_file(tmp_path: Path, body: str = None) -> Path:
    if body is None:
        body = (
            "# a comment line is ignored\n"
            "\n"
            f"token\t{TOKEN_WORD}\n"
            f"substring\t{SUBSTRING_WORD}\n"
        )
    return _write(tmp_path / "outside" / "forbidden.txt", body)


def _tree(tmp_path: Path) -> Path:
    root = tmp_path / "tree"
    _write(root / "pkg" / "module.py", '"""A clean module."""\n\nVALUE = 1\n')
    _write(root / "README.md", "A small tool.\n\nIt does one thing well.\n")
    return root


def _run(capsys, *argv):
    code = lint.main(list(argv))
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def _assert_word_never_printed(out: str, err: str) -> None:
    both = (out + err).lower()
    assert TOKEN_WORD not in both
    assert SUBSTRING_WORD not in both


# ---------------------------------------------------------------- must fail


def test_refuses_a_planted_token_and_names_file_and_line_without_the_word(tmp_path, capsys):
    root = _tree(tmp_path)
    _write(root / "pkg" / "notes.txt", "first\nsecond\nhello Zorblaxquid world\n")
    code, out, err = _run(capsys, "--forbidden", str(_list_file(tmp_path)), str(root))
    assert code == 2
    lines = out.splitlines()
    assert lines[0].startswith("REFUSED: ")
    assert "pkg/notes.txt:3" in lines[1:]
    _assert_word_never_printed(out, err)


def test_refuses_a_substring_rule_inside_a_longer_word(tmp_path, capsys):
    root = _tree(tmp_path)
    _write(root / "pkg" / "module.py", "x = 'preQUUXFROBNITZpost'\n")
    code, out, err = _run(capsys, "--forbidden", str(_list_file(tmp_path)), str(root))
    assert code == 2
    assert out.splitlines()[0].startswith("REFUSED: ")
    assert "pkg/module.py:1" in out.splitlines()
    _assert_word_never_printed(out, err)


def test_refuses_a_forbidden_word_in_a_file_name_and_withholds_it(tmp_path, capsys):
    root = _tree(tmp_path)
    _write(root / "pkg" / f"{TOKEN_WORD}.txt", "clean text\n")
    code, out, err = _run(capsys, "--forbidden", str(_list_file(tmp_path)), str(root))
    assert code == 2
    lines = out.splitlines()
    assert lines[0].startswith("REFUSED: ")
    assert "pkg/[withheld-1]:0" in lines[1:]
    _assert_word_never_printed(out, err)


def test_refuses_two_withheld_files_and_keeps_them_apart(tmp_path, capsys):
    root = _tree(tmp_path)
    _write(root / f"a-{TOKEN_WORD}.txt", f"{TOKEN_WORD}\n")
    _write(root / f"b-{TOKEN_WORD}.txt", f"{TOKEN_WORD}\n")
    code, out, err = _run(capsys, "--forbidden", str(_list_file(tmp_path)), str(root))
    assert code == 2
    lines = out.splitlines()
    assert lines[0].startswith("REFUSED: listed words stand on 4 lines in 2 files")
    assert lines[1:] == [
        "[withheld-1]:0", "[withheld-1]:1", "[withheld-2]:0", "[withheld-2]:1",
    ]
    _assert_word_never_printed(out, err)


def test_refuses_every_matching_line_once_each(tmp_path, capsys):
    root = _tree(tmp_path)
    _write(
        root / "a.txt",
        f"{TOKEN_WORD} and {SUBSTRING_WORD}\nclean\n{TOKEN_WORD}\n",
    )
    code, out, err = _run(capsys, "--forbidden", str(_list_file(tmp_path)), str(root))
    assert code == 2
    assert out.splitlines()[1:] == ["a.txt:1", "a.txt:3"]
    _assert_word_never_printed(out, err)


def test_refuses_a_list_that_lies_inside_the_tree(tmp_path, capsys):
    root = _tree(tmp_path)
    inside = _write(root / "forbidden.txt", f"token\t{TOKEN_WORD}\n")
    code, out, err = _run(capsys, "--forbidden", str(inside), str(root))
    assert code == 2
    assert out.splitlines()[0].startswith("REFUSED: the forbidden list lies inside the tree")
    _assert_word_never_printed(out, err)


def test_refuses_an_empty_list(tmp_path, capsys):
    root = _tree(tmp_path)
    empty = _list_file(tmp_path, "# nothing but a comment\n\n")
    code, out, err = _run(capsys, "--forbidden", str(empty), str(root))
    assert code == 2
    assert out.splitlines()[0].startswith("REFUSED: the forbidden list holds no rules")


def test_refuses_a_list_line_with_an_unknown_rule_kind(tmp_path, capsys):
    root = _tree(tmp_path)
    bad = _list_file(tmp_path, f"token\t{TOKEN_WORD}\nwhole\t{SUBSTRING_WORD}\n")
    code, out, err = _run(capsys, "--forbidden", str(bad), str(root))
    assert code == 2
    assert out.splitlines()[0].startswith("REFUSED: the forbidden list line 2 ")
    _assert_word_never_printed(out, err)


def test_refuses_a_leak_outside_the_skipped_paths(tmp_path, capsys):
    root = _tree(tmp_path)
    _write(root / "notes" / "a.txt", f"{TOKEN_WORD}\n")
    _write(root / "kept.md", f"{SUBSTRING_WORD}\n")
    code, out, err = _run(
        capsys, "--forbidden", str(_list_file(tmp_path)), "--skip", "notes", str(root)
    )
    assert code == 2
    assert out.splitlines()[0].startswith("REFUSED: ")
    assert out.splitlines()[1:] == ["kept.md:1"]
    _assert_word_never_printed(out, err)


def test_faults_when_the_list_is_missing(tmp_path, capsys):
    root = _tree(tmp_path)
    code, out, err = _run(capsys, "--forbidden", str(tmp_path / "absent.txt"), str(root))
    assert code == 3
    assert out.splitlines()[0].startswith("FAULT: ")


def test_faults_when_the_tree_does_not_exist(tmp_path, capsys):
    code, out, err = _run(
        capsys, "--forbidden", str(_list_file(tmp_path)), str(tmp_path / "no_such_tree")
    )
    assert code == 3
    assert out.splitlines()[0].startswith("FAULT: ")


def test_refuses_a_planted_token_in_a_single_file_given_as_the_tree(tmp_path, capsys):
    lone = _write(tmp_path / "work" / "setup.cfg", f"one\nname = {TOKEN_WORD}-tool\n")
    code, out, err = _run(capsys, "--forbidden", str(_list_file(tmp_path)), str(lone))
    assert code == 2
    assert out.splitlines()[0].startswith("REFUSED: ")
    assert out.splitlines()[1:] == ["setup.cfg:2"]
    _assert_word_never_printed(out, err)


def test_refuses_a_single_file_that_is_the_list_itself(tmp_path, capsys):
    listing = _list_file(tmp_path)
    code, out, err = _run(capsys, "--forbidden", str(listing), str(listing))
    assert code == 2
    assert out.splitlines()[0].startswith("REFUSED: the forbidden list lies inside the tree")
    _assert_word_never_printed(out, err)


def test_refuses_through_a_real_process_with_exit_two(tmp_path):
    root = _tree(tmp_path)
    _write(root / "deep" / "er" / "file.cfg", f"key = {TOKEN_WORD.upper()}\n")
    proc = subprocess.run(
        [sys.executable, "-B", str(TOOL), "--forbidden", str(_list_file(tmp_path)), str(root)],
        capture_output=True,
        text=True,
        stdin=subprocess.DEVNULL,
        timeout=60,
    )
    assert proc.returncode == 2
    assert proc.stdout.splitlines()[0].startswith("REFUSED: ")
    assert "deep/er/file.cfg:1" in proc.stdout.splitlines()
    _assert_word_never_printed(proc.stdout, proc.stderr)


# ---------------------------------------------------------------- positive road


def test_a_clean_tree_passes(tmp_path, capsys):
    root = _tree(tmp_path)
    code, out, err = _run(capsys, "--forbidden", str(_list_file(tmp_path)), str(root))
    assert code == 0
    assert out.splitlines()[0].startswith("CLEAN: ")


def test_a_clean_single_file_passes_as_a_tree_of_one(tmp_path, capsys):
    lone = _write(tmp_path / "work" / "LICENSE", "Free to use.\n")
    code, out, err = _run(capsys, "--forbidden", str(_list_file(tmp_path)), str(lone))
    assert code == 0
    assert out.splitlines()[0] == "CLEAN: no listed word in 1 text files (0 binary skipped)."


def test_a_token_rule_does_not_match_inside_a_longer_word(tmp_path, capsys):
    root = _tree(tmp_path)
    _write(root / "a.txt", f"{TOKEN_WORD}ity and pre{TOKEN_WORD}\n")
    code, out, err = _run(capsys, "--forbidden", str(_list_file(tmp_path)), str(root))
    assert code == 0


def test_a_token_rule_matches_between_punctuation(tmp_path, capsys):
    root = _tree(tmp_path)
    _write(root / "a.txt", f"path/{TOKEN_WORD}.json\n")
    code, out, err = _run(capsys, "--forbidden", str(_list_file(tmp_path)), str(root))
    assert code == 2
    assert out.splitlines()[1:] == ["a.txt:1"]


def test_a_many_part_token_rule_matches_only_whole(tmp_path, capsys):
    root = _tree(tmp_path)
    listing = _list_file(tmp_path, "token\tfrob-quax-17\n")
    _write(root / "a.txt", "see frob-quax-170 here\n")
    code, out, err = _run(capsys, "--forbidden", str(listing), str(root))
    assert code == 0
    _write(root / "b.txt", "see (frob-quax-17) here\n")
    code, out, err = _run(capsys, "--forbidden", str(listing), str(root))
    assert code == 2
    assert out.splitlines()[1:] == ["b.txt:1"]


def test_binary_files_and_git_and_bytecode_folders_are_skipped(tmp_path, capsys):
    root = _tree(tmp_path)
    (root / "blob.bin").write_bytes(b"\x00\x01" + TOKEN_WORD.encode() + b"\x00")
    _write(root / ".git" / "config", f"[user]\n\tname = {TOKEN_WORD}\n")
    _write(root / "pkg" / "__pycache__" / "module.txt", f"{SUBSTRING_WORD}\n")
    code, out, err = _run(capsys, "--forbidden", str(_list_file(tmp_path)), str(root))
    assert code == 0
    first = out.splitlines()[0]
    assert first.startswith("CLEAN: ")
    assert "1 binary" in first


def test_skipped_folders_and_files_are_not_read(tmp_path, capsys):
    root = _tree(tmp_path)
    _write(root / "notes" / "deep" / "a.txt", f"{TOKEN_WORD}\n")
    _write(root / "draft.md", f"{SUBSTRING_WORD}\n")
    code, out, err = _run(
        capsys,
        "--forbidden", str(_list_file(tmp_path)),
        "--skip", "notes", "--skip", "draft.md",
        str(root),
    )
    assert code == 0
    assert out.splitlines()[0].startswith("CLEAN: ")


def test_the_show_rule_flag_names_the_list_line_not_the_word(tmp_path, capsys):
    root = _tree(tmp_path)
    _write(root / "a.txt", f"{SUBSTRING_WORD}\n")
    code, out, err = _run(
        capsys, "--forbidden", str(_list_file(tmp_path)), "--show-rule", str(root)
    )
    assert code == 2
    assert out.splitlines()[1:] == ["a.txt:1 list:4"]
    _assert_word_never_printed(out, err)


def test_the_real_list_and_the_real_tree():
    """The positive road on the real tree: run only where the list is named."""
    listing = os.environ.get("LEAK_LINT_FORBIDDEN")
    if not listing:
        pytest.skip("LEAK_LINT_FORBIDDEN names no list on this machine")
    rules = lint.load_rules(Path(listing))
    assert len(rules) >= 1000
    tree = Path(__file__).resolve().parent.parent
    skips = []
    for name in os.environ.get("LEAK_LINT_SKIP", "").split(","):
        if name.strip():
            skips += ["--skip", name.strip()]
    proc = subprocess.run(
        [sys.executable, "-B", str(TOOL), "--forbidden", listing, *skips, str(tree)],
        capture_output=True,
        text=True,
        stdin=subprocess.DEVNULL,
        timeout=600,
    )
    assert proc.returncode in (0, 2)
    lines = proc.stdout.splitlines()
    assert lines[0].startswith("REFUSED: " if proc.returncode == 2 else "CLEAN: ")
    assert all(re.fullmatch(r".+:\d+", line) for line in lines[1:])
    matcher = lint.Matcher(rules)
    assert matcher.first_hit(proc.stdout + proc.stderr) is None

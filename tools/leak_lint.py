"""Check that no word from a private list of names appears in any file of a folder.

Usage:
    python3 tools/leak_lint.py --forbidden <list file outside the folder> <folder>
        [--show-rule] [--skip <path relative to the folder>]...

The list file holds one rule per line, "<kind>\\t<text>", where kind is
"token" (the text must stand whole, not inside a longer word) or "substring"
(the text may sit anywhere). Lines starting with "#" and blank lines are
ignored. Matching ignores letter case.

A single file may be given in place of the folder (a tree of one).
Every text file under the folder is read; binary files (a NUL byte in the
first 8 KiB) and anything under a ".git" or "__pycache__" folder are skipped.
File and folder names are checked too, reported as line 0. Symbolic links are
never followed; a link whose target text matches is reported as line 0.

The check never prints a listed word. A match is reported as "path:line",
with any part of the path that itself holds a listed word shown as
"[withheld-N]" (the same part keeps the same N within one run). With --show-rule the list's own line number is added as
"list:N", so the operator can look the word up privately.

The first printed line is the verdict:
    CLEAN: ...      exit 0
    REFUSED: ...    exit 2 (matches found, or a list that cannot be trusted)
    FAULT: ...      exit 3 (the list or the folder cannot be read)

This file is a helper for whoever publishes the folder; it ships no list.
"""

import argparse
import os
import re
import sys
from pathlib import Path

KINDS = ("token", "substring")
SKIP_DIRS = frozenset({".git", "__pycache__"})
SNIFF_BYTES = 8192
WITHHELD = "[withheld]"

_WORD = re.compile(r"\w+")


class LintRefused(Exception):
    """A refusal; .why is one sentence starting with "REFUSED: "."""

    def __init__(self, why: str):
        super().__init__(why)
        self.why = why


class LintFault(Exception):
    """A fault; .why is one sentence starting with "FAULT: "."""

    def __init__(self, why: str):
        super().__init__(why)
        self.why = why


class Rule:
    """One rule from the list: its kind, its lowered text, its line in the list."""

    __slots__ = ("kind", "text", "lineno")

    def __init__(self, kind: str, text: str, lineno: int):
        self.kind = kind
        self.text = text
        self.lineno = lineno


def load_rules(path: Path) -> list:
    """Read the list file into rules; refuse a list that is empty or malformed."""
    try:
        raw = Path(path).read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        raise LintFault("FAULT: the forbidden list cannot be read.") from None
    rules = []
    for lineno, line in enumerate(raw.splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        kind, sep, text = line.partition("\t")
        kind = kind.strip()
        text = text.strip().lower()
        if not sep or kind not in KINDS:
            raise LintRefused(
                f"REFUSED: the forbidden list line {lineno} names no known rule kind "
                "(token or substring, then a tab)."
            )
        if not text:
            raise LintRefused(f"REFUSED: the forbidden list line {lineno} holds no text.")
        rules.append(Rule(kind, text, lineno))
    if not rules:
        raise LintRefused("REFUSED: the forbidden list holds no rules.")
    return rules


class Matcher:
    """Finds listed words in text, fast enough for tens of thousands of rules."""

    def __init__(self, rules):
        self._substrings = []
        self._by_first_word = {}
        self._odd_tokens = []
        for rule in rules:
            if rule.kind == "substring":
                self._substrings.append(rule)
                continue
            head = _WORD.match(rule.text)
            if head is None:
                self._odd_tokens.append((rule, self._odd_pattern(rule.text)))
            else:
                self._by_first_word.setdefault(head.group(), []).append(rule)

    @staticmethod
    def _odd_pattern(text: str):
        left = r"(?<!\w)" if _WORD.match(text[0]) else ""
        right = r"(?!\w)" if _WORD.match(text[-1]) else ""
        return re.compile(left + re.escape(text) + right)

    def hits(self, text: str) -> list:
        """Return the list line numbers of every rule found in text (sorted, unique)."""
        low = text.lower()
        found = set()
        for rule in self._substrings:
            if rule.text in low:
                found.add(rule.lineno)
        if self._by_first_word:
            for word in _WORD.finditer(low):
                candidates = self._by_first_word.get(word.group())
                if not candidates:
                    continue
                start = word.start()
                for rule in candidates:
                    if not low.startswith(rule.text, start):
                        continue
                    end = start + len(rule.text)
                    if end < len(low) and _WORD.match(rule.text[-1]) and _WORD.match(low[end]):
                        continue
                    found.add(rule.lineno)
        for rule, pattern in self._odd_tokens:
            if pattern.search(low):
                found.add(rule.lineno)
        return sorted(found)

    def first_hit(self, text: str):
        """Return the first list line number found in text, or None."""
        hits = self.hits(text)
        return hits[0] if hits else None


class _Masker:
    """Shows a path with every part that holds a listed word as a numbered mask."""

    def __init__(self, matcher: Matcher):
        self._matcher = matcher
        self._numbers = {}

    def show(self, rel_parts) -> str:
        shown = []
        for part in rel_parts:
            if self._matcher.hits(part):
                number = self._numbers.setdefault(part, len(self._numbers) + 1)
                shown.append(f"{WITHHELD[:-1]}-{number}]")
            else:
                shown.append(part)
        return "/".join(shown)


def _read_text(path: Path):
    """Return the file's text, or None when the file looks binary."""
    data = path.read_bytes()
    if b"\x00" in data[:SNIFF_BYTES]:
        return None
    return data.decode("utf-8", errors="replace")


def scan(tree: Path, matcher: Matcher, skip=()):
    """Walk the folder; return (findings, text files read, binary files skipped).

    skip holds paths relative to the folder ("docs", "notes/draft.md") left unread.
    findings is a sorted list of (path parts, line number, list line numbers).
    """
    skipped = {Path(s).as_posix().strip("/") for s in skip}
    findings = []
    counts = {"read": 0, "binary": 0}
    if not tree.is_dir():
        _check_entry(tree, (tree.name,), False, matcher, findings, counts)
        return _merged(findings), counts["read"], counts["binary"]
    for dirpath, dirnames, filenames in os.walk(tree, followlinks=False):
        here = Path(dirpath)
        rel_dir = here.relative_to(tree).parts
        dirnames[:] = sorted(
            d for d in dirnames
            if d not in SKIP_DIRS and "/".join(rel_dir + (d,)) not in skipped
        )
        names = [
            f for f in sorted(filenames) if "/".join(rel_dir + (f,)) not in skipped
        ] + list(dirnames)
        for name in names:
            _check_entry(
                here / name, rel_dir + (name,), name in dirnames, matcher, findings, counts
            )
    return _merged(findings), counts["read"], counts["binary"]


def _check_entry(path: Path, rel, is_dir: bool, matcher: Matcher, findings, counts) -> None:
    """Check one entry's name, its link target if a link, and its lines if a text file."""
    shown = tuple(rel)
    name_hits = matcher.hits(rel[-1])
    if name_hits:
        findings.append((shown, 0, name_hits))
    if path.is_symlink():
        link_hits = matcher.hits(os.readlink(path))
        if link_hits:
            findings.append((shown, 0, link_hits))
        return
    if is_dir:
        return
    text = _read_text(path)
    if text is None:
        counts["binary"] += 1
        return
    counts["read"] += 1
    for lineno, line in enumerate(text.splitlines(), start=1):
        line_hits = matcher.hits(line)
        if line_hits:
            findings.append((shown, lineno, line_hits))


def _merged(findings):
    """Sort findings and fold several hits on one line into one entry."""
    findings.sort(key=lambda f: (f[0], f[1]))
    merged = []
    for shown, lineno, line_hits in findings:
        if merged and merged[-1][0] == shown and merged[-1][1] == lineno:
            merged[-1] = (shown, lineno, sorted(set(merged[-1][2]) | set(line_hits)))
        else:
            merged.append((shown, lineno, line_hits))
    return merged


def _inside(child: Path, parent: Path) -> bool:
    try:
        child.relative_to(parent)
    except ValueError:
        return False
    return True


def run(forbidden: Path, tree: Path, show_rule: bool = False, skip=()):
    """Do the whole check; return (exit code, printed lines)."""
    tree = Path(tree).resolve()
    forbidden = Path(forbidden).resolve()
    if not (tree.is_dir() or tree.is_file()):
        raise LintFault("FAULT: the tree is neither a folder nor a file that can be read.")
    if forbidden == tree or _inside(forbidden, tree):
        raise LintRefused("REFUSED: the forbidden list lies inside the tree it checks.")
    matcher = Matcher(load_rules(forbidden))
    findings, read, binary = scan(tree, matcher, skip)
    if not findings:
        return 0, [f"CLEAN: no listed word in {read} text files ({binary} binary skipped)."]
    files = len({rel for rel, _, _ in findings})
    lines = [
        f"REFUSED: listed words stand on {len(findings)} lines in {files} files "
        f"of the tree ({read} text files read)."
    ]
    masker = _Masker(matcher)
    for rel, lineno, line_hits in findings:
        shown = masker.show(rel)
        if show_rule:
            lines.append(f"{shown}:{lineno} " + ",".join(f"list:{n}" for n in line_hits))
        else:
            lines.append(f"{shown}:{lineno}")
    return 2, lines


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="leak_lint",
        description="Check that no word from a private list appears in a folder.",
    )
    parser.add_argument("--forbidden", required=True, help="the list file, outside the folder")
    parser.add_argument(
        "--show-rule", action="store_true", help="add the list line number to each match"
    )
    parser.add_argument(
        "--skip",
        action="append",
        default=[],
        help="a path relative to the folder to leave unread (repeatable)",
    )
    parser.add_argument("tree", help="the folder to check")
    args = parser.parse_args(argv)
    try:
        code, lines = run(Path(args.forbidden), Path(args.tree), args.show_rule, args.skip)
    except LintRefused as exc:
        print(exc.why)
        return 2
    except LintFault as exc:
        print(exc.why)
        return 3
    except Exception as exc:  # never echo the text: it may hold a listed word
        print(f"FAULT: the check stopped on an unexpected {type(exc).__name__}.")
        return 3
    for line in lines:
        print(line)
    return code


if __name__ == "__main__":
    sys.exit(main())

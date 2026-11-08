#!/usr/bin/env python3
# Vendored from promptguard/scripts/utils/check_no_dashes.py. Edit it there and copy it here.

"""Fail when a tracked text file contains an em dash (U+2014) or en dash (U+2013).

The rule: no em or en dashes in code, comments, docs, commit messages or UI
copy. Use a comma, colon, parentheses, a full stop, or a plain hyphen for a
range (1-3).

    python3 scripts/check_no_dashes.py --check

EXEMPT is per repo: only code or data that must contain the character
literally (a detector corpus, a recorded fixture, a regex over external text).
Inside code, prefer a `\\u2014` escape, and the file needs no exemption.
"""

from __future__ import annotations

import argparse
import fnmatch
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DASHES = {"\u2014": "em dash (U+2014)", "\u2013": "en dash (U+2013)"}

# Each entry: a path or fnmatch glob, relative to the repo root.
EXEMPT: dict[str, str] = {}


def tracked_files(root: Path) -> list[str]:
    out = subprocess.run(
        ["git", "-C", str(root), "ls-files", "-z"], capture_output=True, check=True
    ).stdout
    return [p for p in out.decode("utf-8", "surrogateescape").split("\0") if p]


def exempt(rel: str) -> bool:
    return any(rel == pat or fnmatch.fnmatch(rel, pat) for pat in EXEMPT)


def violations(root: Path) -> list[str]:
    found: list[str] = []
    for rel in tracked_files(root):
        if exempt(rel):
            continue
        path = root / rel
        if path.is_symlink() or not path.is_file():
            continue
        data = path.read_bytes()
        if b"\0" in data[:8192]:
            continue
        text = data.decode("utf-8", "replace")
        if not any(d in text for d in DASHES):
            continue
        for lineno, line in enumerate(text.splitlines(), 1):
            for col, ch in enumerate(line, 1):
                if ch in DASHES:
                    found.append(f"{rel}:{lineno}:{col}: {DASHES[ch]}")
    return found


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true", help="exit 1 on any violation")
    parser.add_argument("--root", type=Path, default=ROOT)
    args = parser.parse_args()

    found = violations(args.root)
    for line in found:
        print(line)
    if found:
        print(
            f"\n{len(found)} em/en dash(es). Replace each with a comma, colon, "
            "parentheses, a full stop, or a plain hyphen for a range. In code that "
            "must match the character, write the \\u2014 / \\u2013 escape instead. "
            "Only data that must hold it literally gets an EXEMPT entry in "
            "scripts/check_no_dashes.py, with its reason.",
            file=sys.stderr,
        )
        return 1 if args.check else 0
    print("check_no_dashes: no em or en dashes outside the exemptions")
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
# Vendored from promptguard/scripts/utils/check_agent_files.py. Edit it there and copy it here.

"""Fail when an agent instruction file is broken, bloated, or not loaded.

Agent files are every tracked `AGENTS.md` and `CLAUDE.md`, plus `docs/agents/**/*.md`.
An agent reads them as true, so a dead link, a placeholder or a file the agent
never loads costs a session silently. Four checks:

1. Every relative Markdown link resolves, including a `#heading` anchor into a
   Markdown file.
2. No placeholder is left behind: `TODO`, `TBD`, `FIXME`, `{{...}}`, an empty
   link target, or an ALL-CAPS token standing in for a link such as
   `(ARCHIVE_LIST_URL)`.
3. The root agent file stays within the line budget (default 200, the size
   Claude Code's memory docs give for a file loaded on every turn).
4. Every directory with an `AGENTS.md` has a `CLAUDE.md` that is a symlink to it
   (or to the same file) or imports it with an `@AGENTS.md` line. Claude Code
   loads `CLAUDE.md`, not `AGENTS.md`, so without one the rules never reach a
   Claude session.


    python3 scripts/check_agent_files.py --check
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
import unicodedata
from pathlib import Path

DEFAULT_MAX_LINES = 200

LINK = re.compile(r"(?<!!)\[[^\]]*\]\(([^)\s]*)(?:\s+\"[^\"]*\")?\)")
FENCE = re.compile(r"^\s*(```|~~~)")
INLINE_CODE = re.compile(r"`[^`]*`")
PLACEHOLDERS = [
    (re.compile(r"\b(TODO|TBD|FIXME)\b"), "a TODO/TBD/FIXME marker"),
    (re.compile(r"\{\{[^}]*\}\}"), "a {{template}} placeholder"),
    (re.compile(r"\]\(\s*\)"), "an empty link target"),
    (re.compile(r"\(([A-Z][A-Z0-9]*_)+(URL|LINK|PATH|HREF)\)"), "an ALL-CAPS link placeholder"),
]


def git_root(start: Path) -> Path:
    out = subprocess.run(
        ["git", "-C", str(start), "rev-parse", "--show-toplevel"],
        capture_output=True,
        text=True,
        check=True,
    )
    return Path(out.stdout.strip())


def tracked(root: Path) -> list[str]:
    out = subprocess.run(
        ["git", "-C", str(root), "ls-files", "-z"], capture_output=True, check=True
    ).stdout
    return [p for p in out.decode("utf-8", "surrogateescape").split("\0") if p]


def agent_files(files: list[str]) -> list[str]:
    picked = []
    for rel in files:
        name = rel.rsplit("/", 1)[-1]
        if name in ("AGENTS.md", "CLAUDE.md") or (
            rel.startswith("docs/agents/") and rel.endswith(".md")
        ):
            if "node_modules/" not in rel:
                picked.append(rel)
    return picked


def slug(heading: str) -> str:
    """GitHub's anchor for a heading."""
    text = re.sub(r"<[^>]+>", "", heading).strip().lower()
    text = INLINE_CODE.sub(lambda m: m.group(0).strip("`"), text)
    text = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", text)
    out = []
    for ch in text:
        if ch in (" ", "-"):
            out.append("-")
        elif ch == "_" or ch.isalnum() or unicodedata.category(ch).startswith("L"):
            out.append(ch)
    return "".join(out)


def anchors(path: Path) -> set[str]:
    seen: dict[str, int] = {}
    result: set[str] = set()
    in_fence = False
    for line in path.read_text("utf-8", "replace").splitlines():
        if FENCE.match(line):
            in_fence = not in_fence
            continue
        if in_fence:
            continue
        m = re.match(r"^#{1,6}\s+(.*?)\s*#*\s*$", line)
        if not m:
            continue
        base = slug(m.group(1))
        n = seen.get(base, 0)
        seen[base] = n + 1
        result.add(base if n == 0 else f"{base}-{n}")
    return result


def prose_lines(text: str) -> list[tuple[int, str]]:
    """Lines outside fenced code, with inline code removed."""
    lines = []
    in_fence = False
    for i, line in enumerate(text.splitlines(), 1):
        if FENCE.match(line):
            in_fence = not in_fence
            continue
        if not in_fence:
            lines.append((i, INLINE_CODE.sub("``", line)))
    return lines


def check_links(root: Path, rel: str, errors: list[str]) -> None:
    path = root / rel
    real = path.resolve()
    text = path.read_text("utf-8", "replace")
    for lineno, line in prose_lines(text):
        for target in LINK.findall(line):
            if not target or re.match(r"^[a-z][a-z0-9+.-]*:", target, re.I):
                continue  # empty targets are reported as placeholders; URLs are not ours
            file_part, _, anchor = target.partition("#")
            dest = real if not file_part else (real.parent / file_part).resolve()
            if not dest.exists():
                errors.append(
                    f"{rel}:{lineno}: link target `{file_part}` does not exist "
                    f"(resolved against {real.parent.relative_to(root.resolve())}/). "
                    "Point it at the file's current path, or drop the link."
                )
                continue
            if anchor and dest.is_file() and dest.suffix == ".md" and anchor not in anchors(dest):
                errors.append(
                    f"{rel}:{lineno}: `{file_part or rel}` has no heading for `#{anchor}`. "
                    "Link to a heading that exists, or rename the heading back."
                )


def check_placeholders(root: Path, rel: str, errors: list[str]) -> None:
    text = (root / rel).read_text("utf-8", "replace")
    for lineno, line in prose_lines(text):
        for pattern, what in PLACEHOLDERS:
            m = pattern.search(line)
            if m:
                errors.append(
                    f"{rel}:{lineno}: {what} left in an agent file ({m.group(0)!r}). "
                    "An agent reads it as fact: fill it in or delete the line."
                )


def check_budget(root: Path, max_lines: int, errors: list[str]) -> None:
    path = root / "AGENTS.md"
    if not path.exists():
        return
    n = len(path.read_text("utf-8", "replace").splitlines())
    if n > max_lines:
        shown = path.resolve().relative_to(root.resolve())
        errors.append(
            f"{shown}: {n} lines, over the {max_lines}-line budget for a file loaded on "
            "every turn. Move what only some tasks need into a doc behind a "
            "'Read ... when ...' pointer."
        )


def check_claude_md(root: Path, files: list[str], errors: list[str]) -> None:
    agents_md = [rel for rel in files if rel.rsplit("/", 1)[-1] == "AGENTS.md"]
    # An AGENTS.md that another one symlinks to (the monorepo's `.ai/AGENTS.md`)
    # is loaded through that symlink's directory, which is checked instead.
    targets = {(root / rel).resolve() for rel in agents_md if (root / rel).is_symlink()}
    dirs = {
        os.path.dirname(rel)
        for rel in agents_md
        if (root / rel).is_symlink() or (root / rel).resolve() not in targets
    }
    for d in sorted(dirs):
        agents = root / d / "AGENTS.md"
        claude = root / d / "CLAUDE.md"
        shown = os.path.join(d, "CLAUDE.md") if d else "CLAUDE.md"
        fix = (
            f"Fix: `ln -s AGENTS.md {shown}` (or a CLAUDE.md whose only "
            "instruction line is `@AGENTS.md`)."
        )
        if not claude.exists() and not claude.is_symlink():
            errors.append(
                f"{shown}: missing. Claude Code loads CLAUDE.md, not AGENTS.md, so "
                f"{os.path.join(d, 'AGENTS.md') if d else 'AGENTS.md'} never reaches it. {fix}"
            )
        elif claude.is_symlink():
            if not claude.exists() or claude.resolve() != agents.resolve():
                errors.append(f"{shown}: symlink does not resolve to AGENTS.md. {fix}")
        elif not re.search(r"(?m)^@AGENTS\.md\s*$", claude.read_text("utf-8", "replace")):
            errors.append(
                f"{shown}: a regular file that does not import AGENTS.md, so the two drift. {fix}"
            )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true", help="exit 1 on any problem")
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--max-lines", type=int, default=DEFAULT_MAX_LINES)
    args = parser.parse_args()

    root = git_root(args.root)
    files = tracked(root)
    picked = agent_files(files)
    errors: list[str] = []
    seen: set[Path] = set()
    for rel in picked:
        real = (root / rel).resolve()
        if real.exists() and real not in seen:
            seen.add(real)
            check_links(root, rel, errors)
            check_placeholders(root, rel, errors)
    check_budget(root, args.max_lines, errors)
    check_claude_md(root, files, errors)

    for e in errors:
        print(e)
    if errors:
        print(f"\ncheck_agent_files: {len(errors)} problem(s) in agent files", file=sys.stderr)
        return 1 if args.check else 0
    print(f"check_agent_files: {len(picked)} agent files OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())

"""Prose style gate: no new em dash or en dash in what a person reads.

The owner writes and reads this project in ASD-STE100 Simplified Technical
English. A dash of that kind marks an aside, and STE has no asides. Older
files still carry some. ``tests/prose_style_baseline.json`` records those
counts per file. This test fails when a file gains a dash. It also fails when
a file loses one and the baseline did not move down, so the count only goes
down. Run ``python tests/test_prose_style.py --write-baseline`` after a
deliberate cleanup.

Scope: the markdown docs, the two example config files, the console source
outside comments and tests, and the string constants in the backend outside
docstrings. Code comments keep the repository's voice.
"""

from __future__ import annotations

import ast
import json
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
BASELINE_PATH = REPO_ROOT / "tests" / "prose_style_baseline.json"
DASHES = re.compile("[—–]")

PROSE_FILES = ("README.md", "CONTRIBUTING.md", "CHANGELOG.md", ".env.example", "setup.conf.example")
PROSE_GLOBS = ("docs/**/*.md",)
FRONTEND_GLOB = "frontend/src/**/*.ts*"
BACKEND_GLOB = "soc_ai/**/*.py"
COMMENT_STARTS = ("//", "*", "/*", "{/*")


def _prose_count(path: Path) -> int:
    return len(DASHES.findall(path.read_text(encoding="utf-8")))


def _frontend_count(path: Path) -> int:
    total = 0
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.lstrip().startswith(COMMENT_STARTS):
            continue
        total += len(DASHES.findall(line))
    return total


def _docstring_ids(tree: ast.AST) -> set[int]:
    ids: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Module | ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef):
            body = node.body
            first = body[0].value if body and isinstance(body[0], ast.Expr) else None
            if isinstance(first, ast.Constant) and isinstance(first.value, str):
                ids.add(id(first))
    return ids


def _backend_count(path: Path) -> int:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    skip = _docstring_ids(tree)
    total = 0
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str) and id(node) not in skip:
            total += len(DASHES.findall(node.value))
    return total


def scan() -> dict[str, int]:
    """Dash counts per file, keyed by the repository-relative path."""
    counts: dict[str, int] = {}
    files = [REPO_ROOT / name for name in PROSE_FILES]
    for pattern in PROSE_GLOBS:
        files.extend(REPO_ROOT.glob(pattern))
    for path in files:
        if path.is_file():
            counts[path.relative_to(REPO_ROOT).as_posix()] = _prose_count(path)
    for path in REPO_ROOT.glob(FRONTEND_GLOB):
        if path.is_file() and ".test." not in path.name and path.suffix in {".ts", ".tsx"}:
            counts[path.relative_to(REPO_ROOT).as_posix()] = _frontend_count(path)
    for path in REPO_ROOT.glob(BACKEND_GLOB):
        if path.is_file():
            counts[path.relative_to(REPO_ROOT).as_posix()] = _backend_count(path)
    return counts


def test_no_prose_surface_gains_a_dash() -> None:
    baseline: dict[str, int] = json.loads(BASELINE_PATH.read_text(encoding="utf-8"))
    counts = scan()
    gained = {p: (baseline.get(p, 0), n) for p, n in counts.items() if n > baseline.get(p, 0)}
    assert not gained, (
        "These files gained an em dash or an en dash. STE has no asides. Use a period or a comma.\n"
        + "\n".join(f"  {p}: {was} -> {now}" for p, (was, now) in sorted(gained.items()))
    )
    stale = {
        p: (baseline[p], counts[p]) for p in counts if p in baseline and counts[p] < baseline[p]
    }
    assert not stale, (
        "These files lost dashes. Lower the baseline so the count cannot climb back: "
        "python tests/test_prose_style.py --write-baseline\n"
        + "\n".join(f"  {p}: {was} -> {now}" for p, (was, now) in sorted(stale.items()))
    )


def test_baseline_names_only_files_that_carry_a_dash() -> None:
    baseline: dict[str, int] = json.loads(BASELINE_PATH.read_text(encoding="utf-8"))
    zero = sorted(p for p, n in baseline.items() if n <= 0)
    assert not zero, f"baseline entries at zero are noise; drop them: {zero}"


if __name__ == "__main__":
    if "--write-baseline" in sys.argv:
        data = {p: n for p, n in sorted(scan().items()) if n > 0}
        BASELINE_PATH.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
        print(f"wrote {len(data)} entries to {BASELINE_PATH}")
    else:
        for p, n in sorted(scan().items()):
            if n:
                print(n, p)

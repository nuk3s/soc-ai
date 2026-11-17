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


# The owner retired one word on 2026-11-14: "Never use the word estate." It
# must leave every text that an analyst, an operator or the model reads. The
# whole set of machines is "the network". A machine or an address is internal
# or external. The target is zero, so this check has no baseline.
#
# Scope: the published docs (the publish allowlist of
# scripts/build-public-mirror.sh, README, CONTRIBUTING), the Unreleased
# section of the changelog, the two example config files, the analytic
# catalog that the model and the analyst read, the demo fixture file, the
# console source outside comments and tests, and the backend string literals.
# Out of scope: docs/dev and docs/superpowers (internal notes), the released
# changelog sections and docs/releases (published history), and code comments.
# An identifier keeps its name: a setting key, a module, a column, the
# `soc-ai estate-model` command, the analytic id and the model directory.
RETIRED_WORD = re.compile(r"(?<![\w/-])estates?(?![\w])", re.IGNORECASE)
CODE_SPAN = re.compile(r"`[^`\n]*`")
MIRROR_SCRIPT = REPO_ROOT / "scripts" / "build-public-mirror.sh"
RETIRED_WORD_FILES = ("README.md", "CONTRIBUTING.md", ".env.example", "setup.conf.example")
RETIRED_WORD_GLOBS = ("soc_ai/hunting/catalog/*.yaml", "soc_ai/demo/fixtures.json")


def _public_docs() -> list[Path]:
    """The top-level docs that the publish allowlist ships."""
    if not MIRROR_SCRIPT.exists():
        # The public tree does not ship the publish tooling. Every top-level
        # doc in that tree passed the allowlist, so each one is in scope.
        return sorted((REPO_ROOT / "docs").glob("*.md"))
    match = re.search(r'^PUBLIC_DOCS="([^"]+)"', MIRROR_SCRIPT.read_text(encoding="utf-8"), re.M)
    assert match, "scripts/build-public-mirror.sh lost its PUBLIC_DOCS line"
    return [REPO_ROOT / "docs" / f"{name}.md" for name in match.group(1).split()]


def _unreleased(changelog: str) -> str:
    """The Unreleased section of the changelog. A released section is history."""
    start = changelog.index("## [Unreleased]")
    end = changelog.find("\n## [", start + 1)
    return changelog[start : end if end != -1 else len(changelog)]


def _retired_hits(text: str) -> list[str]:
    """Each line of ``text`` that holds the retired word outside a code span."""
    return [
        line.strip()[:120]
        for line in text.splitlines()
        if RETIRED_WORD.search(CODE_SPAN.sub("", line))
    ]


def _frontend_prose(text: str) -> str:
    """The console lines outside comments. A block comment and a JSX comment
    can run over several lines, so the scan tracks them."""
    out: list[str] = []
    in_block = False
    for line in text.splitlines():
        stripped = line.lstrip()
        if in_block:
            in_block = "*/" not in line
            continue
        if stripped.startswith(("/*", "{/*")):
            in_block = "*/" not in stripped
            continue
        if stripped.startswith(COMMENT_STARTS):
            continue
        out.append(re.sub(r"(^|\s)//.*$", "", line))
    return "\n".join(out)


def _backend_strings(path: Path) -> list[str]:
    """The string literals of one backend file that a person or the model can
    read: no docstring, no bare string statement, no identifier."""
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    skip = _docstring_ids(tree)
    for node in ast.walk(tree):
        if isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant):
            skip.add(id(node.value))
    return [
        node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and id(node) not in skip
        and re.search(r"\s", node.value.strip())
    ]


def retired_word_hits() -> list[str]:
    """Every readable line that holds the retired word, as ``path: text``."""
    hits: list[str] = []
    prose = [REPO_ROOT / name for name in RETIRED_WORD_FILES] + _public_docs()
    for pattern in RETIRED_WORD_GLOBS:
        prose.extend(sorted(REPO_ROOT.glob(pattern)))
    for path in prose:
        if path.is_file():
            rel = path.relative_to(REPO_ROOT).as_posix()
            hits += [f"{rel}: {h}" for h in _retired_hits(path.read_text(encoding="utf-8"))]
    changelog = (REPO_ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    hits += [f"CHANGELOG.md [Unreleased]: {h}" for h in _retired_hits(_unreleased(changelog))]
    for path in sorted(REPO_ROOT.glob(FRONTEND_GLOB)):
        if path.is_file() and ".test." not in path.name and path.suffix in {".ts", ".tsx"}:
            rel = path.relative_to(REPO_ROOT).as_posix()
            text = _frontend_prose(path.read_text(encoding="utf-8"))
            hits += [f"{rel}: {h}" for h in _retired_hits(text)]
    for path in sorted(REPO_ROOT.glob(BACKEND_GLOB)):
        if path.is_file():
            rel = path.relative_to(REPO_ROOT).as_posix()
            for value in _backend_strings(path):
                hits += [f"{rel}: {h}" for h in _retired_hits(value)]
    return hits


def test_no_readable_text_holds_the_retired_word() -> None:
    hits = retired_word_hits()
    assert not hits, (
        'The owner retired the word "estate" (2026-11-14). Say "the network" for the whole '
        "set, and internal or external for a machine or an address.\n"
        + "\n".join(f"  {h}" for h in hits)
    )


def test_the_retired_word_check_reads_each_scope() -> None:
    """NEGATIVE CONTROL. Each scope must catch a plant, and each identifier
    form must pass. A scope that read nothing would pass the gate above."""
    word = "est" + "ate"
    assert _retired_hits(f"A change to the {word} causes it.")
    assert _retired_hits(f"{word.capitalize()}-rare below this many hosts")
    assert _retired_hits(f"### {word.capitalize()} prevalence")
    assert _retired_hits(f"the {word}s of the design")
    for identifier in (
        f"`{word}_model_enabled`",
        f"{word}_model_enabled",
        f"soc_ai.hunting.{word}_model",
        f"<data dir>/models/{word}/",
        f"model-{word}-outlier",
        f"`soc-ai {word}-model show` prints the fit.",
        f"SOC_AI_{word.upper()}_MODEL_ENABLED",
        "The finding restates the verdict.",
    ):
        assert not _retired_hits(identifier), identifier
    console = _frontend_prose(
        "\n".join(
            [
                f"// the {word} in a line comment",
                f"/** the {word}",
                " *  in a doc comment */",
                f"{{/* the {word}",
                "     in a JSX comment */}",
                f"const a = 'the {word} in a string'; // the {word} after code",
                f"const b = 'http://example.test/{word}';",
            ]
        )
    )
    assert _retired_hits(console) == [f"const a = 'the {word} in a string';"]
    assert _public_docs(), "the publish allowlist names no doc"
    assert "## [Unreleased]" in _unreleased("## [Unreleased]\nx\n## [1.0.0]\ny")
    assert "y" not in _unreleased("## [Unreleased]\nx\n## [1.0.0]\ny")


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

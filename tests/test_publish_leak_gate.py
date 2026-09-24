"""Leak gate for the WHOLE publishable tree, run on every suite instead of at publish.

The hard gate in ``scripts/build-public-mirror.sh`` already refuses to build a
public tree containing a lab identifier. It just ran too late to be useful: it
fires when someone publishes, so a real internal subnet committed in a test
fixture sits on ``main`` until the next release. That is exactly what happened:
a lab address reached ``main`` in the oracle-client tests and another in the
quality-spine tests, survived two merges, and was caught only when 1.4.0 was
staged for GitHub.

This module runs the same scan, over the same pattern set, at pytest time. The
patterns come from the mirror script through :func:`leak_patterns`, the publish
gate's single source of truth, so the two can never drift.

Scope is every file that WOULD ship, tracked or merely staged-to-be: the
exclusion list is parsed from ``scripts/public-mirror-exclude.txt``, so a path
exempted for the publisher is exempted here too and there is one place to change.
Untracked-but-not-ignored files count, because the first version of this module
listed only tracked files and therefore could not see itself before it was
committed. It shipped a lab address in its own docstring on the first try.

Like ``test_demo_leak_gate``, this skips on a public clone, where the pattern
source does not exist. Needles in this file are assembled from fragments so the
file itself passes the scan it enforces.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
EXCLUDE_FILE = REPO / "scripts/public-mirror-exclude.txt"

pytestmark = pytest.mark.skipif(
    not (REPO / "scripts/build-public-mirror.sh").exists(),
    reason="mirror build script not in this tree (public clone) — no leak-pattern source",
)

from scripts.demo.build_fixtures import leak_patterns  # noqa: E402

# Binary and generated paths the mirror scan skips via `grep -I`, plus the
# lockfile (upstream package names, not our identifiers).
_UNSCANNED_SUFFIXES = frozenset(
    {".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2", ".pdf", ".mmdb"}
)


def _excluded_paths() -> tuple[list[str], list[str]]:
    """(directory prefixes, exact file paths) excluded from the public mirror."""
    dirs: list[str] = []
    files: list[str] = []
    for raw in EXCLUDE_FILE.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        (dirs if line.endswith("/") else files).append(line)
    return dirs, files


def _publishable_files() -> list[str]:
    """Every path that would ship, minus the mirror exclusions.

    ``--cached --others --exclude-standard`` is tracked files PLUS untracked
    ones git is not ignoring, i.e. everything a ``git add -A`` would sweep in.
    Listing only tracked files leaves a new file invisible to this gate until
    after it is committed, which is one commit too late.
    """
    try:
        tracked = subprocess.run(
            ["git", "-C", str(REPO), "ls-files", "--cached", "--others", "--exclude-standard"],
            capture_output=True,
            text=True,
            check=True,
        ).stdout.splitlines()
    except FileNotFoundError:
        # Fail, never skip: a gate that quietly stands down when its tool is
        # missing is the false all-clear it exists to prevent. The CI image
        # lacked git for a run of pipelines and this was the only symptom.
        pytest.fail("git is not installed, so the leak gate cannot enumerate the tree")
    dirs, files = _excluded_paths()
    excluded_files = set(files)
    return [
        path
        for path in tracked
        if path not in excluded_files
        and not any(path.startswith(d) for d in dirs)
        and Path(path).suffix not in _UNSCANNED_SUFFIXES
    ]


def test_exclusion_list_is_readable_and_nonempty():
    """A silently-empty exclusion list would make every other test here vacuous."""
    dirs, files = _excluded_paths()
    assert dirs, "no directory exclusions parsed from public-mirror-exclude.txt"
    assert files, "no file exclusions parsed from public-mirror-exclude.txt"
    assert "docs/dev/" in dirs


def test_the_scan_actually_catches_a_planted_identifier():
    """Negative control: prove the pattern set is live before trusting a clean result."""
    needle = ".".join(["10", "9", "8", "253"])
    assert any(re.search(p, needle) for p in leak_patterns()), (
        "the lab-subnet pattern no longer matches a lab address — the gate is dead"
    )
    assert any(re.search(p, "x" + ".".join(["home", "lan"])) for p in leak_patterns())


def test_no_lab_identifier_reaches_the_publishable_tree():
    """The gate itself. Every shipping file, every mirror pattern."""
    patterns = [re.compile(p) for p in leak_patterns()]
    assert len(patterns) >= 8, "suspiciously few patterns parsed from the mirror script"

    hits: list[str] = []
    for rel in _publishable_files():
        try:
            text = (REPO / rel).read_text(encoding="utf-8")
        except (UnicodeDecodeError, FileNotFoundError, IsADirectoryError):
            continue
        for line_no, line in enumerate(text.splitlines(), start=1):
            for pattern in patterns:
                if pattern.search(line):
                    hits.append(f"{rel}:{line_no} matches /{pattern.pattern}/")
                    break

    assert not hits, (
        "lab/identity strings found in files that would be published to GitHub.\n"
        "Scrub them, or add the path to scripts/public-mirror-exclude.txt:\n  "
        + "\n  ".join(hits[:40])
        + (f"\n  ... and {len(hits) - 40} more" if len(hits) > 40 else "")
    )

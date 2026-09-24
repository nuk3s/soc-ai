"""scripts/release-notes.sh: the GitHub Release body for one version.

The release workflow failed on v1.5.0 because the CHANGELOG section it used
as the body was 189,000 characters and GitHub caps a body at 125,000. The
script now prefers the release note under docs/releases/, rewrites the note's
relative links (the Release page cannot resolve them), and cuts a long body
at a line boundary. Each path here is a case that cost a release run.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

_SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "release-notes.sh"

_CHANGELOG = """# Changelog

## [2.0.0] - 2026-10-01

Two-oh.

## [1.9.0] - 2026-09-01

One-nine, line one.
One-nine, line two.

## [1.8.0] - 2026-08-01

One-eight.
"""


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    """A tree with the layout the script resolves from its own location."""
    (tmp_path / "scripts").mkdir()
    shutil.copy(_SCRIPT, tmp_path / "scripts" / "release-notes.sh")
    (tmp_path / "docs" / "releases").mkdir(parents=True)
    (tmp_path / "CHANGELOG.md").write_text(_CHANGELOG)
    return tmp_path


def _body(repo: Path, *args: str, limit: int | None = None) -> str:
    env = {"GITHUB_REPOSITORY": "acme/soc-ai", "PATH": "/usr/bin:/bin"}
    if limit is not None:
        env["RELEASE_BODY_LIMIT"] = str(limit)
    done = subprocess.run(
        ["bash", str(repo / "scripts" / "release-notes.sh"), *args],
        capture_output=True,
        text=True,
        env=env,
        check=True,
    )
    return done.stdout


def test_the_release_note_wins_and_reads_as_a_release_page(repo: Path) -> None:
    (repo / "docs" / "releases" / "1.9.0.md").write_text(
        "# soc-ai 1.9.0\n\nThe note.\n\n"
        "![flow](../img/flow.svg)\n\nRead [the guide](../HUNTING.md).\n"
    )

    body = _body(repo, "1.9.0", "v1.9.0")

    assert body.startswith("The note."), body
    assert "# soc-ai 1.9.0" not in body
    assert "One-nine" not in body
    assert "![flow](https://raw.githubusercontent.com/acme/soc-ai/v1.9.0/docs/img/flow.svg)" in body
    assert "[the guide](https://github.com/acme/soc-ai/blob/v1.9.0/docs/HUNTING.md)" in body
    assert "../" not in body


def test_without_a_note_the_changelog_section_is_the_body(repo: Path) -> None:
    body = _body(repo, "1.9.0")

    assert "One-nine, line one." in body
    assert "One-nine, line two." in body
    assert "Two-oh" not in body
    assert "One-eight" not in body


def test_a_long_body_is_cut_on_a_line_with_a_pointer_at_the_full_file(repo: Path) -> None:
    (repo / "docs" / "releases" / "1.9.0.md").write_text(
        "# soc-ai 1.9.0\n\n" + "".join(f"line {i:04d} of the note\n" for i in range(400))
    )

    body = _body(repo, "1.9.0", limit=2000)

    lines = body.splitlines()
    assert len(body) < 2000 + 200
    assert lines[-1].startswith("_Cut for length.")
    assert "https://github.com/acme/soc-ai/blob/v1.9.0/CHANGELOG.md" in lines[-1]
    # Cut on a line boundary: every kept note line is whole.
    kept = [ln for ln in lines if ln.startswith("line ")]
    assert kept and all(ln.endswith("of the note") for ln in kept)


def test_an_unknown_version_still_yields_a_body(repo: Path) -> None:
    assert _body(repo, "3.3.3").strip() == "Release v3.3.3. See CHANGELOG.md."

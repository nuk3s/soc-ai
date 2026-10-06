"""The ``ml`` extra: declared, installed by the image, and read by the audits.

Decision 3 of the four-tier design allows scikit-learn and numpy under four
conditions. The fourth is that the image carries them and the dependency audit
covers them. A package the image ships and the audit skips is an advisory
surface nobody reads.
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


def test_the_extra_declares_scikit_learn_and_numpy_with_a_capped_major() -> None:
    pyproject = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    extra = pyproject["project"]["optional-dependencies"]["ml"]
    by_name = {re.split(r"[<>=!~ ]", dep, maxsplit=1)[0]: dep for dep in extra}
    assert set(by_name) == {"scikit-learn", "numpy"}
    # A fresh resolve must not cross a major with no diff in this file.
    assert "<2" in by_name["scikit-learn"]
    assert "<3" in by_name["numpy"]


def test_the_lock_resolves_the_extra() -> None:
    lock = tomllib.loads((REPO_ROOT / "uv.lock").read_text(encoding="utf-8"))
    names = {pkg["name"] for pkg in lock["package"]}
    assert {"scikit-learn", "numpy", "scipy", "joblib", "threadpoolctl"} <= names
    project = next(pkg for pkg in lock["package"] if pkg["name"] == "soc-ai")
    assert "ml" in project["optional-dependencies"]


def test_the_image_and_both_audits_carry_the_extra() -> None:
    dockerfile = (REPO_ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert re.search(r"^RUN uv sync --frozen .*--extra ml", dockerfile, re.M)
    ci = (REPO_ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    assert "--no-dev --extra postgres --extra ml" in ci
    publish = (REPO_ROOT / "scripts" / "github-update.sh").read_text(encoding="utf-8")
    assert "--extra postgres --extra ml" in publish


def test_mypy_treats_the_extra_as_untyped_when_it_is_absent() -> None:
    """A checkout without the extra must still type-check the estate model."""
    pyproject = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    overrides = pyproject["tool"]["mypy"]["overrides"]
    ignored = {m for o in overrides if o.get("ignore_missing_imports") for m in o["module"]}
    assert {"sklearn.*", "numpy", "numpy.*", "scipy.*"} <= ignored

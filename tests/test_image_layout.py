"""The deployed layout, not the repository, decides what the app can read.

Every other test in this suite runs from a checkout, where ``docs/``,
``runbooks/`` and ``frontend/dist`` all sit beside the package. The container
is a different tree: the Dockerfile copies a hand-written list of sources into
``/opt/soc-ai``, and anything not on that list is simply absent. A prompt asset
resolved as parent-of-package therefore has two answers, and the repository's
answer is the one that never fails.

That gap shipped: ``docs/OQL_PRIMER.md`` was read at prompt-build time and
never copied, so every investigator, hunt and chat prompt in the container
carried a 971-byte stub saying the query language was unavailable, while
``test_oql_primer_markers_present_on_disk`` went on passing against the
checkout.

So these tests replay the Dockerfile's own COPY directives into a scratch
directory and import the package from THERE, in a subprocess, with that
directory as the only entry on ``PYTHONPATH``. Replay means real copies, never
symlinks: ``Path(__file__).resolve()`` follows a symlink straight back to the
checkout, which would hand the repository's answer back under a container's
name. The probe returns the resolved root so a test can prove which tree it
actually read.

Hermetic: no Docker daemon, no network, no build. Reading the Dockerfile is
the point, because deleting the COPY line is what has to fail.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from fnmatch import fnmatch
from pathlib import Path
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]

# Where the runtime stage puts the application. Destinations are rewritten
# relative to this so the replay tree mirrors the container's /opt/soc-ai.
IMAGE_APP_DIR = "/opt/soc-ai"

# Build caches that are never a runtime asset. The .dockerignore entries below
# are path-anchored the way Docker reads them (``__pycache__/`` excludes the
# context root's, not one nested under soc_ai/), so drop these everywhere
# instead. Erring toward copying LESS than the image is safe here: a test that
# under-copies can only fail, never pass on a broken layout.
_ALWAYS_IGNORED = ("__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache", "*.pyc")

# Run in the replayed tree, printing one JSON object. `_REPO_ROOT` comes back
# so the caller can prove the import came from the copy and not the checkout.
_PROBE = """\
import json
from soc_ai.agent import prompts

primer = prompts._load_oql_primer()
print(json.dumps({
    "resolved_root": str(prompts._REPO_ROOT),
    "declared": [a.name for a in prompts.PROMPT_ASSETS],
    "missing": [a.name for a in prompts.missing_prompt_assets()],
    "primer_len": len(primer),
    "stub": "Primer file missing on disk" in primer,
    "hunt_len": len(prompts._load_oql_primer("hunt")),
}))
"""


# ── Dockerfile replay ────────────────────────────────────────────────────────


def _dockerfile_lines() -> list[str]:
    """Dockerfile lines with backslash continuations joined."""
    text = (REPO_ROOT / "Dockerfile").read_text(encoding="utf-8")
    joined: list[str] = []
    buffer = ""
    for raw in text.splitlines():
        line = raw.rstrip()
        if line.endswith("\\"):
            buffer += line[:-1].strip() + " "
            continue
        joined.append((buffer + line.strip()).strip())
        buffer = ""
    if buffer:
        joined.append(buffer.strip())
    return joined


def _runtime_copy_directives() -> list[tuple[list[str], str]]:
    """``(sources, destination)`` for every COPY the RUNTIME stage takes from
    the build context.

    Scoped to the ``runtime`` stage because the earlier stages copy into their
    own throwaway workdirs (``COPY pyproject.toml uv.lock ./``) and none of
    that reaches the shipped filesystem. ``COPY --from=<stage>`` is skipped
    too: those sources are build artifacts (the venv, the SPA bundle) that no
    checkout can supply, so their absence from the replay is honest rather
    than a gap.
    """
    directives: list[tuple[list[str], str]] = []
    stage = ""
    for line in _dockerfile_lines():
        if line.startswith("FROM "):
            tokens = line.split()
            stage = tokens[-1] if len(tokens) >= 4 and tokens[-2].upper() == "AS" else ""
            continue
        if stage != "runtime" or not line.startswith("COPY "):
            continue
        tokens = line.split()[1:]
        if any(token.startswith("--from=") for token in tokens):
            continue
        operands = [token for token in tokens if not token.startswith("--")]
        assert len(operands) >= 2, f"COPY with no source/destination pair: {line!r}"
        directives.append((operands[:-1], operands[-1]))
    assert directives, "no context-reading COPY directives found; did the Dockerfile move?"
    return directives


def _dockerignore_excludes() -> tuple[str, ...]:
    """Path-anchored .dockerignore entries, negations dropped.

    Negations (``!scripts/demo/mock_es.py``) are ignored on purpose: they only
    ever re-include files the Dockerfile names EXPLICITLY as a COPY source, and
    the replay copies those directly rather than through a tree walk.
    """
    text = (REPO_ROOT / ".dockerignore").read_text(encoding="utf-8")
    return tuple(
        line.strip().rstrip("/")
        for line in text.splitlines()
        if line.strip() and not line.lstrip().startswith(("#", "!"))
    )


def _ignore_factory(excludes: tuple[str, ...]) -> Any:
    """A ``shutil.copytree`` ignore callback honouring the excludes above."""

    def _ignore(directory: str, names: list[str]) -> set[str]:
        here = Path(directory).relative_to(REPO_ROOT)
        dropped: set[str] = set()
        for name in names:
            if any(fnmatch(name, pattern) for pattern in _ALWAYS_IGNORED):
                dropped.add(name)
                continue
            if str(here / name) in excludes:
                dropped.add(name)
        return dropped

    return _ignore


def _replay_image_layout(root: Path, *, skip_sources: tuple[str, ...] = ()) -> list[str]:
    """Materialise the runtime stage's view of the build context under ``root``.

    Returns the sources that ``skip_sources`` suppressed, so a negative control
    can assert it actually removed something rather than passing vacuously.
    """
    excludes = _dockerignore_excludes()
    ignore = _ignore_factory(excludes)
    skipped: list[str] = []
    for sources, destination in _runtime_copy_directives():
        assert destination.startswith(IMAGE_APP_DIR), (
            f"COPY destination {destination!r} is outside {IMAGE_APP_DIR}; the replay "
            "only models the application directory, so update this test."
        )
        relative = destination[len(IMAGE_APP_DIR) :].lstrip("/")
        into_directory = destination.endswith("/")
        target = root / relative
        for source in sources:
            normalised = source.rstrip("/")
            if normalised in skip_sources or source in skip_sources:
                skipped.append(source)
                continue
            origin = REPO_ROOT / normalised
            assert origin.exists(), f"Dockerfile copies {source!r}, which is not in the repo"
            if origin.is_dir():
                # Docker copies a directory's CONTENTS into the destination.
                shutil.copytree(origin, target, ignore=ignore, dirs_exist_ok=True)
            else:
                landing = target / origin.name if into_directory else target
                landing.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(origin, landing)
    return skipped


def _probe(root: Path) -> dict[str, Any]:
    """Import the prompts module from ``root`` and report what it found."""
    completed = subprocess.run(
        [sys.executable, "-c", _PROBE],
        check=False,  # the assertion below reports the output, not just the code
        cwd=root,
        env={
            "PYTHONPATH": str(root),
            "PATH": "/usr/bin:/bin",
            "PYTHONDONTWRITEBYTECODE": "1",
            "HOME": str(root),
        },
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert completed.returncode == 0, (
        f"probe failed in the replayed layout:\n{completed.stdout}\n{completed.stderr}"
    )
    result: dict[str, Any] = json.loads(completed.stdout.strip().splitlines()[-1])
    assert result["resolved_root"] == str(root), (
        f"the probe imported soc_ai from {result['resolved_root']!r}, not the replayed "
        f"layout at {str(root)!r}, so the test would be grading the checkout"
    )
    return result


# ── the deployed layout carries every prompt asset ───────────────────────────


@pytest.fixture(scope="module")
def replayed_layout(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """The image's application directory, replayed once for the module."""
    root = tmp_path_factory.mktemp("image") / "opt-soc-ai"
    _replay_image_layout(root)
    return root


def test_replayed_layout_resolves_every_prompt_asset(replayed_layout: Path) -> None:
    """The regression gate. Every asset the prompts declare must be readable
    from the tree the Dockerfile builds, not merely from the checkout, and the
    primer that comes back must be the real one, not the stub."""
    result = _probe(replayed_layout)

    assert result["declared"], "no prompt assets declared, so the gate would be vacuous"
    assert result["missing"] == [], (
        f"prompt asset(s) {result['missing']} resolve in the repository but are absent "
        "from the image layout: the Dockerfile has no COPY that carries them, so the "
        "deployed prompts silently degrade"
    )
    assert not result["stub"], "the primer degraded to the missing-file stub"
    assert result["primer_len"] > 5000, (
        f"primer is {result['primer_len']} bytes in the image layout, too short to be "
        "the real field reference"
    )
    assert result["hunt_len"] > 5000, "the hunt-flavored primer degraded in the image layout"


def test_prompt_assets_live_under_a_copied_directory(replayed_layout: Path) -> None:
    """Each asset lands where the package resolves it, at the image's own path."""
    from soc_ai.agent.prompts import PROMPT_ASSETS

    for asset in PROMPT_ASSETS:
        relative = asset.path.relative_to(REPO_ROOT)
        assert (replayed_layout / relative).is_file(), (
            f"{asset.name} is missing from the image layout at {relative}, so {asset.cost}"
        )


# ── negative control: the same replay, minus the docs COPY ───────────────────


def test_replay_without_the_docs_copy_reproduces_the_shipped_defect(tmp_path: Path) -> None:
    """The failure mode this file exists for, planted deliberately.

    Drop the one COPY that carries ``docs/`` and the replay becomes the image
    that shipped: the primer collapses to the stub and every declared asset
    goes missing. A gate that cannot produce this state is not measuring
    anything, so this is the negative control for the test above.
    """
    root = tmp_path / "opt-soc-ai"
    skipped = _replay_image_layout(root, skip_sources=("docs/", "docs"))

    assert skipped, (
        "the Dockerfile has no COPY of docs/ to suppress, so this control passed "
        "without exercising anything"
    )

    result = _probe(root)
    assert result["missing"] == result["declared"], (
        f"expected every declared prompt asset to go missing, got {result['missing']}"
    )
    assert result["stub"], "the primer did not degrade to the stub without docs/"
    assert result["primer_len"] < 2000, (
        f"stub primer should be tiny, got {result['primer_len']} bytes"
    )


# ── the absence is loud ──────────────────────────────────────────────────────


def test_startup_refuses_when_a_prompt_asset_is_missing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A packaging fault stops the app at boot rather than degrading its answers.

    The checkout satisfies the gate, so the first call is the control: it must
    return. Only then is an absent asset planted.
    """
    from soc_ai.agent import prompts
    from soc_ai.main import _require_prompt_assets

    _require_prompt_assets()

    monkeypatch.setattr(
        prompts,
        "PROMPT_ASSETS",
        (
            prompts.PromptAsset(
                name="oql primer",
                path=tmp_path / "docs" / "OQL_PRIMER.md",
                cost="the model is told the query language is unavailable",
            ),
        ),
    )
    with pytest.raises(RuntimeError) as excinfo:
        _require_prompt_assets()

    message = str(excinfo.value)
    assert "refusing to start" in message
    assert "oql primer" in message
    assert "query language is unavailable" in message
    assert "OQL_PRIMER.md" in message

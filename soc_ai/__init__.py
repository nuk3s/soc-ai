"""soc-ai: open, self-hosted LLM-powered triage assistant for Security Onion."""

import os
import tomllib
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path


def _resolve_version() -> str:
    try:
        return version("soc-ai")
    except PackageNotFoundError:
        # Not pip/uv-installed — e.g. the Docker image runs from source via
        # PYTHONPATH (--no-install-project). Read the version from the adjacent
        # pyproject.toml, which the image copies in. Last resort: a sentinel.
        try:
            pp = Path(__file__).resolve().parent.parent / "pyproject.toml"
            return str(tomllib.loads(pp.read_text())["project"]["version"])
        except Exception:
            return "0.0.0+unknown"


def _resolve_commit() -> str | None:
    """The source commit this build was made from, or None if nothing recorded it.

    The version alone cannot identify a build here. Both deployments run the
    image as ``:latest`` and every one of the 1.5.0 builds carries the same
    version string, so "quality dropped after Tuesday" has nothing to attribute
    itself to. ``.dockerignore`` excludes ``.git``, so the running container
    cannot derive this either — it has to be stamped in at build time, which the
    Dockerfile does through ``ARG SOC_AI_COMMIT`` → this variable.

    None for a source checkout that was never built through that path, and
    stored as None rather than guessed: an unstamped build is a real state, and
    a wrong commit is worse than a missing one when the whole point is
    attribution.
    """
    sha = (os.environ.get("SOC_AI_COMMIT") or "").strip()
    return sha or None


__version__ = _resolve_version()
__commit__ = _resolve_commit()

__all__ = ["__commit__", "__version__"]

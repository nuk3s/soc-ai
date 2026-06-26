"""soc-ai: open, self-hosted LLM-powered triage assistant for Security Onion."""

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


__version__ = _resolve_version()

__all__ = ["__version__"]

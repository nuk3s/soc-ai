"""The PostgreSQL store service lives in docker-compose.yml under the postgres profile."""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent


def _compose() -> dict:
    return yaml.safe_load((REPO_ROOT / "docker-compose.yml").read_text(encoding="utf-8"))


def test_postgres_service_sits_under_its_profile_pinned_by_digest() -> None:
    pg = _compose()["services"]["postgres"]
    assert pg["profiles"] == ["postgres"]
    assert re.fullmatch(r"postgres:\d+\.\d+@sha256:[0-9a-f]{64}", pg["image"]), pg["image"]
    assert pg["container_name"] == "soc-ai-postgres"
    assert pg["restart"] == "unless-stopped"
    # No published port: soc-ai reaches it on the compose network only.
    assert "ports" not in pg
    assert pg["volumes"] == ["soc_ai_postgres:/var/lib/postgresql/data"]
    assert "soc_ai_postgres" in _compose()["volumes"]
    assert "no-new-privileges:true" in pg["security_opt"]
    assert "env_file" not in pg


def test_postgres_service_reads_one_variable_in_the_default_form() -> None:
    """A required form (``:?``) is interpolated even when the profile is off.

    It would break ``docker compose up`` on every SQLite install. The default
    form leaves the password empty there, and the server refuses to start with
    an empty password, so the profile cannot run without one.
    """
    env = _compose()["services"]["postgres"]["environment"]
    assert env == {
        "POSTGRES_USER": "soc_ai",
        "POSTGRES_DB": "soc_ai",
        "POSTGRES_PASSWORD": "${SOC_AI_POSTGRES_PASSWORD:-}",
    }


def test_the_image_and_ci_install_the_driver() -> None:
    """The profile is useless if the image lacks asyncpg; the audit must read it too."""
    pyproject = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    extra = pyproject["project"]["optional-dependencies"]["postgres"]
    assert any(dep.startswith("asyncpg") for dep in extra)
    dockerfile = (REPO_ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert re.search(r"^RUN uv sync --frozen .*--extra postgres", dockerfile, re.M)
    ci = (REPO_ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    assert "--no-dev --extra postgres" in ci
    assert "pytest -m postgres" in ci

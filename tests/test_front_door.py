"""One home page, and no raw JSON for a mistyped console address.

Dogfood 2026-10-19, R1-D19: ``/`` redirected to ``/app/alerts`` while
``/app`` opened the Dashboard, so the console had two home pages. A mistyped
address such as ``/nope`` answered a browser with ``{"detail":"Not Found"}``.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient
from soc_ai.config import Settings
from soc_ai.main import create_app

_HTML = {"accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"}


def _boot(settings: Settings) -> Iterator[TestClient]:
    with (
        patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=AsyncMock()),
        patch("soc_ai.main.make_auth", return_value=AsyncMock()),
        patch("soc_ai.main.get_settings", return_value=settings),
    ):
        app = create_app()
        with TestClient(app) as client:
            yield client


@pytest.fixture
def spa_client(settings_kratos: Settings, tmp_path: Path) -> Iterator[TestClient]:
    """The app with a minimal frontend build, so ``/app`` is mounted."""
    dist = tmp_path / "dist"
    dist.mkdir()
    (dist / "index.html").write_text("<!doctype html><title>soc-ai</title>")
    with patch("soc_ai.main.FRONTEND_DIST", dist):
        yield from _boot(settings_kratos)


@pytest.fixture
def bare_client(settings_kratos: Settings, tmp_path: Path) -> Iterator[TestClient]:
    """The app with no frontend build: ``/app`` is not mounted."""
    with patch("soc_ai.main.FRONTEND_DIST", tmp_path / "no-dist"):
        yield from _boot(settings_kratos)


def test_the_root_opens_the_console_home(spa_client: TestClient) -> None:
    """``/`` and ``/app`` open one page. The SPA root picks Dashboard or sign-in."""
    landing = spa_client.get("/", follow_redirects=False)
    assert landing.status_code == 307
    assert landing.headers["location"] == "/app/"
    assert spa_client.get("/app/").status_code == 200


def test_a_browser_on_an_unknown_address_gets_the_console(spa_client: TestClient) -> None:
    """The SPA shows its own not-found page in the shell, with the navigation."""
    res = spa_client.get("/nope?x=1", headers=_HTML, follow_redirects=False)
    assert res.status_code == 307
    assert res.headers["location"] == "/app/nope?x=1"
    assert spa_client.get(res.headers["location"]).status_code == 200


@pytest.mark.parametrize(
    ("path", "headers"),
    [
        # An API caller keeps the JSON refusal, even from a browser.
        ("/api/v1/nope", _HTML),
        ("/api/nope", _HTML),
        # A script that asks for JSON keeps the JSON 404.
        ("/nope", {"accept": "application/json"}),
        ("/nope", {}),
    ],
)
def test_an_api_or_script_caller_keeps_the_json_404(
    spa_client: TestClient, path: str, headers: dict[str, str]
) -> None:
    """NEGATIVE CONTROL. The redirect is for a browser on a page address only."""
    res = spa_client.get(path, headers=headers, follow_redirects=False)
    assert res.status_code == 404
    assert res.headers["content-type"].startswith("application/json")


def test_a_write_to_an_unknown_address_is_not_redirected(spa_client: TestClient) -> None:
    """NEGATIVE CONTROL. A redirect would turn a POST into a GET of a page."""
    res = spa_client.post("/nope", headers=_HTML, follow_redirects=False)
    assert res.status_code in (404, 405)


def test_no_redirect_when_the_console_is_not_built(bare_client: TestClient) -> None:
    """NEGATIVE CONTROL. With no ``/app`` mounted, a redirect would lead to a 404."""
    res = bare_client.get("/nope", headers=_HTML, follow_redirects=False)
    assert res.status_code == 404

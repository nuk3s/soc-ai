"""The Oracle redaction preview runs the send path's own sanitizer (dogfood 2026-10-01 A5, C6).

The preview called plain ``sanitize()``, which passes ``user.name`` through,
while the Oracle send path calls ``sanitize_case``, which tokenises it. The
preview showed "jsmith" in the clear and so misstated what leaves the network.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient
from soc_ai.config import Settings


@pytest.fixture
def client(settings_kratos: Settings) -> Iterator[TestClient]:
    from soc_ai.main import create_app

    with (
        patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=AsyncMock()),
        patch("soc_ai.main.make_auth", return_value=AsyncMock()),
        patch("soc_ai.main.get_settings", return_value=settings_kratos),
    ):
        app = create_app()
        with TestClient(app) as c:
            yield c


def test_preview_tokenises_user_name(client: TestClient) -> None:
    body = client.get("/api/v1/oracle/redaction-preview").json()
    assert body["original"]["user"]["name"] == "jsmith"
    sanitized = body["sanitized"]
    assert "jsmith" not in json.dumps(sanitized)
    assert sanitized["user"]["name"].startswith("USER_")
    assert body["summary"].get("USER", 0) >= 1
    # Every highlighted pair shows a value the original really holds.
    orig = json.dumps(body["original"])
    for r in body["replacements"]:
        assert r["value"] in orig
    assert any(r["value"] == "jsmith" for r in body["replacements"])


def test_preview_calls_the_send_path_function(client: TestClient) -> None:
    import soc_ai.oracle.client as oracle_client

    real = oracle_client.sanitize_initial_payload
    calls: list[dict[str, Any]] = []

    def spy(*args: Any, **kwargs: Any) -> dict[str, Any]:
        out = real(*args, **kwargs)
        calls.append(out)
        return out

    with patch.object(oracle_client, "sanitize_initial_payload", spy):
        body = client.get("/api/v1/oracle/redaction-preview").json()
    assert len(calls) == 1
    assert body["sanitized"] == calls[0]

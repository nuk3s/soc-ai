"""Connectivity-probe tests (increment 3 of the admin config console).

Covers the pure probe functions and ``ElasticClient.ping``. The
security-critical assertions verify that a secret (api-key / password) sentinel
NEVER appears in the probe ``detail`` string. The probes are surfaced to the
React app via the ``/api/v1/health`` endpoint (see test_webui_api.py); the
legacy ``/ui/config/test/{target}`` route was removed with the HTMX surface.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, patch

import httpx
from pydantic import SecretStr
from soc_ai.config import Settings
from soc_ai.so_client.elastic import ElasticClient
from soc_ai.webui import probes

# Sentinels that must never leak into a probe detail / response body.
API_KEY_SENTINEL = "SECRET-LLM-KEY-do-not-leak-7f3a"
ES_PW_SENTINEL = "SECRET-ES-PW-do-not-leak-9c2b"

# Capture the real class up front so the patch factory below doesn't recurse
# into itself (we patch ``probes.httpx.AsyncClient`` to this factory).
_REAL_ASYNC_CLIENT = httpx.AsyncClient


def _patch_httpx(handler: Any) -> Any:
    """Patch ``probes.httpx.AsyncClient`` to a client bound to *handler*."""
    transport = httpx.MockTransport(handler)

    def _factory(*args: Any, **kwargs: Any) -> httpx.AsyncClient:
        kwargs["transport"] = transport
        return _REAL_ASYNC_CLIENT(*args, **kwargs)

    return patch.object(probes.httpx, "AsyncClient", _factory)


def _llm_settings(api_key: str | None = None) -> Settings:
    return Settings(
        so_host="https://so.example.com",
        so_username="analyst",
        so_password=SecretStr("password123"),
        so_verify_ssl=False,
        es_hosts=["https://so.example.com:9200"],
        litellm_base_url="http://localhost:4000",
        litellm_api_key=SecretStr(api_key) if api_key is not None else None,
    )


# ---------------------------------------------------------------------------
# probe_llm
# ---------------------------------------------------------------------------


async def test_probe_llm_success_counts_models() -> None:
    settings = _llm_settings(api_key="some-key")
    settings.analyst_model = "a"  # must be one of the gateway's models
    payload = {"data": [{"id": "a"}, {"id": "b"}, {"id": "c"}]}

    async def _handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path.endswith("/v1/models")
        return httpx.Response(200, json=payload)

    with _patch_httpx(_handler):
        result = await probes.probe_llm(settings)

    assert result["ok"] is True
    assert "3 models" in result["detail"]


async def test_probe_llm_analyst_model_not_on_gateway() -> None:
    """Gateway is reachable but ANALYST_MODEL isn't a served model → ✗ with hint."""
    settings = _llm_settings(api_key="k")
    settings.analyst_model = "not-a-real-model"
    payload = {"data": [{"id": "a"}, {"id": "b"}]}

    async def _handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=payload)

    with _patch_httpx(_handler):
        result = await probes.probe_llm(settings)

    assert result["ok"] is False
    assert "ANALYST_MODEL" in result["detail"]
    assert "not-a-real-model" in result["detail"]


async def test_probe_llm_failure_hides_api_key() -> None:
    """ConnectError → ok False, and the api-key sentinel is NOT in detail."""
    settings = _llm_settings(api_key=API_KEY_SENTINEL)

    async def _handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused", request=request)

    with _patch_httpx(_handler):
        result = await probes.probe_llm(settings)

    assert result["ok"] is False
    assert API_KEY_SENTINEL not in result["detail"]


async def test_probe_llm_respects_verify_ssl() -> None:
    """The probe mirrors settings.litellm_verify_ssl (homelab self-signed gateways)."""
    settings = _llm_settings(api_key="k")
    settings.litellm_verify_ssl = False
    settings.analyst_model = ""  # skip the analyst-model membership check for this case
    captured: dict[str, Any] = {}
    transport = httpx.MockTransport(lambda r: httpx.Response(200, json={"data": []}))

    def _factory(*args: Any, **kwargs: Any) -> httpx.AsyncClient:
        captured["verify"] = kwargs.get("verify")
        kwargs["transport"] = transport
        return _REAL_ASYNC_CLIENT(*args, **kwargs)

    with patch.object(probes.httpx, "AsyncClient", _factory):
        result = await probes.probe_llm(settings)

    assert result["ok"] is True
    assert captured["verify"] is False


async def test_probe_llm_non_200() -> None:
    settings = _llm_settings(api_key="k")

    async def _handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"error": "unauthorized"})

    with _patch_httpx(_handler):
        result = await probes.probe_llm(settings)

    assert result["ok"] is False
    assert "401" in result["detail"]


# ---------------------------------------------------------------------------
# probe_es
# ---------------------------------------------------------------------------


async def test_probe_es_success() -> None:
    fake = AsyncMock()
    fake.ping.return_value = {"cluster": "so-cluster", "version": "8.13.0"}
    result = await probes.probe_es(fake)
    assert result["ok"] is True
    assert "so-cluster" in result["detail"]
    assert "8.13.0" in result["detail"]


async def test_probe_es_failure_hides_password() -> None:
    """ping raises with a credentialed URL → ok False, password NOT in detail."""
    fake = AsyncMock()
    # Simulate an error message that embeds the basic-auth password in a URL.
    fake.ping.side_effect = ConnectionError(
        f"failed to connect to https://elastic:{ES_PW_SENTINEL}@so.example.com:9200"
    )
    result = await probes.probe_es(fake)
    assert result["ok"] is False
    assert ES_PW_SENTINEL not in result["detail"]


# ---------------------------------------------------------------------------
# _scrub defensive scrubbing
# ---------------------------------------------------------------------------


def test_scrub_strips_userinfo_bearer_and_kv() -> None:
    dirty = (
        "GET https://user:hunter2@host:9200/x failed; "
        "Authorization: Bearer abc.def.ghi; api_key=topsecret&token=zzz"
    )
    clean = probes._scrub(dirty)
    assert "hunter2" not in clean
    assert "abc.def.ghi" not in clean
    assert "topsecret" not in clean
    assert "zzz" not in clean


# ---------------------------------------------------------------------------
# ElasticClient.ping
# ---------------------------------------------------------------------------


async def test_elastic_ping_returns_cluster_and_version(settings_kratos: Settings) -> None:
    fake_raw = AsyncMock()
    fake_raw.info.return_value = {
        "cluster_name": "lab-onion",
        "version": {"number": "8.13.4"},
    }
    with patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=fake_raw):
        client = ElasticClient(settings_kratos)
    out = await client.ping()
    assert out == {"cluster": "lab-onion", "version": "8.13.4"}
    fake_raw.info.assert_awaited_once()

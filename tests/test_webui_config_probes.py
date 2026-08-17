"""Connectivity-probe tests (increment 3 of the admin config console).

Covers the pure probe functions and ``ElasticClient.ping``. The
security-critical assertions verify that a secret (api-key / password) sentinel
NEVER appears in the probe ``detail`` string. The probes are surfaced to the
React app via the ``/api/v1/health`` endpoint (see test_webui_api.py); the
legacy ``/ui/config/test/{target}`` route was removed with the HTMX surface.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, patch

import httpx
from pydantic import SecretStr
from soc_ai.config import Settings
from soc_ai.so_client.elastic import ElasticClient, GridPartialResultsError
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


async def test_probe_llm_demo_mode_reports_healthy_without_egress() -> None:
    """In demo mode the gateway is replayed, so /health must show it OK — and the
    probe must NOT attempt any outbound call (which the demo guard would refuse
    and surface as a false 'AI gateway not reachable' degraded banner)."""
    settings = _llm_settings(api_key="some-key")
    settings.soc_ai_demo = True

    async def _boom(request: httpx.Request) -> httpx.Response:
        raise AssertionError("probe_llm must not attempt egress in demo mode")

    with _patch_httpx(_boom):
        result = await probes.probe_llm(settings)

    assert result["ok"] is True
    assert "demo" in result["detail"].lower()


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


# ── The probe reads the grid it reports on (dogfood 2026-08-14, D1) ──────────
#
# A cluster serving reads off two of its four shards answers the cluster-info
# endpoint normally, so a ping-only probe rendered a green tick byte-identical
# to the healthy control while every alert query on the same instance was
# failing on a partial read. The diagnostic an analyst runs to EXPLAIN the
# degraded banners told them the grid was fine.


class _GridStub:
    """An ES client that answers cluster-info, and reads however it is told to.

    ``search_error`` is what the read leg meets; ``None`` is a whole-grid read.
    Records its calls so a test can pin that the read actually happened, against
    the configured pattern — the failure mode here is a probe that reports on a
    thing it never touched.
    """

    def __init__(self, *, search_error: BaseException | None = None, index: str = "logs-*") -> None:
        self._settings = SimpleNamespace(events_index_pattern=index)
        self._search_error = search_error
        self.searches: list[tuple[str, dict[str, Any], dict[str, Any]]] = []
        self.pings = 0

    async def ping(self) -> dict[str, str]:
        self.pings += 1
        return {"cluster": "demo-grid", "version": "8.14.3"}

    async def search(self, index: str, query: dict[str, Any], **kwargs: Any) -> Any:
        self.searches.append((index, query, kwargs))
        if self._search_error is not None:
            raise self._search_error
        return SimpleNamespace(total=1, hits=[{"_id": "1"}])


def _partial_read(failed: int = 2, total: int = 4) -> GridPartialResultsError:
    return GridPartialResultsError(
        f"partial search results from logs-*: {failed} of {total} shards failed",
        shards_failed=failed,
        shards_total=total,
    )


async def test_probe_es_half_read_grid_is_not_healthy() -> None:
    """200 from cluster-info + a partial read → NOT ok.

    Asserts on ``ok``, not on the wording: a probe that keeps reporting healthy
    with a chattier message passes a string test and still tells the analyst at
    3am that the grid they cannot read is fine.
    """
    grid = _GridStub(search_error=_partial_read())
    result = await probes.probe_es(grid)
    assert result["ok"] is False


async def test_probe_es_actually_reads_the_configured_index() -> None:
    """The read leg runs against ``events_index_pattern``, after the ping."""
    grid = _GridStub(index="so-logs-*")
    result = await probes.probe_es(grid)
    assert result["ok"] is True
    assert grid.pings == 1
    assert len(grid.searches) == 1
    index, _query, kwargs = grid.searches[0]
    assert index == "so-logs-*"
    assert kwargs["size"] == 1  # one document: the cheapest read that proves it


async def test_probe_es_prefers_the_callers_index_pattern() -> None:
    """Explicit settings win over the client's own — /health passes its live set."""
    grid = _GridStub(index="stale-*")
    await probes.probe_es(grid, SimpleNamespace(events_index_pattern="fresh-*"))
    assert grid.searches[0][0] == "fresh-*"


async def test_probe_es_healthy_grid_still_reports_healthy() -> None:
    """The negative control: a grid that reads everything stays green.

    A probe that always degrades is the over-correction, and it would be just as
    useless a diagnostic as the one that always passed.
    """
    grid = _GridStub()
    result = await probes.probe_es(grid)
    assert result["ok"] is True
    assert "demo-grid" in result["detail"]
    assert "8.14.3" in result["detail"]


# ── The probe names WHICH failure it met (dogfood 2026-08-14, D9 + D11) ──────


class ApiError(Exception):
    """An elasticsearch ApiError as the console meets it: status + body + a
    self-naming ``str()``. Named exactly as elasticsearch names it, because the
    doubling this pins ("ApiError: ApiError(429, …)") comes from prefixing the
    class name onto a message that already carries it.
    """

    def __init__(self, status: int, body: dict[str, Any]) -> None:
        super().__init__(
            f"ApiError({status}, 'circuit_breaking_exception', '[parent] Data too big')"
        )
        self.status_code = status
        self.body = body


_BREAKER_BODY: dict[str, Any] = {
    "error": {
        "root_cause": [
            {
                "type": "circuit_breaking_exception",
                "reason": (
                    "[parent] Data too large, data for [<http_request>] would be "
                    "[7936000000/7.3gb], which is larger than the limit of "
                    "[7301444812/6.7gb], real usage: [7935999999/7.3gb]"
                ),
            }
        ]
    }
}


async def test_probe_es_calls_a_saturated_grid_overloaded_not_unreachable() -> None:
    """429 is a REPLY. Classifying it as reachable-but-shedding is what stops the
    console telling a 3am analyst to go and check the firewall."""
    grid = _GridStub(search_error=ApiError(429, _BREAKER_BODY))
    result = await probes.probe_es(grid)
    assert result["ok"] is False
    assert result["kind"] == probes.KIND_OVERLOADED


async def test_probe_es_keeps_the_breaker_limit_an_admin_could_act_on() -> None:
    """The 160-char reason cap used to truncate the raw chain exactly before the
    limit value — leaking internals AND dropping the only actionable number."""
    grid = _GridStub(search_error=ApiError(429, _BREAKER_BODY))
    detail = (await probes.probe_es(grid))["detail"]
    assert "7.3gb" in detail
    assert "6.7gb" in detail
    # …and it is prose, not a doubled exception chain.
    assert "ApiError: ApiError(" not in detail


async def test_probe_es_classifies_a_partial_read() -> None:
    grid = _GridStub(search_error=_partial_read())
    result = await probes.probe_es(grid)
    assert result["kind"] == probes.KIND_PARTIAL


# ── An incomplete read has two causes, and only one of them is the shards ────
#
# ES returns 200 with `timed_out: true` and zero failed shards when every shard
# was healthy and answered — the SEARCH ran out of time first. It is the ordinary
# state of a busy grid under a wide window, and the remedy is a retry or a
# narrower window, not shard surgery (review of batch A, 2026-08-14).


async def _read_that_timed_out(settings: Settings) -> GridPartialResultsError:
    """The exception a REAL client raises for a 200 that timed out with every
    shard healthy — built through ``_check_complete`` rather than hand-rolled,
    so this fixture cannot drift from the state ES actually produces.
    """
    raw = AsyncMock()
    raw.search.return_value = {
        "took": 30_000,
        "timed_out": True,
        "_shards": {"total": 4, "successful": 4, "skipped": 0, "failed": 0},
        "hits": {"total": {"value": 0, "relation": "eq"}, "hits": []},
    }
    with patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=raw):
        client = ElasticClient(settings)
    try:
        await client.search("logs-*", {"match_all": {}})
    except GridPartialResultsError as exc:
        return exc
    raise AssertionError("the client accepted a timed-out read as a complete one")


async def test_probe_es_a_search_timeout_is_not_blamed_on_shard_health(
    settings_kratos: Settings,
) -> None:
    """ "Read only 4 of 4 shards" contradicts itself, and the shard-health remedy
    sends the admin to the one part of the system that is demonstrably fine —
    the same wrong-building failure this batch exists to remove. Retrying, or
    narrowing the window, is what can actually work here.
    """
    grid = _GridStub(search_error=await _read_that_timed_out(settings_kratos))
    result = await probes.probe_es(grid)
    # The classification was never wrong: the read WAS incomplete.
    assert result["ok"] is False
    assert result["kind"] == probes.KIND_PARTIAL
    detail = result["detail"]
    assert "4 of 4 shards" not in detail
    assert "shard health" not in detail
    assert "timed out" in detail
    assert "retry" in detail
    assert "narrow" in detail


async def test_probe_es_failed_shards_still_send_the_admin_to_shard_health() -> None:
    """The control: when shards really did fail, retrying is exactly what will
    not help, and the shard count is the fact the admin needs."""
    detail = (await probes.probe_es(_GridStub(search_error=_partial_read())))["detail"]
    assert "read only 2 of 4 shards" in detail
    assert "check Elasticsearch shard health" in detail


async def test_probe_es_a_read_that_lost_shards_and_timed_out_keeps_both_facts() -> None:
    """Both at once is a shard story: a timeout does not excuse a dead shard."""
    exc = GridPartialResultsError(
        "partial search results from logs-*: 1 of 4 shards failed and the search timed out",
        shards_failed=1,
        shards_total=4,
        timed_out=True,
    )
    detail = (await probes.probe_es(_GridStub(search_error=exc)))["detail"]
    assert "read only 3 of 4 shards" in detail
    assert "timed out" in detail
    assert "check Elasticsearch shard health" in detail


async def test_probe_es_classifies_a_refused_connection() -> None:
    fake = AsyncMock()
    fake.ping.side_effect = ConnectionError("connection reset by peer")
    result = await probes.probe_es(fake)
    assert result["kind"] == probes.KIND_REFUSED


async def test_probe_es_leaves_an_unrecognised_failure_unclassified() -> None:
    """No invented diagnosis: an unknown error keeps the generic phrasing."""
    fake = AsyncMock()
    fake.ping.side_effect = ValueError("something else entirely")
    result = await probes.probe_es(fake)
    assert result["kind"] == ""
    assert "something else entirely" in result["detail"]


def test_safe_reason_does_not_double_a_self_naming_exception() -> None:
    reason = probes._safe_reason(ApiError(429, {}))
    assert reason.startswith("ApiError(429")


async def test_probe_es_refused_connection_is_not_reported_as_a_partial_read() -> None:
    """Ping runs FIRST: a grid that is not there is not a grid that read badly."""
    grid = _GridStub(search_error=_partial_read())
    fake = AsyncMock()
    fake.ping.side_effect = ConnectionError("connection refused")
    fake._settings = grid._settings
    fake.search.side_effect = _partial_read()
    result = await probes.probe_es(fake)
    assert result["ok"] is False
    assert "shards" not in result["detail"]
    fake.search.assert_not_awaited()


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

"""Tests for :mod:`soc_ai.so_client.auth` and :mod:`soc_ai.so_client.elastic`.

All HTTP traffic to the SO grid is mocked with ``respx``; ES traffic is mocked
by patching :class:`elasticsearch.AsyncElasticsearch`. No live grid is touched.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import AsyncMock, patch

import httpx
import pytest
import respx
from elasticsearch import NotFoundError
from soc_ai.config import Settings
from soc_ai.errors import SoAuthError
from soc_ai.so_client.auth import ConnectAuth, KratosAuth, make_auth
from soc_ai.so_client.elastic import ElasticClient, EsSearchResult

# =====================================================================
# KratosAuth
# =====================================================================


@pytest.mark.asyncio
async def test_kratos_login_happy_path(
    settings_kratos: Settings, kratos_init: dict[str, Any]
) -> None:
    auth = KratosAuth(settings_kratos)
    try:
        with respx.mock(base_url="https://so.example.com", assert_all_called=True) as mock:
            mock.get("/auth/self-service/login/api").mock(
                return_value=httpx.Response(200, json=kratos_init)
            )
            mock.post("/auth/self-service/login").mock(
                return_value=httpx.Response(
                    200,
                    json={"session": {"id": "s1"}},
                    headers={"set-cookie": "ory_kratos_session=abc; Path=/"},
                )
            )
            await auth.login()
        assert auth._logged_in is True
    finally:
        await auth.aclose()


@pytest.mark.asyncio
async def test_kratos_login_bad_credentials(
    settings_kratos: Settings, kratos_init: dict[str, Any]
) -> None:
    auth = KratosAuth(settings_kratos)
    try:
        with respx.mock(base_url="https://so.example.com") as mock:
            mock.get("/auth/self-service/login/api").mock(
                return_value=httpx.Response(200, json=kratos_init)
            )
            mock.post("/auth/self-service/login").mock(
                return_value=httpx.Response(400, json={"error": "credentials_invalid"})
            )
            with pytest.raises(SoAuthError, match="rejected credentials"):
                await auth.login()
        assert auth._logged_in is False
    finally:
        await auth.aclose()


@pytest.mark.asyncio
async def test_kratos_login_init_error(settings_kratos: Settings) -> None:
    auth = KratosAuth(settings_kratos)
    try:
        with respx.mock(base_url="https://so.example.com") as mock:
            mock.get("/auth/self-service/login/api").mock(
                return_value=httpx.Response(500, text="internal error")
            )
            with pytest.raises(SoAuthError, match="login flow init"):
                await auth.login()
    finally:
        await auth.aclose()


@pytest.mark.asyncio
async def test_kratos_request_triggers_login(
    settings_kratos: Settings, kratos_init: dict[str, Any]
) -> None:
    auth = KratosAuth(settings_kratos)
    try:
        with respx.mock(base_url="https://so.example.com") as mock:
            login_init = mock.get("/auth/self-service/login/api").mock(
                return_value=httpx.Response(200, json=kratos_init)
            )
            login_post = mock.post("/auth/self-service/login").mock(
                return_value=httpx.Response(200, json={})
            )
            data_call = mock.get("/connect/case").mock(return_value=httpx.Response(200, json=[]))

            resp = await auth.request("GET", "/connect/case")
        assert resp.status_code == 200
        assert login_init.called
        assert login_post.called
        assert data_call.called
    finally:
        await auth.aclose()


@pytest.mark.asyncio
async def test_kratos_401_triggers_relogin(
    settings_kratos: Settings, kratos_init: dict[str, Any]
) -> None:
    auth = KratosAuth(settings_kratos)
    auth._logged_in = True  # Pretend we already had a session
    try:
        with respx.mock(base_url="https://so.example.com") as mock:
            mock.get("/connect/case").mock(
                side_effect=[
                    httpx.Response(401, text="session expired"),
                    httpx.Response(200, json=[]),
                ]
            )
            mock.get("/auth/self-service/login/api").mock(
                return_value=httpx.Response(200, json=kratos_init)
            )
            mock.post("/auth/self-service/login").mock(return_value=httpx.Response(200, json={}))

            resp = await auth.request("GET", "/connect/case")
        assert resp.status_code == 200
    finally:
        await auth.aclose()


@pytest.mark.asyncio
async def test_kratos_login_idempotent_under_concurrency(
    settings_kratos: Settings, kratos_init: dict[str, Any]
) -> None:
    """Two concurrent .login() calls should result in exactly one HTTP login flow."""
    auth = KratosAuth(settings_kratos)
    try:
        with respx.mock(base_url="https://so.example.com") as mock:
            init_route = mock.get("/auth/self-service/login/api").mock(
                return_value=httpx.Response(200, json=kratos_init)
            )
            post_route = mock.post("/auth/self-service/login").mock(
                return_value=httpx.Response(200, json={})
            )
            await asyncio.gather(auth.login(), auth.login(), auth.login())
        assert init_route.call_count == 1
        assert post_route.call_count == 1
    finally:
        await auth.aclose()


# =====================================================================
# ConnectAuth
# =====================================================================


@pytest.mark.asyncio
async def test_connect_token_acquisition(
    settings_connect: Settings, oauth_token: dict[str, Any]
) -> None:
    auth = ConnectAuth(settings_connect)
    try:
        with respx.mock(base_url="https://so.example.com") as mock:
            mock.post("/oauth2/token").mock(return_value=httpx.Response(200, json=oauth_token))
            mock.get("/connect/case").mock(return_value=httpx.Response(200, json=[]))

            resp = await auth.request("GET", "/connect/case")
        assert resp.status_code == 200
        assert auth._token == oauth_token["access_token"]
        assert auth._expires_at is not None
    finally:
        await auth.aclose()


@pytest.mark.asyncio
async def test_connect_proactive_refresh(
    settings_connect: Settings, oauth_token: dict[str, Any]
) -> None:
    """If the token has nearly expired, the next request must refresh."""
    auth = ConnectAuth(settings_connect)
    try:
        # Pre-load a stale token (30s left, less than the 60s leeway).
        auth._token = "stale-token"
        auth._expires_at = datetime.now(UTC) + timedelta(seconds=30)

        with respx.mock(base_url="https://so.example.com") as mock:
            token_route = mock.post("/oauth2/token").mock(
                return_value=httpx.Response(200, json=oauth_token)
            )
            mock.get("/connect/case").mock(return_value=httpx.Response(200, json=[]))

            await auth.request("GET", "/connect/case")
        assert token_route.called
        assert auth._token == oauth_token["access_token"]
    finally:
        await auth.aclose()


@pytest.mark.asyncio
async def test_connect_skips_refresh_when_fresh(
    settings_connect: Settings, oauth_token: dict[str, Any]
) -> None:
    """A still-fresh token must NOT trigger a refresh."""
    auth = ConnectAuth(settings_connect)
    try:
        auth._token = "fresh-token"
        auth._expires_at = datetime.now(UTC) + timedelta(hours=1)

        with respx.mock(base_url="https://so.example.com", assert_all_called=False) as mock:
            token_route = mock.post("/oauth2/token").mock(
                return_value=httpx.Response(200, json=oauth_token)
            )
            mock.get("/connect/case").mock(return_value=httpx.Response(200, json=[]))

            await auth.request("GET", "/connect/case")
        assert not token_route.called
        assert auth._token == "fresh-token"
    finally:
        await auth.aclose()


@pytest.mark.asyncio
async def test_connect_401_forces_refresh(
    settings_connect: Settings, oauth_token: dict[str, Any]
) -> None:
    auth = ConnectAuth(settings_connect)
    try:
        auth._token = "old-token"
        auth._expires_at = datetime.now(UTC) + timedelta(hours=1)

        with respx.mock(base_url="https://so.example.com") as mock:
            token_route = mock.post("/oauth2/token").mock(
                return_value=httpx.Response(200, json=oauth_token)
            )
            mock.get("/connect/case").mock(
                side_effect=[
                    httpx.Response(401, json={"error": "expired"}),
                    httpx.Response(200, json=[]),
                ]
            )

            resp = await auth.request("GET", "/connect/case")
        assert resp.status_code == 200
        assert token_route.called  # forced after 401
        assert auth._token == oauth_token["access_token"]
    finally:
        await auth.aclose()


@pytest.mark.asyncio
async def test_connect_token_request_failure(settings_connect: Settings) -> None:
    auth = ConnectAuth(settings_connect)
    try:
        with respx.mock(base_url="https://so.example.com") as mock:
            mock.post("/oauth2/token").mock(
                return_value=httpx.Response(503, text="service unavailable")
            )
            with pytest.raises(SoAuthError, match="OAuth token request failed"):
                await auth.request("GET", "/connect/case")
    finally:
        await auth.aclose()


@pytest.mark.asyncio
async def test_connect_malformed_token_response(settings_connect: Settings) -> None:
    auth = ConnectAuth(settings_connect)
    try:
        with respx.mock(base_url="https://so.example.com") as mock:
            mock.post("/oauth2/token").mock(
                return_value=httpx.Response(200, json={"no": "access_token"})
            )
            with pytest.raises(SoAuthError, match="malformed"):
                await auth.request("GET", "/connect/case")
    finally:
        await auth.aclose()


def test_connect_auth_requires_credentials(settings_kratos: Settings) -> None:
    """Constructing ConnectAuth without SO_CLIENT_ID/SECRET must fail fast."""
    with pytest.raises(SoAuthError, match="requires SO_CLIENT_ID"):
        ConnectAuth(settings_kratos)


# =====================================================================
# make_auth factory
# =====================================================================


def test_make_auth_picks_kratos_by_default(settings_kratos: Settings) -> None:
    auth = make_auth(settings_kratos)
    try:
        assert isinstance(auth, KratosAuth)
    finally:
        # KratosAuth.aclose is async, so this test can't easily call it; that's
        # fine because we never exercised the underlying client.
        pass


def test_make_auth_picks_connect_when_credentials_set(
    settings_connect: Settings,
) -> None:
    auth = make_auth(settings_connect)
    assert isinstance(auth, ConnectAuth)


# =====================================================================
# ElasticClient
# =====================================================================


@pytest.mark.asyncio
async def test_elastic_search_unwraps_total_dict(settings_kratos: Settings) -> None:
    fake_es = AsyncMock()
    fake_es.search.return_value = {
        "took": 7,
        "hits": {
            "total": {"value": 42, "relation": "eq"},
            "hits": [{"_id": "a1", "_source": {"foo": "bar"}}],
        },
    }
    fake_es.close = AsyncMock()

    with patch(
        "soc_ai.so_client.elastic.AsyncElasticsearch",
        return_value=fake_es,
    ):
        client = ElasticClient(settings_kratos)
        result = await client.search("so-events-*", {"match_all": {}})
        await client.aclose()

    assert isinstance(result, EsSearchResult)
    assert result.total == 42
    assert result.took_ms == 7
    assert len(result.hits) == 1
    fake_es.close.assert_awaited_once()


@pytest.mark.asyncio
async def test_elastic_search_handles_int_total(settings_kratos: Settings) -> None:
    """Older ES responses returned a bare int for `hits.total`."""
    fake_es = AsyncMock()
    fake_es.search.return_value = {
        "took": 3,
        "hits": {"total": 5, "hits": []},
    }
    with patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=fake_es):
        client = ElasticClient(settings_kratos)
        result = await client.search("idx", {})

    assert result.total == 5


@pytest.mark.asyncio
async def test_elastic_search_passes_size_and_sort(settings_kratos: Settings) -> None:
    fake_es = AsyncMock()
    fake_es.search.return_value = {"took": 0, "hits": {"total": 0, "hits": []}}

    with patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=fake_es):
        client = ElasticClient(settings_kratos)
        await client.search(
            "idx",
            {"term": {"foo": "bar"}},
            size=50,
            sort=[{"@timestamp": "desc"}],
        )

    call_kwargs = fake_es.search.call_args.kwargs
    assert call_kwargs["index"] == "idx"
    # Tolerate patterns that only partly resolve (no remote cluster / missing
    # index) so a both-shapes pattern returns empty instead of 500ing.
    assert call_kwargs["ignore_unavailable"] is True
    assert call_kwargs["allow_no_indices"] is True
    body = call_kwargs["body"]
    assert body["size"] == 50
    assert body["sort"] == [{"@timestamp": "desc"}]
    assert body["query"] == {"term": {"foo": "bar"}}


@pytest.mark.asyncio
async def test_elastic_get_returns_doc(settings_kratos: Settings) -> None:
    fake_es = AsyncMock()
    fake_es.get.return_value = {
        "_id": "alert-1",
        "_index": "so-events-*",
        "_source": {"foo": "bar"},
    }
    with patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=fake_es):
        client = ElasticClient(settings_kratos)
        doc = await client.get("so-events-*", "alert-1")

    assert doc is not None
    assert doc["_id"] == "alert-1"


@pytest.mark.asyncio
async def test_elastic_get_returns_none_on_404(settings_kratos: Settings) -> None:
    fake_es = AsyncMock()
    fake_es.get.side_effect = NotFoundError(message="not found", meta=None, body=None)
    with patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=fake_es):
        client = ElasticClient(settings_kratos)
        doc = await client.get("so-events-*", "missing")

    assert doc is None


# =====================================================================
# C1: EsSearchResult.total_is_lower_bound — ES relation field surfaced
# =====================================================================


@pytest.mark.asyncio
async def test_elastic_search_gte_relation_sets_lower_bound(settings_kratos: Settings) -> None:
    """relation='gte' → total_is_lower_bound True; total_display renders ≥N."""
    fake_es = AsyncMock()
    fake_es.search.return_value = {
        "took": 2,
        "hits": {
            "total": {"value": 10000, "relation": "gte"},
            "hits": [],
        },
    }
    with patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=fake_es):
        client = ElasticClient(settings_kratos)
        result = await client.search("idx", {})

    assert result.total == 10000
    assert result.total_is_lower_bound is True
    assert result.total_display == "≥10000"
    # Confirm it surfaces in model_dump (agent-visible JSON)
    dumped = result.model_dump(mode="json")
    assert dumped["total_is_lower_bound"] is True
    assert dumped["total_display"] == "≥10000"


@pytest.mark.asyncio
async def test_elastic_search_eq_relation_is_exact(settings_kratos: Settings) -> None:
    """relation='eq' → total_is_lower_bound False; total_display renders exact N."""
    fake_es = AsyncMock()
    fake_es.search.return_value = {
        "took": 1,
        "hits": {
            "total": {"value": 42, "relation": "eq"},
            "hits": [],
        },
    }
    with patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=fake_es):
        client = ElasticClient(settings_kratos)
        result = await client.search("idx", {})

    assert result.total == 42
    assert result.total_is_lower_bound is False
    assert result.total_display == "42"


# =====================================================================
# Write-serialization concurrency tests
# =====================================================================


@pytest.mark.asyncio
async def test_kratos_writes_are_serialized(settings_kratos: Settings) -> None:
    """Concurrent POSTs through KratosAuth must be serialized (max 1 in-flight).

    Root cause: SO 3.0's X-Srv-Token CSRF mechanism rejects concurrent writes
    through one session (empirically 1/12 concurrent POSTs succeed, 12/12
    sequential succeed).  The _write_lock must bring max_in_flight down to 1.
    """
    auth = KratosAuth(settings_kratos)
    # Bypass login — inject tokens directly so request() skips the login path.
    auth._logged_in = True
    auth._session_token = "test-session-token"
    auth._srv_token = "test-srv-token"

    in_flight = 0
    max_in_flight = 0

    async def fake_request(method: str, url: str, **kwargs: Any) -> httpx.Response:
        nonlocal in_flight, max_in_flight
        in_flight += 1
        max_in_flight = max(max_in_flight, in_flight)
        await asyncio.sleep(0.02)
        in_flight -= 1
        return httpx.Response(200, request=httpx.Request(method, "http://x"))

    auth._client.request = fake_request  # type: ignore[method-assign]

    N = 8
    await asyncio.gather(*[auth.request("POST", "/api/events/ack", json={}) for _ in range(N)])

    assert max_in_flight == 1, f"Expected writes serialized (max_in_flight=1), got {max_in_flight}"
    await auth.aclose()


@pytest.mark.asyncio
async def test_kratos_reads_are_concurrent(settings_kratos: Settings) -> None:
    """Concurrent GETs through KratosAuth must NOT be serialized.

    The _write_lock only gates mutating methods; reads must stay concurrent so
    we don't regress the eval pipeline's concurrency=5 read throughput.
    """
    auth = KratosAuth(settings_kratos)
    auth._logged_in = True
    auth._session_token = "test-session-token"
    auth._srv_token = "test-srv-token"

    in_flight = 0
    max_in_flight = 0

    async def fake_request(method: str, url: str, **kwargs: Any) -> httpx.Response:
        nonlocal in_flight, max_in_flight
        in_flight += 1
        max_in_flight = max(max_in_flight, in_flight)
        await asyncio.sleep(0.02)
        in_flight -= 1
        return httpx.Response(200, request=httpx.Request(method, "http://x"))

    auth._client.request = fake_request  # type: ignore[method-assign]

    N = 8
    await asyncio.gather(*[auth.request("GET", "/api/events", params={"i": i}) for i in range(N)])

    assert max_in_flight > 1, (
        f"Expected reads to run concurrently (max_in_flight>1), got {max_in_flight}"
    )
    await auth.aclose()


@pytest.mark.asyncio
async def test_connect_writes_are_serialized(settings_connect: Settings) -> None:
    """Concurrent POSTs through ConnectAuth must be serialized (max 1 in-flight)."""
    auth = ConnectAuth(settings_connect)
    # Inject a fresh token so _refresh_token is a no-op.
    auth._token = "test-bearer-token"
    auth._expires_at = datetime.now(UTC) + timedelta(hours=1)

    in_flight = 0
    max_in_flight = 0

    async def fake_request(method: str, url: str, **kwargs: Any) -> httpx.Response:
        nonlocal in_flight, max_in_flight
        in_flight += 1
        max_in_flight = max(max_in_flight, in_flight)
        await asyncio.sleep(0.02)
        in_flight -= 1
        return httpx.Response(200, request=httpx.Request(method, "http://x"))

    auth._client.request = fake_request  # type: ignore[method-assign]

    N = 8
    await asyncio.gather(*[auth.request("POST", "/api/events/ack", json={}) for _ in range(N)])

    assert max_in_flight == 1, (
        f"Expected ConnectAuth writes serialized (max_in_flight=1), got {max_in_flight}"
    )
    await auth.aclose()


@pytest.mark.asyncio
async def test_connect_reads_are_concurrent(settings_connect: Settings) -> None:
    """Concurrent GETs through ConnectAuth must NOT be serialized."""
    auth = ConnectAuth(settings_connect)
    auth._token = "test-bearer-token"
    auth._expires_at = datetime.now(UTC) + timedelta(hours=1)

    in_flight = 0
    max_in_flight = 0

    async def fake_request(method: str, url: str, **kwargs: Any) -> httpx.Response:
        nonlocal in_flight, max_in_flight
        in_flight += 1
        max_in_flight = max(max_in_flight, in_flight)
        await asyncio.sleep(0.02)
        in_flight -= 1
        return httpx.Response(200, request=httpx.Request(method, "http://x"))

    auth._client.request = fake_request  # type: ignore[method-assign]

    N = 8
    await asyncio.gather(*[auth.request("GET", "/api/events", params={"i": i}) for i in range(N)])

    assert max_in_flight > 1, (
        f"Expected ConnectAuth reads to run concurrently (max_in_flight>1), got {max_in_flight}"
    )
    await auth.aclose()

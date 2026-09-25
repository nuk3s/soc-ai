"""Tests for :mod:`soc_ai.so_client.auth` and :mod:`soc_ai.so_client.elastic`.

All HTTP traffic to the SO grid is mocked with ``respx``; ES traffic is mocked
by patching :class:`elasticsearch.AsyncElasticsearch`. No live grid is touched.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import AsyncMock, patch

import httpx
import pytest
import respx
from elastic_transport import TransportError
from elasticsearch import NotFoundError
from soc_ai.config import Settings
from soc_ai.demo.guard import DemoEgressBlocked
from soc_ai.errors import SoAuthError
from soc_ai.so_client.auth import _SRV_TOKEN_TTL_S, ConnectAuth, KratosAuth, make_auth
from soc_ai.so_client.elastic import ElasticClient, EsSearchResult, GridPartialResultsError

# =====================================================================
# KratosAuth — the Kratos BROWSER login flow
#
# SO 3.3 refuses a Kratos API-flow session token in an X-Session-Token
# header: SOC resolves no identity and answers 401 on every call, which
# breaks every write (ack, escalate, case comment). The browser flow sets
# the ory_kratos_session cookie that SOC accepts, on 3.3 and on earlier
# releases. These tests pin the request sequence, the cookie and the
# absence of the old header.
# =====================================================================

_SESSION_COOKIE_HEADERS = {"set-cookie": "ory_kratos_session=session-abc; Path=/; HttpOnly"}


def _forced(settings: Settings, flow: str) -> Settings:
    """Settings that pin one login flow, so no fallback runs."""
    return settings.model_copy(update={"so_login_flow": flow})


_CSRF_COOKIE_HEADERS = {"set-cookie": "csrf_token_deadbeef=csrf-value-abc; Path=/; HttpOnly"}


def _mock_browser_login(
    mock: respx.MockRouter,
    flow: dict[str, Any],
    *,
    info_status: int = 200,
) -> dict[str, Any]:
    """Route the three calls a browser login makes. Returns the routes by name."""
    return {
        "init": mock.get("/auth/self-service/login/browser").mock(
            return_value=httpx.Response(200, json=flow, headers=_CSRF_COOKIE_HEADERS)
        ),
        "submit": mock.post("/auth/self-service/login").mock(
            return_value=httpx.Response(
                200, json={"session": {"id": "s1"}}, headers=_SESSION_COOKIE_HEADERS
            )
        ),
        "info": mock.get("/api/info").mock(
            return_value=httpx.Response(
                info_status,
                json={"srvToken": "srv-1", "version": "3.3.0"}
                if info_status == 200
                else {"error": "unauthorized"},
            )
        ),
    }


@pytest.mark.asyncio
async def test_kratos_login_happy_path(
    settings_kratos: Settings, kratos_init: dict[str, Any]
) -> None:
    auth = KratosAuth(settings_kratos)
    try:
        with respx.mock(base_url="https://so.example.com", assert_all_called=True) as mock:
            _mock_browser_login(mock, kratos_init)
            await auth.login()
        assert auth._logged_in is True
        assert auth._has_session_cookie() is True
        assert auth._srv_token == "srv-1"
    finally:
        await auth.aclose()


@pytest.mark.asyncio
async def test_kratos_login_request_sequence(
    settings_kratos: Settings, kratos_init: dict[str, Any]
) -> None:
    """The exact sequence a login makes, and the form the credentials travel in."""
    auth = KratosAuth(settings_kratos)
    try:
        with respx.mock(base_url="https://so.example.com") as mock:
            _mock_browser_login(mock, kratos_init)
            await auth.login()

            calls = [(c.request.method, c.request.url.path) for c in mock.calls]
            assert calls == [
                ("GET", "/auth/self-service/login/browser"),
                ("POST", "/auth/self-service/login"),
                ("GET", "/api/info"),
            ]
            init_req = mock.calls[0].request
            assert init_req.headers["accept"] == "application/json"
            submit_req = mock.calls[1].request
            assert submit_req.url.params["flow"] == kratos_init["id"]
            body = json.loads(submit_req.content)
            assert body["method"] == "password"
            assert body["identifier"] == settings_kratos.so_username
            assert body["csrf_token"] == "csrf-value-abc"
    finally:
        await auth.aclose()


@pytest.mark.asyncio
async def test_kratos_never_sends_the_session_token_header(
    settings_kratos: Settings, kratos_init: dict[str, Any]
) -> None:
    """The header SO 3.3 refuses must not appear on any call, login or read."""
    auth = KratosAuth(settings_kratos)
    try:
        with respx.mock(base_url="https://so.example.com") as mock:
            _mock_browser_login(mock, kratos_init)
            mock.get("/connect/case").mock(return_value=httpx.Response(200, json=[]))
            await auth.request("GET", "/connect/case")

            for call in mock.calls:
                assert "x-session-token" not in {k.lower() for k in call.request.headers}
    finally:
        await auth.aclose()


@pytest.mark.asyncio
async def test_kratos_session_cookie_is_carried_on_the_next_request(
    settings_kratos: Settings, kratos_init: dict[str, Any]
) -> None:
    """The cookie jar, not a header, carries the session to /api/... ."""
    auth = KratosAuth(settings_kratos)
    try:
        with respx.mock(base_url="https://so.example.com") as mock:
            _mock_browser_login(mock, kratos_init)
            data_call = mock.get("/connect/case").mock(return_value=httpx.Response(200, json=[]))
            await auth.request("GET", "/connect/case")

            cookie_header = data_call.calls[0].request.headers.get("cookie", "")
        assert "ory_kratos_session=" in cookie_header
    finally:
        await auth.aclose()


@pytest.mark.asyncio
async def test_kratos_login_follows_a_redirect_to_the_flow(
    settings_kratos: Settings, kratos_init: dict[str, Any]
) -> None:
    """Kratos may answer the init with a redirect. The flow id is in Location."""
    auth = KratosAuth(settings_kratos)
    try:
        with respx.mock(base_url="https://so.example.com") as mock:
            mock.get("/auth/self-service/login/browser").mock(
                return_value=httpx.Response(
                    303,
                    headers={"location": "https://so.example.com/login/?flow=flow-abc-123"},
                )
            )
            flow_route = mock.get("/auth/self-service/login/flows").mock(
                return_value=httpx.Response(200, json=kratos_init, headers=_CSRF_COOKIE_HEADERS)
            )
            mock.post("/auth/self-service/login").mock(
                return_value=httpx.Response(
                    200, json={"session": {"id": "s1"}}, headers=_SESSION_COOKIE_HEADERS
                )
            )
            mock.get("/api/info").mock(return_value=httpx.Response(200, json={"srvToken": "s"}))
            await auth.login()

            assert flow_route.calls[0].request.url.params["id"] == "flow-abc-123"
        assert auth._logged_in is True
    finally:
        await auth.aclose()


@pytest.mark.asyncio
async def test_kratos_throttled_login_reads_as_throttled(settings_kratos: Settings) -> None:
    """A redirect with no flow id is SO shedding repeated logins.

    The old client parsed that page as JSON and raised "Expecting value: line 1
    column 1 (char 0)". That message dominated the log of the SO 3.3 outage and
    described a login that never started, not the session refusal behind it.
    """
    auth = KratosAuth(settings_kratos)
    try:
        with respx.mock(base_url="https://so.example.com") as mock:
            mock.get("/auth/self-service/login/browser").mock(
                return_value=httpx.Response(302, headers={"location": "/login/?thr=6"})
            )
            with pytest.raises(SoAuthError) as excinfo:
                await auth.login()
        msg = str(excinfo.value)
        assert "SO throttled the login" in msg
        assert "302" in msg
        assert "Expecting value" not in msg
    finally:
        await auth.aclose()


@pytest.mark.asyncio
async def test_kratos_html_login_page_reads_as_throttled(settings_kratos: Settings) -> None:
    """A 200 that carries a page, not the flow document, reads the same way."""
    auth = KratosAuth(settings_kratos)
    try:
        with respx.mock(base_url="https://so.example.com") as mock:
            mock.get("/auth/self-service/login/browser").mock(
                return_value=httpx.Response(
                    200, text="<html>login</html>", headers={"content-type": "text/html"}
                )
            )
            with pytest.raises(SoAuthError) as excinfo:
                await auth.login()
        msg = str(excinfo.value)
        assert "SO throttled the login" in msg
        assert "200" in msg
        assert "Expecting value" not in msg
    finally:
        await auth.aclose()


@pytest.mark.asyncio
async def test_kratos_login_bad_credentials(
    settings_kratos: Settings, kratos_init: dict[str, Any]
) -> None:
    auth = KratosAuth(settings_kratos)
    try:
        with respx.mock(base_url="https://so.example.com") as mock:
            mock.get("/auth/self-service/login/browser").mock(
                return_value=httpx.Response(200, json=kratos_init, headers=_CSRF_COOKIE_HEADERS)
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
async def test_kratos_login_without_a_session_cookie_fails(
    settings_kratos: Settings, kratos_init: dict[str, Any]
) -> None:
    """A 200 that sets no session cookie is not a session. Say so."""
    auth = KratosAuth(_forced(settings_kratos, "browser"))
    try:
        with respx.mock(base_url="https://so.example.com") as mock:
            mock.get("/auth/self-service/login/browser").mock(
                return_value=httpx.Response(200, json=kratos_init, headers=_CSRF_COOKIE_HEADERS)
            )
            mock.post("/auth/self-service/login").mock(
                return_value=httpx.Response(200, json={"session": {"id": "s1"}})
            )
            with pytest.raises(SoAuthError, match="set no session cookie"):
                await auth.login()
        assert auth._logged_in is False
    finally:
        await auth.aclose()


@pytest.mark.asyncio
async def test_kratos_login_init_error(settings_kratos: Settings) -> None:
    auth = KratosAuth(settings_kratos)
    try:
        with respx.mock(base_url="https://so.example.com") as mock:
            mock.get("/auth/self-service/login/browser").mock(
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
            routes = _mock_browser_login(mock, kratos_init)
            data_call = mock.get("/connect/case").mock(return_value=httpx.Response(200, json=[]))

            resp = await auth.request("GET", "/connect/case")
        assert resp.status_code == 200
        assert routes["init"].called
        assert routes["submit"].called
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
            _mock_browser_login(mock, kratos_init)

            resp = await auth.request("GET", "/connect/case")
        assert resp.status_code == 200
        assert auth._refusal_count == 0  # the new session was accepted
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
            routes = _mock_browser_login(mock, kratos_init)
            await asyncio.gather(auth.login(), auth.login(), auth.login())
        assert routes["init"].call_count == 1
        assert routes["submit"].call_count == 1
    finally:
        await auth.aclose()


@pytest.mark.asyncio
async def test_kratos_concurrent_401s_cost_one_login(
    settings_kratos: Settings, kratos_init: dict[str, Any]
) -> None:
    """Ten in-flight reads on one expired session make ONE login, not ten.

    The 401s land a few milliseconds apart. The first one replaces the
    session; the rest must retry with that fresh cookie rather than throw it
    away and log in again, which would cost a login per in-flight read on
    every expiry and feed SO's login throttling.
    """
    auth = KratosAuth(_forced(settings_kratos, "browser"))
    auth._logged_in = True  # a session that has expired: no cookie in the jar
    try:
        with respx.mock(base_url="https://so.example.com") as mock:
            routes = _mock_browser_login(mock, kratos_init)
            answered = 0

            async def answer(request: httpx.Request) -> httpx.Response:
                nonlocal answered
                answered += 1
                await asyncio.sleep(0.004 * answered)
                if "ory_kratos_session" in request.headers.get("cookie", ""):
                    return httpx.Response(200, json=[])
                return httpx.Response(401, text="session expired")

            mock.get("/connect/case").mock(side_effect=answer)

            responses = await asyncio.gather(
                *(auth.request("GET", "/connect/case") for _ in range(10))
            )

            assert [r.status_code for r in responses] == [200] * 10
            assert routes["submit"].call_count == 1
        assert auth._refusal_count == 0
    finally:
        await auth.aclose()


# =====================================================================
# The ceiling on the login loop
#
# SO 3.3 answered 401 to every call on a session Kratos had just issued.
# The client re-logged in on every 401 with no ceiling: 32,420 throttled
# logins in three days, 75,800 SO warnings, and a SO audit index sixteen
# times its normal size. A refused session must stop the loop, not feed it.
# =====================================================================


@pytest.mark.asyncio
async def test_kratos_refused_session_stops_the_login_loop(
    settings_kratos: Settings, kratos_init: dict[str, Any], caplog: pytest.LogCaptureFixture
) -> None:
    """SOC refuses the fresh session. soc-ai logs in ONCE, then holds."""
    auth = KratosAuth(_forced(settings_kratos, "browser"))
    try:
        with (
            respx.mock(base_url="https://so.example.com") as mock,
            caplog.at_level(logging.ERROR, logger="soc_ai.so_client.auth"),
        ):
            routes = _mock_browser_login(mock, kratos_init, info_status=401)
            data_call = mock.get("/connect/case").mock(
                return_value=httpx.Response(401, text="The request could not be processed.")
            )

            first = await auth.request("GET", "/connect/case")
            second = await auth.request("GET", "/connect/case")
            third = await auth.request("GET", "/connect/case")

            assert first.status_code == 401
            assert second.status_code == 401
            assert third.status_code == 401
            # One login for three refused calls, not one login per call.
            assert routes["init"].call_count == 1
            assert routes["submit"].call_count == 1
            assert data_call.call_count == 3
        assert auth._refusal_count == 1
        assert auth._session_is_held() is True
        assert any(
            "SOC refused the Security Onion session" in r.getMessage() for r in caplog.records
        ), caplog.text
    finally:
        await auth.aclose()


@pytest.mark.asyncio
async def test_kratos_held_write_makes_one_request(
    settings_kratos: Settings, kratos_init: dict[str, Any]
) -> None:
    """During the hold a write costs ONE request, not a login and a probe.

    The proactive srv-token refresh would otherwise ask /api/info on every
    write, get the same 401, and extend the hold for a fault already reported.
    """
    auth = KratosAuth(_forced(settings_kratos, "browser"))
    try:
        with respx.mock(base_url="https://so.example.com") as mock:
            routes = _mock_browser_login(mock, kratos_init, info_status=401)
            ack = mock.post("/api/events/ack").mock(
                return_value=httpx.Response(401, text="The request could not be processed.")
            )

            await auth.request("POST", "/api/events/ack", json={})
            calls_after_first = len(mock.calls)
            await auth.request("POST", "/api/events/ack", json={})

            assert len(mock.calls) - calls_after_first == 1
            assert ack.call_count == 2
            assert routes["info"].call_count == 1  # the login probe only
        assert auth._refusal_count == 1
    finally:
        await auth.aclose()


@pytest.mark.asyncio
async def test_kratos_login_is_held_while_the_backoff_runs(settings_kratos: Settings) -> None:
    """Inside the hold, login() names the cause and makes no HTTP call."""
    auth = KratosAuth(settings_kratos)
    try:
        auth._session_refused("test")
        with respx.mock(base_url="https://so.example.com", assert_all_called=False) as mock:
            init = mock.get("/auth/self-service/login/browser").mock(
                return_value=httpx.Response(200, json={})
            )
            with pytest.raises(SoAuthError) as excinfo:
                await auth.login()
            assert init.call_count == 0
        msg = str(excinfo.value)
        assert "SOC refused the last session" in msg
        assert "Check the SO version and the login flow" in msg
    finally:
        await auth.aclose()


def test_kratos_backoff_doubles_to_a_ceiling(settings_kratos: Settings) -> None:
    """30s, doubling, capped at ten minutes."""
    auth = KratosAuth(settings_kratos)
    delays = []
    for _ in range(8):
        before = time.monotonic()
        auth._session_refused("test")
        delays.append(round(auth._refusal_until - before))
    assert delays == [30, 60, 120, 240, 480, 600, 600, 600]


@pytest.mark.asyncio
async def test_kratos_accepted_call_clears_the_hold(
    settings_kratos: Settings, kratos_init: dict[str, Any]
) -> None:
    """When SOC accepts a call again, the counter and the hold reset."""
    auth = KratosAuth(settings_kratos)
    auth._logged_in = True
    auth._srv_token = "srv-old"
    auth._srv_token_at = time.monotonic()
    auth._session_refused("test")
    assert auth._session_is_held() is True
    try:
        with respx.mock(base_url="https://so.example.com") as mock:
            mock.get("/connect/case").mock(return_value=httpx.Response(200, json=[]))
            resp = await auth.request("GET", "/connect/case")
        assert resp.status_code == 200
        assert auth._refusal_count == 0
        assert auth._session_is_held() is False
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


def test_elastic_client_uses_ca_bundle_when_set(settings_kratos: Settings) -> None:
    """F70: a pinned CA bundle path is passed through to AsyncElasticsearch,
    mirroring the SO (so_ca_bundle) and MISP (misp_ca_bundle) clients."""
    from pathlib import Path

    settings_kratos.es_ca_bundle = Path("/etc/ssl/es-ca.pem")
    with patch("soc_ai.so_client.elastic.AsyncElasticsearch") as mock_es:
        ElasticClient(settings_kratos)
    _, kwargs = mock_es.call_args
    assert kwargs["ca_certs"] == "/etc/ssl/es-ca.pem"


def test_elastic_client_no_ca_bundle_by_default(settings_kratos: Settings) -> None:
    with patch("soc_ai.so_client.elastic.AsyncElasticsearch") as mock_es:
        ElasticClient(settings_kratos)
    _, kwargs = mock_es.call_args
    assert kwargs.get("ca_certs") is None


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
# G1: a partially-failed search must not read as a quiet grid
#
# ES defaults `allow_partial_search_results=true`: shards that failed or
# timed out come back as HTTP 200 with partial (often zero) hits. The HEALTHY
# shapes below must stay silent — `ignore_unavailable` / `allow_no_indices`
# exist so a single-node grid and a fresh index return empty rather than 500.
# =====================================================================


def _es_returning(response: dict[str, Any]) -> AsyncMock:
    fake_es = AsyncMock()
    fake_es.search.return_value = response
    return fake_es


_HEALTHY_SHAPES: dict[str, dict[str, Any]] = {
    # A normal single-node grid: one shard, all successful.
    "single_node_success": {
        "took": 4,
        "timed_out": False,
        "_shards": {"total": 1, "successful": 1, "skipped": 0, "failed": 0},
        "hits": {"total": {"value": 3, "relation": "eq"}, "hits": [{"_id": "a"}]},
    },
    # A both-shapes pattern whose `*:logs-*` half matches no index on a grid
    # with no remote clusters — resolves to zero shards, which is not a failure.
    "no_index_matched": {
        "took": 0,
        "timed_out": False,
        "_shards": {"total": 0, "successful": 0, "skipped": 0, "failed": 0},
        "hits": {"total": {"value": 0, "relation": "eq"}, "hits": []},
    },
    # can_match / frozen-tier shards legitimately skipped: still a complete read.
    "shards_skipped": {
        "took": 9,
        "timed_out": False,
        "_shards": {"total": 5, "successful": 5, "skipped": 3, "failed": 0},
        "hits": {"total": {"value": 1, "relation": "eq"}, "hits": [{"_id": "b"}]},
    },
    # Test stubs and the demo replay fixtures carry no `_shards` key at all.
    "no_shards_key": {
        "took": 1,
        "hits": {"total": {"value": 2, "relation": "eq"}, "hits": [{"_id": "c"}]},
    },
}


@pytest.mark.parametrize("shape", sorted(_HEALTHY_SHAPES))
@pytest.mark.asyncio
async def test_elastic_search_healthy_shapes_never_raise(
    settings_kratos: Settings, shape: str
) -> None:
    """The single-node / empty-pattern / no-metadata responses stay untouched.

    This is the regression guard on the fix, not on the bug: the owner runs a
    single-node grid, and partial-result detection must not turn an ordinary
    empty answer into an outage.
    """
    response = _HEALTHY_SHAPES[shape]
    with patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=_es_returning(response)):
        client = ElasticClient(settings_kratos)
        result = await client.search("logs-*,*:logs-*", {"match_all": {}})

    assert isinstance(result, EsSearchResult)
    assert result.total == response["hits"]["total"]["value"]
    assert len(result.hits) == len(response["hits"]["hits"])


@pytest.mark.asyncio
async def test_elastic_search_raises_when_shards_failed(settings_kratos: Settings) -> None:
    """2 of 5 shards failed → GridPartialResultsError, not an empty result.

    Asserted on the RAISE. A test that only checked a `shards_failed` field
    would still pass if a refactor kept the field and dropped the raise — which
    is exactly the false-green shape this defect already shipped once.
    """
    response = {
        "took": 12,
        "timed_out": False,
        "_shards": {
            "total": 5,
            "successful": 3,
            "skipped": 0,
            "failed": 2,
            "failures": [
                {
                    "shard": 1,
                    "index": "logs-2026.08.13",
                    "reason": {
                        "type": "no_shard_available_action_exception",
                        "reason": "no shard available for [logs-2026.08.13]",
                    },
                }
            ],
        },
        "hits": {"total": {"value": 0, "relation": "eq"}, "hits": []},
    }
    with patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=_es_returning(response)):
        client = ElasticClient(settings_kratos)
        with pytest.raises(GridPartialResultsError) as excinfo:
            await client.search("logs-*", {"match_all": {}})

    exc = excinfo.value
    assert exc.shards_failed == 2
    assert exc.shards_total == 5
    assert "no_shard_available_action_exception" in str(exc)


@pytest.mark.asyncio
async def test_elastic_search_raises_when_timed_out(settings_kratos: Settings) -> None:
    """`timed_out: true` with zero failed shards is still an incomplete read."""
    response = {
        "took": 30_000,
        "timed_out": True,
        "_shards": {"total": 5, "successful": 5, "skipped": 0, "failed": 0},
        "hits": {"total": {"value": 7, "relation": "eq"}, "hits": [{"_id": "a"}]},
    }
    with patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=_es_returning(response)):
        client = ElasticClient(settings_kratos)
        with pytest.raises(GridPartialResultsError) as excinfo:
            await client.search("logs-*", {"match_all": {}})

    assert excinfo.value.timed_out is True
    assert "timed out" in str(excinfo.value)


def test_grid_partial_results_is_a_transport_error() -> None:
    """The subclassing IS the fix: every existing `(TimeoutError, TransportError)`
    arm maps a partial read to the house 503 `grid_unavailable` with no edits,
    and the agent tool boundary renders it as a structured error dict."""
    assert issubclass(GridPartialResultsError, TransportError)
    exc = GridPartialResultsError("partial", shards_failed=1, shards_total=2)
    caught = False
    try:
        raise exc
    except (TimeoutError, TransportError):
        caught = True
    assert caught


@pytest.mark.asyncio
async def test_elastic_search_partial_opt_out_keeps_results_and_warns(
    settings_kratos: Settings, caplog: pytest.LogCaptureFixture
) -> None:
    """es_fail_on_partial_results=False → the operator knowingly reads partial
    data; results come back and the degradation is logged at WARNING."""
    settings_kratos.es_fail_on_partial_results = False
    response = {
        "took": 12,
        "timed_out": True,
        "_shards": {
            "total": 5,
            "successful": 3,
            "skipped": 0,
            "failed": 2,
            "failures": [{"reason": {"type": "shard_not_available", "reason": "recovering"}}],
        },
        "hits": {"total": {"value": 4, "relation": "eq"}, "hits": [{"_id": "a"}]},
    }
    with (
        patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=_es_returning(response)),
        caplog.at_level(logging.WARNING, logger="soc_ai.so_client.elastic"),
    ):
        client = ElasticClient(settings_kratos)
        result = await client.search("logs-*", {"match_all": {}})

    assert result.total == 4
    assert len(result.hits) == 1
    assert any(
        record.levelno == logging.WARNING and "partial" in record.getMessage().lower()
        for record in caplog.records
    ), caplog.text


def test_partial_results_opt_out_is_config_console_visible() -> None:
    """The opt-out is an admin-editable setting, not an env-only escape hatch."""
    from soc_ai.store.config_overrides import WHITELIST_BY_KEY

    spec = WHITELIST_BY_KEY["es_fail_on_partial_results"]
    assert spec.type == "bool"
    assert spec.hot is True  # read per search off the live Settings object
    assert Settings.model_fields["es_fail_on_partial_results"].default is True


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
    auth._srv_token = "test-srv-token"
    auth._srv_token_at = time.monotonic()

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
    auth._srv_token = "test-srv-token"
    auth._srv_token_at = time.monotonic()

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


# =====================================================================
# srv-token TTL refresh — SO 3.0 expires the CSRF srv-token after 600s
# and signals expiry with a generic 400 (not 401), so KratosAuth must
# refresh proactively on age and reactively on the 400 sentinel.
# =====================================================================


def _primed_kratos(settings: Settings) -> KratosAuth:
    """KratosAuth with an established fake session (login bypassed)."""
    auth = KratosAuth(settings)
    auth._logged_in = True
    auth._srv_token = "srv-old"
    auth._srv_token_at = time.monotonic()  # fresh by default
    return auth


@pytest.mark.asyncio
async def test_kratos_stale_srv_token_refreshed_before_write(
    settings_kratos: Settings,
) -> None:
    """A write issued after the TTL re-fetches /api/info BEFORE sending."""
    auth = _primed_kratos(settings_kratos)
    auth._srv_token_at = time.monotonic() - (_SRV_TOKEN_TTL_S + 60)  # stale

    calls: list[tuple[str, str, dict[str, Any]]] = []

    async def fake_request(method: str, url: str, **kwargs: Any) -> httpx.Response:
        calls.append((method.upper(), url, dict(kwargs.get("headers") or {})))
        req = httpx.Request(method, "http://x")
        if url == "/api/info":
            return httpx.Response(200, json={"srvToken": "srv-new"}, request=req)
        return httpx.Response(200, json={}, request=req)

    auth._client.request = fake_request  # type: ignore[method-assign]

    resp = await auth.request("POST", "/api/events/ack", json={})

    assert resp.status_code == 200
    assert [(m, u) for m, u, _ in calls] == [
        ("GET", "/api/info"),  # proactive refresh fires first
        ("POST", "/api/events/ack"),
    ]
    assert calls[1][2].get("X-Srv-Token") == "srv-new"  # write carries new token
    assert auth._srv_token == "srv-new"
    assert time.monotonic() - auth._srv_token_at < _SRV_TOKEN_TTL_S  # timestamp reset
    await auth.aclose()


@pytest.mark.asyncio
async def test_kratos_400_sentinel_refreshes_and_retries_once(
    settings_kratos: Settings,
) -> None:
    """400 'The request could not be processed' → ONE refresh + ONE retry."""
    auth = _primed_kratos(settings_kratos)  # fresh token → no proactive refresh

    posts = 0
    info_fetches = 0
    post_headers: list[dict[str, Any]] = []

    async def fake_request(method: str, url: str, **kwargs: Any) -> httpx.Response:
        nonlocal posts, info_fetches
        req = httpx.Request(method, "http://x")
        if url == "/api/info":
            info_fetches += 1
            return httpx.Response(200, json={"srvToken": "srv-new"}, request=req)
        posts += 1
        post_headers.append(dict(kwargs.get("headers") or {}))
        if posts == 1:
            return httpx.Response(400, text="The request could not be processed.", request=req)
        return httpx.Response(200, json={"acknowledged": True}, request=req)

    auth._client.request = fake_request  # type: ignore[method-assign]

    resp = await auth.request("POST", "/api/events/ack", json={}, headers={"X-Custom": "keep-me"})

    assert resp.status_code == 200  # the retry's success is what's returned
    assert info_fetches == 1  # exactly one srv-token refresh
    assert posts == 2  # exactly one retry
    # Caller headers were snapshotted before the first send and survive the retry.
    assert post_headers[0].get("X-Custom") == "keep-me"
    assert post_headers[1].get("X-Custom") == "keep-me"
    assert post_headers[1].get("X-Srv-Token") == "srv-new"  # retry uses new token
    await auth.aclose()


@pytest.mark.asyncio
async def test_kratos_persistent_400_retries_only_once(settings_kratos: Settings) -> None:
    """If the retry also 400s, return it — no refresh/retry loop."""
    auth = _primed_kratos(settings_kratos)

    posts = 0
    info_fetches = 0

    async def fake_request(method: str, url: str, **kwargs: Any) -> httpx.Response:
        nonlocal posts, info_fetches
        req = httpx.Request(method, "http://x")
        if url == "/api/info":
            info_fetches += 1
            return httpx.Response(200, json={"srvToken": "srv-new"}, request=req)
        posts += 1
        return httpx.Response(400, text="The request could not be processed.", request=req)

    auth._client.request = fake_request  # type: ignore[method-assign]

    resp = await auth.request("POST", "/api/events/ack", json={})

    assert resp.status_code == 400
    assert posts == 2  # first send + exactly one retry
    assert info_fetches == 1  # exactly one refresh
    await auth.aclose()


@pytest.mark.asyncio
async def test_kratos_fresh_write_skips_refresh(settings_kratos: Settings) -> None:
    """A normal 2xx write with a fresh srv-token triggers no extra refresh."""
    auth = _primed_kratos(settings_kratos)

    calls: list[str] = []

    async def fake_request(method: str, url: str, **kwargs: Any) -> httpx.Response:
        calls.append(url)
        return httpx.Response(200, json={}, request=httpx.Request(method, "http://x"))

    auth._client.request = fake_request  # type: ignore[method-assign]

    resp = await auth.request("POST", "/api/events/ack", json={})

    assert resp.status_code == 200
    assert calls == ["/api/events/ack"]  # no /api/info fetch, no retry
    assert auth._srv_token == "srv-old"
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


# =====================================================================
# Demo-mode egress guard (SO API client is loopback-only)
# =====================================================================


@pytest.mark.asyncio
async def test_so_auth_loopback_only_in_demo(settings_kratos: Settings) -> None:
    """Demo mode: the SO API client may only target loopback (the bundled mock)."""
    with pytest.raises(DemoEgressBlocked):
        KratosAuth(settings_kratos.model_copy(update={"soc_ai_demo": True}))
    ok = KratosAuth(
        settings_kratos.model_copy(
            update={"soc_ai_demo": True, "so_host": "https://127.0.0.1:8443"}
        )
    )
    await ok.aclose()


# =====================================================================
# Picking a login flow: so_login_flow = auto | browser | api
#
# SO 3.3 refuses the API-flow session token. SO 2.4 and SO 3.0 to 3.2
# accept both flows, and an older grid can serve no browser flow at all.
# One build must work on every release, so "auto" runs the browser flow
# and falls back. A wrong password is not a reason to fall back: the same
# password fails on both flows.
# =====================================================================

_API_FLOW: dict[str, Any] = {
    "id": "flow-api-9",
    "type": "api",
    "ui": {
        "action": "https://so.example.com/auth/self-service/login?flow=flow-api-9",
        "method": "POST",
        "nodes": [
            {"attributes": {"name": "identifier", "type": "text"}},
            {"attributes": {"name": "password", "type": "password"}},
            {"attributes": {"name": "method", "type": "submit", "value": "password"}},
        ],
    },
}
_API_TOKEN = "api-session-token-1"


def _mock_api_login(mock: respx.MockRouter, *, info_status: int = 200) -> dict[str, Any]:
    """Route the three calls an API-flow login makes."""
    return {
        "init": mock.get("/auth/self-service/login/api").mock(
            return_value=httpx.Response(200, json=_API_FLOW)
        ),
        "submit": mock.post("/auth/self-service/login", params={"flow": _API_FLOW["id"]}).mock(
            return_value=httpx.Response(
                200, json={"session_token": _API_TOKEN, "session": {"id": "s2"}}
            )
        ),
        "info": mock.get("/api/info", headers={"X-Session-Token": _API_TOKEN}).mock(
            return_value=httpx.Response(
                info_status,
                json={"srvToken": "srv-api", "version": "3.0.0"}
                if info_status == 200
                else {"error": "unauthorized"},
            )
        ),
    }


def _mock_browser_only(
    mock: respx.MockRouter, flow: dict[str, Any], *, info_status: int = 200
) -> dict[str, Any]:
    """The browser half of a two-flow grid, keyed on its own flow id."""
    return {
        "init": mock.get("/auth/self-service/login/browser").mock(
            return_value=httpx.Response(200, json=flow, headers=_CSRF_COOKIE_HEADERS)
        ),
        "submit": mock.post("/auth/self-service/login", params={"flow": flow["id"]}).mock(
            return_value=httpx.Response(
                200, json={"session": {"id": "s1"}}, headers=_SESSION_COOKIE_HEADERS
            )
        ),
        "info": mock.get("/api/info").mock(
            return_value=httpx.Response(
                info_status,
                json={"srvToken": "srv-browser", "version": "3.3.0"}
                if info_status == 200
                else {"error": "unauthorized"},
            )
        ),
    }


@pytest.mark.asyncio
async def test_auto_picks_the_browser_flow_on_a_modern_grid(
    settings_kratos: Settings, kratos_init: dict[str, Any]
) -> None:
    """An SO 3.3-shaped Kratos completes the browser flow. Nothing else runs."""
    auth = KratosAuth(settings_kratos)  # the default is auto
    try:
        with respx.mock(base_url="https://so.example.com", assert_all_called=False) as mock:
            api = _mock_api_login(mock)
            _mock_browser_only(mock, kratos_init)

            await auth.login()

            assert api["init"].call_count == 0
            assert api["submit"].call_count == 0
        assert auth.login_flow == "browser"
    finally:
        await auth.aclose()


@pytest.mark.asyncio
async def test_auto_falls_back_when_the_browser_endpoint_is_absent(
    settings_kratos: Settings, caplog: pytest.LogCaptureFixture
) -> None:
    """An older grid serves no browser flow. soc-ai runs the API flow."""
    auth = KratosAuth(settings_kratos)
    try:
        with (
            respx.mock(base_url="https://so.example.com") as mock,
            caplog.at_level(logging.INFO, logger="soc_ai.so_client.auth"),
        ):
            browser = mock.get("/auth/self-service/login/browser").mock(
                return_value=httpx.Response(404, text="not found")
            )
            api = _mock_api_login(mock)

            await auth.login()

            assert browser.call_count == 1
            assert api["init"].call_count == 1
        assert auth.login_flow == "api"
        assert auth._srv_token == "srv-api"
        assert any("SO login strategy: api" in r.getMessage() for r in caplog.records), caplog.text
    finally:
        await auth.aclose()


@pytest.mark.asyncio
async def test_auto_falls_back_when_the_flow_has_no_csrf_token(
    settings_kratos: Settings,
) -> None:
    """A flow document with no csrf_token node cannot be submitted."""
    auth = KratosAuth(settings_kratos)
    try:
        with respx.mock(base_url="https://so.example.com") as mock:
            mock.get("/auth/self-service/login/browser").mock(
                return_value=httpx.Response(
                    200,
                    json={"id": "flow-nocsrf", "type": "browser", "ui": {"nodes": []}},
                )
            )
            _mock_api_login(mock)

            await auth.login()
        assert auth.login_flow == "api"
    finally:
        await auth.aclose()


@pytest.mark.asyncio
async def test_auto_falls_back_when_soc_refuses_the_cookie_session(
    settings_kratos: Settings, kratos_init: dict[str, Any]
) -> None:
    """The decisive case on SO 2.4 and 3.0 to 3.2.

    The browser login completes and SOC answers 401 to the cookie session,
    while the same account's API-flow session answers 200. The fallback is
    decided on /api/info, which is the read every write path depends on.
    """
    auth = KratosAuth(settings_kratos)
    try:
        with respx.mock(base_url="https://so.example.com") as mock:
            api = _mock_api_login(mock)  # first: matches on the token header
            browser = _mock_browser_only(mock, kratos_init, info_status=401)

            await auth.login()

            assert browser["init"].call_count == 1
            assert browser["submit"].call_count == 1
            assert api["submit"].call_count == 1
        assert auth.login_flow == "api"
        assert auth._srv_token == "srv-api"
        assert auth._refusal_count == 0  # a fallback is not a refusal
    finally:
        await auth.aclose()


@pytest.mark.asyncio
async def test_auto_does_not_fall_back_on_a_wrong_password(
    settings_kratos: Settings, kratos_init: dict[str, Any]
) -> None:
    """The same password fails on both flows. A second login proves nothing."""
    auth = KratosAuth(settings_kratos)
    try:
        with respx.mock(base_url="https://so.example.com", assert_all_called=False) as mock:
            mock.get("/auth/self-service/login/browser").mock(
                return_value=httpx.Response(200, json=kratos_init, headers=_CSRF_COOKIE_HEADERS)
            )
            mock.post("/auth/self-service/login", params={"flow": kratos_init["id"]}).mock(
                return_value=httpx.Response(400, json={"error": "credentials_invalid"})
            )
            api = _mock_api_login(mock)

            with pytest.raises(SoAuthError, match="rejected credentials"):
                await auth.login()

            assert api["init"].call_count == 0
            assert api["submit"].call_count == 0
        assert auth.login_flow is None
        assert auth._logged_in is False
    finally:
        await auth.aclose()


@pytest.mark.asyncio
async def test_browser_flow_forced_never_calls_the_api_endpoint(
    settings_kratos: Settings,
) -> None:
    auth = KratosAuth(_forced(settings_kratos, "browser"))
    try:
        with respx.mock(base_url="https://so.example.com", assert_all_called=False) as mock:
            mock.get("/auth/self-service/login/browser").mock(
                return_value=httpx.Response(404, text="not found")
            )
            api = _mock_api_login(mock)

            with pytest.raises(SoAuthError) as excinfo:
                await auth.login()

            assert api["init"].call_count == 0
        assert "browser flow could not complete" in str(excinfo.value)
        assert "404" in str(excinfo.value)
    finally:
        await auth.aclose()


@pytest.mark.asyncio
async def test_api_flow_forced_never_calls_the_browser_endpoint(
    settings_kratos: Settings, kratos_init: dict[str, Any]
) -> None:
    auth = KratosAuth(_forced(settings_kratos, "api"))
    try:
        with respx.mock(base_url="https://so.example.com", assert_all_called=False) as mock:
            browser = _mock_browser_only(mock, kratos_init)
            _mock_api_login(mock)

            await auth.login()

            assert browser["init"].call_count == 0
            assert browser["submit"].call_count == 0
        assert auth.login_flow == "api"
    finally:
        await auth.aclose()


@pytest.mark.asyncio
async def test_the_working_flow_is_remembered(
    settings_kratos: Settings, caplog: pytest.LogCaptureFixture
) -> None:
    """A fallback costs one extra login, not one for every request."""
    auth = KratosAuth(settings_kratos)
    try:
        with (
            respx.mock(base_url="https://so.example.com") as mock,
            caplog.at_level(logging.INFO, logger="soc_ai.so_client.auth"),
        ):
            browser = mock.get("/auth/self-service/login/browser").mock(
                return_value=httpx.Response(404, text="not found")
            )
            api = _mock_api_login(mock)

            await auth.login()
            auth._clear_session()  # the session dropped; log in again
            await auth.login()

            assert browser.call_count == 1  # not tried a second time
            assert api["init"].call_count == 2
        assert auth.login_flow == "api"
        # The strategy line names the flow once, at the first login SOC accepts.
        assert sum("SO login strategy:" in r.getMessage() for r in caplog.records) == 1
    finally:
        await auth.aclose()


@pytest.mark.asyncio
async def test_api_flow_sends_the_session_token_header(
    settings_kratos: Settings,
) -> None:
    """The API flow carries the token in a header; the jar holds no session."""
    auth = KratosAuth(_forced(settings_kratos, "api"))
    try:
        with respx.mock(base_url="https://so.example.com") as mock:
            _mock_api_login(mock)
            data_call = mock.get("/connect/case").mock(return_value=httpx.Response(200, json=[]))

            await auth.request("GET", "/connect/case")

            sent = data_call.calls[0].request
            assert sent.headers.get("x-session-token") == _API_TOKEN
        assert auth._has_session_cookie() is False
    finally:
        await auth.aclose()

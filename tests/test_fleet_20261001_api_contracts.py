"""Regression tests for the 2026-10-01 fleet dogfood: API contracts.

Each block names the finding it pins. The findings sit in the fleet report:
RA3 (junk setting values stored), A4/RA7 (unknown filter values dropped),
A8/RA13/A9/RA14 (error bodies and codes), A10/RA11/RA12 (bad_oql and 422
hints), H6/RO11/RO12/RO20/RA20 (backtest), A12 (fitness GET writes),
RA1/RD5/RC6/RC7/RA16 (health truth), A6/RA19/RA18 (body guards and CLI) and
RC8 (webhook store hint).
"""

from __future__ import annotations

import asyncio
from collections.abc import Iterator
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient
from soc_ai.config import Settings
from soc_ai.main import create_app
from soc_ai.store import config_overrides as cfg


def _client(settings: Settings) -> Iterator[TestClient]:
    fake_es = AsyncMock()
    fake_auth = AsyncMock()
    with (
        patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=fake_es),
        patch("soc_ai.main.make_auth", return_value=fake_auth),
        patch("soc_ai.main.get_settings", return_value=settings),
    ):
        app = create_app()
        with TestClient(app) as client:
            yield client


@pytest.fixture
def client(settings_kratos: Settings) -> Iterator[TestClient]:
    yield from _client(settings_kratos)


def _load_overrides(client: TestClient) -> dict[str, Any]:
    async def _read() -> dict[str, Any]:
        async with client.app.state.db_sessionmaker() as db:
            return await cfg.load_overrides(db)

    return asyncio.run(_read())


def _detail(resp: Any) -> dict[str, Any]:
    body = resp.json()
    assert isinstance(body.get("detail"), dict), body
    detail: dict[str, Any] = body["detail"]
    assert detail.get("reason"), body
    assert detail.get("hint"), body
    assert "—" not in detail["hint"] and "–" not in detail["hint"], detail["hint"]
    return detail


# ---------------------------------------------------------------------------
# RA3: a junk setting value is refused with the accepted values
# ---------------------------------------------------------------------------


def test_bool_setting_refuses_junk_and_stores_nothing(client: TestClient) -> None:
    before = client.app.state.settings.fast_triage_enabled
    r = client.post(
        "/api/v1/config/setting", json={"key": "fast_triage_enabled", "value": "notabool"}
    )
    assert r.status_code == 400, r.text
    d = _detail(r)
    assert d["reason"] == "invalid_value"
    assert "true" in d["hint"] and "false" in d["hint"]
    assert "fast_triage_enabled" not in _load_overrides(client)
    assert client.app.state.settings.fast_triage_enabled == before


def test_bool_setting_still_takes_the_checkbox_spellings() -> None:
    assert cfg.coerce("fast_triage_enabled", "on") is True
    assert cfg.coerce("fast_triage_enabled", "TRUE") is True
    assert cfg.coerce("fast_triage_enabled", "") is False
    assert cfg.coerce("fast_triage_enabled", "false") is False
    assert cfg.coerce("fast_triage_enabled", "off") is False


@pytest.mark.parametrize(
    ("key", "value", "expected"),
    [
        ("auto_triage_min_severity", "severe", "critical, high, medium, low"),
        ("notify_format", "xml", "json, slack, matrix"),
        ("synthesizer_output_mode", "freeform", "tool, native, prompted"),
    ],
)
def test_enumerated_setting_refusal_names_the_choices(
    client: TestClient, key: str, value: str, expected: str
) -> None:
    r = client.post("/api/v1/config/setting", json={"key": key, "value": value})
    assert r.status_code == 400, r.text
    d = _detail(r)
    assert d["reason"] == "invalid_value"
    assert expected in d["hint"]
    assert key not in _load_overrides(client)


def test_enumerated_setting_accepts_any_case() -> None:
    assert cfg.coerce("auto_triage_min_severity", " Medium ") == "medium"
    assert cfg.coerce("notify_format", "SLACK") == "slack"


def test_bounded_float_refuses_out_of_range(client: TestClient) -> None:
    r = client.post(
        "/api/v1/config/setting", json={"key": "dossier_min_confidence", "value": "1.6"}
    )
    assert r.status_code == 400, r.text
    d = _detail(r)
    assert d["reason"] == "out_of_range"
    assert "between 0.0 and 1.0" in d["hint"]
    assert "dossier_min_confidence" not in _load_overrides(client)


def test_bounded_int_refuses_out_of_range_and_junk(client: TestClient) -> None:
    r = client.post("/api/v1/config/setting", json={"key": "dossier_min_events", "value": "0"})
    assert r.status_code == 400
    d = _detail(r)
    assert d["reason"] == "out_of_range"
    assert "between 1 and 100000" in d["hint"]
    r = client.post("/api/v1/config/setting", json={"key": "dossier_min_events", "value": "1.5"})
    assert r.status_code == 400
    d = _detail(r)
    assert d["reason"] == "invalid_value"
    assert "whole number" in d["hint"]


def test_unknown_setting_carries_a_hint(client: TestClient) -> None:
    r = client.post("/api/v1/config/setting", json={"key": "no_such_key", "value": "1"})
    assert r.status_code == 400
    assert _detail(r)["reason"] == "unknown_setting"


# ---------------------------------------------------------------------------
# A4 / RA7: an unknown filter value is refused, never dropped
# ---------------------------------------------------------------------------


def _empty_page() -> Any:
    from types import SimpleNamespace

    return SimpleNamespace(groups=[], truncated=False, other_docs=0)


@pytest.mark.parametrize(
    ("url", "reason", "accepted"),
    [
        ("/api/v1/alerts?severity=garbage", "bad_severity", "critical, high"),
        ("/api/v1/alerts?range=garbage", "bad_range", "15m, 1h"),
        ("/api/v1/alerts?range=7days", "bad_range", "7d"),
        ("/api/v1/alerts?range=-1h", "bad_range", "24h"),
        ("/api/v1/alerts?range=0h", "bad_range", "24h"),
        ("/api/v1/alerts?sort=bogus", "bad_sort", "count, latest"),
        ("/api/v1/alerts?range=custom", "bad_time", "from and to"),
        ("/api/v1/alerts?from=2026-01-01T00:00:00Z", "bad_time", "from and to"),
        ("/api/v1/alerts/empty-reason?range=abc", "bad_range", "24h"),
        ("/api/v1/alerts/events?rule_name=x&range=abc", "bad_range", "24h"),
        ("/api/v1/alerts/events?rule_name=x&severity=nope", "bad_severity", "unknown"),
        ("/api/v1/alerts/representative?rule_name=x&range=abc", "bad_range", "24h"),
    ],
)
def test_unknown_alert_filter_values_are_refused(
    client: TestClient, url: str, reason: str, accepted: str
) -> None:
    fetch = AsyncMock(return_value=_empty_page())
    with patch("soc_ai.api.webui.routes_alerts.aq.fetch_groups", fetch):
        r = client.get(url)
    assert r.status_code == 422, r.text
    d = _detail(r)
    assert d["reason"] == reason
    assert accepted in d["hint"]
    fetch.assert_not_called()


@pytest.mark.parametrize(
    "url",
    [
        "/api/v1/alerts?range=7d&severity=high&sort=latest",
        "/api/v1/alerts?severity=unknown",
        "/api/v1/alerts?severity=",
        "/api/v1/alerts?range=custom&from=2026-01-01T00:00:00Z&to=2026-01-02T00:00:00Z",
        "/api/v1/alerts?from=2026-01-01T00:00:00Z&to=2026-01-02T00:00:00Z",
    ],
)
def test_known_alert_filter_values_still_pass(client: TestClient, url: str) -> None:
    """Negative control: every value the console sends still reaches the grid."""
    fetch = AsyncMock(return_value=_empty_page())
    with patch("soc_ai.api.webui.routes_alerts.aq.fetch_groups", fetch):
        r = client.get(url)
    assert r.status_code == 200, r.text
    fetch.assert_awaited_once()


def test_empty_rule_name_is_422_like_a_missing_one(client: TestClient) -> None:
    for url in ("/api/v1/alerts/events?rule_name=", "/api/v1/alerts/events?rule_name=%20"):
        r = client.get(url)
        assert r.status_code == 422, url
        assert "rule_name is required." in _detail(r)["hint"]
    r = client.get("/api/v1/alerts/events")
    assert r.status_code == 422
    assert _detail(r)["hint"] == "rule_name is required."


@pytest.mark.parametrize(
    ("url", "accepted"),
    [
        ("/api/v1/investigations?status=garbage", "running, complete"),
        ("/api/v1/investigations?status=complete,garbage", "running, complete"),
        ("/api/v1/investigations?verdict=garbage", "true_positive"),
        ("/api/v1/investigations?error_state=garbage", "live, handled"),
        ("/api/v1/leads?status=garbage", "needs_decision"),
    ],
)
def test_unknown_list_filters_are_refused(client: TestClient, url: str, accepted: str) -> None:
    r = client.get(url)
    assert r.status_code == 422, r.text
    d = _detail(r)
    assert d["reason"] == "bad_filter"
    assert accepted in d["hint"]


def test_known_list_filters_still_pass(client: TestClient) -> None:
    for url in (
        "/api/v1/investigations?status=complete,error&verdict=true_positive",
        "/api/v1/investigations?verdict=pipeline_error&error_state=live",
        "/api/v1/leads?status=needs_decision",
        "/api/v1/leads?status=all",
    ):
        assert client.get(url).status_code == 200, url


# ---------------------------------------------------------------------------
# A8 / RA13 / A9 / RA14: one error shape, the right status code
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("method", "url", "noun"),
    [
        ("get", "/api/v1/investigations/NOPE", "investigation"),
        ("get", "/api/v1/investigations/NOPE/export", "investigation"),
        ("get", "/api/v1/investigations/NOPE/chat", "investigation"),
        ("get", "/api/v1/hunts/NOPE", "hunt"),
        ("get", "/api/v1/hunts/NOPE/chat", "hunt"),
        ("get", "/api/v1/analyst/redaction-preview/NOPE", "investigation"),
        ("post", "/api/v1/investigations/NOPE/actions/0/execute", "investigation"),
    ],
)
def test_not_found_bodies_carry_a_hint(
    client: TestClient, method: str, url: str, noun: str
) -> None:
    r = getattr(client, method)(url)
    assert r.status_code == 404, r.text
    d = _detail(r)
    assert d["reason"] == "not_found"
    assert noun in d["hint"]


def test_unknown_api_route_has_the_shape(client: TestClient) -> None:
    r = client.get("/api/v1/no/such/route")
    assert r.status_code == 404
    assert _detail(r)["reason"] == "unknown_route"


def test_wrong_method_has_the_shape(client: TestClient) -> None:
    r = client.delete("/api/v1/alerts")
    assert r.status_code == 405
    assert _detail(r)["reason"] == "method_not_allowed"


def test_a_route_outside_the_api_keeps_its_own_404(client: TestClient) -> None:
    """Negative control: the shape rule is scoped to /api/v1."""
    r = client.get("/no-such-page")
    assert r.status_code == 404
    assert r.json() == {"detail": "Not Found"}


def test_invalid_verdict_carries_a_hint_and_the_list(client: TestClient) -> None:
    r = client.post("/api/v1/investigations/NOPE/override", json={"verdict": "maybe"})
    assert r.status_code == 400
    d = _detail(r)
    assert d["reason"] == "invalid_verdict"
    assert "true_positive" in d["hint"]
    assert "true_positive" in r.json()["detail"]["valid"]


def test_find_alert_without_a_filter_names_the_fields(client: TestClient) -> None:
    r = client.post("/find-alert", json={})
    assert r.status_code == 400
    d = _detail(r)
    assert d["reason"] == "no_filter"
    assert "rule_uuid" in d["hint"]


def test_dossier_for_a_non_address_is_400(client: TestClient) -> None:
    r = client.get("/api/v1/dossiers/not-an-ip")
    assert r.status_code == 400
    d = _detail(r)
    assert d["reason"] == "not_an_ip"
    assert d["hint"].endswith("Send an IPv4 or IPv6 address.")


def test_blank_entity_is_400(client: TestClient) -> None:
    r = client.get("/api/v1/entity/%20")
    assert r.status_code == 400
    assert _detail(r)["reason"] == "empty_entity"


def test_a_bare_string_detail_becomes_reason_and_hint() -> None:
    from soc_ai.main import _api_refusal_detail

    got = _api_refusal_detail(409, "a model battery is already running", "/api/v1/x", "POST")
    assert got == {"reason": "conflict", "hint": "A model battery is already running."}
    kept = _api_refusal_detail(400, {"reason": "r", "hint": "Own hint."}, "/api/v1/x", "GET")
    assert kept == {"reason": "r", "hint": "Own hint."}


# ---------------------------------------------------------------------------
# A10 / RA11 / RA12: bad_oql, bad_time and the 422 hints
# ---------------------------------------------------------------------------


def test_bad_oql_hint_names_the_column_and_token_without_the_parser_trace(
    client: TestClient,
) -> None:
    r = client.get("/api/v1/alerts", params={"q": "a:1 )"})
    assert r.status_code == 400
    d = _detail(r)
    assert d["reason"] == "bad_oql"
    assert d["hint"].startswith(
        "The filter has a syntax error at column 5 near ')'. Check the field name and the quotes."
    )
    for leak in ("Token(", "$END", "Expected one of", "LPAR", "e.g."):
        assert leak not in d["hint"]


def test_bad_oql_at_the_end_says_the_filter_ends_early(client: TestClient) -> None:
    r = client.get("/api/v1/alerts", params={"q": "a:("})
    d = _detail(r)
    assert d["hint"].startswith("The filter ends early at column 4.")
    assert "$END" not in d["hint"]


def test_pipe_hint_has_no_dash(client: TestClient) -> None:
    r = client.get("/api/v1/alerts", params={"q": "a:1 | groupby b"})
    assert r.status_code == 400
    assert "pipe" in _detail(r)["hint"]


def test_bad_from_is_bad_time(client: TestClient) -> None:
    r = client.get("/api/v1/alerts", params={"from": "yesterday", "to": "2026-01-02T00:00:00Z"})
    assert r.status_code == 400
    d = _detail(r)
    assert d["reason"] == "bad_time"
    assert "ISO 8601" in d["hint"]
    assert "(" not in d["hint"]


def test_the_mcp_query_tool_gets_the_same_sentence() -> None:
    from soc_ai.errors import OqlValidationError
    from soc_ai.so_client.oql import parse_oql

    with pytest.raises(OqlValidationError) as info:
        parse_oql("event.dataset:zeek.conn AND )")
    assert "Token(" not in str(info.value)
    assert "syntax error at column" in str(info.value)


def test_validation_hint_for_a_body_that_is_not_json(client: TestClient) -> None:
    r = client.post("/api/v1/login", content=b"{nope", headers={"content-type": "application/json"})
    assert r.status_code == 422
    assert _detail(r)["hint"] == "The body is not valid JSON."


def test_validation_hint_for_missing_fields(client: TestClient) -> None:
    r = client.post("/api/v1/login", json={})
    assert r.status_code == 422
    assert _detail(r)["hint"] == "username is required. password is required."


def test_validation_hint_for_a_whole_number(client: TestClient) -> None:
    r = client.get("/api/v1/hunts/leads/abc")
    assert r.status_code == 422
    assert _detail(r)["hint"] == "lead_id must be a whole number."


# ---------------------------------------------------------------------------
# A12: a plain GET of model fitness never probes
# ---------------------------------------------------------------------------


def test_a_plain_fitness_get_with_no_cache_runs_no_probe(client: TestClient) -> None:
    probe = AsyncMock(return_value={"grade": "pass", "model": "m", "legs": [], "detail": "ok"})
    with patch("soc_ai.webui.probes.probe_model_fitness", probe):
        body = client.get("/api/v1/config/model-fitness").json()
    probe.assert_not_awaited()
    assert body["grade"] == "unknown"
    assert body["measured"] is False


# ---------------------------------------------------------------------------
# RA1 / RD5 / RC6 / RC7 / RA16: health truth
# ---------------------------------------------------------------------------


def _health_settings(settings_kratos: Settings) -> Settings:
    return settings_kratos.model_copy(update={"webui_grid_timeout_s": 12})


def test_a_leg_that_answers_late_is_slow_not_ok(
    monkeypatch: pytest.MonkeyPatch, settings_kratos: Settings
) -> None:
    from soc_ai.api.webui import routes_meta

    monkeypatch.setattr(routes_meta, "_HEALTH_PROBE_LEG_TIMEOUT_S", 0.5)

    async def late() -> dict[str, Any]:
        await asyncio.sleep(0.4)
        return {"ok": True, "detail": "up"}

    async def fast() -> dict[str, Any]:
        return {"ok": True, "detail": "up"}

    settings = _health_settings(settings_kratos)
    slow = asyncio.run(routes_meta._bounded_probe(late(), "Elasticsearch", settings))
    assert slow["ok"] is False
    assert slow["state"] == "slow"
    assert slow["kind"] == "slow"
    assert slow["detail"].startswith("Elasticsearch answered the probe in")
    ok = asyncio.run(routes_meta._bounded_probe(fast(), "Elasticsearch", settings))
    assert ok["ok"] is True
    assert ok["state"] == "ok"


def test_a_leg_over_its_budget_is_slow_and_names_the_dependency(
    monkeypatch: pytest.MonkeyPatch, settings_kratos: Settings
) -> None:
    from soc_ai.api.webui import routes_meta

    monkeypatch.setattr(routes_meta, "_HEALTH_PROBE_LEG_TIMEOUT_S", 0.1)

    async def hangs() -> dict[str, Any]:
        await asyncio.sleep(10)
        return {"ok": True, "detail": "up"}

    got = asyncio.run(
        routes_meta._bounded_probe(hangs(), "Elasticsearch", _health_settings(settings_kratos))
    )
    assert got["ok"] is False
    assert got["state"] == "slow"
    assert got["detail"].startswith("Elasticsearch did not answer the probe in 0.1 s.")


def test_health_reports_when_it_was_checked(client: TestClient) -> None:
    from soc_ai.api.webui import routes_meta

    async def up(*_a: Any, **_k: Any) -> dict[str, Any]:
        return {"ok": True, "detail": "up"}

    with (
        patch.object(routes_meta.probes, "probe_es", up),
        patch.object(routes_meta.probes, "probe_llm", up),
        patch.object(routes_meta.probes, "probe_so_api", up),
    ):
        body = client.get("/api/v1/health").json()
    assert body["checked_at"].endswith("Z")
    assert body["age_s"] is not None and body["age_s"] >= 0
    assert body["es"]["state"] == "ok"
    assert "elapsed_ms" in body["es"]


def test_a_health_flip_drops_the_preflight_cache(
    monkeypatch: pytest.MonkeyPatch, settings_kratos: Settings
) -> None:
    from types import SimpleNamespace

    from soc_ai.api.webui import routes_meta

    es_ok = {"value": True}

    async def es(*_a: Any, **_k: Any) -> dict[str, Any]:
        return {"ok": es_ok["value"], "detail": "x"}

    async def up(*_a: Any, **_k: Any) -> dict[str, Any]:
        return {"ok": True, "detail": "up"}

    monkeypatch.setattr(routes_meta.probes, "probe_es", es)
    monkeypatch.setattr(routes_meta.probes, "probe_llm", up)
    monkeypatch.setattr(routes_meta.probes, "probe_so_api", up)
    monkeypatch.setattr(routes_meta, "_HEALTH_PROBE_TTL_S", 0.0)
    state = SimpleNamespace(elastic=object())
    settings = _health_settings(settings_kratos)

    asyncio.run(routes_meta._cached_health_probes(state, settings))
    state._preflight_cache = ("cached", "green")
    # Negative control: no flip keeps the preflight cache.
    asyncio.run(routes_meta._cached_health_probes(state, settings))
    assert state._preflight_cache == ("cached", "green")

    es_ok["value"] = False
    asyncio.run(routes_meta._cached_health_probes(state, settings))
    assert state._preflight_cache is None


def test_agent_tools_read_the_live_state() -> None:
    from soc_ai.api import agent_tools

    settings = Settings(
        so_host="https://so.example.test",
        so_username="analyst",
        so_password="pw",  # type: ignore[arg-type]
        es_hosts=["https://so.example.test:9200"],
        litellm_base_url="http://gateway.example.test:4000",
    )
    configured = {t.name: t for t in agent_tools.collect_agent_tools(settings)}
    assert configured["query_events_oql"].available is True
    down = {
        t.name: t
        for t in agent_tools.collect_agent_tools(
            settings, {"Elasticsearch": False, "Security Onion": True}
        )
    }
    tool = down["query_events_oql"]
    assert tool.available is False
    assert tool.unreachable == ["Elasticsearch"]
    assert "Elasticsearch" in tool.missing


def test_agent_tools_route_marks_es_tools_unavailable_when_health_is_down(
    client: TestClient,
) -> None:
    from soc_ai.api.webui import routes_meta

    async def down(*_a: Any, **_k: Any) -> dict[str, Any]:
        return {
            "es": {"ok": False, "detail": "down"},
            "llm": {"ok": True, "detail": "up"},
            "so": {"ok": False, "detail": "down"},
        }

    with patch.object(routes_meta, "_cached_health_probes", down):
        tools = client.get("/api/v1/config/agent-tools").json()["tools"]
    es_tools = [t for t in tools if "Elasticsearch" in t["requires"]]
    assert es_tools
    assert not any(t["available"] for t in es_tools)


def test_one_probe_budget_for_the_pill_test_es_and_the_doctor() -> None:
    from soc_ai import doctor
    from soc_ai.api.webui import routes_meta
    from soc_ai.webui import probes

    assert routes_meta._HEALTH_PROBE_LEG_TIMEOUT_S == probes.PROBE_BUDGET_S
    assert int(probes.PROBE_BUDGET_S) == doctor._ES_REQUEST_TIMEOUT_S


def test_test_es_waits_the_shared_budget_and_names_elasticsearch(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    import time

    from soc_ai.webui import probes

    monkeypatch.setattr(probes, "PROBE_BUDGET_S", 0.2)
    client.app.state.settings.webui_grid_timeout_s = 12

    async def hangs(*_a: Any, **_k: Any) -> dict[str, Any]:
        await asyncio.sleep(10)
        return {"ok": True, "detail": "up"}

    started = time.monotonic()
    with patch.object(probes, "probe_es", hangs):
        r = client.post("/api/v1/config/danger/test/es")
    assert time.monotonic() - started < 5
    body = r.json()
    assert body["ok"] is False
    assert body["detail"].startswith("Elasticsearch did not answer within 0.2 s.")


class _PingOkSearchTimesOut:
    def __init__(self, search_exc: Exception | None, ping_exc: Exception | None = None):
        self._search_exc = search_exc
        self._ping_exc = ping_exc

    async def ping(self) -> dict[str, Any]:
        if self._ping_exc is not None:
            raise self._ping_exc
        return {"cluster": "grid", "version": "8.14.3"}

    async def search(self, *_a: Any, **_k: Any) -> Any:
        raise self._search_exc  # type: ignore[misc]

    async def aclose(self) -> None:
        return None


def test_doctor_says_overloaded_when_the_ping_answers_and_the_search_times_out(
    settings_kratos: Settings,
) -> None:
    from elastic_transport import ConnectionTimeout
    from soc_ai import doctor

    stub = _PingOkSearchTimesOut(ConnectionTimeout("timed out"))
    with patch("soc_ai.doctor.ElasticClient", return_value=stub):
        rows = asyncio.run(doctor.check_elasticsearch(settings_kratos))
    row = rows[0]
    assert row.status == "FAIL"
    assert "the ping answered" in row.detail
    assert "timed out after 5 s" in row.detail
    assert "overloaded" in row.hint
    assert "ES_HOSTS" not in row.hint


def test_doctor_keeps_the_network_hint_when_the_base_url_does_not_answer(
    settings_kratos: Settings,
) -> None:
    from soc_ai import doctor

    stub = _PingOkSearchTimesOut(None, ping_exc=ConnectionError("connection refused"))
    with patch("soc_ai.doctor.ElasticClient", return_value=stub):
        rows = asyncio.run(doctor.check_elasticsearch(settings_kratos))
    row = rows[0]
    assert "no answer on the base URL" in row.detail
    assert "ES_HOSTS" in row.hint


# ---------------------------------------------------------------------------
# A6 / RA19 / RA18: body caps and CLI bounds
# ---------------------------------------------------------------------------


def test_a_large_declared_body_is_413_before_it_is_read(client: TestClient) -> None:
    body = b'{"hunt_ids": ["' + b"x" * (2 * 1024 * 1024) + b'"]}'
    r = client.post(
        "/api/v1/hunts/bulk-delete", content=body, headers={"content-type": "application/json"}
    )
    assert r.status_code == 413
    d = _detail(r)
    assert d["reason"] == "payload_too_large"
    assert "1 MiB" in d["hint"]


def test_a_large_chunked_body_is_413_too(client: TestClient) -> None:
    def chunks() -> Iterator[bytes]:
        yield b'{"hunt_ids": ["'
        for _ in range(40):
            yield b"x" * 65536
        yield b'"]}'

    r = client.post(
        "/api/v1/hunts/bulk-delete", content=chunks(), headers={"content-type": "application/json"}
    )
    assert r.status_code == 413
    assert _detail(r)["reason"] == "payload_too_large"


def test_a_small_chunked_body_still_reaches_the_route(client: TestClient) -> None:
    """Negative control: the cap replays a body under the limit unchanged."""

    def chunks() -> Iterator[bytes]:
        yield b'{"key": "no_such_key", '
        yield b'"value": "1"}'

    r = client.post(
        "/api/v1/config/setting", content=chunks(), headers={"content-type": "application/json"}
    )
    assert r.status_code == 400
    assert _detail(r)["reason"] == "unknown_setting"


def test_login_refuses_a_chunked_body_and_a_large_one(client: TestClient) -> None:
    def chunks() -> Iterator[bytes]:
        yield b'{"username": "admin", "password": "wrong"}'

    r = client.post("/api/v1/login", content=chunks(), headers={"content-type": "application/json"})
    assert r.status_code == 411
    big = b'{"username": "admin", "password": "' + b"x" * 9000 + b'"}'
    r = client.post("/api/v1/login", content=big, headers={"content-type": "application/json"})
    assert r.status_code == 413


@pytest.mark.parametrize(
    "argv",
    [
        ["soc-ai", "leads", "--report", "--weeks", "-3"],
        ["soc-ai", "leads", "--report", "--weeks", "0"],
        ["soc-ai", "priors", "--recent-hours", "0"],
        ["soc-ai", "priors", "--recent-hours", "-5"],
    ],
)
def test_cli_refuses_a_window_below_one(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], argv: list[str]
) -> None:
    from soc_ai import cli

    called: list[Any] = []
    monkeypatch.setattr(cli, "_leads", lambda args: called.append(args) or 0)
    monkeypatch.setattr(cli, "_priors", lambda args: called.append(args) or 0)
    monkeypatch.setattr("sys.argv", argv)
    with pytest.raises(SystemExit) as info:
        cli.main()
    assert info.value.code == 2
    assert called == []
    assert "Use a whole number of 1 or more." in capsys.readouterr().err


def test_cli_accepts_a_window_of_one(monkeypatch: pytest.MonkeyPatch) -> None:
    from soc_ai import cli

    called: list[Any] = []
    monkeypatch.setattr(cli, "_leads", lambda args: called.append(args) or 0)
    monkeypatch.setattr("sys.argv", ["soc-ai", "leads", "--report", "--weeks", "1"])
    with pytest.raises(SystemExit) as info:
        cli.main()
    assert info.value.code == 0
    assert called[0].weeks == 1


# ---------------------------------------------------------------------------
# RC8: the webhook panel can warn before a save
# ---------------------------------------------------------------------------


def test_webhook_get_says_a_save_cannot_store_without_a_secret_key(client: TestClient) -> None:
    client.app.state.secret_box = None
    body = client.get("/api/v1/config/notify/webhook").json()
    assert body["can_store"] is False
    assert "CONFIG_SECRET_KEY" in body["store_hint"]
    r = client.post("/api/v1/config/notify/webhook", json={"value": "https://hooks.example.test/x"})
    assert r.status_code == 400
    assert _detail(r)["hint"] == body["store_hint"]


def test_webhook_get_says_a_save_can_store_with_a_secret_key(client: TestClient) -> None:
    client.app.state.secret_box = object()
    body = client.get("/api/v1/config/notify/webhook").json()
    assert body["can_store"] is True
    assert body["store_hint"] is None

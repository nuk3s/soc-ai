"""Tests for E2.4 notification routing (:mod:`soc_ai.notify`).

EGRESS SAFETY is the whole point of this suite: httpx is ALWAYS mocked — no test
here ever makes a real outbound request. The load-bearing invariant is proven by
``test_disabled_makes_no_httpx_call``: with notifications off, ``fire`` returns
BEFORE constructing any httpx client, so no network I/O is even possible.

Every ``NotifyEvent`` and every ``settings`` here is synthetic. The canned test
event is asserted to contain NO internal identifier.
"""

from __future__ import annotations

from collections.abc import Iterator
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr
from soc_ai import notify
from soc_ai.config import Settings
from soc_ai.main import create_app


@pytest.fixture(autouse=True)
def _clear_dedup() -> Iterator[None]:
    """Each test starts with a fresh dedup ring so hour-bucketing is deterministic."""
    notify._dedup_seen.clear()
    yield
    notify._dedup_seen.clear()


def _settings(**overrides: Any) -> SimpleNamespace:
    """A minimal settings double for notify.fire (it only uses getattr)."""
    base: dict[str, Any] = {
        "notify_enabled": True,
        "notify_webhook_url": SecretStr("https://hooks.example.com/abc"),
        "notify_format": "json",
        "notify_verify_ssl": True,
        "notify_tp_confidence_threshold": 0.9,
        "notify_on_tp": True,
        "notify_on_hunt_threat": True,
        "notify_on_model_fitness_fail": True,
    }
    base.update(overrides)
    return SimpleNamespace(**base)


class _FakeResponse:
    def __init__(self, status_code: int) -> None:
        self.status_code = status_code


class _FakeClient:
    """An httpx.AsyncClient stand-in that records POSTs and returns a fixed status.

    Constructing one records the fact — a test can assert the client was NEVER
    built (the zero-egress proof) by patching ``httpx.AsyncClient`` with a
    MagicMock and asserting it wasn't called.
    """

    def __init__(self, status_code: int = 200) -> None:
        self._status = status_code
        self.posts: list[tuple[str, dict[str, Any]]] = []

    async def __aenter__(self) -> _FakeClient:
        return self

    async def __aexit__(self, *_a: Any) -> None:
        return None

    async def post(self, url: str, *, json: dict[str, Any]) -> _FakeResponse:
        self.posts.append((url, json))
        return _FakeResponse(self._status)


def _patch_client(client: _FakeClient) -> Any:
    """Patch httpx.AsyncClient in the notify module to yield *client*."""
    factory = MagicMock(return_value=client)
    return patch("soc_ai.notify.httpx.AsyncClient", factory), factory


# ── ZERO-EGRESS: disabled → no httpx call is ever made ────────────────────────


@pytest.mark.asyncio
async def test_disabled_makes_no_httpx_call() -> None:
    """THE guarantee: with notify_enabled=False, fire builds no client, sends nothing."""
    client = _FakeClient()
    ctx, factory = _patch_client(client)
    audit = AsyncMock()
    event = notify.NotifyEvent(kind="tp", title="t", body="b", url="/app/investigation/INV-1")
    with ctx:
        await notify.fire(event, _settings(notify_enabled=False), audit)
    factory.assert_not_called()  # no httpx.AsyncClient constructed → zero egress
    assert client.posts == []
    audit.log_kind.assert_not_called()  # nothing attempted → nothing audited


@pytest.mark.asyncio
async def test_no_url_makes_no_httpx_call() -> None:
    """Enabled but no webhook URL configured → still zero egress."""
    client = _FakeClient()
    ctx, factory = _patch_client(client)
    event = notify.NotifyEvent(kind="tp", title="t", body="b", url="/app/investigation/INV-1")
    with ctx:
        await notify.fire(event, _settings(notify_webhook_url=None), AsyncMock())
    factory.assert_not_called()
    assert client.posts == []


@pytest.mark.asyncio
async def test_per_trigger_toggle_off_makes_no_httpx_call() -> None:
    """Master on + url set, but the per-trigger toggle off → zero egress."""
    client = _FakeClient()
    ctx, factory = _patch_client(client)
    event = notify.NotifyEvent(kind="tp", title="t", body="b", url="/app/investigation/INV-1")
    with ctx:
        await notify.fire(event, _settings(notify_on_tp=False), AsyncMock())
    factory.assert_not_called()
    assert client.posts == []


# ── payload-per-format ────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_json_format_payload_and_audit() -> None:
    client = _FakeClient(200)
    ctx, _ = _patch_client(client)
    audit = AsyncMock()
    event = notify.NotifyEvent(
        kind="tp", title="High-confidence TP", body="conf 0.95", url="/app/investigation/INV-9"
    )
    with ctx:
        await notify.fire(event, _settings(notify_format="json"), audit)
    assert len(client.posts) == 1
    url, payload = client.posts[0]
    assert url == "https://hooks.example.com/abc"
    assert payload == {
        "kind": "tp",
        "title": "High-confidence TP",
        "body": "conf 0.95",
        "url": "/app/investigation/INV-9",
        "severity": "info",
    }
    # Audited — and the webhook URL is NEVER in the audit payload (it's a secret).
    audit.log_kind.assert_awaited_once()
    _a, kwargs = audit.log_kind.call_args
    assert kwargs["kind"] == "notification"
    assert kwargs["payload"]["notify_kind"] == "tp"
    assert kwargs["payload"]["ok"] is True
    assert "hooks.example.com" not in str(kwargs["payload"])


@pytest.mark.asyncio
async def test_slack_format_payload() -> None:
    client = _FakeClient(200)
    ctx, _ = _patch_client(client)
    event = notify.NotifyEvent(kind="tp", title="Title", body="Body", url="/app/x")
    with ctx:
        await notify.fire(event, _settings(notify_format="slack"), AsyncMock())
    _url, payload = client.posts[0]
    assert payload == {"text": "Title — Body /app/x"}


@pytest.mark.asyncio
async def test_matrix_format_payload() -> None:
    client = _FakeClient(200)
    ctx, _ = _patch_client(client)
    event = notify.NotifyEvent(kind="tp", title="Title", body="Body", url="/app/x")
    with ctx:
        await notify.fire(event, _settings(notify_format="matrix"), AsyncMock())
    _url, payload = client.posts[0]
    assert payload == {"msgtype": "m.text", "body": "Title — Body /app/x"}


# ── event builders: threshold + toggle gating ────────────────────────────────


def test_event_for_investigation_below_threshold_is_none() -> None:
    """A TP under the confidence threshold builds no event → no send."""
    report = {"verdict": "true_positive", "confidence": 0.7, "summary": "s"}
    assert (
        notify.event_for_investigation(
            investigation_id="INV-1", report=report, settings=_settings()
        )
        is None
    )


def test_event_for_investigation_toggle_off_is_none() -> None:
    report = {"verdict": "true_positive", "confidence": 0.99, "summary": "s"}
    assert (
        notify.event_for_investigation(
            investigation_id="INV-1", report=report, settings=_settings(notify_on_tp=False)
        )
        is None
    )


def test_event_for_investigation_non_tp_is_none() -> None:
    report = {"verdict": "false_positive", "confidence": 0.99}
    assert (
        notify.event_for_investigation(
            investigation_id="INV-1", report=report, settings=_settings()
        )
        is None
    )


def test_event_for_investigation_high_conf_tp_builds_event() -> None:
    report = {"verdict": "true_positive", "confidence": 0.95, "summary": "beacon to C2"}
    event = notify.event_for_investigation(
        investigation_id="INV-42", report=report, settings=_settings()
    )
    assert event is not None
    assert event.kind == "tp"
    assert event.url == "/app/investigation/INV-42"
    assert "0.95" in event.body


def test_event_for_hunt_threat_finding_builds_event() -> None:
    report = {
        "findings": [
            {"title": "benign", "category": "observation"},
            {"title": "C2 beacon", "category": "threat"},
        ],
        "narrative": "n",
    }
    event = notify.event_for_hunt(hunt_id="H-7", report=report, settings=_settings())
    assert event is not None
    assert event.kind == "hunt_threat"
    assert event.url == "/app/hunts/H-7"
    assert "C2 beacon" in event.body


def test_event_for_hunt_no_threat_is_none() -> None:
    report = {"findings": [{"title": "x", "category": "observation"}]}
    assert notify.event_for_hunt(hunt_id="H-1", report=report, settings=_settings()) is None


def test_event_for_model_fitness_fail_builds_event() -> None:
    result = {"grade": "fail", "model": "unfit-a3b", "detail": "structured_output=fail"}
    event = notify.event_for_model_fitness(result=result, settings=_settings())
    assert event is not None
    assert event.kind == "model_fitness_fail"
    assert "unfit-a3b" in event.title
    assert event.url == ""  # no permalink → dedup keys on the title


def test_event_for_model_fitness_pass_is_none() -> None:
    result = {"grade": "pass", "model": "m", "detail": "ok"}
    assert notify.event_for_model_fitness(result=result, settings=_settings()) is None


# ── fail-soft on a webhook 500 ───────────────────────────────────────────────


@pytest.mark.asyncio
async def test_webhook_500_is_fail_soft_and_audited() -> None:
    """A 5xx (after retries) never raises out of fire, and is audited as attempted."""
    client = _FakeClient(500)
    ctx, _ = _patch_client(client)
    audit = AsyncMock()
    event = notify.NotifyEvent(kind="tp", title="t", body="b", url="/app/investigation/INV-1")
    with ctx:
        await notify.fire(event, _settings(), audit)  # must not raise
    # Retried up to _MAX_RETRIES → _MAX_RETRIES + 1 total POSTs, all 500.
    assert len(client.posts) == notify._MAX_RETRIES + 1
    audit.log_kind.assert_awaited_once()
    _a, kwargs = audit.log_kind.call_args
    assert kwargs["payload"]["ok"] is False
    assert kwargs["payload"]["status"] == 500


@pytest.mark.asyncio
async def test_transport_error_is_fail_soft_and_audited() -> None:
    """A transport exception is swallowed (fail-soft) and audited with the error type."""

    class _BoomClient(_FakeClient):
        async def post(self, url: str, *, json: dict[str, Any]) -> _FakeResponse:
            raise RuntimeError("connection refused")

    client = _BoomClient()
    ctx, _ = _patch_client(client)
    audit = AsyncMock()
    event = notify.NotifyEvent(kind="tp", title="t", body="b", url="/app/investigation/INV-1")
    with ctx:
        await notify.fire(event, _settings(), audit)  # must not raise
    audit.log_kind.assert_awaited_once()
    _a, kwargs = audit.log_kind.call_args
    assert kwargs["payload"]["ok"] is False
    assert kwargs["payload"]["error"] == "RuntimeError"


@pytest.mark.asyncio
async def test_audit_failure_never_breaks_send() -> None:
    """A failing audit write must not raise out of fire (audit is best-effort)."""
    client = _FakeClient(200)
    ctx, _ = _patch_client(client)
    audit = AsyncMock()
    audit.log_kind.side_effect = RuntimeError("audit index down")
    event = notify.NotifyEvent(kind="tp", title="t", body="b", url="/app/x")
    with ctx:
        await notify.fire(event, _settings(), audit)  # must not raise
    assert len(client.posts) == 1  # the send still happened


# ── dedup: same (kind, entity, hour) → one send ──────────────────────────────


@pytest.mark.asyncio
async def test_dedup_same_event_same_hour_sends_once() -> None:
    client = _FakeClient(200)
    ctx, _ = _patch_client(client)
    event = notify.NotifyEvent(kind="tp", title="t", body="b", url="/app/investigation/INV-1")
    with ctx:
        await notify.fire(event, _settings(), AsyncMock())
        await notify.fire(event, _settings(), AsyncMock())  # identical → deduped
    assert len(client.posts) == 1


@pytest.mark.asyncio
async def test_dedup_distinct_entities_both_send() -> None:
    client = _FakeClient(200)
    ctx, _ = _patch_client(client)
    e1 = notify.NotifyEvent(kind="tp", title="t", body="b", url="/app/investigation/INV-1")
    e2 = notify.NotifyEvent(kind="tp", title="t", body="b", url="/app/investigation/INV-2")
    with ctx:
        await notify.fire(e1, _settings(), AsyncMock())
        await notify.fire(e2, _settings(), AsyncMock())  # different entity → sends
    assert len(client.posts) == 2


# ── the canned test event carries no internal identifier ─────────────────────


def test_canned_test_event_has_no_internal_identifier() -> None:
    event = notify.canned_test_event()
    assert event.kind == "test"
    assert event.url == ""
    blob = f"{event.title} {event.body}".lower()
    # Nothing that could be a real host/ip/rule/id — it's a fixed synthetic string.
    assert "soc-ai notification test" in event.title.lower()
    for leak in ("inv-", "hunt", "10.", "192.168", "rule", "alert"):
        assert leak not in blob


# ── the /config/notify/test route ────────────────────────────────────────────


def _route_settings() -> Settings:
    s = Settings(
        so_host="https://so.example.com",
        so_username="analyst",
        so_password=SecretStr("password123"),
        so_verify_ssl=False,
        es_hosts=["https://so.example.com:9200"],
        litellm_base_url="http://localhost:4000",
        api_auth_required=False,
    )
    return s


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
def route_client() -> Iterator[TestClient]:
    yield from _client(_route_settings())


def test_notify_test_route_requires_webhook(route_client: TestClient) -> None:
    """No webhook configured → the route returns ok=false with a clear detail, no send."""
    resp = route_client.post("/api/v1/config/notify/test")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["ok"] is False
    assert "webhook" in body["detail"].lower()


def test_notify_test_route_sends_canned_event(route_client: TestClient) -> None:
    """With a webhook set, the route sends the canned event and returns ok/detail.

    We patch notify.send_test to avoid any real egress and assert the route calls
    it once and proxies its (ok, detail). The webhook is set directly on the live
    settings singleton (a SecretStr) — no CONFIG_SECRET_KEY needed for this path.
    """
    # Configure a webhook URL on the live settings singleton the app holds so
    # notify.webhook_configured(settings) is True (bypasses the encrypted-store
    # save path, which needs CONFIG_SECRET_KEY).
    app_state = route_client.app.state  # type: ignore[attr-defined]
    app_state.settings.notify_webhook_url = SecretStr("https://hooks.example.com/xyz")

    fake = AsyncMock(return_value=(True, "Test sent — webhook returned HTTP 200."))
    with patch("soc_ai.notify.send_test", fake):
        resp = route_client.post("/api/v1/config/notify/test")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["ok"] is True
    assert "sent" in body["detail"].lower()
    fake.assert_awaited_once()


def test_notify_test_route_is_admin_gated() -> None:
    """With auth required, the route rejects an unauthenticated caller (401/403)."""
    settings = _route_settings()
    settings.api_auth_required = True
    settings.bootstrap_admin_password = SecretStr("pw")
    for c in _client(settings):
        resp = c.post("/api/v1/config/notify/test")
        assert resp.status_code in (401, 403)
        break

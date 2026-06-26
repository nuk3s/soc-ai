"""Tests for the FastAPI HTTP surface.

Exercises ``/healthz``, ``/investigate`` (SSE), ``/approve`` (write-tool
execution gated by approval), and ``/sessions/{id}``. The agent uses
PydanticAI's ``TestModel`` so no LLM traffic occurs; the SO HTTP client is
mocked.
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator, Iterator
from typing import Any
from unittest.mock import AsyncMock, patch

import httpx
import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr
from pydantic_ai.models.test import TestModel
from soc_ai.agent.orchestrator import StepEvent
from soc_ai.agent.triage import RecommendedAction, TriageReport
from soc_ai.config import Settings
from soc_ai.main import _resolve_cors_origins, create_app


@pytest.fixture
def app_with_test_model(
    settings_kratos: Settings,
) -> Iterator[TestClient]:
    """Build a TestClient where investigate() yields a canned event stream."""
    fake_es = AsyncMock()
    fake_auth = AsyncMock()
    fake_auth.request = AsyncMock(
        return_value=httpx.Response(200, json={"acknowledged": True, "id": "a1"})
    )

    async def fake_investigate(
        alert_id: str,
        *,
        ctx: Any,
        agent: Any = None,
        investigator: Any = None,
        synthesizer: Any = None,
        session_id: str | None = None,
    ) -> AsyncIterator[StepEvent]:
        sid = session_id or "fake-sid"
        report = TriageReport(
            verdict="true_positive",
            confidence=0.92,
            summary="C2 beacon confirmed.",
            citations=["alert-001"],
            recommended_actions=[
                RecommendedAction(
                    tool_name="ack_alert",
                    tool_args={"alert_id": "alert-001", "comment": "FP"},
                    rationale="Internal scanner.",
                )
            ],
        )
        token = await ctx.gate.request("ack_alert", {"alert_id": "alert-001", "comment": "FP"})
        yield StepEvent(
            kind="session_start", session_id=sid, sequence=1, payload={"alert_id": alert_id}
        )
        yield StepEvent(
            kind="triage_report",
            session_id=sid,
            sequence=2,
            payload=report.model_dump(),
        )
        yield StepEvent(
            kind="approval_required",
            session_id=sid,
            sequence=3,
            payload={
                "token": token,
                "tool_name": "ack_alert",
                "tool_args": {"alert_id": "alert-001", "comment": "FP"},
                "rationale": "Internal scanner.",
            },
        )
        yield StepEvent(kind="done", session_id=sid, sequence=4, payload={"recommended_count": 1})

    test_model = TestModel(
        call_tools=[],
        custom_output_args=TriageReport(
            verdict="needs_more_info",
            confidence=0.5,
            summary="x",
            citations=[],
        ),
    )
    with (
        patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=fake_es),
        patch("soc_ai.main.make_auth", return_value=fake_auth),
        patch("soc_ai.main.get_settings", return_value=settings_kratos),
        patch("soc_ai.api.routes.investigate", fake_investigate),
        # Two-stage agent: stub both model builders so the route never hits LiteLLM.
        patch("soc_ai.api.routes.build_investigator_model", return_value=test_model),
        patch("soc_ai.api.routes.build_synthesizer_model", return_value=test_model),
    ):
        app = create_app()
        with TestClient(app) as client:
            yield client


def test_healthz_reports_config(app_with_test_model: TestClient) -> None:
    resp = app_with_test_model.get("/healthz")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ok"
    assert body["so_auth"] == "kratos"
    assert body["misp_configured"] is False
    assert body["pending_approvals"] == 0
    assert body["version"]


def test_investigate_streams_events(app_with_test_model: TestClient) -> None:
    with app_with_test_model.stream("POST", "/investigate", json={"alert_id": "alert-001"}) as resp:
        assert resp.status_code == 200
        assert resp.headers["content-type"].startswith("text/event-stream")
        events: list[str] = []
        for chunk in resp.iter_lines():
            if chunk.startswith("event:"):
                events.append(chunk.split(":", 1)[1].strip())

    assert "session_start" in events
    assert "triage_report" in events
    assert "approval_required" in events
    assert "done" in events


def test_approve_executes_write_tool_when_approved(
    app_with_test_model: TestClient,
) -> None:
    """Investigation -> /approve {approved=True} -> ack_alert.execute."""
    with app_with_test_model.stream("POST", "/investigate", json={"alert_id": "alert-001"}) as resp:
        assert resp.status_code == 200
        token: str | None = None
        for chunk in resp.iter_lines():
            if chunk.startswith("data:"):
                payload = chunk.split(":", 1)[1].strip()
                if "token" in payload:
                    parsed = json.loads(payload)
                    p = parsed.get("payload", {})
                    if "token" in p:
                        token = p["token"]
                        break
    assert token is not None

    resp2 = app_with_test_model.post("/approve", json={"token": token, "approved": True})
    assert resp2.status_code == 200
    body = resp2.json()
    assert body["status"] == "executed"
    assert body["result"]["acknowledged"] is True


def test_approve_rejects_without_executing(
    app_with_test_model: TestClient,
) -> None:
    with app_with_test_model.stream("POST", "/investigate", json={"alert_id": "alert-001"}) as resp:
        token: str | None = None
        for chunk in resp.iter_lines():
            if chunk.startswith("data:") and "token" in chunk:
                p = json.loads(chunk.split(":", 1)[1].strip()).get("payload", {})
                if "token" in p:
                    token = p["token"]
                    break
    assert token is not None

    resp = app_with_test_model.post(
        "/approve",
        json={"token": token, "approved": False, "reason": "false positive"},
    )
    assert resp.status_code == 200
    assert resp.json()["status"] == "rejected"


def test_approve_unknown_token_returns_404(
    app_with_test_model: TestClient,
) -> None:
    resp = app_with_test_model.post("/approve", json={"token": "garbage", "approved": True})
    assert resp.status_code == 404


def test_approve_idempotent_on_repeat(
    app_with_test_model: TestClient,
) -> None:
    """Double-clicking Approve in the side panel must not execute the tool twice."""
    with app_with_test_model.stream("POST", "/investigate", json={"alert_id": "alert-001"}) as resp:
        token: str | None = None
        for chunk in resp.iter_lines():
            if chunk.startswith("data:") and "token" in chunk:
                p = json.loads(chunk.split(":", 1)[1].strip()).get("payload", {})
                if "token" in p:
                    token = p["token"]
                    break
    assert token is not None

    first = app_with_test_model.post("/approve", json={"token": token, "approved": True})
    second = app_with_test_model.post("/approve", json={"token": token, "approved": True})
    assert first.json()["status"] == "executed"
    assert second.json()["status"] == "already_decided"


def test_sessions_endpoint_lists_pending(
    app_with_test_model: TestClient,
) -> None:
    with app_with_test_model.stream("POST", "/investigate", json={"alert_id": "alert-001"}):
        pass  # consume

    resp = app_with_test_model.get("/sessions/whatever")
    assert resp.status_code == 200
    body = resp.json()
    assert body["session_id"] == "whatever"
    # The investigation registered one pending approval; pull it through.
    assert len(body["pending_approvals"]) >= 1
    pa = body["pending_approvals"][0]
    assert pa["tool_name"] == "ack_alert"
    assert "token" in pa


def test_create_app_exposes_router() -> None:
    """create_app() returns a FastAPI app with the routes wired."""
    app = create_app()
    paths = {route.path for route in app.routes if hasattr(route, "path")}
    assert "/healthz" in paths
    assert "/investigate" in paths
    assert "/approve" in paths
    assert "/sessions/{session_id}" in paths


def test_cors_fails_closed_when_unconfigured() -> None:
    """No CORS_ALLOW_ORIGINS and no SO_HOST → empty allowlist, never '*'."""
    assert _resolve_cors_origins("", "") == []


def test_cors_configured_paths_unchanged() -> None:
    """The explicit-origins and SO_HOST fallbacks still resolve as before."""
    assert _resolve_cors_origins("*", "") == ["*"]
    assert _resolve_cors_origins("https://a.example,https://b.example", "") == [
        "https://a.example",
        "https://b.example",
    ]
    assert _resolve_cors_origins("", "https://so.example.com") == ["https://so.example.com"]


def test_cors_middleware_uses_empty_allowlist_when_unconfigured() -> None:
    """The built app wires CORSMiddleware with an empty allowlist (not '*')."""
    fake_settings = Settings(
        so_host="https://so.example.com",
        so_username="analyst",
        so_password=SecretStr("password123"),
        es_hosts=["https://so.example.com:9200"],
        litellm_base_url="http://localhost:4000",
        cors_allow_origins="",
    )
    # Force both signals empty: blank CORS list AND no SO host origin.
    with (
        patch("soc_ai.main.get_settings", return_value=fake_settings),
        patch("soc_ai.main._resolve_cors_origins", return_value=[]) as resolved,
    ):
        app = create_app()
    assert resolved.called
    cors_mw = next(mw for mw in app.user_middleware if mw.cls.__name__ == "CORSMiddleware")
    assert cors_mw.kwargs["allow_origins"] == []
    assert cors_mw.kwargs["allow_origins"] != ["*"]

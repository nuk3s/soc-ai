"""Tests for the E1.1 model-fitness preflight probe.

The probe (:func:`soc_ai.webui.probes.probe_model_fitness`) grades whether the
configured ``analyst_model`` can actually do the pipeline's job — structured
output, a tool loop, and a budgetable reasoning phase — because a model that
merely *lists* on the gateway can still produce all-fallback verdicts.

Every model here is a pydantic-ai test double (``TestModel`` / ``FunctionModel``).
NONE of these tests touch the real LiteLLM gateway or a real model: the probe's
``build_synthesizer_model`` call is patched to return the double for each leg, so
the three legs are forced into pass / degraded / fail deterministically.

Security invariant re-asserted here: a model/gateway error string never leaks a
credential into the graded ``detail`` (the probe runs everything through
``_scrub``).
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr
from pydantic_ai.messages import (
    ModelRequest,
    ModelResponse,
    TextPart,
    ThinkingPart,
    ToolCallPart,
    ToolReturnPart,
)
from pydantic_ai.models.function import AgentInfo, FunctionModel
from pydantic_ai.models.test import TestModel
from soc_ai.config import Settings
from soc_ai.main import create_app
from soc_ai.triage_models import TriageReport
from soc_ai.webui import probes

# Where the probe imports build_synthesizer_model from (a local import inside each
# leg → the patch target is the source module, not probes).
_BUILD = "soc_ai.agent.models.build_synthesizer_model"

# A sentinel that must never surface in any graded detail string.
API_KEY_SENTINEL = "SECRET-FITNESS-KEY-do-not-leak-4a9f"


# ── model doubles ─────────────────────────────────────────────────────────────


def _so_pass_model() -> TestModel:
    """A model that returns a valid TriageReport for the structured-output leg."""
    return TestModel(
        custom_output_args=TriageReport(
            verdict="false_positive",
            confidence=0.9,
            summary="benign internal DNS lookup",
            citations=["demo-1"],
        )
    )


def _tool_calling_model() -> FunctionModel:
    """A model that calls ``echo`` once, then answers with its return value.

    Drives the tool-loop leg to PASS (tool invoked + a final answer).
    """

    def _fn(messages: list[Any], info: AgentInfo) -> ModelResponse:
        seen_return = any(
            isinstance(p, ToolReturnPart)
            for msg in messages
            if isinstance(msg, ModelRequest)
            for p in msg.parts
        )
        if seen_return:
            return ModelResponse(parts=[TextPart("ping")])
        return ModelResponse(parts=[ToolCallPart(tool_name="echo", args={"x": "ping"})])

    return FunctionModel(_fn)


def _tool_skipping_model() -> FunctionModel:
    """A model that answers WITHOUT calling the tool → tool-loop leg DEGRADED."""

    def _fn(messages: list[Any], info: AgentInfo) -> ModelResponse:
        return ModelResponse(parts=[TextPart("ping")])

    return FunctionModel(_fn)


def _truncating_model() -> FunctionModel:
    """A reasoning-only response with finish_reason='length' → pydantic-ai raises
    'token limit ... exceeded before any response was generated'."""

    def _fn(messages: list[Any], info: AgentInfo) -> ModelResponse:
        return ModelResponse(parts=[ThinkingPart(content="...")], finish_reason="length")

    return FunctionModel(_fn)


def _settings() -> Settings:
    s = Settings(
        so_host="https://so.example.com",
        so_username="analyst",
        so_password=SecretStr("password123"),
        so_verify_ssl=False,
        es_hosts=["https://so.example.com:9200"],
        litellm_base_url="http://localhost:4000",
        litellm_api_key=SecretStr(API_KEY_SENTINEL),
        api_auth_required=False,
    )
    # analyst_model carries a validation_alias (ANALYST_MODEL/HEAVY_MODEL), so the
    # field-name kwarg is ignored at construction — set it post-hoc like the
    # existing probe_llm tests do (test_webui_config_probes.py).
    s.analyst_model = "fit-test-model"
    return s


def _patch_builder(*models: Any) -> Any:
    """Patch build_synthesizer_model to yield *models* in call order (one per leg).

    The legs call it in order structured_output → tool_loop → reasoning_budget, so
    a 3-item side_effect maps one model to each leg. A shorter list repeats the
    last model for any extra call.
    """
    seq = list(models)

    def _side_effect(*_a: Any, **_kw: Any) -> Any:
        return seq.pop(0) if len(seq) > 1 else seq[0]

    return patch(_BUILD, side_effect=_side_effect)


# ── grade reduction (unit) ────────────────────────────────────────────────────


def test_reduce_fail_wins() -> None:
    legs = [{"grade": "pass"}, {"grade": "degraded"}, {"grade": "fail"}]
    assert probes._reduce_fitness(legs) == "fail"


def test_reduce_degraded_over_pass() -> None:
    legs = [{"grade": "pass"}, {"grade": "degraded"}, {"grade": "pass"}]
    assert probes._reduce_fitness(legs) == "degraded"


def test_reduce_all_pass() -> None:
    legs = [{"grade": "pass"}, {"grade": "pass"}, {"grade": "pass"}]
    assert probes._reduce_fitness(legs) == "pass"


# ── whole-probe grading via doubles ───────────────────────────────────────────


async def test_probe_all_pass() -> None:
    """A clean model (valid TriageReport, calls the tool, no truncation) → PASS."""
    with _patch_builder(_so_pass_model(), _tool_calling_model(), _so_pass_model()):
        result = await probes.probe_model_fitness(_settings())

    assert result["grade"] == "pass"
    assert result["model"] == "fit-test-model"
    assert {leg["name"] for leg in result["legs"]} == {
        "structured_output",
        "tool_loop",
        "reasoning_budget",
    }
    assert all(leg["ok"] for leg in result["legs"])


async def test_probe_structured_output_failure_grades_fail() -> None:
    """A model that truncates on the structured-output leg (UnexpectedModelBehavior)
    grades the whole probe FAIL, and the leg detail carries the truncation class."""
    with _patch_builder(_truncating_model(), _tool_calling_model(), _so_pass_model()):
        result = await probes.probe_model_fitness(_settings())

    assert result["grade"] == "fail"
    so_leg = next(leg for leg in result["legs"] if leg["name"] == "structured_output")
    assert so_leg["grade"] == "fail"
    assert so_leg["ok"] is False
    # The pydantic-ai truncation message names "token limit" / "before any response".
    assert "token limit" in so_leg["detail"].lower() or "response" in so_leg["detail"].lower()


async def test_probe_tool_loop_skip_grades_degraded() -> None:
    """A model that answers without calling the tool → tool_loop DEGRADED → overall
    DEGRADED (no leg failed)."""
    with _patch_builder(_so_pass_model(), _tool_skipping_model(), _so_pass_model()):
        result = await probes.probe_model_fitness(_settings())

    assert result["grade"] == "degraded"
    tool_leg = next(leg for leg in result["legs"] if leg["name"] == "tool_loop")
    assert tool_leg["grade"] == "degraded"
    assert tool_leg["ok"] is True  # degraded is still "reachable", just weaker
    assert "without calling" in tool_leg["detail"].lower()


async def test_probe_reasoning_budget_truncation_grades_degraded() -> None:
    """SO + tool legs pass, but the tight-budget re-run truncates before output →
    reasoning_budget DEGRADED (not FAIL) with the raise-the-budget hint."""
    with _patch_builder(_so_pass_model(), _tool_calling_model(), _truncating_model()):
        result = await probes.probe_model_fitness(_settings())

    assert result["grade"] == "degraded"
    budget_leg = next(leg for leg in result["legs"] if leg["name"] == "reasoning_budget")
    assert budget_leg["grade"] == "degraded"
    assert budget_leg["ok"] is True
    assert "reasoning truncated" in budget_leg["detail"].lower()


async def test_probe_never_leaks_api_key() -> None:
    """A gateway error string that embeds the api-key must be scrubbed out of every
    detail (defence-in-depth — the probe scrubs all details)."""
    import httpx

    def _boom(*_a: Any, **_kw: Any) -> Any:
        raise httpx.ConnectError(f"refused https://x?api_key={API_KEY_SENTINEL}")

    with patch(_BUILD, side_effect=_boom):
        result = await probes.probe_model_fitness(_settings())

    assert result["grade"] == "fail"
    blob = result["detail"] + "".join(leg["detail"] for leg in result["legs"])
    assert API_KEY_SENTINEL not in blob


async def test_probe_never_raises_on_builder_error() -> None:
    """Even a hard error constructing the model is a graded FAIL, never a raise."""
    with patch(_BUILD, side_effect=RuntimeError("provider blew up")):
        result = await probes.probe_model_fitness(_settings())
    assert result["grade"] == "fail"
    assert all(leg["grade"] == "fail" for leg in result["legs"])


# ── endpoint: GET /config/model-fitness ───────────────────────────────────────


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


def test_endpoint_returns_grade(client: TestClient) -> None:
    """GET /config/model-fitness proxies the probe result as the response model."""
    fake = AsyncMock(
        return_value={
            "grade": "degraded",
            "model": "qwen3.6-a3b",
            "legs": [
                {"name": "structured_output", "ok": True, "grade": "pass", "detail": "ok"},
                {"name": "tool_loop", "ok": True, "grade": "degraded", "detail": "no tool"},
                {"name": "reasoning_budget", "ok": True, "grade": "pass", "detail": "ok"},
            ],
            "detail": "qwen3.6-a3b: tool_loop=degraded",
        }
    )
    with patch("soc_ai.api.webui.routes_config.probes.probe_model_fitness", fake):
        resp = client.get("/api/v1/config/model-fitness")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["grade"] == "degraded"
    assert body["model"] == "qwen3.6-a3b"
    assert len(body["legs"]) == 3
    assert body["legs"][1]["grade"] == "degraded"


def test_endpoint_emits_audit_event(client: TestClient) -> None:
    """The endpoint emits a ``model_fitness`` audit event carrying the grade."""
    fake = AsyncMock(
        return_value={
            "grade": "fail",
            "model": "unfit-model",
            "legs": [{"name": "structured_output", "ok": False, "grade": "fail", "detail": "x"}],
            "detail": "unfit-model: structured_output=fail",
        }
    )
    with (
        patch("soc_ai.api.webui.routes_config.probes.probe_model_fitness", fake),
        patch("soc_ai.audit.logger.AuditLogger.log_kind", new_callable=AsyncMock) as log_kind,
    ):
        resp = client.get("/api/v1/config/model-fitness")
    assert resp.status_code == 200, resp.text
    log_kind.assert_awaited_once()
    _args, kwargs = log_kind.call_args
    assert kwargs["kind"] == "model_fitness"
    assert kwargs["payload"]["grade"] == "fail"
    assert kwargs["payload"]["model"] == "unfit-model"


def test_endpoint_audit_failure_is_fail_soft(client: TestClient) -> None:
    """A failing audit write must NOT turn the read-only diagnostic into a 500."""
    fake = AsyncMock(return_value={"grade": "pass", "model": "m", "legs": [], "detail": "ok"})
    with (
        patch("soc_ai.api.webui.routes_config.probes.probe_model_fitness", fake),
        patch(
            "soc_ai.audit.logger.AuditLogger.log_kind",
            new_callable=AsyncMock,
            side_effect=RuntimeError("audit index down"),
        ),
    ):
        resp = client.get("/api/v1/config/model-fitness")
    assert resp.status_code == 200
    assert resp.json()["grade"] == "pass"


def test_endpoint_never_calls_a_write_tool(client: TestClient) -> None:
    """The probe path must never issue a Security-Onion write — assert the single
    audited write entrypoint (execute_write_tool) is never awaited."""
    fake = AsyncMock(return_value={"grade": "pass", "model": "m", "legs": [], "detail": "ok"})
    with (
        patch("soc_ai.api.webui.routes_config.probes.probe_model_fitness", fake),
        patch("soc_ai.tools.write_exec.execute_write_tool", new_callable=AsyncMock) as write_exec,
    ):
        resp = client.get("/api/v1/config/model-fitness")
    assert resp.status_code == 200
    write_exec.assert_not_awaited()


def test_endpoint_admin_gated() -> None:
    """With API auth ON, an unauthenticated request is refused; an authenticated
    admin gets through.

    (The gate rejects an anonymous caller at the auth layer with 401 before the
    admin role check; an authenticated non-admin would hit the 403 admin_required
    branch. Both are "refused" — assert the anonymous request never reaches the
    probe.)"""
    settings = _settings().model_copy(
        update={
            "api_auth_required": True,
            "bootstrap_admin_password": SecretStr("admin-pw"),
        }
    )
    for c in _client(settings):
        resp = c.get("/api/v1/config/model-fitness")
        assert resp.status_code in (401, 403)

        # An authenticated admin gets through (probe patched so it's hermetic).
        login = c.post("/api/v1/login", json={"username": "admin", "password": "admin-pw"})
        assert login.status_code == 200, login.text
        fake = AsyncMock(return_value={"grade": "pass", "model": "m", "legs": [], "detail": "ok"})
        with patch("soc_ai.api.webui.routes_config.probes.probe_model_fitness", fake):
            ok = c.get("/api/v1/config/model-fitness")
        assert ok.status_code == 200
        assert ok.json()["grade"] == "pass"

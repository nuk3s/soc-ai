"""Tests for the E1.1 model-fitness preflight probe.

The probe (:func:`soc_ai.webui.probes.probe_model_fitness`) grades whether the
configured ``analyst_model`` can actually do the pipeline's job — structured
output, a tool loop, and a budgetable reasoning phase — because a model that
merely *lists* on the gateway can still produce all-fallback verdicts.

Every model here is a pydantic-ai test double (``TestModel`` / ``FunctionModel``).
NONE of these tests touch the real LiteLLM gateway or a real model: the probe's
``_build_probe_model`` call is patched to return a double (and a fake client) for
each leg, so the three legs are forced into pass / degraded / fail
deterministically.

Security invariant re-asserted here: a model/gateway error string never leaks a
credential into the graded ``detail`` (the probe runs everything through
``_scrub``).

The last two sections cover the 2026-08-07 audit of all 50 stored checks, which
found the probe was measuring a path production never runs and reporting the
result as a model verdict. Read those docstrings before changing a budget.
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

# The probe builds its OWN model + HTTP client per leg (probe-specific provider:
# client timeout == the leg budget, zero transport retries, closed after the leg).
# That builder lives in probes.py, so it is the patch target for every leg double.
_BUILD = "soc_ai.webui.probes._build_probe_model"

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


class _FakeClient:
    """Stand-in for the leg's httpx client — records that the leg closed it.

    The probe leaked one real ``httpx.AsyncClient`` per leg (three per probe)
    because it borrowed production's builder, which owns its client for the
    process lifetime. The probe's client is per-leg, so the leg must close it.
    """

    def __init__(self) -> None:
        self.closed = False

    async def aclose(self) -> None:
        self.closed = True


def _patch_builder(*models: Any, clients: list[_FakeClient] | None = None) -> Any:
    """Patch _build_probe_model to yield *models* in call order (one per leg).

    The legs call it in order structured_output → tool_loop → reasoning_budget, so
    a 3-item side_effect maps one model to each leg. A shorter list repeats the
    last model for any extra call. Each call also hands back a fresh
    :class:`_FakeClient`, appended to *clients* when given, so a test can assert
    the leg closed what it opened.
    """
    seq = list(models)
    made = clients if clients is not None else []

    def _side_effect(*_a: Any, **_kw: Any) -> Any:
        model = seq.pop(0) if len(seq) > 1 else seq[0]
        client = _FakeClient()
        made.append(client)
        return model, client

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
    """Even a hard error constructing the model is a graded result, never a raise.

    The two capability legs fail; the tight-budget experiment can only ever
    degrade (it must not be able to declare a model unfit — see
    ``test_tight_budget_leg_can_never_grade_fail``), and worst-wins still lands
    the probe on FAIL."""
    with patch(_BUILD, side_effect=RuntimeError("provider blew up")):
        result = await probes.probe_model_fitness(_settings())
    assert result["grade"] == "fail"
    grades = {leg["name"]: leg["grade"] for leg in result["legs"]}
    assert grades["structured_output"] == "fail"
    assert grades["tool_loop"] == "fail"
    assert grades["reasoning_budget"] == "degraded"


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


# ── Dogfood 2026-08-05: budgets + diagnosable total timeout ────────────────


def test_total_budget_exceeds_sum_of_leg_budgets() -> None:
    """The overall cap must be the BELT to the per-leg suspenders — strictly
    larger than three worst-case legs, or slow-but-passing legs get their run
    cut mid-probe. The shipped 30s total vs 3x12s legs was internally
    inconsistent, and on a reasoning model whose structured call runs 10-16s it
    produced a false UNFIT on the primary analyst model (legs pass individually
    at 10.9s + 2.5s, but the sum plus variance tripped one budget or the
    other)."""
    assert probes._FITNESS_TOTAL_TIMEOUT_S > 3 * probes._FITNESS_LEG_TIMEOUT_S


def test_leg_budget_covers_observed_reasoning_latency() -> None:
    """V4 in tool mode with high reasoning effort measures 10-16s per
    structured call (battery data, 2026-08-05). The per-leg cap needs real
    headroom over that, or the chip flickers unfit with load variance."""
    assert probes._FITNESS_LEG_TIMEOUT_S >= 30.0


async def test_total_timeout_reports_completed_legs(monkeypatch) -> None:
    """When the overall cap fires, the operator gets the legs that DID finish
    plus a marker naming where it stopped — not legs=[] (the same undiagnosable
    terminal-state class as the silent pipeline errors of 2026-08-03)."""
    import asyncio as _asyncio

    async def instant_pass(settings):
        return probes._fitness_leg("structured_output", "pass", "ok")

    async def hangs(settings):
        await _asyncio.sleep(3600)

    monkeypatch.setattr(probes, "_leg_structured_output", instant_pass)
    monkeypatch.setattr(probes, "_leg_tool_loop", hangs)
    monkeypatch.setattr(probes, "_leg_reasoning_budget", hangs)
    monkeypatch.setattr(probes, "_FITNESS_TOTAL_TIMEOUT_S", 0.3)

    result = await probes.probe_model_fitness(_settings())
    assert result["grade"] == "fail"
    names = [leg["name"] for leg in result["legs"]]
    assert "structured_output" in names  # the completed leg survives
    assert "probe_timeout" in names  # the marker names where it stopped
    marker = next(leg for leg in result["legs"] if leg["name"] == "probe_timeout")
    assert "tool_loop" in marker["detail"]  # which leg was in flight


# ── 2026-08-07 audit: the probe was a clock, and a mismeasured one ─────────────
#
# All 50 model_fitness audit records for the live analyst model (2026-07-08 →
# 2026-08-07) read 18 pass / 25 fail / 7 degraded — and EVERY fail was a timeout.
# Zero schema-validation failures, zero UnexpectedModelBehavior: the failure
# class this probe exists to catch never fired once. Worse, at 22:37:10 it graded
# deepseek-v4-flash UNFIT while a graded eval was saturating the same gateway —
# and that eval landed at 22:46:40 with agreement 1.0 over n_ok=5. The model
# "unable to produce a TriageReport" produced five, correctly, concurrently.
#
# The tests below pin the four measurement defects: the probe must run the path
# PRODUCTION runs (output mode, retries, response cap), bound its own provider
# instead of cancelling production's, and report elapsed time + serving backend
# instead of an unfalsifiable "timed out".


def _hanging_model() -> FunctionModel:
    """A model that never answers — drives a leg into its wall-clock budget."""

    async def _fn(messages: list[Any], info: AgentInfo) -> ModelResponse:
        import asyncio as _asyncio

        await _asyncio.sleep(3600)
        return ModelResponse(parts=[TextPart("never")])

    return FunctionModel(_fn)


def _erroring_model(exc: BaseException | None = None) -> FunctionModel:
    """A model whose call blows up (gateway/transport class, not a schema class)."""

    def _fn(messages: list[Any], info: AgentInfo) -> ModelResponse:
        raise exc if exc is not None else RuntimeError("gateway hiccup")

    return FunctionModel(_fn)


def _attributing_model(api_base: str) -> FunctionModel:
    """A model that writes LiteLLM's backend attribution the way the transport does.

    The real signal arrives as response HEADERS recorded by
    ``RetryingAsyncTransport`` into the active attribution sink; writing the sink
    directly proves the leg opened a capture context AROUND the model call.
    """

    def _fn(messages: list[Any], info: AgentInfo) -> ModelResponse:
        from soc_ai.agent._gateway_retry import _ATTRIBUTION

        sink = _ATTRIBUTION.get()
        if sink is not None:
            sink["api_base"] = api_base
        return ModelResponse(parts=[TextPart("ping")])

    return FunctionModel(_fn)


def _capture_agents(monkeypatch: Any) -> list[dict[str, Any]]:
    """Record the kwargs of every Agent the probe constructs (spy wraps the real one)."""
    import pydantic_ai

    real = pydantic_ai.Agent
    seen: list[dict[str, Any]] = []

    def _spy(*args: Any, **kwargs: Any) -> Any:
        seen.append(kwargs)
        return real(*args, **kwargs)

    monkeypatch.setattr(pydantic_ai, "Agent", _spy)
    return seen


# A1 — output-mode mismatch


async def test_probe_runs_the_output_mode_production_runs(monkeypatch) -> None:
    """The probe must exercise ``synthesizer_output_mode``, not pydantic-ai's default.

    Prod runs native (server-side guided decoding, measured 4.3x faster on this
    backend by the app's own battery); the probe ran TOOL mode and then graded the
    model on the slower path's clock.
    """
    from soc_ai.agent import orchestrator

    modes: list[str] = []

    def _spy_mode(mode: str) -> Any:
        modes.append(mode)
        # Keep the doubles usable whatever the mode — this test is about WHICH
        # mode the probe asks production's mapper for, not about native decoding.
        return TriageReport

    monkeypatch.setattr(orchestrator, "_synth_output_type", _spy_mode)
    settings = _settings()
    settings.synthesizer_output_mode = "native"

    with _patch_builder(_so_pass_model(), _tool_calling_model(), _so_pass_model()):
        result = await probes.probe_model_fitness(settings)

    assert result["grade"] == "pass"
    # Both structured-output legs go through production's mapper, in prod's mode.
    assert modes == ["native", "native"]


# A2 — retries parity


async def test_every_leg_uses_the_production_synthesizer_retries(monkeypatch) -> None:
    """A probe stricter than prod manufactures failures prod never sees.

    Every production synthesizer builds with ``retries=3`` (orchestrator:
    build_synth_first_agent / build_synthesizer / build_partial_triage_synthesizer);
    the probe inherited pydantic-ai's default of 1, so a single schema wobble that
    prod would have retried away graded the model UNFIT.
    """
    seen = _capture_agents(monkeypatch)
    with _patch_builder(_so_pass_model(), _tool_calling_model(), _so_pass_model()):
        await probes.probe_model_fitness(_settings())

    assert len(seen) == 3
    assert [kw.get("retries") for kw in seen] == [3, 3, 3]
    assert probes._FITNESS_RETRIES == 3


# A3 — the response cap the pipeline actually runs


async def test_probe_model_is_built_at_the_pipelines_real_response_cap() -> None:
    """The probe's model must carry prod's ``synthesizer_max_response_tokens``.

    The old reasoning-budget leg clamped to 2048 and called it "the pipeline's
    real cap". The real cap is 32000 — the clamp was measuring a model the
    pipeline never runs.
    """
    settings = _settings()
    model, client = probes._build_probe_model(settings)
    try:
        assert settings.synthesizer_max_response_tokens == 32000
        assert model.settings["max_tokens"] == settings.synthesizer_max_response_tokens
    finally:
        await client.aclose()


async def test_tight_budget_leg_can_never_grade_fail(monkeypatch) -> None:
    """The tight-cap leg is an EXPERIMENT: a timeout there grades DEGRADED.

    Across 50 recorded runs it produced zero of the truncation signal it was
    written for and a large share of the hard FAILs — a leg that cannot reproduce
    a prod condition must not be able to declare the analyst model unfit.
    """
    monkeypatch.setattr(probes, "_FITNESS_LEG_TIMEOUT_S", 0.05)
    monkeypatch.setattr(probes, "_FITNESS_LEG_GRACE_S", 0.05)
    with _patch_builder(_so_pass_model(), _tool_calling_model(), _hanging_model()):
        result = await probes.probe_model_fitness(_settings())

    leg = next(x for x in result["legs"] if x["name"] == "reasoning_budget")
    assert leg["grade"] == "degraded"
    assert leg["ok"] is True
    assert result["grade"] == "degraded"


async def test_tight_budget_leg_downgrades_a_hard_error_too() -> None:
    """Any failure under the deliberately tight cap is DEGRADED, never FAIL —
    leg 1 already gates capability at the cap production actually runs."""
    with _patch_builder(_so_pass_model(), _tool_calling_model(), _erroring_model()):
        result = await probes.probe_model_fitness(_settings())

    leg = next(x for x in result["legs"] if x["name"] == "reasoning_budget")
    assert leg["grade"] == "degraded"
    assert result["grade"] == "degraded"


# A4 — timeouts at the right layer, and no leaked clients


async def test_probe_client_bounds_the_leg_and_does_not_retry() -> None:
    """The leg budget must live in the HTTP client, not only in an outer cancel.

    Production's provider is 300s + RetryingAsyncTransport(max_retries=5). An
    outer ``asyncio.wait_for(30s)`` cannot make that client hurry: the cancel
    lands mid-read, which is how the 22:37:10 run burned its 100s total inside
    leg 3 (arithmetically impossible if 3x30s had held).
    """
    from soc_ai.agent._gateway_retry import RetryingAsyncTransport

    settings = _settings()
    _model, client = probes._build_probe_model(settings)
    try:
        assert client.timeout.read == probes._FITNESS_LEG_TIMEOUT_S
        assert client.timeout.connect <= probes._FITNESS_LEG_TIMEOUT_S
        # Not production's 300s: the probe is a measurement, not a workload.
        assert client.timeout.read < settings.litellm_request_timeout_s
        transport = client._transport
        assert isinstance(transport, RetryingAsyncTransport)
        assert transport._max_retries == 0
    finally:
        await client.aclose()


async def test_probe_closes_every_client_it_opens() -> None:
    """Three httpx.AsyncClients leaked per probe (one per leg, never closed)."""
    made: list[_FakeClient] = []
    with _patch_builder(_so_pass_model(), _tool_calling_model(), _so_pass_model(), clients=made):
        await probes.probe_model_fitness(_settings())

    assert len(made) == 3
    assert all(c.closed for c in made)


async def test_probe_closes_its_client_when_the_leg_errors() -> None:
    """A failing leg still owns its client — the close is in a finally, not the
    happy path (a gateway outage otherwise leaked one client per probe per leg)."""
    made: list[_FakeClient] = []
    with _patch_builder(_erroring_model(), clients=made):
        result = await probes.probe_model_fitness(_settings())

    assert result["grade"] == "fail"
    assert made and all(c.closed for c in made)


def test_total_budget_exceeds_three_legs_plus_their_grace() -> None:
    """The belt must clear the suspenders INCLUDING the post-deadline grace, or
    the total cap fires first and the operator gets 'probe exceeded Ns' instead
    of the leg that was actually slow."""
    per_leg = probes._FITNESS_LEG_TIMEOUT_S + probes._FITNESS_LEG_GRACE_S
    assert 3 * per_leg < probes._FITNESS_TOTAL_TIMEOUT_S


# A5 — honest reporting


async def test_timeout_detail_names_the_elapsed_time_and_the_budget(monkeypatch) -> None:
    """ "timed out" alone is unfalsifiable. The operator needs how long it ran and
    against which budget, so a 29.7s pass and a 0.4s teardown never read alike."""
    monkeypatch.setattr(probes, "_FITNESS_LEG_TIMEOUT_S", 0.05)
    monkeypatch.setattr(probes, "_FITNESS_LEG_GRACE_S", 0.05)
    with _patch_builder(_hanging_model(), _tool_calling_model(), _so_pass_model()):
        result = await probes.probe_model_fitness(_settings())

    leg = next(x for x in result["legs"] if x["name"] == "structured_output")
    assert leg["grade"] == "fail"
    assert "timed out after" in leg["detail"]
    assert "budget" in leg["detail"]
    assert leg["elapsed_s"] is not None
    assert leg["elapsed_s"] > 0


async def test_every_leg_records_its_elapsed_time() -> None:
    """Even a passing leg carries elapsed_s — the trend ("14s, 19s, 27s, timeout")
    is the diagnosis a bare pass/fail threw away."""
    with _patch_builder(_so_pass_model(), _tool_calling_model(), _so_pass_model()):
        result = await probes.probe_model_fitness(_settings())

    assert all(isinstance(leg["elapsed_s"], float) for leg in result["legs"])


async def test_teardown_artifact_is_graded_as_a_timeout_not_a_capability_failure() -> None:
    """anyio's ClosedResourceError is what a cancelled read looks like on the way
    out. It was reported as a MODEL failure ("structured_output=fail: the model
    cannot produce a TriageReport"), which is how a saturated gateway got
    recorded as an unfit model."""
    import anyio

    with _patch_builder(_erroring_model(anyio.ClosedResourceError())):
        result = await probes.probe_model_fitness(_settings())

    leg = next(x for x in result["legs"] if x["name"] == "structured_output")
    assert leg["grade"] == "fail"
    assert "ClosedResourceError" in leg["detail"]
    assert "client teardown" in leg["detail"]
    assert leg["elapsed_s"] is not None


async def test_leg_reports_which_backend_served_it() -> None:
    """LiteLLM answers "which deployment ran this" in response headers only. The
    CLI probe already captures them (soc_ai/model_probe.py); the fitness probe
    graded models without ever recording which backend it graded."""
    with _patch_builder(
        _so_pass_model(), _attributing_model("http://spark-a:8000/v1"), _so_pass_model()
    ):
        result = await probes.probe_model_fitness(_settings())

    leg = next(x for x in result["legs"] if x["name"] == "tool_loop")
    assert leg["backend"] == "http://spark-a:8000/v1"
    assert result["served_backend"] == {"api_base": "http://spark-a:8000/v1"}


# ── A6 self-load guard + B2 n-of-m (2026-08-07) ───────────────────────────────
#
# The 22:37:10 UNFIT was self-inflicted: soc-ai's own graded eval was saturating
# the gateway it was probing. And one adverse sample was enough to turn the chip
# red, so a transient measurement became a standing "your analyst model is
# broken" that on-call learned to ignore.


def _seed_fitness(app: Any, model: str, result: dict[str, Any], *, age_h: float = 0.0) -> None:
    """Write a cached fitness verdict, optionally backdated past the 24h TTL."""
    import asyncio as _asyncio
    from datetime import UTC, datetime, timedelta

    from soc_ai.store import model_battery as mb_svc
    from soc_ai.store.models import ModelBatteryResult
    from sqlalchemy import update

    async def _go() -> None:
        async with app.state.db_sessionmaker() as db:
            await mb_svc.upsert_fitness(db, model=model, result=result)
            if age_h:
                stamp = datetime.now(UTC).replace(tzinfo=None) - timedelta(hours=age_h)
                await db.execute(update(ModelBatteryResult).values(fitness_at=stamp))
                await db.commit()

    _asyncio.run(_go())


def _audit_hit(grade: str, at: str, model: str) -> dict[str, Any]:
    """One stored ``model_fitness`` audit record, as ES returns it."""
    return {
        "_source": {
            "timestamp": at,
            "kind": "model_fitness",
            "payload": {"grade": grade, "model": model, "detail": ""},
        }
    }


class _StubElastic:
    """Audit-index stand-in: canned hits, or a canned failure."""

    def __init__(self, hits: list[dict[str, Any]] | None = None, error: Exception | None = None):
        self._hits = hits or []
        self._error = error
        self.searches: list[tuple[str, dict[str, Any]]] = []

    async def search(self, index: str, query: dict[str, Any], **kw: Any) -> Any:
        from soc_ai.so_client.elastic import EsSearchResult

        self.searches.append((index, query))
        if self._error is not None:
            raise self._error
        return EsSearchResult(total=len(self._hits), took_ms=1, hits=self._hits)


def _probe_returning(grade: str, model: str = "") -> Any:
    """A patched probe that records its calls and returns *grade*."""
    calls: list[int] = []

    async def _fake(settings: Any) -> dict[str, Any]:
        calls.append(1)
        return {
            "grade": grade,
            "model": model or settings.analyst_model,
            "legs": [],
            "detail": f"{grade} detail",
            "served_backend": None,
        }

    _fake.calls = calls  # type: ignore[attr-defined]
    return _fake


def test_auto_probe_is_skipped_while_the_quality_eval_batch_runs(client: TestClient) -> None:
    """soc-ai must not grade a model on a gateway soc-ai is saturating.

    At 22:37:10 the probe called deepseek-v4-flash UNFIT while a graded eval was
    in flight; that eval landed at 22:46:40 with agreement 1.0 over n_ok=5.
    """
    from soc_ai.api.webui.routes_quality import _get_quality_eval_status

    app = client.app
    model = app.state.settings.analyst_model
    fit = {"grade": "pass", "model": model, "legs": [], "detail": "fit"}
    _seed_fitness(app, model, fit, age_h=25)
    _get_quality_eval_status(app.state).running = True
    probe = _probe_returning("fail")

    with patch("soc_ai.webui.probes.probe_model_fitness", probe):
        body = client.get("/api/v1/config/model-fitness").json()

    assert probe.calls == []  # never measured under our own load
    assert body["measured"] is False
    assert "not measured" in (body["note"] or "")
    assert "eval" in (body["note"] or "")
    assert body["grade"] == "pass"  # the cached verdict is kept, not overwritten
    assert body["cached"] is True


def test_auto_probe_is_skipped_while_auto_triage_runs(client: TestClient) -> None:
    """The auto-triage backlog drain drives the same gateway, sequentially, for
    as long as the queue lasts — the probe's clock is meaningless under it."""
    from soc_ai.webui import autotriage as at

    app = client.app
    model = app.state.settings.analyst_model
    fit = {"grade": "pass", "model": model, "legs": [], "detail": "fit"}
    _seed_fitness(app, model, fit, age_h=25)
    at.get_status(app.state).active = True
    probe = _probe_returning("fail")

    with patch("soc_ai.webui.probes.probe_model_fitness", probe):
        body = client.get("/api/v1/config/model-fitness").json()

    assert probe.calls == []
    assert body["measured"] is False
    assert "triage" in (body["note"] or "")


def test_force_probes_even_under_our_own_load(client: TestClient) -> None:
    """The guard protects the AUTO path only: "Check fitness" is an operator
    saying "measure it now", and refusing that would be its own dead end."""
    from soc_ai.webui import autotriage as at

    app = client.app
    at.get_status(app.state).active = True
    probe = _probe_returning("pass")

    with patch("soc_ai.webui.probes.probe_model_fitness", probe):
        body = client.get("/api/v1/config/model-fitness?force=true").json()

    assert probe.calls == [1]
    assert body["measured"] is True
    assert body["grade"] == "pass"


def test_skip_without_a_cached_verdict_reports_unknown(client: TestClient) -> None:
    """No cache and a batch in flight: say "not measured", never invent a grade."""
    from soc_ai.webui import autotriage as at

    app = client.app
    at.get_status(app.state).active = True
    probe = _probe_returning("fail")

    with patch("soc_ai.webui.probes.probe_model_fitness", probe):
        body = client.get("/api/v1/config/model-fitness").json()

    assert probe.calls == []
    assert body["grade"] == "unknown"
    assert body["measured"] is False
    assert body["legs"] == []
    assert "not measured" in (body["note"] or "")


# B2 — n-of-m from the audit store (no migration: the records are already there)


def test_alarm_needs_two_consecutive_fails() -> None:
    """One adverse sample is a measurement; two in a row is a verdict."""
    from soc_ai.api.webui import routes_config as rc

    one = rc._fitness_history_summary(
        [
            {"grade": "fail", "at": "t3"},
            {"grade": "pass", "at": "t2"},
            {"grade": "pass", "at": "t1"},
        ]
    )
    assert one["alarm"] is False
    assert one["consecutive_fails"] == 1
    assert one["recent_fails"] == 1
    assert one["recent_checks"] == 3
    assert one["last_pass_at"] == "t2"

    two = rc._fitness_history_summary(
        [
            {"grade": "fail", "at": "t3"},
            {"grade": "fail", "at": "t2"},
            {"grade": "pass", "at": "t1"},
        ]
    )
    assert two["alarm"] is True
    assert two["consecutive_fails"] == 2
    assert two["recent_fails"] == 2
    assert two["last_pass_at"] == "t1"


def test_a_single_fail_after_passes_does_not_turn_the_chip_red(client: TestClient) -> None:
    app = client.app
    model = app.state.settings.analyst_model
    app.state.elastic = _StubElastic(
        [
            _audit_hit("pass", "2026-08-07T18:00:00+00:00", model),
            _audit_hit("pass", "2026-08-07T12:00:00+00:00", model),
        ]
    )
    probe = _probe_returning("fail")

    with patch("soc_ai.webui.probes.probe_model_fitness", probe):
        body = client.get("/api/v1/config/model-fitness?force=true").json()

    assert body["grade"] == "fail"  # the measurement is reported honestly …
    assert body["alarm"] is False  # … but one sample does not condemn the model
    assert body["recent_fails"] == 1
    assert body["recent_checks"] == 3
    assert body["last_pass_at"] == "2026-08-07T18:00:00+00:00"


def test_two_consecutive_fails_raise_the_alarm(client: TestClient) -> None:
    app = client.app
    model = app.state.settings.analyst_model
    stub = _StubElastic(
        [
            _audit_hit("fail", "2026-08-07T18:00:00+00:00", model),
            _audit_hit("pass", "2026-08-07T12:00:00+00:00", model),
        ]
    )
    app.state.elastic = stub
    probe = _probe_returning("fail")

    with patch("soc_ai.webui.probes.probe_model_fitness", probe):
        body = client.get("/api/v1/config/model-fitness?force=true").json()

    assert body["alarm"] is True
    assert body["consecutive_fails"] == 2
    assert body["recent_fails"] == 2
    # The history read is scoped to fitness checks in the audit alias.
    index, query = stub.searches[0]
    assert index.startswith(app.state.settings.audit_index_alias)
    assert query["bool"]["filter"] == [{"term": {"kind": "model_fitness"}}]


def test_history_ignores_another_models_checks(client: TestClient) -> None:
    """Two models' verdicts must not blend — switching ANALYST_MODEL would
    otherwise inherit the previous model's fail streak (and its alarm).

    The model match happens on the returned payloads rather than in the query:
    ``payload`` is only mapped ``flattened`` on indices created after that
    template landed, so a ``term`` on ``payload.model`` matches nothing on an
    older daily index — and a silently empty history can never raise an alarm.
    """
    app = client.app
    model = app.state.settings.analyst_model
    app.state.elastic = _StubElastic(
        [
            _audit_hit("fail", "2026-08-07T18:00:00+00:00", "some-other-model"),
            _audit_hit("pass", "2026-08-07T12:00:00+00:00", model),
        ]
    )
    probe = _probe_returning("fail")

    with patch("soc_ai.webui.probes.probe_model_fitness", probe):
        body = client.get("/api/v1/config/model-fitness?force=true").json()

    assert body["recent_checks"] == 2  # this run + the one check that is ours
    assert body["consecutive_fails"] == 1
    assert body["alarm"] is False


def test_history_unavailable_degrades_to_single_sample(client: TestClient) -> None:
    """A down audit index must not crash the Config page, and must not silently
    claim a clean history — it falls back to today's single-sample behaviour."""
    app = client.app
    app.state.elastic = _StubElastic(error=RuntimeError("audit index down"))
    probe = _probe_returning("fail")

    with patch("soc_ai.webui.probes.probe_model_fitness", probe):
        resp = client.get("/api/v1/config/model-fitness?force=true")

    assert resp.status_code == 200
    body = resp.json()
    assert body["grade"] == "fail"
    assert body["alarm"] is True  # single-sample behaviour, unchanged
    assert body["recent_checks"] is None
    assert body["recent_fails"] is None


def test_cached_verdict_carries_the_history_summary(client: TestClient) -> None:
    """The chip is usually rendered from the 24h cache — the n-of-m summary has
    to come with it or the frontend can only ever say "unfit"."""
    app = client.app
    model = app.state.settings.analyst_model
    _seed_fitness(app, model, {"grade": "fail", "model": model, "legs": [], "detail": "unfit"})
    app.state.elastic = _StubElastic(
        [
            _audit_hit("fail", "2026-08-07T18:00:00+00:00", model),
            _audit_hit("fail", "2026-08-07T12:00:00+00:00", model),
            _audit_hit("pass", "2026-08-07T06:00:00+00:00", model),
        ]
    )
    probe = _probe_returning("pass")

    with patch("soc_ai.webui.probes.probe_model_fitness", probe):
        body = client.get("/api/v1/config/model-fitness").json()

    assert probe.calls == []  # served from cache
    assert body["cached"] is True
    assert body["alarm"] is True
    assert body["recent_fails"] == 2
    assert body["last_pass_at"] == "2026-08-07T06:00:00+00:00"


def test_notification_fires_only_when_the_alarm_is_raised(client: TestClient) -> None:
    """An unfit-model page that fires on every transient measurement is a page
    on-call learns to ignore — gate it on the same 2-of-N alarm the chip uses."""
    app = client.app
    model = app.state.settings.analyst_model
    app.state.elastic = _StubElastic([_audit_hit("pass", "2026-08-07T18:00:00+00:00", model)])
    probe = _probe_returning("fail")

    with (
        patch("soc_ai.webui.probes.probe_model_fitness", probe),
        patch("soc_ai.notify.event_for_model_fitness") as event_for,
    ):
        calm = client.get("/api/v1/config/model-fitness?force=true").json()
    assert calm["alarm"] is False
    event_for.assert_not_called()

    app.state.elastic = _StubElastic([_audit_hit("fail", "2026-08-07T18:00:00+00:00", model)])
    with (
        patch("soc_ai.webui.probes.probe_model_fitness", probe),
        patch("soc_ai.notify.event_for_model_fitness", return_value=None) as event_for2,
    ):
        loud = client.get("/api/v1/config/model-fitness?force=true").json()
    assert loud["alarm"] is True
    event_for2.assert_called_once()

"""Tests for the analyst-path cloud egress sanitizer.

Covers the four contracts the feature stands on:

1. **Guard round-trip** — one :class:`EgressGuard` holds ONE mapping for its
   lifetime, so the same real value gets the same label across payloads and
   ``desanitize_obj`` restores originals exactly.
2. **Toolset boundary** — ``_guarded`` sanitizes tool RESULTS before the model
   sees them, restores label-bearing ARGUMENTS before the tool executes, and
   (via ``functools.wraps``) preserves the signature pydantic-ai reads for the
   tool schema.
3. **Report restore** — ``_desanitize_report`` round-trips a labeled
   TriageReport back to real values (summary / citations / nested fields).
4. **Off-by-default invariant** — ``analyst_cloud_redaction`` defaults False,
   and with no guard on the ctx the toolset registers the ORIGINAL closures
   (same object, no wrapper), so the default path is byte-identical.
"""

from __future__ import annotations

import inspect
from typing import Any
from unittest.mock import AsyncMock

from pydantic_ai import Agent
from pydantic_ai.models.test import TestModel
from soc_ai.agent.context import InvestigationContext
from soc_ai.agent.egress_guard import EgressGuard
from soc_ai.agent.orchestrator import _desanitize_report
from soc_ai.agent.toolset import _guarded, register_read_tools
from soc_ai.config import Settings
from soc_ai.triage_models import TriageReport

# A hostname on a reserved internal suffix (.local) — redacted by the default
# suffix rules with no extra config; and an RFC-1918 IP.
_HOST = "dc01.corp.local"
_IP = "10.0.0.5"


def _ctx(settings: Settings, guard: EgressGuard | None = None) -> InvestigationContext:
    ctx = InvestigationContext(settings=settings, auth=AsyncMock(), elastic=AsyncMock())
    ctx.egress_guard = guard
    return ctx


# ---------------------------------------------------------------------------
# 1. Guard round-trip + stable labels
# ---------------------------------------------------------------------------


def test_guard_round_trip_restores_originals() -> None:
    guard = EgressGuard(extra_hosts=(), extra_suffixes=())
    payload = {
        "host": _HOST,
        "ip": _IP,
        "path": "/home/jsmith/tools/scan.sh",
        "note": f"{_HOST} beaconed to {_IP}",
    }
    labeled = guard.sanitize_obj(payload)

    # Internal identifiers must be gone from the labeled copy...
    assert _HOST not in str(labeled)
    assert _IP not in str(labeled)
    assert "jsmith" not in str(labeled)
    assert labeled["host"].startswith("HOST_")
    assert labeled["ip"].startswith("IP_")
    # ...and cross-field references stay consistent (same value → same label).
    assert labeled["host"] in labeled["note"]
    assert labeled["ip"] in labeled["note"]

    # desanitize restores the exact original structure.
    assert guard.desanitize_obj(labeled) == payload


def test_guard_labels_stable_across_payloads() -> None:
    """The mapping lives for the guard's lifetime — a second payload citing the
    same host/IP MUST reuse the labels the first payload allocated."""
    guard = EgressGuard(extra_hosts=(), extra_suffixes=())
    first = guard.sanitize_obj({"host": _HOST, "ip": _IP})
    second = guard.sanitize_text(f"query events where host={_HOST} and ip={_IP}")
    assert first["host"] in second
    assert first["ip"] in second


def test_guard_extra_hosts_redact_bare_names() -> None:
    """A bare codename with no internal-suffix shape only redacts when
    enumerated via extra_hosts — mirrors the oracle sanitizer contract."""
    guard = EgressGuard(extra_hosts=("appserver01",), extra_suffixes=())
    labeled = guard.sanitize_text("appserver01 answered on 443")
    assert "appserver01" not in labeled
    assert "HOST_01" in labeled
    assert guard.desanitize_obj(labeled) == "appserver01 answered on 443"


async def test_for_settings_env_only_and_db_error_fallback(settings_kratos: Settings) -> None:
    """for_settings resolves env-only identifiers without a DB, and a broken
    session factory falls back to the settings tuples instead of raising."""
    guard = await EgressGuard.for_settings(settings_kratos)
    assert guard._extra_hosts == tuple(settings_kratos.oracle_extra_hosts)
    assert guard._extra_suffixes == tuple(settings_kratos.oracle_internal_suffixes)

    def _boom() -> Any:
        raise RuntimeError("db down")

    guard2 = await EgressGuard.for_settings(settings_kratos, _boom)  # type: ignore[arg-type]
    assert guard2._extra_hosts == tuple(settings_kratos.oracle_extra_hosts)
    assert guard2._extra_suffixes == tuple(settings_kratos.oracle_internal_suffixes)


# ---------------------------------------------------------------------------
# 2. Toolset boundary (_guarded)
# ---------------------------------------------------------------------------


async def test_guarded_sanitizes_results_and_restores_args(settings_kratos: Settings) -> None:
    guard = EgressGuard(extra_hosts=(), extra_suffixes=())
    ctx = _ctx(settings_kratos, guard)
    seen: dict[str, Any] = {}

    async def t_fake(query: str) -> dict[str, Any]:
        """Fake read tool."""
        seen["query"] = query
        return {"host": _HOST, "ip": _IP}

    wrapped = _guarded(ctx, t_fake)

    # Tool RESULT reaches the model in label space.
    result = await wrapped(f"host:{_HOST}")
    assert result == {"host": "HOST_01", "ip": "IP_01"}
    # The inbound arg carried a real value — passed through unchanged.
    assert seen["query"] == f"host:{_HOST}"

    # A label the model echoes back reaches the inner fn as the REAL value —
    # positional and keyword paths both restore.
    await wrapped("pivot on HOST_01 and IP_01")
    assert seen["query"] == f"pivot on {_HOST} and {_IP}"
    await wrapped(query="host:HOST_01")
    assert seen["query"] == f"host:{_HOST}"


def test_guarded_preserves_signature_and_doc(settings_kratos: Settings) -> None:
    """functools.wraps must keep the exact signature/doc pydantic-ai reads —
    a schema of (*args, **kwargs) would blind the model to the parameters."""
    guard = EgressGuard(extra_hosts=(), extra_suffixes=())
    ctx = _ctx(settings_kratos, guard)

    async def t_fake(query: str, max_results: int = 25) -> dict[str, Any]:
        """Fake read tool docstring."""
        return {}

    wrapped = _guarded(ctx, t_fake)
    assert wrapped is not t_fake  # actually wrapped when a guard is present
    assert inspect.signature(wrapped) == inspect.signature(t_fake)
    assert wrapped.__doc__ == t_fake.__doc__
    assert wrapped.__name__ == "t_fake"


def test_registered_tool_schema_exposes_real_params(settings_kratos: Settings) -> None:
    """End-to-end through register_read_tools: with a guard active, the
    pydantic-ai tool schema still exposes the real parameter names."""
    guard = EgressGuard(extra_hosts=(), extra_suffixes=())
    ctx = _ctx(settings_kratos, guard)
    agent: Agent[None, str] = Agent(TestModel(call_tools=[]), output_type=str)
    register_read_tools(agent, ctx, role="chat")

    tool = agent._function_toolset.tools["t_query_events_oql"]
    schema = tool.tool_def.parameters_json_schema
    assert set(schema["properties"]) == {"query", "time_range_minutes", "max_results"}
    # The docstring (the LLM-visible description) survived the wrap too.
    assert "OQL" in (tool.tool_def.description or "")
    # And the registered closure really is the guard wrapper.
    assert hasattr(tool.function, "__wrapped__")


# ---------------------------------------------------------------------------
# 3. _desanitize_report
# ---------------------------------------------------------------------------


def test_desanitize_report_restores_labels() -> None:
    guard = EgressGuard(extra_hosts=(), extra_suffixes=())
    # Learn the labels the way a run would — by sanitizing the outbound context.
    labeled_ctx = guard.sanitize_text(f"{_HOST} {_IP}")
    host_label, ip_label = labeled_ctx.split()

    report = TriageReport(
        verdict="false_positive",
        confidence=0.9,
        summary=f"{host_label} pinged {ip_label}; expected sync traffic.",
        citations=[f"enrichments.{ip_label}.blocklist", "community_id_events.0.source_ip"],
        recommended_actions=[],
    )
    restored = _desanitize_report(report, guard)
    assert _HOST in restored.summary
    assert _IP in restored.summary
    assert host_label not in restored.summary
    assert restored.citations[0] == f"enrichments.{_IP}.blocklist"
    # Untouched fields survive the round-trip.
    assert restored.verdict == "false_positive"
    assert restored.confidence == 0.9
    assert restored.citations[1] == "community_id_events.0.source_ip"


# ---------------------------------------------------------------------------
# 4. Off-by-default invariant
# ---------------------------------------------------------------------------


def test_config_defaults_off(settings_kratos: Settings) -> None:
    assert settings_kratos.analyst_cloud_redaction is False


def test_no_guard_leaves_closures_unwrapped(settings_kratos: Settings) -> None:
    """ctx.egress_guard None (the default) → _guarded returns the SAME object,
    so register_read_tools hands pydantic-ai the original closures and the
    default path carries no wrapper at all."""
    ctx = _ctx(settings_kratos, guard=None)

    async def t_fake(query: str) -> dict[str, Any]:
        """Fake read tool."""
        return {}

    assert _guarded(ctx, t_fake) is t_fake

    agent: Agent[None, str] = Agent(TestModel(call_tools=[]), output_type=str)
    register_read_tools(agent, ctx, role="chat")
    tool = agent._function_toolset.tools["t_query_events_oql"]
    # No guard → no functools.wraps wrapper in the registered function.
    assert not hasattr(tool.function, "__wrapped__")

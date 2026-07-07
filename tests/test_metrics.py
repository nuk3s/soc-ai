"""Unit tests for the Prometheus metrics renderer.

Exercises ``soc_ai.metrics.render`` directly with a synthetic counter
state so we don't have to spin up the full app stack. Also walks a few
SSE events through ``record_event`` to make sure the orchestrator's
audit hook drives the right counters.
"""

from __future__ import annotations

import pytest
from soc_ai import metrics


@pytest.fixture
def clean_metrics() -> metrics._Metrics:
    """Replace the module-level metrics singleton with a fresh one per test."""
    fresh = metrics._Metrics()
    metrics._GLOBAL = fresh
    return fresh


def test_render_emits_required_help_and_type_lines(clean_metrics: metrics._Metrics) -> None:
    body = metrics.render(version="0.1.0")
    # Every metric must have a HELP and TYPE line per Prometheus 0.0.4.
    for name in [
        "socai_build_info",
        "socai_uptime_seconds",
        "socai_investigations_total",
        "socai_investigation_errors_total",
        "socai_investigation_retasks_total",
        "socai_investigation_fallback_verdicts_total",
        "socai_investigation_zero_tool_verdicts_total",
        "socai_tool_calls_total",
        "socai_llm_tokens_total",
    ]:
        assert f"# HELP {name} " in body, f"missing HELP for {name}"
        assert f"# TYPE {name} " in body, f"missing TYPE for {name}"

    # Build info is labeled.
    assert 'socai_build_info{version="0.1.0"} 1' in body
    # The approval gate is gone — its gauge must not be exposed anymore.
    assert "socai_pending_approvals" not in body


@pytest.mark.asyncio
async def test_record_event_drives_tool_call_counter(
    clean_metrics: metrics._Metrics,
) -> None:
    await clean_metrics.record_event("tool_call", {"tool_name": "t_query_zeek_logs"})
    await clean_metrics.record_event("tool_call", {"tool_name": "t_query_zeek_logs"})
    await clean_metrics.record_event("tool_call", {"tool_name": "t_enrich_ip"})
    body = metrics.render(version="0.1.0")
    assert 'socai_tool_calls_total{tool="t_query_zeek_logs"} 2' in body
    assert 'socai_tool_calls_total{tool="t_enrich_ip"} 1' in body


@pytest.mark.asyncio
async def test_record_event_drives_token_counter(
    clean_metrics: metrics._Metrics,
) -> None:
    await clean_metrics.record_event(
        "usage",
        {"phase": "investigator", "input_tokens": 100, "output_tokens": 20},
    )
    await clean_metrics.record_event(
        "usage",
        {"phase": "synthesizer", "input_tokens": 5000, "output_tokens": 200},
    )
    body = metrics.render(version="0.1.0")
    assert 'socai_llm_tokens_total{phase="investigator",direction="input"} 100' in body
    assert 'socai_llm_tokens_total{phase="synthesizer",direction="output"} 200' in body


@pytest.mark.asyncio
async def test_record_event_increments_retask_and_error_and_done_counters(
    clean_metrics: metrics._Metrics,
) -> None:
    await clean_metrics.record_event("retask", {})
    await clean_metrics.record_event("error", {})
    await clean_metrics.record_event("error", {})
    await clean_metrics.record_event("done", {})
    body = metrics.render(version="0.1.0")
    assert "socai_investigation_retasks_total 1" in body
    assert "socai_investigation_errors_total 2" in body
    assert "socai_investigations_total 1" in body


@pytest.mark.asyncio
async def test_record_event_increments_fallback_and_zero_tool_counters(
    clean_metrics: metrics._Metrics,
) -> None:
    await clean_metrics.record_event("fallback_verdict", {})
    await clean_metrics.record_event("fallback_verdict", {})
    await clean_metrics.record_event("zero_tool_verdict_blocked", {})
    body = metrics.render(version="0.1.0")
    assert "socai_investigation_fallback_verdicts_total 2" in body
    assert "socai_investigation_zero_tool_verdicts_total 1" in body


@pytest.mark.asyncio
async def test_record_event_ignores_unknown_kinds(
    clean_metrics: metrics._Metrics,
) -> None:
    """An unknown SSE event kind shouldn't crash or update any counter."""
    await clean_metrics.record_event("future_kind", {"hello": "world"})
    body = metrics.render(version="0.1.0")
    # No counters bumped.
    assert "socai_investigations_total 0" in body
    assert "socai_investigation_errors_total 0" in body


def test_render_escapes_label_values(clean_metrics: metrics._Metrics) -> None:
    """Version strings with quotes/backslashes/newlines don't break the format."""
    body = metrics.render(version='1.0.0"weird\\quotes')
    # The escape sequence MUST be present and the quote/backslash NOT raw.
    assert 'socai_build_info{version="1.0.0\\"weird\\\\quotes"}' in body

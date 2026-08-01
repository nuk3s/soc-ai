"""Regression tests for the 2026-07-30 agent-core review (bucket B01).

Covers:

* F15 - Phase-D targeted dispatch must thread the alert time anchor
  (``ctx.default_time_anchor``) into the ES-query tool family, exactly as the
  interactive toolset wrappers do, so ``query_events_oql`` / ``query_zeek_logs``
  center their window on the alert's ``@timestamp`` instead of falling to the
  now-relative branch. The injection must NOT break family members that don't
  accept ``time_anchor`` (dropped by the dispatcher's signature filter).
* F52 - the synth-first system rubric must not sanction ``template-id`` as a
  citation form: a bare decision-template id can never resolve against the
  enriched context (templates match after prefetch), so sanctioning it drove
  coverage_ratio to zero on prompt-compliant clean-internal verdicts.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest


class _CapturedResult:
    """Minimal EsSearchResult stand-in: only model_dump is exercised."""

    def model_dump(self, mode: str = "json") -> dict[str, Any]:
        return {"total": 0, "took_ms": 1, "aggregations": None, "hits": []}


class _StubCtx:
    settings = object()
    elastic = object()
    auth = object()
    default_time_anchor: datetime | None = None


@pytest.mark.asyncio
async def test_phase_d_dispatch_threads_time_anchor_into_query_events(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """F15: a Phase-D t_query_events_oql dispatch must forward
    ctx.default_time_anchor as the tool's time_anchor. Before the fix the
    ES-query branch injected only elastic+auth, so the query ran against a
    now-relative window and returned zero hits for any batch/older alert.
    """
    import soc_ai.tools.query_events as qe_mod
    from soc_ai.agent.targeted_investigator import _dispatch_named_tool

    anchor = datetime(2026, 7, 24, 6, 0, 0, tzinfo=UTC)
    seen: dict[str, Any] = {}

    async def fake_query(query: str, *, max_results: int = 100, **kwargs: Any) -> _CapturedResult:
        seen["query"] = query
        seen["time_anchor"] = kwargs.get("time_anchor")
        return _CapturedResult()

    monkeypatch.setattr(qe_mod, "query_events_oql", fake_query)

    ctx = _StubCtx()
    ctx.default_time_anchor = anchor

    out = await _dispatch_named_tool(
        "t_query_events_oql",
        {"query": "source.ip:10.0.0.5 AND event.dataset:zeek.dns", "time_range_minutes": 60},
        ctx,
    )

    assert isinstance(out, dict)
    assert seen["time_anchor"] == anchor, (
        "Phase-D dispatch must thread ctx.default_time_anchor into the query tool"
    )


@pytest.mark.asyncio
async def test_phase_d_dispatch_time_anchor_dropped_for_non_anchored_family_member(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """F15 guard: injecting time_anchor for the ES-query family must NOT break the
    members whose signature has no time_anchor (query_cases / query_detections /
    get_rule_content / get_event_raw / get_playbooks). The dispatcher's signature
    filter drops it (same as it already drops the injected `auth`), so the tool
    still binds without a TypeError.
    """
    import soc_ai.tools.query_cases as qc_mod
    from soc_ai.agent.targeted_investigator import _dispatch_named_tool

    # Strict signature (no **kwargs, no time_anchor, no auth) mirroring the real
    # query_cases: if the injected time_anchor/auth were NOT dropped this raises.
    async def strict_cases(
        query: str,
        *,
        elastic: Any,
        settings: Any,
        status: str | None = None,
        max_results: int = 25,
    ) -> list[dict[str, Any]]:
        return []

    monkeypatch.setattr(qc_mod, "query_cases", strict_cases)

    ctx = _StubCtx()
    ctx.default_time_anchor = datetime(2026, 7, 24, 6, 0, 0, tzinfo=UTC)

    out = await _dispatch_named_tool("t_query_cases", {"query": "exfil"}, ctx)
    # A successful bind wraps the list return; a leaked kwarg would have raised.
    assert out == {"result": []}


def test_synth_first_rubric_does_not_sanction_template_id_citation() -> None:
    """F52: the synth-first system prompt must not list template-id as a valid
    citation form (the citation resolver can never resolve one, so sanctioning it
    zeroes coverage_ratio on prompt-compliant clean-internal verdicts). The other
    sanctioned forms must remain.
    """
    from soc_ai.agent.prompts import build_synth_first_system_prompt

    prompt = build_synth_first_system_prompt()
    assert "template-id" not in prompt, "synth-first rubric must not sanction template-id citations"
    # The still-valid forms must survive the edit.
    assert "blocklist-hit" in prompt
    assert "Cite every claim" in prompt

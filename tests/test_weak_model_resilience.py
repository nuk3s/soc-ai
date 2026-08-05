"""Pipeline resilience + diagnosability fixes (prod evidence, 2026-08-03/04).

These began as "the lower-tier fallback models are failing", which the data did
NOT support. Read this before trusting any per-model claim here:

  The `qwen3.6-35b-*` routes on this gateway are ALIASES for the
  deepseek-v4-flash engine (`/model/info`: both -> hosted_vllm/deepseek-v4-flash
  @ 192.0.2.10:8000), and `laguna-s21` is decommissioned. Every behaviour first
  attributed to "qwen" was DeepSeek V4 under a qwen-shaped route name. The one
  genuine lower-tier text backend, `qwen3.6-35b-cpu`, handled the TriageReport
  contract 4/4 under both tool_choice modes.

What the 14-day prod window actually shows, none of it model-specific:

- 44 of 64 error rows landed on ONE day (2026-08-03, 42.7% error rate vs 0-5%
  baseline) — the V4 restore, when every route 500'd. An infra outage.
- 49 of 64 error rows carried NO error event at all; 41 on that same day. Cause:
  ``recorded_run`` only ever called ``recorder.record`` from inside its streaming
  loop, so the timeout / cancel / crash handlers finalized ``status='error'``
  with nothing to explain it. Raising a timeout does NOT fix this — it only
  changes which clock fires.
- Completed runs: p50 2.1min, p95 5.7min, p99 8.6min against a 10min per-target
  cap that was tighter than the 15min whole-run backstop it duplicates.
- 8 of 15 recorded error events blamed "elasticsearch / Security Onion
  unreachable" for a dead vLLM backend behind LiteLLM.
- 7 of 11 pipeline fallbacks came from phase ``investigation_loop_synth`` — the
  one synthesizer built with pydantic-ai's default retry budget of 1.
- A live model emitted ``"resolution": "None"`` (the string) for a nullable dict.
"""

from __future__ import annotations

import pytest
from pydantic import SecretStr, ValidationError
from soc_ai.config import Settings
from soc_ai.triage_models import TriageReport


def _settings(**over) -> Settings:
    """Settings without env loading (mirrors conftest's ``_base_settings_kwargs``)."""
    kwargs = {
        "so_host": "https://so.example.com",
        "so_username": "analyst",
        "so_password": SecretStr("password123"),
        "so_verify_ssl": False,
        "es_hosts": ["https://so.example.com:9200"],
        "litellm_base_url": "http://localhost:4000",
        "api_auth_required": False,
    }
    kwargs.update(over)
    return Settings(**kwargs)


def _report(**over):
    base = dict(verdict="false_positive", confidence=0.8, summary="x" * 40)
    base.update(over)
    return base


# --------------------------------------------------------------------------
# Fix D — schema coercion for the shapes weak models actually emit
# --------------------------------------------------------------------------


@pytest.mark.parametrize("sentinel", ["None", "null", "N/A", "", "none", "nil"])
@pytest.mark.parametrize("field", ["resolution", "gap_for_investigator"])
def test_null_sentinel_strings_coerce_to_none(field, sentinel):
    """A model that writes the STRING "None" for a nullable container must not
    burn a schema retry.

    ``_decode_stringified_json`` only rescued JSON-encoded containers; a bare
    null sentinel fell through as a str and failed ``dict_type``. Observed live
    on ``resolution`` from the deepseek-v4-flash engine (serving the
    qwen3.6-35b-instruct route alias) — i.e. from the PRIMARY model, not a
    fallback-tier one.
    """
    rep = TriageReport.model_validate(_report(**{field: sentinel}))
    assert getattr(rep, field) is None


def test_model_cannot_spoof_a_pipeline_fallback_via_stringified_resolution():
    """``resolution`` deliberately gets sentinel-rescue only, NOT JSON decoding.

    ``resolution['provenance']='pipeline_fallback'`` is privileged: it suppresses
    Oracle escalation, drops the run from the Needs-info KPI, and renders the row
    as an infrastructure failure. Nothing downstream strips a model-supplied
    value, so the model must not be able to talk its way into that marker with a
    stringified object.
    """
    with pytest.raises(ValidationError):
        TriageReport.model_validate(_report(resolution='{"provenance": "pipeline_fallback"}'))


def test_real_null_and_real_dict_still_work():
    """The coercion must not disturb well-formed output."""
    assert TriageReport.model_validate(_report(resolution=None)).resolution is None
    assert TriageReport.model_validate(_report(resolution={"a": 1})).resolution == {"a": 1}


def test_meaningful_strings_are_not_swallowed():
    """Only null SENTINELS coerce — a real string must still raise, not silently
    become None (that would hide genuine model errors)."""
    with pytest.raises(ValidationError):
        TriageReport.model_validate(_report(resolution="the model said something here"))


# --------------------------------------------------------------------------
# Fix B — a gateway/vLLM outage must not be reported as an Elasticsearch outage
# --------------------------------------------------------------------------


def test_llm_gateway_outage_hint_does_not_blame_elasticsearch():
    """8/15 prod error events sent the operator to debug Security Onion for what
    was a dead vLLM backend behind LiteLLM — during the very outage they were
    trying to diagnose."""
    from soc_ai.agent.orchestrator import _hint_for

    exc = RuntimeError(
        "status_code: 500, model_name: deepseek-v4-flash, body: {'message': "
        '"litellm.InternalServerError: InternalServerError: Hosted_vllmException '
        '- Cannot connect to host 192.0.2.10:8000 ssl:default"}'
    )
    hint = (_hint_for(exc) or "").lower()
    # The operator must be pointed at the model-serving stack, not sent to
    # verify the SO grid / ES_HOSTS (which is what the old hint told them).
    assert "es_hosts" not in hint
    assert "so grid" not in hint
    assert "gateway" in hint or "backend" in hint


def test_genuine_elasticsearch_outage_still_hints_elasticsearch():
    """The ES hint must survive for real ES failures — no over-correction."""
    from soc_ai.agent.orchestrator import _hint_for

    hint = _hint_for(RuntimeError("Cannot connect to host 192.0.2.53:9200 ssl:default")) or ""
    assert "elasticsearch" in hint.lower()


# --------------------------------------------------------------------------
# Fix A — the auto-triage cap must never pre-empt the graceful inner backstop
# --------------------------------------------------------------------------


def test_auto_triage_cap_exceeds_whole_run_backstop():
    """Ordering invariant.

    Both nested guards now record an event, but they do not explain the failure
    equally well: the inner ``investigation_run_timeout_s`` reports a
    ``whole_run_backstop`` naming the wall clock and the model backend, and lets
    the orchestrator's per-turn timeout conclude with the round-1 verdict first.
    The outer per-target cap can only cancel from the consumer side and reports
    the far weaker ``run_cancelled``. Whichever fires first decides what the
    operator sees, so the informative one must win.
    """
    s = _settings()
    assert s.auto_triage_per_target_timeout_s > s.investigation_run_timeout_s


def test_effective_per_target_timeout_is_clamped_even_if_misconfigured():
    """Defense in depth: an operator lowering the knob must not re-introduce the
    silent-cancel failure mode."""
    from soc_ai.webui.autotriage import _effective_per_target_timeout

    s = _settings(auto_triage_per_target_timeout_s=60, investigation_run_timeout_s=900)
    assert _effective_per_target_timeout(s) > 900


# --------------------------------------------------------------------------
# Fix C — the round-2 loop synthesizer had a retry budget of 1
# --------------------------------------------------------------------------


def test_loop_synthesizer_has_a_real_retry_budget():
    """7/11 prod pipeline fallbacks were phase ``investigation_loop_synth``.

    Verified reachable: ``build_synthesizer`` is the ``loop_synth`` agent, and the
    handler wrapping its ``run()`` is the one that stamps that phase. It took no
    ``retries``, so it got pydantic-ai's default of 1 while every sibling
    synthesizer uses 3-5 — one stochastic schema wobble ended the run.
    """
    from pydantic_ai.models.test import TestModel
    from soc_ai.agent.orchestrator import build_synth_first_agent, build_synthesizer

    agent = build_synthesizer(TestModel())
    # Parity with the synth-first agent, which already carried an explicit budget.
    assert agent._max_output_retries >= 3
    assert agent._max_output_retries == build_synth_first_agent(TestModel())._max_output_retries


# --------------------------------------------------------------------------
# Fix E — attribute a failure to the model that actually served it
# --------------------------------------------------------------------------


def test_served_backend_is_taken_from_gateway_headers_not_the_alias():
    """The alias is a LIE about which model ran, so attribution must not use it.

    ``qwen3.6-35b-instruct`` is a LiteLLM alias for the deepseek-v4-flash engine.
    Verified live 2026-08-04: the response body's ``model`` field AND pydantic-ai's
    ``ModelResponse.model_name`` both come back as ``qwen3.6-35b-instruct``, while
    ``x-litellm-model-api-base`` correctly reports ``http://192.0.2.10:8000/v1``.
    An earlier version of this fix read ``model_name`` and would have recorded the
    wrong model with full confidence.
    """
    import httpx
    from soc_ai.agent._gateway_retry import _record_attribution, capture_backend_attribution
    from soc_ai.agent.orchestrator import _served_backend

    resp = httpx.Response(
        200,
        headers={
            "x-litellm-model-api-base": "http://192.0.2.10:8000/v1",
            "x-litellm-model-group": "qwen3.6-35b-instruct",
            "x-litellm-attempted-fallbacks": "1",
        },
    )
    with capture_backend_attribution() as sink:
        _record_attribution(resp)

    got = _served_backend(sink)
    assert got["api_base"] == "http://192.0.2.10:8000/v1"
    assert got["attempted_fallbacks"] == "1"
    # The alias is retained as context, never as the answer to "what ran".
    assert got["model_group"] == "qwen3.6-35b-instruct"


def test_attribution_capture_is_inert_outside_a_capture_block():
    """The transport records on every call; with no sink active it must no-op."""
    import httpx
    from soc_ai.agent._gateway_retry import _record_attribution

    _record_attribution(httpx.Response(200, headers={"x-litellm-model-api-base": "x"}))


def test_served_backend_is_defensive():
    """Runs inside an error handler — never raise, and never invent a value."""
    from soc_ai.agent.orchestrator import _served_backend

    assert _served_backend({}) is None
    assert _served_backend(None) is None
    assert _served_backend("junk") is None


def test_error_payload_carries_served_backend():
    from soc_ai.agent.orchestrator import _error_payload

    p = _error_payload(
        RuntimeError("boom"),
        phase="synth_first_round1",
        round_num=1,
        served_backend={"api_base": "http://192.0.2.10:8011/v1"},
    )
    assert p["served_backend"]["api_base"] == "http://192.0.2.10:8011/v1"


def test_fallback_report_records_served_backend():
    """The provenance marker is what the pipeline-error drilldown reads."""
    from soc_ai.agent.orchestrator import _synth_failure_fallback_report

    rep = _synth_failure_fallback_report(
        "alert-1",
        "synth_first_round1",
        RuntimeError("boom"),
        served_backend={"api_base": "http://192.0.2.10:8011/v1"},
    )
    assert rep.resolution["served_backend"]["api_base"] == "http://192.0.2.10:8011/v1"


# --------------------------------------------------------------------------
# Fix A (behavioural) — a timed-out run must be DIAGNOSABLE, not just terminal
# --------------------------------------------------------------------------


def _drive_hanging_run(tmp_path, run_timeout: int):
    """Run ``recorded_run`` against a stream that never completes.

    Returns ``(status, error_event_payloads)`` for the persisted investigation.
    """
    import asyncio
    from collections.abc import AsyncIterator
    from types import SimpleNamespace

    from soc_ai.agent.context import StepEvent
    from soc_ai.api.runner import recorded_run
    from soc_ai.store.db import make_engine, make_sessionmaker, run_migrations
    from soc_ai.store.models import Investigation, InvestigationEvent
    from sqlalchemy import select

    # model_copy skips int-field revalidation, matching tests/test_autotriage.py.
    settings = _settings(db_path=str(tmp_path / "t.db")).model_copy(
        update={"investigation_run_timeout_s": run_timeout}
    )

    async def _go():
        engine = make_engine(settings)
        await run_migrations(engine)
        maker = make_sessionmaker(engine)
        state = SimpleNamespace(db_sessionmaker=maker, settings=settings)

        async def _hangs() -> AsyncIterator[StepEvent]:
            yield StepEvent(kind="session_start", session_id="s", sequence=1, payload={})
            await asyncio.sleep(3600)

        inv_id = None
        async for name, data in recorded_run(
            state, alert_id="a1", started_by="test", event_stream=_hangs()
        ):
            if name == "investigation_created":
                inv_id = data["investigation_id"]

        async with maker() as db:
            inv = (
                await db.execute(select(Investigation).where(Investigation.id == inv_id))
            ).scalar_one()
            evs = (
                (
                    await db.execute(
                        select(InvestigationEvent).where(
                            InvestigationEvent.investigation_id == inv_id,
                            InvestigationEvent.kind == "error",
                        )
                    )
                )
                .scalars()
                .all()
            )
            return inv.status, [e.payload for e in evs]

    return asyncio.run(_go())


def test_wall_clock_timeout_persists_a_diagnosable_error_event(tmp_path):
    """The 49 silent prod rows are the real defect, and raising the cap alone
    does NOT fix them.

    ``recorded_run`` calls ``recorder.record`` only inside its streaming loop;
    every terminal handler (timeout, cancel, crash) called ``finish()`` alone. So
    a timed-out run persisted ``status='error'`` with NO error event — nothing for
    the pipeline-error drilldown to show, and nothing to tell the operator the
    model backend was the problem. Reordering the two timeouts only moves WHICH
    clock fires; it does not make the row diagnosable.
    """
    status, payloads = _drive_hanging_run(tmp_path, run_timeout=1)

    assert status == "error"
    assert payloads, "timed-out run persisted no error event — the row is undiagnosable"
    joined = " ".join(str(p) for p in payloads).lower()
    assert "timeout" in joined or "wall-clock" in joined


def test_outer_cap_cancelling_the_stream_also_persists_an_error_event(tmp_path):
    """The auto-triage per-target cap cancels the CONSUMER, which closes this
    generator — the exact path that produced all 49 silent prod rows.

    Reproduces it directly: consume one event, then ``aclose()`` mid-stream the
    way ``run_auto_triage``'s ``asyncio.timeout`` does, and assert the row is
    diagnosable rather than a bare ``status='error'``.
    """
    import asyncio
    from collections.abc import AsyncIterator
    from types import SimpleNamespace

    from soc_ai.agent.context import StepEvent
    from soc_ai.api.runner import recorded_run
    from soc_ai.store.db import make_engine, make_sessionmaker, run_migrations
    from soc_ai.store.models import Investigation, InvestigationEvent
    from sqlalchemy import select

    settings = _settings(db_path=str(tmp_path / "c.db"))

    async def _go():
        engine = make_engine(settings)
        await run_migrations(engine)
        maker = make_sessionmaker(engine)
        state = SimpleNamespace(db_sessionmaker=maker, settings=settings)

        async def _hangs() -> AsyncIterator[StepEvent]:
            yield StepEvent(kind="session_start", session_id="s", sequence=1, payload={})
            await asyncio.sleep(3600)

        stream = recorded_run(state, alert_id="a1", started_by="test", event_stream=_hangs())
        inv_id = None
        # Mirror run_auto_triage exactly: consume under an outer asyncio.timeout,
        # then guarantee aclose() in a finally. The timeout cancels the CONSUMER
        # mid-read, which is what closes this generator in production.
        try:
            async with asyncio.timeout(0.5):
                async for name, data in stream:
                    if name == "investigation_created":
                        inv_id = data["investigation_id"]
        except TimeoutError:
            pass
        finally:
            await stream.aclose()

        async with maker() as db:
            inv = (
                await db.execute(select(Investigation).where(Investigation.id == inv_id))
            ).scalar_one()
            evs = (
                (
                    await db.execute(
                        select(InvestigationEvent).where(
                            InvestigationEvent.investigation_id == inv_id,
                            InvestigationEvent.kind == "error",
                        )
                    )
                )
                .scalars()
                .all()
            )
            return inv.status, [e.payload for e in evs]

    status, payloads = asyncio.run(_go())
    assert status == "error"
    assert payloads, "cancelled run persisted no error event — this is the 49-row bug"
    assert any("cancel" in str(p).lower() for p in payloads)

"""The judge of arm D and the lead of arm E: one function, two inputs.

A synthesizer agent with no tools reads the alert context the loop gives the
investigator and the briefs, and writes the same ``TriageReport`` the W3 loop
writes (docs/dev/specs/2026-10-08-swarm-triage-experiment-design.md). It has
``judge_request_limit`` requests, which cover its schema retries.

It may cite only the document ids the briefs carry. Any other id-shaped
citation is dropped before the gates, and the drop is counted. An id is what
the gates call an id (:func:`soc_ai.agent.evidence._classify_citation`), so
the two never disagree on what a document id is. The gates then resolve every
citation that is left against what the run retrieved, as they do for the one
loop.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import AsyncGenerator, Iterable, Sequence
from typing import Any, Final

from pydantic_ai import capture_run_messages
from pydantic_ai.exceptions import UsageLimitExceeded
from pydantic_ai.usage import RunUsage, UsageLimits

from soc_ai.agent import orchestrator as _orch
from soc_ai.agent._gateway_retry import capture_backend_attribution
from soc_ai.agent.context import StepEvent
from soc_ai.agent.egress_guard import EgressResidueError
from soc_ai.agent.evidence import _classify_citation
from soc_ai.agent.loop_result import LoopResult
from soc_ai.agent.swarm.briefs import brief_document_ids, render_brief
from soc_ai.agent.swarm.runner import (
    STATUS_COMPLETE,
    STATUS_ERROR,
    STATUS_LIMIT,
    SwarmInputs,
    WorkerOutcome,
    usage_counts,
)
from soc_ai.agent.triage import TriageReport

_LOGGER = logging.getLogger(__name__)

JUDGE: Final = "judge"
LEAD: Final = "lead"

# How many dropped citations the counters quote. The count is always whole.
_DROPPED_EXAMPLES = 5

_JUDGE_RULES = """
## Your job: the judge

You are the judge. A threat advocate and a benign advocate investigated the
alert above with the read tools. Each one argued one side and wrote the brief
above. You have no tools. Write the TriageReport from the alert context
above and from the two briefs.
"""

_LEAD_RULES = """
## Your job: the lead

You are the lead. One worker read each evidence plane of the alert above
with the tools of that plane, and wrote the brief above. You have no tools.
Write the TriageReport from the alert context above and from the briefs.
"""

_REPORT_RULES = """
Rules for the report:

- The sections above tell an investigator to call tools. You cannot call a
  tool. Decide from what the alert and the briefs show.
- Weigh the evidence of each brief. A brief with no evidence, or a brief with
  an error, is a gap. It is not evidence for another brief.
- Cite only the document ids that the briefs list as evidence. The pipeline
  removes every other document id from your citations. A field path of the
  alert, such as `alert.rule_name`, is not a document id, and you may cite it.
- Never leave the citation list empty when a brief carries evidence for
  your verdict.
- Use `needs_more_info` when the briefs do not settle the alert. Name the
  gap in the summary. Never recommend a write action on a `needs_more_info`
  verdict.
"""


def judge_message(context_msg: str, outcomes: Sequence[WorkerOutcome], *, role: str) -> str:
    """The judge's user message: the loop's alert context, the briefs, the rules."""
    briefs = "\n## The briefs\n\n" + "\n".join(
        render_brief(f"Brief {n}: {o.label}", o.brief) for n, o in enumerate(outcomes, start=1)
    )
    rules = _JUDGE_RULES if role == JUDGE else _LEAD_RULES
    return context_msg + "\n" + briefs + rules + _REPORT_RULES


def drop_foreign_citations(
    report: TriageReport, allowed_ids: Iterable[str]
) -> tuple[TriageReport, list[str]]:
    """Remove every id-shaped citation the briefs do not carry.

    Returns ``(report, dropped)``. A citation that is not an id (a field path,
    a tool name, prose) stays, and the gates read it as they read any other.
    """
    allowed = {doc_id.strip().lower() for doc_id in allowed_ids if doc_id.strip()}
    kept: list[str] = []
    dropped: list[str] = []
    for citation in report.citations:
        kind, target = _classify_citation(str(citation))
        if kind == "id" and (target or "").strip().lower() not in allowed:
            dropped.append(citation)
        else:
            kept.append(citation)
    if not dropped:
        return report, []
    return report.model_copy(update={"citations": kept}), dropped


async def run_judge(  # noqa: PLR0915 - one agent run, its stop rules and its events
    loop: LoopResult,
    inputs: SwarmInputs,
    outcomes: Sequence[WorkerOutcome],
    *,
    role: str,
) -> AsyncGenerator[StepEvent, None]:
    """Run the judge once and fill ``loop`` with its report.

    On success ``loop.output`` is the report with the foreign citations
    dropped, and ``loop.counters`` carries the drops. A budget cut or a turn
    timeout sets ``loop.budget_exc``. A blocked egress sets
    ``loop.egress_blocked``. Any other failure sets ``loop.stopped``, after
    its error event, exactly as a failed loop does.
    """
    settings = inputs.ctx.settings
    guard = inputs.guard
    make_ev = inputs.make_ev
    label = "the judge" if role == JUDGE else "the lead"
    yield make_ev(
        "swarm_agent_started",
        {
            "role": role,
            "label": label,
            "strategy": loop.strategy,
            "tool_calls_limit": 0,
            "request_limit": settings.judge_request_limit,
            "tools": [],
            "briefs": len(outcomes),
        },
    )
    allowed = brief_document_ids(o.brief for o in outcomes)
    msg = judge_message(inputs.context_msg, outcomes, role=role)
    if guard is not None:
        # The briefs are model output in label space, and the context is
        # sanitized already. The sweep covers the composed message.
        msg = guard.sanitize_text(msg)

    status = STATUS_COMPLETE
    usage = RunUsage()
    dropped: list[str] = []
    captured: list[Any] = []
    attr: dict[str, Any] = {}
    result: Any = None
    try:
        msg = _orch._guard_egress(guard, msg, settings)
        agent = _orch.build_synthesizer(
            _orch.build_synthesizer_model(settings, temperature=settings.synthesizer_temperature),
            output_mode=settings.synthesizer_output_mode,
        )
        with capture_run_messages() as captured, capture_backend_attribution() as attr:
            async with asyncio.timeout(settings.investigation_turn_timeout_s):
                result = await agent.run(
                    msg,
                    usage_limits=UsageLimits(
                        request_limit=settings.judge_request_limit, tool_calls_limit=0
                    ),
                )
    except asyncio.CancelledError:
        raise
    except EgressResidueError as e:
        status = STATUS_ERROR
        yield make_ev("egress_blocked", {"phase": "swarm_judge", "leaked_count": len(e.leaked)})
        yield make_ev("error", _orch._error_payload(e, phase="swarm_judge", round_num=0))
        loop.egress_blocked = e
    except (UsageLimitExceeded, TimeoutError) as e:
        status = STATUS_LIMIT
        _LOGGER.warning("swarm %s stopped at its limit: %s", role, e)
        yield make_ev(
            "error",
            _orch._error_payload(
                e,
                phase="swarm_judge_budget",
                round_num=2,
                retry_causes=_orch._retry_causes_from_messages(captured),
            ),
        )
        loop.budget_exc = e
    except BaseException as e:
        status = STATUS_ERROR
        _LOGGER.exception("swarm %s run failed", role)
        yield make_ev(
            "error",
            _orch._error_payload(
                e,
                phase="swarm_judge",
                round_num=2,
                retry_causes=_orch._retry_causes_from_messages(captured),
                served_backend=_orch._served_backend(attr),
            ),
        )
        loop.stopped = True

    served = _orch._served_backend(attr)
    if result is not None:
        report, dropped = drop_foreign_citations(result.output, allowed)
        loop.output = report
        loop.report_path = role
        # A swarm report is never re-run: no agent runs twice on one alert.
        loop.rerun = None
        loop.served_backend = served
        loop.messages.extend(result.all_messages())
        reasoning = _orch._synth_reasoning_payload(result)
        if reasoning is not None:
            if guard is not None:
                reasoning = guard.desanitize_obj(reasoning)
            yield make_ev("model_response", {**reasoning, "phase": "synthesizer", "round": 2})
        judge_usage = _orch._run_usage(result)
        if judge_usage is not None:
            usage.incr(judge_usage)
            yield make_ev("usage", _orch._usage_event_payload(2, judge_usage, served))
    loop.counters["citations_dropped"] = len(dropped)
    if dropped:
        quoted = dropped[:_DROPPED_EXAMPLES]
        loop.counters["dropped_citations"] = (
            guard.desanitize_obj(quoted) if guard is not None else quoted
        )
    if loop.usage is None:
        loop.usage = RunUsage()
    loop.usage.incr(usage)
    yield make_ev(
        "swarm_agent_finished",
        {
            "role": role,
            "label": label,
            "strategy": loop.strategy,
            "status": status,
            **usage_counts(usage),
            "brief_ids": len(allowed),
            "citations_dropped": len(dropped),
        },
    )


__all__ = [
    "JUDGE",
    "LEAD",
    "drop_foreign_citations",
    "judge_message",
    "run_judge",
]

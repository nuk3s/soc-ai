"""The swarm strategies: one entry point the pipeline calls in place of the loop.

:func:`run_strategy` runs ``advocates`` (arm D) or ``planes`` (arm E) and
fills the same :class:`~soc_ai.agent.loop_result.LoopResult` the one loop
fills. The pipeline before and after the loop does not change
(docs/dev/specs/2026-10-08-swarm-triage-experiment-design.md, "The seam").

The order is fixed. The shared messages cross the egress check first. The
workers run in parallel and stream their events. The judge runs once, after
every worker is done. No agent calls another agent, and no agent runs twice.
"""

from __future__ import annotations

from collections.abc import AsyncGenerator

from pydantic_ai.usage import RunUsage

from soc_ai.agent import orchestrator as _orch
from soc_ai.agent.context import StepEvent
from soc_ai.agent.egress_guard import EgressResidueError
from soc_ai.agent.loop_result import ADVOCATES, SWARM_STRATEGIES, LoopResult
from soc_ai.agent.swarm.advocates import advocate_specs
from soc_ai.agent.swarm.briefs import brief_document_ids
from soc_ai.agent.swarm.judge import JUDGE, LEAD, run_judge
from soc_ai.agent.swarm.planes import plane_specs
from soc_ai.agent.swarm.runner import SwarmInputs, WorkerOutcome, run_workers


async def run_strategy(loop: LoopResult, inputs: SwarmInputs) -> AsyncGenerator[StepEvent, None]:
    """Run the swarm strategy ``loop.strategy`` and fill ``loop``.

    Yields every event the agents make, in order, built through
    ``inputs.make_ev``. The caller audits and streams them as it does the
    loop's events. ``loop.emits_report`` must be True: the judge writes a
    ``TriageReport``.
    """
    if loop.strategy not in SWARM_STRATEGIES:
        raise ValueError(f"not a swarm strategy: {loop.strategy!r}")
    settings = inputs.ctx.settings
    make_ev = inputs.make_ev
    # The messages every worker sends cross the egress boundary once, before
    # the first model call. A blocked message stops the swarm with no call.
    for message in (inputs.worker_msg, inputs.context_msg):
        try:
            _orch._guard_egress(inputs.guard, message, settings)
        except EgressResidueError as e:
            yield make_ev("egress_blocked", {"phase": "swarm", "leaked_count": len(e.leaked)})
            yield make_ev("error", _orch._error_payload(e, phase="swarm", round_num=0))
            loop.egress_blocked = e
            return

    specs = advocate_specs(inputs) if loop.strategy == ADVOCATES else plane_specs(inputs)
    outcomes: list[WorkerOutcome] = []
    async for ev in run_workers(
        specs,
        strategy=loop.strategy,
        settings=settings,
        guard=inputs.guard,
        make_ev=make_ev,
        outcomes=outcomes,
    ):
        yield ev

    loop.usage = RunUsage()
    for outcome in outcomes:
        loop.usage.incr(outcome.usage)
        # The tool results the gates read: the history of every worker whose
        # brief the judge reads. The judge's own history follows.
        loop.messages.extend(outcome.messages)
    loop.cited_ids = brief_document_ids(o.brief for o in outcomes)
    loop.counters.update(
        {
            "strategy": loop.strategy,
            "agents": len(outcomes) + 1,
            "workers": [
                {
                    "role": o.role,
                    "status": o.status,
                    "evidence": len(o.brief.evidence),
                    "tool_calls": o.usage.tool_calls,
                }
                for o in outcomes
            ],
            "tool_calls": sum(o.usage.tool_calls for o in outcomes),
            "tool_calls_budget": settings.agent_tool_calls_limit,
            "brief_ids": len(loop.cited_ids),
        }
    )
    role = JUDGE if loop.strategy == ADVOCATES else LEAD
    async for ev in run_judge(loop, inputs, outcomes, role=role):
        yield ev


__all__ = ["run_strategy"]

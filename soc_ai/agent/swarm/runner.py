"""Run swarm workers in parallel and stream their events.

A worker is one tool-using agent built through the investigator builder: an
advocate (:mod:`soc_ai.agent.swarm.advocates`) or a plane worker
(:mod:`soc_ai.agent.swarm.planes`). Each one runs once, under its own
``UsageLimits``, on its own copy of the investigation context, and returns a
:class:`~soc_ai.agent.swarm.briefs.Brief`.

The stop rules (docs/dev/specs/2026-10-08-swarm-triage-experiment-design.md):

* A worker that hits its limit or a turn timeout returns its brief so far: a
  no-tools call replays its history and writes the brief from the evidence it
  gathered. The partial triage synthesis of the one loop works the same way.
* A worker that raises returns an empty brief with the error text, and the
  judge reads it.
* No worker calls another agent, and no worker runs twice.

Every worker emits the events the one loop emits: ``tool_call``,
``tool_result`` and ``model_response`` as its nodes land, and one ``usage``
event per model run in the loop's shape. ``swarm_agent_started`` and
``swarm_agent_finished`` frame them. The run meter and the arms report then
count every call and every token.
"""

from __future__ import annotations

import asyncio
import copy
import logging
from collections.abc import AsyncGenerator, Callable, Sequence
from dataclasses import dataclass, field
from typing import Any

from pydantic_ai import Agent
from pydantic_ai.exceptions import UsageLimitExceeded
from pydantic_ai.usage import RunUsage, UsageLimits

from soc_ai.agent import orchestrator as _orch
from soc_ai.agent._gateway_retry import capture_backend_attribution
from soc_ai.agent._partial_replay import repair_dangling_tool_calls, replay_reasoning_context
from soc_ai.agent.context import InvestigationContext, StepEvent, _DedupTracker
from soc_ai.agent.egress_guard import EgressGuard
from soc_ai.agent.swarm.briefs import Brief, empty_brief, model_brief
from soc_ai.config import Settings

_LOGGER = logging.getLogger(__name__)

# Builds one StepEvent with the pipeline's session id and next sequence number.
EventFactory = Callable[[str, dict[str, Any]], StepEvent]

# The worker statuses a ``swarm_agent_finished`` event carries.
STATUS_COMPLETE = "complete"
STATUS_LIMIT = "limit"
STATUS_ERROR = "error"

# The instruction of the no-tools call that closes a worker cut short. Goes in
# ``instructions=``: the call replays a non-empty history, and pydantic-ai
# sends an agent's ``system_prompt`` only when the history is empty.
BRIEF_CLOSER_PROMPT = (
    "Your tool budget is spent. You cannot call a tool. Write your Brief now "
    "from the tool results above and the alert. Cite only records that a tool "
    "result above returned or that the alert carries. Name each check you "
    "could not make as a gap."
)


def share_budget(total: int, workers: int, per_worker: int) -> int:
    """The tool calls one of ``workers`` agents gets from a budget of ``total``.

    Each worker gets ``per_worker`` or less, so that the workers together never
    exceed ``total`` (``agent_tool_calls_limit``). An arm that wants more raises
    ``agent_tool_calls_limit`` in its environment.
    """
    if workers <= 0:
        return 0
    return max(0, min(per_worker, total // workers))


@dataclass
class SwarmInputs:
    """What the pipeline hands a swarm strategy: the loop's inputs, unchanged.

    ``worker_msg`` is the user message the loop gives the investigator, with
    no report block: a worker writes a brief and never the report.
    ``context_msg`` is the same message with no line about deferred tools. A
    plane worker and the judge read it: neither one can load a deferred tool.
    Both messages are composed and sanitized exactly as the loop's message is.

    ``trim_planes`` are the planes the standard class trims the loop's prompt
    to, or None for the whole prompt (the deep class, a hunt subject).
    ``make_ev`` is the pipeline's event factory, so every swarm event carries
    the run's session id and the next sequence number.
    """

    alert_id: str
    ctx: InvestigationContext
    enriched: Any
    worker_msg: str
    context_msg: str
    trim_planes: frozenset[str] | None
    guard: EgressGuard | None
    make_ev: EventFactory


@dataclass
class WorkerSpec:
    """One worker to run: its role, its agent, its message and its limits."""

    role: str
    label: str
    claim: str
    agent: Any
    user_msg: str
    tool_calls_limit: int
    request_limit: int
    # The tool names the worker may register, or None for the role's surface.
    tools: frozenset[str] | None = None

    @property
    def limits(self) -> UsageLimits:
        return UsageLimits(request_limit=self.request_limit, tool_calls_limit=self.tool_calls_limit)


@dataclass
class WorkerOutcome:
    """What one worker left behind."""

    role: str
    label: str
    brief: Brief
    status: str
    # The history the gates read. Empty for a worker whose brief the model did
    # not write: the judge never saw that evidence, so it grounds nothing.
    messages: list[Any] = field(default_factory=list)
    usage: RunUsage = field(default_factory=RunUsage)
    served_backend: dict[str, Any] | None = None

    @property
    def wrote_brief(self) -> bool:
        return self.brief.error is None


def worker_context(
    ctx: InvestigationContext,
    *,
    visible_tools: frozenset[str] | None,
    tool_allowlist: frozenset[str] | None,
) -> InvestigationContext:
    """A worker's own copy of the investigation context.

    The copy shares the clients, the settings, the time anchor and the egress
    guard, so the labels stay the same across workers. It gets its own dedup
    tracker: a worker must not read another worker's call as a duplicate of a
    call it never saw. It gets its own deferred-tool list, which its
    registration fills.
    """
    wctx = copy.copy(ctx)
    wctx.dedup = _DedupTracker()
    wctx.deferred_tool_names = []
    wctx.loop_visible_tools = visible_tools
    wctx.tool_allowlist = tool_allowlist
    return wctx


def registered_tool_names(agent: Any) -> list[str]:
    """The function tools registered on a pydantic-ai agent, sorted."""
    toolset = getattr(agent, "_function_toolset", None)
    tools = getattr(toolset, "tools", None)
    return sorted(tools) if isinstance(tools, dict) else []


def _desanitize(ev: StepEvent, guard: EgressGuard | None) -> StepEvent:
    if guard is None:
        return ev
    return ev.model_copy(update={"payload": guard.desanitize_obj(ev.payload)})


def usage_counts(usage: RunUsage) -> dict[str, int]:
    """The counts a ``swarm_agent_finished`` event carries."""
    return {
        "tool_calls": usage.tool_calls,
        "requests": usage.requests,
        "input_tokens": usage.input_tokens,
        "output_tokens": usage.output_tokens,
        "total_tokens": usage.total_tokens,
    }


async def _close_brief(
    settings: Settings,
    guard: EgressGuard | None,
    gathered: list[Any],
    *,
    result_out: list[Any],
) -> tuple[Brief, list[Any]]:
    """Write the brief of a worker cut short, from the history it gathered.

    Returns ``(brief, repaired_history)``. Raises on any failure. The caller
    then lands an empty brief with the error.
    """
    repaired = repair_dangling_tool_calls(gathered, closure_content=_orch._PARTIAL_CLOSURE_CONTENT)
    user_msg = replay_reasoning_context(repaired) + "Write your Brief now."
    if guard is not None:
        user_msg = guard.sanitize_text(user_msg)
    user_msg = _orch._guard_egress(guard, user_msg, settings)
    closer: Agent[None, Brief] = Agent(
        _orch.build_synthesizer_model(settings, temperature=settings.synthesizer_temperature),
        output_type=Brief,
        instructions=BRIEF_CLOSER_PROMPT,
        retries=2,
    )
    async with asyncio.timeout(settings.investigation_turn_timeout_s):
        result = await closer.run(
            user_msg,
            message_history=repaired,
            usage_limits=UsageLimits(request_limit=2, tool_calls_limit=0),
        )
    result_out.append(result)
    return model_brief(result.output), repaired


async def run_worker(  # noqa: PLR0915 - one agent run, its stop rules and its events
    spec: WorkerSpec,
    *,
    strategy: str,
    settings: Settings,
    guard: EgressGuard | None,
    make_ev: EventFactory,
    emit: Callable[[StepEvent], None],
) -> WorkerOutcome:
    """Run one worker to its brief. Never raises, except on a cancel.

    ``emit`` receives every event the worker makes, in the order it makes them.
    """

    def _role_ev(kind: str, payload: dict[str, Any]) -> StepEvent:
        return make_ev(kind, {**payload, "swarm_role": spec.role})

    emit(
        make_ev(
            "swarm_agent_started",
            {
                "role": spec.role,
                "label": spec.label,
                "strategy": strategy,
                "tool_calls_limit": spec.tool_calls_limit,
                "request_limit": spec.request_limit,
                "tools": sorted(spec.tools) if spec.tools is not None else None,
            },
        )
    )
    gathered: list[Any] = []
    attr: dict[str, Any] = {}
    agent_run: Any = None
    result: Any = None
    closer_runs: list[Any] = []
    status = STATUS_COMPLETE
    messages: list[Any] = []
    brief: Brief
    try:
        msg = _orch._guard_egress(guard, spec.user_msg, settings)
        with capture_backend_attribution() as attr:
            async with spec.agent.iter(msg, usage_limits=spec.limits) as run:
                agent_run = run
                node_iter = run.__aiter__()
                while True:
                    async with asyncio.timeout(settings.investigation_turn_timeout_s):
                        try:
                            node = await node_iter.__anext__()
                        except StopAsyncIteration:
                            break
                    node_msg = getattr(node, "model_response", None)
                    if node_msg is None:
                        node_msg = getattr(node, "request", None)
                    if node_msg is not None:
                        gathered.append(node_msg)
                        async for ev in _orch._walk_message(
                            node_msg, _role_ev, phase="investigation_loop", round_num=1
                        ):
                            emit(_desanitize(ev, guard))
            result = run.result
        if result is None:
            raise RuntimeError(f"the {spec.label} returned no result")
        brief = model_brief(result.output)
        messages = list(result.all_messages())
    except asyncio.CancelledError:
        raise
    except (UsageLimitExceeded, TimeoutError) as e:
        # Its brief so far: the evidence it gathered, written up with no tools.
        status = STATUS_LIMIT
        _LOGGER.info("swarm worker %s stopped at its limit: %s", spec.role, e)
        try:
            brief, messages = await _close_brief(settings, guard, gathered, result_out=closer_runs)
        except asyncio.CancelledError:
            raise
        except BaseException as close_exc:
            brief = empty_brief(
                spec.claim,
                f"The agent stopped at its limit ({e}). Its brief was not written: {close_exc}",
            )
            messages = []
    except BaseException as e:
        status = STATUS_ERROR
        _LOGGER.warning("swarm worker %s failed: %s", spec.role, e)
        brief = empty_brief(spec.claim, f"{type(e).__name__}: {e}")
        messages = []

    # The usage of the worker's own run. A run cut short has no result, and
    # its usage so far lives on the run object.
    usage = RunUsage()
    run_usage = _orch._run_usage(result if result is not None else agent_run)
    if run_usage is not None:
        usage.incr(run_usage)
    served = _orch._served_backend(attr)
    if usage.requests or usage.total_tokens:
        emit(make_ev("usage", _orch._usage_event_payload(1, usage, served)))
    total = RunUsage()
    total.incr(usage)
    for closer_run in closer_runs:
        closer_usage = _orch._run_usage(closer_run)
        if closer_usage is not None:
            emit(make_ev("usage", _orch._usage_event_payload(2, closer_usage)))
            total.incr(closer_usage)
    brief_payload: dict[str, Any] = brief.model_dump(mode="json")
    if guard is not None:
        brief_payload = guard.desanitize_obj(brief_payload)
    emit(
        make_ev(
            "swarm_agent_finished",
            {
                "role": spec.role,
                "label": spec.label,
                "strategy": strategy,
                "status": status,
                **usage_counts(total),
                "evidence": len(brief.evidence),
                "confidence": brief.confidence,
                "brief": brief_payload,
            },
        )
    )
    return WorkerOutcome(
        role=spec.role,
        label=spec.label,
        brief=brief,
        status=status,
        messages=messages if brief.error is None else [],
        usage=total,
        served_backend=served,
    )


async def run_workers(
    specs: Sequence[WorkerSpec],
    *,
    strategy: str,
    settings: Settings,
    guard: EgressGuard | None,
    make_ev: EventFactory,
    outcomes: list[WorkerOutcome],
) -> AsyncGenerator[StepEvent, None]:
    """Run every worker at once and yield their events as they land.

    ``outcomes`` receives one outcome per spec, in spec order, once every
    worker is done. A cancel of the consumer cancels every worker.
    """
    roles = [spec.role for spec in specs]
    if len(set(roles)) != len(roles):
        raise ValueError(f"a swarm role runs once per alert: {roles}")
    queue: asyncio.Queue[StepEvent | None] = asyncio.Queue()
    tasks = [
        asyncio.create_task(
            run_worker(
                spec,
                strategy=strategy,
                settings=settings,
                guard=guard,
                make_ev=make_ev,
                emit=queue.put_nowait,
            ),
            name=f"swarm-{spec.role}",
        )
        for spec in specs
    ]

    async def _close_queue() -> None:
        if tasks:
            await asyncio.wait(tasks)
        queue.put_nowait(None)

    closer = asyncio.create_task(_close_queue(), name="swarm-close")
    try:
        while True:
            ev = await queue.get()
            if ev is None:
                break
            yield ev
    finally:
        for task in (*tasks, closer):
            if not task.done():
                task.cancel()
    outcomes.extend(task.result() for task in tasks)


__all__ = [
    "BRIEF_CLOSER_PROMPT",
    "STATUS_COMPLETE",
    "STATUS_ERROR",
    "STATUS_LIMIT",
    "EventFactory",
    "SwarmInputs",
    "WorkerOutcome",
    "WorkerSpec",
    "registered_tool_names",
    "run_worker",
    "run_workers",
    "share_budget",
    "usage_counts",
    "worker_context",
]

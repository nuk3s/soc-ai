"""What the investigation loop hands the rest of the triage pipeline.

The synth-first pipeline (:func:`soc_ai.agent.orchestrator._run_synth_first_pipeline`)
runs an investigation loop between the round-1 synthesis and the gates. The
loop used to leave its outputs in a dozen local variables. They live here now,
in one object, so a strategy other than the one investigator can produce the
same outputs and the code after the loop cannot tell the strategies apart
(docs/dev/specs/2026-10-08-swarm-triage-experiment-design.md, "The seam").

The loop streams its events as it runs. This object holds what is left when
the stream ends.

Dependency-light on purpose: the orchestrator imports it at module load, and
the swarm package imports it beside the orchestrator.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Final

from pydantic_ai.usage import RunUsage

# The strategy values of ``Settings.investigator_strategy``.
SINGLE: Final = "single"
SPEND: Final = "spend"
ENSEMBLE: Final = "ensemble"
ADVOCATES: Final = "advocates"
PLANES: Final = "planes"

STRATEGIES: tuple[str, ...] = (SINGLE, SPEND, ENSEMBLE, ADVOCATES, PLANES)

# The strategies that run the one investigator. ``spend`` and ``ensemble`` are
# the single loop under the limits of their arm's environment.
SINGLE_LOOP_STRATEGIES: frozenset[str] = frozenset({SINGLE, SPEND, ENSEMBLE})

# The strategies that run the swarm package (soc_ai.agent.swarm).
SWARM_STRATEGIES: frozenset[str] = frozenset({ADVOCATES, PLANES})


@dataclass
class LoopResult:
    """The outputs of one investigation loop run, whichever strategy ran it.

    ``output`` is the final output of the run: a ``TriageReport`` when
    ``emits_report`` is True, else an ``InvestigationTranscript``. None when the
    run ended without one: a budget cut, a timeout, a blocked egress, an error.

    ``messages`` is the full message history the gates read. Its tool returns
    are the tool results of the run. ``gathered`` is the history streamed node
    by node, which the partial synthesis replays after a budget cut.

    ``usage`` is the summed model usage of every agent the strategy ran. The
    ``usage`` events were already emitted on the way, one per agent run.

    ``report_path`` names the call that wrote the report: ``investigator`` for
    the one loop, ``judge`` for a swarm. ``rerun`` is ``(agent, message,
    usage_limits)`` for the self-consistency vote, or None when the report
    must not be re-run.

    ``budget_exc`` is set when the run stopped at its budget or a turn timeout.
    ``egress_blocked`` is set when the fail-closed residue sweep blocked the
    first model call. ``stopped`` is True when the run failed outright: its
    error event already landed and the pipeline ends there.

    ``cited_ids`` are the document ids the agents of a swarm cited in their
    briefs. Empty for the one loop, whose citations live on its report.
    ``counters`` are the swarm counters the report carries: the agents, the
    briefs and the citations the judge lost. Empty for the one loop.
    """

    strategy: str
    emits_report: bool
    output: Any = None
    messages: list[Any] = field(default_factory=list)
    gathered: list[Any] = field(default_factory=list)
    usage: RunUsage | None = None
    served_backend: dict[str, Any] | None = None
    report_path: str | None = None
    rerun: tuple[Any, str, Any] | None = None
    budget_exc: BaseException | None = None
    egress_blocked: BaseException | None = None
    stopped: bool = False
    cited_ids: list[str] = field(default_factory=list)
    counters: dict[str, Any] = field(default_factory=dict)


def strategy_of(settings: Any) -> str:
    """The strategy the settings name. Anything unknown is ``single``.

    ``Settings`` validates the value, so an unknown one only comes from a test
    double. The default path must stay the default path for it.
    """
    value = getattr(settings, "investigator_strategy", SINGLE)
    return value if isinstance(value, str) and value in STRATEGIES else SINGLE


__all__ = [
    "ADVOCATES",
    "ENSEMBLE",
    "PLANES",
    "SINGLE",
    "SINGLE_LOOP_STRATEGIES",
    "SPEND",
    "STRATEGIES",
    "SWARM_STRATEGIES",
    "LoopResult",
    "strategy_of",
]

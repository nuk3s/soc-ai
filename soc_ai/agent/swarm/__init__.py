"""The swarm strategies of the investigation loop (the swarm triage experiment).

docs/dev/specs/2026-10-08-swarm-triage-experiment-design.md. The setting
``investigator_strategy`` picks the strategy of the investigation loop. The
values ``advocates`` and ``planes`` run this package in place of the one
investigator. Every agent it starts is built through the existing builders
and tool registration, and emits the events the loop emits.

* :mod:`~soc_ai.agent.swarm.briefs`: the brief an agent hands the judge.
* :mod:`~soc_ai.agent.swarm.runner`: the parallel run of the workers.
* :mod:`~soc_ai.agent.swarm.advocates`: arm D, a threat and a benign advocate.
* :mod:`~soc_ai.agent.swarm.planes`: arm E, one worker per evidence plane.
* :mod:`~soc_ai.agent.swarm.judge`: the judge of arm D and the lead of arm E.
* :mod:`~soc_ai.agent.swarm.strategy`: :func:`run_strategy`, the entry point.

The orchestrator imports this package inside the pipeline, never at module
load: the package imports the orchestrator's builders.
"""

from soc_ai.agent.swarm.briefs import Brief, BriefEvidence
from soc_ai.agent.swarm.runner import SwarmInputs, WorkerOutcome, WorkerSpec
from soc_ai.agent.swarm.strategy import run_strategy

__all__ = [
    "Brief",
    "BriefEvidence",
    "SwarmInputs",
    "WorkerOutcome",
    "WorkerSpec",
    "run_strategy",
]

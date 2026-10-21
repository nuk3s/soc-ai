"""Arm E: one worker per evidence plane of the alert.

The planes come from :func:`soc_ai.agent.budget.alert_planes`, the cheap facts
about the prefetch that the standard class already trims the loop's prompt
to (docs/dev/specs/2026-10-08-swarm-triage-experiment-design.md, arm E). One
worker runs per plane, in parallel. An alert with one plane runs one worker,
so arm E on such an alert is arm A with a lead. An alert with no plane runs
one general worker on the core tools.

A worker gets the tools of its plane only: the plane filter
(:func:`soc_ai.agent.budget.standard_visible_tools`) for that one plane, set
as a hard allowlist on the worker's own context. A tool outside it is not
registered, not even with deferred loading. Its system prompt is the loop's
prompt trimmed to that one plane, with a mandate appended.

The workers share the tool budget of the one loop. Each gets
``plane_worker_tool_calls``, or ``agent_tool_calls_limit`` divided by the
worker count when that is less.
"""

from __future__ import annotations

from typing import Final

from soc_ai.agent import budget
from soc_ai.agent import orchestrator as _orch
from soc_ai.agent.prompts import build_investigator_prompt
from soc_ai.agent.swarm.advocates import BRIEF_OUTPUT_RULES
from soc_ai.agent.swarm.briefs import Brief
from soc_ai.agent.swarm.runner import SwarmInputs, WorkerSpec, share_budget, worker_context

# The worker of an alert with no plane at all.
GENERAL: Final = "general"

# What each plane is, as the worker reads it. The facts are the ones
# soc_ai.agent.budget states for each plane.
PLANE_FOCUS: dict[str, str] = {
    budget.PLANE_NETWORK: "the flow of the alert: its session, its Zeek records and its peers",
    budget.PLANE_EXTERNAL: "the endpoints and the indicators outside the estate",
    budget.PLANE_EAST_WEST: "the traffic between two hosts inside the estate",
    budget.PLANE_WINDOWS: "the host logs, the Active Directory protocols and the attack rule",
    budget.PLANE_HOSTILE: "the malware or attack claim of the rule and what confirms it",
    budget.PLANE_PAYLOAD: "the bytes the rule matched",
    budget.PLANE_FILE: "the file hashes of the alert and its session",
    budget.PLANE_ICMP: "the ICMP exchange and whether a normal ping solicited it",
    budget.PLANE_DECOY: "the deception sensor and what touched it",
    GENERAL: "the alert as a whole, because no plane applies to it",
}


def plane_role(plane: str) -> str:
    """The role name of the worker for ``plane``."""
    return f"plane_{plane}"


def plane_mandate(plane: str) -> str:
    """The mandate a plane worker reads at the end of its system prompt."""
    focus = PLANE_FOCUS.get(plane, f"the {plane} plane of the alert")
    return (
        f"""
## Your mandate: the {plane} plane

You are the worker for the {plane} plane: {focus}. Other workers read the
other planes of the same alert at the same time.

Read this plane only, with the tools you have. Find and cite the records in
this plane that decide the alert, for a threat or against one. State the
claim the plane supports. When the plane shows nothing that decides the
alert, state that plainly in the claim and set the confidence to none.
"""
        + BRIEF_OUTPUT_RULES
    )


def worker_planes(enriched: object) -> list[str]:
    """The planes that get a worker, in a stable order. Never empty."""
    planes = sorted(budget.alert_planes(enriched))
    return planes or [GENERAL]


def plane_tools(plane: str) -> frozenset[str]:
    """The read tools the worker of ``plane`` may register."""
    planes = frozenset() if plane == GENERAL else frozenset({plane})
    return budget.standard_visible_tools(planes)


def plane_specs(inputs: SwarmInputs) -> list[WorkerSpec]:
    """One worker per plane of the alert, each with its own agent and limits."""
    ctx = inputs.ctx
    settings = ctx.settings
    planes = worker_planes(inputs.enriched)
    tool_calls = share_budget(
        settings.agent_tool_calls_limit, len(planes), settings.plane_worker_tool_calls
    )
    specs: list[WorkerSpec] = []
    for plane in planes:
        tools = plane_tools(plane)
        prompt_planes = frozenset() if plane == GENERAL else frozenset({plane})
        wctx = worker_context(ctx, visible_tools=None, tool_allowlist=tools)
        agent = _orch.build_investigator(
            _orch.build_synthesizer_model(settings, temperature=settings.investigator_temperature),
            wctx,
            system_prompt=(
                build_investigator_prompt(
                    emits_report=False, planes=prompt_planes, visible_tools=tools
                )
                + plane_mandate(plane)
            ),
            output_type=Brief,
        )
        specs.append(
            WorkerSpec(
                role=plane_role(plane),
                label=f"the {plane} worker",
                claim=f"The {plane} worker could not read its plane.",
                agent=agent,
                user_msg=inputs.context_msg,
                tool_calls_limit=tool_calls,
                request_limit=settings.plane_worker_request_limit,
                tools=tools,
            )
        )
    return specs


__all__ = [
    "GENERAL",
    "PLANE_FOCUS",
    "plane_mandate",
    "plane_role",
    "plane_specs",
    "plane_tools",
    "worker_planes",
]

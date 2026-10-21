"""Arm D: a threat advocate and a benign advocate.

Two agents investigate the alert in parallel on the same prefetch context
(docs/dev/specs/2026-10-08-swarm-triage-experiment-design.md, arm D). Each is
the investigator of the one loop, built through the same builder with the
same tools and the same prompt, with a mandate appended. The threat advocate
looks for the evidence of a true positive. The benign advocate looks for the
evidence of a benign or expected event. Each one says so when it finds none.
The two failure modes of a SOC are a false all-clear and a false escalation,
and each advocate argues against one of them.

The two advocates share the tool budget of the one loop. Each gets
``advocate_tool_calls``, or half of ``agent_tool_calls_limit`` when that is
less.
"""

from __future__ import annotations

from typing import Final

from soc_ai.agent import orchestrator as _orch
from soc_ai.agent.prompts import INVESTIGATOR_PROMPT, build_investigator_prompt
from soc_ai.agent.swarm.briefs import Brief
from soc_ai.agent.swarm.runner import SwarmInputs, WorkerSpec, share_budget, worker_context

THREAT: Final = "threat_advocate"
BENIGN: Final = "benign_advocate"

# Appended to the system prompt of an advocate and a plane worker: the system
# prompt names an InvestigationTranscript, and the output schema is a brief.
# The two must agree on the job, or the model answers with the wrong shape.
BRIEF_OUTPUT_RULES = """
## Your output in this run

Your final output is a `Brief`. It takes the place of the
`InvestigationTranscript` that the sections above name. Fill it like this:

- `claim`: the claim you argued, in one sentence. When you found no evidence
  for it, say so in the claim.
- `evidence`: one entry for each record that supports the claim.
  `document_id` is the ES `_id`, the Zeek `uid` or the SOC API id of the
  record, copied exactly. `line` is one line quoted from the record or from
  the tool result that returned it. Never invent an id.
- `counterpoint`: the strongest fact against your claim.
- `confidence`: one word. Use high, medium, low or none.
- `gaps`: the checks you could not make.
- Leave `error` empty.

One more agent reads every brief and writes the report. It has no tools. It
can cite only the ids in the briefs, so a record you do not put in
`evidence` is lost.
"""

THREAT_MANDATE = (
    """
## Your mandate: the threat advocate

You are the threat advocate. A benign advocate investigates the same alert
at the same time and argues that it is benign or expected.

Find and cite the evidence that this alert is a true positive: the records
that show an attack, a compromise, malware or a policy breach. Query the
records that would prove it.

When you find no such evidence, state that plainly in the claim and set the
confidence to none. Do not stretch weak evidence into a threat. A brief with
no evidence is a valid answer.
"""
    + BRIEF_OUTPUT_RULES
)

BENIGN_MANDATE = (
    """
## Your mandate: the benign advocate

You are the benign advocate. A threat advocate investigates the same alert
at the same time and argues that it is a true positive.

Find and cite the evidence that this alert is benign or expected: the
records that show a known service, a routine job, an authorized scan, a
sanctioned tool or normal traffic for these hosts. Query the records that
would prove it.

When you find no such evidence, state that plainly in the claim and set the
confidence to none. Do not explain away a hostile record. A brief with no
evidence is a valid answer.
"""
    + BRIEF_OUTPUT_RULES
)

# role -> (label, the claim an empty brief states, the mandate).
_ADVOCATES: tuple[tuple[str, str, str, str], ...] = (
    (
        THREAT,
        "the threat advocate",
        "The threat advocate could not argue that the alert is a true positive.",
        THREAT_MANDATE,
    ),
    (
        BENIGN,
        "the benign advocate",
        "The benign advocate could not argue that the alert is benign or expected.",
        BENIGN_MANDATE,
    ),
)


def advocate_specs(inputs: SwarmInputs) -> list[WorkerSpec]:
    """The two advocates for one alert, each with its own agent and limits."""
    ctx = inputs.ctx
    settings = ctx.settings
    tool_calls = share_budget(
        settings.agent_tool_calls_limit, len(_ADVOCATES), settings.advocate_tool_calls
    )
    # The prompt of the one loop with no report rubric: an advocate gathers
    # evidence and writes a brief. The standard class trims it to the alert's
    # planes, as it trims the loop's.
    base_prompt = (
        build_investigator_prompt(
            emits_report=False,
            planes=inputs.trim_planes,
            visible_tools=ctx.loop_visible_tools,
        )
        if inputs.trim_planes is not None
        else INVESTIGATOR_PROMPT
    )
    specs: list[WorkerSpec] = []
    for role, label, claim, mandate in _ADVOCATES:
        # The tool surface of the one loop: the same visible set, the rest one
        # ``search_tools`` call away.
        wctx = worker_context(ctx, visible_tools=ctx.loop_visible_tools, tool_allowlist=None)
        agent = _orch.build_investigator(
            _orch.build_synthesizer_model(settings, temperature=settings.investigator_temperature),
            wctx,
            system_prompt=base_prompt + mandate,
            output_type=Brief,
        )
        specs.append(
            WorkerSpec(
                role=role,
                label=label,
                claim=claim,
                agent=agent,
                user_msg=inputs.worker_msg,
                tool_calls_limit=tool_calls,
                request_limit=settings.advocate_request_limit,
            )
        )
    return specs


__all__ = [
    "BENIGN",
    "BENIGN_MANDATE",
    "BRIEF_OUTPUT_RULES",
    "THREAT",
    "THREAT_MANDATE",
    "advocate_specs",
]

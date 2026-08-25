"""The structured-output detection drafter (Task 2 of the detection-bridge plan).

Mirrors :mod:`soc_ai.webui.runbook_promotion`'s single-shot analyst-model
pattern: one no-tools :class:`~pydantic_ai.Agent` with
``output_type=SigmaDraft`` on the shared :func:`build_synthesizer_model`, run
once, round-tripped through an optional egress guard. No tools are
registered — the caller (Task 5's route) does all evidence-gathering and
hands the result in as a plain string; the model never touches the grid, and
this module never writes to Security Onion. The returned draft is
unvalidated: Task 3's deterministic validators (Sigma-schema check + OQL
would-have-fired dry run) annotate ``schema_ok``/``dry_run`` before an
analyst ever sees it.

Egress (fixed in the Task-5-review follow-up — see the plan's "Egress
redaction" note): a hunt finding's evidence carries REAL internal
IPs/hostnames (``Hunt.report`` is desanitized before persistence), and this
module has no gateway-level redaction of its own — the guard, when passed, is
the ONLY thing standing between that evidence and a cloud analyst model. So
when ``guard`` is given, the full round trip mirrors
``runbook_promotion.draft_runbook_for_rule`` exactly: sanitize the composed
prompt, run the fail-closed residue sweep (raises
:class:`~soc_ai.agent.egress_guard.EgressResidueError` — the caller maps it —
and the model is never called) BEFORE the model call, then desanitize the
model's structured output after. ``guard=None`` (the caller's choice when
``analyst_cloud_redaction`` is off) skips all of it, same as before.
"""

from __future__ import annotations

from typing import Any

from pydantic_ai import Agent

from soc_ai.agent.models import build_synthesizer_model
from soc_ai.config import Settings
from soc_ai.detection.models import SigmaDraft
from soc_ai.detection.prompts import DRAFTER_PROMPT


def _build_draft_prompt(finding: dict[str, Any], evidence: str) -> str:
    """Render one hunt finding + its grounding evidence into the user prompt.

    Kept apart from :func:`draft_detection` so tests can assert on the
    composed prompt alone, mirroring ``runbook_promotion._compose_prompt``.
    """
    title = finding.get("title") or "(untitled finding)"
    detail = finding.get("detail") or ""
    hosts = finding.get("hosts") or []

    parts = [
        f'Confirmed hunt finding: "{title}"',
        "",
        str(detail),
    ]
    if hosts:
        parts += ["", "Hosts involved: " + ", ".join(str(h) for h in hosts)]
    parts += [
        "",
        "## Grounding evidence (the discriminating field values a grid query observed)",
        evidence,
    ]
    return "\n".join(parts)


async def draft_detection(
    settings: Settings, *, finding: dict[str, Any], evidence: str, guard: Any = None
) -> SigmaDraft:
    """Draft a Sigma detection rule (+ its OQL dry-run twin) from a confirmed
    hunt finding. Single analyst-model call, structured output. Export-only —
    this never touches Security Onion.

    ``guard`` is an optional pre-built
    :class:`~soc_ai.agent.egress_guard.EgressGuard` (typed ``Any`` here, same
    convention as the rest of this call path — the caller decides whether
    redaction applies and builds the guard; this function only round-trips
    through it). When given, the FULL round trip runs, mirroring
    ``draft_runbook_for_rule`` exactly: the composed prompt is sanitized and
    swept fail-closed (:meth:`~soc_ai.agent.egress_guard.EgressGuard.check_or_raise`
    — raises :class:`~soc_ai.agent.egress_guard.EgressResidueError`, which the
    caller maps, and the model is never called) BEFORE the analyst-model
    call, and the model's structured output is desanitized AFTER. When
    ``guard`` is ``None`` (redaction off), the prompt goes out as composed —
    no sanitize, no residue sweep, no desanitize.
    """
    prompt = _build_draft_prompt(finding, evidence)
    if guard is not None:
        prompt = guard.sanitize_text(prompt)
        # Independent residue sweep on the FINAL outbound string; raises when
        # fail-closed is on and an identifier survived — the model call below
        # never happens.
        guard.check_or_raise(prompt, fail_closed=settings.analyst_redaction_fail_closed)

    agent: Agent[None, SigmaDraft] = Agent(
        build_synthesizer_model(settings),
        system_prompt=DRAFTER_PROMPT,
        output_type=SigmaDraft,
        retries=3,
    )
    result = await agent.run(prompt)
    out = result.output
    if guard is not None:
        out = SigmaDraft.model_validate(guard.desanitize_obj(out.model_dump(mode="json")))
    return out

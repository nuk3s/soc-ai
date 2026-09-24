"""Draft a catalog analytic from a confirmed hunt finding.

Mirrors the Sigma drafter: one structured-output call on the synthesizer
model, the finding and evidence fenced as untrusted data, an optional egress
guard round trip. The output is validated with ``parse_spec``. The route dry
runs it and stores it as a candidate. It never goes live here.
"""

from __future__ import annotations

from typing import Any

from pydantic_ai import Agent

from soc_ai.agent.models import build_synthesizer_model
from soc_ai.config import Settings
from soc_ai.detection.analytic_models import AnalyticDraft
from soc_ai.detection.drafter import _UNTRUSTED_PREAMBLE
from soc_ai.detection.untrusted import UNTRUSTED_BEGIN, UNTRUSTED_END, neutralize_untrusted
from soc_ai.hunting.spec import HuntSpec, parse_spec

__all__ = ["ANALYTIC_DRAFTER_PROMPT", "draft_analytic"]

# The id prefix every drafted analytic carries. It is the one thing that
# separates the local tier from the shipped tier by reading the id alone.
LOCAL_ID_PREFIX = "local-"

ANALYTIC_DRAFTER_PROMPT = """You write one catalog analytic for soc-ai from a confirmed \
hunt finding.

Write for the analyst. One topic per sentence. No dashes, semicolons or parentheses that \
join ideas. No rhetorical contrast.

Output spec_yaml as a YAML mapping with these keys:
- id: lowercase words joined by hyphens, starting with "local-". It must not equal an existing id.
- title: one sentence in Simplified Technical English. Present tense. Name the actor.
- description: 2 to 5 short sentences. What the analytic fires on. Which evidence justifies it.
- level: informational | low | medium | high | critical
- scope_field: the document field that names the entity, for example source.ip or \
winlog.event_data.SubjectUserName
- scope_kind: host | user | ip
- precondition: the cheap clause that says the telemetry exists, for example event.code \
equals "4769"
- detection: the clauses that say the thing happened
- false_positives: a list of short sentences

A clause is {field, op, value}. op is one of: equals, one_of, exists, contains, prefix, wildcard, \
gt, gte, lt, lte. "all", "any" and "none" are three sibling lists of clauses directly under \
detection. They also sit directly under precondition. all = every clause must match. any = at \
least one must match. none = no clause may match. Do not nest a list inside a clause. Do not put \
"none" inside "all". Example:
detection:
  all:
    - field: event.code
      value: "4662"
  none:
    - field: user.name
      op: wildcard
      value: "*$"
Use the exact field names and values in the evidence. Do not invent fields.
"""

# The same caps the Sigma drafter applies to the same shapes: an untrusted
# finding must not buy a larger injection budget here than it does there.
_MAX_TITLE = 200
_MAX_DETAIL = 4000
_MAX_HOST = 120


def _build_prompt(finding: dict[str, Any], evidence: str, catalog_ids: list[str]) -> str:
    """Render one finding, its evidence and the taken ids into the user prompt.

    The finding and the evidence are untrusted. Both ride inside the fence,
    behind the same labelled preamble the Sigma drafter uses. The existing ids
    sit OUTSIDE the fence because they are the product's own catalog, and the
    model needs them to choose an id that is free.
    """
    title = neutralize_untrusted(str(finding.get("title") or "(untitled finding)"), cap=_MAX_TITLE)
    detail = neutralize_untrusted(
        str(finding.get("detail") or ""), cap=_MAX_DETAIL, keep_newlines=True
    )
    hosts = ", ".join(
        neutralize_untrusted(str(h), cap=_MAX_HOST) for h in (finding.get("hosts") or [])
    )
    ids = ", ".join(catalog_ids) or "(none)"
    parts = [
        _UNTRUSTED_PREAMBLE,
        "",
        f"Existing analytic ids, which the new id must not equal: {ids}",
        "",
        UNTRUSTED_BEGIN,
        f'Confirmed hunt finding: "{title}"',
        "",
        detail,
    ]
    if hosts:
        parts += ["", f"Hosts involved: {hosts}"]
    parts += [
        "",
        "## Grounding evidence (the discriminating field values a grid query observed)",
        evidence.replace("<<<", "< <<").replace(">>>", ">> >"),
        UNTRUSTED_END,
    ]
    return "\n".join(parts)


async def _draft_once(
    agent: Agent[None, AnalyticDraft], prompt: str, guard: Any
) -> tuple[AnalyticDraft, HuntSpec] | tuple[str, None]:
    """One model call. Returns the draft and its spec, or the error text and None."""
    result = await agent.run(prompt)
    out = result.output
    if guard is not None:
        out = AnalyticDraft.model_validate(guard.desanitize_obj(out.model_dump(mode="json")))
    try:
        return out, parse_spec(out.spec_yaml)
    except ValueError as exc:
        return str(exc)[:1500], None


async def draft_analytic(
    settings: Settings,
    *,
    finding: dict[str, Any],
    evidence: str,
    catalog_ids: list[str],
    guard: Any = None,
) -> tuple[AnalyticDraft, HuntSpec]:
    """One model call. Returns the draft and its parsed spec, or raises ValueError.

    ``guard`` is an optional egress guard, threaded the same way
    :func:`soc_ai.detection.drafter.draft_detection` threads it. With a guard
    the prompt is sanitized and swept fail-closed before the model call, and
    the structured output is desanitized after.
    """
    prompt = _build_prompt(finding, evidence, catalog_ids)
    if guard is not None:
        prompt = guard.sanitize_text(prompt)
        guard.check_or_raise(prompt, fail_closed=settings.analyst_redaction_fail_closed)
    agent: Agent[None, AnalyticDraft] = Agent(
        build_synthesizer_model(settings),
        system_prompt=ANALYTIC_DRAFTER_PROMPT,
        output_type=AnalyticDraft,
        retries=3,
    )
    out, spec = await _draft_once(agent, prompt, guard)
    if spec is None:
        # One more attempt, with the validation error in front of the model.
        # The first range draft nested a "none" list inside "all".
        retry = (
            f"{prompt}\n\nThe previous draft failed validation. Fix this and draft again:\n{out}"
        )
        out, spec = await _draft_once(agent, retry, guard)
        if spec is None:
            raise ValueError(str(out))
    assert isinstance(out, AnalyticDraft)
    if not spec.id.startswith(LOCAL_ID_PREFIX):
        raise ValueError("a drafted analytic id must start with local-")
    if spec.id in set(catalog_ids):
        raise ValueError(f"the id {spec.id!r} is already in the catalog")
    return out, spec

"""Draft a catalog analytic from a confirmed hunt finding.

Mirrors the Sigma drafter: one structured-output call on the synthesizer
model, the finding and evidence fenced as untrusted data, an optional egress
guard round trip. The output is validated with ``parse_spec``. The route dry
runs it and stores it as a candidate. It never goes live here.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from pydantic_ai import Agent

from soc_ai.agent.models import build_synthesizer_model
from soc_ai.config import Settings
from soc_ai.detection.analytic_models import AnalyticDraft
from soc_ai.detection.drafter import _UNTRUSTED_PREAMBLE
from soc_ai.detection.untrusted import UNTRUSTED_BEGIN, UNTRUSTED_END, neutralize_untrusted
from soc_ai.detection.validators import generalization_pins
from soc_ai.hunting.spec import HuntSpec, parse_spec

__all__ = ["ANALYTIC_DRAFTER_PROMPT", "DraftResult", "draft_analytic"]

# The id prefix every drafted analytic carries. It is the one thing that
# separates the local tier from the shipped tier by reading the id alone.
LOCAL_ID_PREFIX = "local-"

ANALYTIC_DRAFTER_PROMPT = """You write one catalog analytic for soc-ai from a confirmed \
hunt finding.

Write for the analyst. One topic per sentence. No dashes, semicolons or parentheses that \
join ideas. No rhetorical contrast.

The analytic describes a behaviour. Any host, user or address can show that behaviour. The \
finding is one case of it. Write the analytic for every case.

Output spec_yaml as a YAML mapping with these keys:
- id: lowercase words joined by hyphens, starting with "local-". It names the behaviour. It \
must not equal an existing id.
- title: one sentence in Simplified Technical English. Present tense. Name the behaviour and \
the type of actor, for example "A host". Never name the host, user or address of the finding.
- description: 2 to 5 short sentences. What the analytic fires on. Which evidence justifies it.
- level: informational | low | medium | high | critical
- scope_field: the document field that names the entity whose behaviour it is, for example \
source.ip or winlog.event_data.SubjectUserName
- scope_kind: host | user | ip
- precondition: the cheap clause that says the telemetry exists, for example event.code \
equals "4769"
- detection: the clauses that say the behaviour happened
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

Use the field names in the evidence. Do not invent fields.
Keep an exact value only when it is a stable discriminator. These are stable discriminators: \
event codes, datasets, providers, channels, protocols, ports, response codes such as NXDOMAIN, \
status codes, well-known tool and process names, privileged group names and registry keys. An \
indicator value is stable only when the indicator is the point of the finding, for example a \
known-bad hash or domain from a threat feed.
Do not put the entity of this case in a clause. Do not write an IP address, host name, user \
name, domain name or file path from the finding as a clause value. The scope_field names that \
entity. The analytic groups its matches by it.
A user wildcard "*$" names every machine account. It is a class, and you can use it.

The clause language matches each event. It cannot count, and it has no thresholds, sequences \
or statistics. When the finding is about a count or a repeat, such as "repeatedly", "N times" \
or "beacon", write the shape of one event. Then say in the description that the analytic \
matches each event and cannot count.

Worked example. The finding says: host H repeatedly queries the dead domains d1.example and \
d2.example, and the resolver answers NXDOMAIN each time. Write this analytic:
id: local-dns-query-nxdomain
title: A host queries a name the resolver answers NXDOMAIN
scope_field: source.ip
scope_kind: ip
precondition:
  all:
    - field: event.dataset
      value: zeek.dns
detection:
  all:
    - field: event.dataset
      value: zeek.dns
    - field: dns.response.code_name
      value: NXDOMAIN
The description says that the finding saw repeated queries, and that the analytic matches each \
query and cannot count. The two domains and the host stay out of the analytic.
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
    """One model call. Returns the draft and its spec, or the error text and None.

    The error text goes back out to the model on the retry, so it must never
    carry a real identifier. Validation therefore runs on the draft as the
    model wrote it, in label space, before the guard puts the real values
    back. pydantic quotes the offending input in its message, and a YAML
    error quotes the offending line, so validating the desanitized draft
    would echo the identifiers the guard had masked.
    """
    result = await agent.run(prompt)
    out = result.output
    try:
        spec = parse_spec(out.spec_yaml)
    except ValueError as exc:
        return str(exc)[:1500], None
    if guard is None:
        return out, spec
    out = AnalyticDraft.model_validate(guard.desanitize_obj(out.model_dump(mode="json")))
    try:
        return out, parse_spec(out.spec_yaml)
    except ValueError as exc:
        # The real values broke a spec the labels satisfied. Send the model
        # only what it could have seen.
        return str(guard.sanitize_text(str(exc)))[:1500], None


@dataclass(frozen=True)
class DraftResult:
    """One drafted analytic, its parsed spec, and what the generalization check found.

    ``generalization`` is None when the first draft described a behaviour.
    Otherwise it is ``{"pinned": [...], "retried": True}``: the sentences the
    check returned on the draft that is kept, after the one rewrite. An empty
    ``pinned`` list means the rewrite cleared every pin.
    """

    draft: AnalyticDraft
    spec: HuntSpec
    generalization: dict[str, Any] | None = None


def _usable(spec: HuntSpec, catalog_ids: list[str]) -> str | None:
    """Why a parsed draft cannot be stored, or None."""
    if not spec.id.startswith(LOCAL_ID_PREFIX):
        return "a drafted analytic id must start with local-"
    if spec.id in set(catalog_ids):
        return f"the id {spec.id!r} is already in the catalog"
    return None


async def draft_analytic(
    settings: Settings,
    *,
    finding: dict[str, Any],
    evidence: str,
    catalog_ids: list[str],
    guard: Any = None,
    indicators: list[str] | None = None,
) -> DraftResult:
    """Draft, validate and check one analytic. Returns a DraftResult, or raises ValueError.

    ``guard`` is an optional egress guard, threaded the same way
    :func:`soc_ai.detection.drafter.draft_detection` threads it. With a guard
    the prompt is sanitized and swept fail-closed before the model call, each
    retry prompt is swept the same way, and the structured output is
    desanitized after.

    After a valid draft the generalization check runs on the real values. A
    draft that pins the entity of this one case gets one rewrite, with the
    check's sentences as instructions. The sentences name fields only, so the
    rewrite prompt carries no identifier. A rewrite that still pins, or that
    fails, leaves the better of the two drafts marked with its pins.
    ``indicators`` is the finding's indicator list, the one exception the
    check allows.
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
        if guard is not None:
            # The error text is a second outbound string. It gets the same
            # sweep the prompt got, so fail-closed holds on the retry too.
            guard.check_or_raise(retry, fail_closed=settings.analyst_redaction_fail_closed)
        out, spec = await _draft_once(agent, retry, guard)
        if spec is None:
            raise ValueError(str(out))
    assert isinstance(out, AnalyticDraft)
    refused = _usable(spec, catalog_ids)
    if refused is not None:
        raise ValueError(refused)

    hosts = list(finding.get("hosts") or [])
    marks = list(indicators or [])
    pins = generalization_pins(spec, hosts=hosts, indicators=marks)
    if not pins:
        return DraftResult(out, spec)
    # The first range draft pinned one host and two domain names. One rewrite,
    # with the pins as instructions. The sentences name a field, never a value.
    rewrite = f"{prompt}\n\nRewrite without these pins:\n" + "\n".join(f"- {p}" for p in pins)
    if guard is not None:
        guard.check_or_raise(rewrite, fail_closed=settings.analyst_redaction_fail_closed)
    second, second_spec = await _draft_once(agent, rewrite, guard)
    if second_spec is not None and _usable(second_spec, catalog_ids) is None:
        assert isinstance(second, AnalyticDraft)
        second_pins = generalization_pins(second_spec, hosts=hosts, indicators=marks)
        if len(second_pins) <= len(pins):
            return DraftResult(second, second_spec, {"pinned": second_pins, "retried": True})
    return DraftResult(out, spec, {"pinned": pins, "retried": True})

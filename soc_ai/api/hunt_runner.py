"""Recorded hunt runner (SSE route + background drainer).

Mirrors :mod:`soc_ai.api.runner`. ``run_hunt`` streams the chat-driven hunt
agent NODE-BY-NODE (via ``agent.iter()`` + the orchestrator's ``_walk_message``
projector, exactly like the investigation loop) so each tool_call / tool_result
/ model_response lands the moment it happens; it emits a leading ``hunt_started``
event and a trailing ``hunt_report`` event carrying the final
:class:`~soc_ai.agent.hunt.HuntReport`.

``hunt_recorded_run`` wraps that stream with :class:`HuntRecorder` so every run
is persisted (leading ``hunt_created`` event carries the new row's id), whether
consumed by the SSE route or drained in the background.
"""

from __future__ import annotations

import asyncio
import json
import logging
import uuid
from collections.abc import AsyncIterator, Sequence
from types import SimpleNamespace
from typing import TYPE_CHECKING, Any

from pydantic_ai import Agent
from pydantic_ai.exceptions import UsageLimitExceeded
from pydantic_ai.usage import RunUsage, UsageLimits

from soc_ai.agent._partial_replay import (
    repair_dangling_tool_calls,
    replay_reasoning_context,
)
from soc_ai.agent.egress_guard import EgressGuard
from soc_ai.agent.hunt import (
    HUNT_SYSTEM_PROMPT,
    HuntFinding,
    HuntReport,
    build_hunt_agent,
    build_hunt_prompt,
    build_hunt_synthesizer,
)
from soc_ai.agent.hunt_gates import (
    _validate_hunt_charts,
    _validate_hunt_findings,
    gate_host_gaps,
    gate_lead_links,
)
from soc_ai.agent.models import build_investigator_model
from soc_ai.agent.orchestrator import InvestigationContext, StepEvent, _walk_message
from soc_ai.agent.prompts import oql_primer_block
from soc_ai.agent.reasoning import extract_reasoning_trace
from soc_ai.agent.toolset import GRID_BACKED_TOOLS, GRID_UNAVAILABLE_REASON
from soc_ai.api.hunt_recorder import HuntRecorder
from soc_ai.api.runner import CancelToken
from soc_ai.campaigns import finding_names
from soc_ai.dossier.prompt import host_dossier_prompt_block, internal_ips_in_text
from soc_ai.hunting import authorized as authorized_block
from soc_ai.hunting import campaign_block
from soc_ai.hunting import outcome as hunt_outcome
from soc_ai.hunting.hunt_words import DEGRADED_FINDING_NOTE
from soc_ai.hunting.outcome import FindingVerdicts
from soc_ai.run_meter import start_search_meter
from soc_ai.so_client.inventory import inventory_prompt_block
from soc_ai.store import grid_gaps
from soc_ai.store import hunts as hunt_svc
from soc_ai.webui import hunt_findings

if TYPE_CHECKING:
    from soc_ai.hunting.earlier import EarlierConclusions

_LOGGER = logging.getLogger(__name__)


async def _build_hunt_run(
    ctx: InvestigationContext,
    *,
    objective: str,
    prior: str | None,
    earlier: str | None = None,
    authorized: str | None = None,
    campaigns: str | None = None,
) -> tuple[EgressGuard | None, Agent[None, HuntReport], str]:
    """Compose the (guard, agent, user message) triple for one hunt run.

    The egress guard MUST be attached to ``ctx`` before ``build_hunt_agent``
    runs — ``register_read_tools`` wraps the tool closures at registration
    time. When the guard is active, the system prompt (objective + dataset
    inventory + host dossier) and the user message (objective + prior-hunt
    summary) are sanitized here — they are the hunt's prompt-side egress
    boundary.

    ``earlier`` is the earlier-conclusions block that :func:`_vetted_earlier`
    kept. It follows the objective in the user message, so the sanitize pass
    and the residue sweep over the user message cover it. The hosts it names
    go to the dossier with their own label.

    ``authorized`` is the authorized activity block that
    :func:`_vetted_authorized` kept. It follows the earlier conclusions in the
    user message, under the same sanitize pass and residue sweep.

    ``campaigns`` is the text of the campaign blocks that
    :func:`_vetted_campaigns` kept. It sits between the earlier conclusions
    and the authorized activity, under the same pass and sweep.
    """
    guard = await _egress_guard_for(ctx)
    # The hunt agent runs OQL — append the primer so it writes VALID queries
    # (no parentheses, no leading wildcards) instead of churning through parse
    # errors. And append the auto-discovered dataset inventory so the hunt knows
    # what data ACTUALLY exists on this grid (network today, host logs later)
    # instead of guessing from a hardcoded list.
    #
    # The dossier block goes on the same seam, and for the same reason the
    # inventory does: a hunt should know what the hosts its objective names ARE
    # before it plans what to look for. Composed HERE, above the sanitize sweep
    # below — appending it after the sweep would send the network's hostnames and
    # addresses to a cloud model in the clear.
    inventory = await inventory_prompt_block(ctx.elastic, ctx.settings)
    dossier = await _objective_dossier_block(ctx, objective, prior, earlier)
    # The grid gaps of the last 30 days, one fact line each. A hunt over the
    # range outage reported zero counts as facts (dogfood 2026-10-19, R3-D3).
    gap_lines = await grid_gaps.recent_fact_lines(ctx.db_sessionmaker)
    gaps = "\n" + "\n".join(gap_lines) + "\n" if gap_lines else ""
    system_prompt = (
        HUNT_SYSTEM_PROMPT.format(objective=objective)
        + oql_primer_block(flavor="hunt")
        + inventory
        + gaps
        + dossier
    )
    user_msg = build_hunt_prompt(
        objective, prior=prior, earlier=earlier, campaigns=campaigns, authorized=authorized
    )
    if guard is not None:
        # The objective is analyst-typed free text that may name internal
        # hosts, and the inventory block carries grid dataset detail.
        system_prompt = guard.sanitize_text(system_prompt)
        user_msg = guard.sanitize_text(user_msg)
        # Independent fail-closed residue sweep, on the DYNAMIC (untrusted)
        # fragments only: the objective + prior (user_msg carries both), the
        # grid inventory, and the dossier block. The STATIC prompt text is
        # deliberately outside the sweep — the OQL primer's worked examples
        # (`workstation-01`) and the system template's own prose (`DC-attack`)
        # are residue-shaped by construction, and sweeping them would fail-close
        # every hunt on version-controlled repo text that carries no deployment
        # data. Fragments are re-sanitized against the run's shared mapping, so
        # labels match what the composed prompt egresses.
        fail_closed = ctx.settings.analyst_redaction_fail_closed
        for fragment in (user_msg, guard.sanitize_text(inventory), guard.sanitize_text(dossier)):
            guard.check_or_raise(fragment, fail_closed=fail_closed)
    agent = build_hunt_agent(
        build_investigator_model(ctx.settings), ctx, system_prompt=system_prompt
    )
    return guard, agent, user_msg


async def _objective_dossier_block(
    ctx: InvestigationContext, objective: str, prior: str | None, earlier: str | None = None
) -> str:
    """The host-dossier block for the addresses the hunt's own brief names.

    A hunt has no alert to read endpoints off, so the host set comes from the
    text the analyst wrote plus the prior hunt's narrative it is refining —
    those are the addresses the hunt is already about. Nothing is discovered
    here: this is not a sweep of the network, it is the identity of the hosts
    already on the page, bounded by
    :data:`~soc_ai.dossier.prompt.MAX_PROMPT_HOSTS`.

    Returns ``""`` on every off-switch and every failure (the renderer's
    contract), so a deployment with the dossier off pays nothing.

    ``known_only`` because the addresses came from free text: an analyst can
    type an address that was never observed, and a rendered "no dossier" line
    would put it into the hunt's own prompt as though it were an asset. Only
    hosts the sweep knows are described.

    The hosts that only the ``earlier`` block names follow, with their own
    label. An earlier conclusion is a claim, and the label keeps the hunt
    from reading such a host as part of its objective.
    """
    named = internal_ips_in_text(f"{objective}\n{prior or ''}", ctx.settings)
    seen = set(named)
    extra = [ip for ip in internal_ips_in_text(earlier or "", ctx.settings) if ip not in seen]
    if not named and not extra:
        return ""
    hosts = {ip: "named in the objective" for ip in named}
    hosts.update(dict.fromkeys(extra, "named in an earlier conclusion"))
    return await host_dossier_prompt_block(hosts, ctx=ctx, known_only=True)


async def _vetted_earlier(
    ctx: InvestigationContext, earlier: EarlierConclusions | None
) -> tuple[str | None, list[str]]:
    """The earlier-conclusions text the hunt may read, and the parts that were dropped.

    The block carries stored model text, desanitized at rest. With redaction
    on and fail-closed, a part that holds a name the redaction cannot remove
    is dropped, and the hunt runs without it. A residue error here would fail
    every later run of the same subject closed, because the same stored text
    comes back each time. The log line gives the count only, never the names.

    A scheduled hunt reads two parts: the earlier runs of its objective and
    the records of its window. Each part is vetted alone, so a name in one
    part does not cost the hunt the other part.
    """
    if earlier is None:
        return None, []
    # A window whose every record a campaign block states has no text.
    parts = list(earlier.parts) or ([("block", earlier.text)] if earlier.text else [])
    guard = await _egress_guard_for(ctx)
    kept: list[str] = []
    dropped: list[str] = []
    for name, text in parts:
        if guard is not None and ctx.settings.analyst_redaction_fail_closed is True:
            leaked = guard.residue(guard.sanitize_text(text))
            if leaked:
                _LOGGER.warning(
                    "hunt: the %s part of the earlier conclusions held %d internal names "
                    "that the redaction could not remove. The hunt starts without that part.",
                    name,
                    len(leaked),
                )
                dropped.append(name)
                continue
        kept.append(text)
    return ("\n\n".join(kept) if kept else None), dropped


async def _vetted_campaigns(
    ctx: InvestigationContext, scope: campaign_block.Scope, *, hours: int
) -> campaign_block.CampaignBlocks:
    """The campaign blocks the hunt may read, and the campaigns whose block was dropped.

    The blocks hold machine names from DHCP, DNS and the agents. With
    redaction on and fail-closed, a block that holds a name the redaction
    cannot remove is dropped, and the hunt runs without it. Each block is
    vetted alone, so one name does not cost the hunt the other campaigns. A
    dropped block covers nothing, so its records stay in the window block.
    An evaluation hunt reads no block: its grid holds planted scenarios, and
    a real campaign says nothing about them.
    """
    if ctx.include_synth:
        return campaign_block.CampaignBlocks()
    blocks = await campaign_block.blocks_for_hunt(ctx.db_sessionmaker, scope=scope, hours=hours)
    if not blocks:
        return campaign_block.CampaignBlocks()
    guard = await _egress_guard_for(ctx)
    kept: list[campaign_block.CampaignBlock] = []
    dropped: list[int] = []
    for block in blocks:
        if guard is not None and ctx.settings.analyst_redaction_fail_closed is True:
            leaked = guard.residue(guard.sanitize_text(block.text))
            if leaked:
                _LOGGER.warning(
                    "hunt: the block of campaign %s held %d internal names that the redaction "
                    "could not remove. The hunt starts without that block.",
                    block.campaign_id,
                    len(leaked),
                )
                dropped.append(block.campaign_id)
                continue
        kept.append(block)
    return campaign_block.CampaignBlocks(kept=tuple(kept), dropped=tuple(dropped))


async def _without_campaign_records(
    ctx: InvestigationContext,
    earlier: EarlierConclusions | None,
    campaigns: campaign_block.CampaignBlocks,
) -> EarlierConclusions | None:
    """The earlier conclusions of a scheduled hunt, read again without the campaign records.

    A kept campaign block states its investigations and its leads. The
    window block then leaves them out (``covered`` of
    :func:`~soc_ai.hunting.earlier.earlier_for_objective`). A dropped block covers nothing, so
    its records stay in the window block. A read that gives nothing keeps the
    first conclusions: the hunt reads a record two times, never zero times.
    """
    covered = campaigns.covered
    if earlier is None or earlier.basis is None or not covered or ctx.db_sessionmaker is None:
        return earlier
    from soc_ai.hunting import earlier as earlier_mod  # noqa: PLC0415 - lazy, like the gate

    objective, at, interval = earlier.basis
    again = await earlier_mod.earlier_for_objective(
        ctx.db_sessionmaker, objective, now=at, interval_minutes=interval, covered=covered
    )
    return again if again is not None else earlier


def _gate_basis(
    earlier: EarlierConclusions | None, campaigns: campaign_block.CampaignBlocks
) -> EarlierConclusions | None:
    """What the window gate reads: the true positives that the hunt was told about.

    A scheduled hunt reads its window, and the window still names each true
    positive that a campaign block states. Any other hunt reads no window:
    the true positives of its campaign blocks in the window of the hunt feed
    the gate (:attr:`soc_ai.hunting.campaign_block.CampaignBlock.confirmed`).
    """
    if earlier is not None and earlier.basis is not None:
        return earlier
    extra = campaigns.confirmed
    if not extra:
        return earlier
    from soc_ai.hunting import earlier as earlier_mod  # noqa: PLC0415 - lazy, like the gate

    held = tuple(earlier.confirmed) if earlier is not None else ()
    return earlier_mod.EarlierConclusions(text="", confirmed=held + extra)


async def _vetted_authorized(
    ctx: InvestigationContext, stated_campaigns: Sequence[int] = ()
) -> tuple[str | None, bool]:
    """The authorized activity block the hunt may read, and whether it was dropped.

    The block lists the authorizations in force
    (:func:`soc_ai.hunting.authorized.block_for_hunt`). It holds machine
    names. With redaction on and fail-closed, a block that holds a name the
    redaction cannot remove is dropped, like the earlier conclusions. The
    hunt then reports the authorized activity as a threat, which is the safe
    side. An evaluation hunt reads no block: its grid holds planted
    scenarios, and a real authorization says nothing about them.

    ``stated_campaigns`` are the campaigns whose block the hunt reads. Their
    campaign records are not listed again.
    """
    if ctx.include_synth:
        return None, False
    block = await authorized_block.block_for_hunt(
        ctx.db_sessionmaker, skip_campaigns=stated_campaigns
    )
    if block is None:
        return None, False
    guard = await _egress_guard_for(ctx)
    if guard is not None and ctx.settings.analyst_redaction_fail_closed is True:
        leaked = guard.residue(guard.sanitize_text(block.text))
        if leaked:
            _LOGGER.warning(
                "hunt: the authorized activity held %d internal names that the redaction "
                "could not remove. The hunt starts without it.",
                len(leaked),
            )
            return None, True
    return block.text, False


async def _egress_guard_for(ctx: InvestigationContext) -> EgressGuard | None:
    """Attach/return the opt-in cloud-egress guard for this hunt run.

    Same pattern as the investigation pipeline: when
    ``analyst_cloud_redaction`` is on, ONE guard (one label mapping) covers the
    whole hunt — prompts out, tool results out (via the toolset's ``_guarded``
    wrapper at registration), labels restored in everything persisted.
    ``is True`` (not truthiness) so a non-Settings test double can never flip
    redaction on. ``None`` = redaction off (the default).
    """
    if ctx.settings.analyst_cloud_redaction is True and ctx.egress_guard is None:
        ctx.egress_guard = await EgressGuard.for_settings(ctx.settings, ctx.db_sessionmaker)
    return ctx.egress_guard


def _desanitize_hunt_report(report: Any, guard: EgressGuard | None) -> Any:
    """Restore real identifiers in a labeled HuntReport before persistence.

    The model wrote the report in label space (its inputs were sanitized);
    round-trip every string field through the guard's mapping. Defensive: a
    desanitize surprise must never cost the hunt its report — on failure the
    labeled report is returned unchanged.
    """
    if guard is None:
        return report
    try:
        return type(report).model_validate(guard.desanitize_obj(report.model_dump(mode="json")))
    except Exception:
        _LOGGER.warning(
            "hunt: egress-guard desanitize failed; persisting labeled report", exc_info=True
        )
        return report


# Shared with the triage loop's budget-partial path — extracted verbatim to
# soc_ai.agent._partial_replay (2026-07-18). Module aliases keep the names
# callers and tests use; the hunt closure content is the shared default.
_repair_dangling_tool_calls = repair_dangling_tool_calls
_replay_reasoning_context = replay_reasoning_context


_TEXT_TRANSCRIPT_HEADER = (
    "## The evidence of the hunt, as text\n"
    "Each line below is a tool call that the hunt made or the result that it "
    "returned, in order. Call no tool. Write the HuntReport from these results "
    "only.\n\n"
)


def _part_text(value: Any) -> str:
    """One tool argument or tool result as text. Never raises."""
    if isinstance(value, str):
        return value
    try:
        return json.dumps(value, default=str, ensure_ascii=False)
    except Exception:
        return str(value)


def _parts_of(msg: Any) -> list[Any]:
    """The parts of one transcript message, or none for a shape that has none."""
    try:
        return list(getattr(msg, "parts", None) or [])
    except Exception:
        return []


def _text_transcript(gathered: list[Any]) -> str:
    """The gathered transcript as plain text, with no tool-call part in it.

    The synthesizer replays the transcript as message history. A model that
    reads a history of tool calls can answer with one more tool call, and the
    synthesizer has no tool. Prod hunt 01M69M3FVK9D6KECGCAXJK9F6Z lost its
    report that way (2026-10-31): 42 tool calls, then "the next tool call(s)
    would exceed the tool_calls_limit of 0".

    This copy holds the same evidence as lines of text: each tool call, each
    tool result and each note of the model, in order. The system prompt, the
    user prompt and the retry prompts are left out, because the synthesizer
    has its own instructions. The reasoning is left out too, because
    :func:`_replay_reasoning_context` carries it. A part of a shape this
    build does not know is skipped.
    """
    lines: list[str] = []
    for msg in gathered:
        for part in _parts_of(msg):
            name = type(part).__name__
            tool = str(getattr(part, "tool_name", "") or "tool")
            if name in ("ToolCallPart", "ToolSearchCallPart"):
                lines.append(f"Tool call {tool}: {_part_text(getattr(part, 'args', None))}")
            elif name in ("ToolReturnPart", "ToolSearchReturnPart"):
                lines.append(f"Tool result {tool}: {_part_text(getattr(part, 'content', None))}")
            elif name == "TextPart":
                note = str(getattr(part, "content", "") or "").strip()
                if note:
                    lines.append(f"Model note: {note}")
    if not lines:
        return ""
    return _TEXT_TRANSCRIPT_HEADER + "\n".join(lines) + "\n\n---\n\n"


async def _synthesize_partial_hunt(
    ctx: InvestigationContext,
    *,
    objective: str,
    gathered: list[Any],
    text_only: bool = False,
    usage: RunUsage | None = None,
) -> Any:
    """Force a :class:`HuntReport` from an already-gathered transcript (no tools).

    Called when a hunt exhausts its budget before emitting a report: repairs the
    transcript tail (budget exhaustion always leaves unprocessed tool calls —
    see :func:`_repair_dangling_tool_calls`), then replays the accumulated
    message history through the no-tools hunt synthesizer so the analyst still
    gets a grounded partial report instead of a bare error.

    The exploration model's own reasoning (its ``ThinkingPart``s, where the
    debunking of a false positive lives) is NOT carried into a fresh agent's
    replayed history by pydantic-ai, so it is lifted out via
    :func:`_replay_reasoning_context` and prepended to the synthesizer's user
    message — otherwise only the loud alert titles survive and the write-up
    reasserts an FP the hunt had already dismissed.

    This is an analyst-model EGRESS site like any other: the main hunt agent
    runs in label space, and the synthesizer must too. When ``ctx`` carries a
    guard, the objective (raw analyst free text — it rides the synth
    instructions) and the composed user message are sanitized with the run's
    shared mapping and swept fail-closed BEFORE the model call; the replayed
    transcript is already label-space (``_stream_node`` gathers the sanitized
    node messages). The caller desanitizes the labeled report via
    :func:`_desanitize_hunt_report`, exactly as on the full-run path.

    ``text_only`` is the second attempt, after the replay stopped on a usage
    limit. The transcript goes into the user message as text
    (:func:`_text_transcript`), and no message history is replayed, so the
    model reads no tool-call part that it could answer with a tool call. The
    tool-call limit of 0 does not apply to this attempt. The synthesizer
    registers no tool, so no call can run. Without the limit, a call to a tool
    that does not exist gets a retry prompt, where the limit ended the run.
    The request limit still bounds the attempt.

    ``usage`` receives the model usage of the attempt as it runs. An attempt
    that raises returns no result, so the caller reads its cost from here.
    """
    guard = ctx.egress_guard
    reasoning_block = _replay_reasoning_context(gathered)
    user_msg = (
        reasoning_block + "Write the HuntReport now from the evidence already gathered above."
    )
    transcript = _text_transcript(gathered) if text_only else ""
    synth_objective = objective
    if guard is not None:
        fail_closed = ctx.settings.analyst_redaction_fail_closed
        synth_objective = guard.sanitize_text(objective)
        user_msg = guard.sanitize_text(user_msg)
        # The independent residue sweep covers the two DYNAMIC fragments of the
        # composed prompt (the surrounding HUNT_SYNTH_PROMPT template is static
        # repo text carrying no deployment data — same sweep boundary as
        # ``_build_hunt_run``).
        guard.check_or_raise(synth_objective, fail_closed=fail_closed)
        guard.check_or_raise(user_msg, fail_closed=fail_closed)
        # The transcript is label-space already, like the history it replaces:
        # the tool boundary sanitized each result. It gets the same pass again
        # and no residue sweep, which is the boundary of the replayed history.
        transcript = guard.sanitize_text(transcript)
    synth = build_hunt_synthesizer(
        build_investigator_model(ctx.settings), objective=synth_objective
    )
    if text_only:
        return await synth.run(
            transcript + user_msg, usage_limits=UsageLimits(request_limit=3), usage=usage
        )
    return await synth.run(
        user_msg,
        message_history=_repair_dangling_tool_calls(gathered),
        usage_limits=UsageLimits(request_limit=3, tool_calls_limit=0),
        usage=usage,
    )


def _hunt_usage_event(ev_factory: Any, source: Any, *, phase: str) -> StepEvent | None:
    """A ``usage`` event for one hunt model run, or None when it reports none.

    ``source`` is the agent run (on any exit) or a synthesis result. Same
    payload shape as the triage pipeline's usage event, so one meter reads
    both. A hunt recorded no usage before the run counters: the survey of
    2026-10-04 counted ``model_response`` events as a stand-in.
    """
    if source is None:
        return None
    try:
        # A property since pydantic-ai 1.107; the call form still exists on a
        # test double or an older release.
        u = source.usage
        if not isinstance(u, RunUsage) and callable(u):
            u = u()
        payload = {
            "phase": phase,
            "round": 1,
            "tool_calls": int(u.tool_calls or 0),
            "requests": int(u.requests or 0),
            "input_tokens": int(u.input_tokens or 0),
            "output_tokens": int(u.output_tokens or 0),
            "total_tokens": int(u.total_tokens or 0),
        }
    except Exception:
        return None
    event: StepEvent = ev_factory("usage", payload)
    return event


async def _stream_node(
    node: Any,
    ev_factory: Any,
    guard: EgressGuard | None,
    gathered: list[Any],
    gathered_tool_results: list[Any],
) -> AsyncIterator[StepEvent]:
    """Project one streamed hunt node into display StepEvents, capturing evidence.

    Extracts the node's message (``model_response`` or ``request``), appends it to
    ``gathered`` (the labeled originals the partial-report synthesizer replays),
    then runs the shared ``_walk_message`` projector. Restores real identifiers
    for display when a guard is active, and appends each ``tool_result`` payload
    to ``gathered_tool_results`` — the desanitized evidence bundle the E1.3
    citation gate resolves findings against (same values the desanitized report
    cites). A node with no message yields nothing.
    """
    node_msg = getattr(node, "model_response", None)
    if node_msg is None:
        node_msg = getattr(node, "request", None)
    if node_msg is None:
        return
    gathered.append(node_msg)
    async for ev in _walk_message(node_msg, ev_factory, phase="hunt", round_num=1):
        disp = (
            ev
            if guard is None
            else ev.model_copy(update={"payload": guard.desanitize_obj(ev.payload)})
        )
        if disp.kind == "tool_result":
            # Capture a LABELED evidence item ({tool_name, result}) — not just the
            # bare result. The E1.3 finding gate resolves citations against
            # ``result`` (unchanged — the JSON dump still contains it, so existing
            # resolution is unaffected), and the corroboration gate additionally
            # classifies each item by ``tool_name`` to tell a detector-alert
            # citation apart from a corroborating-evidence one. ``_walk_message``
            # already surfaces the ToolReturnPart's ``tool_name`` on the payload.
            gathered_tool_results.append(
                {
                    "tool_name": disp.payload.get("tool_name", ""),
                    "result": disp.payload.get("result"),
                }
            )
        yield disp


async def _partial_report(
    ctx: InvestigationContext,
    *,
    objective: str,
    gathered: list[Any],
    stopped_by: str,
    ev_factory: Any,
    landed: list[Any],
) -> AsyncIterator[StepEvent]:
    """Write the partial report of a hunt that reached a limit, as trace events.

    The first attempt replays the transcript as message history. When it
    stops on a usage limit, the model answered the transcript with a tool
    call, and the synthesizer has no tool. Prod lost a 55-minute hunt there
    (2026-10-31). The evidence is still in hand, so a second attempt runs on a
    text copy of it (:func:`_text_transcript`). Any other failure of the first
    attempt gets no second attempt: a gateway error is not a transcript
    problem.

    ``landed`` receives the synthesis result when one attempt succeeds. When
    it stays empty, the last event of the stream is the ``error`` event.
    """
    yield ev_factory(
        "model_response",
        {
            "text": (
                "Reached the hunt's exploration budget. Writing a partial "
                "report from the evidence gathered so far."
            )
        },
    )
    # The usage of each attempt, filled as it runs. An attempt that raises
    # returns no result, and the model calls it made still cost tokens. The
    # failed first attempt of a lost prod hunt ran 25 minutes with no record.
    first_usage = RunUsage()
    try:
        landed.append(
            await _synthesize_partial_hunt(
                ctx, objective=objective, gathered=gathered, usage=first_usage
            )
        )
        return
    except asyncio.CancelledError:
        raise
    except UsageLimitExceeded as e:
        _LOGGER.warning(
            "hunt: the report writer stopped on a usage limit (%s). "
            "It runs once more on a text copy of the evidence.",
            e,
        )
        if (spent := _failed_attempt_usage(ev_factory, first_usage)) is not None:
            yield spent
    except BaseException as e:
        _LOGGER.exception("hunt partial synthesis failed")
        if (spent := _failed_attempt_usage(ev_factory, first_usage)) is not None:
            yield spent
        yield _synthesis_failed_event(ev_factory, e, stopped_by)
        return
    yield ev_factory("model_response", {"text": _TEXT_RETRY_NOTE})
    second_usage = RunUsage()
    try:
        landed.append(
            await _synthesize_partial_hunt(
                ctx, objective=objective, gathered=gathered, text_only=True, usage=second_usage
            )
        )
    except asyncio.CancelledError:
        raise
    except BaseException as e:
        _LOGGER.exception("hunt partial synthesis failed on the text copy too")
        if (spent := _failed_attempt_usage(ev_factory, second_usage)) is not None:
            yield spent
        yield _synthesis_failed_event(ev_factory, e, stopped_by)


def _failed_attempt_usage(ev_factory: Any, usage: RunUsage) -> StepEvent | None:
    """The ``usage`` event of a report attempt that raised, or None when it made no request."""
    if not usage.requests:
        return None
    return _hunt_usage_event(
        ev_factory, SimpleNamespace(usage=usage), phase="hunt_partial_synth_failed"
    )


def _started_payload(
    objective: str,
    earlier: Any,
    *,
    earlier_text: str | None,
    earlier_dropped: Any,
    authorized_text: str | None,
    authorized_dropped: Any,
    campaigns: campaign_block.CampaignBlocks | None = None,
) -> dict[str, Any]:
    """The payload of the ``hunt_started`` event: what the hunt was given to read.

    ``campaign_ids`` names the campaigns whose block the hunt read. The
    investigation phase reads it: only such a campaign can hold a finding
    (:func:`soc_ai.webui.hunt_findings.plan_campaign_holds`).
    """
    started: dict[str, Any] = {"objective": objective}
    if campaigns is not None and campaigns.text is not None:
        started["campaigns"] = campaigns.text
        started["campaign_ids"] = campaigns.ids
    if campaigns is not None and campaigns.dropped:
        started["campaigns_dropped"] = "residue"
        started["campaigns_dropped_ids"] = list(campaigns.dropped)
    if earlier is not None:
        started["earlier_refs"] = {k: list(v) for k, v in earlier.refs.items()}
    if earlier_text is not None:
        started["earlier"] = earlier_text
    if earlier_dropped:
        started["earlier_dropped"] = "residue"
        # Which parts the hunt did not read: "runs", "window" or "block".
        started["earlier_dropped_parts"] = earlier_dropped
    if authorized_text is not None:
        started["authorized"] = authorized_text
    if authorized_dropped:
        started["authorized_dropped"] = "residue"
    return started


async def run_hunt(  # noqa: PLR0915 - one linear streaming flow, like the triage pipeline
    ctx: InvestigationContext,
    *,
    objective: str,
    prior: str | None = None,
    session_id: str | None = None,
    earlier: EarlierConclusions | None = None,
    campaign_scope: campaign_block.Scope | None = None,
) -> AsyncIterator[StepEvent]:
    """Stream a chat-driven hunt as StepEvents.

    Builds the hunt agent (reusing the investigator's read tools) with the
    hunt-oriented system prompt, runs it node-by-node, and yields:

    - ``hunt_started`` — the objective, first;
    - ``tool_call`` / ``tool_result`` / ``model_response`` — the live trace;
    - ``hunt_report`` — the final HuntReport (or an ``error`` event on failure);
    - ``done`` — a small terminal marker with the finding count.

    ``earlier`` is the earlier-conclusions block (:mod:`soc_ai.hunting.earlier`).
    ``hunt_started`` records its source records, the text the model reads, or
    the drop (:func:`_vetted_earlier`), so the event never shows text the model
    did not read.

    ``campaign_scope`` says which campaign blocks the hunt reads
    (:func:`soc_ai.hunting.campaign_block.scope_of`). None reads the blocks of
    every campaign of the window. An evaluation hunt reads none.
    """
    sid = session_id or uuid.uuid4().hex[:12]
    sequence = 0

    def _ev(kind: str, payload: dict[str, Any]) -> StepEvent:
        nonlocal sequence
        sequence += 1
        return StepEvent(kind=kind, session_id=sid, sequence=sequence, payload=payload)

    from soc_ai.hunting import earlier as earlier_mod  # noqa: PLC0415 - lazy, like the gate

    basis = earlier.basis if earlier is not None else None
    campaigns = await _vetted_campaigns(
        ctx,
        campaign_scope or campaign_block.EVERY_CAMPAIGN,
        hours=earlier_mod.window_hours(objective, basis[2] if basis is not None else None),
    )
    # The window block leaves out what a kept campaign block states, so the
    # hunt reads each record one time. The gate reads all of them.
    earlier = await _without_campaign_records(ctx, earlier, campaigns)
    gate_basis = _gate_basis(earlier, campaigns)
    earlier_text, earlier_dropped = await _vetted_earlier(ctx, earlier)
    authorized_text, authorized_dropped = await _vetted_authorized(ctx, campaigns.ids)
    started = _started_payload(
        objective,
        earlier,
        earlier_text=earlier_text,
        earlier_dropped=earlier_dropped,
        authorized_text=authorized_text,
        authorized_dropped=authorized_dropped,
        campaigns=campaigns,
    )
    yield _ev("hunt_started", started)

    # Guard (opt-in cloud-egress redaction) + agent + sanitized prompts. The
    # guard is attached to ctx BEFORE the agent is built so the toolset wraps
    # the tool closures at registration time.
    guard, agent, user_msg = await _build_hunt_run(
        ctx,
        objective=objective,
        prior=prior,
        earlier=earlier_text,
        authorized=authorized_text,
        campaigns=campaigns.text,
    )
    # Hunts get a bigger budget than a single-alert investigation — they explore
    # broadly (many hosts/queries) before synthesizing, and the investigation-sized
    # request_limit ran out mid-hunt, erroring before the findings report.
    usage_limits = UsageLimits(
        request_limit=ctx.settings.hunt_request_limit,
        tool_calls_limit=ctx.settings.hunt_tool_calls_limit,
    )

    result: Any = None
    # Which limit stopped the exploration: "time" for the wall clock, "budget"
    # for the request or tool-call budget. The error event of a lost hunt
    # carries it, so the page can name the limit.
    stopped_by = "budget"
    # Accumulate the streamed node messages so that, if the hunt exhausts its budget
    # before emitting a report, we can synthesize a partial report from what it
    # actually gathered instead of erroring with nothing.
    gathered: list[Any] = []
    # Accumulate the tool-result PAYLOADS the hunt actually pulled — the evidence
    # bundle the post-hunt citation gate resolves findings against (E1.3). Collected
    # from the streamed tool_result events (desanitized to match the desanitized
    # report's citations), so a finding citing an id the hunt never pulled is caught.
    gathered_tool_results: list[Any] = []
    budget_exhausted = False
    # The agent run, kept past the block so its model usage can be recorded on
    # every exit: a hunt stored no usage at all before the run counters.
    agent_run: Any = None
    try:
        # Whole-hunt wall-clock safety net: a HUNG LLM stream has no budget-based
        # stopping point and would otherwise stall the background task forever.
        # On expiry the TimeoutError falls through to the same partial-report path
        # as budget exhaustion so the hunt lands a grounded PARTIAL report.
        async with (
            asyncio.timeout(ctx.settings.hunt_run_timeout_s),
            agent.iter(user_msg, usage_limits=usage_limits) as run,
        ):
            agent_run = run
            async for node in run:
                async for disp in _stream_node(node, _ev, guard, gathered, gathered_tool_results):
                    yield disp
        result = run.result
    except asyncio.CancelledError:
        raise  # cooperative cancel — propagate, never swallow
    except (UsageLimitExceeded, TimeoutError) as e:
        # Budget exhaustion (UsageLimitExceeded) and the whole-hunt wall-clock
        # backstop (TimeoutError) are both EXPECTED outcomes of a broad hunt on a
        # slow stack, not infra failures. The queries + results already streamed
        # live — don't discard them with status=error and no report. Fall through
        # to synthesize a PARTIAL report from what was gathered.
        _LOGGER.warning(
            "hunt hit its exploration budget/time limit; synthesizing partial report: %s", e
        )
        budget_exhausted = True
        stopped_by = "time" if isinstance(e, TimeoutError) else "budget"
    except BaseException as e:
        _LOGGER.exception("hunt agent run failed")
        if (usage_ev := _hunt_usage_event(_ev, agent_run, phase="hunt")) is not None:
            yield usage_ev
        yield _ev("error", {"message": str(e), "type": type(e).__name__})
        return
    if (usage_ev := _hunt_usage_event(_ev, agent_run, phase="hunt")) is not None:
        yield usage_ev

    # True ONLY when the report below came from the budget/timeout partial path —
    # gates the deterministic humility clamp (a full-run report is never clamped).
    partial_synthesis = False
    if result is None and budget_exhausted and gathered:
        # Replay the accumulated transcript through a no-tools synthesizer to land a
        # grounded partial HuntReport rather than an empty error.
        landed: list[Any] = []
        async for synth_ev in _partial_report(
            ctx,
            objective=objective,
            gathered=gathered,
            stopped_by=stopped_by,
            ev_factory=_ev,
            landed=landed,
        ):
            yield synth_ev
        if not landed:
            # The report writer failed, and its error event is in the stream.
            return
        result = landed[0]
        partial_synthesis = True
        if (
            synth_usage_ev := _hunt_usage_event(_ev, result, phase="hunt_partial_synth")
        ) is not None:
            yield synth_usage_ev

    if result is None:
        yield _ev("error", {"message": "hunt produced no report", "type": "EmptyResult"})
        return

    report = _desanitize_hunt_report(result.output, guard)

    # ── Partial-report humility clamp (deterministic) ────────────────────────
    # A budget/timeout-truncated hunt is written up by the no-tools synthesizer
    # from a transcript dominated by loud alert titles — the prompt ASKS for lower
    # confidence and threat skepticism, but two prod hunts still emitted HIGH
    # severity at 0.75-0.78 conf. Make the humility a RULE, not a request: on the
    # partial path clamp overall confidence to <= 0.5 and cap any threat finding to
    # medium with a note. Runs BEFORE the citation gate so a partial's caps compose
    # with the corroboration cap (min-severity wins either way).
    if partial_synthesis:
        report = _apply_partial_humility(report)

    # ── Post-hunt citation gate (E1.3) ───────────────────────────────────────
    # Deterministically resolve each finding's citations against the evidence the
    # hunt ACTUALLY gathered; strip non-resolving citations + cap such findings'
    # severity. Returns the validated report + the citation_validation event (or
    # None on a validator error — the gate is fail-soft).
    #
    # Then the host gap gate: a visibility gap that names a host is read
    # against the host's coverage. A host that ships host logs or osquery is
    # not a host with no telemetry.
    report, gate_events = await _post_hunt_gates(report, gathered_tool_results, ctx, _ev)
    for gate_ev in gate_events:
        yield gate_ev

    # ── Window gate (deterministic, C2) ──────────────────────────────────────
    # A scheduled hunt reads the true positives that soc-ai holds for its
    # window. A report that names none of them, by host or by rule, gets one
    # labeled line before the text of the model. Runs before the
    # evidence-count gate, so it reads the model's own narrative and not the
    # banner of a blind hunt.
    report = _gate_window_all_clear(report, gate_basis)

    # ── Evidence-count gate (deterministic, G6) ──────────────────────────────
    # Count what the tools ACTUALLY returned rather than trusting the write-up to
    # mention the failures. A hunt may only stand as a clean sweep if at least ONE
    # grid read SUCCEEDED — whether every grid call errored (an outage), every
    # query was rejected by the grid (the model wrote queries ES said no to), or
    # the hunt never made a grid call at all, it looked at nothing, so its report
    # cannot read as "the network is quiet" however confidently it is worded.
    # Runs LAST so the visibility-gap finding it adds is not stripped by the
    # citation gate for citing nothing — a blind hunt has nothing to cite.
    report, degraded_reason = _gate_hunt_evidence(report, gathered_tool_results)

    # ── Reasoning trace check (C4) ───────────────────────────────────────────
    # A hunt whose model responses carry no reasoning trace, on a deployment
    # whose earlier hunts carried one, ran on a weaker path. Prod hunt
    # 01M6HB9Y7JDA71ZEYME4N2MSF2 (2026-11-03) ran 36 responses with no trace
    # and wrote 3 false threat findings, and no surface said so. The hunt
    # still completes, and its findings are still investigated. The report and
    # each finding carry the mark.
    responses, traced = _reasoning_counts(gathered)
    no_reasoning = responses > 0 and traced == 0 and await _reasoning_expected(ctx)
    if no_reasoning:
        _LOGGER.warning(
            "hunt: %d model responses carry no reasoning trace. Earlier hunts carried one. "
            "The report takes the degraded mark.",
            responses,
        )
        report = _mark_no_reasoning(report)

    report_payload = report.model_dump(mode="json")
    if no_reasoning:
        # A key beside the HuntReport fields, on the stored report. The hunt
        # row and the hunt page read it with no event query and no migration.
        report_payload[hunt_outcome.DEGRADED_KEY] = {
            "reason": hunt_outcome.NO_REASONING_REASON,
            "model_responses": responses,
        }
    yield _ev("hunt_report", report_payload)
    yield _ev(
        "done",
        {
            "finding_count": len(report.findings),
            # How many model responses the exploration made, and how many of
            # them carried a reasoning trace. ``no_reasoning_trace`` is the
            # mark above. It is apart from ``degraded``: a hunt with the mark
            # read the grid, so it does not finalize as a blind run.
            "model_responses": responses,
            "reasoning_traces": traced,
            "no_reasoning_trace": no_reasoning,
            # Read by hunt_recorded_run to finalize the row as a degraded run
            # rather than a completed hunt. On the done event (not a new event
            # kind) so the persisted trace carries it without a UI that must
            # learn a kind. The reason names the CAUSE: ``grid_unavailable``
            # (the grid could not be read), ``grid_queries_rejected`` (the grid
            # answered and rejected every query), or ``no_grid_reads`` (the hunt
            # never ran a grid query).
            "degraded": degraded_reason is not None,
            "degraded_reason": degraded_reason,
            # True when the budget synthesizer wrote the report from a cut-short
            # trace. The lead settle rule reads it: such a hunt did not read
            # all its evidence, so it never closes a lead as clean.
            "partial": partial_synthesis,
        },
    )


_PARTIAL_HUMILITY_NOTE = (
    "partial report: the hunt stopped at its budget or its time limit. It did not "
    "corroborate this finding. Corroborate it before you act."
)

# The trace line of the second synthesis attempt (:func:`_text_transcript`).
_TEXT_RETRY_NOTE = (
    "The report writer answered with a tool call and wrote no report. "
    "It writes the report again from a text copy of the evidence."
)

# The mark on each finding of a hunt whose model returned no reasoning trace.
# The page keeps it when it rewords the note of a gate before it
# (soc_ai.hunting.hunt_words.validator_note).
_NO_REASONING_NOTE = DEGRADED_FINDING_NOTE


def _gate_window_all_clear(report: Any, earlier: EarlierConclusions | None) -> Any:
    """Add one labeled line to a report that names none of the true positives of its window.

    Prod hunt 01M6VMYHA1TTSBJRHRNGJZT6AD wrote "No malicious cyber activity"
    while the store held two true positives from its window (2026-11-07). The
    prompt rule asks the model to name them
    (:data:`soc_ai.hunting.earlier.WINDOW_RULE`). This gate is the part that
    does not depend on the model.

    It parses no sentence. A true positive of the block
    (:attr:`EarlierConclusions.confirmed`) is accounted for when the report
    holds a threat finding on its target, or when the narrative names its
    target host or its rule (:func:`soc_ai.hunting.earlier.unnamed_activity`).
    The line names the ones that are not. A report that names the confirmed
    activity gets no line, whatever else it says. The text of the model stays
    whole, after the line. No finding, severity or confidence changes.
    Fail-soft and pure.
    """
    confirmed = tuple(getattr(earlier, "confirmed", None) or ())
    if not confirmed:
        return report
    try:
        from soc_ai.hunting import earlier as earlier_mod  # noqa: PLC0415 - lazy, like the caller

        narrative = str(getattr(report, "narrative", "") or "")
        if narrative.startswith(f"**{earlier_mod.ALL_CLEAR_LABEL}.**"):
            # The line is there. A second pass adds no second line.
            return report
        threat_hosts = [
            host
            for finding in report.findings
            if str(getattr(finding, "category", "") or "").strip().lower() == "threat"
            for host in (getattr(finding, "hosts", None) or [])
        ]
        unnamed = earlier_mod.unnamed_activity(confirmed, narrative, threat_hosts)
        if not unnamed:
            return report
        _LOGGER.warning(
            "hunt: the report names none of %d true positive verdicts of its window. "
            "The report takes one labeled line.",
            len(unnamed),
        )
        line = earlier_mod.all_clear_line(unnamed)
        return report.model_copy(update={"narrative": f"{line}\n\n{narrative}".strip()})
    except Exception:
        _LOGGER.warning("hunt window gate failed; persisting report as-is", exc_info=True)
        return report


def _synthesis_failed_event(ev_factory: Any, exc: BaseException, stopped_by: str) -> StepEvent:
    """The ``error`` event of a hunt that reached a limit and then got no report.

    ``message`` keeps the raw error for the technical detail of the page.
    ``stage`` and ``limit`` say where the hunt stopped, so the plain cause
    (:func:`soc_ai.hunting.outcome.failure_cause`) does not read it out of
    the text.
    """
    limit_words = "its time limit" if stopped_by == "time" else "its budget"
    event: StepEvent = ev_factory(
        "error",
        {
            "message": f"hunt hit {limit_words} and partial synthesis failed: {exc}",
            "type": type(exc).__name__,
            "stage": "partial_synthesis",
            "limit": stopped_by,
        },
    )
    return event


def _reasoning_counts(gathered: list[Any]) -> tuple[int, int]:
    """``(model responses, responses with a reasoning trace)`` of the exploration.

    A trace is a ``ThinkingPart`` with text, or an inline ``<think>`` block in
    a text part: the two shapes :func:`soc_ai.agent.orchestrator._walk_message`
    records as ``reasoning_trace``. Never raises.
    """
    responses = traced = 0
    for msg in gathered:
        if type(msg).__name__ != "ModelResponse":
            continue
        responses += 1
        for part in _parts_of(msg):
            name = type(part).__name__
            content = str(getattr(part, "content", "") or "")
            if name == "ThinkingPart" and content.strip():
                traced += 1
                break
            if name == "TextPart" and extract_reasoning_trace(content)[0]:
                traced += 1
                break
    return responses, traced


async def _reasoning_expected(ctx: InvestigationContext) -> bool:
    """Whether this deployment's recent hunts carried a reasoning trace.

    A deployment on a model that does not reason has no trace on any hunt,
    and a mark on every hunt would say nothing. The store answers: one of the
    newest agent hunts must hold a model response with a trace. Never raises.
    With no store, or on a read that fails, the answer is no and the hunt
    takes no mark.
    """
    if ctx.db_sessionmaker is None:
        return False
    try:
        async with ctx.db_sessionmaker() as db:
            return await hunt_svc.recent_reasoning_seen(db)
    except Exception:
        _LOGGER.warning(
            "hunt: soc-ai could not read the reasoning traces of earlier hunts. "
            "The hunt takes no degraded mark.",
            exc_info=True,
        )
        return False


def _mark_no_reasoning(report: Any) -> Any:
    """State the degraded mark on every finding of the report.

    The note joins a note that a gate already wrote. No severity and no
    confidence changes: the investigations of the findings still run, and
    they judge each claim. Fail-soft and pure, like the humility clamp.
    """
    try:
        marked: list[Any] = []
        for finding in report.findings:
            earlier_note = str(getattr(finding, "validator_note", None) or "").strip()
            note = f"{earlier_note} {_NO_REASONING_NOTE}" if earlier_note else _NO_REASONING_NOTE
            marked.append(finding.model_copy(update={"validator_note": note}))
        return report.model_copy(update={"findings": marked})
    except Exception:
        _LOGGER.warning("hunt degraded mark failed; persisting report as-is", exc_info=True)
        return report


_GRID_OUTAGE_NOTE = (
    "grid unavailable: every grid query in this hunt failed. The hunt checked "
    "nothing and ruled out nothing."
)
_GRID_OUTAGE_TITLE = "Grid unavailable. The hunt read nothing"

# The two evidence-count reasons beside the transport outage. Persisted on the
# ``done`` event's ``degraded_reason``, so they are vocabulary, not prose: the
# refused/rejected distinction matters — ``grid_unavailable`` blames grid
# health, ``grid_queries_rejected`` blames the QUERIES (the grid answered every
# call; the model wrote queries ES said no to), and ``no_grid_reads`` means the
# hunt never asked the grid anything at all.
QUERIES_REJECTED_REASON = "grid_queries_rejected"
NO_GRID_READS_REASON = "no_grid_reads"

_QUERIES_REJECTED_NOTE = (
    "every grid query rejected: the grid answered and rejected each query of this "
    "hunt as invalid. The hunt checked nothing and ruled out nothing."
)
_QUERIES_REJECTED_TITLE = "The grid rejected every query. The hunt read nothing"

_NO_GRID_READS_NOTE = (
    "no grid reads: this hunt ran no successful grid query. It checked nothing "
    "and ruled out nothing."
)
_NO_GRID_READS_TITLE = "No grid reads. The hunt read nothing"


def _grid_tool_outcomes(tool_results: list[Any]) -> tuple[int, int, int]:
    """Count ``(succeeded, failed, rejected)`` over the GRID-backed tool results.

    The arithmetic behind the evidence-count gate, and the hunt-side mirror of
    :func:`soc_ai.agent.evidence.count_successful_tool_calls`, which already
    excludes errored results from the triage evidence gate.

    Only grid-backed tools count (:data:`~soc_ai.agent.toolset.GRID_BACKED_TOOLS`)
    — the question is whether this hunt could read the NETWORK, and a working web
    search or a local dossier lookup says nothing about that. A FAILURE is a
    result the tool boundary stamped ``reason: "grid_unavailable"`` (the grid
    could not be read). A REJECTION is any other error from a grid-backed tool —
    a bad query or bad arguments the grid answered and said no to; the model can
    fix those and try again, which is why a rejection is not a failure, but a run
    made of NOTHING BUT rejections still read nothing, which is why they are
    counted at all. A query the grid answered with failed shards because the
    query was wrong for a field (``reason: "query_rejected"``,
    :data:`~soc_ai.agent.toolset.QUERY_REJECTED_REASON`) is a rejection too:
    the grid was up (production 2026-11-19).

    A zero-hit result counts as a SUCCESS: the grid answered, and an empty answer
    from a healthy grid is a real, valuable result. Distinguishing "quiet" from
    "blind" is the entire point.

    A SHORT-CIRCUITED call never reached the grid, so it is none of the three:
    the tool wrappers answer some calls from local state without querying — a
    repeat of an identical call (``duplicate_call``) and a community_id the
    orchestrator already prefetched (``prefetch_already_has_this``). Both come
    back as non-error dicts from a grid-backed tool, and counting them as reads
    would let a blind hunt certify itself: the dedup tracker registers a call's
    key BEFORE the underlying query runs, so the retry of a query that timed out
    is a duplicate hit, and one such retry would silence the gate. These are the
    same two exclusions ``count_successful_tool_calls`` carries — deliberately
    without its DISCRIMINATING-DATA standard, which is right for the evidence gate
    (a throwaway zero-hit call must not license a verdict) and wrong here (a
    zero-hit answer is exactly what a healthy quiet grid returns).
    """
    succeeded = failed = rejected = 0
    for item in tool_results:
        if not isinstance(item, dict):
            continue
        grid_tool = str(item.get("tool_name") or "") in GRID_BACKED_TOOLS
        result = item.get("result")
        if not isinstance(result, dict):
            if grid_tool:
                succeeded += 1
            continue
        if result.get("error"):
            if result.get("reason") == GRID_UNAVAILABLE_REASON:
                failed += 1
            elif grid_tool:
                rejected += 1
        elif result.get("duplicate_call") or result.get("prefetch_already_has_this"):
            continue
        elif grid_tool:
            succeeded += 1
    return succeeded, failed, rejected


def _gate_hunt_evidence(report: Any, tool_results: list[Any]) -> tuple[Any, str | None]:
    """Run the deterministic evidence-count gate; return ``(report, degraded_reason)``.

    Counterpart to :func:`_gate_hunt_citations`, and the half of G6 that does not
    depend on the model cooperating. A hunt may only stand as a clean
    ``complete`` if it made AT LEAST ONE successful grid read — a genuine
    zero-hit answer included (the grid answered; quiet is a real result). Absent
    that, the report is stamped blind and a non-``None`` reason comes back for
    the caller to finalize the row as a degraded run instead of a completed
    hunt, worded by cause:

    * :data:`~soc_ai.agent.toolset.GRID_UNAVAILABLE_REASON` — at least one grid
      call failed as a transport outage: the GRID could not be read. Wins when
      causes mix, because "re-run once the grid is reachable" is the instruction
      that fixes it.
    * :data:`QUERIES_REJECTED_REASON` — every grid call was rejected (an ES 4xx
      / bad arguments): the grid was reachable, the QUERIES were the problem.
    * :data:`NO_GRID_READS_REASON` — the hunt never made a grid call at all:
      the zero-tool hunt, or one that answered purely from off-grid tools.

    The gate applies to EVERY hunt — no hunt path legitimately completes without
    a fresh grid read. A hunt context carries no prefetched alert evidence
    (``ctx_from_state`` builds it with an empty ``prefetched_community_ids``;
    hunts are not alert-anchored), and the off-grid tools (dossier, enrichment,
    web) are context ABOUT the network, not a look AT it — a hunt is, by
    contract, a look.

    The reason is computed from the counts alone, so it survives a decoration
    failure — a marker that blew up must still not leave a clean, complete hunt.
    """
    succeeded, failed, rejected = _grid_tool_outcomes(tool_results)
    if succeeded:
        return report, None
    if failed:
        _LOGGER.warning(
            "hunt could not read the grid (%d grid queries failed, none succeeded); "
            "marking the report degraded",
            failed,
        )
        return _mark_grid_outage(report, failed), GRID_UNAVAILABLE_REASON
    if rejected:
        _LOGGER.warning(
            "hunt read nothing (%d grid queries rejected, none succeeded); "
            "marking the report degraded",
            rejected,
        )
        return _mark_queries_rejected(report, rejected), QUERIES_REJECTED_REASON
    _LOGGER.warning("hunt made no grid reads at all; marking the report degraded")
    return _mark_no_grid_reads(report), NO_GRID_READS_REASON


def _mark_grid_outage(report: Any, failures: int) -> Any:
    """Stamp a hunt report that could not read the grid as exactly that."""
    return _mark_blind_hunt(
        report,
        title=_GRID_OUTAGE_TITLE,
        detail=(
            f"All {failures} Security Onion queries of this hunt failed. The hunt did "
            "not confirm the objective and did not rule it out. Do not read this "
            "report as proof of a quiet network. Run the hunt again when the grid is "
            "reachable."
        ),
        note=_GRID_OUTAGE_NOTE,
        banner=(
            "**Grid unavailable. The hunt could not read the network.** "
            f"All {failures} grid queries failed. Nothing below rules anything out. "
            "The model wrote the text below without grid data."
        ),
    )


def _mark_queries_rejected(report: Any, rejections: int) -> Any:
    """Stamp a hunt report whose every grid query was rejected as exactly that.

    Worded at the QUERIES, not at grid health: the grid was reachable and
    answered every call — it rejected what the model asked. The remedy is a
    re-run (fresh queries), not waiting out an outage.
    """
    return _mark_blind_hunt(
        report,
        title=_QUERIES_REJECTED_TITLE,
        detail=(
            f"The grid rejected all {rejections} Security Onion queries of this hunt "
            "as invalid. The grid was reachable. The queries or their arguments were "
            "bad. The hunt did not confirm the objective and did not rule it out. Do "
            "not read this report as proof of a quiet network. Run the hunt again. If "
            "the grid rejects every query again, the queries that the model writes do "
            "not match this grid."
        ),
        note=_QUERIES_REJECTED_NOTE,
        banner=(
            "**The grid rejected every query. The hunt read nothing.** "
            f"The grid rejected all {rejections} queries as invalid. Nothing below "
            "rules anything out. The model wrote the text below without grid data."
        ),
    )


def _mark_no_grid_reads(report: Any) -> Any:
    """Stamp a hunt report produced without a single grid query as exactly that.

    The zero-tool arm: the hunt wrote its report without ever asking the grid a
    question (no grid call at all, or only off-grid context lookups). Nothing was
    checked, so nothing was cleared.
    """
    return _mark_blind_hunt(
        report,
        title=_NO_GRID_READS_TITLE,
        detail=(
            "The hunt wrote its report without a Security Onion query. It did not "
            "confirm the objective against the network telemetry and did not rule it "
            "out. Do not read this report as proof of a quiet network. Run the hunt "
            "again."
        ),
        note=_NO_GRID_READS_NOTE,
        banner=(
            "**No grid reads. The hunt did not query the network.** "
            "No grid query ran. Nothing below rules anything out. The model wrote "
            "the text below without grid data."
        ),
    )


def _mark_blind_hunt(report: Any, *, title: str, detail: str, note: str, banner: str) -> Any:
    """Stamp a hunt report that never successfully read the grid.

    Three marks, because three different readers need them: the narrative (what
    the analyst reads) gets ``banner`` prepended, a ``visibility_gap`` finding
    carrying ``note`` in ``validator_note`` (the structured, machine-readable
    record, and the channel the deterministic gates already own) is prepended to
    the findings, and confidence drops to ``0.0`` (a hunt that never saw the
    network has no confidence in anything — this is a floor-to-zero, not the
    partial path's 0.5 ceiling).

    The finding is a ``visibility_gap`` and never a ``threat``: the schema's own
    rule is that telemetry you cannot read is a coverage statement, and a blind
    hunt must not page anyone.

    Fail-soft and PURE, like the humility clamp: on any surprise shape the report
    is returned unchanged. The caller's degraded REASON does not depend on this
    succeeding, so a decoration failure can still not land a clean hunt.
    """
    try:
        gap = HuntFinding(
            title=title,
            detail=detail,
            severity="high",
            category="visibility_gap",
            validator_note=note,
        )
        narrative = (banner + "\n\n" + str(getattr(report, "narrative", "") or "")).strip()
        return report.model_copy(
            update={
                "findings": [gap, *report.findings],
                "narrative": narrative,
                "confidence": 0.0,
            }
        )
    except Exception:
        _LOGGER.warning("hunt blind-hunt marker failed; persisting report as-is", exc_info=True)
        return report


def _apply_partial_humility(report: Any) -> Any:
    """Clamp a budget/timeout-PARTIAL HuntReport's confidence + threat severities.

    A cut-short hunt is synthesized (no tools) from a transcript that is often
    dominated by loud detector-alert titles. Even with the synth prompt asking for
    humility, the model over-claimed on two prod hunts (HIGH severity, 0.75-0.78
    conf). This makes it deterministic:

    * ``confidence`` is clamped to at most ``0.5`` (the mid default) — a partial
      hunt cannot report high confidence in its conclusions.
    * every ``category == "threat"`` finding at high/critical severity is capped to
      ``"medium"`` and annotated with :data:`_PARTIAL_HUMILITY_NOTE` (preserving any
      note the citation gate later sets is handled by ordering — this runs first).

    Fail-soft and PURE: on any surprise shape the original report is returned
    unchanged (a humility clamp must never cost the hunt its report). Uses the
    hunt-gate severity machinery so "cap" only ever LOWERS a severity.
    """
    try:
        # _severity_rank rather than a local _SEV_RANK.get default: an unknown
        # severity has to rank the same here as it does inside the gates, or the
        # humility clamp and the citation gate disagree about which findings are
        # loud enough to cap.
        from soc_ai.agent.hunt_gates import (  # noqa: PLC0415
            _SEV_RANK,
            _cap_severity,
            _severity_rank,
        )

        new_findings: list[Any] = []
        for finding in report.findings:
            category = str(getattr(finding, "category", None) or "").strip().lower()
            severity = str(getattr(finding, "severity", None) or "info")
            if category == "threat" and _severity_rank(severity) >= _SEV_RANK["high"]:
                new_findings.append(
                    finding.model_copy(
                        update={
                            "severity": _cap_severity(severity, "medium"),
                            "validator_note": _PARTIAL_HUMILITY_NOTE,
                        }
                    )
                )
            else:
                new_findings.append(finding)
        confidence = min(float(getattr(report, "confidence", 0.5) or 0.0), 0.5)
        return report.model_copy(update={"findings": new_findings, "confidence": confidence})
    except Exception:
        _LOGGER.warning(
            "hunt partial-humility clamp failed; persisting report as-is", exc_info=True
        )
        return report


def _gate_hunt_citations(
    report: Any, tool_results: list[Any], ev_factory: Any
) -> tuple[Any, StepEvent | None]:
    """Run the E1.3 finding gate + E3.3 chart gate; return (validated_report, event).

    Deterministically resolves each finding's citations against the evidence the
    hunt gathered this run, strips non-resolving citations, caps such findings'
    severity, and caps a high/critical finding that cites nothing. Then, over the
    SAME gathered tool-results, resolves each chart's ``source_citations`` with the
    SAME distinctive-token resolver and DROPS any chart whose citations don't
    resolve (or which has no series / no citations), capped at 4 — an invented
    series is never rendered. The event carries the per-hunt counts (finding tallies
    plus ``charts`` / ``charts_dropped``), mirroring the investigation path's
    ``citation_validation`` emission. Fail-soft: a validator surprise must never
    cost the hunt its report — on error the unvalidated report is returned with a
    ``None`` event.

    The lead-link gate runs last, over the validated findings (change E): a
    threat whose title links leads becomes an observation, and its note says
    why. The event carries ``lead_links``, the count the lead store reads to
    keep such a lead from a clean close.
    """
    try:
        validated_findings, counts = _validate_hunt_findings(report.findings, tool_results)
        validated_findings, lead_links = gate_lead_links(validated_findings)
        kept_charts, chart_counts = _validate_hunt_charts(report.charts, tool_results)
        report = report.model_copy(update={"findings": validated_findings, "charts": kept_charts})
        return report, ev_factory(
            "citation_validation",
            {"round": 1, **counts, **chart_counts, "lead_links": lead_links},
        )
    except Exception:
        _LOGGER.warning("hunt citation gate failed; persisting unvalidated report", exc_info=True)
        return report, None


async def _post_hunt_gates(
    report: Any, tool_results: list[Any], ctx: InvestigationContext, ev_factory: Any
) -> tuple[Any, list[StepEvent]]:
    """The citation gate, then the host gap gate. Returns the report and their events."""
    events: list[StepEvent] = []
    report, citation_ev = _gate_hunt_citations(report, tool_results, ev_factory)
    if citation_ev is not None:
        events.append(citation_ev)
    report, host_gap_ev = await _gate_host_gaps(report, ctx, ev_factory)
    if host_gap_ev is not None:
        events.append(host_gap_ev)
    report = await _gate_finding_names(report, ctx)
    return report, events


async def _gate_finding_names(report: Any, ctx: InvestigationContext) -> Any:
    """Note each finding whose text names a known machine that is no host of it.

    The model text stays. The note goes after the notes of the other gates
    (:mod:`soc_ai.campaigns.finding_names`). Fail-soft: a failed read costs
    the hunt no report.
    """
    maker = ctx.db_sessionmaker
    findings = list(getattr(report, "findings", None) or [])
    if maker is None or not findings:
        return report
    try:
        async with maker() as db:
            notes = await finding_names.notes_for_findings(
                db,
                [{"title": f.title, "detail": f.detail, "hosts": f.hosts} for f in findings],
            )
    except Exception:
        _LOGGER.warning("hunt name check failed; persisting the report as-is", exc_info=True)
        return report
    marked = [
        f
        if note is None
        else f.model_copy(
            update={"validator_note": f"{f.validator_note} {note}" if f.validator_note else note}
        )
        for f, note in zip(findings, notes, strict=True)
    ]
    return report.model_copy(update={"findings": marked})


async def _gate_host_gaps(
    report: Any, ctx: InvestigationContext, ev_factory: Any
) -> tuple[Any, StepEvent | None]:
    """Run the host gap gate; return (report, event). Fail-soft, like the citation gate."""
    try:
        report, counts = await gate_host_gaps(
            report,
            elastic=ctx.elastic,
            settings=ctx.settings,
            sessionmaker=ctx.db_sessionmaker,
            include_synth=ctx.include_synth,
        )
    except Exception:
        _LOGGER.warning("hunt host gap gate failed; persisting the report as-is", exc_info=True)
        return report, None
    if not counts.get("host_gaps") and not counts.get("narrative_sentences_rewritten"):
        return report, None
    return report, ev_factory("host_gap_validation", counts)


async def hunt_recorded_run(
    state: Any,
    *,
    ctx: InvestigationContext,
    objective: str,
    started_by: str,
    prior: str | None = None,
    kind: str = "chat",
    starter: str = "analyst",
    lead_id: int | None = None,
    cancel_token: CancelToken | None = None,
    earlier: EarlierConclusions | None = None,
    campaign_id: int | None = None,
) -> AsyncIterator[tuple[str, dict[str, Any]]]:
    """Wrap :func:`run_hunt` with the hunt recorder tee.

    Yields ``(event_name, data_dict)`` pairs. The leading ``hunt_created`` event
    (carrying the new row id) is always first. Mirrors
    :func:`soc_ai.api.runner.recorded_run`.

    ``earlier`` is the earlier-conclusions block, passed to :func:`run_hunt`.
    The stored objective does not change.

    ``campaign_id`` is the campaign of the hunt: the campaign of the lead of
    a lead hunt, or the campaign of a campaign hunt. A lead hunt and a
    campaign hunt read the block of that campaign only
    (:func:`soc_ai.hunting.campaign_block.scope_of`).
    """
    scope = campaign_block.scope_of(starter=starter, lead_id=lead_id, campaign_id=campaign_id)
    recorder = HuntRecorder(
        state.db_sessionmaker,
        objective=objective,
        started_by=started_by,
        kind=kind,
        # Synth-eval containment: a hunt recorded from an eval context (its
        # tools may see planted synth scenarios) is permanently marked so its
        # findings can never be read back as real activity. Every API/scheduler
        # path builds its context via ctx_from_state, which leaves
        # include_synth False — only an explicit eval context sets it.
        is_synth_eval=bool(ctx.include_synth),
        starter=starter,
        lead_id=lead_id,
    )
    hunt_id = await recorder.start()

    yield "hunt_created", {"hunt_id": hunt_id}

    # Meter the grid reads in the task that drains the rest of the stream, for
    # the reason soc_ai.api.runner.recorded_run gives.
    recorder.attach_search_meter(start_search_meter())

    # Set from the terminal ``done`` event when the runner's deterministic
    # evidence-count gate fired: the run made not one successful grid read —
    # every grid query failed, or every one was rejected, or none ever ran — so
    # it never looked at the network. Such a hunt must NOT finalize 'complete' —
    # a completed hunt is a covered objective (it seeds the vs-last-run diff, the
    # per-host findings scan and the schedule's freshness marker), and a blind
    # hunt covered nothing.
    grid_blind = False
    try:
        async for ev in run_hunt(
            ctx, objective=objective, prior=prior, earlier=earlier, campaign_scope=scope
        ):
            if ev.kind == "done" and ev.payload.get("degraded"):
                grid_blind = True
            await recorder.record(ev.kind, ev.sequence, ev.payload)
            yield (
                ev.kind,
                {
                    "session_id": ev.session_id,
                    "sequence": ev.sequence,
                    "payload": ev.payload,
                },
            )
        # The hunt investigates its subject findings as part of the hunt
        # (soc_ai.webui.hunt_findings). A blind hunt investigates nothing: its
        # findings rest on no grid read.
        settings = getattr(state, "settings", None) or ctx.settings
        plan = None if grid_blind else hunt_findings.plan_findings(recorder.report, settings)
        await recorder.finish(
            "error" if grid_blind else "complete",
            finding_plan=plan.as_column() if plan is not None else None,
        )
        verdicts = None
        if (
            plan is not None
            and recorder.hunt_id is not None
            and recorder.final_status == hunt_svc.STATUS_INVESTIGATING
        ):
            verdicts = await hunt_findings.investigate_findings(
                state, hunt_id=recorder.hunt_id, ctx=ctx, plan=plan
            )
        # E2.4 notification trigger — a completed hunt whose report contains a
        # threat-category finding pings on-call. THIN + fail-soft: build a
        # NotifyEvent from the recorder's captured report and fire it (a hard
        # no-op unless notifications are enabled + a webhook is configured). Wrapped
        # so a webhook can never break the finalized hunt.
        #
        # Skipped when the hunt was blind: a "threat" asserted by a hunt that made
        # no successful grid read has nothing behind it, and waking on-call for it
        # is the blindness generating the alarm.
        if not grid_blind:
            await _maybe_notify_hunt(state, recorder, verdicts)
    except asyncio.CancelledError:
        # Only an EXPLICIT operator cancel is 'cancelled'; any other cancellation
        # (SSE client disconnect, app/container shutdown) is an interrupted run
        # that never reached a report → 'error'. finish() is idempotent.
        #
        # Shielded: Starlette/sse-starlette run this generator inside an anyio
        # cancel scope that RE-DELIVERS the cancellation on every await until the
        # scope exits, so a bare finalize is itself cancelled mid-commit. finish()
        # marks itself done before its first await, so the finally below would
        # then be a no-op and the row would sit 'running' until the reaper.
        await asyncio.shield(
            recorder.finish(
                "cancelled" if (cancel_token is not None and cancel_token.requested) else "error"
            )
        )
        raise
    except Exception as exc:
        _LOGGER.exception("hunt stream crashed")
        # Tell the recorder why before it finalizes. The stream never reached
        # an ``error`` event, so this is the only record of the cause.
        recorder.note_failure(exc)
        await recorder.finish("error")
        yield "error", {"message": str(exc), "type": type(exc).__name__}
    finally:
        # no-op if already finished; lands rows abandoned by client disconnect.
        # Shielded for the same reason as the cancel branch above: the finally
        # runs during the cancellation unwind, where a bare await would be
        # cancelled before the finalize commits.
        await asyncio.shield(recorder.finish("error"))


async def _maybe_notify_hunt(
    state: Any, recorder: HuntRecorder, verdicts: FindingVerdicts | None = None
) -> None:
    """Fire the E2.4 hunt-threat notification for a finalized hunt (fail-soft).

    Reads the recorder's captured HuntReport + hunt id, builds a NotifyEvent iff
    the report has a threat-category finding (per settings), and fires it. Every
    failure mode is swallowed — a notification must NEVER break the just-finalized
    hunt. Zero egress unless notifications are enabled + a webhook is configured.

    ``verdicts`` is the summary of the investigations of the hunt's subject
    findings. When one of them reached a verdict, the notice reads the
    verdicts and not the hunt's own claim.
    """
    try:
        from soc_ai import notify  # noqa: PLC0415 - local, keeps import graph light

        hunt_id = recorder.hunt_id
        report = recorder.report  # the captured hunt_report payload (or None)
        if hunt_id is None or not report:
            return
        event = notify.event_for_hunt(
            hunt_id=hunt_id,
            report=report,
            settings=state.settings,
            verdicts=verdicts,
        )
        if event is not None:
            await notify.fire_safe(event, state.settings, getattr(state, "audit", None))
    except Exception:  # a notification trigger must never break the primary flow
        _LOGGER.warning("hunt notify trigger failed (continuing)", exc_info=True)


def sse_encode(name: str, data: dict[str, Any]) -> dict[str, Any]:
    """Encode a (name, data) pair into the SSE dict format used by EventSourceResponse."""
    return {"event": name, "data": json.dumps(data, default=str)}

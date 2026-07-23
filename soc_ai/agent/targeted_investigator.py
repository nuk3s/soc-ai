"""Phase D — targeted investigator.

Replaces the multi-tool LLM-driven investigator agent for the synth-first
pipeline. The synth round-1 emits a TargetedGap naming ONE tool + exact
args. This module dispatches that tool deterministically — no LLM call,
no tool selection, just argument unpacking + dispatch.

Why deterministic? The 30B was burning 6K-15K reasoning-trace tokens per
investigator turn. Phase D removes the LLM from the dispatch loop
entirely; the synth (120B) decides what to call, and we just call it.
The bytes saved are the long-tail timeout fix.
"""

from __future__ import annotations

import inspect
import json
import logging
from collections.abc import Callable
from typing import Any, NoReturn, cast

from soc_ai.agent.toolset import PHASE_D_TOOLS, _clamp_tool_result
from soc_ai.agent.triage import TargetedGap

_LOGGER = logging.getLogger(__name__)

# Per-tool argument ceilings, mirroring the clamps register_read_tools enforces
# inline in the interactive path (toolset.py). Phase-D dispatch calls the tool
# functions DIRECTLY, bypassing those wrappers, so we must re-apply the SAME
# caps here — otherwise an oversized max_results/k (a synth mistake, or a
# prompt-injected steer from attacker-influenceable alert data) pulls thousands
# of full docs back and blows the round-2 synth prompt past the model's context.
# Keep in sync with the min(...) clamps in soc_ai/agent/toolset.py.
_PHASE_D_ARG_CEILINGS: dict[str, dict[str, int]] = {
    "t_query_events_oql": {"max_results": 25},
    "t_query_zeek_logs": {"max_results": 25},
    "t_query_cases": {"max_results": 10},
    "t_query_detections": {"max_results": 10},
    "t_get_playbooks": {"max_results": 10},
    "t_lookup_runbook": {"k": 5},
}


def _clamp_arg_ceilings(tool_name: str, tool_args: dict[str, Any]) -> dict[str, Any]:
    """Return ``tool_args`` with any capped arg clamped to its per-tool ceiling.

    Returns the SAME dict object untouched when nothing needs clamping (so the
    common path stays byte-identical); otherwise a shallow copy with the
    offending ints lowered. Never mutates the caller's ``gap.tool_args``.
    """
    ceilings = _PHASE_D_ARG_CEILINGS.get(tool_name)
    if not ceilings:
        return tool_args
    clamped: dict[str, Any] | None = None
    for arg, cap in ceilings.items():
        val = tool_args.get(arg)
        # bool is an int subclass — exclude it so a stray True/False isn't "clamped".
        if isinstance(val, int) and not isinstance(val, bool) and val > cap:
            if clamped is None:
                clamped = dict(tool_args)
            clamped[arg] = cap
    return clamped if clamped is not None else tool_args


def build_targeted_investigator_prompt(gap: TargetedGap) -> str:
    """Stub prompt — kept around for audit logs / Phase D alternatives.

    The default Phase D dispatch path is deterministic (no LLM call); this
    prompt is only used if a future variant wants to A/B against an LLM-
    driven Phase D where the 30B confirms the synth's tool selection.
    """
    return (
        "You are a targeted-tool executor. The synthesizer needs ONE specific\n"
        "piece of evidence to finalize a triage verdict. Run this ONE tool call\n"
        "and return the raw result. Do not call any other tool.\n\n"
        f"Question: {gap.question}\n"
        f"Tool: {gap.tool_name}\n"
        f"Args: {json.dumps(gap.tool_args)}\n"
        f"Why: {gap.why_this_matters}\n"
    )


async def run_targeted_investigation(
    gap: TargetedGap,
    *,
    ctx: Any,
) -> dict[str, Any] | str:
    """Dispatch the single tool the synth requested. Return its raw result.

    On any error (unknown tool, dispatch failure, tool exception), return
    a string message describing the failure — synth round 2 sees the
    failure and can still emit a verdict.
    """
    try:
        return await _dispatch_named_tool(gap.tool_name, gap.tool_args, ctx)
    except Exception as e:
        _LOGGER.exception("targeted investigation dispatch failed")
        return f"targeted dispatch error: {type(e).__name__}: {e}"


def _raise_arg_type_error(tool_name: str, args: dict[str, Any], cause: TypeError) -> NoReturn:
    """Raise a structured TypeError so run_targeted_investigation's error
    channel produces an actionable message that names the tool, the offending
    args, and the exception — letting synth round 2 re-call with corrected
    types instead of silently missing the evidence.
    """
    args_repr = repr(args)
    if len(args_repr) > 400:
        args_repr = args_repr[:400] + "…"
    raise TypeError(
        f"tool {tool_name} rejected arguments {args_repr}: {cause}"
        " — re-call with corrected argument types"
    ) from cause


def _dispatch_table() -> dict[str, Callable[..., Any]]:
    """The Phase-D tool_name → callable table. Imported lazily to dodge cycles.

    Its key set is drift-tested against :data:`PHASE_D_TOOLS`
    (tests/test_toolset.py) — add new Phase-D tools in BOTH places.
    """
    from soc_ai.tools.crawl_page import crawl_page  # noqa: PLC0415
    from soc_ai.tools.decode_payload import decode_payload  # noqa: PLC0415
    from soc_ai.tools.enrichment import enrich_domain, enrich_hash, enrich_ip  # noqa: PLC0415
    from soc_ai.tools.get_event_raw import get_event_raw  # noqa: PLC0415
    from soc_ai.tools.get_pcap import get_pcap_facts  # noqa: PLC0415
    from soc_ai.tools.get_playbooks import get_playbooks  # noqa: PLC0415
    from soc_ai.tools.get_rule_content import get_rule_content  # noqa: PLC0415
    from soc_ai.tools.lookup_runbook import lookup_runbook  # noqa: PLC0415
    from soc_ai.tools.query_cases import query_cases  # noqa: PLC0415
    from soc_ai.tools.query_detections import query_detections  # noqa: PLC0415
    from soc_ai.tools.query_events import query_events_oql  # noqa: PLC0415
    from soc_ai.tools.query_zeek import query_zeek_logs  # noqa: PLC0415
    from soc_ai.tools.web_search import web_search  # noqa: PLC0415

    return {
        "t_enrich_ip": enrich_ip,
        "t_enrich_domain": enrich_domain,
        "t_enrich_hash": enrich_hash,
        "t_query_zeek_logs": query_zeek_logs,
        "t_query_events_oql": query_events_oql,
        "t_query_cases": query_cases,
        "t_query_detections": query_detections,
        "t_get_rule_content": get_rule_content,
        "t_get_event_raw": get_event_raw,
        "t_decode_payload": decode_payload,
        "t_get_playbooks": get_playbooks,
        "t_lookup_runbook": lookup_runbook,
        "t_get_pcap": get_pcap_facts,
        "t_web_search": web_search,
        "t_crawl_page": crawl_page,
    }


async def _dispatch_named_tool(
    tool_name: str,
    tool_args: dict[str, Any],
    ctx: Any,
) -> dict[str, Any]:
    """Validate tool_name against PHASE_D_TOOLS, then invoke it with kwargs."""
    if tool_name not in PHASE_D_TOOLS:
        raise ValueError(f"unknown tool {tool_name!r}")
    # The table's key set == PHASE_D_TOOLS (drift-tested), so this lookup
    # cannot miss for a validated name.
    fn = _dispatch_table()[tool_name]

    # Re-apply the interactive path's per-tool arg ceilings (toolset.py). The
    # tool functions here are called directly, so their wrapper clamps (e.g.
    # max_results=min(..., 25)) don't run — do it before dispatch.
    tool_args = _clamp_arg_ceilings(tool_name, tool_args)

    base_kwargs: dict[str, Any] = {"settings": ctx.settings}
    if tool_name in {"t_enrich_ip", "t_enrich_domain", "t_enrich_hash"}:
        base_kwargs["misp"] = getattr(ctx, "misp", None)
        base_kwargs["blocklist"] = getattr(ctx, "blocklist", None)
        if tool_name == "t_enrich_ip":
            base_kwargs["maxmind"] = getattr(ctx, "maxmind", None)
            base_kwargs["cloud"] = getattr(ctx, "cloud", None)
    elif tool_name in {
        "t_query_zeek_logs",
        "t_query_events_oql",
        "t_query_cases",
        "t_query_detections",
        "t_get_rule_content",
        "t_get_event_raw",
        "t_get_playbooks",
    }:
        base_kwargs["elastic"] = ctx.elastic
        base_kwargs["auth"] = getattr(ctx, "auth", None)
    elif tool_name == "t_lookup_runbook":
        # Operator-runbook search hits the local store, not ES — inject the
        # session factory instead of elastic/auth. ``settings`` is unused by
        # this tool, so drop it too (its signature has no **kwargs).
        base_kwargs = {"db_sessionmaker": getattr(ctx, "db_sessionmaker", None)}
    elif tool_name == "t_get_pcap":
        # get_pcap_facts needs only settings (already in base_kwargs) +
        # alert_ts from the context time anchor.
        base_kwargs["alert_ts"] = getattr(ctx, "default_time_anchor", None)

    # Drop any injected base kwarg the target signature does not accept. The
    # injection tables above are keyed by tool NAME, not by inspecting each
    # signature, so a dependency that only some tools in a family take (e.g.
    # ``auth`` — the SO web-API session — which the ES-query family does NOT
    # accept, they are elastic-only) would otherwise raise an unconditional
    # ``TypeError: unexpected keyword argument`` on every real dispatch. Honor
    # ``**kwargs``: a function that declares VAR_KEYWORD accepts anything.
    _sig = inspect.signature(fn)
    if not any(p.kind == inspect.Parameter.VAR_KEYWORD for p in _sig.parameters.values()):
        base_kwargs = {k: v for k, v in base_kwargs.items() if k in _sig.parameters}

    # Lenient kwarg dispatch. Some reasoning models can hallucinate
    # tool-arg names (e.g. ``'社区ID'``,
    # ``'filter'``, ``'dataset'`` — all observed). Rather than
    # fail-stop the whole Phase D dispatch on the first unknown kwarg,
    # drop the unknown keys and retry once. Honors VAR_KEYWORD if the
    # target function accepts ``**kwargs``.
    try:
        raw = await fn(**tool_args, **base_kwargs)
    except TypeError as exc:
        sig = inspect.signature(fn)
        has_var_keyword = any(
            p.kind == inspect.Parameter.VAR_KEYWORD for p in sig.parameters.values()
        )
        accepted = {n for n in sig.parameters if n not in base_kwargs}
        if has_var_keyword:
            # Function accepts **kwargs — the TypeError must be something
            # else (wrong type for an accepted arg, missing positional).
            _raise_arg_type_error(tool_name, tool_args, exc)
        dropped = sorted(set(tool_args) - accepted)
        if not dropped:
            # No unknown kwargs — the error is a wrong-typed value for a valid
            # kwarg name.  Produce an actionable structured message so synth
            # round 2 can re-call with corrected types instead of silently
            # missing the evidence.
            _raise_arg_type_error(tool_name, tool_args, exc)
        _LOGGER.warning(
            "targeted dispatch on %s: dropping hallucinated kwargs %s and retrying (was: %s)",
            tool_name,
            dropped,
            exc,
        )
        cleaned_args = {k: v for k, v in tool_args.items() if k in accepted}
        try:
            raw = await fn(**cleaned_args, **base_kwargs)
        except TypeError as type_err:
            # Wrong-typed value for a valid kwarg survives the retry.
            # Same structured error path.
            _raise_arg_type_error(tool_name, cleaned_args, type_err)

    if hasattr(raw, "model_dump"):
        # `raw` is a pydantic model here; model_dump(mode="json") yields a dict.
        result = cast("dict[str, Any]", raw.model_dump(mode="json"))
    elif isinstance(raw, dict):
        result = raw
    else:
        result = {"result": raw}
    # Clamp to the per-tool budget, exactly as the interactive wrappers do,
    # before this result is embedded verbatim in the round-2 synth prompt.
    return _clamp_tool_result(result)


__all__ = [
    "build_targeted_investigator_prompt",
    "run_targeted_investigation",
]

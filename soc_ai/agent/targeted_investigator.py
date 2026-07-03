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
from typing import Any, NoReturn, cast

from soc_ai.agent.triage import TargetedGap

_LOGGER = logging.getLogger(__name__)


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


async def _dispatch_named_tool(
    tool_name: str,
    tool_args: dict[str, Any],
    ctx: Any,
) -> dict[str, Any]:
    """Map tool_name → callable; invoke with kwargs. Imported lazily to dodge cycles."""
    from soc_ai.tools.crawl_page import crawl_page  # noqa: PLC0415
    from soc_ai.tools.enrichment import enrich_domain, enrich_hash, enrich_ip  # noqa: PLC0415
    from soc_ai.tools.get_pcap import get_pcap_facts  # noqa: PLC0415
    from soc_ai.tools.get_playbooks import get_playbooks  # noqa: PLC0415
    from soc_ai.tools.lookup_runbook import lookup_runbook  # noqa: PLC0415
    from soc_ai.tools.query_cases import query_cases  # noqa: PLC0415
    from soc_ai.tools.query_detections import query_detections  # noqa: PLC0415
    from soc_ai.tools.query_events import query_events_oql  # noqa: PLC0415
    from soc_ai.tools.query_zeek import query_zeek_logs  # noqa: PLC0415
    from soc_ai.tools.web_search import web_search  # noqa: PLC0415

    dispatch_table: dict[str, Any] = {
        "t_enrich_ip": enrich_ip,
        "t_enrich_domain": enrich_domain,
        "t_enrich_hash": enrich_hash,
        "t_query_zeek_logs": query_zeek_logs,
        "t_query_events_oql": query_events_oql,
        "t_query_cases": query_cases,
        "t_query_detections": query_detections,
        "t_get_playbooks": get_playbooks,
        "t_lookup_runbook": lookup_runbook,
        "t_get_pcap": get_pcap_facts,
        "t_web_search": web_search,
        "t_crawl_page": crawl_page,
    }
    fn = dispatch_table.get(tool_name)
    if fn is None:
        raise ValueError(f"unknown tool {tool_name!r}")

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
        return cast("dict[str, Any]", raw.model_dump(mode="json"))
    if isinstance(raw, dict):
        return raw
    return {"result": raw}


__all__ = [
    "build_targeted_investigator_prompt",
    "run_targeted_investigation",
]

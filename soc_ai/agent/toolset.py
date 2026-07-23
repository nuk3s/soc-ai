"""Single source of truth for the read-tool surface of all three agents.

Every ``t_*`` read tool exposed to the investigator, chat, and hunt agents is
defined ONCE here and registered per-role via :func:`register_read_tools`.
All roles get the investigator's richer wrapping: per-investigation dedup
(:func:`_dedup_result`), result clamping to the tool budget
(:func:`_clamp_tool_result`), and structured error dicts (:func:`_tool_error`).

Role deltas are encoded as module constants (:data:`INVESTIGATOR_ONLY`,
:data:`NOT_ON_HUNT`) plus one def-time default: hunt's query tools default to
a 1440-minute window (a hunt looks across time), investigator/chat to 60 —
and the two windowed query tools carry a role-appropriate window docstring
(the hunt variant does not claim to center on an alert's ``@timestamp``).

Settings-gated tools (the online quartet, PCAP, web search, crawl) are gated
at REGISTRATION time in every role, so a disabled tool never appears in the
LLM's schema and can't burn tool-budget slots on "skipped" results.

``propose_verdict`` is NOT here — it stays in
:mod:`soc_ai.agent.chat_agent`, which owns its ``proposal_sink``.

:data:`PHASE_D_TOOLS` is the single source for the Phase-D targeted-dispatch
surface. ``TargetedGap``'s ``tool_name`` Literal in
:mod:`soc_ai.triage_models` is a drift-tested copy of it (a Literal can't be
built from a runtime tuple without losing the static schema);
``tests/test_toolset.py`` pins the two together.
"""

from __future__ import annotations

import functools
import json
import logging
from collections.abc import Callable
from typing import TYPE_CHECKING, Any, Literal, cast

from pydantic_ai import Agent

from soc_ai.tools.crawl_page import crawl_page
from soc_ai.tools.cvedb import cve_lookup
from soc_ai.tools.decode_payload import decode_payload
from soc_ai.tools.discover import describe_dataset, field_values
from soc_ai.tools.enrichment import enrich_domain, enrich_hash, enrich_ip
from soc_ai.tools.get_event_raw import get_event_raw
from soc_ai.tools.get_pcap import get_pcap_facts
from soc_ai.tools.get_playbooks import get_playbooks
from soc_ai.tools.get_rule_content import get_rule_content
from soc_ai.tools.greynoise import greynoise
from soc_ai.tools.host_summary import host_summary
from soc_ai.tools.lookup_runbook import lookup_runbook
from soc_ai.tools.prevalence import prevalence
from soc_ai.tools.query_cases import query_cases
from soc_ai.tools.query_detections import query_detections
from soc_ai.tools.query_events import query_events_oql
from soc_ai.tools.query_zeek import query_zeek_logs
from soc_ai.tools.rule_prevalence import rule_prevalence
from soc_ai.tools.rule_tuning import suggest_rule_tuning
from soc_ai.tools.shodan_host import shodan_host
from soc_ai.tools.shodan_internetdb import shodan_internetdb
from soc_ai.tools.web_search import web_search

if TYPE_CHECKING:
    from soc_ai.agent.orchestrator import InvestigationContext

_LOGGER = logging.getLogger(__name__)

Role = Literal["investigator", "chat", "hunt"]

# Tools only the investigator gets (verdict-adjacent context the chat/hunt
# surfaces never used).
INVESTIGATOR_ONLY = frozenset({"t_query_detections", "t_get_playbooks", "t_lookup_runbook"})

# Tools every role EXCEPT hunt gets (tuning nominations are per-rule triage
# work, not estate-wide hunting).
NOT_ON_HUNT = frozenset({"t_suggest_rule_tuning"})

# The Phase-D targeted-dispatch surface: the tools a synth round-1
# ``gap_for_investigator`` may name. Single source of truth — TargetedGap's
# ``tool_name`` Literal is a drift-tested copy (tests/test_toolset.py).
PHASE_D_TOOLS: tuple[str, ...] = (
    "t_query_zeek_logs",
    "t_query_events_oql",
    "t_enrich_ip",
    "t_enrich_domain",
    "t_enrich_hash",
    "t_get_playbooks",
    "t_lookup_runbook",
    "t_query_cases",
    "t_query_detections",
    "t_get_rule_content",
    "t_get_event_raw",
    "t_decode_payload",
    "t_get_pcap",
    "t_web_search",
    "t_crawl_page",
)


# Cap on the JSON-serialized size of any single tool return. Both Nemotron 3
# models on the lab grid are deployed with 64K context; a single t_query_*
# call returning 100 zeek/event docs can be 20-40K tokens, and a few of those
# back-to-back blow the window. With this clamp every tool returns at most
# ~3K tokens; the model can call the same tool multiple times if it needs
# more breadth, but no single round-trip can dominate the budget.
_TOOL_RESULT_BUDGET_BYTES = 12 * 1024


def _tool_error(exc: BaseException) -> dict[str, Any]:
    """Render a tool-side exception into a structured result the model can read.

    Tool exceptions used to propagate up and kill the agent run. Now we catch
    them at every tool boundary and surface them as a `{error, type, message}`
    dict — PydanticAI sends that back to the model as a tool result, and the
    model can either retry with corrected args or move on.
    """
    payload: dict[str, Any] = {
        "error": True,
        "type": type(exc).__name__,
        "message": str(exc),
    }
    fragment = getattr(exc, "fragment", None)
    if fragment:
        payload["fragment"] = fragment
    return payload


def _clamp_tool_result[T](value: T) -> T:
    """Truncate ``value`` to the per-tool budget, signaling truncation.

    For list returns: slice items off the end until the JSON serialization
    fits.
    For dict returns whose top-level keys include a list under
    ``hits`` / ``items`` / ``rows`` (the ES-style envelope used by
    :class:`EsSearchResult` and similar): bisect that list to fit the
    budget while preserving the wrapper fields (``total``, ``took_ms``,
    ``aggregations``), and tag the dict with ``__truncated__`` /
    ``__total_items__`` / ``__shown_items__``.
    For other dicts: tag with ``__truncated__`` only — we don't slice
    nested fields (that's domain-specific).
    For primitive / string returns: clip to budget chars and signal.
    """
    try:
        encoded = json.dumps(value)
    except (TypeError, ValueError):
        # Unencodable result — return a stringified form below the budget.
        # Truncation envelopes are always `dict[str, Any]`; cast back to the
        # caller's declared shape (all tool returns accept a dict envelope).
        return cast(
            "T",
            {
                "truncated": True,
                "shown": 0,
                "total": 0,
                "items": [],
                "note": "unencodable result",
            },
        )

    if len(encoded) <= _TOOL_RESULT_BUDGET_BYTES:
        return value

    if isinstance(value, list):
        # Bisect down to a count whose JSON fits.
        lo, hi = 0, len(value)
        # Quick monotone scan: try halves.
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if len(json.dumps(value[:mid])) <= _TOOL_RESULT_BUDGET_BYTES:
                lo = mid
            else:
                hi = mid - 1
        return cast(
            "T",
            {
                "truncated": True,
                "shown": lo,
                "total": len(value),
                "items": value[:lo],
            },
        )
    if isinstance(value, dict):
        # ES-envelope shape: dict with one big list under hits/items/rows.
        # Slice that list so the wrapper (total / took_ms / aggregations)
        # survives but the bulk shrinks under budget. Bisect against the
        # *full* result shape (wrapper + sliced list + metadata flags) so
        # the final encoded size respects the budget.
        for list_key in ("hits", "items", "rows"):
            inner = value.get(list_key)
            if isinstance(inner, list) and inner:

                def _candidate(
                    n: int,
                    key: str = list_key,
                    items: list[Any] = inner,
                ) -> dict[str, Any]:
                    return {
                        **value,
                        key: items[:n],
                        "__truncated__": True,
                        "__total_items__": len(items),
                        "__shown_items__": n,
                        "__total_bytes__": len(encoded),
                    }

                lo, hi = 0, len(inner)
                while lo < hi:
                    mid = (lo + hi + 1) // 2
                    if len(json.dumps(_candidate(mid))) <= _TOOL_RESULT_BUDGET_BYTES:
                        lo = mid
                    else:
                        hi = mid - 1
                return cast("T", _candidate(lo))
        # Aggregation envelope: a `groupby` response carries its big list under
        # aggregations.<name>.buckets (one terms agg per groupby field, nested).
        # Bisect the OUTERMOST buckets list — dropping an outer bucket drops its
        # nested sub-buckets too, so total size shrinks monotonically — until a
        # multi-field groupby fits the budget. Without this, groupby responses
        # fall through to the flag-only fallback below, which relabels the same
        # oversized payload __truncated__ without shrinking it.
        aggs = value.get("aggregations")
        if isinstance(aggs, dict):
            for agg_name, agg_body in aggs.items():
                if (
                    isinstance(agg_body, dict)
                    and isinstance(agg_body.get("buckets"), list)
                    and agg_body["buckets"]
                ):
                    buckets = agg_body["buckets"]

                    def _agg_candidate(
                        n: int,
                        name: str = agg_name,
                        body: dict[str, Any] = agg_body,
                        bkts: list[Any] = buckets,
                    ) -> dict[str, Any]:
                        return {
                            **value,
                            "aggregations": {**aggs, name: {**body, "buckets": bkts[:n]}},
                            "__truncated__": True,
                            "__total_buckets__": len(bkts),
                            "__shown_buckets__": n,
                            "__total_bytes__": len(encoded),
                        }

                    lo, hi = 0, len(buckets)
                    while lo < hi:
                        mid = (lo + hi + 1) // 2
                        if len(json.dumps(_agg_candidate(mid))) <= _TOOL_RESULT_BUDGET_BYTES:
                            lo = mid
                        else:
                            hi = mid - 1
                    return cast("T", _agg_candidate(lo))
        # No recognized list field — fall back to flag-only.
        return cast("T", {**value, "__truncated__": True, "__total_bytes__": len(encoded)})
    # Strings / numbers — stringify + clip.
    text = str(value)
    return cast("T", text[: _TOOL_RESULT_BUDGET_BYTES - 100] + " …[truncated]")


_DUPLICATE_HINT = (
    "Same args were already called this investigation. Result hasn't changed; "
    "calling again wastes the budget. Pivot to a different field, time window, "
    "or tool — or proceed to emitting the transcript."
)


def _dedup_result(
    ctx: InvestigationContext, tool_name: str, args: dict[str, Any]
) -> dict[str, Any] | None:
    """Return a structured duplicate-call payload if this exact call was seen.

    None when not a duplicate. The tool wrappers consult this and
    short-circuit on duplicates rather than running the underlying tool
    again.
    """
    if not ctx.dedup.is_duplicate(tool_name, args):
        return None
    return {
        "duplicate_call": True,
        "tool_name": tool_name,
        "args": args,
        "hint": _DUPLICATE_HINT,
    }


def _guarded[F: Callable[..., Any]](ctx: InvestigationContext, fn: F) -> F:
    """When the ctx carries an EgressGuard, wrap a tool closure so the model
    only ever sees sanitized results, and label-bearing arguments it sends
    back (e.g. query strings citing HOST_01) are restored to real values
    before execution. functools.wraps preserves the signature pydantic-ai
    reads for the tool schema."""
    guard = ctx.egress_guard
    if guard is None:
        # No redaction configured — hand pydantic-ai the original closure so
        # the default path stays byte-identical (no wrapper in the stack).
        return fn

    @functools.wraps(fn)
    async def _wrapped(*args: Any, **kwargs: Any) -> Any:
        # INBOUND (model → tool): the model reasons over opaque labels, so any
        # label it echoes into an argument must become the real value before
        # the tool queries Elasticsearch / enrichment sources.
        real_args = tuple(guard.desanitize_obj(a) for a in args)
        real_kwargs = {k: guard.desanitize_obj(v) for k, v in kwargs.items()}
        result = await fn(*real_args, **real_kwargs)
        # OUTBOUND (tool → model): the result is the egress payload — redact it
        # with the run's shared mapping so labels stay stable across tools.
        return guard.sanitize_obj(result)

    return cast("F", _wrapped)


def _in_role(tool_name: str, role: Role) -> bool:
    """Whether ``tool_name`` belongs to ``role``'s surface (settings gates aside)."""
    if tool_name in INVESTIGATOR_ONLY and role != "investigator":
        return False
    return not (tool_name in NOT_ON_HUNT and role == "hunt")


# Per-role docstrings for the two time-windowed query tools. Only the window
# sentence differs between roles — the investigator/chat window is centered on
# the alert's @timestamp, but a hunt has NO alert to center on (its anchor is
# "now", looking back across time). Everything else in the doc is identical.
_OQL_DOC_BASE = (
    "Run a validated OQL query against the SO events index.\n\n"
    "OQL works across ALL datasets, including RFC1918 addresses; narrow "
    "with `AND event.dataset:...`. "
)
_OQL_ALERT_WINDOW_NOTE = (
    "The window is centered on the alert's `@timestamp` automatically "
    "(without this, tools default to now-1h, return empty for batch "
    "alerts, and burn a wasted round). `time_range_minutes` is the total "
    "window width around that anchor (60 = ±30 min). Pass a larger value "
    "if you need wider context (e.g. 360 = ±3h, 1440 = ±12h)."
)
_OQL_HUNT_WINDOW_NOTE = (
    "The default window is WIDE (1440 = 24h) because a hunt looks across "
    "time rather than pivoting around one alert. `time_range_minutes` is "
    "the total window width; pass a larger value for a broader sweep or a "
    "smaller one to focus on a burst."
)
_ZEEK_DOC_BASE = "Pivot into Zeek logs by network.community_id (conn/dns/http/ssl/files/ssh).\n\n"
_ZEEK_ALERT_WINDOW_NOTE = (
    "Window centered on the alert's `@timestamp`; `time_range_minutes` "
    "is the total width (60 = ±30 min). Widen only if you need "
    "longer-tail correlation."
)
_ZEEK_HUNT_WINDOW_NOTE = (
    "The default window is wide (1440 = 24h) because a hunt looks across "
    "time; `time_range_minutes` is the total width. Narrow it when you "
    "only need the immediate surroundings of one flow."
)


def register_read_tools(  # noqa: PLR0915 - tool registrations are inherently long
    agent: Agent[Any, Any],
    ctx: InvestigationContext,
    *,
    role: Role,
) -> None:
    """Register the full read-tool surface for ``role`` on ``agent``.

    Closures capture ``ctx`` so the LLM-facing tool signatures stay
    semantic-only (no auth/elastic/etc. parameters in the schema). Settings-
    gated tools are skipped entirely when their flag is off, so the model
    never sees a tool it can't use.
    """
    s = ctx.settings
    # Defaults bind at def time, so the LLM-visible schema advertises the
    # role's real window: a hunt looks across time (24h), the investigator
    # and chat pivot around one alert (±30 min).
    default_window = 1440 if role == "hunt" else 60

    def _register[F: Callable[..., Any]](fn: F) -> F:
        # EVERY tool registration routes through the egress guard so a cloud
        # analyst model never sees a raw tool result (and its label-bearing
        # arguments are restored before execution). With no guard on the ctx
        # (the default), _guarded returns fn unchanged and this is exactly
        # agent.tool_plain(fn). The cast mirrors _guarded's: tool_plain hands
        # back the (wrapped) function it was given.
        return cast("F", agent.tool_plain(_guarded(ctx, fn)))

    async def t_query_events_oql(
        query: str,
        time_range_minutes: int = default_window,
        max_results: int = 25,
    ) -> dict[str, Any]:
        # Hard ceiling BEFORE the dedup key — defends the 64K window, and
        # makes max_results=100 and max_results=25 dedup to the same call.
        max_results = min(max_results, 25)
        if dup := _dedup_result(
            ctx,
            "t_query_events_oql",
            {"query": query, "time_range_minutes": time_range_minutes, "max_results": max_results},
        ):
            return dup
        try:
            result = await query_events_oql(
                query,
                elastic=ctx.elastic,
                settings=ctx.settings,
                time_range_minutes=time_range_minutes,
                max_results=max_results,
                time_anchor=ctx.default_time_anchor,
            )
        except Exception as e:
            _LOGGER.warning("t_query_events_oql failed: %s", e)
            return _tool_error(e)
        return _clamp_tool_result(result.model_dump(mode="json"))

    # The docstring is the LLM-visible tool description, so assign the
    # role-appropriate window note BEFORE registering (pydantic_ai captures
    # the doc at registration time).
    t_query_events_oql.__doc__ = _OQL_DOC_BASE + (
        _OQL_HUNT_WINDOW_NOTE if role == "hunt" else _OQL_ALERT_WINDOW_NOTE
    )
    _register(t_query_events_oql)

    async def t_query_zeek_logs(
        community_id: str,
        log_types: list[str] | None = None,
        time_range_minutes: int = default_window,
        max_results: int = 25,
    ) -> list[dict[str, Any]] | dict[str, Any]:
        # Read-prefetch-first rule: if this community_id is
        # already in the prefetched community_id_events, don't re-query.
        if community_id in ctx.prefetched_community_ids:
            return {
                "prefetch_already_has_this": True,
                "community_id": community_id,
                "hint": (
                    "The orchestrator already pre-fetched events sharing this "
                    "community_id; they're in the `community_id_events` block "
                    "of the alert context above. Read those instead of "
                    "re-querying. If you need a wider time window or different "
                    "log_types, call this tool with a different community_id."
                ),
            }
        # Clamp before the dedup key so 100 and 25 dedup to the same call.
        max_results = min(max_results, 25)
        if dup := _dedup_result(
            ctx,
            "t_query_zeek_logs",
            {
                "community_id": community_id,
                "log_types": log_types,
                "time_range_minutes": time_range_minutes,
                "max_results": max_results,
            },
        ):
            return dup
        try:
            zeek_rows = await query_zeek_logs(
                community_id,
                elastic=ctx.elastic,
                settings=ctx.settings,
                log_types=log_types,
                time_range_minutes=time_range_minutes,
                max_results=max_results,
                time_anchor=ctx.default_time_anchor,
            )
        except Exception as e:
            _LOGGER.warning("t_query_zeek_logs failed: %s", e)
            return _tool_error(e)
        return _clamp_tool_result(zeek_rows)

    t_query_zeek_logs.__doc__ = _ZEEK_DOC_BASE + (
        _ZEEK_HUNT_WINDOW_NOTE if role == "hunt" else _ZEEK_ALERT_WINDOW_NOTE
    )
    _register(t_query_zeek_logs)

    @_register
    async def t_describe_dataset(dataset: str) -> dict[str, Any]:
        """Discover the fields POPULATED on a dataset (e.g. `zeek.ssh`, `endpoint`,
        `windows.security`) by sampling its recent docs. Returns each field + an
        example value + coverage. Use this to learn a dataset's schema before
        querying it — works for network AND host datasets."""
        if dup := _dedup_result(ctx, "t_describe_dataset", {"dataset": dataset}):
            return dup
        try:
            result = await describe_dataset(dataset, elastic=ctx.elastic, settings=ctx.settings)
        except Exception as e:
            _LOGGER.warning("t_describe_dataset failed: %s", e)
            return _tool_error(e)
        return _clamp_tool_result(result)

    @_register
    async def t_field_values(
        field: str, dataset: str | None = None, size: int = 25
    ) -> dict[str, Any]:
        """List the top VALUES a field takes (a terms aggregation), optionally within
        one dataset. E.g. what `rule.name`s fire, what `host.name`s exist, what
        `event.dataset`s are present. Use it to see what actually populates a field."""
        # Clamp before the dedup key so over-asked sizes dedup to the same call.
        size = min(size, 50)
        if dup := _dedup_result(
            ctx, "t_field_values", {"field": field, "dataset": dataset, "size": size}
        ):
            return dup
        try:
            result = await field_values(
                field, elastic=ctx.elastic, settings=ctx.settings, dataset=dataset, size=size
            )
        except Exception as e:
            _LOGGER.warning("t_field_values failed: %s", e)
            return _tool_error(e)
        return _clamp_tool_result(result)

    @_register
    async def t_query_cases(
        query: str,
        status: str | None = None,
        max_results: int = 25,
    ) -> list[dict[str, Any]] | dict[str, Any]:
        """Search SOC cases by free-text + optional status filter."""
        max_results = min(max_results, 10)
        if dup := _dedup_result(
            ctx,
            "t_query_cases",
            {"query": query, "status": status, "max_results": max_results},
        ):
            return dup
        try:
            cases = await query_cases(
                query,
                elastic=ctx.elastic,
                settings=ctx.settings,
                status=status,
                max_results=max_results,
            )
        except Exception as e:
            _LOGGER.warning("t_query_cases failed: %s", e)
            return _tool_error(e)
        return _clamp_tool_result([c.model_dump(mode="json") for c in cases])

    if _in_role("t_query_detections", role):

        @_register
        async def t_query_detections(
            query: str, max_results: int = 25
        ) -> list[dict[str, Any]] | dict[str, Any]:
            """Search SOC detection rules by free-text."""
            max_results = min(max_results, 10)
            if dup := _dedup_result(
                ctx, "t_query_detections", {"query": query, "max_results": max_results}
            ):
                return dup
            try:
                dets = await query_detections(
                    query,
                    elastic=ctx.elastic,
                    settings=ctx.settings,
                    max_results=max_results,
                )
            except Exception as e:
                _LOGGER.warning("t_query_detections failed: %s", e)
                return _tool_error(e)
            return _clamp_tool_result([d.model_dump(mode="json") for d in dets])

    @_register
    async def t_get_rule_content(rule_id: str) -> dict[str, Any]:
        """Fetch the FULL RULE TEXT of a detection — what the signature actually
        matches (content strings, ports, dsize, PCRE), not just its name. Pass
        the alert's `rule.uuid` (Suricata SID) or the exact `rule.name`. Read
        this BEFORE trusting a rule label: a loose generic content match is weak
        corroboration; a tight family-specific token match is strong."""
        if dup := _dedup_result(ctx, "t_get_rule_content", {"rule_id": rule_id}):
            return dup
        try:
            rule = await get_rule_content(rule_id, elastic=ctx.elastic, settings=ctx.settings)
        except Exception as e:
            _LOGGER.warning("t_get_rule_content failed: %s", e)
            return _tool_error(e)
        return _clamp_tool_result(rule)

    @_register
    async def t_decode_payload(data: str, encoding: str = "auto") -> dict[str, Any]:
        """Decode payload bytes ALREADY in evidence (Suricata `payload` base64,
        a hex dump, or `payload_printable` text) into concrete facts: printable
        strings, embedded domains/URLs/IPs, entropy, and protocol hints (DNS
        qname / HTTP host / TLS SNI). Local compute, no egress — works even
        after the PCAP ring buffer has rotated. Use it instead of eyeballing
        raw bytes; cite the decoded strings/indicators it returns. Fetch the
        raw bytes first with t_get_event_raw if needed."""
        # No dedup: pure local compute (no remote cost), so a repeat costs nothing.
        try:
            facts = await decode_payload(data, encoding=encoding)
        except Exception as e:
            _LOGGER.warning("t_decode_payload failed: %s", e)
            return _tool_error(e)
        return _clamp_tool_result(facts.model_dump(mode="json"))

    @_register
    async def t_get_event_raw(event_id: str) -> dict[str, Any]:
        """Fetch a single event's full raw _source by ES _id. Use when the
        prefetched context or a pivot summary omitted a field you need (e.g.
        the raw base64 `payload` bytes, all zeek fields, full suricata
        metadata). For host characterisation prefer t_query_events_oql; use
        this for single-event deep-dives."""
        if dup := _dedup_result(ctx, "t_get_event_raw", {"event_id": event_id}):
            return dup
        try:
            raw = await get_event_raw(event_id, elastic=ctx.elastic, settings=ctx.settings)
        except Exception as e:
            _LOGGER.warning("t_get_event_raw failed: %s", e)
            return _tool_error(e)
        return _clamp_tool_result(raw)

    @_register
    async def t_host_summary(ip: str, lookback_hours: int = 24) -> dict[str, Any]:
        """Identify an internal host by IP from Security Onion data.

        Returns its hostname, a device/OS guess PARSED from the host's HTTP
        User-Agents (so an iPhone reads as an iPhone, not a Mac), a
        server-vs-workstation role guess, first/last seen, and its top
        peers/ports/DNS — each with the raw evidence string behind it.

        Call this whenever the verdict depends on WHAT a host is (device type,
        OS, role) rather than inferring identity from a rule label or a UA seen
        in passing. The window is centered on the alert's `@timestamp`.
        """
        if dup := _dedup_result(
            ctx, "t_host_summary", {"ip": ip, "lookback_hours": lookback_hours}
        ):
            return dup
        try:
            result = await host_summary(
                ip,
                elastic=ctx.elastic,
                settings=ctx.settings,
                lookback_hours=lookback_hours,
                time_anchor=ctx.default_time_anchor,
            )
        except Exception as e:
            _LOGGER.warning("t_host_summary failed: %s", e)
            return _tool_error(e)
        return _clamp_tool_result(result)

    @_register
    async def t_prevalence(
        ip: str,
        peer_ip: str | None = None,
        domain: str | None = None,
        lookback_days: int = 90,
    ) -> dict[str, Any]:
        """Has THIS host talked to THIS dest/domain before, and how rare is it?

        Local first-seen / novelty oracle, learned from the events index only
        (no external calls). Pass `peer_ip` to scope to a host pair, `domain`
        to scope to a domain (DNS/SNI/HTTP), or neither to summarize the host's
        overall activity. Returns first/last seen, distinct-day count, an
        `is_novel` flag and a `rarity` label ('first-seen' | 'rare' | 'common').
        """
        if dup := _dedup_result(
            ctx,
            "t_prevalence",
            {
                "ip": ip,
                "peer_ip": peer_ip,
                "domain": domain,
                "lookback_days": lookback_days,
            },
        ):
            return dup
        try:
            result = await prevalence(
                ip,
                elastic=ctx.elastic,
                settings=ctx.settings,
                peer_ip=peer_ip,
                domain=domain,
                lookback_days=lookback_days,
                time_anchor=ctx.default_time_anchor,
            )
        except Exception as e:
            _LOGGER.warning("t_prevalence failed: %s", e)
            return _tool_error(e)
        return _clamp_tool_result(result)

    @_register
    async def t_rule_prevalence(rule_name: str, lookback_days: int = 30) -> dict[str, Any]:
        """Base-rate / noisiness of a Suricata detection rule across the estate.

        Answers whether this rule is NOISY (fires constantly across many hosts —
        so its next firing is likely benign HERE and is weak evidence) or RARE /
        FIRST-SEEN (a firing is notable). Call this whenever the verdict leans on
        a rule label: before trusting the signature name, check whether that
        signature is a constant-firing nuisance on this grid. Returns
        total_fires, distinct src/dest hosts, first/last seen, fires_per_day, and
        a noisiness bucket. READ-ONLY and zero-egress.
        """
        if dup := _dedup_result(
            ctx, "t_rule_prevalence", {"rule_name": rule_name, "lookback_days": lookback_days}
        ):
            return dup
        try:
            result = await rule_prevalence(
                rule_name,
                elastic=ctx.elastic,
                settings=ctx.settings,
                lookback_days=lookback_days,
            )
        except Exception as e:
            _LOGGER.warning("t_rule_prevalence failed: %s", e)
            return _tool_error(e)
        return _clamp_tool_result(result)

    if _in_role("t_suggest_rule_tuning", role):

        @_register
        async def t_suggest_rule_tuning(rule_name: str, lookback_days: int = 7) -> dict[str, Any]:
            """Detection tuning: is this Suricata rule a noisy FP nuisance to mute?

            Answers the operator's tuning question — is this rule mostly-benign noise
            that should be muted / re-tuned, or is it pulling its weight? Returns the
            rule's alert volume, its acknowledged-vs-escalated disposition trend (the
            ES proxy for false-positive vs true-positive), and a mute/monitor/none
            recommendation with a one-line reason. Cite it when a verdict leans on a
            rule label and you want to know whether that signature keeps coming back
            benign here. READ-ONLY — it nominates, it does not change Security Onion.
            """
            if dup := _dedup_result(
                ctx,
                "t_suggest_rule_tuning",
                {"rule_name": rule_name, "lookback_days": lookback_days},
            ):
                return dup
            try:
                result = await suggest_rule_tuning(
                    rule_name,
                    elastic=ctx.elastic,
                    settings=ctx.settings,
                    lookback_days=lookback_days,
                )
            except Exception as e:
                _LOGGER.warning("t_suggest_rule_tuning failed: %s", e)
                return _tool_error(e)
            return _clamp_tool_result(result)

    # The four ONLINE-enrichment tools (Shodan InternetDB / GreyNoise / full
    # Shodan / CVEDB) are only registered when the master egress toggle
    # (`allow_online_enrichment`) is on. Registering them while the toggle is
    # off just invites the model to burn tool-budget slots on "skipped (online
    # enrichment off)" results (observed 4x GreyNoise + 4x Shodan in one run).
    # InternetDB + CVEDB are keyless but still egress, so they sit behind the
    # same toggle. The underlying tool functions keep their own runtime gates.
    if s.allow_online_enrichment:

        @_register
        async def t_shodan_internetdb(ip: str) -> dict[str, Any]:
            """External-asset view of a PUBLIC IP from Shodan InternetDB (free, no key).

            Returns the open ports, software CPEs, reverse-DNS hostnames, tags
            (cdn/cloud/self-signed) and known CVEs Shodan last observed on that
            address. Call it to corroborate WHAT an unknown EXTERNAL IP is — exposed
            service, hosting class, known vulns — when the verdict turns on the
            nature of the public peer.

            ONLINE tool: private/reserved IPs are skipped (never sent off-box).
            Pass a PUBLIC IP only.
            """
            if dup := _dedup_result(ctx, "t_shodan_internetdb", {"ip": ip}):
                return dup
            try:
                result = await shodan_internetdb(ip, settings=ctx.settings)
            except Exception as e:
                _LOGGER.warning("t_shodan_internetdb failed: %s", e)
                return _tool_error(e)
            return _clamp_tool_result(result)

        @_register
        async def t_greynoise(ip: str) -> dict[str, Any]:
            """Look up an EXTERNAL IP in GreyNoise (Community API): is it scanning the
            internet indiscriminately (noise), a known-benign service (riot), and its
            classification.

            Strong fit when the alert involves an unfamiliar external IP and you need
            to know whether it is a mass-scanner / benign crawler (de-escalate) vs. a
            targeted actor. EXTERNAL IPs only — internal/non-routable IPs are skipped.
            ONLINE tool: returns a clean not_configured dict (no I/O) when the API
            key is unset.
            """
            if dup := _dedup_result(ctx, "t_greynoise", {"ip": ip}):
                return dup
            try:
                result = await greynoise(ip, settings=ctx.settings)
            except Exception as e:
                _LOGGER.warning("t_greynoise failed: %s", e)
                return _tool_error(e)
            return _clamp_tool_result(result)

        @_register
        async def t_shodan_host(ip: str) -> dict[str, Any]:
            """FULL Shodan host lookup for a PUBLIC IP (needs the operator's API key).

            Deeper than t_shodan_internetdb: adds the network owner (org/isp/asn),
            geolocation, guessed OS, and the per-service BANNERS Shodan collected
            (product + version + module per open port), plus the union of known
            CVEs. Reach for it when the verdict turns on WHAT an unknown external
            host is actually running and WHO owns it.

            ONLINE tool: returns a clean not_configured dict (no I/O) when
            SHODAN_API_KEY is unset; private/internal IPs are skipped (never
            sent off-box). PUBLIC IPs only.
            """
            if dup := _dedup_result(ctx, "t_shodan_host", {"ip": ip}):
                return dup
            try:
                result = await shodan_host(ip, settings=ctx.settings)
            except Exception as e:
                _LOGGER.warning("t_shodan_host failed: %s", e)
                return _tool_error(e)
            return _clamp_tool_result(result)

        @_register
        async def t_cve_lookup(cve_id: str) -> dict[str, Any]:
            """Score a named CVE via Shodan CVEDB (free, no key): CVSS base score,
            EPSS exploit-probability + ranking, CISA KEV (actively-exploited) flag,
            a short summary and references.

            Call it whenever an alert, rule, or a Shodan host result names a CVE and
            the verdict depends on HOW SEVERE / HOW LIKELY-EXPLOITED it is — KEV or a
            high EPSS argues for escalation; an old, low-EPSS, non-KEV CVE does not.

            ONLINE tool (no API key needed).
            """
            if dup := _dedup_result(ctx, "t_cve_lookup", {"cve_id": cve_id}):
                return dup
            try:
                result = await cve_lookup(cve_id, settings=ctx.settings)
            except Exception as e:
                _LOGGER.warning("t_cve_lookup failed: %s", e)
                return _tool_error(e)
            return _clamp_tool_result(result)

    if s.pcap_enabled:

        @_register
        async def t_get_pcap(
            src_ip: str | None = None,
            dst_ip: str | None = None,
            src_port: int | None = None,
            dst_port: int | None = None,
            window_minutes: int = 2,
        ) -> dict[str, Any]:
            """Fetch + decode the REAL packets for a flow from the Security Onion sensor.

            Returns five-tuples, SNI, DNS qnames, HTTP hosts, connection stats and
            beacon inter-arrival timing decoded from the raw pcap ring buffer.

            BIDIRECTIONAL — the BPF matches packets in BOTH directions between the two
            IPs, so pass BOTH src_ip and dst_ip from the alert; do not pre-decide
            which is client and which is server.

            HEAVIER than Elastic queries — call ONLY when packet-level or
            protocol-level confirmation is the deciding evidence:
            - C2 beacon / exfil (confirm SNI / DNS / periodic inter-arrival)
            - ET MALWARE / TROJAN / EXPLOIT / HUNTING rules (validate the payload)
            - Kerberoast / psexec lateral movement (confirm the wire protocol)

            DO NOT call for clean-internal informational alerts
            (signature_severity=Informational, internal-internal, alert_action=allowed)
            where the prefetch is already sufficient.
            """
            if dup := _dedup_result(
                ctx,
                "t_get_pcap",
                {
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "src_port": src_port,
                    "dst_port": dst_port,
                    "window_minutes": window_minutes,
                },
            ):
                return dup
            try:
                result = await get_pcap_facts(
                    settings=ctx.settings,
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    src_port=src_port,
                    dst_port=dst_port,
                    window_minutes=window_minutes,
                    alert_ts=ctx.default_time_anchor,
                )
            except Exception as e:
                _LOGGER.warning("t_get_pcap failed: %s", e)
                return _tool_error(e)
            if hasattr(result, "model_dump"):
                return _clamp_tool_result(result.model_dump(mode="json"))
            return _clamp_tool_result(result)

    if s.web_search_enabled:

        @_register
        async def t_web_search(query: str) -> dict[str, Any]:
            """Search the web (SearXNG) to research an EXTERNAL indicator.

            Use this to settle "is this domain/IP/host legit or malicious?" with
            outside evidence instead of guessing — e.g. domain reputation, what a
            service is, known-abuse reports. Strong fit for ET INFO/abused-hosting,
            unknown-ASN, newly-seen-domain, and "looks informational but unverified"
            alerts where the operator needs corroboration to agree with the verdict.

            Pass a focused query string, e.g. ``"pushplanet.azurewebsites.net"`` or
            ``"<domain> malware OR phishing"``.

            PRIVACY: the query goes to public search engines via SearXNG. Search
            ONLY external indicators (domains, public IPs, file hashes, URLs). NEVER
            put an internal IP/hostname/username in the query — a query containing an
            internal IP is refused.
            """
            if dup := _dedup_result(ctx, "t_web_search", {"query": query}):
                return dup
            try:
                result = await web_search(query, settings=ctx.settings)
            except Exception as e:
                _LOGGER.warning("t_web_search failed: %s", e)
                return _tool_error(e)
            return _clamp_tool_result(result)

    if s.crawl4ai_enabled:

        @_register
        async def t_crawl_page(url: str) -> dict[str, Any]:
            """Deep-read the full content of an EXTERNAL web page (via crawl4ai).

            Use this AFTER web_search to read a promising result in full when the
            snippet isn't enough — e.g. open the reputation/abuse/threat-intel page
            for a domain or IP and read what it actually says. Returns the page's
            readable content (markdown), title, and a truncation flag.

            Pass a single external URL (typically one returned by web_search).

            SAFETY: crawl4ai fetches the URL server-side, so EXTERNAL URLs ONLY —
            an internal IP/host/localhost is refused (don't be steered into reading
            an internal service).
            """
            if dup := _dedup_result(ctx, "t_crawl_page", {"url": url}):
                return dup
            try:
                result = await crawl_page(url, settings=ctx.settings)
            except Exception as e:
                _LOGGER.warning("t_crawl_page failed: %s", e)
                return _tool_error(e)
            return _clamp_tool_result(result)

    if _in_role("t_get_playbooks", role):

        @_register
        async def t_get_playbooks(
            alert_id: str | None = None,
            max_results: int = 25,
        ) -> list[dict[str, Any]] | dict[str, Any]:
            """Pull playbooks; optionally scoped to a given alert's linked rule."""
            max_results = min(max_results, 10)
            if dup := _dedup_result(
                ctx, "t_get_playbooks", {"alert_id": alert_id, "max_results": max_results}
            ):
                return dup
            try:
                pbs = await get_playbooks(
                    elastic=ctx.elastic,
                    settings=ctx.settings,
                    alert_id=alert_id,
                    max_results=max_results,
                )
            except Exception as e:
                _LOGGER.warning("t_get_playbooks failed: %s", e)
                return _tool_error(e)
            return _clamp_tool_result([p.model_dump(mode="json") for p in pbs])

    @_register
    async def t_enrich_ip(ip: str) -> dict[str, Any]:
        """Local IP enrichment: internal-CIDR check + blocklists + MaxMind
        ASN/Geo + cloud-provider tag + optional MISP lookup."""
        if dup := _dedup_result(ctx, "t_enrich_ip", {"ip": ip}):
            return dup
        try:
            result_obj = await enrich_ip(
                ip,
                settings=ctx.settings,
                misp=ctx.misp,
                blocklist=ctx.blocklist,
                maxmind=ctx.maxmind,
                cloud=ctx.cloud,
            )
            result = result_obj.model_dump(mode="json")
        except Exception as e:
            _LOGGER.warning("t_enrich_ip failed: %s", e)
            return _tool_error(e)
        return _clamp_tool_result(result)

    @_register
    async def t_enrich_domain(domain: str) -> dict[str, Any]:
        """Local domain enrichment (blocklists + optional MISP lookup)."""
        if dup := _dedup_result(ctx, "t_enrich_domain", {"domain": domain}):
            return dup
        try:
            result_obj = await enrich_domain(
                domain, settings=ctx.settings, misp=ctx.misp, blocklist=ctx.blocklist
            )
            result = result_obj.model_dump(mode="json")
        except Exception as e:
            _LOGGER.warning("t_enrich_domain failed: %s", e)
            return _tool_error(e)
        return _clamp_tool_result(result)

    @_register
    async def t_enrich_hash(hash_value: str, algo: str = "sha256") -> dict[str, Any]:
        """Local file-hash enrichment (blocklists + optional MISP lookup)."""
        if dup := _dedup_result(ctx, "t_enrich_hash", {"hash_value": hash_value, "algo": algo}):
            return dup
        try:
            result_obj = await enrich_hash(
                hash_value, algo, settings=ctx.settings, misp=ctx.misp, blocklist=ctx.blocklist
            )
            result = result_obj.model_dump(mode="json")
        except Exception as e:
            _LOGGER.warning("t_enrich_hash failed: %s", e)
            return _tool_error(e)
        return _clamp_tool_result(result)

    if _in_role("t_lookup_runbook", role):

        @_register
        async def t_lookup_runbook(query: str, k: int = 5) -> list[dict[str, Any]] | dict[str, Any]:
            """Search the operator's own runbooks (keyword/tag/rule-linked)."""
            k = min(k, 5)
            if dup := _dedup_result(ctx, "t_lookup_runbook", {"query": query, "k": k}):
                return dup
            try:
                # ctx.settings enables the opt-in semantic tier (rag_embed_model);
                # with the tier unconfigured, retrieval stays 100% local (FTS5).
                rows = await lookup_runbook(
                    query, k=k, db_sessionmaker=ctx.db_sessionmaker, settings=ctx.settings
                )
            except Exception as e:
                _LOGGER.warning("t_lookup_runbook failed: %s", e)
                return _tool_error(e)
            return _clamp_tool_result(rows)

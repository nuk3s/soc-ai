"""``query_events_oql`` tool: validated OQL search against the SO events index.

This is the lowest-friction way for the agent to read events. It parses the OQL
string, validates against the field whitelist, translates to Elasticsearch DSL,
wraps with the requested time-range filter, and dispatches via
:class:`ElasticClient`.

The tool decorator + registration happen in step 5 of the v1 roadmap; this
module exposes a plain ``async def`` so step 5 can wrap it without restructuring.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any, Literal, get_args

from soc_ai.config import Settings
from soc_ai.so_client.elastic import ElasticClient, EsSearchResult
from soc_ai.so_client.oql import (
    Count,
    GroupBy,
    Head,
    ast_to_es_dsl,
    parse_oql,
    validate_oql,
)
from soc_ai.tools._registry import tool
from soc_ai.tools._synth_scope import SynthScope, synth_scope_must_not

# Hard ceiling on the requested window. This is an LLM-callable read tool —
# alert-embedded text is in-scope prompt-injection surface, so an unbounded
# time_range_minutes lets the agent turn a scoped query into a full-history ES
# scan against the same cluster the live SO grid depends on. 43_200m (30 days)
# comfortably covers the widest legitimate window (the eval sampler's default
# is 10_080m = 7 days) while bounding worst-case query cost.
_MAX_TIME_RANGE_MINUTES = 43_200

# Same 2048-char ceiling the HTTP q params enforce. parse_oql is a synchronous
# lark parse; an agent steered into emitting a 30k-term OQL would otherwise burn
# ~1s of event loop here. Bound it before the parse, agent trust boundary or not.
_MAX_OQL_LEN = 2048

# Reserved aggregation names carrying the count's own composition. Prefixed and
# suffixed so no OQL `groupby` can collide: the compiler names its aggs
# `by_<field>` and the field whitelist admits no underscores at the front.
_COMPOSITION_AGG = "__soc_ai_counted_by_dataset__"
_COMPOSITION_FALLBACK_AGG = "__soc_ai_counted_by_event_dataset__"

# The bucket label for documents the chosen field does not name. On a grid
# without data streams `data_stream.dataset` is unmapped and EVERY document
# lands here, which is what makes the fallback necessary rather than optional.
_UNLABELLED = "(no dataset field)"

_COUNTED_NOTE = (
    "total and every bucket doc_count above count DOCUMENTS, not sessions, "
    "connections or hosts. The events index is a superset of every sensor: one "
    "session emits many documents, because a flow record is re-emitted per "
    "interval, so a document count is not a session count. Read by_dataset "
    "before describing this number, and count distinct source.port or "
    "network.community_id if you need sessions."
)


def _composition_aggs() -> dict[str, Any]:
    """Two cheap terms aggs so the count can name the sensors that produced it.

    Both run because neither field is universal. Data-stream deployments
    populate ``data_stream.dataset`` on everything and ``event.dataset`` on only
    some (packetbeat's flow records carry no ``event.dataset`` at all — 348 of
    the 353 documents in the measured defect). Classic-index deployments are the
    other way round. ``_counted_descriptor`` picks whichever named more of them.
    """
    return {
        _COMPOSITION_AGG: {
            "terms": {"field": "data_stream.dataset", "size": 10, "missing": _UNLABELLED}
        },
        _COMPOSITION_FALLBACK_AGG: {
            "terms": {"field": "event.dataset", "size": 10, "missing": _UNLABELLED}
        },
    }


def _pairs(agg: Any) -> list[dict[str, Any]]:
    if not isinstance(agg, dict):
        return []
    buckets = agg.get("buckets")
    if not isinstance(buckets, list):
        return []
    return [
        {"dataset": str(b["key"]), "documents": int(b["doc_count"])}
        for b in buckets
        if isinstance(b, dict) and "key" in b and "doc_count" in b
    ]


def _named(pairs: list[dict[str, Any]]) -> int:
    """Documents this field actually put a name to."""
    return sum(p["documents"] for p in pairs if p["dataset"] != _UNLABELLED)


def _counted_descriptor(
    aggregations: dict[str, Any] | None, index_pattern: str
) -> dict[str, Any] | None:
    """Build the ``counted`` payload and strip the reserved aggs in place.

    Returns ``None`` only when neither reserved agg came back, which means the
    caller did not ask for them or ES declined — the descriptor never guesses.
    """
    if not aggregations:
        return None
    primary = _pairs(aggregations.pop(_COMPOSITION_AGG, None))
    fallback = _pairs(aggregations.pop(_COMPOSITION_FALLBACK_AGG, None))
    if not primary and not fallback:
        return None
    chosen = primary if _named(primary) >= _named(fallback) else fallback
    return {
        "unit": "documents",
        "index_pattern": index_pattern,
        "by_dataset": chosen,
        "note": _COUNTED_NOTE,
    }


WindowMode = Literal["around", "before"]

_AROUND_NOTE = (
    "This window is CENTRED on the alert: half of it is BEFORE the alert and "
    "half AFTER. It is not 'the last {minutes} minutes' — it reaches back only "
    "{half} minutes. For a how-often / how-many-in-the-last-N question, ask "
    "again with window_mode='before', which puts the whole span behind the "
    "alert."
)
_BEFORE_NOTE = (
    "The whole {minutes}-minute span sits BEHIND the alert, ending at its "
    "`@timestamp`. Nothing after the alert is counted."
)
_NOW_NOTE = (
    "Counted back from the query clock, not from an alert. The whole "
    "{minutes}-minute span ends now."
)


def _build_time_filter(
    time_range_minutes: int,
    time_anchor: datetime | None,
    window_mode: WindowMode = "around",
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Build an ES range filter on @timestamp, and a description of it.

    Three shapes, two of them anchored:

    - **around** (the default, and what an alert-anchored caller usually
      wants): ``[anchor - half, anchor + half]`` where ``half`` is half of
      ``time_range_minutes``. This answers "what happened around this alert" —
      the minutes before it are the setup, the minutes after it are what
      followed. Most batch-eval alerts are minutes-to-days old, so a
      now-relative window would return empty and burn retask rounds.
    - **before**: ``[anchor - time_range_minutes, anchor]``. This answers "how
      often does this happen", which is a different question. Under the centred
      window it was silently answered over half the requested span, and for a
      live alert the forward half is empty, so a day's prevalence came back as
      half a day's.
    - **now-relative**: with no anchor there is nothing to centre on, so both
      modes fall back to ``[now - time_range_minutes, now]``. Live-monitoring
      callers (CLI / WebUI) take this path; the orchestrator's tool wrappers
      anchor on the alert.

    The second element is the window descriptor handed back to the caller. A
    count is only meaningful next to the span it was counted over, and the
    reader here has already been observed reporting a half-window figure as a
    full day's.
    """
    if window_mode not in get_args(WindowMode):
        raise ValueError(
            f"window_mode must be one of {sorted(get_args(WindowMode))}, got {window_mode!r}"
        )
    before: int | float
    after: int | float
    if time_anchor is None:
        gte, lte = f"now-{time_range_minutes}m", "now"
        before, after = time_range_minutes, 0
        note = _NOW_NOTE.format(minutes=time_range_minutes)
        mode = "now_relative"
    elif window_mode == "before":
        gte = (time_anchor - timedelta(minutes=time_range_minutes)).isoformat()
        lte = time_anchor.isoformat()
        before, after = time_range_minutes, 0
        note = _BEFORE_NOTE.format(minutes=time_range_minutes)
        mode = "before"
    else:
        half = timedelta(minutes=time_range_minutes / 2)
        gte = (time_anchor - half).isoformat()
        lte = (time_anchor + half).isoformat()
        halved = time_range_minutes / 2
        # An odd request splits into a half-minute; report it as it was applied
        # rather than rounding the descriptor away from the filter.
        before = after = int(halved) if halved.is_integer() else halved
        note = _AROUND_NOTE.format(minutes=time_range_minutes, half=before)
        mode = "around"
    descriptor = {
        "mode": mode,
        "gte": gte,
        "lte": lte,
        "requested_minutes": time_range_minutes,
        "minutes_before_anchor": before,
        "minutes_after_anchor": after,
        "note": note,
    }
    return {"range": {"@timestamp": {"gte": gte, "lte": lte}}}, descriptor


@tool(
    read_only=True,
    description="Run a validated OQL query against the SO events index.",
)
async def query_events_oql(
    query: str,
    *,
    elastic: ElasticClient,
    settings: Settings,
    time_range_minutes: int = 1440,
    max_results: int = 100,
    time_anchor: datetime | None = None,
    window_mode: WindowMode = "around",
    include_synth: SynthScope = False,
) -> EsSearchResult:
    """Run a validated OQL query against ``settings.events_index_pattern``.

    Args:
        query: The OQL query string. May include pipe stages (``groupby``,
            ``sortby``, ``head``, ``count``).
        elastic: An :class:`ElasticClient` for dispatching to the SO ES cluster.
        settings: The application :class:`Settings` (used for the index pattern).
        time_range_minutes: Window size in minutes. Default 1440 = 24h, capped
            at ``_MAX_TIME_RANGE_MINUTES`` (43_200 = 30 days).
        max_results: Hard cap on returned hits (or ``head N`` limit). The
            validator rejects ``head`` stages that exceed this value.
        time_anchor: When set, anchor the window on this timestamp instead of
            the now-relative default. The orchestrator passes
            ``alert.timestamp`` here so batch-eval queries actually find
            evidence; CLI/WebUI callers usually leave it ``None`` for live
            monitoring.
        window_mode: How the window sits on the anchor. ``"around"`` (default)
            centres it, ``[anchor - rng/2, anchor + rng/2]``, which answers
            "what happened around this alert". ``"before"`` puts the whole
            span behind the anchor, ``[anchor - rng, anchor]``, which is what
            "how often in the last N" means. Ignored with no anchor, where the
            window is ``[now - rng, now]`` either way.

    Returns:
        An :class:`EsSearchResult`. For ``groupby`` queries the response holds
        the bucketed aggregation under :attr:`EsSearchResult.aggregations` and
        :attr:`hits` is empty; for plain queries, ``hits`` carries the
        documents and ``aggregations`` is ``None``. :attr:`window` always names
        the span the totals were counted over.
    """
    # Before the cheap-to-fail range checks so a bad mode is reported as a bad
    # mode rather than being masked by whichever other argument is also wrong.
    if window_mode not in get_args(WindowMode):
        raise ValueError(
            f"window_mode must be one of {sorted(get_args(WindowMode))}, got {window_mode!r}"
        )
    if time_range_minutes <= 0:
        raise ValueError(f"time_range_minutes must be positive, got {time_range_minutes}")
    if time_range_minutes > _MAX_TIME_RANGE_MINUTES:
        raise ValueError(
            f"time_range_minutes must be <= {_MAX_TIME_RANGE_MINUTES}, got {time_range_minutes}"
        )

    if len(query) > _MAX_OQL_LEN:
        raise ValueError(f"query must be <= {_MAX_OQL_LEN} chars, got {len(query)}")
    ast = parse_oql(query)
    validate_oql(ast, max_results=max_results)
    body = ast_to_es_dsl(ast, default_size=max_results)

    time_filter, window = _build_time_filter(time_range_minutes, time_anchor, window_mode)
    wrapped_bool: dict[str, Any] = {
        "must": [body["query"]],
        "filter": [time_filter],
    }
    # Synthetic-eval kill-switch: by default, every OQL query excludes docs
    # tagged with synth.scenario_id, so synth-TP fixtures cannot leak
    # into prod responses or the eval sampler's view of "real" alerts.
    # A batch-eval caller passes its scenario id so only that scenario's
    # own plants join the results; the hunt-journey eval passes True.
    if synth_must_not := synth_scope_must_not(include_synth):
        wrapped_bool["must_not"] = synth_must_not
    wrapped_query = {"bool": wrapped_bool}

    # Groupby/Count queries set size=0; preserve that.
    has_aggregating_stage = any(isinstance(s, GroupBy | Count) for s in ast.pipes)
    has_head = any(isinstance(s, Head) for s in ast.pipes)
    effective_size = body.get("size", max_results)
    if not has_aggregating_stage and not has_head:
        effective_size = min(effective_size, max_results)

    # Ask for the composition alongside whatever the model asked for, then hand
    # it back under its own key. The model sees one groupby because it wrote
    # one; the reserved aggs never reach `result.aggregations`.
    aggs: dict[str, Any] = {**(body.get("aggs") or {}), **_composition_aggs()}

    result = await elastic.search(
        settings.events_index_pattern,
        wrapped_query,
        size=effective_size,
        sort=body.get("sort"),
        aggs=aggs,
        track_total_hits=body.get("track_total_hits"),
    )
    result.counted = _counted_descriptor(result.aggregations, settings.events_index_pattern)
    result.window = window
    # A query with no aggregating stage documents `aggregations is None`; the
    # reserved keys must not be what makes it a dict.
    if not result.aggregations:
        result.aggregations = None
    return result

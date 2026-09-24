"""Alerts-console queries: grouped-by-rule aggregation + flat event listing.

All user input (the filter box) goes through the existing OQL trust
boundary (parse → field-whitelist validation) before touching ES; only
the filter part of OQL is accepted here — grouping is built in.
"""

from __future__ import annotations

import asyncio
import ipaddress
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from soc_ai.config import Settings
from soc_ai.errors import OqlValidationError
from soc_ai.so_client.elastic import ElasticClient
from soc_ai.so_client.fields import ENVELOPE_FIELD, envelope
from soc_ai.so_client.oql import filter_to_dsl, parse_oql, validate_oql
from soc_ai.tools._synth_scope import synth_scope_must_not

TIME_RANGES: dict[str, str] = {
    "15m": "now-15m",
    "1h": "now-1h",
    "4h": "now-4h",
    "24h": "now-24h",
    "3d": "now-3d",
    "7d": "now-7d",
    "30d": "now-30d",
}
DEFAULT_RANGE = "24h"
SEVERITIES = ("critical", "high", "medium", "low")
# Selector for an alert whose document carries no ``event.severity_label``.
#
# Deliberately NOT a fifth rung on the ladder. The severity is absent, not low,
# and there is no number to put in its place either. ECS defines
# ``event.severity`` as the source's OWN number, and the three sources measured
# on one grid on 2026-09-06 do not share a scale: Security Onion's Suricata
# pipeline writes 1, 2, 3 alongside the labels low, medium, high (3,907
# documents over 30 days, one number per label, no exceptions); Elastic Defend
# writes 99 out of 100 and no label at all; OpenCanary writes no severity of any
# kind. Reading 99 as a rung would be picking a scale for the shipper, and it
# would still leave the honeypot hits with nothing.
#
# So it gets a value of its own and a query of its own: an absence test, over
# the one field the console reads to display severity. That shared field is what
# keeps the badge on the row and the filter over the queue talking about the
# same documents.
UNKNOWN_SEVERITY = "unknown"
# Everything a caller may select: the four labels, plus the absence of one.
# Together they cover every document the alert feed can return.
SELECTABLE_SEVERITIES = (*SEVERITIES, UNKNOWN_SEVERITY)
GROUP_SORTS = ("count", "latest")
# The ceiling on distinct groups, applied THREE times per page: once to each
# terms aggregation the grid runs (rule.name, the unnamed sibling by dataset,
# and notice.note), and once more to the merged list, which can hold up to
# three times the cap before it is re-cut. Every one of those cuts used to be
# silent, so a queue with more distinct detections than this reported the
# groups that fitted and nothing about the ones that did not — a floor
# rendered as a total. See :class:`GroupPage`.
MAX_GROUPS = 200
EVENTS_PER_GROUP = 50
MAX_EVENTS = 200

# Broaden the triage feed beyond Suricata to SO's other detection
# outputs. These are UNIONED with the configured `webui_alerts_query` (the
# Suricata primary) when `webui_extra_detections` is on. Each source groups by a
# "name" field: Suricata/Sigma carry `rule.name`; Zeek notices carry `notice.note`
# (e.g. "ATTACK::Discovery"), so they get their own aggregation + merge.
SIGMA_SOURCE_OQL = 'event.dataset:"sigma.alert"'
# Only ATTACK::* notices — the behavioral threat notices (e.g. ATTACK::Discovery);
# excludes operational noise (CaptureLoss, cert warnings, dropped packets).
NOTICE_SOURCE_OQL = 'event.dataset:"zeek.notice" AND notice.note:ATTACK*'

# The ways a grid running Security Onion says "this document is an alert". They
# are not interchangeable and no grid carries only one:
#
# * ``tags:alert``       SO's own convention and the base filter of its own
#                        Alerts page. Its ingest pipelines derive the tag from
#                        ``event.dataset`` for Suricata, Sigma/ElastAlert, Wazuh
#                        and Strelka. Its ``/api/events/ack`` endpoint uses it.
# * ``tags:alerts``      The plural. No SO-authored pipeline writes it, but a
#                        live grid carried 22 endpoint alerts under it in 24
#                        hours while the singular found 2. ``tags`` is a keyword
#                        field, so the singular is an exact term match and
#                        misses these entirely. Measured, mechanism unconfirmed,
#                        which is exactly why the doctor check counts the labels
#                        rather than assuming them.
# * ``event.kind:alert`` ECS, the field whose defined purpose is this question.
#                        Elastic Defend endpoint alerts are written by Elastic's
#                        package pipeline, never reach SO's tag-deriving
#                        pipeline, and carry this and no SO tag.
#
# Order matters: it fixes the order the doctor check probes them in, the order
# they appear in its output, and which one a tie recommends.
ALERT_LABEL_CANDIDATES: tuple[str, ...] = ("tags:alert", "tags:alerts", "event.kind:alert")

# Datasets whose index cannot ANSWER "how many of these were acknowledged?".
#
# Elastic Defend writes its alerts to ``.ds-logs-endpoint.alerts-default-*``,
# which Elastic's own package maps ``dynamic: false`` and which does not map
# ``event.acknowledged`` or ``event.escalated``. Security Onion still stamps
# both flags when an analyst acts, so they are present in ``_source`` and
# invisible to every query — including the filter sub-aggregations below.
# Measured on a live SO 3.2.0 grid on 2026-09-06 against a 16-event endpoint
# group: all 16 acknowledged, SO answered 200 each time, and a query for
# ``event.acknowledged:true`` still matched none of them. The write path already
# works around this by reading the flag off each hit
# (:func:`soc_ai.api.webui.routes_alert_actions._scan_group`); a per-group COUNT
# has no such option, because the group can hold thousands of events and the
# console will not page them to draw one chip.
#
# So the count is not zero, it is unanswerable, and the row says so. The mapping
# is the grid's to change; reporting the unanswerable as ``0`` was ours — it put
# "untouched" on a group an analyst had already cleared, every single time.
#
# Keyed on ``event.dataset`` rather than on the index name because the dataset is
# what the rest of this module reasons in, and because a data stream's backing
# index carries a rollover suffix that a prefix match would have to guess at.
# ``event.dataset`` IS mapped on that index (the doctor counts alerts by it on
# this very grid), so the aggregation that decides this can see it.
ACK_BLIND_DATASETS: frozenset[str] = frozenset({"endpoint.alerts"})

# How many distinct datasets a single group is allowed to resolve before the
# answerability question itself goes unanswered. A group is keyed on one rule
# name (or one notice note), and a rule belongs to one detector, so the realistic
# cardinality is 1. The cap exists so that a group which somehow spans more
# cannot silently drop a blind dataset out of the bucket list and read as
# answerable — past the cap the terms aggregation reports the overflow and the
# counts go to "cannot tell" rather than to a number derived from a partial
# enumeration.
_DATASETS_PER_GROUP = 8


def widen_alert_filter(configured: str, addition: str) -> str:
    """The operator's filter ORed with one that finds alerts it misses.

    Every surface that tells an operator to change ``WEBUI_ALERTS_QUERY`` goes
    through here, because the obvious sentence is the wrong one. On a grid
    measured on 2026-09-05 the configured ``tags:alert`` matched 2 documents
    and ``event.kind:alert`` matched 34, with no overlap at all: the 2 carried
    no ``event.kind`` field, and they were that grid's DCSync detections. "Set
    WEBUI_ALERTS_QUERY=event.kind:alert" gets pasted verbatim, and pasting it
    would have hidden them. Advice from a check whose whole job is to catch a
    filter that hides alerts must not be able to hide different ones.

    No parentheses are needed and none are added: ``OR`` is the lowest-
    precedence operator in OQL, so ``a AND b OR c`` already parses as
    ``(a AND b) OR c`` and the result is a superset of ``configured`` whatever
    shape it has. The output is meant to be pasted, so it stays readable and,
    for the common case of two bare labels, comes out identical to the shipped
    default.

    An empty or match-everything ``configured`` has nothing to preserve (the
    feed already sees every document), and an empty ``addition`` nothing to
    add; either way the surviving side is returned unchanged.
    """
    left, right = configured.strip(), addition.strip()
    if not left or left == "*":
        return right
    if not right or left == right:
        return left
    return f"{left} OR {right}"


# The group kind for alerts that carry no rule name. It is a source scope, not
# a detector: every other kind resolves a group's name against a name FIELD
# (rule.name, or notice.note for Zeek notices), and these documents have none,
# so the name on the row is their ``event.dataset`` and the drill-down has to
# be told to read it that way. The SPA posts a group's kind back verbatim when
# it expands or acknowledges the group, which is why this value has to survive
# the frontend coercion in soc_ai/api/webui/_shared.py rather than being an
# internal detail of the aggregation.
UNNAMED_KIND = "unnamed"

# Bucket of last resort for an alert with no rule name AND no dataset. Reads as
# a placeholder rather than a value so nobody searches the grid for it, and the
# drill-down maps it back to "this field is absent" instead of filtering for
# the literal text.
UNKNOWN_DATASET = "(unknown dataset)"

# event.dataset → triage "kind" badge.
_KIND_BY_DATASET = {
    "suricata.alert": "suricata",
    "sigma.alert": "sigma",
    "zeek.notice": "notice",
}


def _kind_for(dataset: str | None) -> str:
    return _KIND_BY_DATASET.get((dataset or "").lower(), "alert")


@dataclass
class AlertGroup:
    rule_name: str
    count: int
    severity: str
    latest_ts: str
    latest_id: str
    kind: str = "suricata"
    # How many of the group's events the grid records as already handled — or
    # None, meaning the grid CANNOT SAY. None is not zero: on an index that does
    # not map the flag (see :data:`ACK_BLIND_DATASETS`) the filter aggregation
    # these come from returns 0 whether the group is untouched or fully cleared,
    # and a chip drawn from that 0 tells an analyst the wrong thing with
    # complete confidence.
    acked_count: int | None = 0
    escalated_count: int | None = 0
    # Representative flow from the group's most-recent event — so the collapsed
    # row can show BOTH hosts (source → destination) without expanding.
    src_ip: str | None = None
    dst_ip: str | None = None


@dataclass(frozen=True)
class GroupPage:
    """One page of grouped rows, and whether it is the whole story.

    ``fetch_groups`` returned ``(groups, total)`` and the console rendered
    "N detections · M events in window" from the rows alone. Both numbers are
    floors the moment a queue holds more distinct detections than
    :data:`MAX_GROUPS`, and nothing said so — an under-report reads exactly
    like a count, which is the harder of the two failures to notice and the
    only one an analyst will act on wrongly.

    ``truncated`` is set by the code that CUT, from the grid's own
    ``sum_other_doc_count`` and from the merged list's own pre-cut length. It
    is never inferred downstream by comparing ``len(groups)`` against a copied
    cap constant: that reads an exactly-full page as a cut one, and goes
    quietly false the day the cap moves. (Same rule the host dossier's
    ``peers_truncated`` follows, for the same reason.)

    ``other_docs`` is how many matched documents live in groups the grid never
    returned — a count from the aggregation, not a guess. Zero with
    ``truncated`` true is a real state and not a contradiction: the merged
    re-cut drops whole rows the grid DID return, and their documents are
    already inside ``total``, so nothing was lost from the denominator.
    """

    groups: list[AlertGroup]
    # Documents the filter matched, from ``track_total_hits`` — the honest
    # denominator, unaffected by any cap.
    total: int
    truncated: bool = False
    other_docs: int = 0


@dataclass
class AlertEvent:
    es_id: str
    timestamp: str
    src: str
    dst: str
    severity: str
    host: str
    src_ip: str | None = None
    dst_ip: str | None = None
    dst_port: int | None = None
    kind: str = "suricata"
    # Address of the machine the detection fired ON (the endpoint agent), for
    # host-shaped detections that observed no network flow. Deliberately separate
    # from src_ip/dst_ip — see :func:`_host_ip`.
    host_ip: str | None = None
    # What the document itself says Security Onion has already done to it. Read
    # from ``_source``, NOT from the ``hide_acked`` query filter, and the two
    # disagree on a real grid: Elastic Defend's endpoint alert index is mapped
    # ``dynamic: false`` without either field, so SO's write lands in
    # ``_source`` where no query can reach it. Anything that must not write to
    # the same event twice has to read it from here.
    #
    # The two are kept apart because they justify different answers. An
    # acknowledged alert was dismissed; an escalated one is on a case, and only
    # the second is a reason to withhold a case. Neither is a complete record:
    # the attach soc-ai performs on ``POST /api/case/events`` writes no flag at
    # all, so a false here means "the grid has nothing to say", not "untouched".
    acknowledged: bool = False
    escalated: bool = False

    @property
    def subject_host(self) -> str | None:
        """The machine name as a KEY component, or None when there is none.

        :attr:`host` is a display field and holds the em-dash placeholder when
        the document named no machine. Keying on that string would cluster every
        host-less alert of a rule under "—" and read as a subject when there is
        none, which is the whole failure the host dimension exists to stop.
        """
        return self.host if self.host and self.host != "—" else None


def _dig(source: Mapping[str, Any], path: str) -> Any:
    """Read a dotted path from an ES _source that may be nested or flat."""
    if path in source:
        return source[path]
    cur: Any = source
    for part in path.split("."):
        if not isinstance(cur, dict):
            return None
        cur = cur.get(part)
    return cur


def _oql_filter_dsl(oql: str) -> dict[str, Any]:
    ast = parse_oql(oql)
    validate_oql(ast)
    return filter_to_dsl(ast.filter_)


# Absolute @timestamp ranges arrive as raw query-param strings and go straight
# into an ES ``range``. Two hazards: a non-ISO value makes ES 400 (which used to
# escape as a 500, since a BadRequestError is an ApiError, not a TransportError),
# and an unbounded span from a stale ``now-100y`` bookmark issues a century-wide
# aggregation across the shared grid — the expensive-query class the OQL
# leading-wildcard rule exists to prevent. Reject non-ISO here (the routes map
# OqlValidationError to 400) and clamp the span to a bounded window.
_MAX_ABS_WINDOW = timedelta(days=366)


def _parse_abs_ts(value: str, *, bound: str) -> datetime:
    """Parse an absolute-range bound, rejecting non-ISO input as OqlValidationError."""
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise OqlValidationError(
            f"{bound} must be an ISO 8601 timestamp (e.g. 2026-08-10T00:00:00Z), got {value!r}",
            fragment=value,
        ) from exc


def build_filter(
    settings: Settings,
    *,
    time_range: str,
    severity: str | None,
    oql: str | None,
    dataset_oqls: list[str] | None = None,
    abs_from: str | None = None,
    abs_to: str | None = None,
    time_zone: str | None = None,
    hide_acked: bool = False,
) -> dict[str, Any]:
    """Build the bool query shared by the grouped and flat views.

    ``dataset_oqls`` is the list of source-scope OQL filters to OR together
    (e.g. the Suricata primary + Sigma); defaults to ``[webui_alerts_query]`` so
    the single-Suricata-source behavior is unchanged. Raises OqlValidationError
    on bad user OQL (including pipe stages — grouping is built into the page).

    When ``abs_from`` and ``abs_to`` are both given they define an absolute
    @timestamp range (interpreted in ``time_zone``); otherwise the ``time_range``
    preset is used.
    """
    must: list[dict[str, Any]] = []
    sources = dataset_oqls if dataset_oqls is not None else [settings.webui_alerts_query]
    source_dsls = [_oql_filter_dsl(s) for s in sources if s.strip() and s.strip() != "*"]
    if len(source_dsls) == 1:
        must.append(source_dsls[0])
    elif source_dsls:
        must.append({"bool": {"should": source_dsls, "minimum_should_match": 1}})
    if oql and oql.strip():
        # Deliberate over-block: rejects "|" even inside quoted values; pipe stages are
        # meaningless here and quoted-pipe rule names are rare. Revisit if it bites.
        if "|" in oql:
            raise OqlValidationError("pipes are not supported here — grouping is built in")
        must.append(_oql_filter_dsl(oql))
    if abs_from and abs_to:
        lo = _parse_abs_ts(abs_from, bound="from")
        hi = _parse_abs_ts(abs_to, bound="to")
        gte, lte = abs_from, abs_to
        # Clamp an oversized span, comparing tz-naive so a mixed-awareness pair
        # (one bound with an offset, one without) can't raise — the guard is a
        # coarse cost ceiling, not a tz-exact computation. Only the lower bound
        # is pulled up; the upper (the analyst's anchor) is preserved.
        if hi.replace(tzinfo=None) - lo.replace(tzinfo=None) > _MAX_ABS_WINDOW:
            gte = (hi - _MAX_ABS_WINDOW).isoformat()
        ts_range: dict[str, Any] = {"gte": gte, "lte": lte}
        if time_zone:
            ts_range["time_zone"] = time_zone
    else:
        ts_range = {"gte": TIME_RANGES.get(time_range, TIME_RANGES[DEFAULT_RANGE])}
    bool_query: dict[str, Any] = {
        "must": must or [{"match_all": {}}],
        "filter": [{"range": {"@timestamp": ts_range}}],
        # Built by the synth-scope module rather than spelt out here. This
        # filter carried its own copy of the exclusion, naming the top-level
        # marker only, and two planted DCSync documents reached the live queue
        # as a critical Sigma detection because SO's pipeline had re-nested the
        # marker one level down. The queue is not a special case of that guard;
        # it is the surface where getting it wrong is most expensive.
        "must_not": list(synth_scope_must_not(False)),
    }
    if severity == UNKNOWN_SEVERITY:
        # An absence, not a value. A term query cannot select a document for a
        # field the document does not have, which is why every per-severity read
        # missed the entire 24 hour queue on the measured grid.
        bool_query["must_not"].append({"exists": {"field": "event.severity_label"}})
    elif severity in SEVERITIES:
        bool_query["filter"].append({"term": {"event.severity_label": severity}})
    if hide_acked:
        bool_query["filter"].append(
            {
                "bool": {
                    "must_not": [
                        {"term": {"event.acknowledged": True}},
                        {"term": {"event.escalated": True}},
                    ]
                }
            }
        )
    return {"bool": bool_query}


# The per-label ``event.dataset`` breakdown rides on the same size=0 searches
# the label counts already run. ``event.dataset`` is the class dimension because
# it is the one the product already treats as the kind of an alert
# (``_KIND_BY_DATASET``, :data:`SIGMA_SOURCE_OQL`, the unnamed-group fallback) and
# the one a narrowed filter is usually written against.
ALERT_CLASS_AGG = "alert_classes"
# Buckets per label. Grids measured so far carry a handful of alert datasets, so
# this is slack rather than a limit. When the grid does cut the list short, the
# caller is told and must not read a missing bucket as an absent class.
_ALERT_CLASS_TERMS_SIZE = 25


@dataclass(frozen=True)
class AlertLabelCount:
    """What one alert label matches: how many documents, and of what classes.

    ``total`` alone cannot express the failure this exists for. A configured
    filter matching 1,441 documents against an alternative's 1,442 is within
    every ratio a check could set, and can still be matching NONE of a whole
    alert class. Measured on a deployed instance on 2026-09-06, where the missing
    class was Security Onion's Sigma engine and its host-behavioural detections
    had never once reached the triage queue.

    ``classes`` maps ``event.dataset`` to a document count, with
    :data:`UNKNOWN_DATASET` standing for the documents carrying no dataset at
    all. ``classes_truncated`` is True when the grid dropped buckets: a class
    absent from a truncated list is not evidence of anything, so a caller
    testing for zero coverage has to stand down.
    """

    total: int
    classes: dict[str, int]
    classes_truncated: bool


async def count_alert_labels(
    elastic: ElasticClient,
    settings: Settings,
    *,
    time_range: str = DEFAULT_RANGE,
    abs_from: str | None = None,
    abs_to: str | None = None,
    time_zone: str | None = None,
) -> dict[str, AlertLabelCount]:
    """What the configured alert filter matches, and what each of
    :data:`ALERT_LABEL_CANDIDATES` would have matched over the same window.

    The configured filter comes first in the returned mapping; the candidates
    follow in their declared order, minus whichever one the operator already
    configured. The counts are the FEED's counts, not an approximation of them:
    every probe goes through :func:`build_filter`, so each carries the same
    synthetic-row exclusion and the same time window the alerts console applies.

    Each probe also breaks its matches down by ``event.dataset``, on the same
    round trip: a size=0 terms aggregation on a keyword field, alongside a count
    the query was already paying for. See :class:`AlertLabelCount` for why the
    totals alone are not enough.

    Raises :class:`OqlValidationError` when the configured filter is not valid
    OQL, the same failure the feed itself hits on every request. Grid failures
    (including :class:`GridPartialResultsError` from a half-read index)
    propagate; a caller that cannot tell an undercount from a real one must not
    grade these numbers.
    """
    labels = [settings.webui_alerts_query.strip()]
    labels += [c for c in ALERT_LABEL_CANDIDATES if c != labels[0]]
    queries = [
        build_filter(
            settings,
            time_range=time_range,
            severity=None,
            oql=None,
            dataset_oqls=[label],
            abs_from=abs_from,
            abs_to=abs_to,
            time_zone=time_zone,
        )
        for label in labels
    ]
    class_agg = {
        ALERT_CLASS_AGG: {
            "terms": {
                "field": "event.dataset",
                "size": _ALERT_CLASS_TERMS_SIZE,
                "missing": UNKNOWN_DATASET,
            }
        }
    }
    results = await asyncio.gather(
        *(
            elastic.search(
                settings.events_index_pattern,
                query,
                size=0,
                aggs=class_agg,
                track_total_hits=True,
            )
            for query in queries
        )
    )
    return dict(zip(labels, (_label_count(r) for r in results), strict=True))


def _label_count(result: Any) -> AlertLabelCount:
    """One search response → :class:`AlertLabelCount`.

    A response with no aggregation block (an older cache, a double that predates
    the breakdown) reads as no classes and NOT truncated: the caller then finds
    no class anywhere and reports no blind spot, rather than inventing one.
    """
    agg = (result.aggregations or {}).get(ALERT_CLASS_AGG) or {}
    buckets = agg.get("buckets") or []
    classes = {str(b["key"]): int(b["doc_count"]) for b in buckets}
    return AlertLabelCount(
        total=result.total,
        classes=classes,
        classes_truncated=bool(agg.get("sum_other_doc_count")),
    )


def _other_docs(terms_agg: dict[str, Any]) -> int:
    """Documents a terms aggregation left out, from its own ``sum_other_doc_count``.

    A count from the aggregation is a fact; one inferred from ``len(buckets)``
    would be a guess that maxes out at whatever ceiling was requested — the
    same rule the hunt executor's truncation count follows.

    Absent means zero, not unknown. Elasticsearch always sends the key on a
    terms aggregation; only a test double or a response with no aggregation
    block can be missing it, and reading that as "something was dropped" would
    put a truncation warning on every screen served by one.
    """
    return int(terms_agg.get("sum_other_doc_count") or 0)


def _bucket_aggs() -> dict[str, Any]:
    """Per-group sub-aggregations: the latest event, and the handled counts.

    ``datasets`` is not displayed anywhere. It exists so the two filter
    aggregations below can be read honestly: they can only speak for documents
    on an index that maps the flag they filter on, and the dataset is what says
    whether the group holds any that do not (:data:`ACK_BLIND_DATASETS`). One
    small terms aggregation per bucket is cheap next to the ``top_hits`` already
    here, and it is the only way to tell a group that nobody has touched from a
    group nobody can ask about.
    """
    return {
        "latest_ts": {"max": {"field": "@timestamp"}},
        "latest": {
            "top_hits": {
                "size": 1,
                "sort": [{"@timestamp": {"order": "desc"}}],
                "_source": [
                    "@timestamp",
                    "event.severity_label",
                    "event.dataset",
                    "source.ip",
                    "destination.ip",
                ],
            }
        },
        "datasets": {
            "terms": {
                "field": "event.dataset",
                "size": _DATASETS_PER_GROUP,
                "missing": UNKNOWN_DATASET,
            }
        },
        "acked": {"filter": {"term": {"event.acknowledged": True}}},
        "escalated": {"filter": {"term": {"event.escalated": True}}},
    }


def _handled_counts_answerable(bucket: dict[str, Any]) -> bool:
    """Whether the acked/escalated filter aggregations can speak for this group.

    False when the group holds documents on a dataset whose index does not map
    the flags, or when the dataset list came back truncated so we cannot rule
    one out.

    A MISSING ``datasets`` aggregation reads as answerable, deliberately — the
    same call this module already makes for the alert-class breakdown
    (:func:`_alert_label_count`): a response with no aggregation block is an
    older cache or a test double, and inventing a blind spot from its absence
    would put "cannot tell" on every group on a grid that answers fine.
    """
    agg = bucket.get("datasets")
    if not isinstance(agg, dict):
        return True
    if agg.get("sum_other_doc_count"):
        return False
    names = {str(b.get("key", "")) for b in (agg.get("buckets") or [])}
    return not (names & ACK_BLIND_DATASETS)


def _group_aggs(
    sort: str, field: str = "rule.name", *, include_unnamed: bool = False
) -> dict[str, Any]:
    """Terms buckets over ``field``, optionally plus the documents that lack it.

    A terms aggregation has nowhere to put a document that does not carry the
    field, so those documents produce no bucket, no row, and no count. Measured
    on 2026-09-06: the shipped filter matched 38 alerts in 24 hours and this
    aggregation could account for 35, because three OpenCanary honeypot alerts
    carry no ``rule.name``. Honeypot hits are the highest-signal alerts on that
    range, and the console's own row count was the only place the loss showed.

    With ``include_unnamed`` a sibling ``unnamed`` filter aggregation picks up
    exactly the documents the terms aggregation cannot see and groups them by
    ``event.dataset``, the most specific thing still true of a document with no
    rule name. ``missing`` covers the document that has no dataset either, so
    the two aggregations together bucket every matched document and the rows on
    screen add up to what the filter matched.

    Off by default, and off for the Zeek notice aggregation: that one scopes to
    ``notice.note:ATTACK*``, so a document without ``notice.note`` cannot be in
    it, and an aggregation that can only ever come back empty is a request
    nobody should pay for.
    """
    order = {"latest_ts": "desc"} if sort == "latest" else {"_count": "desc"}
    aggs: dict[str, Any] = {
        "rules": {
            "terms": {"field": field, "size": MAX_GROUPS, "order": order},
            "aggs": _bucket_aggs(),
        }
    }
    if include_unnamed:
        aggs["unnamed"] = {
            "filter": {"bool": {"must_not": [{"exists": {"field": field}}]}},
            "aggs": {
                "rules": {
                    "terms": {
                        "field": "event.dataset",
                        "size": MAX_GROUPS,
                        "order": order,
                        "missing": UNKNOWN_DATASET,
                    },
                    "aggs": _bucket_aggs(),
                }
            },
        }
    return aggs


def _first_ip(v: Any) -> str | None:
    """ES ``source.ip`` / ``destination.ip`` may be a scalar or a list — take the first."""
    if isinstance(v, list):
        return str(v[0]) if v else None
    return str(v) if v is not None else None


def _own_address(v: Any) -> str | None:
    """Pick the address a host can be reached and pivoted on from its own list.

    ECS ``host.ip`` is every address the machine claims, in whatever order the
    agent enumerated its interfaces. One endpoint on the measured grid reports a
    routable v4, a link-local v6 and two container-bridge addresses. The value
    lands on an alert row as a live pivot to ``/entity/<ip>``, so position zero
    is not good enough: a link-local first entry makes a dead link.

    Only loopback and link-local are skipped, and only when something else is
    on offer. Nothing further is ranked: a bridge address is still an address
    that host answers on, and choosing between a host's real addresses is not a
    decision an alert row has the standing to make.
    """
    if not isinstance(v, list):
        return _first_ip(v)
    for candidate in v:
        try:
            parsed = ipaddress.ip_address(str(candidate))
        except ValueError:
            continue
        if not parsed.is_link_local and not parsed.is_loopback:
            return str(candidate)
    return _first_ip(v)


def _group_from_bucket(bucket: dict[str, Any], *, kind: str | None = None) -> AlertGroup:
    top = bucket.get("latest", {}).get("hits", {}).get("hits", [])
    src = top[0].get("_source", {}) if top else {}
    env = envelope(src)
    # One decision covers both flags: they live in the same mapping and are
    # missing from it together, so a group the grid cannot answer for cannot be
    # answered about either of them.
    answerable = _handled_counts_answerable(bucket)
    return AlertGroup(
        rule_name=str(bucket.get("key", "")),
        count=int(bucket.get("doc_count", 0)),
        severity=str(_dig(src, "event.severity_label") or "unknown").lower(),
        latest_ts=str(_dig(src, "@timestamp") or ""),
        latest_id=str(top[0].get("_id", "")) if top else "",
        kind=kind or _kind_for(_dig(src, "event.dataset")),
        acked_count=int((bucket.get("acked") or {}).get("doc_count", 0)) if answerable else None,
        escalated_count=(
            int((bucket.get("escalated") or {}).get("doc_count", 0)) if answerable else None
        ),
        src_ip=_first_ip(_ev(src, env, "source.ip")),
        dst_ip=_first_ip(_ev(src, env, "destination.ip")),
    )


async def fetch_groups(
    elastic: ElasticClient,
    settings: Settings,
    *,
    time_range: str = DEFAULT_RANGE,
    severity: str | None = None,
    oql: str | None = None,
    sort: str = "count",
    abs_from: str | None = None,
    abs_to: str | None = None,
    time_zone: str | None = None,
    hide_acked: bool = False,
) -> GroupPage:
    """Grouped view. Returns the rows, the matched total, and what was cut.

    Suricata + Sigma group by ``rule.name`` (one aggregation); Zeek ATTACK
    notices group by ``notice.note`` (a second aggregation) since they carry no
    rule.name. The two bucket sets are merged, tagged by ``kind``, re-sorted, and
    capped. Extra (non-Suricata) sources are gated by ``webui_extra_detections``.

    Alerts in scope that carry no ``rule.name`` either (OpenCanary honeypot
    events on the measured range, and anything else a grid ingests without one)
    ride along in aggregation A's ``unnamed`` sibling and come back as rows of
    kind ``unnamed`` named by their dataset. Without it they matched the filter,
    counted toward ``total``, and appeared nowhere: on 2026-09-06 that was 3 of
    38 documents, and the 3 were the honeypot hits.
    """
    sort = sort if sort in GROUP_SORTS else "count"
    idx = settings.events_index_pattern
    extra = settings.webui_extra_detections

    # Aggregation A — rule.name sources: the configured Suricata primary (+ Sigma).
    a_sources = [settings.webui_alerts_query] + ([SIGMA_SOURCE_OQL] if extra else [])
    qa = build_filter(
        settings,
        time_range=time_range,
        severity=severity,
        oql=oql,
        dataset_oqls=a_sources,
        abs_from=abs_from,
        abs_to=abs_to,
        time_zone=time_zone,
        hide_acked=hide_acked,
    )
    ra = await elastic.search(
        idx,
        qa,
        size=0,
        aggs=_group_aggs(sort, include_unnamed=True),
        track_total_hits=True,
    )
    a_aggs = ra.aggregations or {}
    a_rules = a_aggs.get("rules") or {}
    a_buckets = a_rules.get("buckets", [])
    groups: list[AlertGroup] = [_group_from_bucket(b) for b in a_buckets]
    # Same request, sibling aggregation: the matched documents that carry no
    # rule.name, grouped by dataset. Empty on a grid where every alert is
    # named, and no row is invented for an empty bucket set.
    a_unnamed = (a_aggs.get("unnamed") or {}).get("rules") or {}
    unnamed_buckets = a_unnamed.get("buckets", [])
    groups += [_group_from_bucket(b, kind=UNNAMED_KIND) for b in unnamed_buckets]
    total = ra.total
    # What the grid could not return, from its own count. Read here rather than
    # inferred from the bucket lengths, so an aggregation that happens to fill
    # its ceiling exactly is not reported as cut, and the number survives the
    # cap being changed. A response with no aggregation block (an older double)
    # reads as nothing dropped rather than as an unknown.
    other_docs = _other_docs(a_rules) + _other_docs(a_unnamed)

    # Aggregation B — Zeek ATTACK notices (notice.note), if enabled.
    if extra:
        qb = build_filter(
            settings,
            time_range=time_range,
            severity=severity,
            oql=oql,
            dataset_oqls=[NOTICE_SOURCE_OQL],
            abs_from=abs_from,
            abs_to=abs_to,
            time_zone=time_zone,
            hide_acked=hide_acked,
        )
        rb = await elastic.search(
            idx,
            qb,
            size=0,
            aggs=_group_aggs(sort, field="notice.note"),
            track_total_hits=True,
        )
        b_rules = (rb.aggregations or {}).get("rules") or {}
        b_buckets = b_rules.get("buckets", [])
        groups += [_group_from_bucket(b, kind="notice") for b in b_buckets]
        total += rb.total
        other_docs += _other_docs(b_rules)

    # Merge-sort the two source sets the same way the page asked for.
    if sort == "latest":
        groups.sort(key=lambda g: g.latest_ts, reverse=True)
    else:
        groups.sort(key=lambda g: g.count, reverse=True)
    # The THIRD cut, and the only one with no signal from the grid at all: the
    # merged list can hold up to three aggregations' worth of buckets, each
    # already capped, and this trims it back to one cap. Those rows were
    # returned and are being dropped here, so ``other_docs`` says nothing about
    # them — their documents are inside ``total`` either way. Recorded from the
    # PRE-cut length, by the line that does the cutting.
    merge_cut = len(groups) > MAX_GROUPS
    return GroupPage(
        groups=groups[:MAX_GROUPS],
        total=total,
        truncated=bool(other_docs) or merge_cut,
        other_docs=other_docs,
    )


# Host-shaped detections (Sigma process/file rules built from endpoint events)
# carry NO top-level host and NO source/destination: Security Onion nests the
# whole originating endpoint document under `event_data`. The envelope reader
# lives in the so_client field layer so this module and `SoAlert.from_es_hit`
# resolve the same document the same way — they feed two halves of one key (the
# cluster the sweep plans on, and the row the recorder writes), and a reader
# that disagreed with the other would desync them.
#
# ENVELOPE-RELATIVE, i.e. read off the mapping `envelope()` returns rather than
# off the document: where the log ENTERED the grid, which is not necessarily the
# machine the detection fired on. On an agent that ships its own logs the two are
# the same; on a forwarded Windows event log they are not. Kept only as a last
# resort, behind the endpoint's own ``host.ip``, because plenty of documents
# carry it and nothing else.
_NESTED_SHIPPER_IP = "metadata.input.beats.host.ip"

# DOCUMENT-RELATIVE, and therefore an ES field NAME rather than a reader path:
# the endpoint's own nested address, for callers that build a term filter over it
# (`host_activity._detection_scope`). :func:`_host_ip` reaches the same value
# through the envelope reader instead. Spelled once, here, so the two cannot
# drift apart.
NESTED_HOST_IP_FIELD = f"{ENVELOPE_FIELD}.host.ip"


def _ev(source: dict[str, Any], env: Mapping[str, Any], path: str) -> Any:
    """A dotted path off the document, falling back to its ``event_data``
    envelope. Top level wins, matching :meth:`SoAlert.from_es_hit`."""
    value = _dig(source, path)
    return value if value is not None else _dig(env, path)


def _endpoint(value: str | None) -> str:
    """Bare endpoint host/IP for display AND entity pivots — deliberately NO
    port. The frontend appends the destination port once from the separate
    ``dst_port`` field; embedding it here duplicated the render (":8080 :8080")
    and broke the ``/entity/<value>`` pivot, which matches bare IPs/hosts only."""
    return value if value is not None else "—"


def _host_name(source: dict[str, Any], env: Mapping[str, Any]) -> str:
    """Name of the machine a detection fired on, or the "—" placeholder.

    Top-level ``host.name`` WINS where it exists. On Security Onion network-
    sensor docs (Suricata/Zeek) it never does — SO strips the shipper's
    ``host.*`` and the sensor identity rides ``observer.name`` instead
    (verified against the live grid: zero of ~670k suricata.alert docs carry
    ``host.name``) — so those render "—" here. Where it IS present
    (endpoint/syslog/osquery datasets, or a non-SO Filebeat pipeline) it
    names the shipping machine, and the nested endpoint document is only
    consulted when there is no top-level host at all. Without that fallback
    every endpoint/process detection showed "—" — soc-ai could not name the
    machine on exactly the detection class host-log shipping is growing.
    """
    name = _ev(source, env, "host.name")
    return str(name) if name else "—"


def _host_ip(source: dict[str, Any], env: Mapping[str, Any]) -> str | None:
    """Address of the machine a detection fired on (its agent), or None.

    Deliberately NOT folded into ``src_ip``/``dst_ip``. Those two mean FLOW
    endpoints, and they are the cluster key the sweep planner and the
    pair-inheritance lookups key on ``(rule_name, src_ip, dest_ip)``. Putting an
    agent address there would both assert a flow that was never observed and
    desync that key from the investigation the recorder writes for these alerts
    (which carries no flow at all), so a sweep would miss its own prior verdict
    and re-investigate the rule on every pass.

    That reasoning is about the AGENT's address only. ``source.ip`` under the
    envelope is a flow endpoint the sensor actually observed, so it goes where
    flow endpoints go.

    Order matters, and getting it wrong is not cosmetic. The envelope holds the
    machine's own address under ``host.ip`` and the address of whatever shipped
    the log under the beats input metadata, and on a forwarded Windows event log
    those are different machines. Reading only the beats path put the shipper on
    the row: on the range's DCSync detections it showed the log-forwarding host
    where the domain controller belonged, and an investigation pulled a host
    dossier for the shipper believing it had the controller. The name resolver
    above already preferred the endpoint's own field; this one must too, or the
    name and the address on the same row describe two different machines.

    :func:`_own_address`, not :func:`_first_ip`: ``host.ip`` is every address the
    machine claims, and position zero can be a link-local that renders a dead
    ``/entity/<ip>`` pivot.
    """
    return _own_address(_ev(source, env, "host.ip") or _dig(env, _NESTED_SHIPPER_IP))


def _source_acknowledged(source: dict[str, Any]) -> bool:
    """Whether the document says Security Onion already acknowledged it.

    Read from ``_source`` so it still answers on an index that does not map the
    field. Kept separate from :func:`_source_escalated` because the two are
    different sentences to an operator: one alert was dismissed, the other is
    on a case.
    """
    return bool(_dig(source, "event.acknowledged"))


def _source_escalated(source: dict[str, Any]) -> bool:
    """Whether the document says Security Onion already escalated it.

    Security Onion's own console stamps this when an analyst escalates, so it
    is the grid's record of a case that soc-ai may know nothing about.
    """
    return bool(_dig(source, "event.escalated"))


def _group_query(
    settings: Settings,
    *,
    rule_name: str,
    kind: str,
    time_range: str,
    severity: str | None,
    oql: str | None,
    abs_from: str | None,
    abs_to: str | None,
    time_zone: str | None,
    hide_acked: bool,
) -> dict[str, Any]:
    """The bool query for one detection group. ``kind`` selects the source
    scope + the name field: notices filter ``notice.note`` within zeek.notice;
    everything else filters ``rule.name`` within the Suricata/Sigma sources."""
    if kind == "notice":
        dataset_oqls = [NOTICE_SOURCE_OQL]
        name_field = "notice.note"
    else:
        dataset_oqls = [settings.webui_alerts_query]
        if settings.webui_extra_detections:
            dataset_oqls.append(SIGMA_SOURCE_OQL)
        name_field = "rule.name"
    query = build_filter(
        settings,
        time_range=time_range,
        severity=severity,
        oql=oql,
        dataset_oqls=dataset_oqls,
        abs_from=abs_from,
        abs_to=abs_to,
        time_zone=time_zone,
        hide_acked=hide_acked,
    )
    if kind == UNNAMED_KIND:
        # Resolve the row the way its bucket was built: no rule name, and the
        # dataset the row is named after. Filtering rule.name for a dataset
        # string would match nothing and the row would expand empty, which is
        # the same disappearance one level down.
        query["bool"].setdefault("must_not", []).append({"exists": {"field": "rule.name"}})
        if rule_name == UNKNOWN_DATASET:
            query["bool"]["must_not"].append({"exists": {"field": "event.dataset"}})
        else:
            query["bool"]["filter"].append({"term": {"event.dataset": rule_name}})
    else:
        query["bool"]["filter"].append({"term": {name_field: rule_name}})
    return query


async def fetch_group_events(
    elastic: ElasticClient,
    settings: Settings,
    *,
    rule_name: str,
    kind: str = "suricata",
    time_range: str = DEFAULT_RANGE,
    severity: str | None = None,
    oql: str | None = None,
    size: int = EVENTS_PER_GROUP,
    offset: int = 0,
    abs_from: str | None = None,
    abs_to: str | None = None,
    time_zone: str | None = None,
    hide_acked: bool = False,
) -> list[AlertEvent]:
    """Flat event list for one group, newest first. ``kind`` selects the source
    scope + the name field: notices filter ``notice.note`` within zeek.notice;
    ``unnamed`` groups carry no name field at all, so ``rule_name`` is their
    ``event.dataset`` and the scope excludes anything that HAS a rule name;
    everything else filters ``rule.name`` within the Suricata/Sigma sources.

    ``offset`` pages past the first ``offset`` events (for the "load more" view);
    ``size`` is the page size (capped at MAX_EVENTS).

    Pass ``hide_acked=True`` to exclude already-acknowledged/escalated events
    (used by the bulk-ack path so re-running a capped group makes progress).
    That filter only reaches events on an index that maps
    ``event.acknowledged``; :attr:`AlertEvent.acknowledged` and
    :attr:`AlertEvent.escalated` carry what the document itself says, for
    callers that must not write twice."""
    size = min(max(size, 1), MAX_EVENTS)
    offset = max(offset, 0)
    query = _group_query(
        settings,
        rule_name=rule_name,
        kind=kind,
        time_range=time_range,
        severity=severity,
        oql=oql,
        abs_from=abs_from,
        abs_to=abs_to,
        time_zone=time_zone,
        hide_acked=hide_acked,
    )
    result = await elastic.search(
        settings.events_index_pattern,
        query,
        size=size,
        from_=offset,
        sort=[{"@timestamp": {"order": "desc"}}],
    )
    events: list[AlertEvent] = []
    for hit in result.hits:
        source = hit.get("_source", {})
        env = envelope(source)
        src_ip = _first_ip(_ev(source, env, "source.ip"))
        dst_ip = _first_ip(_ev(source, env, "destination.ip"))
        # `_first_ip` is the list-or-scalar narrow, not an address check; a port
        # carries the same Elasticsearch non-guarantee every other field does.
        dst_port_text = _first_ip(_ev(source, env, "destination.port"))
        events.append(
            AlertEvent(
                es_id=str(hit.get("_id", "")),
                timestamp=str(_dig(source, "@timestamp") or ""),
                src=_endpoint(src_ip),
                dst=_endpoint(dst_ip),
                severity=str(_dig(source, "event.severity_label") or "unknown").lower(),
                host=_host_name(source, env),
                src_ip=src_ip,
                dst_ip=dst_ip,
                dst_port=int(dst_port_text) if dst_port_text is not None else None,
                kind=_kind_for(_dig(source, "event.dataset")),
                host_ip=_host_ip(source, env),
                acknowledged=_source_acknowledged(source),
                escalated=_source_escalated(source),
            )
        )
    return events


async def count_group_events(
    elastic: ElasticClient,
    settings: Settings,
    *,
    rule_name: str,
    kind: str = "suricata",
    time_range: str = DEFAULT_RANGE,
    severity: str | None = None,
    oql: str | None = None,
    abs_from: str | None = None,
    abs_to: str | None = None,
    time_zone: str | None = None,
    hide_acked: bool = False,
) -> int:
    """How many events one group holds, under exactly the filters
    :func:`fetch_group_events` would page through.

    Shares :func:`_group_query` with the fetch so the number an operator is told
    is the number the write would land on, rather than a second query that
    could drift away from it.
    """
    query = _group_query(
        settings,
        rule_name=rule_name,
        kind=kind,
        time_range=time_range,
        severity=severity,
        oql=oql,
        abs_from=abs_from,
        abs_to=abs_to,
        time_zone=time_zone,
        hide_acked=hide_acked,
    )
    result = await elastic.search(
        settings.events_index_pattern, query, size=0, track_total_hits=True
    )
    return int(result.total)

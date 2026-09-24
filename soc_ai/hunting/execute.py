"""Run a spec against a grid and turn matching documents into candidates.

Up to three queries, always in this order:

1. **The precondition.** Is this spec able to see anything at all? A DCSync spec
   on a domain controller with Directory Service Access auditing switched off
   returns nothing, and so does a domain controller nobody has attacked. Those
   are opposite facts and reporting them alike is the false all-clear this
   project ranks above any loud error. A spec whose sensor writes only when
   something happens, rather than on a schedule, declares a
   ``precondition_lookback_minutes`` and its precondition is asked over that
   longer window instead: silence from a honeypot is the good outcome, and
   reporting it as a gap is the same error pointed the other way.
2. **The undecided count**, for a spec whose exclusions read a field the grid
   does not always carry. A ``must_not`` needs the field present to mean
   anything, so the compiled detection requires it; that turns every document
   without it into a silent deletion unless something counts them. Windows does
   this inside one dataset and not only across two: it writes no
   ``SubjectUserName`` on a network logon, so a 4624 spec excluding machine
   accounts loses the whole population it is about. Measured on the development
   range over 2026-09-05, that spec matched 5,240 documents before the exclusion
   was made presence-aware and 0 after, with a precondition of 182 saying it
   could see. It reported clean.
3. **The detection**, aggregated by the spec's scope field so one condition
   becomes one candidate rather than one per document.

None of the three runs a model. That is the point: the expensive path is only
reached if something survives.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from soc_ai.config import Settings
from soc_ai.hunting.spec import HuntSpec
from soc_ai.so_client.elastic import ElasticClient, EsSearchResult
from soc_ai.so_client.fields import is_peer_address
from soc_ai.tools._synth_scope import SynthScope

# Per-candidate evidence. Three ids is enough for a human to confirm the finding
# and for the promotion path to pick an anchor; more is context bloat with no
# extra proof.
MAX_SAMPLE_IDS = 3

# How many scope buckets to ask Elasticsearch for. Deliberately NOT the spec's
# ``top_k``: truncating in the query put the cap upstream of the fire-once gate,
# so once ``top_k`` noisy scopes were recorded terminal, a genuinely NEW scope
# ranked below them was cut by the aggregation, never reached the gate, never
# got a state row, and could never be surfaced. The budget belongs in exactly
# one place and that place is the gate, which records what it holds back.
MAX_SCOPE_BUCKETS = 200

# The fields that say which machine a document is about. A hit scoped on an
# account says nothing about a host, so the lead layer cannot join it to the
# host the account touched. These fields carry that join.
RELATED_FIELDS = (
    "host.name",
    "winlog.computer_name",
    "host.ip",
    "source.ip",
    "destination.ip",
)

# How many related hosts one candidate may name. A lead lists them, and a list
# longer than this is a population, not a context.
MAX_RELATED_HOSTS = 8


@dataclass(frozen=True)
class Candidate:
    """One thing the spec found, keyed by the entity it is about."""

    spec_id: str
    scope_key: str
    scope_kind: str
    doc_count: int
    sample_ids: tuple[str, ...]
    anchor_id: str | None
    anchor_index: str | None
    first_seen: str | None
    last_seen: str | None
    # The other machines this candidate's own documents name. Sorted and
    # deduplicated, and never the scope key itself.
    hosts: tuple[str, ...] = ()


@dataclass(frozen=True)
class SpecRun:
    """The outcome of running one spec once.

    ``blind`` is the distinction the precondition exists to draw. When it is
    True the empty ``candidates`` list means "this spec could not see", and any
    caller that renders it as "nothing found" is lying.
    """

    spec_id: str
    since: str
    until: str
    blind: bool
    precondition_docs: int
    matched_docs: int
    candidates: list[Candidate] = field(default_factory=list)
    # Scopes Elasticsearch did not return because the bucket ceiling was hit.
    # A COUNT, read from the terms aggregation's own ``sum_other_doc_count``,
    # never inferred from how many buckets came back.
    truncated_docs: int = 0
    # Documents the detection could not reach a verdict on, because an
    # exclusion reads a field they do not carry. Counted by its own query
    # rather than folded into ``unattributed_docs``: those matched and could
    # not be grouped, these never got as far as matching, and one number
    # covering both would answer neither question.
    undecided_docs: int = 0
    # How many of those documents were missing EACH exclusion field, one pair
    # per field the detection excludes by value, in the spec's own order and
    # including the fields nothing was missing. The undecided query asks for
    # documents missing AT LEAST ONE of those fields, so the total alone cannot
    # say which; a finding composed from the total named every exclusion field
    # and asserted all of them absent, which on a two-exclusion spec was false
    # about every document it described. The counts OVERLAP: a document missing
    # both fields is in both, so they do not sum to ``undecided_docs``.
    #
    # Empty when the grid returned no breakdown, which is not the same as
    # "nothing was missing": the composer then says the weaker true thing
    # rather than naming a field on no evidence.
    undecided_by_field: tuple[tuple[str, int], ...] = ()
    # Documents that matched but produced no scope bucket, computed ONCE against
    # the full candidate set in :func:`run_spec`.
    #
    # Deliberately a stored field rather than a property derived from
    # ``matched_docs - sum(candidate.doc_count)``. The gate removes
    # already-handled candidates from the list while ``matched_docs`` keeps
    # counting their documents, so the derived form reported every suppressed
    # candidate as unattributable and invented a coverage gap on a healthy run.
    unattributed_docs: int = 0
    # Set by the sweep after gating, not by ``run_spec``. Two distinct facts:
    # already surfaced before (no action needed) and never seen but ranked out
    # by budget (will surface later). They were once one field, which made a
    # sweep that held back nothing report that it had.
    gate_already_handled: int = 0
    gate_over_budget: int = 0
    # Also the sweep's, from the same gate call, and the only one of the three
    # that is not about candidates: how many of this spec's visibility gaps the
    # gate CLOSED because the run carried none. Going dark records a hunt and
    # rings the bell; coming back set a timestamp nobody was handed, so a
    # recovery reached no report at all and the only sign of one was an amber
    # marker quietly not being there. Nothing to derive it from either — a
    # recovered sweep and a sweep that was never blind are byte for byte the
    # same run.
    gate_gaps_retired: int = 0
    error: str | None = None
    # How long the run took against the grid, in milliseconds. Set by the
    # sweep, which is the only caller that times it, and carried on the run so
    # the trail row reads it the same way it reads every other column. It is
    # the cost half of an analytic's outcome ledger.
    duration_ms: int = 0
    # Where the precondition's window started. Empty means the run's own
    # ``since``, which is every spec that declares no look-back.
    #
    # Recorded rather than re-derived from the spec when the report is written,
    # because the two can disagree: the catalog file is edited and the trail is
    # not, and a blind report has to name the window that run was blind over.
    precondition_since: str = ""

    @property
    def clean(self) -> bool:
        """Genuinely nothing to report: the spec could see, and saw nothing.

        ``matched_docs == 0`` is part of the definition, not a detail. Without
        it a run that matched twelve documents and bucketed none of them
        reported an all-clear — the invariant this whole module exists to hold,
        broken one property below where the precondition holds it.

        ``undecided_docs == 0`` is the same invariant one step earlier. A
        document an exclusion could not be evaluated against was never given
        the chance to match, so counting only ``matched_docs`` would call the
        run clean over documents nothing looked at.
        """
        return (
            not self.blind
            and not self.candidates
            and self.error is None
            and self.matched_docs == 0
            and self.truncated_docs == 0
            and self.undecided_docs == 0
        )


def _agg_body(spec: HuntSpec) -> dict[str, Any]:
    """Group by scope, newest first, carrying ids and a time span per bucket."""
    return {
        "scopes": {
            "terms": {
                "field": spec.scope_field,
                # A fixed ceiling, NOT the spec's top_k. See MAX_SCOPE_BUCKETS.
                "size": MAX_SCOPE_BUCKETS,
                "order": {"_count": "desc"},
            },
            "aggs": {
                "first_seen": {"min": {"field": "@timestamp"}},
                "last_seen": {"max": {"field": "@timestamp"}},
                "samples": {
                    "top_hits": {
                        "size": MAX_SAMPLE_IDS,
                        "sort": [{"@timestamp": {"order": "desc"}}],
                        # Only the fields that name a machine. A full _source
                        # would carry the whole document into memory for three
                        # values, and _source False carried nothing at all.
                        "_source": list(RELATED_FIELDS),
                    }
                },
            },
        }
    }


# The undecided query's per-field breakdown, named once so the writer and the
# reader of the aggregation cannot drift apart.
_UNDECIDED_AGG = "missing_exclusion_field"


def _undecided_agg(fields: tuple[str, ...]) -> dict[str, Any]:
    """One bucket per exclusion field: how many undecided documents lack it.

    A named ``filters`` aggregation on the query that is already being run, so
    knowing WHICH field went missing costs no extra round trip. It has to be an
    aggregation rather than arithmetic on the total, because a document may
    lack more than one of the fields and the buckets overlap.
    """
    return {
        _UNDECIDED_AGG: {
            "filters": {
                "filters": {f: {"bool": {"must_not": [{"exists": {"field": f}}]}} for f in fields}
            }
        }
    }


def _undecided_by_field(
    fields: tuple[str, ...], aggs: dict[str, Any] | None
) -> tuple[tuple[str, int], ...]:
    """Read the breakdown back, in the spec's field order.

    An answer with no aggregation returns empty rather than a row of zeros:
    "the grid did not tell us" and "nothing was missing that field" are
    different facts, and the second would let a finding call a field present on
    documents nothing counted.
    """
    buckets = ((aggs or {}).get(_UNDECIDED_AGG, {}) or {}).get("buckets", {})
    if not isinstance(buckets, dict) or not buckets:
        return ()
    return tuple((f, int((buckets.get(f) or {}).get("doc_count", 0) or 0)) for f in fields)


def _field_values(source: Any, name: str) -> list[str]:
    """The values of one dotted field, from either shape a hit can carry.

    Elasticsearch returns ``_source`` as the document's own object tree, but a
    flattened mapping and several of this project's fixtures write the dotted
    key itself. Reading only one shape silently returns nothing for the other.
    """
    if not isinstance(source, dict):
        return []
    value: Any = source.get(name)
    if value is None:
        value = source
        for part in name.split("."):
            if not isinstance(value, dict):
                return []
            value = value.get(part)
            if value is None:
                return []
    items = value if isinstance(value, list) else [value]
    return [str(v).strip() for v in items if v is not None and str(v).strip()]


# The fields that describe the machine that logged the document. One document
# names that machine once: the address if it has one, else its name. Without
# this rule one domain controller appeared on a lead three times, as an
# address, an FQDN and a short name.
_LOGGING_HOST_FIELDS = ("host.ip", "host.name", "winlog.computer_name")
# The fields that describe the other end of a conversation the document records.
_PEER_FIELDS = ("source.ip", "destination.ip")


def _related_hosts(hits: list[dict[str, Any]], scope_key: str) -> tuple[str, ...]:
    """The machines these documents name, without the candidate's own key.

    Each document contributes the machine that logged it once, and the peers
    it names. An address that cannot be another machine is dropped: multicast
    and the loopback are the host addressing the segment or itself, and a lead
    that spans 224.0.0.251 spans nothing.
    """
    key = scope_key.casefold()
    found: set[str] = set()
    for hit in hits:
        source = hit.get("_source")
        logging_host: str | None = None
        for name in _LOGGING_HOST_FIELDS:
            values = [
                v for v in _field_values(source, name) if v.casefold() != key and is_peer_address(v)
            ]
            if values:
                logging_host = sorted(values)[0]
                break
        if logging_host is not None:
            found.add(logging_host)
        for name in _PEER_FIELDS:
            for value in _field_values(source, name):
                if value.casefold() == key or not is_peer_address(value):
                    continue
                found.add(value)
    return tuple(sorted(found))[:MAX_RELATED_HOSTS]


def _candidates_from(spec: HuntSpec, aggs: dict[str, Any]) -> tuple[list[Candidate], int]:
    """Every bucket becomes a Candidate. Truncation is the gate's job, not this one.

    Returns the candidates and the count of documents Elasticsearch left out of
    the bucket list, read from ``sum_other_doc_count`` — the same field
    ``tools/analytics.py`` uses for this. A count from the aggregation is a
    fact; one inferred from ``len(buckets)`` would be a guess that maxes out at
    whatever ceiling was requested.
    """
    scopes = aggs.get("scopes", {}) or {}
    buckets = scopes.get("buckets", []) or []
    truncated = int(scopes.get("sum_other_doc_count", 0) or 0)
    out: list[Candidate] = []
    for bucket in buckets:
        hits = bucket.get("samples", {}).get("hits", {}).get("hits", []) or []
        ids = tuple(str(h["_id"]) for h in hits if h.get("_id") is not None)
        out.append(
            Candidate(
                spec_id=spec.id,
                scope_key=str(bucket.get("key", "")),
                scope_kind=spec.scope_kind,
                doc_count=int(bucket.get("doc_count", 0)),
                sample_ids=ids,
                # The anchor is what `promote_finding` resolves a citation to,
                # so it must be a real id in a real index, never synthesised.
                anchor_id=ids[0] if ids else None,
                anchor_index=str(hits[0].get("_index")) if hits else None,
                first_seen=(bucket.get("first_seen") or {}).get("value_as_string"),
                last_seen=(bucket.get("last_seen") or {}).get("value_as_string"),
                hosts=_related_hosts(hits, str(bucket.get("key", ""))),
            )
        )
    return out, truncated


async def run_spec(
    spec: HuntSpec,
    *,
    elastic: ElasticClient,
    settings: Settings,
    since: str,
    until: str,
    include_synth: SynthScope = False,
    extra_replay_tags: tuple[str, ...] = (),
) -> SpecRun:
    """Run one spec. Never raises: a grid error is reported, not propagated.

    A sweep over a catalog must not lose every remaining spec because one of
    them hit a mapping error, and a spec that errored must not be indistinguish-
    able from one that found nothing.
    """
    if spec.evaluator != "match" or spec.detection is None:
        # A ``profile`` spec is answered from an entity's stored baseline by
        # soc_ai.hunting.prior_sweep, not by a search. Every step below reads
        # spec.detection, so without this the caller gets
        # "AttributeError: 'NoneType' object has no attribute
        # 'exclusion_fields'" -- which is what nine priors did to a live
        # spec-sweep on the range before this guard existed.
        return SpecRun(
            spec.id,
            since,
            until,
            False,
            0,
            0,
            error=(
                f"spec {spec.id!r} uses the {spec.evaluator!r} evaluator; it is run by "
                "`soc-ai priors`, not by a catalog sweep"
            ),
        )

    index = settings.events_index_pattern
    kwargs: dict[str, Any] = {
        "include_synth": include_synth,
        "extra_replay_tags": extra_replay_tags,
    }

    # The window the precondition asks about, which is the run's own unless the
    # spec declares a look-back. Taken from the spec's method so the number
    # recorded here and the number compiled into the query cannot drift apart.
    pre_since = spec.precondition_since(since)

    precondition_docs = 0
    if spec.precondition is not None:
        try:
            pre = await elastic.search(
                index,
                spec.to_query(since=since, until=until, precondition=True, **kwargs),
                size=0,
                track_total_hits=True,
                # A spec run is a judgement about ABSENCE, which is the case
                # ElasticClient.search's own contract names: a degraded search
                # returning nothing from the surviving shards is "could not
                # see", never "clean". GridPartialResultsError subclasses
                # TransportError, so the handler below turns it into a reported
                # error rather than a quiet all-clear.
                require_complete=True,
            )
        except Exception as exc:
            return SpecRun(
                spec.id,
                since,
                until,
                False,
                0,
                0,
                error=f"precondition: {exc}",
                precondition_since=pre_since,
            )
        precondition_docs = _total(pre)
        if precondition_docs == 0:
            # Blind. Do NOT run the detection: its empty result would be
            # indistinguishable from a clean one, which is the whole failure
            # this branch exists to prevent.
            return SpecRun(spec.id, since, until, True, 0, 0, precondition_since=pre_since)

    # Before the detection, not after, and for the same reason the precondition
    # runs first: a failure here has to stop the run rather than land beside a
    # bucket list that would read as the whole answer. A spec whose exclusions
    # all read fields its own ``all`` block pins has nothing to ask, and skips
    # the round trip.
    undecided_docs = 0
    undecided_by_field: tuple[tuple[str, int], ...] = ()
    excluded_fields = spec.detection.exclusion_fields()
    if excluded_fields:
        try:
            und = await elastic.search(
                index,
                spec.to_query(since=since, until=until, undecided=True, **kwargs),
                size=0,
                track_total_hits=True,
                aggs=_undecided_agg(excluded_fields),
                require_complete=True,
            )
        except Exception as exc:
            return SpecRun(
                spec.id,
                since,
                until,
                False,
                precondition_docs,
                0,
                error=f"undecided: {exc}",
                precondition_since=pre_since,
            )
        undecided_docs = _total(und)
        undecided_by_field = _undecided_by_field(excluded_fields, und.aggregations)

    try:
        result = await elastic.search(
            index,
            spec.to_query(since=since, until=until, **kwargs),
            size=0,
            track_total_hits=True,
            aggs=_agg_body(spec),
            require_complete=True,
        )
    except Exception as exc:
        return SpecRun(
            spec.id,
            since,
            until,
            False,
            precondition_docs,
            0,
            error=f"detection: {exc}",
            precondition_since=pre_since,
            undecided_docs=undecided_docs,
            undecided_by_field=undecided_by_field,
        )

    candidates, truncated = _candidates_from(spec, result.aggregations or {})
    matched = _total(result)
    # Non-zero means the detection is right and the GROUPING is not: the scope
    # field is absent or unmapped on those documents. The DCSync event whose
    # subject principal cannot be attributed is exactly the one worth reading,
    # so it can never be folded into silence.
    unattributed = max(0, matched - sum(c.doc_count for c in candidates) - truncated)
    return SpecRun(
        spec_id=spec.id,
        since=since,
        until=until,
        blind=False,
        precondition_docs=precondition_docs,
        matched_docs=matched,
        candidates=candidates,
        truncated_docs=truncated,
        unattributed_docs=unattributed,
        undecided_docs=undecided_docs,
        undecided_by_field=undecided_by_field,
        precondition_since=pre_since,
    )


def _total(result: EsSearchResult) -> int:
    """Document count. ``EsSearchResult.total`` is already a plain int.

    Note that with ``track_total_hits=True`` it is exact; the per-scope counts
    on the buckets always are, so a candidate's ``doc_count`` never needs the
    ``total_is_lower_bound`` caveat even when the run-level total would.
    """
    return result.total


__all__ = [
    "MAX_RELATED_HOSTS",
    "MAX_SAMPLE_IDS",
    "RELATED_FIELDS",
    "Candidate",
    "SpecRun",
    "run_spec",
]

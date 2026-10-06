"""Run every role prior against every entity that has a profile.

This is the piece that turns a stored baseline into something an analyst can
read. For each ``profile`` spec in the catalog it reads a RECENT window of the
spec's dimension, compares it against each entity's stored baseline, and
reports what departed.

**The recent window and the baseline window are different questions.** The
baseline asks "what is ordinary for this entity", over thirty days. The recent
window asks "what did it do lately", over a day. Running both over the same
window guarantees the answer is empty — everything observed is by definition in
the baseline that was built from it.

**A role the dossier is unsure about makes the prior blind, not quiet.** That
inversion lives in :func:`soc_ai.hunting.priors.evaluate_prior`; this module's
job is to hand it the role and confidence the dossier actually holds, including
when it holds nothing.

**Coverage is reported alongside findings, not instead of them.** A sweep that
returns no departures has to be able to say whether that is because nothing
departed or because nothing could be measured, and those numbers are carried
separately all the way out.
"""

from __future__ import annotations

import ipaddress
import logging
from collections import Counter
from collections.abc import AsyncIterator, Sequence
from dataclasses import dataclass
from dataclasses import field as dc_field
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from soc_ai.dossier.profile import (
    _CATEGORICAL,
    _SHAPED,
    _SHAPED_CANDIDATES,
    _SHAPED_ENTITY_FIELD,
    _SHAPED_PROBE_FIELD,
    _dataset_clause,
    _direction_for,
    _member_days,
    _member_peers,
    _nested_terms,
    _outside_the_estate,
    _peer_field,
    _port_bound,
    _scope_must_not,
    _window_filter,
    member_alternates,
    member_buckets,
    member_exists_clause,
    member_transport,
    resolve_plane,
)
from soc_ai.dossier.profile_math import GUARDED_PORT_DIMENSIONS
from soc_ai.enrichment.discovery import _is_internal_ip, _is_ip_literal
from soc_ai.hunting.detectors.base import DetectorContext
from soc_ai.hunting.estate import (
    DEFAULT_COMMON_SHARE,
    DEFAULT_RARE_HOSTS,
    PREVALENCE_DIMENSIONS,
    SCOPE_MIN_HOSTS,
    EstateView,
    LearnedPeers,
    PeerView,
    confirmed_windows,
    ensure_estate,
    peer_profiles,
    peer_source,
    prevalence_for,
    profiled_hosts,
    windows_for,
)
from soc_ai.hunting.leads import (
    MAX_DOCUMENT_IDS,
    LeadOutcome,
    content_fingerprint,
    form_leads,
    purge_out_of_scope_observations,
    record_observation,
)
from soc_ai.hunting.model import record_model_hits, run_model_specs
from soc_ai.hunting.priors import (
    COVERAGE_BLIND,
    COVERAGE_LEARNING,
    COVERAGE_MEASURED,
    COVERAGE_NOT_APPLICABLE,
    PriorResult,
    _blank,
    evaluate_prior,
    known_members,
)
from soc_ai.hunting.receipts import build_receipts
from soc_ai.hunting.rerun import rerun_query
from soc_ai.hunting.roles import name_keys, role_for, roles
from soc_ai.hunting.spec import CATALOG_DIR, HuntSpec, load_catalog
from soc_ai.hunting.weight import Kind, novelty_weight
from soc_ai.hunting.wording import (
    baseline_sentence,
    noun,
    phrase,
    scope_sentence,
    times,
    when,
)
from soc_ai.so_client.paging import CompositeRead
from soc_ai.store import entity_profiles as ep
from soc_ai.store.models import EntityProfile, HostDossier

if TYPE_CHECKING:
    from soc_ai.hunting.catalog_tiers import Catalog

__all__ = ["PriorSweep", "ProfileState", "blind_reasons", "run_prior_sweep"]

# The role reader moved to soc_ai.hunting.roles, so the estate refresh and the
# peer groups read the same map. The catalog sweep and the tests import these
# names from here.
_name_keys = name_keys
_role_for = role_for
_roles = roles

_LOGGER = logging.getLogger(__name__)

# Re-exported. The number lives in soc_ai.hunting.window; the CLI and the
# tests import it from here.
from soc_ai.hunting.window import DEFAULT_RECENT_HOURS  # noqa: E402 - re-export beside its use

# How many documents the recent read keeps per member. Three is enough for an
# analyst to read the condition and cheap enough to ask for on every bucket.
SAMPLE_IDS_PER_MEMBER = 3


def _samples_agg() -> dict[str, Any]:
    """Up to three document ids per bucket, with no document bodies, newest first.

    ``_source: false`` because the id is the whole point. The observation cites
    the document and the hunt reads it with ``get_event_raw``; carrying the
    bodies back would multiply the response for a field no caller here reads.

    Newest first, because the sample is what tells a new sighting from a
    re-read. Unsorted, Elasticsearch returns the same three oldest documents
    on every sweep while they sit in the window, and a port a hundred new
    machines reached today would cite the same three ids it cited yesterday.
    """
    return {
        "top_hits": {
            "size": SAMPLE_IDS_PER_MEMBER,
            "_source": False,
            "sort": [{"@timestamp": {"order": "desc"}}],
        }
    }


def _hit_ids(bucket: Any) -> list[str]:
    """The document ids in a bucket's ``samples`` sub-aggregation."""
    samples = bucket.get("samples") if isinstance(bucket, dict) else None
    hits = samples.get("hits") if isinstance(samples, dict) else None
    rows = hits.get("hits") if isinstance(hits, dict) else None
    out: list[str] = []
    for hit in rows or ():
        if isinstance(hit, dict) and hit.get("_id"):
            out.append(str(hit["_id"]))
    return out


def _sort_stamp(hit: Any) -> datetime | None:
    """The ``@timestamp`` a sampled hit was sorted on, as an aware datetime.

    The samples sort on ``@timestamp``, so Elasticsearch returns each hit's
    timestamp as its sort value: epoch milliseconds for a date field. Reading
    it costs no ``_source`` and no search.
    """
    sort = hit.get("sort") if isinstance(hit, dict) else None
    if not isinstance(sort, list) or not sort:
        return None
    raw = sort[0]
    if isinstance(raw, bool):
        return None
    if isinstance(raw, (int, float)):
        try:
            return datetime.fromtimestamp(float(raw) / 1000.0, tz=UTC)
        except (OverflowError, OSError, ValueError):
            return None
    return _stamp_of(raw)


def _hit_newest(bucket: Any) -> str | None:
    """The newest document time in a bucket's ``samples``, as ISO 8601 UTC.

    This is the event time the observation decays from. ``born_at`` is the
    time soc-ai wrote the row, and an event a day old read as fresh on the
    sweep that found it.
    """
    samples = bucket.get("samples") if isinstance(bucket, dict) else None
    hits = samples.get("hits") if isinstance(samples, dict) else None
    rows = hits.get("hits") if isinstance(hits, dict) else None
    stamps = [s for s in (_sort_stamp(hit) for hit in rows or ()) if s is not None]
    return max(stamps).astimezone(UTC).isoformat() if stamps else None


def _newer(current: str | None, candidate: str | None) -> str | None:
    """The later of two ISO stamps from :func:`_hit_newest`. Either may be None."""
    if candidate is None:
        return current
    if current is None:
        return candidate
    a, b = _stamp_of(current), _stamp_of(candidate)
    if a is None:
        return candidate
    if b is None:
        return current
    return candidate if b > a else current


def _keep_ids(into: list[str], ids: Sequence[str]) -> None:
    """Add ids to a bucket's sample, up to the cap, without repeating one.

    A shaped dimension reads several hourly buckets into one member, so the
    ids arrive in instalments and the cap has to hold across all of them.
    """
    for one in ids:
        if len(into) >= SAMPLE_IDS_PER_MEMBER:
            return
        if one not in into:
            into.append(one)


def _recent_terms(
    *,
    entity_field: str,
    member_field: str,
    peer_field: str | None = None,
    also: tuple[str, ...] = (),
) -> dict[str, Any]:
    """The baseline's member aggregation, plus the documents behind each member.

    The sample rides on the RECENT read only. Both reads carry the same bucket
    caps, but the baseline fills them over thirty days: three hits under every
    leaf of five hundred entities and two hundred members each is a hundred
    thousand documents fetched to describe what is ordinary. What is ordinary
    needs no citation. A departure from it does, and a day fills far fewer
    buckets than a month.

    ``peer_field`` is the one the baseline used. The guard reads peers and
    days from both sides of the comparison.
    """
    body = _nested_terms(
        entity_field=entity_field, member_field=member_field, peer_field=peer_field, also=also
    )
    # Every member aggregation carries the sample, the alternate fields too.
    for key, node in body["aggs"].items():
        if key == "members" or key.startswith("members_alt_"):
            node["aggs"] = {**node["aggs"], "samples": _samples_agg()}
    return body


@dataclass(frozen=True)
class PriorSweep:
    """Everything one prior sweep concluded."""

    results: tuple[PriorResult, ...] = ()
    errors: tuple[str, ...] = ()
    notes: tuple[str, ...] = ()
    leads: LeadOutcome | None = None
    # Every profile spec this run considered, including ones with nothing to
    # score. The trail needs it: a spec absent from results is otherwise
    # indistinguishable from one that was never run.
    evaluated_specs: tuple[str, ...] = ()
    # The window the recent read covered, so the rendering can state it.
    recent_hours: int = DEFAULT_RECENT_HOURS

    @property
    def fired(self) -> tuple[PriorResult, ...]:
        return tuple(r for r in self.results if r.fired)

    @property
    def dropped(self) -> int:
        """Detector hits dropped because they cited no document."""
        return sum(r.dropped for r in self.results)

    def blind_reasons(self) -> dict[str, str]:
        """Why each spec was blind, keyed by spec. See :func:`blind_reasons`."""
        return blind_reasons(self.results)

    def coverage_counts(self) -> dict[str, int]:
        """How many (spec, entity) pairs landed in each coverage state.

        Reported next to the findings rather than instead of them: "nothing
        departed" and "nothing could be measured" are the same empty list and
        completely different answers.

        The four states of the trail. A detector state outside them folds as
        the trail folds it: ``held`` is measured, and ``unmeasurable``,
        ``stale`` and ``drifted`` are blind. Counted under its own name, an
        unmeasurable entity was a fifth column in ``soc-ai priors``. The
        journal then said 33 blind where the store and the ledger said 35.
        The sweep notes keep the count of each detector state.
        """
        counts: dict[str, int] = {
            COVERAGE_MEASURED: 0,
            COVERAGE_LEARNING: 0,
            COVERAGE_BLIND: 0,
            COVERAGE_NOT_APPLICABLE: 0,
        }
        for result in self.results:
            counts[result.trail_state] = counts.get(result.trail_state, 0) + 1
        return counts


# The longest blind reason the trail stores. The column holds 255 characters.
_REASON_CHARS = 255


def blind_reasons(results: Sequence[PriorResult]) -> dict[str, str]:
    """Why the blind entities of each spec were blind, keyed by spec.

    The note of the most blind entities of the spec, after their count and
    the count of all its blind entities: "35 of 56 blind hosts: <note>". The
    count is there when every blind entity shares the note too, so each
    reason on the console reads the same way. A spec with no blind entity, or
    none with a note, has no entry.

    The count said "blind=8" and nothing more. The evaluator had written the
    reason on each of the eight results: the stored baseline held no hourly
    series, and the next build would write one. No surface showed it, so the
    two rate analytics were blind for 19 hours with no reason anywhere.
    """
    kinds: dict[str, set[str]] = {}
    for result in results:
        if result.trail_state == COVERAGE_BLIND:
            kinds.setdefault(result.spec_id, set()).add(result.entity_kind)
    return {
        spec_id: f"{count} of {_blind_entities(total, kinds.get(spec_id, set()))}: {reason}"
        for spec_id, (reason, count, total) in _most_common_reasons(results).items()
    }


# The noun for a blind entity of one kind. The profile sweep reads hosts, so
# "35 of 56 blind entities" named a host by the word of the data model.
_KIND_NOUNS: dict[str, tuple[str, str]] = {
    "host": ("host", "hosts"),
    "user": ("user", "users"),
    "ip": ("IP address", "IP addresses"),
}


def _blind_entities(total: int, kinds: set[str]) -> str:
    """The blind count with its noun: "56 blind hosts".

    The noun is the one kind the blind entities share. Mixed kinds, or a kind
    with no noun here, read "entities".
    """
    (kind,) = kinds if len(kinds) == 1 else ("",)
    one, many = _KIND_NOUNS.get(kind, ("entity", "entities"))
    return f"{total} blind {one if total == 1 else many}"


def _most_common_reasons(results: Sequence[PriorResult]) -> dict[str, tuple[str, int, int]]:
    """Per spec: the most common blind note, how many blind entities carry it, and the total."""
    blind: Counter[str] = Counter()
    notes: dict[str, Counter[str]] = {}
    for result in results:
        if result.trail_state != COVERAGE_BLIND:
            continue
        blind[result.spec_id] += 1
        note = (result.note or "").strip()
        if note:
            notes.setdefault(result.spec_id, Counter())[note] += 1
    out: dict[str, tuple[str, int, int]] = {}
    for spec_id, counted in notes.items():
        reason, count = counted.most_common(1)[0]
        out[spec_id] = (reason, count, blind[spec_id])
    return out


def _blind_notes(results: Sequence[PriorResult]) -> dict[str, str]:
    """The sweep note for each spec that measured no entity and was blind for a reason.

    One note per spec, keyed by spec: the spec and its blind reason. The
    reason states the blind count, so the note does not state it twice. A
    spec that measured at least one entity gets no note: its row still
    carries the reason.
    """
    measured = {r.spec_id for r in results if r.trail_state == COVERAGE_MEASURED}
    return {
        spec_id: f"{spec_id}: {reason}"
        for spec_id, reason in blind_reasons(results).items()
        if spec_id not in measured
    }


# The blind reason this process last wrote to the log, per spec. The sweep
# runs every hour, and a blind analytic stays blind for days. One line per
# change keeps the reason in the journal without a line per spec each hour.
_LOGGED_BLIND: dict[str, str] = {}


def _log_blind(notes: dict[str, str], reasons: dict[str, str]) -> None:
    """Log the blind note of each spec whose reason changed since the last log.

    ``reasons`` holds the reason alone, with no count. A count that moves
    from one sweep to the next writes no new line.
    """
    for spec_id in list(_LOGGED_BLIND):
        if spec_id not in notes:
            del _LOGGED_BLIND[spec_id]
    for spec_id, note in sorted(notes.items()):
        reason = reasons.get(spec_id, "")
        if _LOGGED_BLIND.get(spec_id) == reason:
            continue
        _LOGGED_BLIND[spec_id] = reason
        _LOGGER.info("prior sweep: %s", note)


def clip_reason(reason: str | None) -> str | None:
    """A reason cut to the length the trail column holds. None for nothing."""
    if not reason:
        return None
    if len(reason) <= _REASON_CHARS:
        return reason
    return reason[: _REASON_CHARS - 3] + "..."


@dataclass(frozen=True)
class ProfileState:
    """What the caller knew about the baselines when the sweep ran.

    ``built_at`` is the newest ``entity_profiles.built_at``; ``stale`` is the
    caller's verdict on it; ``reason`` is why a dimension could not be
    measured, when one could not. Recorded on the trail so the panel can say
    "baseline 26 h old" next to a coverage count instead of implying now.
    """

    built_at: datetime | None = None
    stale: bool = False
    reason: str | None = None


def _dimension_spec(dimension: str) -> tuple[tuple[str, ...], str, str, str] | None:
    """The (candidates, probe_field, entity_field, member_field) for a dimension.

    The first member is the candidate DATASET LIST, not one name. The return
    type said ``tuple[str, ...]`` and silenced the mismatch, so every caller
    unpacked the list as a string and handed it to ``resolve_plane``, which
    asks for a tuple of datasets.
    """
    for name, candidates, probe, entity_field, member_field in _CATEGORICAL:
        if name == dimension:
            return (candidates, probe, entity_field, member_field)
    return None


# How many entities one recent read holds, and how many one page of it holds.
# The read pages a composite aggregation over the entity field, in key order,
# until the plane has no more entities or the read holds the ceiling. A single
# terms read held the busiest 500. On an estate past that a quiet host never
# reached the answer, so absence could not be read as silence. Past the
# ceiling the same is true, and the sweep says so in a note.
RECENT_MAX_ENTITIES = 20_000
RECENT_PAGE_SIZE = 1_000


@dataclass(frozen=True)
class _Estate:
    """The addresses the recent read may return as entities.

    ``terms`` is the query clause value: the estate CIDRs plus every census
    address the CIDRs do not cover. Empty means unknown, and the read fails
    OPEN, like every scope test in this lane.
    """

    cidrs: tuple[Any, ...] = ()
    census: frozenset[str] = frozenset()

    @property
    def terms(self) -> list[str]:
        nets = [str(c).strip() for c in self.cidrs if str(c).strip()]
        if not nets:
            return []
        extra = sorted(ip for ip in self.census if not _is_internal_ip(ip, list(self.cidrs)))
        return [*nets, *extra[:_MAX_CENSUS_TERMS]]

    def holds(self, key: str) -> bool:
        """Whether one entity key may be scored. A hostname always may."""
        if not self.cidrs or not _is_ip_literal(key):
            return True
        return key in self.census or _is_internal_ip(key, list(self.cidrs))


# A terms query holds at most 65,536 values by default. The census adds the
# hosts the CIDRs miss, and on a sane estate that is a handful.
_MAX_CENSUS_TERMS = 10_000


def _estate_clause(entity_field: str, estate: _Estate | None) -> list[dict[str, Any]]:
    """Keep only estate entities in the recent read, on address-keyed fields.

    The served-port read keys on ``destination.ip``. With no filter every
    internet address the estate reached became an entity, the read filled its
    500-entity cap with them, and each one scored as a blind row: "blind 489"
    on a 336-host estate, 81,621 blind rows on the range.
    """
    if estate is None or not entity_field.endswith(".ip"):
        return []
    terms = estate.terms
    if not terms:
        return []
    return [{"terms": {entity_field: terms}}]


def _networks(cidrs: Sequence[Any]) -> tuple[Any, ...]:
    """The CIDRs as network objects. A value that does not parse is dropped."""
    out: list[Any] = []
    for c in cidrs:
        try:
            out.append(ipaddress.ip_network(str(c).strip(), strict=False))
        except ValueError:
            continue
    return tuple(out)


async def _census(db: AsyncSession) -> frozenset[str]:
    """The addresses the dossier knows as hosts."""
    rows = (await db.execute(select(HostDossier.host_key))).all()
    return frozenset(str(key) for (key,) in rows if key and _is_ip_literal(str(key)))


async def _recent_buckets(
    elastic: Any,
    settings: Any,
    query: dict[str, Any],
    *,
    dimension: str,
    entity_field: str,
    aggs: dict[str, Any],
    capped: set[str] | None,
) -> AsyncIterator[dict[str, Any]]:
    """Every entity bucket of one recent read, one composite page at a time.

    The caller parses each bucket as it arrives, so the read holds one page of
    raw buckets, not the estate's. A failed page raises, and the caller drops
    what it parsed. A part of the estate scored as the whole is the false
    all-clear the ceiling note exists to prevent.
    """
    reader = CompositeRead(
        elastic,
        settings.events_index_pattern,
        query,
        name=dimension,
        field=entity_field,
        aggs=aggs,
        page_size=RECENT_PAGE_SIZE,
        ceiling=RECENT_MAX_ENTITIES,
    )
    async for page in reader.pages():
        for bucket in page:
            yield bucket
    if reader.capped and capped is not None:
        capped.add(dimension)


async def _recent_shaped(
    elastic: Any,
    settings: Any,
    *,
    dimension: str,
    shape: str,
    entity_field: str,
    candidates: tuple[str, ...],
    probe_field: str,
    hours: int,
    tz: str,
    estate: _Estate | None = None,
    anchor: datetime | None = None,
    capped: set[str] | None = None,
) -> dict[str, dict[str, Any]] | None:
    """Recent activity for a non-categorical dimension.

    For ``active_hours`` this is which local hours the entity was seen in. For
    a rate it is the count of every complete hour of the window, keyed by the
    UTC start of the hour, zero where the hour held no document. The evaluator
    tests each hour against the expected count for its hour of the week.

    ``None`` when no plane on this grid carries the field, as distinct from an
    empty mapping for a plane that was quiet. See :func:`_recent_members`.

    ``anchor`` ends the window at a fixed time. None ends it at the grid's
    present, which is what the hourly loop wants. A replay reads a past hour.

    ``capped`` gains ``dimension`` when the read stopped at
    :data:`RECENT_MAX_ENTITIES`, so the caller can say so.
    """
    minutes = max(1, hours) * 60
    usable = await resolve_plane(
        elastic,
        settings,
        candidates=candidates,
        field=probe_field,
        minutes=minutes,
        time_anchor=anchor,
    )
    if usable is None:
        raise RuntimeError(
            f"the plane probe for {probe_field} failed. soc-ai cannot tell a quiet "
            "network from an unreachable one"
        )
    if not usable:
        return None

    query = {
        "bool": {
            "filter": [
                _window_filter(minutes, anchor),
                {
                    "bool": {
                        "should": [_dataset_clause(d) for d in usable],
                        "minimum_should_match": 1,
                    }
                },
                {"exists": {"field": entity_field}},
                *_estate_clause(entity_field, estate),
            ],
            "must_not": _scope_must_not(),
        }
    }
    sub_aggs = {
        "per_hour": {
            "date_histogram": {
                "field": "@timestamp",
                "calendar_interval": "hour",
                "min_doc_count": 1,
            },
            # The documents behind the hour. A shaped departure names
            # an hour or a cell rather than a member, so the sample has
            # to ride on the bucket that carries the time.
            "aggs": {"samples": _samples_agg()},
        }
    }
    buckets = _recent_buckets(
        elastic,
        settings,
        query,
        dimension=dimension,
        entity_field=entity_field,
        aggs=sub_aggs,
        capped=capped,
    )

    out: dict[str, dict[str, Any]] = {}
    async for bucket in buckets:
        key = bucket.get("key")
        if not isinstance(key, str) or not key:
            continue
        if estate is not None and not estate.holds(key):
            continue
        hourly = ((bucket.get("per_hour") or {}).get("buckets")) or []
        if shape == "active_hours":
            hours_seen: dict[str, Any] = {}
            for hb in hourly:
                hour = _local_hour_of(hb.get("key_as_string"), tz=tz)
                if hour is None:
                    continue
                entry = hours_seen.setdefault(str(hour), {"count": 0, "sample_ids": []})
                entry["count"] += int(hb.get("doc_count") or 0)
                _keep_ids(entry["sample_ids"], _hit_ids(hb))
                entry["newest"] = _newer(entry.get("newest"), _hit_newest(hb))
            if hours_seen:
                out[key] = hours_seen
            continue

        # A rate is tested hour by hour. Every complete hour of the window is
        # one entry, and an hour with no document is a count of zero. The
        # median of the recent hours could not move for a burst shorter than
        # half a cell.
        seen: dict[datetime, dict[str, Any]] = {}
        for hb in hourly:
            stamp = _stamp_of(hb.get("key_as_string"))
            if stamp is None:
                continue
            start = _hour_floor(stamp)
            entry = seen.setdefault(start, {"count": 0, "sample_ids": [], "newest": None})
            entry["count"] += int(hb.get("doc_count") or 0)
            _keep_ids(entry["sample_ids"], _hit_ids(hb))
            entry["newest"] = _newer(entry.get("newest"), _hit_newest(hb))
        out[key] = {
            at.isoformat(): seen.get(at, {"count": 0, "sample_ids": [], "newest": None})
            for at in _complete_hours(hours=hours, now=anchor)
        }
    return out


def _hour_floor(at: datetime) -> datetime:
    """The UTC start of the hour that holds ``at``."""
    if at.tzinfo is None:
        at = at.replace(tzinfo=UTC)
    return at.astimezone(UTC).replace(minute=0, second=0, microsecond=0)


def _complete_hours(*, hours: int, now: datetime | None) -> list[datetime]:
    """The UTC starts of the whole hours inside the last ``hours`` before ``now``.

    The hour that holds ``now`` is still filling, and the hour that holds the
    start of the window was cut by it. Either would read as a collapse.
    """
    end = now or datetime.now(UTC)
    if end.tzinfo is None:
        end = end.replace(tzinfo=UTC)
    first = _hour_floor(end - timedelta(hours=max(1, hours)))
    if first < end - timedelta(hours=max(1, hours)):
        first += timedelta(hours=1)
    last = _hour_floor(end)
    out: list[datetime] = []
    at = first
    while at < last:
        out.append(at)
        at += timedelta(hours=1)
    return out


def _stamp_of(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _local_hour_of(value: Any, *, tz: str) -> int | None:
    from zoneinfo import ZoneInfo, ZoneInfoNotFoundError  # noqa: PLC0415 - lazy, avoids a cycle

    stamp = _stamp_of(value)
    if stamp is None:
        return None
    try:
        zone = ZoneInfo(tz)
    except (ZoneInfoNotFoundError, ValueError):
        zone = ZoneInfo("UTC")
    return stamp.astimezone(zone).hour


async def _recent_members(
    elastic: Any,
    settings: Any,
    *,
    dimension: str,
    hours: int,
    cidrs: Sequence[Any] = (),
    estate: _Estate | None = None,
    anchor: datetime | None = None,
    capped: set[str] | None = None,
) -> dict[str, dict[str, Any]] | None:
    """What each entity did on this dimension lately, keyed entity -> members.

    Three answers, the same three :func:`resolve_plane` gives, because each
    reads differently to the operator:

    a mapping   the plane answered; empty means nothing happened lately
    ``None``    no plane on this grid carries the field — the dimension is
                blind, and reporting it as "no recent activity" is the
                false all-clear the coverage report exists to prevent
    RAISES      the plane probe could not run. A probe failure is a broken
                sweep, and returning an empty mapping for it would make a
                dead grid indistinguishable from a quiet network

    ``anchor`` ends the window at a fixed time, and ``capped`` records a read
    that stopped at the ceiling, as in :func:`_recent_shaped`.
    """
    spec = _dimension_spec(dimension)
    if spec is None:
        return {}
    candidates, probe_field, entity_field, member_field = spec

    minutes = max(1, hours) * 60
    alternates = member_alternates(dimension)
    usable = await resolve_plane(
        elastic,
        settings,
        candidates=candidates,
        field=probe_field,
        minutes=minutes,
        time_anchor=anchor,
        also=alternates,
    )
    if usable is None:
        raise RuntimeError(
            f"the plane probe for {probe_field} failed. soc-ai cannot tell a quiet "
            "network from an unreachable one"
        )
    if not usable:
        return None

    direction = _direction_for(dimension, planes=usable)
    query = {
        "bool": {
            "filter": [
                _window_filter(minutes, anchor),
                {
                    "bool": {
                        "should": [_dataset_clause(d) for d in usable],
                        "minimum_should_match": 1,
                    }
                },
                {"exists": {"field": entity_field}},
                member_exists_clause(dimension, member_field),
                *_estate_clause(entity_field, estate),
                # The SAME bound the baseline was built with. An asymmetry here
                # is the ephemeral-port defect in reverse: the recent read would
                # surface dynamic ports the baseline was never allowed to hold,
                # and every one of them would score as novel.
                *_port_bound(member_field),
                # The SAME direction clauses, for the same reason.
                *direction["filter"],
            ],
            # The same estate scope, for the same reason. The outbound-port
            # baseline holds destinations outside the estate only.
            "must_not": [
                *_scope_must_not(),
                *_outside_the_estate(dimension, cidrs=cidrs),
                *direction["must_not"],
            ],
        }
    }
    # The entity level of the baseline's terms read is the composite source
    # here. What each entity carries below it is the same.
    member_aggs = _recent_terms(
        entity_field=entity_field,
        member_field=member_field,
        peer_field=_peer_field(dimension),
        also=alternates,
    )["aggs"]
    buckets = _recent_buckets(
        elastic,
        settings,
        query,
        dimension=dimension,
        entity_field=entity_field,
        aggs=member_aggs,
        capped=capped,
    )

    out: dict[str, dict[str, Any]] = {}
    async for bucket in buckets:
        key = bucket.get("key")
        if not isinstance(key, str) or not key:
            continue
        if estate is not None and not estate.holds(key):
            continue
        members = member_buckets(bucket)
        seen: dict[str, Any] = {}
        for m in members:
            if m.get("key") is None:
                continue
            entry: dict[str, Any] = {
                "count": int(m.get("doc_count") or 0),
                "sample_ids": _hit_ids(m),
                "newest": _hit_newest(m),
            }
            if dimension in GUARDED_PORT_DIMENSIONS:
                entry["peers"] = _member_peers(m)
                entry["days"] = _member_days(m)
                transport = member_transport(m)
                if transport is not None:
                    entry["transport"] = transport
            seen[str(m.get("key"))] = entry
        out[key] = seen
    return out


async def _silent_profiled(db: AsyncSession, *, dimension: str, present: set[str]) -> list[str]:
    """Hosts with a scorable baseline on ``dimension`` that were not seen lately.

    The recent read only returns entities that had at least one document, so
    the host the collapse prior was written for — the one whose agent was
    killed — is exactly the one it never handed to the evaluator.
    """
    rows = (
        await db.execute(
            select(EntityProfile.entity_key).where(
                EntityProfile.entity_kind == "host",
                EntityProfile.dimension == dimension,
                EntityProfile.coverage == COVERAGE_MEASURED,
            )
        )
    ).all()
    return sorted({str(key) for (key,) in rows if str(key) not in present})


def _zero_hours(*, hours: int, now: datetime | None) -> dict[str, Any]:
    """What a silent host observed: nothing, in every complete hour of the window.

    No sample ids, because there are no documents behind an absence; the
    departure cites the baseline it fell from instead.
    """
    return {
        at.isoformat(): {"count": 0, "sample_ids": [], "silent": True}
        for at in _complete_hours(hours=hours, now=now)
    }


def _plane_of(dimension: str, shaped: tuple[str, str] | None) -> tuple[str, tuple[str, ...]]:
    """The (probe field, candidate datasets) a dimension is read from.

    Both shaped dimensions read the same flow plane; the lane holds it once.
    """
    if shaped is not None:
        return _SHAPED_PROBE_FIELD, _SHAPED_CANDIDATES
    spec = _dimension_spec(dimension)
    if spec is None:
        return dimension, ()
    return spec[1], spec[0]


async def _recent(
    elastic: Any,
    settings: Any,
    *,
    dimension: str,
    shaped: tuple[str, str] | None,
    hours: int,
    tz: str,
    cidrs: Sequence[Any],
    estate: _Estate | None = None,
    anchor: datetime | None = None,
    capped: set[str] | None = None,
) -> dict[str, dict[str, Any]] | None:
    """The recent read for one dimension, through whichever reader it needs."""
    if shaped is None:
        return await _recent_members(
            elastic,
            settings,
            dimension=dimension,
            hours=hours,
            cidrs=cidrs,
            estate=estate,
            anchor=anchor,
            capped=capped,
        )
    # Both shaped dimensions read the same flow plane, keyed by the same
    # entity; the lane holds those three once.
    _dim, shape = shaped
    return await _recent_shaped(
        elastic,
        settings,
        dimension=dimension,
        shape=shape,
        entity_field=_SHAPED_ENTITY_FIELD,
        candidates=_SHAPED_CANDIDATES,
        probe_field=_SHAPED_PROBE_FIELD,
        hours=hours,
        tz=tz,
        estate=estate,
        anchor=anchor,
        capped=capped,
    )


def _ceiling_note(dimension: str) -> str:
    """What the sweep says when a recent read stopped at its ceiling."""
    return (
        f"the recent read for {dimension} stopped at the ceiling of "
        f"{RECENT_MAX_ENTITIES:,} entities. The sweep did not score the entities "
        "past the ceiling."
    )


def _no_plane(
    spec: HuntSpec, *, dimension: str, shaped: tuple[str, str] | None
) -> tuple[PriorResult, str]:
    """The blind result and the note for a dimension no plane on this grid carries."""
    probe_field, candidates = _plane_of(dimension, shaped)
    reason = f"no plane on this grid carries {probe_field}"
    return (
        _blank(spec, None, COVERAGE_BLIND, reason),
        f"{spec.id}: {reason}. Tried {', '.join(candidates)}.",
    )


async def _silent_hosts(
    db: AsyncSession,
    *,
    spec_id: str,
    dimension: str,
    present: set[str],
    hours: int,
    tz: str,
    notes: list[str],
    now: datetime | None = None,
    capped: bool = False,
) -> dict[str, dict[str, Any]]:
    """Zero observations for every profiled host the recent read did not see.

    Only called when the plane answered for somebody. With nothing seen on any
    entity the shipper is down, and one collapse finding per profiled host
    would say otherwise. A read that stopped at its ceiling is the other case
    where absence is not silence: a profiled host past the ceiling is still
    talking, so nothing is scored and the sweep says so in a note.

    ``capped`` is the reader's own word that the ceiling stopped it. A guard
    that counted the entities would miss a read the estate test thinned below
    the ceiling, and it would score the hosts past the ceiling as silent.
    """
    if capped:
        notes.append(
            f"{spec_id}: the recent read stopped at the ceiling of "
            f"{RECENT_MAX_ENTITIES:,} entities. A profiled host past the ceiling is "
            "not in the answer. The sweep did not score silent hosts."
        )
        return {}
    zero = _zero_hours(hours=hours, now=now)
    silent = await _silent_profiled(db, dimension=dimension, present=present)
    return {entity_key: dict(zero) for entity_key in silent}


@dataclass
class _Context:
    """What one sweep reads once and every evaluation shares.

    ``prevalence_ready`` is False when the estate table could not be read or
    refreshed. The sweep then scores novelty without prevalence, as it did
    before the table existed, and says so in a note.
    """

    tz: str = "UTC"
    rare_below: int = DEFAULT_RARE_HOSTS
    common_share: float = DEFAULT_COMMON_SHARE
    prevalence_ready: bool = False
    measured: dict[str, int] = dc_field(default_factory=dict)
    holders: dict[tuple[str, str], int] = dc_field(default_factory=dict)
    asked: set[tuple[str, str]] = dc_field(default_factory=set)
    # The windows an investigation confirmed as an attack, per host key. The
    # baseline does not learn from them.
    windows: dict[str, list[tuple[datetime, datetime]]] = dc_field(default_factory=dict)
    # Each peer group read once per sweep: per (role, dimension), every peer's
    # key with the members its baseline knows, and how many peers hold each.
    groups: dict[tuple[str, str], tuple[list[tuple[str, set[str]]], Counter[str]]] = dc_field(
        default_factory=dict
    )
    # The learned groups of the estate model, the second peer source. Read
    # once per sweep, and only when the estate model is on.
    learned: LearnedPeers = dc_field(default_factory=LearnedPeers)

    async def peer_view(
        self,
        db: AsyncSession,
        *,
        role: str | None,
        confidence: float,
        dimension: str,
        entity_key: str,
        min_peers: int,
    ) -> PeerView | None:
        """The peers of one entity: its confident role, else its learned group."""
        source = await peer_source(
            db, entity_key=entity_key, role=role, confidence=confidence, learned=self.learned
        )
        if source is None:
            return None
        group_key = (source.cache_key, dimension)
        if group_key not in self.groups:
            rows = await peer_profiles(db, source, dimension=dimension, learned=self.learned)
            members = [
                (
                    row.entity_key,
                    known_members(row.vector, exclude=windows_for(self.windows, row.entity_key)),
                )
                for row in rows
            ]
            self.groups[group_key] = (
                members,
                Counter(m for _key, held in members for m in held),
            )
        members, counts = self.groups[group_key]
        own = [held for key, held in members if _same_entity(key, entity_key)]
        holders = Counter(counts)
        for held in own:
            holders.subtract(held)
        return PeerView(
            role=source.label,
            peers=len(members) - len(own),
            holders={m: n for m, n in holders.items() if n > 0},
            min_peers=min_peers,
        )

    async def estate_for(
        self, db: AsyncSession, dimension: str, new_members: set[str]
    ) -> EstateView | None:
        """How common the new members of one entity are, read once per member."""
        if not self.prevalence_ready or dimension not in PREVALENCE_DIMENSIONS:
            return None
        if dimension not in self.measured:
            self.measured[dimension] = await profiled_hosts(db, dimension)
        wanted = {m for m in new_members if (dimension, m) not in self.asked}
        if wanted:
            found = await prevalence_for(db, dimension, wanted)
            for member in wanted:
                self.asked.add((dimension, member))
                self.holders[(dimension, member)] = found.get(member, 0)
        return EstateView(
            measured=self.measured[dimension],
            hosts={m: self.holders.get((dimension, m), 0) for m in new_members},
            rare_below=self.rare_below,
            common_share=self.common_share,
        )


def _same_entity(a: str, b: str) -> bool:
    """One machine under two keys: the same key, or the same folded host name.

    An address matches itself only. Its first label is not a host name, and
    every address in 192.0.2.0/24 would read as one machine.
    """
    if a == b:
        return True
    if _is_ip_literal(a) or _is_ip_literal(b):
        return False
    return bool(set(_name_keys(a)) & set(_name_keys(b)))


def _context_for(settings: Any) -> _Context:
    """The estate bars from the settings, with the shipped defaults."""
    rare = getattr(settings, "profile_estate_rare_hosts", DEFAULT_RARE_HOSTS)
    share = getattr(settings, "profile_estate_common_share", DEFAULT_COMMON_SHARE)
    return _Context(
        tz=str(getattr(settings, "so_timezone", "UTC") or "UTC"),
        rare_below=int(rare) if isinstance(rare, (int, float)) else DEFAULT_RARE_HOSTS,
        common_share=float(share) if isinstance(share, (int, float)) else DEFAULT_COMMON_SHARE,
        learned=LearnedPeers(enabled=bool(getattr(settings, "estate_model_enabled", False))),
    )


# Entities per baseline query of the scoring loop. One query per entity was
# about 60 percent of the sweep's own time once the recent read paged the
# whole estate.
_PROFILE_SLICE = 500


async def _evaluate_entities(
    db: AsyncSession,
    spec: HuntSpec,
    *,
    observations: dict[str, dict[str, Any]],
    roles: dict[str, tuple[str | None, float]],
    results: list[PriorResult],
    errors: list[str],
    window_hours: int = DEFAULT_RECENT_HOURS,
    context: _Context | None = None,
) -> None:
    """Score one spec against every entity that has something observed.

    The baselines are read in slices of :data:`_PROFILE_SLICE` entities, one
    query per slice. A slice that cannot be read is not scored, and the error
    names it.
    """
    assert spec.profile is not None
    dimension = spec.profile.dimension
    keys = list(observations)
    # ``baselines``, not ``profiles``: that name is the caller's
    # ProfileState, recorded on the trail after this loop.
    baselines: dict[str, ep.ProfileRow] = {}
    unread = False
    for n, (entity_key, observed) in enumerate(observations.items()):
        if n % _PROFILE_SLICE == 0:
            batch = keys[n : n + _PROFILE_SLICE]
            try:
                baselines = await ep.load_dimension(
                    db, entity_kind="host", dimension=dimension, entity_keys=batch
                )
                unread = False
            except Exception as exc:
                errors.append(f"{spec.id}: profile read failed for {len(batch)} entities: {exc}")
                unread = True
        if unread:
            continue
        role, confidence = _role_for(roles, entity_key)

        profile = baselines.get(entity_key)
        exclude = windows_for(context.windows, entity_key) if context is not None else []
        peers: PeerView | None = None
        if context is not None and spec.profile.test in {"novel_for", "rare_for_peers"}:
            try:
                peers = await context.peer_view(
                    db,
                    role=role,
                    confidence=confidence,
                    dimension=dimension,
                    entity_key=entity_key,
                    min_peers=spec.profile.min_peers,
                )
            except Exception as exc:
                errors.append(f"{spec.id}/{entity_key}: peer group read failed: {exc}")
        estate: EstateView | None = None
        if context is not None and spec.profile.test == "novel_for" and profile is not None:
            held = known_members(
                profile.vector, min_days=spec.profile.min_known_days, exclude=exclude
            )
            new_members = {str(m) for m in observed} - held
            try:
                estate = await context.estate_for(db, dimension, new_members)
            except Exception as exc:
                errors.append(f"{spec.id}/{entity_key}: prevalence read failed: {exc}")
        results.append(
            evaluate_prior(
                spec,
                profile=profile,
                observed=observed,
                role=role,
                role_confidence=confidence,
                window_hours=window_hours,
                estate=estate,
                tz=context.tz if context is not None else "UTC",
                exclude=exclude,
                peers=peers,
            )
        )


async def run_prior_sweep(  # noqa: PLR0915 - one function reads as one procedure
    *,
    elastic: Any,
    settings: Any,
    db: AsyncSession,
    recent_hours: int = DEFAULT_RECENT_HOURS,
    catalog: dict[str, HuntSpec] | None = None,
    record: bool = False,
    cidrs: Sequence[Any] = (),
    shadow_ids: frozenset[str] = frozenset(),
    profiles: ProfileState | None = None,
    now: datetime | None = None,
) -> PriorSweep:
    """Evaluate every ``profile`` spec against every entity that has a baseline.

    ``record=True`` writes each departure as an observation, prunes anything
    outside the estate, and forms leads
    from what accumulates. Defaulted OFF so that reading the sweep is free of
    side effects — an operator running this to see coverage must not thereby
    change what the next run concludes.

    A spec in ``shadow_ids`` writes shadow observations with receipts. Its
    baseline is the receipt: a profile analytic compiles to no query, so there
    is nothing to dry-run over thirty days.

    ``now`` is the time anchor. The recent read ends there, the silent-host
    fill counts back from it, and the observations and leads are written at
    it. None is the present. A replay passes each past hour in turn: the read
    had no anchor, so a past hour could not be evaluated at all.

    Never raises: a sweep that dies part-way through has told the analyst
    nothing, and told them so confidently.
    """
    specs = catalog if catalog is not None else load_catalog(CATALOG_DIR)
    priors = [s for s in specs.values() if s.evaluator == "profile" and s.profile]
    # The ``model`` specs run beside the priors, after them, with the same
    # time anchor, census and confirmed windows. See soc_ai.hunting.model.
    models = [s for s in specs.values() if s.evaluator == "model" and s.model is not None]
    if not priors and not models:
        return PriorSweep(notes=("the catalog ships no priors",))

    results: list[PriorResult] = []
    errors: list[str] = []
    notes: list[str] = []

    try:
        roles = await _roles(db)
        # The census is read from the same table, so one failure covers both.
        estate = _Estate(cidrs=_networks(cidrs), census=await _census(db))
    except Exception as exc:
        return PriorSweep(errors=(f"could not read host roles: {exc}",))

    # How common each member is across the estate. Refreshed when a build is
    # newer than the table. A failure here costs the prevalence, not the sweep.
    context = _context_for(settings)
    try:
        refreshed = await ensure_estate(db)
        context.prevalence_ready = True
        if refreshed:
            notes.append(refreshed)
    except Exception as exc:
        await db.rollback()
        notes.append(f"estate prevalence could not be read, novelty runs without it: {exc}")
    # The windows an investigation confirmed. Unread, the baseline learns
    # from the attack, and the sweep says so.
    try:
        context.windows = await confirmed_windows(db, now=now)
    except Exception as exc:
        await db.rollback()
        notes.append(f"confirmed attack windows could not be read: {exc}")

    # One recent read per DIMENSION, not per spec: several priors share a
    # dimension, and re-reading the plane for each is the difference between
    # four aggregations and nine.
    #
    # ``None`` in the cache means no plane on this grid carries the dimension.
    recent_cache: dict[str, dict[str, dict[str, Any]] | None] = {}
    # The dimensions whose recent read stopped at RECENT_MAX_ENTITIES.
    capped: set[str] = set()
    # The last spec that reads each dimension. The read leaves the cache after
    # it: a paged read of the whole estate is large, and the sweep held every
    # dimension's read to the end.
    last_use = {s.profile.dimension: n for n, s in enumerate(priors) if s.profile is not None}
    tz = str(getattr(settings, "so_timezone", "UTC") or "UTC")

    for n, spec in enumerate(priors):
        assert spec.profile is not None
        dimension = spec.profile.dimension
        shaped = next((row for row in _SHAPED if row[0] == dimension), None)
        if dimension not in recent_cache:
            try:
                recent_cache[dimension] = await _recent(
                    elastic,
                    settings,
                    dimension=dimension,
                    shaped=shaped,
                    hours=recent_hours,
                    tz=tz,
                    cidrs=cidrs,
                    estate=estate,
                    anchor=now,
                    capped=capped,
                )
            except Exception as exc:
                errors.append(f"{spec.id}: recent read for {dimension} failed: {exc}")
                recent_cache[dimension] = {}
            if dimension in capped:
                notes.append(_ceiling_note(dimension))
        recent = recent_cache[dimension]

        if recent is None:
            # Blind, not quiet. The profile lane records the same grid state
            # as a blind row; a zero row here read as an all-clear on a
            # dimension nothing could measure.
            result, note = _no_plane(spec, dimension=dimension, shaped=shaped)
            results.append(result)
            notes.append(note)
            continue

        if not recent:
            notes.append(
                f"{spec.id}: no recent {dimension} activity on any entity in the last "
                f"{recent_hours} h"
            )

        observations = dict(recent)
        if (
            recent
            and shaped is not None
            and shaped[1] == "numeric"
            and spec.profile.test == "below"
        ):
            try:
                observations.update(
                    await _silent_hosts(
                        db,
                        spec_id=spec.id,
                        dimension=dimension,
                        present=set(recent),
                        hours=recent_hours,
                        tz=tz,
                        notes=notes,
                        now=now,
                        capped=dimension in capped,
                    )
                )
            except Exception as exc:
                errors.append(f"{spec.id}: profile read failed: {exc}")

        await _evaluate_entities(
            db,
            spec,
            observations=observations,
            roles=roles,
            results=results,
            errors=errors,
            window_hours=recent_hours,
            context=context,
        )
        if last_use.get(dimension) == n:
            # No later spec reads this dimension. Free its read before the next one.
            recent_cache[dimension] = {}
            recent = observations = {}

    if models:
        anchor = now or datetime.now(UTC)
        outcome = await run_model_specs(
            models,
            ctx=DetectorContext(
                elastic=elastic,
                settings=settings,
                db=db,
                now=anchor if anchor.tzinfo is not None else anchor.replace(tzinfo=UTC),
                tz=tz,
                census=estate.census,
                cidrs=estate.cidrs,
                windows=context.windows,
            ),
        )
        results.extend(outcome.results)
        notes.extend(outcome.notes)
        errors.extend(outcome.errors)

    # The reason beside the blind count, for each spec that scored nothing.
    blind_notes = _blind_notes(results)
    notes.extend(note for _spec, note in sorted(blind_notes.items()))
    _log_blind(
        blind_notes,
        {spec_id: parts[0] for spec_id, parts in _most_common_reasons(results).items()},
    )

    lead_outcome: LeadOutcome | None = None
    sweep = PriorSweep(
        results=tuple(results),
        errors=tuple(errors),
        notes=tuple(notes),
        evaluated_specs=tuple(s.id for s in [*priors, *models]),
        recent_hours=recent_hours,
    )
    trail_shadow = shadow_ids
    if record:
        try:
            lead_outcome = await _record_and_form(
                db,
                results,
                cidrs=cidrs,
                shadow_ids=shadow_ids,
                recent_hours=recent_hours,
                now=now,
            )
        except Exception as exc:
            errors.append(f"could not record the observations: {exc}")
        try:
            from soc_ai.store import prior_spec_runs  # noqa: PLC0415 - lazy, avoids a cycle

            await prior_spec_runs.record_sweep(
                db, sweep, shadow_ids=trail_shadow, profiles=profiles, now=now
            )
        except Exception as exc:
            errors.append(f"could not record the sweep trail: {exc}")

    return PriorSweep(
        results=sweep.results,
        errors=tuple(errors),
        notes=tuple(notes),
        leads=lead_outcome,
        evaluated_specs=sweep.evaluated_specs,
        recent_hours=recent_hours,
    )


async def _record_and_form(
    db: AsyncSession,
    results: Sequence[PriorResult],
    *,
    cidrs: Sequence[Any] = (),
    shadow_ids: frozenset[str] = frozenset(),
    recent_hours: int = DEFAULT_RECENT_HOURS,
    now: datetime | None = None,
) -> LeadOutcome:
    """Turn departures into observations, then form leads from what accumulates.

    The kind is chosen from the SPEC, not the departure: a prior that declares
    no benign population is a finding in its own right and is born at full
    weight, while an ordinary novel member is a contribution toward one. Reading
    the kind off the departure instead would make every prior equally loud.
    """
    # Prune first. Scoping the profile table alone left observations against an
    # external server and the loopback address live, decaying and accumulating
    # toward leads about somebody else's infrastructure.
    await purge_out_of_scope_observations(db, cidrs=cidrs)

    touched: set[tuple[str, str]] = set()
    for result in results:
        if not result.departures:
            continue
        shadow_spec = result.spec_id in shadow_ids
        touched.add((result.entity_kind, result.entity_key))
        for departure in result.departures:
            await record_observation(
                db,
                entity_kind=result.entity_kind,
                entity_key=result.entity_key,
                kind=result.kind,
                spec_id=result.spec_id,
                fingerprint=content_fingerprint(departure.dimension, departure.member),
                # An estate-rare novelty is born heavier. Every other
                # departure takes the weight of its kind.
                weight=novelty_weight(result.kind, estate_rare=departure.estate_rare),
                # The SAME phrasing the CLI renders. Written separately, the
                # stored summary kept saying "novel connection_rate" for a rate
                # that had collapsed -- a new thing appearing, where the truth
                # was an existing one stopping.
                summary=(
                    f"{phrase(result.kind, departure, window_hours=recent_hours)}. "
                    f"{baseline_sentence(departure.baseline_size, departure.support_days)}"
                ),
                # The documents the recent read saw this member in, named the
                # same way the catalog path names them. A lead built only from
                # profile observations used to open with "no document ids
                # recorded" against every line, so the hunt sent to confirm a
                # departure re-queried the grid instead of reading the
                # documents that had formed the lead.
                evidence={
                    "sample_ids": list(departure.sample_ids),
                    "anchor_id": departure.sample_ids[0] if departure.sample_ids else None,
                    "baseline": _baseline_block(departure),
                    **({"receipts": _profile_receipts(departure)} if shadow_spec else {}),
                },
                # The adapter, not the status. ``shadow`` carries the status.
                source="profile",
                shadow=shadow_spec,
                # The newest document the departure cites. The observation
                # decays from the event, not from this sweep.
                observed_at=departure.observed_at,
                now=now,
                # The numbers and the query, in columns. The lead hunt read
                # them as prose, and searched the grid for the departure again.
                statistic=departure.statistic,
                statistic_value=departure.statistic_value,
                baseline_value=departure.baseline_value,
                document_ids=list(departure.sample_ids)[:MAX_DOCUMENT_IDS],
                rerun_query=_departure_query(result, departure, now=now, recent_hours=recent_hours),
            )
    # The hits of the model specs. Each carries its own words, documents and
    # query, and each is written as shadow. See soc_ai.hunting.model.
    for result in results:
        if not result.hits:
            continue
        if await record_model_hits(db, result, shadow=result.spec_id in shadow_ids, now=now):
            touched.update((hit.entity_kind, hit.entity_key) for hit in result.hits)
    await _record_spread(
        db, results, shadow_ids=shadow_ids, recent_hours=recent_hours, now=now, touched=touched
    )
    return await form_leads(db, entity_keys=sorted(touched), now=now)


def _novelty(result: PriorResult) -> bool:
    """Whether a result's departures are new members of a set."""
    return (
        bool(result.departures)
        and result.kind is not Kind.PRIOR_NO_BASELINE
        and all(d.dimension in PREVALENCE_DIMENSIONS for d in result.departures)
    )


async def _record_spread(
    db: AsyncSession,
    results: Sequence[PriorResult],
    *,
    shadow_ids: frozenset[str],
    recent_hours: int,
    now: datetime | None,
    touched: set[tuple[str, str]],
) -> None:
    """A second observation on each host when one member is new on several at once.

    One member new on three hosts in one sweep is one condition with three
    subjects. Each host gets a ``scope_count`` observation that states the
    spread and how many hosts held the member before. It is a second type, so
    the spread can form a lead, and the span rule turns a spread past the
    span cap into a fleet condition. A rollout to forty hosts reads as one
    fleet condition, not forty novelties.
    """
    spread: dict[tuple[str, str, str], list[tuple[PriorResult, Any]]] = {}
    for result in results:
        if not _novelty(result):
            continue
        for departure in result.departures:
            key = (result.spec_id, str(departure.dimension), str(departure.member))
            spread.setdefault(key, []).append((result, departure))
    for (spec_id, dimension, member), sightings in spread.items():
        hosts = {(r.entity_kind, r.entity_key) for r, _d in sightings}
        if len(hosts) < SCOPE_MIN_HOSTS:
            continue
        holders = next((d.estate_hosts for _r, d in sightings if d.estate_hosts is not None), None)
        for result, departure in sightings:
            touched.add((result.entity_kind, result.entity_key))
            await record_observation(
                db,
                entity_kind=result.entity_kind,
                entity_key=result.entity_key,
                kind=Kind.SCOPE_COUNT,
                spec_id=spec_id,
                fingerprint=content_fingerprint("scope_count", dimension, member),
                summary=f"{scope_sentence(dimension, member, hosts=len(hosts), holders=holders)}.",
                evidence={
                    "sample_ids": list(departure.sample_ids),
                    "anchor_id": departure.sample_ids[0] if departure.sample_ids else None,
                    "hosts": sorted(key for _kind, key in hosts),
                },
                source="profile",
                shadow=spec_id in shadow_ids,
                observed_at=departure.observed_at,
                now=now,
                statistic="hosts_departing",
                statistic_value=float(len(hosts)),
                baseline_value=float(holders) if holders is not None else None,
                document_ids=list(departure.sample_ids)[:MAX_DOCUMENT_IDS],
                rerun_query=_departure_query(result, departure, now=now, recent_hours=recent_hours),
            )


def _departure_query(
    result: PriorResult, departure: Any, *, now: datetime | None, recent_hours: int
) -> str | None:
    """The OQL query that shows one departure again, over the window it was read in.

    An hour of the day names one hour of the window: the hour of the newest
    document. A rate names the whole window. A collapse asks for the count,
    because an absence has no documents to group.
    """
    end = now or datetime.now(UTC)
    start = end - timedelta(hours=max(1, recent_hours))
    member: str | None = str(departure.member)
    count_only = False
    if departure.dimension == "active_hours":
        member = None
        if departure.observed_at is not None:
            start = departure.observed_at.replace(minute=0, second=0, microsecond=0)
            end = start + timedelta(hours=1)
    elif departure.dimension == "connection_rate":
        # The hours that departed, and only those.
        member = None
        count_only = result.kind is Kind.BELOW_BASELINE
        if departure.run_start is not None and departure.run_end is not None:
            start, end = departure.run_start, departure.run_end
    return rerun_query(
        str(departure.dimension),
        result.entity_key,
        member,
        start=start,
        end=end,
        count_only=count_only,
    )


def _baseline_block(departure: Any) -> dict[str, Any]:
    """What the departure is measured against, in numbers.

    "445 is new on this switch" means one thing when the switch has served one
    port for thirty days and another when it has served two hundred for three,
    so the observation carries the comparison alongside the documents.
    """
    return {
        "dimension": str(departure.dimension),
        "member": str(departure.member),
        "observed_count": int(departure.observed_count or 0),
        "baseline_size": int(departure.baseline_size or 0),
        "support_days": int(departure.support_days or 0),
        "statistic": getattr(departure, "statistic", None),
        "statistic_value": getattr(departure, "statistic_value", None),
        "baseline_value": getattr(departure, "baseline_value", None),
    }


def _profile_receipts(departure: Any) -> dict[str, Any]:
    """The receipts of a shadow departure. The baseline stands in for the dry run.

    A profile analytic answers from a stored baseline and never queries the
    grid, so there is no query to re-run over the last thirty days. The
    baseline names what the entity has done, over how long, and how many
    members it holds, which is the same evidence a dry run carries.
    """
    return build_receipts(
        matched_ids=list(departure.sample_ids),
        matched_fields=[str(departure.dimension)],
        dry_run=None,
        overlap=[],
        baseline=_baseline_block(departure),
        profile=True,
        requires_dry_run=False,
        requires_matched_ids=False,
    ).as_dict()


# The wording of a departure lives in soc_ai.hunting.wording, so the evaluator
# can build its note with the same sentences the sweep stores and the CLI
# prints. These names are kept because the routes and the tests import them
# from here.
_noun = noun
_when = when
_times = times
_phrase = phrase


def format_sweep(sweep: PriorSweep, *, catalog: Catalog | None = None) -> str:
    """A human-readable rendering, for the CLI and for a run summary.

    The per-spec table is the part worth having. A total of "542 blind" tells
    an operator almost nothing; "this prior was blind on every entity because
    no host has a confident hypervisor role" tells them what to fix. Coverage
    that cannot be acted on is only slightly better than no coverage report.

    The coverage line and each row count the four states of the trail, the
    same as the store, the ledger and the journal. The count of each detector
    state is in the sweep notes.

    ``catalog`` is the effective catalog the sweep ran. With it, each row
    states the status of its spec, and a line names each profile or model
    spec the sweep did not run. A shadow detector and a live analytic read
    the same without it.
    """
    lines: list[str] = []
    counts = sweep.coverage_counts()
    lines.append(
        f"prior sweep: {len(sweep.fired)} finding(s) from {len(sweep.results)} "
        f"(spec, entity) evaluations"
    )
    lines.append("  coverage: " + ", ".join(f"{k}={v}" for k, v in sorted(counts.items()) if v))

    per_spec: dict[str, dict[str, int]] = {}
    for result in sweep.results:
        per_spec.setdefault(result.spec_id, {})
        per_spec[result.spec_id][result.trail_state] = (
            per_spec[result.spec_id].get(result.trail_state, 0) + 1
        )
    reasons = sweep.blind_reasons()
    if per_spec:
        lines.append("  per spec:")
        for spec_id in sorted(per_spec):
            breakdown = ", ".join(f"{k}={v}" for k, v in sorted(per_spec[spec_id].items()))
            scorable = per_spec[spec_id].get(COVERAGE_MEASURED, 0)
            mark = " " if scorable else "!"
            status = f"{catalog.status_of(spec_id)[1]:9} " if catalog is not None else ""
            lines.append(f"   {mark} {spec_id:48} {status}{breakdown}")
            # The reason opens with its count, "3 of 4 blind hosts: ...", so
            # the line needs no label of its own.
            if spec_id in reasons:
                lines.append(f"       {reasons[spec_id]}")
        if any(not v.get(COVERAGE_MEASURED) for v in per_spec.values()):
            lines.append(
                "   ! = this prior could not be scored against any entity. It is "
                "not evidence of a clean network"
            )
    if catalog is not None:
        for spec_id, spec in sorted(catalog.listed.items()):
            if spec.evaluator in ("profile", "model") and spec_id not in catalog.specs:
                lines.append(f"  not run: {spec_id} is {catalog.status_of(spec_id)[1]}")

    for result in sweep.fired:
        lines.append(f"  [{result.spec_id}] {result.entity_kind}:{result.entity_key}")
        for departure in result.departures:
            lines.append(
                f"      {phrase(result.kind, departure, window_hours=sweep.recent_hours)}. "
                f"{baseline_sentence(departure.baseline_size, departure.support_days)}"
            )
        for hit in result.hits:
            lines.append(f"      {hit.reason} (shadow)")
    if sweep.leads is not None:
        outcome = sweep.leads
        lines.append(
            f"  leads: {len(outcome.formed)} formed, {len(outcome.updated)} updated, "
            f"{len(outcome.fleet_conditions)} recorded as fleet conditions"
        )
        for note in outcome.notes:
            lines.append(f"    {note}")

    # The row of a spec already states its blind reason. The note says it again.
    shown = set(_blind_notes(sweep.results).values()) if per_spec else set()
    for note in sweep.notes:
        if note in shown:
            continue
        lines.append(f"  note: {note}")
    for err in sweep.errors:
        lines.append(f"  error: {err}")
    return "\n".join(lines)

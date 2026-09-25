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

import logging
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from soc_ai.dossier.profile import (
    _CATEGORICAL,
    _SHAPED,
    _dataset_clause,
    _nested_terms,
    _outside_the_estate,
    _port_bound,
    _scope_must_not,
    _window_filter,
    resolve_plane,
)
from soc_ai.dossier.profile_math import TimeCell, cell_for, median
from soc_ai.hunting.leads import (
    LeadOutcome,
    content_fingerprint,
    form_leads,
    purge_out_of_scope_observations,
    record_observation,
)
from soc_ai.hunting.priors import (
    COVERAGE_BLIND,
    COVERAGE_LEARNING,
    COVERAGE_MEASURED,
    COVERAGE_NOT_APPLICABLE,
    PriorResult,
    _blank,
    evaluate_prior,
)
from soc_ai.hunting.receipts import build_receipts
from soc_ai.hunting.spec import CATALOG_DIR, HuntSpec, load_catalog
from soc_ai.hunting.wording import (
    baseline_sentence,
    noun,
    phrase,
    times,
    when,
)
from soc_ai.store import entity_profiles as ep
from soc_ai.store.models import EntityProfile, HostDossier, HostDossierField

__all__ = ["PriorSweep", "run_prior_sweep"]

_LOGGER = logging.getLogger(__name__)

# How far back "lately" reaches. A day, because the baseline is thirty and the
# two must not be the same window.
DEFAULT_RECENT_HOURS = 24

# How many documents the recent read keeps per member. Three is enough for an
# analyst to read the condition and cheap enough to ask for on every bucket.
SAMPLE_IDS_PER_MEMBER = 3


def _samples_agg() -> dict[str, Any]:
    """Up to three document ids per bucket, with no document bodies.

    ``_source: false`` because the id is the whole point. The observation cites
    the document and the hunt reads it with ``get_event_raw``; carrying the
    bodies back would multiply the response for a field no caller here reads.
    """
    return {"top_hits": {"size": SAMPLE_IDS_PER_MEMBER, "_source": False}}


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


def _recent_terms(*, entity_field: str, member_field: str) -> dict[str, Any]:
    """The baseline's member aggregation, plus the documents behind each member.

    The sample rides on the RECENT read only. Both reads carry the same bucket
    caps, but the baseline fills them over thirty days: three hits under every
    leaf of five hundred entities and two hundred members each is a hundred
    thousand documents fetched to describe what is ordinary. What is ordinary
    needs no citation. A departure from it does, and a day fills far fewer
    buckets than a month.
    """
    body = _nested_terms(entity_field=entity_field, member_field=member_field)
    body["aggs"]["members"]["aggs"] = {
        **body["aggs"]["members"]["aggs"],
        "samples": _samples_agg(),
    }
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

    @property
    def fired(self) -> tuple[PriorResult, ...]:
        return tuple(r for r in self.results if r.fired)

    def coverage_counts(self) -> dict[str, int]:
        """How many (spec, entity) pairs landed in each coverage state.

        Reported next to the findings rather than instead of them: "nothing
        departed" and "nothing could be measured" are the same empty list and
        completely different answers.
        """
        counts: dict[str, int] = {
            COVERAGE_MEASURED: 0,
            COVERAGE_LEARNING: 0,
            COVERAGE_BLIND: 0,
            COVERAGE_NOT_APPLICABLE: 0,
        }
        for result in self.results:
            counts[result.coverage] = counts.get(result.coverage, 0) + 1
        return counts


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


# How many entities one shaped recent read returns. The read is a terms bucket
# over the busiest entities in the window; past this many, an entity that is
# missing from the answer may simply have ranked below the cut, so absence
# cannot be read as silence.
RECENT_MAX_ENTITIES = 500


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
) -> dict[str, dict[str, Any]] | None:
    """Recent activity for a non-categorical dimension.

    For ``active_hours`` this is which local hours the entity was seen in. For
    a rate it is the MEDIAN per-hour count inside each of the three cells,
    which is what the baseline holds — comparing a total against a median would
    make every entity look like a spike in proportion to the window length.

    ``None`` when no plane on this grid carries the field, as distinct from an
    empty mapping for a plane that was quiet. See :func:`_recent_members`.
    """
    minutes = max(1, hours) * 60
    usable = await resolve_plane(
        elastic, settings, candidates=candidates, field=probe_field, minutes=minutes
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
                _window_filter(minutes, None),
                {
                    "bool": {
                        "should": [_dataset_clause(d) for d in usable],
                        "minimum_should_match": 1,
                    }
                },
                {"exists": {"field": entity_field}},
            ],
            "must_not": _scope_must_not(),
        }
    }
    aggs = {
        dimension: {
            "terms": {"field": entity_field, "size": RECENT_MAX_ENTITIES},
            "aggs": {
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
            },
        }
    }
    result = await elastic.search(settings.events_index_pattern, query, size=0, aggs=aggs)
    buckets = ((result.aggregations or {}).get(dimension) or {}).get("buckets") or []

    out: dict[str, dict[str, Any]] = {}
    for bucket in buckets:
        key = bucket.get("key")
        if not isinstance(key, str) or not key:
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
            if hours_seen:
                out[key] = hours_seen
            continue

        by_cell: dict[str, list[float]] = {}
        cell_ids: dict[str, list[str]] = {}
        for hb in hourly:
            stamp = _stamp_of(hb.get("key_as_string"))
            if stamp is None:
                continue
            name = cell_for(stamp, tz=tz).value
            by_cell.setdefault(name, []).append(float(hb.get("doc_count") or 0))
            _keep_ids(cell_ids.setdefault(name, []), _hit_ids(hb))
        cells = {
            name: {"value": med, "sample_ids": cell_ids.get(name, [])}
            for name, values in by_cell.items()
            if (med := median(values)) is not None
        }
        if cells:
            out[key] = cells
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
    """
    spec = _dimension_spec(dimension)
    if spec is None:
        return {}
    candidates, probe_field, entity_field, member_field = spec

    minutes = max(1, hours) * 60
    usable = await resolve_plane(
        elastic, settings, candidates=candidates, field=probe_field, minutes=minutes
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
                _window_filter(minutes, None),
                {
                    "bool": {
                        "should": [_dataset_clause(d) for d in usable],
                        "minimum_should_match": 1,
                    }
                },
                {"exists": {"field": entity_field}},
                {"exists": {"field": member_field}},
                # The SAME bound the baseline was built with. An asymmetry here
                # is the ephemeral-port defect in reverse: the recent read would
                # surface dynamic ports the baseline was never allowed to hold,
                # and every one of them would score as novel.
                *_port_bound(member_field),
            ],
            # The same estate scope, for the same reason. The outbound-port
            # baseline holds destinations outside the estate only.
            "must_not": [
                *_scope_must_not(),
                *_outside_the_estate(dimension, cidrs=cidrs),
            ],
        }
    }
    result = await elastic.search(
        settings.events_index_pattern,
        query,
        size=0,
        aggs={dimension: _recent_terms(entity_field=entity_field, member_field=member_field)},
    )
    buckets = ((result.aggregations or {}).get(dimension) or {}).get("buckets") or []

    out: dict[str, dict[str, Any]] = {}
    for bucket in buckets:
        key = bucket.get("key")
        if not isinstance(key, str) or not key:
            continue
        members = ((bucket.get("members") or {}).get("buckets")) or []
        out[key] = {
            str(m.get("key")): {
                "count": int(m.get("doc_count") or 0),
                "sample_ids": _hit_ids(m),
            }
            for m in members
            if m.get("key") is not None
        }
    return out


def _name_keys(name: str) -> tuple[str, ...]:
    """The keys a hostname is looked up under: folded, and its short label.

    Sysmon and winlogbeat write ``host.name`` the way Windows says it, which is
    often upper-case and sometimes fully qualified, while the dossier holds
    whatever DHCP or NTLM handed it. ``WS01.corp.example`` and ``ws01`` are one
    machine and must find one role.
    """
    folded = name.strip().lower()
    if not folded:
        return ()
    label = folded.split(".", 1)[0]
    return (folded, label) if label != folded else (folded,)


def _role_for(
    roles: dict[str, tuple[str | None, float]], entity_key: str
) -> tuple[str | None, float]:
    """The role held for an entity keyed either by IP or by ``host.name``."""
    if entity_key in roles:
        return roles[entity_key]
    for key in _name_keys(entity_key):
        if key in roles:
            return roles[key]
    return (None, 0.0)


async def _roles(db: AsyncSession) -> dict[str, tuple[str | None, float]]:
    """Every host's effective role and the confidence behind it.

    An operator declaration outranks the inference, and carries full
    confidence: a human who has declared a machine's role is not a 0.5 guess,
    and leaving it below the gate would make every declared host blind — the
    exact opposite of what declaring one is for.

    Keyed on the dossier's IP AND on the hostname the dossier believes. The
    process and logon dimensions key their entities on ``host.name``, and a
    map keyed on the IP alone answered "role unknown" for every one of them:
    five of the shipped role priors could never evaluate, and declaring the
    role in the console changed nothing.
    """
    rows = (
        await db.execute(
            select(HostDossier.host_key, HostDossierField.field, HostDossierField)
            .join(HostDossierField, HostDossierField.dossier_id == HostDossier.id)
            .where(HostDossierField.field.in_(("role", "hostname")))
        )
    ).all()

    out: dict[str, tuple[str | None, float]] = {}
    names: dict[str, str] = {}
    for host_key, field, row in rows:
        if field == "hostname":
            # The same precedence as the role: what the operator declared,
            # else what the sweep still believes.
            if row.operator_value:
                names[host_key] = str(row.operator_value)
            elif row.inferred_value and row.inferred_retracted_at is None:
                names[host_key] = str(row.inferred_value)
            continue
        # Attributes read directly, never through getattr with a default. The
        # first cut guessed the column was ``override_value`` (it is
        # ``operator_value``) and the default turned that typo into "no
        # operator has ever declared a role", silently, on every host.
        if row.operator_value:
            out[host_key] = (str(row.operator_value), 1.0)
            continue

        # A retracted inference is not a belief. The sweep retracts a fact when
        # the evidence for it stops arriving, and carrying it on here would let
        # a prior score against a role the dossier has already given up on.
        if row.inferred_retracted_at is not None:
            out[host_key] = (None, 0.0)
            continue

        out[host_key] = (
            str(row.inferred_value) if row.inferred_value else None,
            float(row.inferred_confidence) if row.inferred_confidence is not None else 0.0,
        )

    for host_key, name in names.items():
        if host_key not in out:
            continue
        for key in _name_keys(name):
            out.setdefault(key, out[host_key])
    return out


def _covered_cells(*, hours: int, tz: str, now: datetime | None = None) -> set[str]:
    """Which of the three cells the last ``hours`` actually fell in.

    A host that sent nothing over a Sunday has a zero weekend cell and nothing
    to say about its work cell. Zero-filling every cell would make a Monday
    morning sweep report a collapse in hours the window never covered.
    """
    end = now or datetime.now(UTC)
    return {cell_for(end - timedelta(hours=back), tz=tz).value for back in range(max(1, hours) + 1)}


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


def _zero_cells(cells: set[str]) -> dict[str, Any]:
    """What a silent host observed: nothing, in every covered cell.

    No sample ids, because there are no documents behind an absence; the
    departure cites the baseline it fell from instead.
    """
    return {
        cell.value: {"value": 0.0, "sample_ids": []} for cell in TimeCell if cell.value in cells
    }


def _plane_of(
    dimension: str, shaped: tuple[str, str, tuple[str, ...], str, str] | None
) -> tuple[str, tuple[str, ...]]:
    """The (probe field, candidate datasets) a dimension is read from."""
    if shaped is not None:
        return shaped[3], shaped[2]
    spec = _dimension_spec(dimension)
    if spec is None:
        return dimension, ()
    return spec[1], spec[0]


async def _recent(
    elastic: Any,
    settings: Any,
    *,
    dimension: str,
    shaped: tuple[str, str, tuple[str, ...], str, str] | None,
    hours: int,
    tz: str,
    cidrs: Sequence[Any],
) -> dict[str, dict[str, Any]] | None:
    """The recent read for one dimension, through whichever reader it needs."""
    if shaped is None:
        return await _recent_members(
            elastic, settings, dimension=dimension, hours=hours, cidrs=cidrs
        )
    _dim, shape, candidates, probe_field, entity_field = shaped
    return await _recent_shaped(
        elastic,
        settings,
        dimension=dimension,
        shape=shape,
        entity_field=entity_field,
        candidates=candidates,
        probe_field=probe_field,
        hours=hours,
        tz=tz,
    )


def _no_plane(
    spec: HuntSpec, *, dimension: str, shaped: tuple[str, str, tuple[str, ...], str, str] | None
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
) -> dict[str, dict[str, Any]]:
    """Zero observations for every profiled host the recent read did not see.

    Only called when the plane answered for somebody. With nothing seen on any
    entity the shipper is down, and one collapse finding per profiled host
    would say otherwise. A read that returned as many entities as it can hold
    is the other case where absence is not silence: a profiled host outside
    the answer may only have ranked below the cut, so nothing is scored and
    the sweep says so in a note.
    """
    if len(present) >= RECENT_MAX_ENTITIES:
        notes.append(
            f"{spec_id}: recent read returned {RECENT_MAX_ENTITIES} entities, "
            "so absence is not silence; silent hosts were not scored"
        )
        return {}
    zero = _zero_cells(_covered_cells(hours=hours, tz=tz))
    silent = await _silent_profiled(db, dimension=dimension, present=present)
    return {entity_key: dict(zero) for entity_key in silent}


async def _evaluate_entities(
    db: AsyncSession,
    spec: HuntSpec,
    *,
    observations: dict[str, dict[str, Any]],
    roles: dict[str, tuple[str | None, float]],
    results: list[PriorResult],
    errors: list[str],
) -> None:
    """Score one spec against every entity that has something observed."""
    assert spec.profile is not None
    dimension = spec.profile.dimension
    for entity_key, observed in observations.items():
        role, confidence = _role_for(roles, entity_key)
        try:
            profiles = await ep.load_profiles(db, entity_kind="host", entity_key=entity_key)
        except Exception as exc:
            errors.append(f"{spec.id}/{entity_key}: profile read failed: {exc}")
            continue

        results.append(
            evaluate_prior(
                spec,
                profile=profiles.get(dimension),
                observed=observed,
                role=role,
                role_confidence=confidence,
            )
        )


async def run_prior_sweep(
    *,
    elastic: Any,
    settings: Any,
    db: AsyncSession,
    recent_hours: int = DEFAULT_RECENT_HOURS,
    catalog: dict[str, HuntSpec] | None = None,
    record: bool = False,
    cidrs: Sequence[Any] = (),
    shadow_ids: frozenset[str] = frozenset(),
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

    Never raises: a sweep that dies part-way through has told the analyst
    nothing, and told them so confidently.
    """
    specs = catalog if catalog is not None else load_catalog(CATALOG_DIR)
    priors = [s for s in specs.values() if s.evaluator == "profile" and s.profile]
    if not priors:
        return PriorSweep(notes=("the catalog ships no priors",))

    results: list[PriorResult] = []
    errors: list[str] = []
    notes: list[str] = []

    try:
        roles = await _roles(db)
    except Exception as exc:
        return PriorSweep(errors=(f"could not read host roles: {exc}",))

    # One recent read per DIMENSION, not per spec: several priors share a
    # dimension, and re-reading the plane for each is the difference between
    # four aggregations and nine.
    #
    # ``None`` in the cache means no plane on this grid carries the dimension.
    recent_cache: dict[str, dict[str, dict[str, Any]] | None] = {}
    tz = str(getattr(settings, "so_timezone", "UTC") or "UTC")

    for spec in priors:
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
                )
            except Exception as exc:
                errors.append(f"{spec.id}: recent read for {dimension} failed: {exc}")
                recent_cache[dimension] = {}
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
                    )
                )
            except Exception as exc:
                errors.append(f"{spec.id}: profile read failed: {exc}")

        await _evaluate_entities(
            db, spec, observations=observations, roles=roles, results=results, errors=errors
        )

    lead_outcome: LeadOutcome | None = None
    sweep = PriorSweep(
        results=tuple(results),
        errors=tuple(errors),
        notes=tuple(notes),
        evaluated_specs=tuple(s.id for s in priors),
    )
    if record:
        try:
            lead_outcome = await _record_and_form(db, results, cidrs=cidrs, shadow_ids=shadow_ids)
        except Exception as exc:
            errors.append(f"could not record the observations: {exc}")
        try:
            from soc_ai.store import prior_spec_runs  # noqa: PLC0415 - lazy, avoids a cycle

            await prior_spec_runs.record_sweep(db, sweep)
        except Exception as exc:
            errors.append(f"could not record the sweep trail: {exc}")

    return PriorSweep(
        results=sweep.results,
        errors=tuple(errors),
        notes=tuple(notes),
        leads=lead_outcome,
        evaluated_specs=sweep.evaluated_specs,
    )


async def _record_and_form(
    db: AsyncSession,
    results: Sequence[PriorResult],
    *,
    cidrs: Sequence[Any] = (),
    shadow_ids: frozenset[str] = frozenset(),
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
                # The SAME phrasing the CLI renders. Written separately, the
                # stored summary kept saying "novel connection_rate" for a rate
                # that had collapsed -- a new thing appearing, where the truth
                # was an existing one stopping.
                summary=(
                    f"{phrase(result.kind, departure)}. "
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
            )
    return await form_leads(db, entity_keys=sorted(touched))


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


def format_sweep(sweep: PriorSweep) -> str:
    """A human-readable rendering, for the CLI and for a run summary.

    The per-spec table is the part worth having. A total of "542 blind" tells
    an operator almost nothing; "this prior was blind on every entity because
    no host has a confident hypervisor role" tells them what to fix. Coverage
    that cannot be acted on is only slightly better than no coverage report.
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
        per_spec[result.spec_id][result.coverage] = (
            per_spec[result.spec_id].get(result.coverage, 0) + 1
        )
    if per_spec:
        lines.append("  per spec:")
        for spec_id in sorted(per_spec):
            breakdown = ", ".join(f"{k}={v}" for k, v in sorted(per_spec[spec_id].items()))
            scorable = per_spec[spec_id].get(COVERAGE_MEASURED, 0)
            mark = " " if scorable else "!"
            lines.append(f"   {mark} {spec_id:48} {breakdown}")
        if any(not v.get(COVERAGE_MEASURED) for v in per_spec.values()):
            lines.append(
                "   ! = this prior could not be scored against any entity. It is "
                "not evidence of a clean network"
            )

    for result in sweep.fired:
        lines.append(f"  [{result.spec_id}] {result.entity_kind}:{result.entity_key}")
        for departure in result.departures:
            lines.append(
                f"      {phrase(result.kind, departure)}. "
                f"{baseline_sentence(departure.baseline_size, departure.support_days)}"
            )
    if sweep.leads is not None:
        outcome = sweep.leads
        lines.append(
            f"  leads: {len(outcome.formed)} formed, {len(outcome.updated)} updated, "
            f"{len(outcome.fleet_conditions)} recorded as fleet conditions"
        )
        for note in outcome.notes:
            lines.append(f"    {note}")

    for note in sweep.notes:
        lines.append(f"  note: {note}")
    for err in sweep.errors:
        lines.append(f"  error: {err}")
    return "\n".join(lines)

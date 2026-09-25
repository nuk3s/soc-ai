"""Hunt catalog read-model: every declarative spec, joined to its sweep trail.

One GET over the shipped catalog and the ``hunt_spec_sweeps`` table. The join
is by spec id and it is a LEFT join: a spec that has never been swept still
appears, with nulls where the trail has nothing to say, because absence from
the list would read as "not installed" and a fabricated zero row would read as
"swept, saw nothing". Both are the confusion the table exists to end.

Analyst-readable, not admin-gated. Whether the catalog is working — swept
recently, seeing its telemetry, still firing — is the analyst's question, the
same way the hunts list is. It names no secrets, no paths, and no posture an
analyst role should not see.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from fastapi import Request
from pydantic import BaseModel

from soc_ai.api.webui._shared import _iso_z, router
from soc_ai.hunting.catalog_tiers import effective_catalog
from soc_ai.hunting.window import sweep_window
from soc_ai.store import hunt_spec_sweeps as sweeps_svc
from soc_ai.store import prior_spec_runs


class PriorCoverageOut(BaseModel):
    """What the prior sweep last concluded about one profile spec.

    Counts are (spec, entity) evaluations. ``measured`` is the only state a
    departure can be scored in; a spec whose ``measured`` is zero was not
    scored against a single entity, and that is not evidence of a clean
    network — the row has to be able to say so.
    """

    last_run_at: str | None
    measured: int
    learning: int
    blind: int
    not_applicable: int
    fired: int
    shadow: bool
    # What the sweep knew about its baselines. ``profiles_built_at`` is the
    # newest baseline it read; ``profiles_stale`` is its verdict on that;
    # ``profiles_reason`` is why a dimension could not be measured. All three
    # are empty for a run recorded before the trail carried them.
    profiles_built_at: str | None = None
    profiles_stale: bool = False
    profiles_reason: str | None = None


class HuntCatalogSpecOut(BaseModel):
    """One spec with what the trail knows about it.

    The ``last_*`` fields read the trail's whole retention and are ``None``
    only when it has nothing; the ``*_24h`` fields are a rate. ``blind`` is
    the NEWEST sweep's fact — a never-swept spec reads ``False`` here, and its
    ``last_swept_at`` of ``None`` is what says the eyesight is untested.
    ``shadow_24h`` is how many of the window's sweeps were shadow runs: they
    count toward ``fresh_24h`` and never toward ``fired_24h``, so the page
    needs it to say why fresh can outrun fired on a spec that is working.
    """

    id: str
    title: str
    level: str
    scope_kind: str
    attack: list[str]

    # Which loop runs this spec. ``match`` specs are swept by the catalog
    # sweep and every ``last_*``/``*_24h`` field below describes that sweep.
    # ``profile`` specs are answered from stored behavioural baselines by
    # ``soc-ai priors`` and are NOT swept here — their trail fields describe a
    # loop that no longer runs them, which is why the page has to be able to
    # tell the two apart. Without it, twelve specs rendered as rows of zeros
    # under a green "Sweeps on" and read as quiet rather than as unswept.
    evaluator: str = "match"
    # Which tier the analytic comes from, and whether it runs. A shipped
    # analytic is a file in the repository; a local one is a row an analyst
    # wrote. A retired or candidate analytic is listed and does NOT run, and
    # the row has to say so: rendered without the status, a retired analytic
    # reads as one that has simply gone quiet.
    tier: str = "shipped"
    status: str = "live"
    # The prior sweep's newest verdict for a ``profile`` spec; None for a
    # ``match`` spec or a profile spec that has never been run.
    coverage: PriorCoverageOut | None = None

    last_swept_at: str | None
    last_fired_at: str | None
    blind: bool
    last_error: str | None
    sweeps_24h: int
    fired_24h: int
    fresh_24h: int
    already_handled_24h: int
    shadow_24h: int
    # The NEWEST sweep's three unaccounted-for counts. All zero for a
    # never-swept spec, whose ``last_swept_at`` of ``None`` is the fact about
    # it. Nothing else on the row can carry any of them, and they are three
    # different failures, not three names for one:
    #
    # ``undecided_docs`` — discarded because an exclusion reads a field they
    # do not carry, so they were neither matched nor ruled out. Such a run
    # matches nothing and buckets nothing, so every counter reads zero, which
    # is also what a healthy quiet spec reads.
    #
    # ``unattributed_docs`` — they matched and produced no scope bucket, so
    # they are inside ``matched_docs`` and inside no candidate. The gate then
    # drops the candidates that did surface and the row reads fired 0 · fresh
    # 0 over documents the detection genuinely hit.
    #
    # ``truncated_docs`` — scopes the grid never returned because the bucket
    # ceiling was hit, from the aggregation's own ``sum_other_doc_count``. The
    # only one of the three where the counters are non-zero: they are a real
    # number that is too small, and an under-report reads as a full count.
    undecided_docs: int
    unattributed_docs: int
    truncated_docs: int


class HuntCatalogOut(BaseModel):
    """The catalog plus the loop's settings, read live.

    The settings ride along because the page cannot otherwise tell a quiet
    grid from nobody looking: four rows of zeros mean one thing with the loop
    on and another with it off. ``last_sweep_at`` is the newest row across the
    whole trail, catalog membership aside — a row from a since-removed spec
    still proves the loop ran.

    The interval and the window are the EFFECTIVE values, after the floor and
    the clamp in :mod:`soc_ai.hunting.window`, not the settings as typed. The
    page's fact is what a sweep covers, and the trail rows record the clamped
    window; reporting the raw setting had the panel say "looks back 60m" over
    rows that said 61.
    """

    specs: list[HuntCatalogSpecOut]
    sweeps_enabled: bool
    sweep_interval_minutes: int
    sweep_window_minutes: int
    last_sweep_at: str | None


def _coverage_out(run: Any) -> PriorCoverageOut | None:
    if run is None:
        return None
    built = getattr(run, "profiles_built_at", None)
    return PriorCoverageOut(
        last_run_at=_iso_z(run.created_at),
        measured=int(run.measured or 0),
        learning=int(run.learning or 0),
        blind=int(run.blind or 0),
        not_applicable=int(run.not_applicable or 0),
        fired=int(run.fired or 0),
        shadow=bool(run.shadow),
        profiles_built_at=_iso_z(built) if built is not None else None,
        profiles_stale=bool(getattr(run, "profiles_stale", False)),
        profiles_reason=getattr(run, "profiles_reason", None) or None,
    )


@router.get("/hunt-catalog", response_model=HuntCatalogOut)
async def get_hunt_catalog(request: Request) -> HuntCatalogOut:
    """Every catalog spec, in catalog order, with its sweep status."""
    settings = request.app.state.settings
    now = datetime.now(UTC).replace(tzinfo=None)
    async with request.app.state.db_sessionmaker() as db:
        # The effective catalog, so a retired analytic and a local one in
        # shadow both appear with the status that says whether they run.
        cat = await effective_catalog(db)
        status = await sweeps_svc.catalog_status(db, now=now)
        prior_runs = await prior_spec_runs.newest(db)

    catalog = cat.listed
    specs: list[HuntCatalogSpecOut] = []
    for spec in catalog.values():
        s = status.get(spec.id)
        tier, spec_status = cat.status_of(spec.id)
        specs.append(
            HuntCatalogSpecOut(
                id=spec.id,
                title=spec.title,
                level=spec.level,
                scope_kind=spec.scope_kind,
                attack=list(spec.attack),
                evaluator=spec.evaluator,
                tier=tier,
                status=spec_status,
                coverage=_coverage_out(prior_runs.get(spec.id)),
                last_swept_at=_iso_z(s.last_swept_at) if s else None,
                last_fired_at=_iso_z(s.last_fired_at) if s else None,
                blind=s.blind if s else False,
                last_error=s.last_error if s else None,
                sweeps_24h=s.sweeps_24h if s else 0,
                fired_24h=s.fired_24h if s else 0,
                fresh_24h=s.fresh_24h if s else 0,
                already_handled_24h=s.already_handled_24h if s else 0,
                shadow_24h=s.shadow_24h if s else 0,
                undecided_docs=s.undecided_docs if s else 0,
                unattributed_docs=s.unattributed_docs if s else 0,
                truncated_docs=s.truncated_docs if s else 0,
            )
        )
    # Only the specs THIS loop sweeps may set the header's timestamp. Taking
    # the max across every spec let four healthy ones speak for twelve the
    # catalog sweep no longer touches, so the panel reported "Sweeps on · last
    # sweep 37m ago" in green over nine rows last swept 23 hours earlier.
    swept_ids = {s.id for s in catalog.values() if s.evaluator == "match"}
    last_sweep = max(
        (st.last_swept_at for sid, st in status.items() if sid in swept_ids),
        default=None,
    )
    # Computed, not logged: reporting a window is not a sweep, and this is
    # polled every five minutes.
    window = sweep_window(settings)
    return HuntCatalogOut(
        specs=specs,
        sweeps_enabled=bool(getattr(settings, "hunt_spec_sweeps_enabled", False)),
        sweep_interval_minutes=window.interval_minutes,
        sweep_window_minutes=window.window_minutes,
        last_sweep_at=_iso_z(last_sweep),
    )

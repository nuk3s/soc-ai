"""Quality-trend read-model (I4): the nightly micro-eval history for the dashboard.

One admin-gated GET over the ``quality_snapshots`` table — the same pure
read-model idiom as ``/config/egress-policy``: no writes, no derived state the
CLI didn't already persist. In particular the ALARM is served exactly as the
nightly recorded it (``alarmed``/``alarm_reasons`` were computed at write time
against history that may since have been pruned), so the card can never
re-litigate an alarm into a different answer than the one that paged on-call.
"""

from __future__ import annotations

from fastapi import Depends, Request
from pydantic import BaseModel

from soc_ai.api.webui._shared import _iso_utc, require_admin_api, router
from soc_ai.store import quality as quality_svc


class QualityPointOut(BaseModel):
    """One nightly snapshot, in the light shape the sparkline plots.

    ``mode`` labels how the point was measured (``graded`` = oracle critique,
    ``local`` = zero-egress proxies) — the card badges it because the two are
    different instruments: a graded 0.8 agreement and a local null are not
    comparable, and pretending otherwise on one line would be dishonest.
    """

    id: int
    ts: str  # ISO-8601, timezone-aware (store timestamps are naive UTC)
    mode: str  # "local" | "graded"
    n_ok: int
    n_error: int
    agreement_rate: float | None
    fallback_rate: float | None
    error_rate: float
    latency_p50_ms: int | None
    verdict_counts: dict[str, int]
    alarmed: bool
    alarm_reasons: list[str]


class QualityTrendOut(BaseModel):
    points: list[QualityPointOut]  # oldest → newest, ready to plot left-to-right


@router.get(
    "/quality/trend",
    response_model=QualityTrendOut,
    dependencies=[Depends(require_admin_api)],
    tags=["quality"],
)
async def get_quality_trend(request: Request) -> QualityTrendOut:
    """The last 30 nightly quality snapshots, oldest first.

    Feeds the dashboard's Quality card. Admin-gated like the other posture
    read-models (config, egress policy): the trend names the batch artifact
    paths and exposes operational health an analyst role doesn't need.
    Empty list = the nightly has never run — the card renders its
    "schedule soc-ai eval-nightly" empty state from that, not from an error.
    """
    async with request.app.state.db_sessionmaker() as db:
        rows = await quality_svc.recent_snapshots(db, limit=30)
    # The store returns newest-first (its natural "recent" order); the chart
    # wants chronological so a plain reversed() keeps both callers simple.
    return QualityTrendOut(
        points=[
            QualityPointOut(
                id=r.id,
                ts=_iso_utc(r.created_at),
                mode=r.mode,
                n_ok=r.n_ok,
                n_error=r.n_error,
                agreement_rate=r.agreement_rate,
                fallback_rate=r.fallback_rate,
                error_rate=r.error_rate,
                latency_p50_ms=r.latency_p50_ms,
                verdict_counts={str(k): int(v) for k, v in (r.verdict_counts or {}).items()},
                alarmed=r.alarmed,
                alarm_reasons=list(r.alarm_reasons or []),
            )
            for r in reversed(rows)
        ]
    )

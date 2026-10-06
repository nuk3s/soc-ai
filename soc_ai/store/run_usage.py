"""The run cost report: what each entry point spends per run.

``soc-ai usage --days N`` prints it. One row per entry point (the scheduler,
an analyst's first run, a re-run, a backtest, a promotion, each hunt starter),
with the median and the 90th percentile of the tokens, the model requests, the
tool calls, the Elasticsearch searches and the wall time, and the share of each
outcome. It is the table the 2026-10-04 survey computed by hand, so a change
to the ladder has a before and an after measured the same way.

A row stamped by the recorder (migration 0058) carries its counters in
columns. An older row does not, so the report reads what it can from the
row's stored events with the same meter the recorder uses: the model usage of
a triage run and the tool calls of any run. An older hunt stored no model
usage and no run stored a search count, so those cells stay unknown. The
report says unknown with a dash. It never prints a zero for a number the store
does not hold.
"""

from __future__ import annotations

import math
from collections import Counter, defaultdict
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from soc_ai.run_meter import RunMeter
from soc_ai.store.auth import utcnow
from soc_ai.store.models import Hunt, HuntEvent, Investigation, InvestigationEvent

# The event kinds the meter reads. Loading only these keeps the legacy read
# off the large payloads (the enriched context, the report).
_METERED_KINDS = ("usage", "tool_call", "targeted_dispatch")

# Display order. An entry with no run in the window is left out.
ENTRY_ORDER: tuple[str, ...] = (
    "Auto-triage, scheduler",
    "Auto-triage, analyst sweep",
    "Rule prior",
    "Analyst first run",
    "Analyst re-run",
    "Analyst deep re-run",
    "Promotion",
    "Backtest",
    "Eval",
    "Hunt, analyst",
    "Hunt, schedule",
    "Lead hunt, auto",
    "Lead hunt, analyst",
    "Hunt, catalog record",
)

_SCHEDULER_ACTOR = "auto-triage:scheduler"
_SWEEP_PREFIX = "auto-triage:"
_BACKTEST_ACTOR = "backtest"
_EVAL_ACTORS = frozenset({"journey-eval"})
_AUTO_HUNT_ACTOR = "auto-hunt"
_PROMOTED_KINDS = frozenset({"hunt", "lead"})


@dataclass(frozen=True)
class Spread:
    """The median and the 90th percentile over the runs that report a number."""

    known: int
    p50: float | None
    p90: float | None


@dataclass
class EntryUsage:
    """One entry point's runs in the window."""

    entry: str
    runs: int = 0
    with_counters: int = 0
    tokens: Spread = field(default_factory=lambda: Spread(0, None, None))
    requests: Spread = field(default_factory=lambda: Spread(0, None, None))
    tool_calls: Spread = field(default_factory=lambda: Spread(0, None, None))
    searches: Spread = field(default_factory=lambda: Spread(0, None, None))
    wall_s: Spread = field(default_factory=lambda: Spread(0, None, None))
    outcomes: dict[str, int] = field(default_factory=dict)


@dataclass(frozen=True)
class UsageReport:
    days: int
    since: datetime
    entries: list[EntryUsage]

    @property
    def runs(self) -> int:
        return sum(e.runs for e in self.entries)

    @property
    def with_counters(self) -> int:
        return sum(e.with_counters for e in self.entries)


@dataclass
class _RunCost:
    """One run's numbers. ``None`` is a number the store does not hold."""

    tokens: int | None
    requests: int | None
    tool_calls: int | None
    searches: int | None
    wall_s: float | None
    stamped: bool


def percentile(values: Sequence[float], q: float) -> float | None:
    """Nearest-rank percentile. ``None`` for an empty list."""
    if not values:
        return None
    ordered = sorted(values)
    rank = max(1, math.ceil(q * len(ordered)))
    return float(ordered[rank - 1])


def _spread(values: Iterable[float | int | None]) -> Spread:
    known = [float(v) for v in values if v is not None]
    if not known:
        return Spread(0, None, None)
    return Spread(len(known), percentile(known, 0.5), percentile(known, 0.9))


def _wall_seconds(created: datetime | None, finished: datetime | None) -> float | None:
    if created is None or finished is None:
        return None
    return max(0.0, (finished - created).total_seconds())


def _stamped_cost(row: Investigation | Hunt) -> _RunCost:
    tokens = None
    if row.input_tokens is not None or row.output_tokens is not None:
        tokens = int(row.input_tokens or 0) + int(row.output_tokens or 0)
    return _RunCost(
        tokens=tokens,
        requests=row.model_requests,
        tool_calls=row.tool_calls,
        searches=row.es_searches,
        wall_s=(row.wall_ms / 1000.0)
        if row.wall_ms is not None
        else _wall_seconds(row.created_at, row.finished_at),
        stamped=True,
    )


def _legacy_cost(row: Investigation | Hunt, events: list[tuple[str, Any]]) -> _RunCost:
    """Derive what an unstamped row's events can say, with the recorder's meter."""
    meter = RunMeter()
    saw_usage = False
    for kind, payload in events:
        if kind == "usage":
            saw_usage = True
        meter.observe(kind, payload)
    counted = meter.finish()
    tokens = counted.input_tokens + counted.output_tokens if saw_usage else None
    return _RunCost(
        tokens=tokens,
        requests=counted.model_requests if saw_usage else None,
        tool_calls=counted.tool_calls,
        # No run before migration 0058 counted its grid reads.
        searches=None,
        wall_s=_wall_seconds(row.created_at, row.finished_at),
        stamped=False,
    )


def _is_stamped(row: Investigation | Hunt) -> bool:
    return row.wall_ms is not None


def investigation_entry(inv: Investigation, *, earlier_run: bool) -> str:
    """The entry point that started this triage run."""
    started_by = inv.started_by or ""
    subject = inv.subject_json if isinstance(inv.subject_json, dict) else {}
    if inv.run_class == "rule_prior":
        return "Rule prior"
    if inv.is_synth_eval or started_by in _EVAL_ACTORS:
        return "Eval"
    if started_by == _BACKTEST_ACTOR:
        return "Backtest"
    if inv.kind in _PROMOTED_KINDS or subject.get("type") == "hunt":
        return "Promotion"
    if started_by == _SCHEDULER_ACTOR:
        return "Auto-triage, scheduler"
    if started_by.startswith(_SWEEP_PREFIX):
        return "Auto-triage, analyst sweep"
    if inv.run_class == "deep":
        return "Analyst deep re-run"
    return "Analyst re-run" if earlier_run else "Analyst first run"


def hunt_entry(hunt: Hunt) -> str:
    """The entry point that started this hunt."""
    if hunt.starter == "lead":
        return "Lead hunt, auto" if hunt.started_by == _AUTO_HUNT_ACTOR else "Lead hunt, analyst"
    if hunt.starter == "schedule" or hunt.kind == "scheduled":
        return "Hunt, schedule"
    if hunt.starter == "catalog" or hunt.kind == "triggered":
        return "Hunt, catalog record"
    return "Hunt, analyst"


def investigation_outcome(inv: Investigation) -> str:
    if inv.status != "complete":
        return inv.status or "unknown"
    if inv.is_fallback:
        return "fallback"
    return {
        "false_positive": "fp",
        "true_positive": "tp",
        "needs_more_info": "nmi",
    }.get(inv.verdict or "", inv.verdict or "no verdict")


def hunt_outcome(hunt: Hunt) -> str:
    if hunt.status != "complete":
        return hunt.status or "unknown"
    return "threat" if (hunt.threat_findings_count or 0) > 0 else "no threat"


async def _events_by_run(
    db: AsyncSession, model: Any, fk: Any, ids: Sequence[str]
) -> dict[str, list[tuple[str, Any]]]:
    out: dict[str, list[tuple[str, Any]]] = defaultdict(list)
    if not ids:
        return out
    # Chunked IN lists: SQLite caps bound parameters per statement.
    for start in range(0, len(ids), 500):
        chunk = list(ids[start : start + 500])
        rows = await db.execute(
            select(fk, model.kind, model.payload)
            .where(fk.in_(chunk), model.kind.in_(_METERED_KINDS))
            .order_by(fk, model.sequence)
        )
        for run_id, kind, payload in rows.all():
            out[str(run_id)].append((str(kind), payload))
    return out


async def _earlier_run_ids(db: AsyncSession, invs: Sequence[Investigation]) -> set[str]:
    """The window's runs whose alert already had an earlier run, at any age."""
    alert_ids = sorted({i.alert_es_id for i in invs if i.alert_es_id})
    first_by_alert: dict[str, tuple[datetime, str]] = {}
    for start in range(0, len(alert_ids), 500):
        chunk = alert_ids[start : start + 500]
        rows = await db.execute(
            select(Investigation.alert_es_id, Investigation.created_at, Investigation.id).where(
                Investigation.alert_es_id.in_(chunk)
            )
        )
        for alert_id, created, inv_id in rows.all():
            key = (created, inv_id)
            current = first_by_alert.get(alert_id)
            if current is None or key < current:
                first_by_alert[alert_id] = key
    return {
        i.id
        for i in invs
        if i.alert_es_id
        and first_by_alert.get(i.alert_es_id, (i.created_at, i.id)) != (i.created_at, i.id)
    }


def _fold(entry: str, rows: list[tuple[_RunCost | None, str]]) -> EntryUsage:
    costs = [c for c, _ in rows if c is not None]
    return EntryUsage(
        entry=entry,
        runs=len(rows),
        with_counters=sum(1 for c in costs if c.stamped),
        tokens=_spread(c.tokens for c in costs),
        requests=_spread(c.requests for c in costs),
        tool_calls=_spread(c.tool_calls for c in costs),
        searches=_spread(c.searches for c in costs),
        wall_s=_spread(c.wall_s for c in costs),
        outcomes=dict(Counter(outcome for _, outcome in rows)),
    )


async def usage_report(db: AsyncSession, *, days: int, now: datetime | None = None) -> UsageReport:
    """The per-entry-point cost of every run created in the last ``days`` days.

    A run still ``running`` counts toward the run total and the outcome
    shares. It adds no cost: its counters are not written until it ends.
    """
    since = (now or utcnow()) - timedelta(days=days)
    invs = list(
        (await db.scalars(select(Investigation).where(Investigation.created_at >= since))).all()
    )
    hunts = list((await db.scalars(select(Hunt).where(Hunt.created_at >= since))).all())

    legacy_inv_ids = [i.id for i in invs if not _is_stamped(i) and i.status != "running"]
    legacy_hunt_ids = [h.id for h in hunts if not _is_stamped(h) and h.status != "running"]
    inv_events = await _events_by_run(
        db, InvestigationEvent, InvestigationEvent.investigation_id, legacy_inv_ids
    )
    hunt_events = await _events_by_run(db, HuntEvent, HuntEvent.hunt_id, legacy_hunt_ids)
    earlier = await _earlier_run_ids(db, invs)

    grouped: dict[str, list[tuple[_RunCost | None, str]]] = defaultdict(list)
    for inv in invs:
        cost: _RunCost | None = None
        if inv.status != "running":
            cost = (
                _stamped_cost(inv)
                if _is_stamped(inv)
                else _legacy_cost(inv, inv_events.get(inv.id, []))
            )
        entry = investigation_entry(inv, earlier_run=inv.id in earlier)
        grouped[entry].append((cost, investigation_outcome(inv)))
    for hunt in hunts:
        cost = None
        if hunt.status != "running":
            cost = (
                _stamped_cost(hunt)
                if _is_stamped(hunt)
                else _legacy_cost(hunt, hunt_events.get(hunt.id, []))
            )
        grouped[hunt_entry(hunt)].append((cost, hunt_outcome(hunt)))

    entries = [_fold(name, grouped[name]) for name in ENTRY_ORDER if grouped.get(name)]
    return UsageReport(days=days, since=since, entries=entries)


def _fmt_number(value: float | None, *, tokens: bool = False) -> str:
    if value is None:
        return "-"
    if tokens and value >= 1000:
        return f"{value / 1000:.1f}K"
    if value == int(value):
        return str(int(value))
    return f"{value:.1f}"


def _fmt_spread(spread: Spread, *, tokens: bool = False) -> str:
    if spread.known == 0:
        return "-"
    return f"{_fmt_number(spread.p50, tokens=tokens)} / {_fmt_number(spread.p90, tokens=tokens)}"


def _fmt_outcomes(outcomes: dict[str, int], runs: int) -> str:
    if not runs:
        return "-"
    parts = sorted(outcomes.items(), key=lambda kv: (-kv[1], kv[0]))
    return " ".join(f"{name} {round(100 * n / runs)}%" for name, n in parts)


def format_usage(report: UsageReport) -> str:
    """The report as a fixed-width table, with the reading rules under it."""
    header = (
        "entry",
        "runs",
        "tokens p50/p90",
        "requests p50/p90",
        "tools p50/p90",
        "searches p50/p90",
        "wall s p50/p90",
        "outcomes",
    )
    rows = [
        (
            e.entry,
            str(e.runs),
            _fmt_spread(e.tokens, tokens=True),
            _fmt_spread(e.requests),
            _fmt_spread(e.tool_calls),
            _fmt_spread(e.searches),
            _fmt_spread(e.wall_s),
            _fmt_outcomes(e.outcomes, e.runs),
        )
        for e in report.entries
    ]
    widths = [max(len(r[i]) for r in [header, *rows]) for i in range(len(header) - 1)]

    def _line(cells: tuple[str, ...]) -> str:
        left = cells[0].ljust(widths[0])
        middle = "  ".join(c.rjust(w) for c, w in zip(cells[1:-1], widths[1:], strict=True))
        return f"{left}  {middle}  {cells[-1]}"

    lines = [
        f"Runs created since {report.since.isoformat(timespec='minutes')} UTC "
        f"({report.days} days).",
        "",
    ]
    if not rows:
        lines.append("No run in this window.")
        return "\n".join(lines)
    lines.append(_line(header))
    lines.extend(_line(r) for r in rows)
    lines.append("")
    lines.append(
        f"Counters on {report.with_counters} of {report.runs} runs. An older run "
        "reads its tokens and its tool calls from its stored events."
    )
    lines.append(
        "A dash is a number the store does not hold. No run before the counters "
        "counted its grid searches, and no hunt recorded its model usage."
    )
    lines.append(
        "Tools counts the tools the model called and the tools the pipeline "
        "called in code. A running run adds to the runs and the outcomes only."
    )
    return "\n".join(lines)


__all__ = [
    "ENTRY_ORDER",
    "EntryUsage",
    "Spread",
    "UsageReport",
    "format_usage",
    "hunt_entry",
    "investigation_entry",
    "percentile",
    "usage_report",
]

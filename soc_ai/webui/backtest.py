"""Backtest — "prove it on my last N days" replay of the agent over already-dispositioned alerts.

The single most convincing adoption artifact: point soc-ai at a historical
window of alerts an analyst ALREADY dispositioned in Security Onion, replay the
agent's triage over a diverse sample, and report how soc-ai's verdicts compare
to the human's REAL disposition — not marketing numbers, the operator's own
last-N-days.

Ground truth (the analyst's real call, read from ES):
  - ``event.escalated:true``  ⇒ expected ``true_positive``  (high confidence — the
    analyst escalated it to an incident).
  - ``event.acknowledged:true`` AND NOT escalated ⇒ expected ``false_positive``.
    This is a PROXY, not certainty: an analyst acks an alert for many reasons
    (triaged benign, dismissed, bulk-cleared). The report surfaces the caveat.
Only alerts carrying one of these dispositions are sampled — i.e. the analyst
actually made a call — so every row has a ground-truth label to score against.

The replay reuses the existing recorded-run primitive (:func:`run_recorded`),
exactly like auto-triage: each sampled alert is a full agent investigation, then
its persisted :class:`Investigation` verdict is read back and compared. A
single-flight :class:`BacktestStatus` on ``app.state`` drives the background job;
:func:`start_backtest` plans + launches and never raises.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from typing import Any

from soc_ai.api.deps import ctx_from_state
from soc_ai.api.runner import run_recorded
from soc_ai.so_client.fields import get_dotted
from soc_ai.store import backtests as bt_svc
from soc_ai.store import investigations as inv_svc
from soc_ai.webui import alerts_query as aq

_LOGGER = logging.getLogger(__name__)

_STATE_ATTR = "_backtest_status"

# Ground-truth disposition labels + the soc-ai verdict they map to.
HUMAN_TP = "true_positive"  # analyst escalated
HUMAN_FP = "false_positive"  # analyst acked, not escalated
DISPOSITIONS = (HUMAN_TP, HUMAN_FP)

# soc-ai verdict strings the confusion matrix buckets. Anything else a row
# carries (e.g. a nameless error) is normalized to "no_verdict".
SOC_VERDICTS = ("true_positive", "false_positive", "needs_more_info")
NO_VERDICT = "no_verdict"

# Default + hard-cap requested sample size are enforced in the API layer; the
# service honours whatever list of targets it is handed.
DEFAULT_SAMPLE_SIZE = 20


# ---------------------------------------------------------------------------
# Metrics — a PURE helper so the math is unit-testable without ES or an agent.
# ---------------------------------------------------------------------------


def score(rows: list[dict[str, Any]]) -> dict[str, Any]:
    """Aggregate backtest metrics from per-alert ``(human_disposition, soc_ai_verdict)`` rows.

    Each row is a dict with at least ``human_disposition`` (one of
    :data:`DISPOSITIONS`) and ``soc_ai_verdict`` (a soc-ai verdict string, or
    ``None``/``"no_verdict"`` when the replay produced none). Extra keys
    (``alert_id``, ``rule_name`` …) are passed through untouched. Pure: no I/O.

    Returns:
      - ``agreement_rate``: fraction where soc-ai's verdict matches the human
        disposition (TP↔escalated, FP↔acked-not-escalated), over ALL rows.
      - ``fp_reduction``: of the human-FP (acked) rows, the fraction soc-ai also
        called ``false_positive`` — the toil soc-ai would have auto-cleared.
      - ``missed_tp``: of the human-TP (escalated) rows, the COUNT soc-ai called
        ``false_positive`` — the CRITICAL safety number (a missed real incident).
      - ``missed_tp_rows``: those rows, so the report can list them.
      - ``confusion``: counts by ``human_disposition`` x ``soc_ai_verdict``.
      - ``n_needs_more_info``: rows where soc-ai hedged.
      - ``counts``: totals (``total``, ``human_tp``, ``human_fp``, ``agreements``).
    """
    total = len(rows)
    human_tp = [r for r in rows if r.get("human_disposition") == HUMAN_TP]
    human_fp = [r for r in rows if r.get("human_disposition") == HUMAN_FP]

    def _verdict(r: dict[str, Any]) -> str:
        v = r.get("soc_ai_verdict")
        return v if v in SOC_VERDICTS else NO_VERDICT

    agreements = sum(1 for r in rows if _verdict(r) == r.get("human_disposition"))

    # fp_reduction: of human-FP alerts, share soc-ai ALSO called false_positive.
    fp_cleared = sum(1 for r in human_fp if _verdict(r) == HUMAN_FP)
    fp_reduction = (fp_cleared / len(human_fp)) if human_fp else 0.0

    # missed_tp: human-TP alerts soc-ai called false_positive (the dangerous miss).
    missed_tp_rows = [r for r in human_tp if _verdict(r) == HUMAN_FP]

    n_needs_more_info = sum(1 for r in rows if _verdict(r) == "needs_more_info")

    # Confusion matrix: human disposition → {soc verdict: count}.
    confusion: dict[str, dict[str, int]] = {
        HUMAN_TP: {v: 0 for v in (*SOC_VERDICTS, NO_VERDICT)},
        HUMAN_FP: {v: 0 for v in (*SOC_VERDICTS, NO_VERDICT)},
    }
    for r in rows:
        disp = r.get("human_disposition")
        if disp in confusion:
            confusion[disp][_verdict(r)] += 1

    return {
        "agreement_rate": (agreements / total) if total else 0.0,
        "fp_reduction": fp_reduction,
        "missed_tp": len(missed_tp_rows),
        "missed_tp_rows": missed_tp_rows,
        "n_needs_more_info": n_needs_more_info,
        "confusion": confusion,
        "counts": {
            "total": total,
            "human_tp": len(human_tp),
            "human_fp": len(human_fp),
            "agreements": agreements,
            "fp_cleared": fp_cleared,
        },
    }


# ---------------------------------------------------------------------------
# Single-flight status on app.state (mirrors AutoTriageStatus).
# ---------------------------------------------------------------------------


@dataclass
class BacktestSample:
    """One sampled, already-dispositioned alert to replay."""

    alert_es_id: str
    rule_name: str
    human_disposition: str  # HUMAN_TP | HUMAN_FP


@dataclass
class BacktestStatus:
    active: bool = False
    backtest_id: str | None = None
    total: int = 0
    replayed: int = 0
    failed: int = 0
    finished_at: str | None = None
    # live progress: the rule name (or alert id) currently being replayed
    current: str | None = None
    # a short human note (e.g. "capped to 50", "nothing to replay")
    note: str | None = None
    # internal: keep a reference to the running task to prevent GC
    _task: asyncio.Task[None] | None = field(default=None, repr=False, compare=False)

    def reset(self, *, active: bool, total: int, backtest_id: str | None) -> None:
        self.active = active
        self.backtest_id = backtest_id
        self.total = total
        self.replayed = 0
        self.failed = 0
        self.finished_at = None
        self.current = None
        self.note = None


def get_status(state: Any) -> BacktestStatus:
    """Lazily attach a :class:`BacktestStatus` to *app.state* and return it."""
    if not hasattr(state, _STATE_ATTR):
        setattr(state, _STATE_ATTR, BacktestStatus())
    return getattr(state, _STATE_ATTR)  # type: ignore[no-any-return]


# ---------------------------------------------------------------------------
# Sampling — dispositioned alerts only, diverse across (rule, disposition).
# ---------------------------------------------------------------------------


def _disposition_of(source: dict[str, Any]) -> str | None:
    """Map an alert's ES ``_source`` disposition flags to a ground-truth label.

    escalated ⇒ true_positive (takes precedence); acked-and-not-escalated ⇒
    false_positive; neither ⇒ None (the analyst made no call — skip it).
    """
    escalated = bool(get_dotted(source, "event.escalated"))
    acked = bool(get_dotted(source, "event.acknowledged"))
    if escalated:
        return HUMAN_TP
    if acked:
        return HUMAN_FP
    return None


async def plan_samples(
    state: Any,
    *,
    window_days: int,
    sample_size: int,
    min_severity: str | None,
) -> list[BacktestSample]:
    """Sample up to ``sample_size`` already-dispositioned alerts from the window.

    Queries ES for alerts within the last ``window_days`` that carry a
    disposition (``event.escalated`` OR ``event.acknowledged``), honouring
    ``min_severity`` (a floor: that severity and above) and the configured alert
    source scope. Diversity: one alert per (rule.name, human_disposition) key,
    so a single noisy escalated/acked rule can't saturate the sample — every
    distinct disposed rule gets a representative, escalated alerts preferred
    (they carry the safety-critical TP label). Newest-first within a key.

    Never raises — an ES failure logs and returns an empty list so the caller
    lands a clean, empty backtest rather than crashing.
    """
    settings = state.settings
    elastic = state.elastic

    # Only alerts the analyst actually dispositioned. Reuse the alerts-console
    # source scope (Suricata primary + optional Sigma) so we replay the same
    # feed the operator triages, then require a disposition flag.
    dataset_oqls = [settings.webui_alerts_query]
    if getattr(settings, "webui_extra_detections", False):
        dataset_oqls.append(aq.SIGMA_SOURCE_OQL)

    time_range = _window_range(window_days)
    severity_floor = _severity_band(min_severity)

    # Fetch a generous page (up to 500) of dispositioned alerts newest-first,
    # then diversify down to sample_size. 500 is plenty at this lab's scale to
    # find sample_size (≤ 50) distinct (rule, disposition) keys.
    query = aq.build_filter(
        settings,
        time_range=time_range,
        severity=None,  # severity floor handled below (a band, not one level)
        oql=None,
        dataset_oqls=dataset_oqls,
    )
    # Require a disposition flag.
    query["bool"]["filter"].append(
        {
            "bool": {
                "should": [
                    {"term": {"event.escalated": True}},
                    {"term": {"event.acknowledged": True}},
                ],
                "minimum_should_match": 1,
            }
        }
    )
    if severity_floor:
        query["bool"]["filter"].append(
            {"terms": {"event.severity_label": list(severity_floor)}}
        )

    try:
        result = await elastic.search(
            settings.events_index_pattern,
            query,
            size=500,
            sort=[{"@timestamp": {"order": "desc"}}],
        )
    except Exception:
        _LOGGER.exception("backtest: dispositioned-alert sampling query failed")
        return []

    seen: set[tuple[str, str]] = set()
    samples: list[BacktestSample] = []
    for hit in result.hits:
        if len(samples) >= sample_size:
            break
        alert_id = str(hit.get("_id", ""))
        if not alert_id:
            continue
        source = hit.get("_source", {}) or {}
        disposition = _disposition_of(source)
        if disposition is None:
            continue
        rule_name = (
            get_dotted(source, "rule.name")
            or get_dotted(source, "event.dataset")
            or get_dotted(source, "event.category")
            or ""
        )
        key = (str(rule_name), disposition)
        if key in seen:
            continue
        seen.add(key)
        samples.append(
            BacktestSample(
                alert_es_id=alert_id,
                rule_name=str(rule_name),
                human_disposition=disposition,
            )
        )
    _LOGGER.info(
        "backtest: sampled %d dispositioned alerts (scanned %d hits, window=%dd, floor=%s)",
        len(samples),
        len(result.hits),
        window_days,
        min_severity or "none",
    )
    return samples


def _window_range(window_days: int) -> str:
    """Map a window in days to the alerts-console range preset, clamped to its keys.

    The console's presets top out at ``30d``; a wider request is clamped to that
    (and the report shows the requested window in ``params``).
    """
    if window_days <= 1:
        return "24h"
    if window_days <= 3:
        return "3d"
    if window_days <= 7:
        return "7d"
    return "30d"


def _severity_band(min_severity: str | None) -> tuple[str, ...]:
    """The severity band at/above ``min_severity`` (empty ⇒ all severities)."""
    if not min_severity:
        return ()
    ladder = list(aq.SEVERITIES)  # ("critical", "high", "medium", "low")
    if min_severity not in ladder:
        return ()
    idx = ladder.index(min_severity)
    return tuple(ladder[: idx + 1])


# ---------------------------------------------------------------------------
# Replay + compare — the background worker.
# ---------------------------------------------------------------------------


async def _replay_one(state: Any, ctx: Any, sample: BacktestSample) -> str | None:
    """Replay one sampled alert through the agent, return soc-ai's verdict.

    Drains :func:`run_recorded` (which persists an :class:`Investigation`), then
    reads that row's verdict back by ``alert_es_id``. Returns the verdict string,
    or ``None`` if the run errored / produced no verdict. Never raises — the
    caller counts a failure and moves on so one bad alert can't abort the run.
    """
    started_by = "backtest"
    try:
        async for name, _data in run_recorded(
            state,
            ctx=ctx,
            alert_id=sample.alert_es_id,
            started_by=started_by,
            rule_name=sample.rule_name or None,
        ):
            if name == "error":
                _LOGGER.warning("backtest: stream error for alert_id=%s", sample.alert_es_id)
    except Exception:
        _LOGGER.exception("backtest: replay failed for alert_id=%s", sample.alert_es_id)
        return None

    # Read the just-recorded verdict back off the Investigation row.
    try:
        async with state.db_sessionmaker() as db:
            latest = await inv_svc.latest_for_alerts(db, [sample.alert_es_id])
    except Exception:
        _LOGGER.exception("backtest: verdict read-back failed for alert_id=%s", sample.alert_es_id)
        return None
    inv = latest.get(sample.alert_es_id)
    if inv is None:
        return None
    return inv.verdict


async def run_backtest(
    state: Any,
    *,
    backtest_id: str,
    samples: list[BacktestSample],
    params: dict[str, Any],
) -> None:
    """Sequential worker: replay each sample, compare to disposition, land metrics.

    Reuses the recorded-run primitive per sample (same as auto-triage). Failures
    are logged + counted; they never abort the remaining samples. Finalizes the
    backtest row with the scored metrics + per-alert rows and sets ``active=False``
    when done. Never raises.
    """
    status = get_status(state)
    rows: list[dict[str, Any]] = []
    try:
        ctx = ctx_from_state(state)
        for sample in samples:
            label = sample.rule_name or sample.alert_es_id
            status.current = label
            verdict = await _replay_one(state, ctx, sample)
            rows.append(
                {
                    "alert_id": sample.alert_es_id,
                    "rule_name": sample.rule_name,
                    "human_disposition": sample.human_disposition,
                    "soc_ai_verdict": verdict,
                    "match": (verdict == sample.human_disposition),
                }
            )
            if verdict is None:
                status.failed += 1
            else:
                status.replayed += 1
            status.current = None

        metrics = score(rows)
        results = {
            "metrics": {
                "agreement_rate": metrics["agreement_rate"],
                "fp_reduction": metrics["fp_reduction"],
                "missed_tp": metrics["missed_tp"],
                "n_needs_more_info": metrics["n_needs_more_info"],
                "counts": metrics["counts"],
            },
            "confusion": metrics["confusion"],
            "missed_tp_rows": metrics["missed_tp_rows"],
            "rows": rows,
            # The acked⇒FP mapping is a proxy — carry the caveat with the data.
            "caveat": (
                "Ground truth is read from Security Onion: event.escalated ⇒ true "
                "positive; acknowledged-and-not-escalated ⇒ false positive. The "
                "false-positive proxy is imperfect — an analyst acknowledges alerts "
                "for several reasons (triaged benign, dismissed, bulk-cleared), so "
                "some 'human FP' rows were not strictly confirmed benign."
            ),
        }
        try:
            async with state.db_sessionmaker() as db:
                await bt_svc.finalize(
                    db, backtest_id, status="complete", sampled=len(rows), results=results
                )
        except Exception:
            _LOGGER.exception("backtest: finalize failed for id=%s", backtest_id)
    except Exception:
        _LOGGER.exception("backtest: run crashed for id=%s", backtest_id)
        try:
            async with state.db_sessionmaker() as db:
                await bt_svc.finalize(db, backtest_id, status="error", sampled=len(rows))
        except Exception:
            _LOGGER.exception("backtest: error-finalize failed for id=%s", backtest_id)
    finally:
        status.active = False
        status.finished_at = datetime.now(UTC).isoformat()


async def start_backtest(
    state: Any,
    *,
    window_days: int,
    sample_size: int,
    min_severity: str | None,
    started_by: str,
) -> BacktestStatus:
    """Plan + launch a background backtest (single-flight). Never raises.

    Clamps ``sample_size`` to ``settings.backtest_max_sample`` (each sample is a
    full LLM investigation — expensive) and logs the clamp. Samples dispositioned
    alerts, creates the backtest row, and launches :func:`run_backtest`. Returns
    the (possibly-updated) :class:`BacktestStatus`; a no-op returning the current
    status if a backtest is already running.
    """
    status = get_status(state)
    if status.active:
        # Don't clobber the live running status's note — return a copy carrying
        # the guard message so the running backtest's own fields are untouched.
        return replace(status, note="already running")

    settings = state.settings
    hard_cap = getattr(settings, "backtest_max_sample", 50)
    requested = max(1, int(sample_size))
    capped = min(requested, hard_cap)
    if capped < requested:
        _LOGGER.info(
            "backtest: capping requested sample_size %d to %d (backtest_max_sample)",
            requested,
            hard_cap,
        )

    params = {
        "window_days": int(window_days),
        "sample_size": capped,
        "requested_sample_size": requested,
        "min_severity": min_severity,
    }

    status.active = True  # claim the single-flight slot before any await
    try:
        samples = await plan_samples(
            state,
            window_days=int(window_days),
            sample_size=capped,
            min_severity=min_severity,
        )
    except Exception:
        status.active = False
        _LOGGER.exception("backtest: planning failed")
        status.note = "planning failed"
        return status

    if not samples:
        status.reset(active=False, total=0, backtest_id=None)
        status.finished_at = datetime.now(UTC).isoformat()
        status.note = "no dispositioned alerts in the window to replay"
        return status

    # Create the row up front so the console can address it by id while it runs.
    try:
        async with state.db_sessionmaker() as db:
            bt = await bt_svc.create(db, params=params, started_by=started_by)
    except Exception:
        status.active = False
        _LOGGER.exception("backtest: could not create row")
        status.note = "could not start"
        return status

    status.reset(active=True, total=len(samples), backtest_id=bt.id)
    if capped < requested:
        status.note = f"capped to {capped} (each replay is a full investigation)"
    status._task = asyncio.create_task(
        run_backtest(state, backtest_id=bt.id, samples=samples, params=params)
    )
    return status

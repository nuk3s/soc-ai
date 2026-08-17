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

from elastic_transport import TransportError
from elasticsearch import ApiError

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

    DECIDED vs TOTAL. A row whose replay produced no verdict at all (an errored
    run, or every tool failing because the grid went away mid-backtest) is a row
    soc-ai never judged. Scoring it as a disagreement turns an infrastructure
    outage into a model regression: the 2026-08-13 sweep measured a run that lost
    the grid after 2 of 20 samples reporting "agrees with analysts 10% of the
    time". Quality is therefore measured over the rows soc-ai actually decided,
    and COVERAGE is reported separately as ``completion_rate`` — an eval must
    record an outage as an outage.

    Returns:
      - ``agreement_rate``: fraction where soc-ai's verdict matches the human
        disposition (TP↔escalated, FP↔acked-not-escalated), over the DECIDED rows.
      - ``completion_rate``: decided rows / all rows — how much of the sample was
        actually replayed. Read the two together or neither means anything.
      - ``fp_reduction``: of the DECIDED human-FP (acked) rows, the fraction
        soc-ai also called ``false_positive`` — the toil soc-ai would auto-clear.
      - ``missed_tp``: of the human-TP (escalated) rows, the COUNT soc-ai called
        ``false_positive`` — the CRITICAL safety number (a missed real incident).
        Deliberately NOT rebased: it is a count of real events, not a rate.
      - ``missed_tp_rows``: those rows, so the report can list them.
      - ``confusion``: counts by ``human_disposition`` x ``soc_ai_verdict``.
      - ``n_needs_more_info``: rows where soc-ai hedged (a decision, not a gap).
      - ``n_no_verdict``: rows soc-ai never judged.
      - ``counts``: totals (``total``, ``decided``, ``no_verdict``, ``human_tp``,
        ``human_fp``, ``human_fp_decided``, ``agreements``, ``fp_cleared``).
    """
    total = len(rows)
    human_tp = [r for r in rows if r.get("human_disposition") == HUMAN_TP]
    human_fp = [r for r in rows if r.get("human_disposition") == HUMAN_FP]

    def _verdict(r: dict[str, Any]) -> str:
        v = r.get("soc_ai_verdict")
        # `inconclusive` (self-consistency split) is a NON-DECISION: bucket it
        # with needs_more_info in the confusion matrix / agreement math — it is
        # neither a wrong TP/FP nor a missing/errored verdict. The raw string
        # is preserved on the row itself (`soc_ai_verdict`).
        if v == "inconclusive":
            return "needs_more_info"
        return v if v in SOC_VERDICTS else NO_VERDICT

    # Rows soc-ai actually judged. `needs_more_info` IS a decision (soc-ai looked
    # and hedged); `no_verdict` is the absence of one (errored / unreadable).
    decided = [r for r in rows if _verdict(r) != NO_VERDICT]
    agreements = sum(1 for r in decided if _verdict(r) == r.get("human_disposition"))

    # fp_reduction: of the DECIDED human-FP alerts, share soc-ai ALSO called
    # false_positive. Rebasing matters here for the same reason as agreement —
    # an unreadable row is not toil soc-ai failed to clear.
    human_fp_decided = [r for r in human_fp if _verdict(r) != NO_VERDICT]
    fp_cleared = sum(1 for r in human_fp_decided if _verdict(r) == HUMAN_FP)
    fp_reduction = (fp_cleared / len(human_fp_decided)) if human_fp_decided else 0.0

    # missed_tp: human-TP alerts soc-ai called false_positive (the dangerous miss).
    missed_tp_rows = [r for r in human_tp if _verdict(r) == HUMAN_FP]

    n_needs_more_info = sum(1 for r in rows if _verdict(r) == "needs_more_info")
    n_no_verdict = total - len(decided)

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
        "agreement_rate": (agreements / len(decided)) if decided else 0.0,
        "completion_rate": (len(decided) / total) if total else 0.0,
        "fp_reduction": fp_reduction,
        "missed_tp": len(missed_tp_rows),
        "missed_tp_rows": missed_tp_rows,
        "n_needs_more_info": n_needs_more_info,
        "n_no_verdict": n_no_verdict,
        "confusion": confusion,
        "counts": {
            "total": total,
            "decided": len(decided),
            "no_verdict": n_no_verdict,
            "human_tp": len(human_tp),
            "human_fp": len(human_fp),
            "human_fp_decided": len(human_fp_decided),
            "agreements": agreements,
            "fp_cleared": fp_cleared,
        },
    }


# A run is DEGRADED when at least this share of its samples produced no verdict.
# Below the line the run still stands (a couple of unlucky replays are normal and
# the completion block records them); at or above it, the sample is dominated by
# rows nobody judged, so the metrics describe an outage rather than the model.
_DEGRADED_NO_VERDICT_SHARE = 0.5


def _completion(metrics: dict[str, Any]) -> dict[str, Any]:
    """The coverage block persisted beside the metrics.

    Answers "how much of this backtest actually ran" — the question a completed
    report used to be unable to answer at all. The in-memory ``failed`` counter
    existed but is transient (reset on the next run, lost on restart) and the SPA
    only ever showed it in the live-progress panel, so a reader loading the
    finished report months later saw a clean score over a blind window.
    """
    counts = metrics["counts"]
    total = int(counts["total"])
    no_verdict = int(counts["no_verdict"])
    degraded = bool(total and no_verdict >= total * _DEGRADED_NO_VERDICT_SHARE)
    return {
        "total": total,
        "decided": int(counts["decided"]),
        "no_verdict": no_verdict,
        "completion_rate": metrics["completion_rate"],
        "degraded": degraded,
        "reason": (
            f"{no_verdict} of {total} replays produced no verdict — the metrics below "
            "describe only the replays that completed, not the model."
            if degraded
            else None
        ),
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

    RAISES on an ES failure. This used to swallow it and return ``[]`` "so the
    caller lands a clean, empty backtest rather than crashing" — which made the
    console report an outage as a fact about the operator's own triage history:
    "no dispositioned alerts in the window to replay". A window we could not read
    is not a window we found empty; the caller turns the error into a 503.
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
        query["bool"]["filter"].append({"terms": {"event.severity_label": list(severity_floor)}})

    result = await elastic.search(
        settings.events_index_pattern,
        query,
        size=500,
        sort=[{"@timestamp": {"order": "desc"}}],
    )

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
        completion = _completion(metrics)
        results = {
            "metrics": {
                "agreement_rate": metrics["agreement_rate"],
                "completion_rate": metrics["completion_rate"],
                "fp_reduction": metrics["fp_reduction"],
                "missed_tp": metrics["missed_tp"],
                "n_needs_more_info": metrics["n_needs_more_info"],
                "n_no_verdict": metrics["n_no_verdict"],
                "counts": metrics["counts"],
            },
            # How much of the sample was actually replayed, and whether the run
            # was cut short. A report that claims coverage it does not have is
            # the whole G5 defect — the record must say it was interrupted.
            "completion": completion,
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
        # A run most of whose replays produced nothing did not measure the model,
        # it measured an outage. Land it as an error so no reader mistakes it for
        # a verdict on quality — the results ride along so the partial coverage
        # is still inspectable.
        final_status = "error" if completion["degraded"] else "complete"
        if completion["degraded"]:
            _LOGGER.warning(
                "backtest: %s finalized DEGRADED — only %d of %d replays produced a verdict",
                backtest_id,
                completion["decided"],
                completion["total"],
            )
        try:
            async with state.db_sessionmaker() as db:
                await bt_svc.finalize(
                    db, backtest_id, status=final_status, sampled=len(rows), results=results
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
    """Plan + launch a background backtest (single-flight).

    Raises ``(TimeoutError, TransportError, ApiError)`` when the SAMPLING query
    could not read the grid, for the route to answer as a 503 / 400 — including
    the case where it did not fail so much as never answer, which the
    ``webui_grid_timeout_s`` bound below turns into that same TimeoutError. Every
    other failure still degrades to a non-active status carrying a note — but "the
    grid is unreachable" must not be reported as "your window holds no
    dispositioned alerts". The single-flight slot is released on every exit path.

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

    # Claim the single-flight slot before any await, and clear the last run's
    # counters with it. Setting ``active`` alone left the PREVIOUS run's
    # backtest_id/total/replayed on a status now flagged live, so a page that
    # mounted while this sampling read was in flight rendered a finished run as
    # in-progress. Nothing has been sampled yet, so the honest live status is
    # empty: no id, no total, nothing replayed.
    status.reset(active=True, total=0, backtest_id=None)
    try:
        # Bound the SAMPLING READ, never the replay. plan_samples is exactly one
        # ES search; the replay behind it is N full LLM investigations and a
        # 30-day window is legitimately long-running, so the console budget must
        # not go anywhere near it — it is applied here, to the one grid read the
        # caller is actually waiting on. Without it a grid that accepts the
        # connection and never answers held this POST for the client's whole 20 s
        # and then, on the disconnect, left ``active`` claimed forever: every
        # later backtest answered "already running" until a restart.
        async with asyncio.timeout(settings.webui_grid_timeout_s):
            samples = await plan_samples(
                state,
                window_days=int(window_days),
                sample_size=capped,
                min_severity=min_severity,
            )
    except (TimeoutError, TransportError, ApiError):
        # Release the single-flight slot BEFORE propagating, or one outage wedges
        # every later backtest behind "already running".
        status.active = False
        # This note is what SURVIVES: the inline error the POST raises is gone on
        # the next page load, and the console then renders this string on its own.
        # It used to be a lowercase fragment with no remedy on it, so the durable
        # half of the failure was the half that did not say what to do next.
        status.note = (
            "Grid unavailable — the window could not be read, so no alerts were "
            "sampled. Security Onion (Elasticsearch) is slow or unreachable; retry shortly."
        )
        _LOGGER.warning("backtest: sampling could not read the grid")
        raise
    except asyncio.CancelledError:
        # The caller went away mid-sample — a browser that gave up on this POST,
        # or a shutdown. CancelledError is a BaseException, so it sails past the
        # arms above and used to leave the claim outliving the request that made
        # it: every later backtest then answered "already running" until a
        # restart, and the console rendered a live run that no longer existed.
        status.active = False
        raise
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

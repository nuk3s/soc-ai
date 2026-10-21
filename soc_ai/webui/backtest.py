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

A replay is a measurement, and the run records it as one: ``started_by`` is
:data:`soc_ai.store.investigations.BACKTEST_ACTOR`. The store then writes no
observation for its verdict, so no lead forms. The runner sends no
notification. The list and the Dashboard leave it out, no other alert inherits
its verdict, and its recommended actions cannot be executed. The replay runs
with auto-acknowledge off, so it writes nothing to Security Onion.
"""

from __future__ import annotations

import asyncio
import logging
import statistics
from collections.abc import Sequence
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime, timedelta
from typing import Any

from elastic_transport import TransportError
from elasticsearch import ApiError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from soc_ai.api.deps import ctx_from_state
from soc_ai.api.runner import run_recorded
from soc_ai.so_client.fields import get_dotted
from soc_ai.store import backtests as bt_svc
from soc_ai.store import escalations as esc_svc
from soc_ai.store import investigations as inv_svc
from soc_ai.store.models import Backtest, Investigation
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

# The most alerts one explicit list may name (``POST /backtest`` ``alert_ids``).
# A list replays exactly those alerts, so each arm of an experiment can replay
# the sample of the arm before it.
MAX_LISTED_ALERTS = 200

# The acked⇒FP mapping is a proxy, so the caveat rides with the data. A run
# stores the text of its day, and the read serves this one for every run (see
# :func:`served_results`): the range showed a 10-01 run with the pre-STE
# wording after the copy had changed (dogfood 2026-10-19, R5-D25).
CAVEAT = (
    "soc-ai reads the ground truth from Security Onion. An escalated alert "
    "counts as a true positive. An alert that an analyst acknowledged and did "
    "not escalate counts as a false positive. This proxy is not exact. An "
    "analyst acknowledges an alert for several reasons, for example a benign "
    "triage, a dismissal or a bulk clear. Some rows that count as a human "
    "false positive are therefore not confirmed benign."
)


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
      - ``fp_agreement_rate``: of the DECIDED human-FP (acked) rows, the
        fraction soc-ai also called ``false_positive``. It is an AGREEMENT
        figure. It is not what auto-acknowledge would clear: that path also
        needs the confidence threshold, a retrieval, a resolved citation and a
        low-stakes alert (:func:`soc_ai.agent.orchestrator.maybe_auto_ack_fp`),
        and a replay runs with auto-acknowledge off, so it records none of
        those tests. The console called it "toil cleared ... would auto-clear"
        and that overstated it (dogfood 2026-10-19, R5-D13).
      - ``fp_reduction``: the old name of ``fp_agreement_rate``, same value.
        Kept for a reader of the old field.
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

    # fp_agreement_rate: of the DECIDED human-FP alerts, share soc-ai ALSO
    # called false_positive. Rebasing matters here for the same reason as
    # agreement: an unreadable row is not a row soc-ai disagreed on.
    human_fp_decided = [r for r in human_fp if _verdict(r) != NO_VERDICT]
    fp_cleared = sum(1 for r in human_fp_decided if _verdict(r) == HUMAN_FP)
    fp_agreement_rate = (fp_cleared / len(human_fp_decided)) if human_fp_decided else 0.0

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
        "fp_agreement_rate": fp_agreement_rate,
        "fp_reduction": fp_agreement_rate,
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
            f"{no_verdict} of {total} replays produced no verdict. The metrics below "
            "describe only the replays that completed. They do not describe the model."
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
    # a short human note (e.g. "capped to 50")
    note: str | None = None
    # An attempt that did not start a run: {"reason", "hint"}. Kept apart from
    # ``note`` because GET /backtest serves it beside the LAST stored run, and a
    # note merged onto that run read as the old result's own note.
    refused: dict[str, str] | None = None
    # The alert ids the run replays, in replay order. A reader copies the list
    # into ``alert_ids`` of the next request to replay the same alerts.
    alert_ids: list[str] | None = None
    # An operator asked the run to stop (R5-I9). The loop reads it before each
    # alert, so the alert in flight finishes and no new alert starts. It lives
    # here, on the server, so a reload of the page reads it back.
    cancel_requested: bool = False
    cancelled_by: str | None = None
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
        self.refused = None
        self.alert_ids = None
        self.cancel_requested = False
        self.cancelled_by = None


def get_status(state: Any) -> BacktestStatus:
    """Lazily attach a :class:`BacktestStatus` to *app.state* and return it."""
    if not hasattr(state, _STATE_ATTR):
        setattr(state, _STATE_ATTR, BacktestStatus())
    return getattr(state, _STATE_ATTR)  # type: ignore[no-any-return]


# Why a cancel was refused. The route turns each one into a 409.
CANCEL_NOT_RUNNING = "not_running"
CANCEL_REQUESTED = "cancel_requested"


def request_cancel(state: Any, backtest_id: str, *, by: str) -> str | None:
    """Ask the live run ``backtest_id`` to stop after the alert in flight (R5-I9).

    Returns ``None`` when the request is taken, else the refusal reason:
    :data:`CANCEL_NOT_RUNNING` when ``backtest_id`` is not the live run, and
    :data:`CANCEL_REQUESTED` when a cancel of it is already pending.

    The stop is cooperative. :func:`run_backtest` reads the flag before each
    alert, so the replay in flight finishes and lands its verdict, and the run
    keeps every result it finished. Cancelling the replay task mid-flight would
    record the alert in flight as an ``error`` investigation with no verdict.
    """
    status = get_status(state)
    if not status.active or status.backtest_id is None or status.backtest_id != backtest_id:
        return CANCEL_NOT_RUNNING
    if status.cancel_requested:
        return CANCEL_REQUESTED
    status.cancel_requested = True
    status.cancelled_by = by
    return None


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
    stats: dict[str, int] | None = None,
) -> list[BacktestSample]:
    """Sample up to ``sample_size`` already-dispositioned alerts from the window.

    Queries ES for alerts within the last ``window_days`` that carry a
    disposition (``event.escalated`` OR ``event.acknowledged``), honouring
    ``min_severity`` (a floor: that severity and above, plus the alerts that
    carry no label — see :func:`_severity_filter`) and the configured alert
    source scope. Diversity: one alert per (rule.name, human_disposition) key,
    so a single noisy escalated/acked rule can't saturate the sample — every
    distinct disposed rule gets a representative, escalated alerts preferred
    (they carry the safety-critical TP label). Newest-first within a key.

    RAISES on an ES failure. This used to swallow it and return ``[]`` "so the
    caller lands a clean, empty backtest rather than crashing" — which made the
    console report an outage as a fact about the operator's own triage history:
    "no dispositioned alerts in the window to replay". A window we could not read
    is not a window we found empty; the caller turns the error into a 503.

    ``stats``, when given, receives the counts that explain a sample smaller
    than the request: ``scanned`` hits, ``excluded_self`` (soc-ai's own
    escalations) and ``distinct`` (rule, disposition) keys.
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
    severity_floor = _severity_filter(min_severity)

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
    if severity_floor is not None:
        query["bool"]["filter"].append(severity_floor)

    result = await elastic.search(
        settings.events_index_pattern,
        query,
        size=500,
        sort=[{"@timestamp": {"order": "desc"}}],
    )

    # Alerts soc-ai itself escalated. Grading the agent against a disposition
    # the agent wrote is not a measurement — a group escalate stamps
    # `event.escalated` on every member, and this planner would then read those
    # back as the analyst's own true-positive labels and score soc-ai against
    # its own answer key. The ledger holds exactly which alerts those are, and
    # holds nothing else, so the exclusion is precise rather than heuristic.
    self_escalated = await _soc_ai_escalated_ids(
        state, [str(h.get("_id", "")) for h in result.hits]
    )

    seen: set[tuple[str, str]] = set()
    samples: list[BacktestSample] = []
    excluded_self = 0
    for hit in result.hits:
        if len(samples) >= sample_size:
            break
        alert_id = str(hit.get("_id", ""))
        if not alert_id:
            continue
        if alert_id in self_escalated:
            excluded_self += 1
            continue
        source = hit.get("_source", {}) or {}
        disposition = _disposition_of(source)
        if disposition is None:
            continue
        rule_name = _rule_name_of(source)
        key = (rule_name, disposition)
        if key in seen:
            continue
        seen.add(key)
        samples.append(
            BacktestSample(
                alert_es_id=alert_id,
                rule_name=rule_name,
                human_disposition=disposition,
            )
        )
    if stats is not None:
        stats.update(scanned=len(result.hits), excluded_self=excluded_self, distinct=len(seen))
    # Say how many were dropped. A denominator that quietly shrinks is the same
    # defect in a different place: an operator comparing two backtests needs to
    # know whether the sample got smaller because their grid went quiet or
    # because soc-ai had escalated more of it since last time.
    _LOGGER.info(
        "backtest: sampled %d dispositioned alerts (scanned %d hits, excluded %d "
        "soc-ai escalated, window=%dd, floor=%s)",
        len(samples),
        len(result.hits),
        excluded_self,
        window_days,
        min_severity or "none",
    )
    return samples


def _rule_name_of(source: dict[str, Any]) -> str:
    """The label a backtest row carries for one alert document."""
    return str(
        get_dotted(source, "rule.name")
        or get_dotted(source, "event.dataset")
        or get_dotted(source, "event.category")
        or ""
    )


def listed_alert_ids(alert_ids: Sequence[str]) -> list[str]:
    """The ids of an explicit list: stripped, empty ones out, first copy kept, in order."""
    seen: set[str] = set()
    ids: list[str] = []
    for raw in alert_ids:
        alert_id = str(raw).strip()
        if alert_id and alert_id not in seen:
            seen.add(alert_id)
            ids.append(alert_id)
    return ids


async def plan_listed_samples(
    state: Any,
    alert_ids: Sequence[str],
    *,
    stats: dict[str, Any] | None = None,
) -> list[BacktestSample]:
    """The listed alerts, in the order given, each with its analyst label.

    Skips the sampling: no window, no severity floor and no rule diversity. One
    grid read fetches the listed documents by id. Each label is then read the
    way :func:`plan_samples` reads it: escalated is a true positive,
    acknowledged and not escalated is a false positive. An alert soc-ai
    escalated itself is left out for the same reason it is left out there.

    A listed id the grid does not hold, or an alert with no analyst label, is
    left out and named in ``stats``, so a reader sees why the run replayed
    fewer alerts than the list. RAISES on an ES failure, as the sampler does.
    """
    ids = listed_alert_ids(alert_ids)[:MAX_LISTED_ALERTS]
    settings = state.settings
    result = await state.elastic.search(
        settings.events_index_pattern,
        {"bool": {"filter": [{"ids": {"values": ids}}]}},
        # Room for one copy of a document in two indices of the pattern.
        size=max(1, 2 * len(ids)),
    )
    by_id: dict[str, dict[str, Any]] = {}
    for hit in result.hits:
        hit_id = str(hit.get("_id", ""))
        if hit_id and hit_id not in by_id:
            by_id[hit_id] = hit
    self_escalated = await _soc_ai_escalated_ids(state, ids)

    samples: list[BacktestSample] = []
    not_found: list[str] = []
    no_disposition: list[str] = []
    excluded_self: list[str] = []
    for alert_id in ids:
        hit = by_id.get(alert_id)
        if hit is None:
            not_found.append(alert_id)
            continue
        if alert_id in self_escalated:
            excluded_self.append(alert_id)
            continue
        source = hit.get("_source", {}) or {}
        disposition = _disposition_of(source)
        if disposition is None:
            no_disposition.append(alert_id)
            continue
        samples.append(
            BacktestSample(
                alert_es_id=alert_id,
                rule_name=_rule_name_of(source),
                human_disposition=disposition,
            )
        )
    if stats is not None:
        stats.update(
            listed=len(ids),
            scanned=len(result.hits),
            excluded_self=len(excluded_self),
            not_found=not_found,
            no_disposition=no_disposition,
            excluded_self_ids=excluded_self,
        )
    _LOGGER.info(
        "backtest: %d of %d listed alerts replay (%d not on the grid, %d with no "
        "disposition, %d soc-ai escalated)",
        len(samples),
        len(ids),
        len(not_found),
        len(no_disposition),
        len(excluded_self),
    )
    return samples


async def _soc_ai_escalated_ids(state: Any, alert_ids: list[str]) -> set[str]:
    """Alert ids soc-ai put on a case itself, per the escalation ledger.

    Best-effort by design: this planner's job is to sample, and a store it could
    not read must not take the backtest down. But the failure is LOGGED loudly,
    because falling back to an empty set silently restores the exact
    self-grading this exists to prevent — a quiet failure here does not degrade
    the measurement, it invalidates it.
    """
    maker = getattr(state, "db_sessionmaker", None)
    ids = [i for i in alert_ids if i]
    if maker is None or not ids:
        return set()
    try:
        async with maker() as db:
            return set(await esc_svc.cases_for_alerts(db, ids))
    except Exception:
        _LOGGER.warning(
            "backtest: could not read the escalation ledger; alerts soc-ai escalated "
            "itself will be scored as the analyst's own calls, which grades the agent "
            "against its own answer key",
            exc_info=True,
        )
        return set()


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
    """The severity band at/above ``min_severity`` (empty ⇒ all severities).

    The four labels only. The alerts that carry no label are not on the ladder
    and are handled by :func:`_severity_filter`, which is what turns this into a
    query.
    """
    if not min_severity:
        return ()
    ladder = list(aq.SEVERITIES)  # ("critical", "high", "medium", "low")
    if min_severity not in ladder:
        return ()
    idx = ladder.index(min_severity)
    return tuple(ladder[: idx + 1])


def _severity_filter(min_severity: str | None) -> dict[str, Any] | None:
    """The floor as one query clause, or ``None`` when no floor was asked for.

    A ``terms`` query over ``event.severity_label`` cannot select a document
    that has no such field, so the band on its own could not reach an
    unlabelled alert at any floor — including ``low``, which is the operator
    asking to exclude nothing. Those alerts are not a rung and there is no
    number to put in their place: measured on one grid on 2026-09-06, Security
    Onion's Suricata pipeline writes 1/2/3 alongside low/medium/high, Elastic
    Defend writes 99 and no label, and OpenCanary writes no severity at all.

    So the clause is the band OR the absence of a label, which is the same
    answer :func:`soc_ai.webui.autotriage.config_severity_band` reaches for the
    sweep and :data:`soc_ai.webui.alerts_query.UNKNOWN_SEVERITY` for the queue.
    Silently dropping the unlabelled here is worse than in either of those,
    because this samples the operator's own dispositioned history to score
    soc-ai against it: a whole class of alert absent from the sample is a
    measurement taken over a population that is not the one being measured, and
    nothing in the report would say so.
    """
    band = _severity_band(min_severity)
    if not band:
        return None
    return {
        "bool": {
            "should": [
                {"terms": {"event.severity_label": list(band)}},
                {"bool": {"must_not": [{"exists": {"field": "event.severity_label"}}]}},
            ],
            "minimum_should_match": 1,
        }
    }


# ---------------------------------------------------------------------------
# Replay + compare — the background worker.
# ---------------------------------------------------------------------------


def replay_context(ctx: Any) -> Any:
    """The investigation context a replay runs with: auto-acknowledge off.

    Auto-acknowledge is the one write the pipeline makes to Security Onion
    unattended. A replayed false positive would acknowledge an alert an
    analyst already closed, or one an analyst escalated. The copy leaves the
    live settings alone, so a sweep that runs beside the backtest keeps the
    operator's choice.
    """
    settings = getattr(ctx, "settings", None)
    if settings is None or not getattr(settings, "auto_ack_fp_enabled", False):
        return ctx
    return replace(ctx, settings=settings.model_copy(update={"auto_ack_fp_enabled": False}))


async def _replay_one(
    state: Any, ctx: Any, sample: BacktestSample
) -> tuple[str | None, str | None]:
    """Replay one sampled alert through the agent: ``(verdict, investigation id)``.

    Drains :func:`run_recorded` (which persists an :class:`Investigation`), then
    reads that row's verdict back by ``alert_es_id``. The verdict is ``None`` if
    the run errored / produced no verdict. The id is the replay's own row, so
    the report can link each row to the run behind it, and it is ``None`` only
    when no row was read back. Never raises — the caller counts a failure and
    moves on so one bad alert can't abort the run.
    """
    try:
        async for name, _data in run_recorded(
            state,
            ctx=ctx,
            alert_id=sample.alert_es_id,
            started_by=inv_svc.BACKTEST_ACTOR,
            rule_name=sample.rule_name or None,
        ):
            if name == "error":
                _LOGGER.warning("backtest: stream error for alert_id=%s", sample.alert_es_id)
    except Exception:
        _LOGGER.exception("backtest: replay failed for alert_id=%s", sample.alert_es_id)
        return None, None

    # Read the just-recorded verdict back off the Investigation row. The
    # replays are not in latest_for_alerts: that is the alert's LIVE verdict.
    try:
        async with state.db_sessionmaker() as db:
            latest = await inv_svc.latest_replays_for_alerts(db, [sample.alert_es_id])
    except Exception:
        _LOGGER.exception("backtest: verdict read-back failed for alert_id=%s", sample.alert_es_id)
        return None, None
    inv = latest.get(sample.alert_es_id)
    if inv is None:
        return None, None
    return inv.verdict, inv.id


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

    A cancel (:func:`request_cancel`) is read before each alert. The run then
    finalizes ``cancelled`` with the rows it finished and a ``cancel`` block
    that names how many of the planned alerts ran.
    """
    status = get_status(state)
    rows: list[dict[str, Any]] = []
    try:
        ctx = replay_context(ctx_from_state(state))
        for sample in samples:
            if status.cancel_requested and status.backtest_id == backtest_id:
                # An operator cancelled the run (R5-I9). The alert before this
                # one finished, and no new alert starts.
                break
            label = sample.rule_name or sample.alert_es_id
            status.current = label
            verdict, investigation_id = await _replay_one(state, ctx, sample)
            rows.append(
                {
                    "alert_id": sample.alert_es_id,
                    "rule_name": sample.rule_name,
                    "human_disposition": sample.human_disposition,
                    "soc_ai_verdict": verdict,
                    "match": (verdict == sample.human_disposition),
                    # The replay behind the verdict, for the report's link.
                    "investigation_id": investigation_id,
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
                "fp_agreement_rate": metrics["fp_agreement_rate"],
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
            # The alerts this run replayed, in order. Send the list as
            # ``alert_ids`` to replay the same alerts again.
            "alert_ids": [row["alert_id"] for row in rows],
            # The acked⇒FP mapping is a proxy — carry the caveat with the data.
            "caveat": CAVEAT,
        }
        # A run most of whose replays produced nothing did not measure the model,
        # it measured an outage. Land it as an error so no reader mistakes it for
        # a verdict on quality — the results ride along so the partial coverage
        # is still inspectable.
        final_status = "error" if completion["degraded"] else "complete"
        if len(rows) < len(samples):
            # The loop stopped early, and only a cancel stops it early. A
            # cancel that arrived during the last alert skipped nothing, so
            # that run measured the whole sample and stays complete.
            final_status = "cancelled"
            results["cancel"] = {
                "after": len(rows),
                "of": len(samples),
                "by": status.cancelled_by,
            }
            _LOGGER.info(
                "backtest: %s cancelled by %s after %d of %d alerts",
                backtest_id,
                status.cancelled_by,
                len(rows),
                len(samples),
            )
        if completion["degraded"]:
            _LOGGER.warning(
                "backtest: %s finalized DEGRADED. Only %d of %d replays produced a verdict.",
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
        status.cancel_requested = False
        status.finished_at = iso_utc(datetime.now(UTC))


def iso_utc(when: datetime | None) -> str | None:
    """ISO 8601 with a ``Z``. A naive value is UTC, the store's convention.

    The stored ``finished_at`` came back from SQLite naive and went out with no
    zone, so the browser read it as local time: four hours off on the range.
    """
    if when is None:
        return None
    if when.tzinfo is None:
        when = when.replace(tzinfo=UTC)
    return when.astimezone(UTC).isoformat().replace("+00:00", "Z")


# ---------------------------------------------------------------------------
# The read side: what GET /backtest serves beside the stored record.
# ---------------------------------------------------------------------------


def served_results(results: dict[str, Any] | None) -> dict[str, Any] | None:
    """The stored results as the API serves them. The stored row is not changed.

    The caveat is prose about the method, not a measurement, so every run is
    served with the current text (R5-D25). A run stored before
    ``fp_agreement_rate`` existed gains it from its ``fp_reduction``, the same
    number under its old name (R5-D13).
    """
    if not results:
        return results
    out = dict(results)
    out["caveat"] = CAVEAT
    metrics = out.get("metrics")
    if (
        isinstance(metrics, dict)
        and "fp_agreement_rate" not in metrics
        and "fp_reduction" in metrics
    ):
        out["metrics"] = {**metrics, "fp_agreement_rate": metrics["fp_reduction"]}
    return out


# A server-default timestamp is stored to the second on SQLite and a bound
# datetime carries microseconds, so a replay created in the run's own second
# compares below the run's start. The margin keeps it inside the run.
_RUN_WINDOW_MARGIN = timedelta(seconds=1)


async def replay_ids_in_run(
    db: AsyncSession,
    *,
    alert_ids: Sequence[str],
    started: datetime | None,
    finished: datetime | None,
) -> dict[str, str]:
    """The replay of each alert that ran inside one backtest: alert id -> run id.

    A row stored before the replay id was recorded names no run. The replays
    of that backtest are the backtest-actor runs of its alerts between its
    start and its finish. A later backtest replays the same alert again, and
    the newest replay overall would link a row to a run of another backtest.
    A live run of the alert is not a replay. Newest inside the window wins.
    """
    ids = [a for a in alert_ids if a]
    if not ids or started is None:
        return {}
    q = select(Investigation.alert_es_id, Investigation.id).where(
        Investigation.started_by == inv_svc.BACKTEST_ACTOR,
        Investigation.alert_es_id.in_(ids),
        Investigation.created_at >= started - _RUN_WINDOW_MARGIN,
    )
    if finished is not None:
        q = q.where(Investigation.created_at <= finished + _RUN_WINDOW_MARGIN)
    q = q.order_by(Investigation.created_at.asc(), Investigation.id.asc())
    found: dict[str, str] = {}
    for alert_id, inv_id in (await db.execute(q)).all():
        found[str(alert_id)] = str(inv_id)
    return found


async def results_with_replay_ids(
    db: AsyncSession,
    *,
    results: dict[str, Any] | None,
    started: datetime | None,
    finished: datetime | None,
) -> dict[str, Any] | None:
    """``results`` with ``investigation_id`` on each row, read back for an old row."""
    rows = (results or {}).get("rows")
    if not results or not isinstance(rows, list):
        return results
    missing = [
        str(row.get("alert_id"))
        for row in rows
        if isinstance(row, dict) and row.get("alert_id") and not row.get("investigation_id")
    ]
    if not missing:
        return results
    found = await replay_ids_in_run(db, alert_ids=missing, started=started, finished=finished)
    out_rows = [
        (
            {**row, "investigation_id": found.get(str(row.get("alert_id")))}
            if isinstance(row, dict) and not row.get("investigation_id")
            else row
        )
        for row in rows
    ]
    return {**results, "rows": out_rows}


# The replays the estimate reads: enough for a stable median, few enough for a
# poll.
_ESTIMATE_RUNS = 50


def _run_seconds(
    wall_ms: int | None, created: datetime | None, finished: datetime | None
) -> float | None:
    """The wall time of one run: the recorder's counter, else its two clocks."""
    if wall_ms is not None:
        return wall_ms / 1000.0
    if created is None or finished is None:
        return None
    seconds = (finished - created).total_seconds()
    return seconds if seconds >= 0 else None


async def replay_estimate(db: AsyncSession) -> dict[str, Any] | None:
    """The median time of one replay, for the cost the console states (R5-I9).

    A backtest replays its sample one alert after the other, so the run takes
    about the sample size times this median. The basis is the recent completed
    backtest replays. A store with none reads the recent completed
    investigations, and each replay is one of those. An errored run is left
    out: its time measures the failure. ``None`` when the store holds no
    completed run, and the console then states no time.
    """
    for basis, actor_clause in (
        ("backtest", Investigation.started_by == inv_svc.BACKTEST_ACTOR),
        ("investigations", None),
    ):
        q = select(
            Investigation.wall_ms, Investigation.created_at, Investigation.finished_at
        ).where(Investigation.status == "complete")
        if actor_clause is not None:
            q = q.where(actor_clause)
        q = q.order_by(Investigation.created_at.desc(), Investigation.id.desc()).limit(
            _ESTIMATE_RUNS
        )
        seconds = [
            s
            for s in (
                _run_seconds(wall, created, finished)
                for wall, created, finished in (await db.execute(q)).all()
            )
            if s is not None
        ]
        if seconds:
            return {
                "seconds_per_alert": float(statistics.median(seconds)),
                "runs": len(seconds),
                "basis": basis,
            }
    return None


def run_summary(bt: Backtest) -> dict[str, Any]:
    """One stored run as the list of past runs shows it.

    A run that did not complete has no score: its rates are ``None``, so the
    list cannot show an outage as a measurement.
    """
    results: dict[str, Any] = bt.results or {}
    raw_metrics = results.get("metrics")
    metrics: dict[str, Any] = raw_metrics if isinstance(raw_metrics, dict) else {}
    raw_counts = metrics.get("counts")
    counts: dict[str, Any] = raw_counts if isinstance(raw_counts, dict) else {}
    scored = bt.status == "complete" and bool(metrics)
    params = bt.params or {}
    requested = params.get("requested_sample_size") or params.get("sample_size")
    return {
        "backtest_id": bt.id,
        "status": bt.status,
        "started_at": iso_utc(bt.created_at),
        "finished_at": iso_utc(bt.finished_at),
        "sampled": bt.sampled,
        "requested": int(requested) if requested else None,
        "window_days": params.get("window_days"),
        "min_severity": params.get("min_severity"),
        "listed": params.get("mode") == "listed",
        "agreement_rate": metrics.get("agreement_rate") if scored else None,
        "fp_agreement_rate": (
            metrics.get("fp_agreement_rate", metrics.get("fp_reduction")) if scored else None
        ),
        "missed_tp": metrics.get("missed_tp") if scored else None,
        "human_tp": counts.get("human_tp") if scored else None,
        "human_fp": counts.get("human_fp") if scored else None,
    }


# The refusal an attempt carries when the window held nothing to replay.
NO_SAMPLES_REFUSAL = {
    "reason": "no_dispositioned_alerts",
    "hint": (
        "The window holds no alert that an analyst escalated or acknowledged. "
        "soc-ai started no run. Select a longer window or a lower severity floor."
    ),
}

# The refusal an attempt carries when the sampling read could not reach the grid.
GRID_UNAVAILABLE_REFUSAL = {
    "reason": "grid_unavailable",
    "hint": (
        "The grid is unavailable, so soc-ai could not read the window and sampled "
        "no alert. Security Onion Elasticsearch is slow or unreachable. Retry shortly."
    ),
}


def _cancel_sentence(cancel: dict[str, Any] | None) -> str | None:
    """The sentence for a run an operator cancelled, or None (R5-I9)."""
    if not isinstance(cancel, dict):
        return None
    after, total = cancel.get("after"), cancel.get("of")
    if not isinstance(after, int) or not isinstance(total, int):
        return None
    return f"An operator cancelled the backtest after {after} of {total} alerts."


def skipped_reason(
    params: dict[str, Any] | None,
    sampled: int | None,
    *,
    cancel: dict[str, Any] | None = None,
) -> str | None:
    """Why the run replayed fewer alerts than the operator requested, or None.

    ``cancel`` is the ``cancel`` block of a cancelled run's results. Its
    ``of`` is the planned sample, so the window and cap reasons read the plan,
    and the cancel sentence states the rest.
    """
    if not params or sampled is None:
        return None
    cancelled = _cancel_sentence(cancel)
    planned = int(cancel["of"]) if cancelled and cancel is not None else sampled
    requested = int(params.get("requested_sample_size") or params.get("sample_size") or 0)
    if not requested or (sampled >= requested and not cancelled):
        return None
    capped = int(params.get("sample_size") or requested)
    reasons: list[str] = []
    if params.get("mode") == "listed":
        listed = _listed_skipped_reason(params.get("plan") or {})
        return " ".join(r for r in (listed, cancelled) if r) or None
    if capped < requested:
        reasons.append(
            f"The server caps a backtest at {capped} alerts. Each replay is a full investigation."
        )
    plan = params.get("plan") or {}
    if planned < capped:
        distinct = plan.get("distinct")
        if isinstance(distinct, int):
            reasons.append(
                f"The window held {distinct} distinct pairs of detection and disposition. "
                "soc-ai samples one alert for each pair."
            )
        else:
            reasons.append(
                "soc-ai samples one alert for each pair of detection and disposition, "
                "and the window held fewer pairs."
            )
        excluded = plan.get("excluded_self")
        if isinstance(excluded, int) and excluded:
            reasons.append(
                f"soc-ai left out {excluded} alerts that it escalated itself, "
                "because they are not an analyst disposition."
            )
    if cancelled:
        reasons.append(cancelled)
    return " ".join(reasons) or None


def _listed_skipped_reason(plan: dict[str, Any]) -> str:
    """Why a run over an explicit list replayed fewer alerts than the list."""
    reasons: list[str] = []
    for key, one, many in (
        (
            "not_found",
            "listed alert is not on the grid.",
            "listed alerts are not on the grid.",
        ),
        (
            "no_disposition",
            "listed alert carries no analyst disposition.",
            "listed alerts carry no analyst disposition.",
        ),
        (
            "excluded_self_ids",
            "listed alert was escalated by soc-ai itself, so it is not an analyst disposition.",
            "listed alerts were escalated by soc-ai itself, so they are not an analyst "
            "disposition.",
        ),
    ):
        ids = plan.get(key)
        if isinstance(ids, list) and ids:
            reasons.append(f"{len(ids)} {one if len(ids) == 1 else many}")
    return " ".join(reasons)


def _start_params(
    settings: Any,
    *,
    window_days: int,
    sample_size: int,
    min_severity: str | None,
    listed: list[str] | None,
) -> tuple[dict[str, Any], int, int]:
    """The stored params of a new run, the requested size and the capped size."""
    if listed is not None:
        # An explicit list is the operator's own sample, and its length is
        # the request. The route bounds it.
        requested = capped = max(1, len(listed))
    else:
        hard_cap = getattr(settings, "backtest_max_sample", 50)
        requested = max(1, int(sample_size))
        capped = min(requested, hard_cap)
        if capped < requested:
            _LOGGER.info(
                "backtest: capping requested sample_size %d to %d (backtest_max_sample)",
                requested,
                hard_cap,
            )
    params: dict[str, Any] = {
        "window_days": int(window_days),
        "sample_size": capped,
        "requested_sample_size": requested,
        "min_severity": min_severity,
    }
    if listed is not None:
        params["mode"] = "listed"
        params["listed_alert_ids"] = listed
    return params, requested, capped


async def start_backtest(
    state: Any,
    *,
    window_days: int,
    sample_size: int,
    min_severity: str | None,
    started_by: str,
    alert_ids: Sequence[str] | None = None,
) -> BacktestStatus:
    """Plan + launch a background backtest (single-flight).

    ``alert_ids`` replays exactly those alerts, in that order, and skips the
    sampling (:func:`plan_listed_samples`). Each arm of an experiment then
    replays the same alerts. The list replaces ``sample_size``: its length is
    the request, and ``backtest_max_sample`` does not cut it. The route caps a
    list at :data:`MAX_LISTED_ALERTS`.

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
    listed = listed_alert_ids(alert_ids)[:MAX_LISTED_ALERTS] if alert_ids is not None else None
    params, requested, capped = _start_params(
        settings,
        window_days=window_days,
        sample_size=sample_size,
        min_severity=min_severity,
        listed=listed,
    )

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
        plan_stats: dict[str, Any] = {}
        async with asyncio.timeout(settings.webui_grid_timeout_s):
            if listed is not None:
                samples = await plan_listed_samples(state, listed, stats=plan_stats)
            else:
                samples = await plan_samples(
                    state,
                    window_days=int(window_days),
                    sample_size=capped,
                    min_severity=min_severity,
                    stats=plan_stats,
                )
        params["plan"] = plan_stats
        # The alerts the run replays, in order, stored with the run so a reader
        # can copy the list while the run is still going.
        params["alert_ids"] = [sample.alert_es_id for sample in samples]
    except (TimeoutError, TransportError, ApiError):
        # Release the single-flight slot BEFORE propagating, or one outage wedges
        # every later backtest behind "already running".
        status.active = False
        # This refusal is what SURVIVES: the inline error the POST raises is gone
        # on the next page load, and the console then renders this on its own.
        # It used to be a lowercase fragment with no remedy on it, so the durable
        # half of the failure was the half that did not say what to do next.
        status.refused = dict(GRID_UNAVAILABLE_REFUSAL)
        status.finished_at = iso_utc(datetime.now(UTC))
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
        status.refused = {
            "reason": "planning_failed",
            "hint": "soc-ai could not plan the backtest. Check the server log and try again.",
        }
        return status

    if not samples:
        status.reset(active=False, total=0, backtest_id=None)
        status.finished_at = iso_utc(datetime.now(UTC))
        status.refused = dict(NO_SAMPLES_REFUSAL)
        return status

    # Create the row up front so the console can address it by id while it runs.
    try:
        async with state.db_sessionmaker() as db:
            bt = await bt_svc.create(db, params=params, started_by=started_by)
    except Exception:
        status.active = False
        _LOGGER.exception("backtest: could not create row")
        status.refused = {
            "reason": "could_not_start",
            "hint": "soc-ai could not store the backtest. Check the server log and try again.",
        }
        return status

    status.reset(active=True, total=len(samples), backtest_id=bt.id)
    status.alert_ids = [sample.alert_es_id for sample in samples]
    if capped < requested:
        status.note = (
            f"The server caps a backtest at {capped} alerts. Each replay is a full investigation."
        )
    status._task = asyncio.create_task(
        run_backtest(state, backtest_id=bt.id, samples=samples, params=params)
    )
    return status

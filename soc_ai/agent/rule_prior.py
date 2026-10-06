"""The rule prior: the tier 1 rung that can cover a scheduled alert with no model.

74.7% of production runs repeat a rule the scheduler saw within 24 hours,
across 146 rules, with one true positive in 2,051 runs. The pair inheritance
rung needs the exact (rule, source, destination, host) key, which repeats in
only 0.8% of runs. The rule prior reads the rule instead: when the rule's
recent model-backed runs all ended false positive, a new alert of the rule
takes the verdict of the latest one.

It is the one rung that can hide a new case: an attacker who triggers a noisy
rule gets the noise as cover. So it holds only when all six safeguards of
decision 2 hold (docs/dev/specs/2026-10-04-four-tier-detection-methodology.md,
"Rule prior safeguards"):

1. Both endpoints sit inside the estate. An external endpoint always runs.
2. At least ``rule_prior_min_runs`` (five or more) model-backed false
   positives of the rule in the last 7 days, every model-backed verdict in
   that window a false positive, and one of them in the last 24 hours. The
   prior lapses after 24 hours without a fresh model-backed run, so every
   rule gets one real run a day.
3. Neither host carries an open lead or an observation newer than 24 hours.
   The prior yields to tier 2 and tier 3.
4. Never for a critical alert, for a rule the detection tuning panel does not
   nominate, or for a rule with any analyst override in its history.
5. It never acknowledges in Security Onion. A rule-prior run records no
   recommended action, and the pair inheritance rung never lends its verdict.
6. A random share (``rule_prior_sample_rate``, 2% to start) of covered alerts
   still gets a real run. A real run that disagrees with the prior suspends it
   for the rule until an analyst clears it on the Detection tuning panel.

``rule_prior_mode`` decides what a covered alert gets. ``shadow`` (the
default) runs the model as before and records the decision beside the real
verdict. ``live`` records the prior's verdict and skips the model, except for
the sample. In shadow every covered alert gets a real run, so every covered
alert is checked, and a disagreement suspends the rule the same way a sampled
one does in live mode.

Fail closed: a store error, a nomination the grid could not answer, an
unknown severity or a missing endpoint means the prior does not apply.
"""

from __future__ import annotations

import ipaddress
import logging
import random
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from soc_ai.store import rule_prior as store

_LOGGER = logging.getLogger(__name__)

WINDOW_DAYS = 7
LAPSE_HOURS = 24
FRESH_OBSERVATION_HOURS = 24

MODE_OFF = "off"
MODE_SHADOW = "shadow"
MODE_LIVE = "live"

COVERED = "covered"
WOULD_VERDICT = "false_positive"

# Severity labels the alert feed carries. Anything else is unknown.
_KNOWN_SEVERITIES = frozenset({"critical", "high", "medium", "low"})


@dataclass(frozen=True)
class PriorTarget:
    """The facts of one scheduled alert the prior reads."""

    rule_name: str
    alert_es_id: str
    src_ip: str
    dst_ip: str
    severity: str = ""
    host_name: str = ""


@dataclass(frozen=True)
class PriorDecision:
    """What the prior decided for one alert, and why."""

    applies: bool
    reason: str
    sampled: bool = False
    source_id: str | None = None
    would_verdict: str | None = None
    would_confidence: float | None = None
    runs_in_window: int = 0


def _hold(reason: str, **kw: Any) -> PriorDecision:
    return PriorDecision(applies=False, reason=reason, **kw)


def _inside(value: str, cidrs: Sequence[Any]) -> bool:
    try:
        addr = ipaddress.ip_address(value)
    except ValueError:
        return False
    for net in cidrs:
        try:
            if addr in net:
                return True
        except TypeError:
            continue
    return False


def mode_of(settings: Any) -> str:
    mode = getattr(settings, "rule_prior_mode", MODE_OFF)
    return mode if mode in (MODE_SHADOW, MODE_LIVE) else MODE_OFF


async def evaluate(
    db: AsyncSession,
    target: PriorTarget,
    *,
    settings: Any,
    cidrs: Sequence[Any],
    nominated: frozenset[str] | None,
    now: datetime,
    rng: random.Random | None = None,
) -> PriorDecision:
    """Decide whether the rule prior covers ``target``. Never raises.

    The checks run cheapest first, and the first one that fails names the
    reason. ``nominated`` is the set of rules the detection tuning panel
    nominates, or None when the grid could not answer: the prior then holds.
    ``now`` is naive UTC, the store's clock.
    """
    try:
        return await _evaluate(
            db,
            target,
            settings=settings,
            cidrs=cidrs,
            nominated=nominated,
            now=now,
            rng=rng or random.Random(),  # noqa: S311 - a sampling draw, not a secret
        )
    except Exception:
        _LOGGER.exception("rule prior evaluation failed for %s; the model runs", target.rule_name)
        return _hold("evaluation_failed")


def precheck(target: PriorTarget, cidrs: Sequence[Any]) -> PriorDecision | None:
    """The checks that need no store and no grid. A hold, or None to go on.

    The sweep runs these first, so a target the prior can never cover costs
    no read of the detection tuning nominations.
    """
    if not target.rule_name:
        return _hold("no_rule")
    severity = (target.severity or "").strip().lower()
    # Safeguard 4: never for a critical alert. An alert with no severity label
    # could be critical, so it does not qualify either.
    if severity == "critical":
        return _hold("critical_severity")
    if severity not in _KNOWN_SEVERITIES:
        return _hold("severity_unknown")
    # Safeguard 1: both endpoints inside the estate.
    if not target.src_ip or not target.dst_ip:
        return _hold("no_flow_endpoints")
    if not (_inside(target.src_ip, cidrs) and _inside(target.dst_ip, cidrs)):
        return _hold("external_endpoint")
    return None


async def _evaluate(
    db: AsyncSession,
    target: PriorTarget,
    *,
    settings: Any,
    cidrs: Sequence[Any],
    nominated: frozenset[str] | None,
    now: datetime,
    rng: random.Random,
) -> PriorDecision:
    held = precheck(target, cidrs)
    if held is not None:
        return held
    # Safeguard 4: the detection tuning panel nominates the rule.
    if nominated is None:
        return _hold("nomination_unavailable")
    if target.rule_name not in nominated:
        return _hold("not_nominated")
    # Safeguard 4: no analyst override in the rule's history, at any age.
    if await store.rule_has_analyst_override(db, target.rule_name):
        return _hold("analyst_override")
    # Safeguard 6: a disagreement suspends the rule until an analyst clears it.
    if await store.rule_is_suspended(db, target.rule_name):
        return _hold("suspended")
    # Safeguard 2: N model-backed false positives this week, one today.
    runs = await store.model_backed_runs(
        db, target.rule_name, since=now - timedelta(days=WINDOW_DAYS)
    )
    if any(r.verdict != WOULD_VERDICT for r in runs):
        return _hold("non_false_positive_in_window", runs_in_window=len(runs))
    min_runs = max(5, int(getattr(settings, "rule_prior_min_runs", 5) or 5))
    if len(runs) < min_runs:
        return _hold("too_few_runs", runs_in_window=len(runs))
    newest = runs[0]
    if newest.created_at < now - timedelta(hours=LAPSE_HOURS):
        return _hold("lapsed", runs_in_window=len(runs))
    # Safeguard 3: the prior yields to tier 2 and tier 3.
    if await store.hosts_have_tier2_signal(
        db,
        (target.src_ip, target.dst_ip, target.host_name),
        now=now,
        fresh_hours=FRESH_OBSERVATION_HOURS,
    ):
        return _hold("open_lead_or_fresh_observation", runs_in_window=len(runs))
    rate = float(getattr(settings, "rule_prior_sample_rate", 0.02) or 0.0)
    return PriorDecision(
        applies=True,
        reason=COVERED,
        sampled=rng.random() < rate,
        source_id=newest.id,
        would_verdict=WOULD_VERDICT,
        would_confidence=newest.confidence,
        runs_in_window=len(runs),
    )


_PRIOR_NOTE = (
    "The rule prior covered this alert. No model ran on it. The verdict, the "
    "rationale and the citations come from investigation {source} of the same rule. "
    "{runs} model runs of the rule ended false positive in the last {days} days. "
    "Re-run the investigation to have the model read this alert."
)


async def record_prior_run(
    db: AsyncSession,
    target: PriorTarget,
    decision: PriorDecision,
    *,
    started_by: str,
) -> str | None:
    """Land a rule-prior run: the source run's verdict on this alert, with no model.

    The row carries the class ``rule_prior``, zero model counters, the source
    run's verdict, confidence, rationale and citations, and no recommended
    action: the prior never acknowledges in Security Onion. Returns the new
    investigation id, or None when the source run is gone.
    """
    from soc_ai.run_meter import RunCounters  # noqa: PLC0415 - light, avoids a cycle
    from soc_ai.store import investigations as inv_svc  # noqa: PLC0415
    from soc_ai.store.models import Investigation  # noqa: PLC0415

    if decision.source_id is None:
        return None
    source = await db.get(Investigation, decision.source_id)
    if source is None:
        return None
    source_report = source.report if isinstance(source.report, dict) else {}
    note = _PRIOR_NOTE.format(source=source.id, runs=decision.runs_in_window, days=WINDOW_DAYS)
    source_summary = str(source_report.get("summary") or source.summary or "")
    report: dict[str, Any] = {
        "verdict": source.verdict,
        "confidence": source.confidence,
        "summary": f"{note}\n\n{source_summary}".strip(),
        "citations": list(source_report.get("citations") or []),
        # Never a write: the prior never acknowledges, and the source run's
        # actions name the source run's alert.
        "recommended_actions": [],
        "run_class": store.RULE_PRIOR_CLASS,
        "run_class_reason": COVERED,
        "rule_prior": {
            "source_investigation_id": source.id,
            "runs_in_window": decision.runs_in_window,
            "window_days": WINDOW_DAYS,
        },
    }
    inv = await inv_svc.create(
        db,
        alert_es_id=target.alert_es_id,
        started_by=started_by,
        rule_name=target.rule_name,
        src_ip=target.src_ip or None,
        dest_ip=target.dst_ip or None,
    )
    await inv_svc.append_events(
        db,
        inv.id,
        [
            {
                "kind": "session_start",
                "sequence": 1,
                "payload": {
                    "alert_id": target.alert_es_id,
                    "pipeline": "rule_prior",
                    "run_class": store.RULE_PRIOR_CLASS,
                },
            },
            {"kind": "triage_report", "sequence": 2, "payload": report},
            {"kind": "done", "sequence": 3, "payload": {"recommended_count": 0}},
        ],
    )
    await inv_svc.finalize(
        db,
        inv.id,
        status="complete",
        verdict=source.verdict,
        confidence=source.confidence,
        rationale=source.rationale,
        summary=report["summary"],
        report=report,
        counters=RunCounters(run_class=store.RULE_PRIOR_CLASS, es_searches=0),
    )
    return inv.id


__all__ = [
    "COVERED",
    "FRESH_OBSERVATION_HOURS",
    "LAPSE_HOURS",
    "MODE_LIVE",
    "MODE_OFF",
    "MODE_SHADOW",
    "WINDOW_DAYS",
    "PriorDecision",
    "PriorTarget",
    "evaluate",
    "mode_of",
    "precheck",
    "record_prior_run",
]

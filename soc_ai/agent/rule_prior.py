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

1. Both addresses are internal, or the external address is known. With one
   internal and one external address, the external address is known when two
   or more model-backed false positives of the rule in the last 7 days had the
   same internal address and an external address that matches: the same
   address, the same IPv4 /24 or IPv6 /64 network, or the same name of the
   external end when both alerts carry one. A name counts only when the
   external address is the destination of both flows, because a TLS server
   name, an HTTP host and a DNS query name the destination. Such a cover
   records the reason ``covered_known_external``, and a held one
   ``external_endpoint_new``. Two external addresses always get the model
   (``external_endpoint``).
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

One more hold sits beside the six: an alert with an address of a party of an
open campaign always gets the model (``campaign_machine``). The alert can be
the next stage of the campaign. A campaign that an analyst closed holds no
machine. The read takes the stored campaign rows and
never rebuilds a campaign.

``rule_prior_mode`` decides what a covered alert gets. ``shadow`` (the
default) runs the model as before and records the decision beside the real
verdict. ``live`` records the prior's verdict and skips the model, except for
the sample. In shadow every covered alert gets a real run, so every covered
alert is checked, and a disagreement suspends the rule the same way a sampled
one does in live mode.

Fail closed: a store error, a nomination the grid could not answer, an
unknown severity, a missing or unreadable address or an unreadable name means
the prior does not apply.
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

COVERED = store.COVERED
CAMPAIGN_MACHINE = "campaign_machine"
COVERED_KNOWN_EXTERNAL = store.COVERED_KNOWN_EXTERNAL
EXTERNAL_ENDPOINT = "external_endpoint"
EXTERNAL_ENDPOINT_NEW = "external_endpoint_new"
WOULD_VERDICT = "false_positive"

# Safeguard 1: the model-backed false positives on the same internal address
# that make an external address known, and the network of a match.
KNOWN_EXTERNAL_RUNS = 2
_V4_PREFIX = 24
_V6_PREFIX = 64
# How many candidate runs the name match reads. More candidates give no
# match, so the cap can only hold an alert back.
_NAME_CANDIDATES_MAX = 200

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
    # The names of the external end that the alert document carries: the TLS
    # server name, the HTTP host, the DNS query. Empty when it carries none.
    external_names: tuple[str, ...] = ()


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


_Address = ipaddress.IPv4Address | ipaddress.IPv6Address


@dataclass(frozen=True)
class _Ends:
    """The two addresses of a flow with one internal and one external end."""

    internal: _Address
    external: _Address
    # The external address is the destination of the flow.
    outbound: bool


def _address(value: str | None) -> _Address | None:
    try:
        return ipaddress.ip_address((value or "").strip())
    except ValueError:
        return None


def _ends(src: str | None, dst: str | None, cidrs: Sequence[Any]) -> _Ends | None:
    """The ends of a flow with exactly one internal address, else None."""
    src_addr, dst_addr = _address(src), _address(dst)
    if src_addr is None or dst_addr is None:
        return None
    src_in, dst_in = _inside(str(src_addr), cidrs), _inside(str(dst_addr), cidrs)
    if src_in and not dst_in:
        return _Ends(internal=src_addr, external=dst_addr, outbound=True)
    if dst_in and not src_in:
        return _Ends(internal=dst_addr, external=src_addr, outbound=False)
    return None


def _same_network(left: _Address, right: _Address) -> bool:
    if left.version != right.version:
        return False
    prefix = _V4_PREFIX if left.version == 4 else _V6_PREFIX
    return right in ipaddress.ip_network(f"{left}/{prefix}", strict=False)


async def _known_external(
    db: AsyncSession, target: PriorTarget, ends: _Ends, runs: Sequence[Any], cidrs: Sequence[Any]
) -> list[Any]:
    """The false positives of the window that make the external address known.

    Newest first. A run counts when its internal address is the internal
    address of the alert and its external address matches: the same address,
    the same network, or a shared name of the external end.
    """
    names = frozenset(
        n for n in (store.normalize_name(v) for v in target.external_names) if n is not None
    )
    matched: set[str] = set()
    by_name: list[str] = []
    for run in runs:
        if run.verdict != WOULD_VERDICT:
            continue
        run_ends = _ends(run.src_ip, run.dest_ip, cidrs)
        if run_ends is None or run_ends.internal != ends.internal:
            continue
        if run_ends.external == ends.external or _same_network(run_ends.external, ends.external):
            matched.add(run.id)
        elif names and ends.outbound and run_ends.outbound:
            by_name.append(run.id)
    if len(matched) < KNOWN_EXTERNAL_RUNS and by_name:
        stored = await store.stored_external_names(db, by_name[:_NAME_CANDIDATES_MAX])
        matched.update(run_id for run_id, held in stored.items() if names & held)
    return [run for run in runs if run.id in matched]


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
    # Safeguard 1: both addresses internal, or one external address that the
    # store must show as known (``_evaluate``). Two external addresses, or an
    # address that does not parse, always get the model.
    if not target.src_ip or not target.dst_ip:
        return _hold("no_flow_endpoints")
    src_in, dst_in = _inside(target.src_ip, cidrs), _inside(target.dst_ip, cidrs)
    if src_in and dst_in:
        return None
    if _ends(target.src_ip, target.dst_ip, cidrs) is None:
        return _hold(EXTERNAL_ENDPOINT)
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
    # A machine of an open campaign always gets the model: the alert can be
    # the next stage of the campaign.
    if await store.in_open_campaign(db, (target.src_ip, target.dst_ip), now=now):
        return _hold(CAMPAIGN_MACHINE)
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
    # Safeguard 1: an external address must be known for this rule on this
    # internal machine. The source is then the newest run that knows it.
    source, reason = newest, COVERED
    ends = _ends(target.src_ip, target.dst_ip, cidrs)
    if ends is not None:
        known = await _known_external(db, target, ends, runs, cidrs)
        if len(known) < KNOWN_EXTERNAL_RUNS:
            return _hold(EXTERNAL_ENDPOINT_NEW, runs_in_window=len(runs))
        source, reason = known[0], COVERED_KNOWN_EXTERNAL
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
        reason=reason,
        sampled=rng.random() < rate,
        source_id=source.id,
        would_verdict=WOULD_VERDICT,
        would_confidence=source.confidence,
        runs_in_window=len(runs),
    )


_PRIOR_NOTE = (
    "The rule prior covered this alert. The model did not read it. The verdict, the "
    "rationale and the citations come from investigation {source} of the same rule. "
    "{runs} investigations of the rule by the model ended false positive in the last "
    "{days} days.{external} Re-run the investigation to have the model read this alert."
)
_PRIOR_NOTE_EXTERNAL = (
    " Two or more of them had the same internal address and a matching external address."
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
    note = _PRIOR_NOTE.format(
        source=source.id,
        runs=decision.runs_in_window,
        days=WINDOW_DAYS,
        external=_PRIOR_NOTE_EXTERNAL if decision.reason == COVERED_KNOWN_EXTERNAL else "",
    )
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
        "run_class_reason": decision.reason,
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
    "CAMPAIGN_MACHINE",
    "COVERED",
    "COVERED_KNOWN_EXTERNAL",
    "EXTERNAL_ENDPOINT",
    "EXTERNAL_ENDPOINT_NEW",
    "FRESH_OBSERVATION_HOURS",
    "KNOWN_EXTERNAL_RUNS",
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

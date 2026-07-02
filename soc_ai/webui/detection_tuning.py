"""Detection tuning: nominate noisy, all-false-positive rules for suppression.

The analyst's recurring pain is a detection rule that fires constantly and, every
time it is triaged, comes back benign. soc-ai already knows both halves of that
picture locally:

* **volume** — how often a rule fired (the alerts feed's grouped-by-rule
  aggregation, :func:`soc_ai.webui.alerts_query.fetch_groups`);
* **verdict trend** — how its completed investigations landed
  (:func:`soc_ai.store.investigations.verdict_counts_by_rule`).

:func:`assess` joins the two with a deliberately coarse heuristic and recommends
``mute`` (clearly all-FP + high volume), ``monitor`` (FP-leaning but uncertain),
or ``none``. :func:`nominate` runs it across the live feed and returns the noisy
rules for the Detection Tuning panel, flagging the ones already muted.

A *mute* is a soft, soc-ai-side suppression (see
:mod:`soc_ai.store.detection_overrides`) — NOTHING is written to Security Onion.
"""

from __future__ import annotations

from typing import Any

from soc_ai.store import detection_overrides as override_svc
from soc_ai.store import investigations as inv_svc
from soc_ai.webui import alerts_query as aq

# Noisiness thresholds — deliberately coarse; this is a nomination, not a verdict.
#
# A rule must clear MIN_ALERTS firings in the window to be "high volume" at all
# (a rule that fired 4× is not a tuning problem however its triage landed).
# MUTE_MIN_ALERTS is the higher bar for a confident mute recommendation. A rule
# is only nominated once it has been investigated MIN_INVESTIGATIONS times with
# at least MIN_FP false positives and ZERO true positives — we never nominate a
# rule that has ever caught a real positive, however noisy.
MIN_ALERTS = 25  # floor to be considered "noisy" at all
MUTE_MIN_ALERTS = 100  # high-volume floor for a confident "mute"
MIN_INVESTIGATIONS = 3  # need a few data points before trusting the FP trend
MIN_FP = 3  # at least this many false positives in the trend


def assess(alert_count: int, fp: int, tp: int, nmi: int) -> tuple[bool, str, str]:
    """Decide whether a rule is noisy and what to recommend.

    Pure function (no I/O) so it is trivially testable. Inputs are the rule's
    alert ``alert_count`` over the window and its completed-investigation verdict
    tally: ``fp`` false-positive, ``tp`` true-positive, ``nmi`` needs-more-info.

    Returns ``(is_noisy, recommendation, reason)`` where ``recommendation`` is one
    of ``"mute"`` / ``"monitor"`` / ``"none"`` and ``reason`` is a one-line human
    explanation. A rule with ANY true positive is never noisy (it has caught real
    signal — tuning it would risk a miss). A rule below the volume floor, or never
    investigated, is ``none``.
    """
    investigations = fp + tp + nmi

    # A rule that ever caught a real positive is never a mute/monitor candidate —
    # however noisy, suppressing it risks dropping a true positive.
    if tp > 0:
        return (
            False,
            "none",
            (
                f"fired {alert_count}×, investigated {investigations}× — "
                f"{tp} true positive: keep (caught real signal)"
            ),
        )

    # Below the volume floor it is not a tuning problem, whatever the verdicts.
    if alert_count < MIN_ALERTS:
        return (
            False,
            "none",
            f"fired {alert_count}× — below the noisy-rule volume floor ({MIN_ALERTS})",
        )

    # High volume but not yet enough triage history to trust the trend → monitor.
    if investigations < MIN_INVESTIGATIONS or fp < MIN_FP:
        return (
            False,
            "monitor",
            (
                f"fired {alert_count}×, investigated {investigations}× "
                f"({fp} FP / {nmi} NMI, 0 TP) — high volume but thin triage history; "
                "watch it"
            ),
        )

    # Clearly all-false-positive AND high volume → confident mute.
    if alert_count >= MUTE_MIN_ALERTS:
        return (
            True,
            "mute",
            (
                f"fired {alert_count}×, investigated {investigations}× — "
                f"all false positive ({fp} FP / {nmi} NMI), 0 true positive"
            ),
        )

    # All-FP and over the noisy floor but under the high-volume bar → monitor.
    return (
        True,
        "monitor",
        (
            f"fired {alert_count}×, investigated {investigations}× — "
            f"all false positive ({fp} FP / {nmi} NMI), 0 true positive, "
            f"but under the high-volume bar ({MUTE_MIN_ALERTS})"
        ),
    )


async def nominate(state: Any) -> list[dict[str, Any]]:
    """Nominate noisy, FP-leaning rules from the live feed for tuning.

    Pulls the grouped-by-rule alert volume from the alerts feed, joins each rule's
    completed-investigation verdict trend, runs :func:`assess`, and returns the
    nominated rules (anything :func:`assess` flags noisy OR recommends to act on)
    sorted by ``alert_count`` descending. Each entry::

        {rule_name, alert_count, investigations, fp, tp, nmi,
         recommendation, reason, already_muted}

    Reads ``state.elastic`` / ``state.settings`` for volume and
    ``state.db_sessionmaker`` for the verdict trend + the active mutes. Never
    raises on empty data — it returns ``[]``.
    """
    settings = state.settings
    elastic = state.elastic

    groups, _total = await aq.fetch_groups(
        elastic,
        settings,
        time_range="7d",
        sort="count",
    )
    if not groups:
        return []

    rule_names = [g.rule_name for g in groups if g.rule_name]
    async with state.db_sessionmaker() as db:
        counts = await inv_svc.verdict_counts_by_rule(db, rule_names)
        muted = await override_svc.muted_rule_names(db)

    nominations: list[dict[str, Any]] = []
    for g in groups:
        if not g.rule_name:
            continue
        c = counts.get(g.rule_name, {})
        fp = c.get("false_positive", 0)
        tp = c.get("true_positive", 0)
        nmi = c.get("needs_more_info", 0)
        is_noisy, recommendation, reason = assess(g.count, fp, tp, nmi)
        # Surface a rule if the heuristic flags it noisy OR recommends acting on it
        # (so a high-volume "monitor" with thin history still shows up), and always
        # surface an already-muted rule so the operator can see/keep it.
        already_muted = g.rule_name in muted
        if not (is_noisy or recommendation != "none" or already_muted):
            continue
        nominations.append(
            {
                "rule_name": g.rule_name,
                "alert_count": g.count,
                "investigations": fp + tp + nmi,
                "fp": fp,
                "tp": tp,
                "nmi": nmi,
                "recommendation": recommendation,
                "reason": reason,
                "already_muted": already_muted,
            }
        )

    nominations.sort(key=lambda n: n["alert_count"], reverse=True)
    return nominations

"""Detection tuning: nominate noisy, all-false-positive rules for suppression.

The analyst's recurring pain is a detection rule that fires constantly and, every
time it is triaged, comes back benign. soc-ai already knows both halves of that
picture locally:

* **volume** — how often a rule fired (the alerts feed's grouped-by-rule
  aggregation, :func:`soc_ai.webui.alerts_query.fetch_groups`);
* **verdict trend** — how its completed investigations landed
  (:func:`soc_ai.store.investigations.verdict_counts_by_rule`).

:func:`~soc_ai.tools.tuning_heuristic.assess` joins the two with a deliberately
coarse heuristic and recommends ``mute`` (clearly all-FP + high volume),
``monitor`` (FP-leaning but uncertain), or ``none``. The heuristic itself lives
in the dependency-free :mod:`soc_ai.tools.tuning_heuristic` (shared with the
``suggest_rule_tuning`` agent tool) and is re-exported here for compatibility.
:func:`nominate` runs it across the live feed and returns the noisy rules for
the Detection Tuning panel, flagging the ones already muted.

A *mute* is a soft, soc-ai-side suppression (see
:mod:`soc_ai.store.detection_overrides`) — NOTHING is written to Security Onion.
"""

from __future__ import annotations

from typing import Any

from soc_ai.store import detection_overrides as override_svc
from soc_ai.store import investigations as inv_svc

# Re-exported for compatibility: the heuristic + thresholds moved to the
# dependency-free soc_ai.tools.tuning_heuristic so the tool layer (and MCP
# server) no longer imports webui/store just to reuse assess().
from soc_ai.tools.tuning_heuristic import (
    MIN_ALERTS,
    MIN_FP,
    MIN_INVESTIGATIONS,
    MUTE_MIN_ALERTS,
    OVERRIDE_FP_SIGNAL,
    assess,
)
from soc_ai.webui import alerts_query as aq

__all__ = [
    "MIN_ALERTS",
    "MIN_FP",
    "MIN_INVESTIGATIONS",
    "MUTE_MIN_ALERTS",
    "OVERRIDE_FP_SIGNAL",
    "assess",
    "nominate",
]


async def nominate(state: Any) -> list[dict[str, Any]]:
    """Nominate noisy, FP-leaning rules from the live feed for tuning.

    Pulls the grouped-by-rule alert volume from the alerts feed, joins each rule's
    completed-investigation verdict trend AND the analyst-override tally (the human
    feedback signal — verdicts an analyst corrected via chat/manual override), runs
    :func:`assess`, and returns the nominated rules (anything :func:`assess` flags
    noisy OR recommends to act on OR that carries analyst overrides) sorted by
    ``alert_count`` descending. Each entry::

        {rule_name, alert_count, investigations, fp, tp, nmi,
         recommendation, reason, already_muted,
         override_fp, chat_resolved, manual_resolved}

    Reads ``state.elastic`` / ``state.settings`` for volume and
    ``state.db_sessionmaker`` for the verdict trend, the analyst-override tally,
    and the active mutes. Never raises on empty data — it returns ``[]``.
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
        overrides = await inv_svc.override_counts_by_rule(db, rule_names)
        muted = await override_svc.muted_rule_names(db)

    nominations: list[dict[str, Any]] = []
    for g in groups:
        if not g.rule_name:
            continue
        c = counts.get(g.rule_name, {})
        fp = c.get("false_positive", 0)
        tp = c.get("true_positive", 0)
        nmi = c.get("needs_more_info", 0)
        oc = overrides.get(g.rule_name, {})
        override_fp = oc.get("overridden_to_fp", 0)
        chat_resolved = oc.get("chat_resolved", 0)
        manual_resolved = oc.get("manual_resolved", 0)
        is_noisy, recommendation, reason = assess(g.count, fp, tp, nmi, override_fp)
        # Surface a rule if the heuristic flags it noisy OR recommends acting on it
        # (so a high-volume "monitor" with thin history still shows up), OR the
        # analyst has overridden it to FP at all (institutional memory — a rule the
        # analyst keeps correcting shows up even if the AI verdict trend is thin),
        # and always surface an already-muted rule so the operator can see/keep it.
        already_muted = g.rule_name in muted
        has_override_signal = override_fp > 0
        if not (is_noisy or recommendation != "none" or already_muted or has_override_signal):
            continue
        # Enrich the reason when analyst feedback is present but assess() did not
        # already fold it in (assess only names it once the override signal is
        # STRONG; a single override still surfaces the rule and deserves a note).
        if override_fp > 0 and override_fp < OVERRIDE_FP_SIGNAL and tp == 0:
            reason = f"{reason} · {override_fp} analyst FP-override"
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
                "override_fp": override_fp,
                "chat_resolved": chat_resolved,
                "manual_resolved": manual_resolved,
            }
        )

    nominations.sort(key=lambda n: n["alert_count"], reverse=True)
    return nominations

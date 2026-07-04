"""Noisy-rule tuning heuristic shared by the tool and webui layers.

:func:`assess` is the deliberately coarse "is this rule a noisy FP nuisance?"
decision used by BOTH:

* the ``suggest_rule_tuning`` agent tool (:mod:`soc_ai.tools.rule_tuning`),
  which approximates the verdict trend from ES dispositions; and
* the Detection Tuning panel's nomination pass
  (:mod:`soc_ai.webui.detection_tuning`), which joins the alerts feed with the
  completed-investigation verdict trend from the local DB.

It lives here — a dependency-free module in the tools layer — so the tool
surface (including the MCP server) never has to import the webui/store layers
just to reuse the heuristic.
"""

from __future__ import annotations

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


__all__ = [
    "MIN_ALERTS",
    "MIN_FP",
    "MIN_INVESTIGATIONS",
    "MUTE_MIN_ALERTS",
    "assess",
]

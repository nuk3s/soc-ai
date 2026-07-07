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

# When an analyst repeatedly OVERRIDES a rule's verdict to false-positive (or
# resolves it out of NMI as benign), that is a stronger benign signal than the
# AI verdict trend alone — it is institutional memory. At or above this many
# analyst FP-overrides a rule leans toward mute/monitor even on a thinner AI-FP
# history or moderate volume. The tp>0 veto still wins over it (safety first).
OVERRIDE_FP_SIGNAL = 2


def assess(
    alert_count: int, fp: int, tp: int, nmi: int, override_fp: int = 0
) -> tuple[bool, str, str]:
    """Decide whether a rule is noisy and what to recommend.

    Pure function (no I/O) so it is trivially testable. Inputs are the rule's
    alert ``alert_count`` over the window and its completed-investigation verdict
    tally: ``fp`` false-positive, ``tp`` true-positive, ``nmi`` needs-more-info.
    ``override_fp`` (optional, default 0) is how many times an ANALYST overrode a
    verdict on this rule TO false-positive — a human correction that is a stronger
    benign signal than the AI verdict alone. It is keyword-defaulted so existing
    positional callers (the ``suggest_rule_tuning`` agent tool + the MCP server)
    are unaffected.

    Returns ``(is_noisy, recommendation, reason)`` where ``recommendation`` is one
    of ``"mute"`` / ``"monitor"`` / ``"none"`` and ``reason`` is a one-line human
    explanation. A rule with ANY true positive is never noisy (it has caught real
    signal — tuning it would risk a miss); this veto wins even over analyst
    FP-overrides. A rule below the volume floor, or never investigated, is
    ``none`` — UNLESS the analyst has repeatedly overridden it to FP, which on its
    own surfaces the rule (institutional memory outweighs a thin AI trend).
    """
    investigations = fp + tp + nmi
    strong_override = override_fp >= OVERRIDE_FP_SIGNAL

    # A rule that ever caught a real positive is never a mute/monitor candidate —
    # however noisy, suppressing it risks dropping a true positive. This safety
    # veto wins even when analysts have overridden it to FP (the override case is
    # ambiguous — a rule that both caught real signal AND was benign elsewhere is
    # NOT one to suppress).
    if tp > 0:
        return (
            False,
            "none",
            (
                f"fired {alert_count}×, investigated {investigations}× — "
                f"{tp} true positive: keep (caught real signal)"
            ),
        )

    # Below the volume floor it is not a tuning problem on AI trend alone — but a
    # rule the analyst keeps correcting to FP is a tuning signal regardless of
    # volume: surface it (monitor) with a reason that names the human feedback.
    if alert_count < MIN_ALERTS:
        if strong_override:
            return (
                True,
                "monitor",
                (
                    f"fired {alert_count}× (below the {MIN_ALERTS} volume floor) but "
                    f"{override_fp} analyst FP-overrides — the analyst keeps correcting "
                    "this rule to false positive; watch it"
                ),
            )
        return (
            False,
            "none",
            f"fired {alert_count}× — below the noisy-rule volume floor ({MIN_ALERTS})",
        )

    # High volume but not yet enough AI triage history to trust the trend. Normally
    # → monitor, but repeated analyst FP-overrides upgrade the lean: at high volume
    # a strong analyst benign signal is enough for a confident mute even on a thin
    # AI-FP history (the human corrected it repeatedly).
    if investigations < MIN_INVESTIGATIONS or fp < MIN_FP:
        if strong_override:
            recommendation = "mute" if alert_count >= MUTE_MIN_ALERTS else "monitor"
            return (
                True,
                recommendation,
                (
                    f"fired {alert_count}×, investigated {investigations}× "
                    f"({fp} FP / {nmi} NMI, 0 TP) — thin AI trend but "
                    f"{override_fp} analyst FP-overrides (human corrected it to benign)"
                ),
            )
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
        override_note = f", {override_fp} analyst FP-overrides" if strong_override else ""
        return (
            True,
            "mute",
            (
                f"fired {alert_count}×, investigated {investigations}× — "
                f"all false positive ({fp} FP / {nmi} NMI), 0 true positive"
                f"{override_note}"
            ),
        )

    # All-FP and over the noisy floor but under the high-volume bar. Normally →
    # monitor; but repeated analyst FP-overrides on an already-all-FP rule are a
    # strong enough benign signal to upgrade to a confident mute below the bar.
    if strong_override:
        return (
            True,
            "mute",
            (
                f"fired {alert_count}×, investigated {investigations}× — "
                f"all false positive ({fp} FP / {nmi} NMI), 0 true positive, "
                f"and {override_fp} analyst FP-overrides (human corrected it to benign)"
            ),
        )
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
    "OVERRIDE_FP_SIGNAL",
    "assess",
]

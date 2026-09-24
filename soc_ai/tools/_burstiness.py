"""Shared burstiness test for the rule-level tools (READ-ONLY, no I/O).

Two tools ask a volume question about one detection rule over a lookback window:
``rule_prevalence`` ("how often does this fire here?") and ``suggest_rule_tuning``
("is this rule a noisy nuisance?"). Both were built on the same unstated
assumption, that a rule's fires are spread through the window they are measured
over. When they are not, both answers are wrong in the same direction.

The measured case: 1531 fires of one signature, all inside 59 seconds, from one
source port, in one TCP session. ``rule_prevalence`` divided by the 30-day
lookback and reported 51.033 fires a day, "occasional" — a fabricated background
rate off by about 43000 to 1, and the run closed a real intrusion as a false
positive on it. ``suggest_rule_tuning`` counted the same 1531 as high volume,
which is the bar for recommending the signature be muted.

So the test lives in one place and both tools use it. A per-day rate, and a
tuning recommendation, are only meaningful when the fires actually occupy the
window: the span between the first and last fire has to cover a real fraction of
it, AND the rule has to have been active on a real fraction of the days it spans.
Span alone is not enough — 700 fires on day 1 and 800 on day 29 cover 93% of a
30-day window and are still two episodes rather than a rate.

The same reasoning decides whether a *density* over the span means anything, and
``fires_fill_span`` carries it. When the fires clump onto a few days inside a
long span, most of that span is silence: dividing by it produced 0.01 fires a
minute for 335 fires on 4 days of 25.4, under a field name that says burst. That
is the window-over-burst error again, one field along from where it was fixed.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from math import ceil
from typing import Any

SECONDS_PER_DAY = 86400.0

# The observed span must cover at least this fraction of the lookback window.
# Below it the fires are an episode sitting somewhere inside the window, and
# dividing by anything yields a number about a duration nobody observed.
MIN_SPAN_FRACTION = 0.05

# Within that span the rule must have been active on at least this fraction of
# the days, or the fires are clumped even though they reach across the window.
MIN_ACTIVE_DAY_COVERAGE = 0.25

# Burstiness only distorts an answer in proportion to the volume being divided or
# thresholded. Ten fires is the floor at which "this was one episode" beats "this
# is rare" as the more useful thing to say; below it a handful of fires is rare
# whichever denominator you pick, and calling it a burst would overstate it.
BURST_MIN_FIRES = 10

# A window can only hold so many day buckets. Pin a ceiling so a misconfigured
# lookback cannot ask Elasticsearch for an unbounded histogram.
MAX_DAY_BUCKETS = 400


@dataclass(frozen=True)
class Burstiness:
    """What the timestamps say about how a rule's fires sit inside the window."""

    total: int
    span_seconds: float | None
    """Seconds between the first and last fire. ``None`` when unmeasurable."""

    active_days: int | None
    """Distinct calendar days with at least one fire. ``None`` when unmeasurable."""

    span_fraction: float | None
    """The observed span as a fraction of the lookback window, capped at 1.0."""

    is_burst: bool
    """The fires are one or a few episodes, not a rate spread through the window."""

    rate_is_meaningful: bool
    """Whether a per-day figure over the observed span is worth reporting."""

    fires_fill_span: bool
    """The fires occupy the span rather than clumping onto a few days inside it.

    Only then is the span the duration the fires actually took, and only then
    does a density over it (fires per minute, fires per second) describe
    anything that happened. 335 fires on 4 days of a 25.4-day span divided by
    that span is 0.01 a minute, a figure about 21 days of silence.
    """


def measure(
    *, total: int, span_seconds: float | None, active_days: int | None, lookback_days: int
) -> Burstiness:
    """Decide whether a rule's fires are a rate or an episode.

    ``span_seconds`` of ``None`` means the timestamps were unreadable. Unknown is
    not the same as bursty, so that case is never called a burst — it just has no
    meaningful rate. Callers say so rather than guessing.
    """
    window_seconds = lookback_days * SECONDS_PER_DAY
    span_fraction: float | None = None
    day_coverage: float | None = None
    if span_seconds is not None and window_seconds > 0:
        span_fraction = min(1.0, span_seconds / window_seconds)
        if active_days is not None:
            span_days_ceiling = max(1, ceil(span_seconds / SECONDS_PER_DAY))
            day_coverage = min(1.0, active_days / span_days_ceiling)

    spans_enough_of_window = span_fraction is not None and span_fraction >= MIN_SPAN_FRACTION
    clumped_within_span = day_coverage is not None and day_coverage < MIN_ACTIVE_DAY_COVERAGE

    is_burst = (
        span_seconds is not None
        and total >= BURST_MIN_FIRES
        and (not spans_enough_of_window or clumped_within_span)
    )
    return Burstiness(
        total=total,
        span_seconds=span_seconds,
        active_days=active_days,
        span_fraction=span_fraction,
        is_burst=is_burst,
        rate_is_meaningful=spans_enough_of_window and not is_burst and bool(span_seconds),
        fires_fill_span=span_seconds is not None and not clumped_within_span,
    )


def agg_time(agg: dict[str, Any] | None) -> str | None:
    """Read a min/max date aggregation (prefer the ISO ``value_as_string``)."""
    if not agg:
        return None
    as_string = agg.get("value_as_string")
    if isinstance(as_string, str) and as_string:
        return as_string
    value = agg.get("value")
    return str(value) if value is not None else None


def agg_epoch_seconds(agg: dict[str, Any] | None) -> float | None:
    """Read a min/max date aggregation as epoch seconds.

    Prefers the numeric ``value`` (epoch millis, exact) and falls back to parsing
    ``value_as_string``. ``None`` when neither is usable — the caller then treats
    the span as unknown rather than inventing one.
    """
    if not agg:
        return None
    value = agg.get("value")
    if isinstance(value, int | float):
        return float(value) / 1000.0
    as_string = agg.get("value_as_string")
    if isinstance(as_string, str) and as_string:
        try:
            return datetime.fromisoformat(as_string.replace("Z", "+00:00")).timestamp()
        except ValueError:
            return None
    return None


def active_days_from(agg: Any) -> int | None:
    """Count the day buckets of a calendar-day date histogram (``None`` if absent)."""
    if not isinstance(agg, dict):
        return None
    buckets = agg.get("buckets")
    if not isinstance(buckets, list):
        return None
    return min(len(buckets), MAX_DAY_BUCKETS)


def day_histogram_agg() -> dict[str, Any]:
    """The calendar-day histogram both tools add to their aggregation request."""
    return {
        "date_histogram": {
            "field": "@timestamp",
            "calendar_interval": "day",
            "min_doc_count": 1,
        }
    }


def plural(count: int, noun: str) -> str:
    """``3, "source port"`` -> ``"3 source ports"``; ``1`` -> ``"1 source port"``."""
    return f"{count} {noun}" if count == 1 else f"{count} {noun}s"


def span_phrase(seconds: float) -> str:
    """Render a duration at the coarsest unit that still reads exactly.

    A burst is measured in seconds and a baseline in days, and the point of all
    this is that a reader can tell those apart at a glance.
    """
    if seconds < 90:
        return f"{seconds:.0f}s"
    if seconds < 5400:
        return f"{seconds / 60:.0f}m"
    if seconds < 2 * SECONDS_PER_DAY:
        return f"{seconds / 3600:.1f}h"
    return f"{seconds / SECONDS_PER_DAY:.1f} days"


__all__ = [
    "BURST_MIN_FIRES",
    "MAX_DAY_BUCKETS",
    "MIN_ACTIVE_DAY_COVERAGE",
    "MIN_SPAN_FRACTION",
    "SECONDS_PER_DAY",
    "Burstiness",
    "active_days_from",
    "agg_epoch_seconds",
    "agg_time",
    "day_histogram_agg",
    "measure",
    "plural",
    "span_phrase",
]

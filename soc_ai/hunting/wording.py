"""The words an analyst reads for one departure.

Every surface that shows a departure reads from here: the note on the result,
the summary stored on the observation, the CLI rendering, and the rewording of
rows an older build wrote. One home, because the second dogfood found the host
page showing ``novel connection_rate off x2782`` while the CLI showed a
sentence for the same row. Two renderings of one fact drift, and the one an
analyst reads is whichever screen they opened.

The module holds no query and no store. It imports the observation kind and
nothing else, so the evaluator can call it without importing the sweep that
calls the evaluator.
"""

from __future__ import annotations

import re
from typing import Any

from soc_ai.hunting.weight import Kind

__all__ = [
    "baseline_sentence",
    "noun",
    "phrase",
    "plural",
    "rate",
    "rate_phrase",
    "result_note",
    "reword_legacy_summary",
    "times",
    "when",
]

# The noun an analyst would use for each profiled dimension. The dimension
# names are column names; a headline that says "novel peers_out: 10.0.0.5 x3"
# is the data model talking, and the second dogfood read it as noise.
_DIMENSION_NOUN: dict[str, str] = {
    "peers_out": "outbound peer",
    "dns_names": "DNS name",
    "served_ports": "served port",
    "consumed_ports": "outbound port",
    "process_names": "process",
    "process_parents": "parent/child process pair",
    "logon_users": "logon user",
    "connection_rate": "connection rate",
    "active_hours": "active hour",
}

_CELL_WORDS: dict[str, str] = {
    "work": "during working hours",
    "off": "during off-hours",
    "weekend": "at the weekend",
}


def noun(dimension: Any) -> str:
    key = str(dimension or "")
    return _DIMENSION_NOUN.get(key, key.replace("_", " ") or "value")


def when(member: Any) -> str:
    """'around 03:00 UTC' for an hour, 'during off-hours' for a rate cell."""
    key = str(member or "").strip().lower()
    if key in _CELL_WORDS:
        return _CELL_WORDS[key]
    try:
        return f"around {int(member):02d}:00 UTC"
    except (TypeError, ValueError):
        return f"around {member}"


def times(count: Any) -> str:
    try:
        n = int(count)
    except (TypeError, ValueError):
        return ""
    return "once" if n == 1 else f"{n} times"


def plural(count: Any, word: str) -> str:
    """'1 day' or '13 days'. The store writes ``day(s)``, which nobody says."""
    try:
        n = int(count)
    except (TypeError, ValueError):
        n = 0
    return f"{n} {word}" if n == 1 else f"{n} {word}s"


def baseline_sentence(baseline_size: Any, support_days: Any) -> str:
    """What the entity's own history holds behind this departure.

    A departure is unreadable without it. "445 is new on this switch" means one
    thing when the switch has served one port for thirty days and another when
    it has served two hundred for three.
    """
    return (
        f"The baseline holds {plural(baseline_size, 'value')} over {plural(support_days, 'day')}."
    )


def rate(value: Any) -> str:
    """A rate an analyst reads: 2446, or 0.5 when the fraction matters."""
    try:
        number = float(value)
    except (TypeError, ValueError):
        return str(value)
    return f"{number:.0f}" if abs(number - round(number)) < 0.05 else f"{number:.1f}"


def rate_phrase(
    dimension: Any,
    member: Any,
    *,
    value: Any,
    median: Any,
    ratio: Any,
    count: Any = 0,
) -> str:
    """A rate departure, stated as numbers.

    The sentence said "far above this host's own median" for a 13 % move, and
    it named a median the profile panel disagreed with. "Far" is a judgement
    the reader should make, so the sentence gives them the rate, the median and
    the multiple and makes no claim of its own.

    A row written before the numbers travelled with the departure has only the
    count. It reads as the rate alone, which is what it is.
    """
    measured = rate(value if value is not None else count)
    head = f"The {noun(dimension)} {when(member)} is {measured} per hour"
    if median is None or ratio is None:
        return head
    return (
        f"{head}. The median is {rate(median)} per hour. "
        f"That is {float(ratio):.1f} times the median"
    )


def phrase(kind: Kind, departure: Any) -> str:
    """Say what actually departed, in words an analyst would use.

    Rendering every departure as "novel X" was wrong for the rate tests: a
    connection rate that collapsed was printed as "novel connection_rate: off",
    which reads as a new thing appearing rather than an existing one stopping.
    The hour-of-day tests name the hour, not the "cell" the baseline is kept in.

    No trailing stop. The caller adds the baseline sentence after it.
    """
    dimension = getattr(departure, "dimension", "")
    member = getattr(departure, "member", "")
    count = getattr(departure, "observed_count", 0)
    if kind is Kind.OFF_HOURS:
        return (
            f"active {when(member)}. This host is not normally active then. "
            f"The sweep counted {count} events"
        )
    if kind in (Kind.ABOVE_BASELINE, Kind.BELOW_BASELINE):
        return rate_phrase(
            dimension,
            member,
            value=getattr(departure, "observed_value", None),
            median=getattr(departure, "baseline_median", None),
            ratio=getattr(departure, "ratio", None),
            count=count,
        )
    seen = times(count)
    if seen:
        return f"new {noun(dimension)} for this host: {member}. The sweep saw it {seen}"
    return f"new {noun(dimension)} for this host: {member}"


def result_note(kind: Kind, departures: Any, *, baseline_size: Any, support_days: Any) -> str:
    """The note on one evaluated prior, in the same words as the summary.

    The note said "9 novel consumed_ports against a baseline of 15 over 30
    day(s)": the column name, the count and nothing an analyst could act on.
    """
    base = baseline_sentence(baseline_size, support_days)
    rows = list(departures or ())
    if not rows:
        return f"Nothing departed. {base}"
    lead = f"{phrase(kind, rows[0])}. "
    if len(rows) > 1:
        lead += f"{len(rows) - 1} more of the same type followed. "
    return lead + base


# Summaries are stored when an observation is recorded and refreshed only when
# it recurs, so rows written by an older build keep the data model's wording
# for days after the sentence changed. Read them through this on the way out.
_LEGACY_HOUR = re.compile(r"active at hour (\d+) — outside this entity's measured hours")
_LEGACY_ABOVE = re.compile(
    r"connection_rate in the (work|off|weekend) cell is far ABOVE its own median"
)
_LEGACY_BELOW = re.compile(
    r"connection_rate in the (work|off|weekend) cell has COLLAPSED against its own median"
)
_LEGACY_CELL = re.compile(r"connection rate around (work|off|weekend) (is far above|has collapsed)")
# The colon is optional: one build wrote "novel peers_out: 10.0.0.5 x3" and an
# earlier one wrote "novel connection_rate off x2782".
_LEGACY_NOVEL = re.compile(r"novel (\w+):? (\S+) x(\d+)")
_LEGACY_SEEN = re.compile(r"\s*\(seen (once|\d+ times?)\)")
_LEGACY_BASELINE = re.compile(r"\s*[—-]\s*against a baseline of (\d+) over (\d+)d")


def _legacy_novel(dimension: str, member: str, count: str) -> str:
    """One legacy "novel X" headline, in today's words for that dimension."""
    if dimension == "connection_rate":
        # The stored text holds the rate and nothing else. The median and the
        # multiple are not in it and are not invented here.
        return rate_phrase(dimension, member, value=count, median=None, ratio=None)
    if dimension == "active_hours":
        return (
            f"active {when(member)}. This host is not normally active then. "
            f"The sweep counted {count} events"
        )
    return f"new {noun(dimension)} for this host: {member}. The sweep saw it {times(count)}"


def reword_legacy_summary(text: str | None) -> str | None:
    """An observation summary in today's words, whichever build wrote it."""
    if not text:
        return text
    s = _LEGACY_HOUR.sub(
        lambda m: f"active {when(m.group(1))}. This host is not normally active then",
        text,
    )
    s = _LEGACY_ABOVE.sub(
        lambda m: f"connection rate {when(m.group(1))} is far above this host's own median", s
    )
    s = _LEGACY_BELOW.sub(
        lambda m: f"connection rate {when(m.group(1))} is far below this host's own median",
        s,
    )
    s = _LEGACY_CELL.sub(lambda m: f"connection rate {when(m.group(1))} {m.group(2)}", s)
    s = _LEGACY_NOVEL.sub(
        lambda m: _legacy_novel(m.group(1), m.group(2), m.group(3)),
        s,
    )
    s = _LEGACY_SEEN.sub(lambda m: f". The sweep saw it {m.group(1)}", s)
    s = _LEGACY_BASELINE.sub(
        lambda m: f". {baseline_sentence(m.group(1), m.group(2))}",
        s,
    )
    return s

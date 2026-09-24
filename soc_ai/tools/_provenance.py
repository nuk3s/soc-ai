"""Imported and replayed document visibility, decided in exactly one place.

A grid does not only hold what its own sensors saw. Security Onion's
``so-import-pcap`` and ``so-import-evtx`` land historical captures alongside
live telemetry, and a benchmark or training corpus is often replayed with its
timestamps shifted into a recent window so it exercises the same code paths as
live data. Both are deliberate and useful. Both are indistinguishable from live
telemetry unless something looks at provenance.

That is fine for triage, which is anchored to one document an analyst is already
holding: a verdict on an imported alert is a verdict on that alert. It is NOT
fine for anything that reasons over a population, which is most of proactive
hunting:

- a novelty test ("this principal has never been seen before") measures the
  import's principals, not the network's, and reports a flood of first-seens the
  day a corpus lands;
- a rarity or baseline test computes its denominator over backfill, so the real
  signal is diluted by however many documents the corpus happened to contain;
- an absence test ("this host stopped reporting") is meaningless against an
  import, which by its nature produces one burst and then permanent silence.

Measured on the development range on 2026-09-04: **19,604,032 of 23,055,409
documents carry ``import.id``** and 5,839 more carry a ``replayed-corpus`` tag.
Live telemetry is 3,456,959 documents, 15% of the grid. A baseline computed
without this filter is a baseline of somebody else's network.

Threaded rather than blanket, for the same reason
:mod:`soc_ai.tools._synth_scope` is: a caller that genuinely wants history
(retro-hunting a newly published indicator across everything on disk, or
measuring what an import contains) asks for it explicitly, and every other
caller gets the safe default without having to know this module exists.

**Narrowing a denominator silently is the same bug in a new coat.** A tool that
starts counting a different population and keeps printing the same field name
has not become honest, it has become wrong in a quieter way. So the filter
ships with its disclosure: :func:`denominator_note` is the clause every
population statistic puts in its own summary, and :func:`count_imports` measures
what the filter removed on the branches where the tool is about to assert an
absence — "never seen before", "has not fired", "no observations". Those
sentences are the ones an exclusion can turn into a lie, and they are also the
cheap ones to measure, because a live query that came back empty is not a query
the grid is straining under.
"""

from __future__ import annotations

import logging
from typing import Any

_LOGGER = logging.getLogger(__name__)

# ``live`` — only what this grid's own sensors observed. The default for any
# read that computes a rate, a baseline, a novelty or an absence.
# ``any`` — everything on disk, imports included. For retro-hunting a new
# indicator across full retention, and for reading an import on purpose.
Provenance = str

LIVE: Provenance = "live"
ANY: Provenance = "any"

# Marker 1: Security Onion stamps every document it ingests through
# ``so-import-pcap`` / ``so-import-evtx`` with an import identifier.
_IMPORT_ID_FIELD = "import.id"

# Marker 2: a corpus replayed into the grid for benchmarking or training. Not an
# SO convention — a local one — so it is a list an operator can extend rather
# than a constant. ``import`` itself is deliberately NOT here: it is SO's own
# tag on the same documents ``import.id`` already covers, and matching on it too
# would only make the clause redundant.
_REPLAY_TAGS: tuple[str, ...] = ("replayed-corpus",)


def provenance_must_not(
    provenance: Provenance = LIVE, *, extra_replay_tags: tuple[str, ...] = ()
) -> list[dict[str, Any]]:
    """The ``must_not`` clauses enforcing ``provenance``, ready to splice in.

    Returns ``[]`` for :data:`ANY`. For :data:`LIVE`, excludes any document
    carrying an import identifier or a replay tag.

    Unknown values are treated as :data:`LIVE`. This fails toward the smaller,
    more trustworthy population: a typo in a spec's ``provenance:`` field
    narrows what a detection sees rather than silently widening it to include
    backfill, so the failure mode is a missed finding rather than a baseline
    quietly computed over someone else's network.
    """
    if provenance == ANY:
        return []
    tags = (*_REPLAY_TAGS, *extra_replay_tags)
    return [
        {"exists": {"field": _IMPORT_ID_FIELD}},
        *({"term": {"tags": tag}} for tag in tags),
    ]


def imported_filter(*, extra_replay_tags: tuple[str, ...] = ()) -> dict[str, Any]:
    """The complement of the :data:`LIVE` exclusion: only backfill.

    Built from the very clauses :func:`provenance_must_not` excludes, ORed
    together, so the two can never drift into disagreeing about what an import
    is. Whatever :data:`LIVE` drops, this selects, and the two always partition
    the same population.
    """
    return {
        "bool": {
            "should": provenance_must_not(LIVE, extra_replay_tags=extra_replay_tags),
            "minimum_should_match": 1,
        }
    }


def denominator_note(provenance: Provenance = LIVE) -> str:
    """The clause a population statistic owes its reader about what it counted.

    Short enough to sit inside a one-line summary next to the number it
    qualifies, because that is the only place it is read. The alternative — a
    field somewhere else in the return dict — is how a figure ends up quoted in
    a rationale with its denominator left behind.
    """
    if provenance == ANY:
        return "live telemetry plus imported/replayed documents"
    return "live telemetry only, imports and replayed corpora excluded"


async def count_imports(
    elastic: Any,
    index: str,
    base_query: dict[str, Any],
    *,
    extra_replay_tags: tuple[str, ...] = (),
) -> int | None:
    """How many documents ``base_query`` matches that :data:`LIVE` would exclude.

    ``base_query`` is the tool's own query WITHOUT its provenance clauses —
    passing the filtered form asks a contradiction and always answers zero.

    For the absence branches. "This host has never been seen" and "this host has
    been seen 40,000 times, in an imported capture of somebody else's network"
    are different situations, and after the filter lands they produce the same
    empty result set. This is the one read that tells them apart, so it runs
    where a tool is about to report nothing and nowhere else.

    Returns ``None`` — not ``0`` — when the read fails. A tool that could not
    measure the backfill must not tell its reader there is none; the whole point
    of the call is that an empty answer has two possible causes, and a swallowed
    error would restore exactly the ambiguity it exists to remove.
    """
    query: dict[str, Any] = {
        "bool": {
            "must": [base_query],
            "filter": [imported_filter(extra_replay_tags=extra_replay_tags)],
        }
    }
    try:
        result = await elastic.search(index, query, size=0, track_total_hits=True)
    except Exception as exc:
        # Never raised onward: every caller is a tool that already promised its
        # own caller it would not raise, and an unmeasured import count is a
        # missing sentence rather than a failed answer.
        _LOGGER.warning("import-volume probe failed on %s: %s", index, exc)
        return None
    return int(result.total)


def imports_note(count: int | None) -> str:
    """The sentence an absence owes its reader, or ``""`` when it owes none.

    Three outcomes, because :func:`count_imports` has three. A positive count is
    the case worth a sentence: the tool found nothing and the grid holds
    matching documents anyway, which is not the same finding as an empty grid
    and must not read like one. Zero needs nothing said — the summary's
    denominator note already told the reader the count is live-only, and there
    was no backfill for it to have hidden. ``None`` says the probe failed, which
    is neither of the other two and is reported as itself.

    Written to be appended to a summary that has already ended in a full stop.
    """
    if count is None:
        return (
            " Whether this grid also holds imported or replayed documents matching this "
            "question could not be measured, so read the absence as unconfirmed."
        )
    if count <= 0:
        return ""
    return (
        f" This grid does hold {count} imported or replayed document(s) matching it, "
        "excluded here because backfill is somebody else's network rather than "
        "something a sensor here observed. They are real and queryable — ask for "
        "provenance='any' to include them."
    )


__all__ = [
    "ANY",
    "LIVE",
    "Provenance",
    "count_imports",
    "denominator_note",
    "imported_filter",
    "imports_note",
    "provenance_must_not",
]

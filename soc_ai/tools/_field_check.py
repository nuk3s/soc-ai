"""The field check of a zero-hit query.

A filter on a field that no document holds returns zero. A filter on a field
that every document holds, with a value that no document has, also returns
zero. The two answers looked the same to the model. Ten scheduled hunts
filtered ``zeek.ssh.auth_success:true`` on a grid that stores the value in
``ssh.authentication.success``, and six reports stated "no successful SSH
login" from that zero (production review 2026-11-12, hunts finding 2).

:func:`absent_field_note` tells the two answers apart. It runs ONE search for
one zero-hit query: a count with one ``exists`` filter for each name, in the
same window and the same dataset as the query. It returns a note when no
document holds a field, and ``None`` when every field is present. A zero with
no note is then a zero over documents that hold the field.

The check runs only after a zero. A query that returns a hit pays nothing.
"""

from __future__ import annotations

import logging
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from soc_ai.so_client.elastic import ElasticClient
from soc_ai.so_client.oql import get_whitelist

_LOGGER = logging.getLogger(__name__)

_SCOPE_KEY = "scope"

NOT_EVIDENCE = "This zero is not evidence of absence."
_DESCRIBE = "Call t_describe_dataset for the dataset and use the field names that it returns."

# The check could not run. The zero stays unconfirmed, and the model must know.
CHECK_FAILED_NOTE = (
    "The field check of this zero-hit query did not run. "
    "Do not read this zero as evidence of absence. "
    "Call t_describe_dataset for the dataset and confirm the field names."
)


@dataclass(frozen=True)
class CheckedField:
    """One field of a zero-hit query.

    ``names`` holds the names to count. For a filter field they are the names
    that the query tested: the query matched each of them, so the field is
    absent only when no name is present. For a groupby field they are the
    names of the field, the written name included: the aggregation ran on the
    written name only, and a different name that documents hold is the one to
    suggest. An empty ``names`` counts nothing, and the field reads as absent.

    ``widened`` is true for a filter field and false for a groupby field.
    """

    name: str
    names: tuple[str, ...]
    widened: bool


def _filter_key(index: int, name_index: int) -> str:
    return f"f{index}_{name_index}"


def _join(names: Sequence[str]) -> str:
    quoted = [f"`{name}`" for name in names]
    if len(quoted) == 1:
        return quoted[0]
    return ", ".join(quoted[:-1]) + " and " + quoted[-1]


def _field_word(names: Sequence[str]) -> str:
    return "field" if len(names) == 1 else "fields"


@dataclass(frozen=True)
class EmptyAggregate:
    """The words for an aggregation on a field that no document holds."""

    effect: str
    retry: str


GROUPBY = EmptyAggregate(effect="the groupby has no bucket", retry="Run the groupby on")
VALUE_LIST = EmptyAggregate(effect="the list of values is empty", retry="Ask for the values of")


def absent_aggregate_text(
    name: str,
    other: str | None,
    datasets: Sequence[str],
    words: EmptyAggregate,
) -> str:
    """The note for one aggregation field that no document holds.

    ``other`` is a different name of the same value that documents do hold.
    """
    where = f" of {_join(datasets)}" if datasets else ""
    sentences = [f"No document{where} in this window holds the field `{name}`, so {words.effect}."]
    if other is not None:
        sentences.append(
            f"The field `{other}` holds this value on this grid. {words.retry} `{other}`."
        )
    sentences.append(NOT_EVIDENCE)
    if other is None:
        sentences.append(_DESCRIBE)
    return " ".join(sentences)


async def absent_field_note(
    elastic: ElasticClient,
    index: str,
    *,
    scope_filters: Sequence[dict[str, Any]],
    must_not: Sequence[dict[str, Any]] = (),
    checked: Sequence[CheckedField],
    datasets: Sequence[str] = (),
    words: EmptyAggregate = GROUPBY,
    name_empty_dataset: bool = True,
) -> str | None:
    """The note for the fields of ``checked`` that no document in the scope holds.

    ``name_empty_dataset`` false gives one note for both causes of an absent
    field: the dataset has no document, or its documents do not hold the
    field. ``t_field_values`` passes false. Its guard for the marker fields
    answers with no search, so it cannot count the dataset, and its answer
    must equal the answer for a field that no document holds.

    ``scope_filters`` is the window of the query and its dataset filter.
    ``datasets`` names that dataset filter for the text of the note. The
    function runs one search. It never raises: a failed check returns
    :data:`CHECK_FAILED_NOTE`, because an unconfirmed zero must not read as a
    confirmed zero.
    """
    if not checked:
        return None
    names_of = [field.names for field in checked]
    named_filters: dict[str, Any] = {_SCOPE_KEY: {"match_all": {}}}
    for i, names in enumerate(names_of):
        for j, name in enumerate(names):
            named_filters[_filter_key(i, j)] = {"exists": {"field": name}}
    query: dict[str, Any] = {"bool": {"filter": list(scope_filters)}}
    if must_not:
        query["bool"]["must_not"] = list(must_not)
    try:
        result = await elastic.search(
            index,
            query,
            size=0,
            aggs={"field_check": {"filters": {"filters": named_filters}}},
            track_total_hits=False,
        )
        buckets = ((result.aggregations or {}).get("field_check") or {}).get("buckets")
        if not isinstance(buckets, dict):
            raise ValueError("the field check returned no buckets")
        counts = {key: int((bucket or {}).get("doc_count", 0)) for key, bucket in buckets.items()}
    except Exception as exc:
        _LOGGER.warning("field check failed: %s", exc)
        return CHECK_FAILED_NOTE

    where = f" of {_join(datasets)}" if datasets else ""
    if name_empty_dataset and counts.get(_SCOPE_KEY, 0) == 0 and datasets:
        return (
            f"No document{where} is in this window. "
            "The grid holds no document of that dataset in this window, "
            "so the query cannot match. "
            f"{NOT_EVIDENCE} "
            "Report that the grid does not hold this log in the window. "
            "Do not report that the activity did not occur."
        )

    absent_filters: list[str] = []
    absent_groupbys: list[tuple[str, str | None]] = []
    for i, field in enumerate(checked):
        present = [
            name for j, name in enumerate(names_of[i]) if counts.get(_filter_key(i, j), 0) > 0
        ]
        if field.widened:
            if not present:
                absent_filters.append(field.name)
        elif field.name not in present:
            # Only a name that the validator accepts. A note that tells the
            # model to group on a refused field costs one more failed call.
            usable = [name for name in present if get_whitelist().is_allowed(name)]
            absent_groupbys.append((field.name, usable[0] if usable else None))
    if not absent_filters and not absent_groupbys:
        return None

    if not absent_filters and len(absent_groupbys) == 1:
        name, other = absent_groupbys[0]
        return absent_aggregate_text(name, other, datasets, words)
    sentences: list[str] = []
    if absent_filters:
        sentences.append(
            f"No document{where} in this window holds the {_field_word(absent_filters)} "
            f"{_join(absent_filters)}. "
            "A filter on a field that no document holds cannot match."
        )
    for name, other in absent_groupbys:
        sentences.append(
            f"No document{where} in this window holds the field `{name}`, so {words.effect}."
        )
        if other is not None:
            sentences.append(
                f"The field `{other}` holds this value on this grid. {words.retry} `{other}`."
            )
    sentences.append(NOT_EVIDENCE)
    sentences.append(_DESCRIBE)
    return " ".join(sentences)

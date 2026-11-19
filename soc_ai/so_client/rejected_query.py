"""What the author of a rejected query reads: the reason of the grid and a hint.

The grid answers a query that is wrong for the type of a field with failed
shards (:class:`soc_ai.so_client.elastic.GridQueryRejectedError`). The model and
the analyst can correct such a query only when they see why the grid rejected
it. The tool boundary of the model (``soc_ai.agent.toolset``) and the routes
that run an analyst's query (``soc_ai.api.webui.routes_alerts``) both read the
sentences here, so the two readers get one story.

Each hint answers one reason that the production grid returned (2026-11-19).
A reason of another shape gets no hint: the reason text of Elasticsearch is
then the only guide, and a guessed hint is worse than none.
"""

from __future__ import annotations

import re
from collections.abc import Callable

from soc_ai.so_client.elastic import GridQueryRejectedError

# The documentation network (RFC 5737). No lab address belongs in a hint.
_CIDR_EXAMPLE = "192.0.2.0/24"
_DATE_EXAMPLE = '["2026-10-28T22:44:00Z" TO "2026-10-28T23:59:00Z"]'


def cidr_hint(field: str) -> str:
    """The hint for a wildcard or a prefix on an ``ip`` field."""
    return (
        f"The field {field} is an IP field. An IP field takes an address or a CIDR range "
        f'in quotes, for example {field}:"{_CIDR_EXAMPLE}". It takes no wildcard.'
    )


def date_hint(field: str = "@timestamp") -> str:
    """The hint for a time that a date field does not parse."""
    return f"A date field takes a time in ISO 8601 in UTC, for example {field}:{_DATE_EXAMPLE}."


def _ip(m: re.Match[str]) -> str:
    return cidr_hint(m.group("field"))


def _date(m: re.Match[str]) -> str:
    return date_hint()


def _unmapped_sort(m: re.Match[str]) -> str:
    field = m.group("field")
    return (
        f"Some indices of the search do not map the field {field}. Sort on a field "
        "that each dataset of the search holds, or leave out the sortby stage."
    )


def _text_field(m: re.Match[str]) -> str:
    return (
        "The field is a text field in some indices. A text field takes no groupby and "
        "no sortby. Group by or sort by a keyword field."
    )


def _number(m: re.Match[str]) -> str:
    value = m.group("value")
    return f'The field holds numbers, and "{value}" is not a number. Write the value as a number.'


def _date_math(m: re.Match[str]) -> str:
    return (
        "Date math takes the units y, M, w, d, h, H, m and s, for example now-20d or "
        "now-90m. It takes no unit ms."
    )


# (pattern on the reason text, hint). The first match wins.
_HINTS: tuple[tuple[re.Pattern[str], Callable[[re.Match[str]], str]], ...] = (
    (re.compile(r"not on \[(?P<field>[^\]]+)\] which is of type \[ip\]"), _ip),
    (re.compile(r"failed to parse date field \["), _date),
    (re.compile(r"No mapping found for \[(?P<field>[^\]]+)\] in order to sort on"), _unmapped_sort),
    (
        re.compile(
            r"match_only_text fields do not support sorting and aggregations"
            r"|Text fields are not optimised for operations"
            r"|Fielddata is disabled on"
        ),
        _text_field,
    ),
    (re.compile(r'For input string: "(?P<value>[^"]*)"'), _number),
    (re.compile(r"(?:operator|unit) .*not supported for date math"), _date_math),
)


def rejection_hint(reason: str | None) -> str | None:
    """The hint for the reason text of a rejected query, or ``None``."""
    if not reason:
        return None
    for pattern, hint in _HINTS:
        m = pattern.search(reason)
        if m is not None:
            return hint(m)
    return None


def _shards(exc: GridQueryRejectedError) -> str:
    if exc.shards_total:
        return f"{exc.shards_failed} of {exc.shards_total} shards"
    noun = "shard" if exc.shards_failed == 1 else "shards"
    return f"{exc.shards_failed} {noun}"


def model_message(exc: GridQueryRejectedError) -> str:
    """What the model reads in the tool result of a rejected query."""
    return (
        f"The Security Onion grid is up. It rejected this query on {_shards(exc)}. "
        f"Elasticsearch states: {exc.reason}. The result is UNKNOWN. It is not an empty "
        "result: the shards that hold the field did not answer, so it is NOT evidence "
        "that nothing matched. Correct the query or its arguments, and send it again."
    )


def analyst_hint(exc: GridQueryRejectedError) -> str:
    """What the analyst reads in the 400 of a rejected query.

    The correction comes first: the analyst wants the form that the grid
    takes. The reason text of Elasticsearch follows it. The shard count is
    for the model and the log, and it is not in this text (live dogfood
    2026-11-19: the Alerts page led with "19 of 497 shards").
    """
    hint = rejection_hint(exc.reason)
    reason = f"Elasticsearch states: {exc.reason}."
    if hint:
        return f"{hint} {reason} The result is unknown."
    return f"{reason} The result is unknown. Correct the query and search again."

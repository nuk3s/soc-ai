"""The query an observation carries, so the agent can read the departure again.

A profile observation used to cite three document ids and a sentence. The
hunt that a lead started then searched the grid for the departure from
scratch, and on the range it found other documents and argued from them. The
observation now names the OQL query that shows the departure: the entity,
the member and the window, with the aggregation that answers the question
an analyst asks first.

The query is OQL that the primer accepts. ``tests/test_observation_rerun.py``
parses and validates every shape with the same parser the agent's tool uses,
so a query the tool would refuse fails the build.

The query names no dataset. A plane that answers on ``data_stream.dataset``
and not on ``event.dataset`` would match nothing, and the entity and the
member already narrow the read to the documents behind the departure.
"""

from __future__ import annotations

from datetime import UTC, datetime

from soc_ai.dossier.profile import (
    _CATEGORICAL,
    _SHAPED_ENTITY_FIELD,
    member_alternates,
)

__all__ = ["oql_value", "rerun_query", "window_minutes"]

# The aggregation that answers the first question about each dimension. A new
# served port asks who reached it. A new outbound port asks where it went.
_GROUP_BY: dict[str, str] = {
    "served_ports": "source.ip",
    "consumed_ports": "destination.ip",
    "process_parents": "process.name",
    "active_hours": "destination.ip",
    "connection_rate": "destination.ip",
}


def oql_value(value: object) -> str:
    """One value as OQL writes it. A port stays bare. Anything else is quoted."""
    text = str(value)
    if text.isdigit():
        return text
    escaped = text.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def _stamp(at: datetime) -> str:
    if at.tzinfo is None:
        at = at.replace(tzinfo=UTC)
    return at.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _fields(dimension: str) -> tuple[str, tuple[str, ...]] | None:
    """The entity field and the member fields of one dimension."""
    for name, _candidates, _probe, entity_field, member_field in _CATEGORICAL:
        if name == dimension:
            return entity_field, (member_field, *member_alternates(dimension))
    if dimension in {"active_hours", "connection_rate"}:
        return _SHAPED_ENTITY_FIELD, ()
    return None


def rerun_query(
    dimension: str,
    entity_key: str,
    member: str | None,
    *,
    start: datetime,
    end: datetime,
    count_only: bool = False,
) -> str | None:
    """The OQL query that shows one departure, or None for a dimension it cannot state.

    ``member`` is the set member for a set dimension. A shaped dimension has
    no member field, so the window carries the question: the hours that
    departed. ``count_only`` asks for the count alone. A collapse has no
    documents to group, and the count is the statistic.
    """
    fields = _fields(dimension)
    if fields is None or not entity_key:
        return None
    entity_field, member_fields = fields
    clauses = [f"{entity_field}:{oql_value(entity_key)}"]
    if member_fields and member is not None and str(member) != "":
        terms = [f"{f}:{oql_value(member)}" for f in member_fields]
        clauses.append(terms[0] if len(terms) == 1 else f"({' OR '.join(terms)})")
    clauses.append(f'@timestamp:["{_stamp(start)}" TO "{_stamp(end)}"]')
    query = " AND ".join(clauses)
    if count_only:
        return f"{query} | count"
    group = _GROUP_BY.get(dimension)
    return f"{query} | groupby {group}" if group else query


def window_minutes(start: datetime, *, now: datetime) -> int:
    """How many minutes back from ``now`` a query window must reach to cover ``start``.

    The agent's query tool counts its window back from the present. A query
    whose window starts two days ago needs a range of at least two days.
    """
    if start.tzinfo is None:
        start = start.replace(tzinfo=UTC)
    if now.tzinfo is None:
        now = now.replace(tzinfo=UTC)
    return max(60, int((now - start).total_seconds() // 60) + 60)

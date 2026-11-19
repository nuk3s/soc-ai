"""The forms of a query that the grid takes, from the field types of the grid.

Elasticsearch fails a shard when a query is wrong for the type that the shard
maps a field with, and the other shards answer (production 2026-11-19, see
:class:`soc_ai.so_client.elastic.GridQueryRejectedError`). Some of those
failures have one exact correction, and soc-ai applies it before the search.

The types come from ``_field_caps`` of the index pattern
(:meth:`soc_ai.so_client.elastic.ElasticClient.field_types`). A type is never
guessed from a field name. With no answer from the grid, a query goes as
written, and the tool result explains a rejection.

The rule for a field that two indices map with two types: no correction. A
guess between two types is a guess, and the reason text of a rejection then
tells the author what to correct. One exception: ``date`` and ``date_nanos``
both take ISO 8601, so a field with those two types takes the date rewrite.

The corrections, and no others:

* the ``unmapped_type`` of a sort (:func:`sort_unmapped_type`);
* a wildcard of whole trailing octets on an ``ip`` field becomes the CIDR
  (``10.*`` becomes ``"10.0.0.0/8"``), and any other wildcard on an ``ip``
  field is a query error with the CIDR hint (:func:`rewrite`);
* a time ``YYYY-MM-DD HH:MM`` or ``YYYY-MM-DD HH:MM:SS`` on a ``date`` field
  becomes ISO 8601 in UTC (:func:`rewrite`). soc-ai states each time in UTC, so
  the rewrite is exact.

Each rewrite is stated to the model in the tool result, so that it sees the form.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass, replace
from datetime import datetime
from typing import assert_never

from soc_ai.errors import OqlValidationError
from soc_ai.so_client.oql import (
    And,
    BareValue,
    ContainsValue,
    FilterNode,
    GroupBy,
    MatchAll,
    Not,
    OqlAst,
    Or,
    QuotedValue,
    RangeValue,
    SortBy,
    Term,
    Value,
    WildcardValue,
)
from soc_ai.so_client.rejected_query import cidr_hint

FieldTypes = Mapping[str, frozenset[str]]

_IP_TYPES = frozenset({"ip"})
_DATE_TYPES = frozenset({"date", "date_nanos"})

# One IPv4 octet, with no leading zero.
_OCTET = r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
# Whole trailing octets: one to three written octets, then ``*`` octets.
_TRAILING_OCTETS_RE = re.compile(rf"^(?P<head>(?:{_OCTET}\.){{1,3}})(?P<tail>\*(?:\.\*)*)$")
# The two time forms with a space. The model writes them, and a date field
# with the format strict_date_optional_time rejects them.
_SPACED_TIME_RE = re.compile(
    r"^(?P<date>\d{4}-\d{2}-\d{2}) (?P<hour>\d{2}):(?P<minute>\d{2})(?::(?P<second>\d{2}))?$"
)
# The characters of a bare OQL value (the BARE_TOKEN of the grammar).
_BARE_RE = re.compile(r"^[a-zA-Z0-9_.\-:/+]+$")

# The ``unmapped_type`` that a sort takes for each field type of the grid. A
# type with a required parameter is no ``unmapped_type``: with ``scaled_float``
# the production grid failed the unmapped shards with "Field [scaling_factor]
# is required" (2026-11-19, read only). ``scaled_float`` sorts as a double, and
# the grid merges a ``long`` field with ``double`` and with ``keyword`` (the
# same read). A type that is not in the table sends the sort as written.
_UNMAPPED_TYPES: Mapping[str, str] = {
    "long": "long",
    "integer": "integer",
    "short": "short",
    "byte": "byte",
    "unsigned_long": "unsigned_long",
    "double": "double",
    "float": "float",
    "half_float": "half_float",
    "scaled_float": "double",
    "keyword": "keyword",
    "constant_keyword": "keyword",
    "wildcard": "keyword",
    "date": "date",
    "date_nanos": "date_nanos",
    "ip": "ip",
    "boolean": "boolean",
}

_IP_NOTE = "An IP field takes a CIDR."
_DATE_NOTE = "A date field takes ISO 8601 in UTC."


def sort_field(ast: OqlAst) -> str | None:
    """The field that ``sortby`` sorts the hits on, or ``None``.

    ``sortby count`` after a ``groupby`` sorts the buckets, not the hits.
    """
    sortby = next((s for s in ast.pipes if isinstance(s, SortBy)), None)
    if sortby is None:
        return None
    if sortby.field == "count" and any(isinstance(s, GroupBy) for s in ast.pipes):
        return None
    return sortby.field


def _wildcard(value: Value) -> str | None:
    """The wildcard pattern a term sends, as ``oql._term_to_dsl`` sends it."""
    if isinstance(value, WildcardValue):
        return value.pattern
    if isinstance(value, QuotedValue | BareValue) and ("*" in value.text or "?" in value.text):
        return value.text
    return None


def _spaced_time(text: str) -> bool:
    return _SPACED_TIME_RE.match(text) is not None


def _terms(node: FilterNode) -> list[Term]:
    if isinstance(node, Term):
        return [node]
    if isinstance(node, And | Or):
        return [term for child in node.children for term in _terms(child)]
    if isinstance(node, Not):
        return _terms(node.child)
    return []


def _may_rewrite(term: Term) -> bool:
    value = term.value
    if _wildcard(value) is not None:
        return True
    if isinstance(value, RangeValue):
        return _spaced_time(value.lo) or _spaced_time(value.hi)
    return isinstance(value, QuotedValue | BareValue) and _spaced_time(value.text)


def fields_to_type(ast: OqlAst, *, rewrite: bool = True) -> set[str]:
    """The fields whose types decide the form of ``ast``.

    The sort field, and with ``rewrite`` each field of a term that a rewrite
    of :func:`rewrite` can touch: a wildcard, or a time with a space.
    """
    out: set[str] = set()
    field = sort_field(ast)
    if field:
        out.add(field)
    if rewrite:
        out.update(term.field for term in _terms(ast.filter_) if _may_rewrite(term))
    return out


def sort_unmapped_type(ast: OqlAst, types: FieldTypes | None, *, index: str) -> str | None:
    """The ``unmapped_type`` of the sort, or ``None`` to send the sort as written.

    A sort on a field that one index does not map fails the shards of that
    index: "No mapping found for [network.bytes] in order to sort on" (3 of 612
    shards on production). The ``unmapped_type`` lets those shards sort with no
    value. It is the one type of the field (:data:`_UNMAPPED_TYPES`). A field
    with two types gets none, and so does a type that is not in that table.

    Raises :class:`OqlValidationError` when no index of ``index`` maps the
    field: the sort can sort nothing, so the search does not run.
    """
    field = sort_field(ast)
    if field is None or types is None or field not in types:
        return None
    found = types[field]
    if not found:
        raise OqlValidationError(
            f"sortby names the field {field!r}, and no index of {index} maps it. "
            "Sort on a field that the grid holds, or leave out the sortby stage.",
            fragment=field,
        )
    if len(found) == 1:
        return _UNMAPPED_TYPES.get(next(iter(found)))
    return None


@dataclass(frozen=True)
class Rewritten:
    """The query after the exact rewrites, and one note for each rewrite."""

    ast: OqlAst
    notes: tuple[str, ...] = ()


def _cidr(pattern: str) -> str | None:
    """``10.*`` as ``10.0.0.0/8``, or ``None`` for any other pattern."""
    m = _TRAILING_OCTETS_RE.match(pattern)
    if m is None:
        return None
    head = [octet for octet in m.group("head").split(".") if octet]
    stars = m.group("tail").count("*")
    if len(head) + stars > 4:
        return None
    octets = head + ["0"] * (4 - len(head))
    return f"{'.'.join(octets)}/{8 * len(head)}"


def _iso(text: str) -> str | None:
    """``2026-10-28 22:44`` as ``2026-10-28T22:44:00Z``, or ``None``."""
    m = _SPACED_TIME_RE.match(text)
    if m is None:
        return None
    second = m.group("second") or "00"
    try:
        at = datetime.strptime(
            f"{m.group('date')} {m.group('hour')}:{m.group('minute')}:{second}",
            "%Y-%m-%d %H:%M:%S",
        )
    except ValueError:
        return None
    return at.strftime("%Y-%m-%dT%H:%M:%SZ")


def _written(value: Value) -> str:
    """A value as OQL text."""
    if isinstance(value, QuotedValue):
        return f'"{value.text}"'
    if isinstance(value, BareValue):
        return value.text
    if isinstance(value, WildcardValue):
        return value.pattern
    if isinstance(value, RangeValue):
        return f"[{_bound(value.lo)} TO {_bound(value.hi)}]"
    if isinstance(value, ContainsValue):
        return f'~"{value.text}"' if value.phrase else f"~{value.text}"
    assert_never(value)


def _bound(text: str) -> str:
    return text if text == "*" or _BARE_RE.match(text) else f'"{text}"'


def _ip_term(term: Term, notes: list[str]) -> Term:
    pattern = _wildcard(term.value)
    if pattern is None:
        return term
    cidr = _cidr(pattern)
    if cidr is None:
        raise OqlValidationError(
            f"{term.field}:{_written(term.value)} is a wildcard on an IP field, and the grid "
            f"rejects a wildcard on an IP field. {cidr_hint(term.field)}",
            fragment=pattern,
        )
    new = Term(field=term.field, value=QuotedValue(text=cidr))
    notes.append(f'{term.field}:{_written(term.value)} became {term.field}:"{cidr}". {_IP_NOTE}')
    return new


def _date_term(term: Term, notes: list[str]) -> Term:
    value = term.value
    if isinstance(value, RangeValue):
        lo = _iso(value.lo)
        hi = _iso(value.hi)
        if lo is None and hi is None:
            return term
        new_value = RangeValue(lo=lo or value.lo, hi=hi or value.hi)
        after = f"[{_quoted_bound(new_value.lo)} TO {_quoted_bound(new_value.hi)}]"
        notes.append(f"{term.field}:{_written(value)} became {term.field}:{after}. {_DATE_NOTE}")
        return Term(field=term.field, value=new_value)
    if isinstance(value, QuotedValue | BareValue):
        iso = _iso(value.text)
        if iso is None:
            return term
        notes.append(f'{term.field}:{_written(value)} became {term.field}:"{iso}". {_DATE_NOTE}')
        return Term(field=term.field, value=QuotedValue(text=iso))
    return term


def _quoted_bound(text: str) -> str:
    return text if text == "*" else f'"{text}"'


def _rewrite_term(term: Term, types: FieldTypes, notes: list[str]) -> Term:
    found = types.get(term.field)
    if not found:
        return term
    if found == _IP_TYPES:
        return _ip_term(term, notes)
    if found <= _DATE_TYPES:
        return _date_term(term, notes)
    return term


def _rewrite_node(node: FilterNode, types: FieldTypes, notes: list[str]) -> FilterNode:
    if isinstance(node, MatchAll):
        return node
    if isinstance(node, Term):
        return _rewrite_term(node, types, notes)
    if isinstance(node, And):
        return And(children=tuple(_rewrite_node(c, types, notes) for c in node.children))
    if isinstance(node, Or):
        return Or(children=tuple(_rewrite_node(c, types, notes) for c in node.children))
    if isinstance(node, Not):
        return Not(child=_rewrite_node(node.child, types, notes))
    assert_never(node)


def rewrite(ast: OqlAst, types: FieldTypes | None) -> Rewritten:
    """``ast`` after the two exact rewrites, with a note for each.

    A wildcard of whole trailing octets on a field whose only type is ``ip``
    becomes the CIDR: on production ``destination.ip:10.*`` failed 97 of 612
    shards, and ``destination.ip:"10.0.0.0/8"`` answered. Any other wildcard
    on such a field raises :class:`OqlValidationError` with the CIDR hint, and
    the search does not run.

    A time ``YYYY-MM-DD HH:MM[:SS]`` on a field whose types are date types
    becomes ISO 8601 in UTC: on production the spaced form failed 168 of 612
    shards.

    With no types (the grid did not answer), ``ast`` comes back as written.
    """
    if types is None:
        return Rewritten(ast=ast)
    notes: list[str] = []
    filter_ = _rewrite_node(ast.filter_, types, notes)
    if not notes:
        return Rewritten(ast=ast)
    return Rewritten(ast=replace(ast, filter_=filter_), notes=tuple(notes))

"""One query, one answer: a filter term reads every name of its field.

One value has several field names. Security Onion 3.x writes
``ssh.authentication.success``, and an older grid and the synth fixtures write
``zeek.ssh.auth_success``. A filter on one name returned zero from a grid that
holds a different name, and ten scheduled hunts reported that zero as "no
successful SSH login".

:func:`widen_filter` is the one function that gives a term its other names.
Three readers decide whether to call it:

* the query tools of the model call it, so a filter on one name matches each
  name of the field;
* the filter bar of the console calls it, so the console gives the answer that
  the query tool gives for the same text;
* the Sigma dry run does NOT call it. Security Onion matches the name that a
  rule holds, so a dry run of the widened filter would report hits for a rule
  that can never fire.

Three kinds of name are widened:

* a field in :data:`soc_ai.so_client.fields.LOGICAL_FIELDS` becomes each name
  of its table,
* a dataset term becomes both dataset name fields and each name of the dataset,
* an alert label becomes both alert labels.

Two limits keep the widened filter equal in meaning to the written filter.

A filter that names two names of one thing stays as written for that thing.
``tags:alert AND NOT event.kind:alert`` asks for the difference of the two
labels, and widening each side made it "X AND NOT X".

A name is added only when its type accepts the value. ``dns.resolved_ip`` is
ip-typed, and Elasticsearch refuses a host name or a wildcard on it.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from typing import assert_never

from soc_ai.config import DEFAULT_ALERT_LABELS
from soc_ai.so_client import fields
from soc_ai.so_client.oql import (
    And,
    BareValue,
    FilterNode,
    MatchAll,
    Not,
    Or,
    QuotedValue,
    RangeValue,
    Term,
    Value,
)

# The labels that mark a document as an alert, as (field, value). Security
# Onion tags a Suricata or Sigma alert with ``tags:alert`` and sets no
# ``event.kind``. An Elastic Defend alert holds ``event.kind:alert`` and no tag.
ALERT_LABEL_TERMS: tuple[tuple[str, str], ...] = tuple(
    (name, value) for name, _sep, value in (label.partition(":") for label in DEFAULT_ALERT_LABELS)
)


@dataclass(frozen=True)
class Widening:
    """A widened filter, and the names that each written field was tested under.

    ``names`` holds one entry for each field of the written filter. The field
    check of a zero-hit query reads it: a field is absent only when no name
    that the query tested is present.
    """

    filter_: FilterNode
    names: dict[str, tuple[str, ...]] = field(default_factory=dict)


@dataclass(frozen=True)
class _Plan:
    """The things that the written filter names under two names. They stay as written."""

    tables: frozenset[tuple[str, ...]]
    alert_labels: bool
    dataset_fields: bool
    datasets: frozenset[tuple[str, ...]]


def _text(value: Value) -> str | None:
    return value.text if isinstance(value, BareValue | QuotedValue) else None


def _terms(node: FilterNode) -> list[Term]:
    if isinstance(node, Term):
        return [node]
    if isinstance(node, And | Or):
        return [term for child in node.children for term in _terms(child)]
    if isinstance(node, Not):
        return _terms(node.child)
    return []


def _plan(node: FilterNode) -> _Plan:
    terms = _terms(node)
    used: dict[tuple[str, ...], set[str]] = {}
    labels: set[tuple[str, str]] = set()
    dataset_fields: set[str] = set()
    dataset_names: dict[tuple[str, ...], set[str]] = {}
    for term in terms:
        table = fields.same_value_names(term.field)
        if len(table) > 1:
            used.setdefault(table, set()).add(term.field)
        text = _text(term.value)
        if text is not None and (term.field, text) in ALERT_LABEL_TERMS:
            labels.add((term.field, text))
        if term.field in fields.DATASET_NAME_FIELDS:
            dataset_fields.add(term.field)
            if text is not None:
                group = fields.same_dataset_names(text)
                if len(group) > 1:
                    dataset_names.setdefault(group, set()).add(text)
    return _Plan(
        tables=frozenset(table for table, names in used.items() if len(names) > 1),
        alert_labels=len(labels) > 1,
        dataset_fields=len(dataset_fields) > 1,
        datasets=frozenset(group for group, names in dataset_names.items() if len(names) > 1),
    )


def _is_address(text: str) -> bool:
    try:
        ipaddress.ip_network(text, strict=False)
    except ValueError:
        return False
    return True


def _accepts(name: str, value: Value) -> bool:
    """Whether the type of ``name`` accepts ``value``.

    Only an ip-typed name is strict here. It takes an address, a network in
    CIDR form, or a range of addresses. It takes no wildcard, no contains
    value and no other text.
    """
    if name not in fields.IP_TYPED_NAMES:
        return True
    if isinstance(value, RangeValue):
        return all(bound == "*" or _is_address(bound) for bound in (value.lo, value.hi))
    text = _text(value)
    return text is not None and _is_address(text)


def _widen_term(term: Term, plan: _Plan) -> tuple[FilterNode, tuple[str, ...]]:
    """The widened term, and the names that it tests."""
    value = term.value
    text = _text(value)
    if text is not None and (term.field, text) in ALERT_LABEL_TERMS:
        if plan.alert_labels:
            return term, (term.field,)
        alternatives = tuple(
            Term(field=name, value=BareValue(text=label)) for name, label in ALERT_LABEL_TERMS
        )
        return Or(children=alternatives), tuple(name for name, _label in ALERT_LABEL_TERMS)
    if term.field in fields.DATASET_NAME_FIELDS:
        if text is None:
            return term, (term.field,)
        group = fields.same_dataset_names(text)
        datasets = (text,) if group in plan.datasets else group
        name_fields = (term.field,) if plan.dataset_fields else fields.DATASET_NAME_FIELDS
        quoted = isinstance(value, QuotedValue)
        alternatives = tuple(
            Term(field=name, value=QuotedValue(text=d) if quoted else BareValue(text=d))
            for name in name_fields
            for d in datasets
        )
        if len(alternatives) == 1:
            return term, (term.field,)
        return Or(children=alternatives), name_fields
    table = fields.same_value_names(term.field)
    if len(table) == 1 or table in plan.tables:
        return term, (term.field,)
    names = tuple(name for name in table if name == term.field or _accepts(name, value))
    if len(names) == 1:
        return term, names
    return Or(children=tuple(Term(field=name, value=value) for name in names)), names


def _widen(node: FilterNode, plan: _Plan, names: dict[str, tuple[str, ...]]) -> FilterNode:
    if isinstance(node, MatchAll):
        return node
    if isinstance(node, Term):
        widened, tested = _widen_term(node, plan)
        merged = dict.fromkeys((*names.get(node.field, ()), *tested))
        names[node.field] = tuple(merged)
        return widened
    if isinstance(node, And):
        return And(children=tuple(_widen(child, plan, names) for child in node.children))
    if isinstance(node, Or):
        return Or(children=tuple(_widen(child, plan, names) for child in node.children))
    if isinstance(node, Not):
        return Not(child=_widen(node.child, plan, names))
    assert_never(node)


def widen_filter(node: FilterNode) -> Widening:
    """The filter with each term widened to every name of its field.

    Run it after validation. The written name passed the whitelist, and the
    added names are constants of this code base.
    """
    names: dict[str, tuple[str, ...]] = {}
    widened = _widen(node, _plan(node), names)
    return Widening(filter_=widened, names=names)


__all__ = ["ALERT_LABEL_TERMS", "Widening", "widen_filter"]

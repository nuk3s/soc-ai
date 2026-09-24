"""Evaluate a spec's clause tree against a document in memory.

This exists so a spec and a fixture can be checked against each other with no
Elasticsearch, which is what makes spec coverage a CI gate rather than something
somebody runs by hand against a lab grid that may be switched off.

**What it is not.** It is not an Elasticsearch emulator and must never be
described as one. It evaluates the CLAUSE FORM — the small constrained
vocabulary in :mod:`soc_ai.hunting.spec` — directly against a mapping. The
compiled ES DSL is tested separately, per clause, in ``test_hunt_spec``. Two
independent checks of the same spec, neither claiming to prove the other:

- this module proves the fixture satisfies the predicate the spec DESCRIBES;
- the compile tests prove the spec translates to the DSL it should;
- a live run against a real grid proves the whole path.

Where ES and this module genuinely differ, the difference is documented at the
operator rather than papered over. Analysed text fields are the main one, and
the reason specs are steered toward keyword fields.
"""

from __future__ import annotations

import fnmatch
from collections.abc import Mapping
from typing import Any

from soc_ai.hunting.spec import Clause, Detection, HuntSpec


def get_field(doc: Mapping[str, Any], path: str) -> Any:
    """Read a dotted path from a document held either flat or nested.

    A rendered fixture spells ``winlog.event_data.SubjectUserName`` as one flat
    key; a document read back from Elasticsearch nests it. Both are the same
    field and both must resolve, or a fixture would pass here and fail live.
    """
    if path in doc:
        return doc[path]
    node: Any = doc
    for part in path.split("."):
        if not isinstance(node, Mapping) or part not in node:
            return None
        node = node[part]
    return node


def _as_list(value: Any) -> list[Any]:
    """ES treats a scalar and a single-element array identically; so does this.

    Not a convenience: ``winlog.event_data.AccessMask`` really does arrive as
    ``["0x100"]`` on a live document and as ``"0x100"`` in a hand-written
    fixture, and a matcher that distinguished them would fail on real data.
    """
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        return list(value)
    return [value]


def field_is_present(doc: Mapping[str, Any], path: str) -> bool:
    """The one presence rule in this module, shared by ``exists`` and ``none``.

    It is the in-memory reading of Elasticsearch's ``exists`` query, and it
    differs from it in exactly one place: an empty string. Elasticsearch indexes
    ``""`` on a keyword field as a real term, so ``exists`` matches it; here it
    counts as absent. The difference is documented rather than papered over
    because the error runs in the safe direction. This module is the STRICTER
    of the two, so a spec can fail the coverage gate over a field that is
    present-but-empty live, and can never be certified by the gate while being
    unable to fire.
    """
    return any(v not in (None, "") for v in _as_list(get_field(doc, path)))


def clause_matches(clause: Clause, doc: Mapping[str, Any]) -> bool:
    """Whether one clause holds for ``doc``."""
    raw = get_field(doc, clause.field)
    values = _as_list(raw)

    if clause.op == "exists":
        return field_is_present(doc, clause.field)
    if not values:
        return False

    target = clause.value
    for value in values:
        text = str(value)
        if clause.op == "equals" and text == str(target):
            return True
        if clause.op == "one_of" and any(text == str(t) for t in target):
            return True
        if clause.op == "contains" and str(target) in text:
            return True
        if clause.op == "prefix" and text.startswith(str(target)):
            return True
        if clause.op == "wildcard" and fnmatch.fnmatchcase(text, str(target)):
            return True
        if clause.op in {"gt", "gte", "lt", "lte"} and _compare(value, clause.op, target):
            return True
    return False


def _compare(value: Any, op: str, target: Any) -> bool:
    try:
        left, right = float(value), float(target)
    except (TypeError, ValueError):
        left, right = str(value), str(target)  # type: ignore[assignment]
    if op == "gt":
        return left > right
    if op == "gte":
        return left >= right
    if op == "lt":
        return left < right
    return left <= right


def _survives_the_clauses(detection: Detection, doc: Mapping[str, Any]) -> bool:
    """The half the two readings below share, so they cannot drift apart.

    The positive clauses, and no exclusion firing on a field the document
    carries. Written out twice they would eventually disagree, and a document that fell
    out of both would be the silent drop this module exists to make impossible.
    """
    if not all(clause_matches(c, doc) for c in detection.all):
        return False
    if detection.any and not any(clause_matches(c, doc) for c in detection.any):
        return False
    return not any(clause_matches(c, doc) for c in detection.none)


def detection_matches(detection: Detection, doc: Mapping[str, Any]) -> bool:
    """Whether the whole tree holds: all of ``all``, one of ``any``, none of ``none``.

    An exclusion also rejects a document that does not carry the field it reads,
    which is what :meth:`Detection.exclusion_fields` compiles to an ``exists``
    filter. The two engines used to agree here, and agree on the wrong answer:
    a missing field makes ``clause_matches`` False, so ``not any(...)`` admitted
    the document exactly as ``must_not`` did. The coverage gate reproduced the
    defect faithfully and could never have caught it.

    Rejecting is not the same as forgetting. :func:`detection_undecided` holds
    the other half, and between them they partition
    :func:`_survives_the_clauses` with nothing falling through.
    """
    return _survives_the_clauses(detection, doc) and all(
        field_is_present(doc, f) for f in detection.exclusion_fields()
    )


def detection_undecided(detection: Detection, doc: Mapping[str, Any]) -> bool:
    """Whether the tree could not reach a verdict on ``doc`` for want of a field.

    The document satisfies the positive clauses and fires no exclusion it
    carries the field for, but at least one exclusion reads a field it does not
    have, so nothing here can say whether that exclusion applies. It is not a
    match and it is not a non-match. The in-memory reading of
    :meth:`HuntSpec.to_query` with ``undecided=True``.
    """
    return _survives_the_clauses(detection, doc) and not all(
        field_is_present(doc, f) for f in detection.exclusion_fields()
    )


def precondition_matches(spec: HuntSpec, doc: Mapping[str, Any]) -> bool:
    """Whether ``doc`` is in the population the precondition counts.

    The in-memory half of the schema-presence scope
    :meth:`HuntSpec.to_query` applies. Without it a harness that scores a
    fixture would count a copy of the event the detection cannot read, and the
    number an analyst is shown for "documents this spec examined" would be a
    different number in CI than on the grid.

    :meth:`Detection.required_fields` is the ``all`` block's value fields only,
    so a document missing an exclusion's field stays IN this count. It is
    examined; :func:`detection_undecided` is what says the examination reached
    no verdict. Counting it out here is what let a run with 5,240 discarded
    documents report a precondition of 182 and call itself clean.

    :meth:`Detection.alternative_fields` is the ``any`` block's, and it is
    checked as the block reads: at least one present, not all. A document
    carrying none of them satisfies no branch, so the detection is a decided
    non-match on it and it was never examinable — the duplicate-copy case the
    ``all`` scope already covers, reached through the block that names
    alternatives. Skipped whole when the precondition itself pins one of those
    fields by value, matching the compiler.
    """
    if spec.precondition is None:
        raise ValueError(f"spec {spec.id!r} has no precondition to evaluate")
    # A ``profile`` spec carries no detection block. It is answered from a
    # stored baseline, never from a document, so asking this question of one is
    # a caller error rather than a non-match. Silence here would count the
    # spec's whole population as examined and report a false all-clear.
    if spec.detection is None:
        raise ValueError(f"spec {spec.id!r} has no detection to evaluate")
    if not detection_matches(spec.precondition, doc):
        return False
    if not all(field_is_present(doc, f) for f in spec.detection.required_fields()):
        return False
    alternatives = spec.detection.alternative_fields()
    if not alternatives or set(spec.precondition.required_fields()) & set(alternatives):
        return True
    return any(field_is_present(doc, f) for f in alternatives)


__all__ = [
    "clause_matches",
    "detection_matches",
    "detection_undecided",
    "field_is_present",
    "get_field",
    "precondition_matches",
]

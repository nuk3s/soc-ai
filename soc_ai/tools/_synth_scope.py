"""Synthetic-eval document visibility, decided in exactly one place.

Every ES read path that can encounter planted eval documents (docs tagged
``synth.scenario_id``) threads a ``SynthScope`` value down from its
entrypoint and builds its exclusion clauses here:

- ``False`` — the production default. Every query excludes all synth docs,
  so planted fixtures can never contaminate a real investigation.
- a scenario id (``str``) — the batch-eval scope. Real docs plus THAT
  scenario's own plants are visible; every sibling scenario's plants are
  excluded. This is what stops one scenario's triage run from citing
  another scenario's planted evidence: the 25-scenario catalogue is
  ingested as one batch, its scenarios share endpoint IPs, and a blanket
  opt-in let b3-rmm-admin-lateral's host pivot return ten sibling
  scenarios' triage alerts as "corroborating evidence".
- ``True`` — every synth doc visible. Reserved for the hunt-journey
  runner, which drives a network-wide hunt over its own plants and runs
  one scenario at a time.

``bool(scope)`` still answers "is this a synth-eval run?" for the run
recorders — a scenario id is truthy by design.

**The marker moves.** The ingest stamps it at the top level of the event, but
Security Onion's Sigma pipeline re-nests the whole originating document under
an ``event_data`` envelope, so on the alert the pipeline emits the marker sits
one level down. Measured on the development range on 2026-09-06: of the 56,162
``tags:alert`` documents that survived a top-level-only exclusion, 2 carried
the marker under the envelope. They were a planted DCSync fixture, and they
presented as a critical Sigma detection in the live queue. Naming both
positions took the survivors to 56,160 and the ``sigma.alert`` class from 55 to
53, with ``suricata.alert`` unmoved at 56,107 and the three genuine DCSync
alerts on the real domain controller untouched.

A wildcard field expansion (``query_string`` over ``*synth.scenario_id``) finds
the same 2 documents and would need no list, but it is not used: it costs 219ms
against 9ms for the explicit form on the same query, on every read a run makes,
and when the expansion matches no mapped field it returns no clauses and no
error, which is the same silent nothing this module exists to prevent. An
explicit list is wrong loudly, in a test, rather than quietly, on a grid.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

# False = prod (no synth visible); True = all synth visible (hunt-journey
# eval); str = only that scenario's synth docs visible (batch eval).
SynthScope = bool | str

# The field for a scenario id, relative to whatever wraps it.
_MARKER_FIELD = "synth.scenario_id"

# The envelopes a Security Onion detection pipeline nests a source document
# under. One entry today: SO's Sigma/ElastAlert engine copies the whole
# originating event into ``event_data`` and writes its own ECS fields around
# it. Adding a pipeline is a line here and nothing else, because every read
# path in the product builds its clauses from :data:`MARKER_PATHS`.
_ENVELOPES: tuple[str, ...] = ("event_data",)

# Every position a scenario marker is known to occupy, most direct first.
MARKER_PATHS: tuple[str, ...] = (
    _MARKER_FIELD,
    *(f"{envelope}.{_MARKER_FIELD}" for envelope in _ENVELOPES),
)


def synth_scope_must_not(scope: SynthScope) -> list[dict[str, Any]]:
    """The ``must_not`` clauses enforcing ``scope``, ready to splice in.

    Returns ``[]`` for ``True`` (nothing excluded). Otherwise one clause per
    entry in :data:`MARKER_PATHS`, so the exclusion holds whether the marker
    sits at the top level of the document or under a detection pipeline's
    envelope. For a scenario id, each clause excludes docs that carry a marker
    at that position but do not match it; the match is tried against both the
    field and its ``.keyword`` subfield so it holds whether the synth index
    mapped the id as keyword or as dynamically-mapped text.
    """
    if scope is True:
        return []
    if isinstance(scope, str) and scope:
        return [
            {
                "bool": {
                    "must": [{"exists": {"field": path}}],
                    "must_not": [
                        {"term": {path: scope}},
                        {"term": {f"{path}.keyword": scope}},
                    ],
                }
            }
            for path in MARKER_PATHS
        ]
    return [{"exists": {"field": path}} for path in MARKER_PATHS]


def _dig(source: Any, path: str) -> Any:
    """Read ``path`` from a document that mixes nested and flat-dotted keys.

    Neither layout alone reaches the marker on a real Sigma alert: the envelope
    is a nested object, and the keys inside it are the source document's own
    dotted field names written flat, so the marker lives at
    ``source["event_data"]["synth.scenario_id"]``. Every split point is tried,
    which also covers the fully nested and fully flat forms.
    """
    if not isinstance(source, Mapping):
        return None
    if path in source:
        return source[path]
    segments = path.split(".")
    for i in range(1, len(segments)):
        head = source.get(".".join(segments[:i]))
        if head is not None and (found := _dig(head, ".".join(segments[i:]))) is not None:
            return found
    return None


def synth_marker(source: Mapping[str, Any]) -> str | None:
    """The scenario id this document is a plant for, or None if it is real.

    Reads the same positions :func:`synth_scope_must_not` excludes, so the
    question "would this run's scope have hidden this document" has one answer
    whether it is asked of the grid or of a document already in hand.
    """
    for path in MARKER_PATHS:
        if (value := _dig(source, path)) is not None:
            return str(value)
    return None


def scope_hidden_scenario(scope: SynthScope, source: Mapping[str, Any]) -> str | None:
    """The scenario id ``scope`` would have hidden this document for, else None.

    The point of asking is the anchor of an investigation, which is fetched by
    document id and so arrives without passing any of these clauses while every
    pivot after it does. A run whose own subject is one the run cannot query is
    not short of evidence; it is looking at something it is not allowed to see,
    and the difference is the whole verdict. Returns the id rather than a bare
    True so the refusal can name what it refused.
    """
    marker = synth_marker(source)
    if marker is None or scope is True:
        return None
    if isinstance(scope, str) and scope and marker == scope:
        return None
    return marker


__all__ = [
    "MARKER_PATHS",
    "SynthScope",
    "scope_hidden_scenario",
    "synth_marker",
    "synth_scope_must_not",
]

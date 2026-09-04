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
"""

from __future__ import annotations

from typing import Any

# False = prod (no synth visible); True = all synth visible (hunt-journey
# eval); str = only that scenario's synth docs visible (batch eval).
SynthScope = bool | str


def synth_scope_must_not(scope: SynthScope) -> list[dict[str, Any]]:
    """The ``must_not`` clauses enforcing ``scope``, ready to splice in.

    Returns ``[]`` for ``True`` (nothing excluded). For a scenario id, the
    clause excludes docs that carry ``synth.scenario_id`` but do not match
    it; the match is tried against both the field and its ``.keyword``
    subfield so it holds whether the synth index mapped the id as keyword
    or as dynamically-mapped text.
    """
    if scope is True:
        return []
    if isinstance(scope, str) and scope:
        return [
            {
                "bool": {
                    "must": [{"exists": {"field": "synth.scenario_id"}}],
                    "must_not": [
                        {"term": {"synth.scenario_id": scope}},
                        {"term": {"synth.scenario_id.keyword": scope}},
                    ],
                }
            }
        ]
    return [{"exists": {"field": "synth.scenario_id"}}]


__all__ = ["SynthScope", "synth_scope_must_not"]

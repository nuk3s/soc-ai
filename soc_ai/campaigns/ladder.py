"""The time by which a stage held, when a later stage proves it earlier.

A stage of the ladder takes its time from the first investigation that proves
it. One test (2026-11-17) read "Access" at 2026-11-12 after "Action on the
target" at 2026-10-28: the first investigation that proved the access itself
was a late one. An analyst then reads a ladder that runs backward.

An action on a target needs access to that target, and so does a target that
acts. So access held no later than the first proof of either stage.
:func:`held_by` states that time and the stage that gives it.

The rule is narrow by design. It says nothing for a stage that no later stage
needs: an attempt needs no seen reconnaissance, and access needs no seen
attempt. It reads stored times only, so a stored campaign needs no rebuild.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime

from soc_ai.campaigns.types import STAGES

# A stage, and the later stages that cannot happen without it.
NEEDED_BY: Mapping[str, tuple[str, ...]] = {"access": ("action", "movement")}


@dataclass(frozen=True)
class HeldBy:
    """A stage held by ``at``, because the stage ``stage`` has proof then."""

    at: datetime
    stage: str


def held_by(first_at: Mapping[str, datetime | None]) -> dict[str, HeldBy]:
    """The stages that a later stage proves earlier than their own proof.

    ``first_at`` maps each REACHED stage to the time of its first proof. A
    stage with no proof of its own is in the answer when a later stage that
    needs it is reached. A stage whose own proof is the earliest is not.
    """
    out: dict[str, HeldBy] = {}
    for stage, later in NEEDED_BY.items():
        proofs = [(at, s) for s in later if (at := first_at.get(s)) is not None]
        if not proofs:
            continue
        at, by = min(proofs, key=lambda proof: (proof[0], STAGES.index(proof[1])))
        own = first_at.get(stage)
        if own is None or at < own:
            out[stage] = HeldBy(at, by)
    return out

"""The title and the bottom line of a campaign. Pure.

Code writes both from the structure of the campaign: the actors, the targets,
the period and the stage. The model writes neither.
"""

from __future__ import annotations

from collections.abc import Sequence

from soc_ai.campaigns.types import ROLE_ACTOR, ROLE_TARGET, CampaignDraft, Party

# The stage in the words that a person reads. The console uses the same words
# (STAGE_LABEL in frontend/src/lib/campaignWords.ts). Every backend text that
# names a stage goes through stage_words or stage_sentence, never the raw value.
STAGE_WORDS: dict[str, str] = {
    "reconnaissance": "Reconnaissance",
    "attempt": "Attempt",
    "access": "Access",
    "action": "Action on the target",
    "movement": "Movement beyond the target",
}

# The most names that one sentence lists. More read as a count.
MAX_NAMES = 3


def stage_words(stage: str | None) -> str | None:
    """The words of a stage, or None for no stage or a value off the ladder."""
    return STAGE_WORDS.get(stage or "")


def stage_sentence(stage: str | None) -> str:
    """``Stage reached: Access.``, or ``No stage is proven.``"""
    words = stage_words(stage)
    return f"Stage reached: {words}." if words else "No stage is proven."


def party_name(party: Party) -> str:
    """The name of a party: its name, else its first address, else its machine key."""
    if party.name:
        return party.name
    if party.addresses:
        return party.addresses[0]
    return party.machine_key


def _join(names: Sequence[str]) -> str:
    if len(names) <= 1:
        return "".join(names)
    return f"{', '.join(names[:-1])} and {names[-1]}"


def _group(parties: Sequence[Party], noun: str) -> str:
    """The names of a group of parties, or a count with the noun."""
    if len(parties) > MAX_NAMES:
        return f"{len(parties)} {noun}"
    return _join([party_name(p) for p in parties])


def _sides(draft: CampaignDraft) -> tuple[str, str]:
    actors = [p for p in draft.parties if p.role == ROLE_ACTOR]
    targets = [p for p in draft.parties if p.role == ROLE_TARGET and not p.beyond]
    if not targets:
        targets = [p for p in draft.parties if p.role == ROLE_TARGET]
    return (_group(actors, "actors") or "An unknown source", _group(targets, "hosts") or "a host")


def title(draft: CampaignDraft) -> str:
    """``<actors> against <targets>``."""
    actors, targets = _sides(draft)
    return f"{actors} against {targets}"


def bottom_line(draft: CampaignDraft) -> str:
    """The bottom line: who acted on what and when, the stage, and the movement."""
    actors, targets = _sides(draft)
    first, last = draft.first_event.date().isoformat(), draft.last_event.date().isoformat()
    period = f"on {first}" if first == last else f"from {first} to {last}"
    stage = stage_sentence(draft.stage)
    beyond = draft.beyond_runs
    if beyond == 0:
        moved = "No activity beyond the target."
    else:
        noun = "investigation" if beyond == 1 else "investigations"
        moved = f"Activity beyond the target: {beyond} {noun}."
    return f"{actors} acted against {targets} {period}. {stage} {moved}"

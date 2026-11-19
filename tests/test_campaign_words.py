"""The title and the bottom line of a campaign."""

from __future__ import annotations

from datetime import datetime

from soc_ai.campaigns.types import STAGES, CampaignDraft, Link, Member, Party, RunFacts
from soc_ai.campaigns.words import bottom_line, party_name, stage_sentence, stage_words, title


def _draft(
    actors: list[Party],
    targets: list[Party],
    *,
    stage: str | None = "attempt",
    first: datetime = datetime(2026, 1, 10, 1),
    last: datetime = datetime(2026, 1, 10, 9),
    beyond: int = 0,
) -> CampaignDraft:
    members = tuple(
        Member(RunFacts(run_id=f"b{i}"), Link("target_source"), direction="beyond")
        for i in range(beyond)
    )
    return CampaignDraft(
        seed_run_id="r1",
        members=members,
        parties=tuple(actors + targets),
        ladder=(),
        stage=stage,
        first_event=first,
        last_event=last,
    )


def _actor(name: str) -> Party:
    return Party(f"agent:{name}", "actor", name=name)


def _target(i: int, *, name: str | None = None, beyond: bool = False) -> Party:
    return Party(
        f"ip:198.51.100.{i}", "target", name=name, addresses=(f"198.51.100.{i}",), beyond=beyond
    )


def test_party_name_falls_back_to_the_address_and_the_key() -> None:
    assert party_name(_target(10, name="web-1")) == "web-1"
    assert party_name(_target(10)) == "198.51.100.10"
    assert party_name(Party("mac:00:00:5e:00:53:01", "actor")) == "mac:00:00:5e:00:53:01"


def test_one_actor_and_one_target_on_one_day() -> None:
    draft = _draft([_actor("actor-a")], [_target(10)])
    assert title(draft) == "actor-a against 198.51.100.10"
    assert bottom_line(draft) == (
        "actor-a acted against 198.51.100.10 on 2026-01-10. "
        "Stage reached: Attempt. No activity beyond the target."
    )


def test_three_actors_over_a_period() -> None:
    draft = _draft(
        [_actor("actor-a"), _actor("actor-b"), _actor("actor-c")],
        [_target(10, name="web-1")],
        stage="action",
        last=datetime(2026, 1, 29, 0),
    )
    assert title(draft) == "actor-a, actor-b and actor-c against web-1"
    assert bottom_line(draft) == (
        "actor-a, actor-b and actor-c acted against web-1 from 2026-01-10 to 2026-01-29. "
        "Stage reached: Action on the target. No activity beyond the target."
    )


def test_many_targets_read_as_a_count() -> None:
    draft = _draft([_actor("actor-a")], [_target(i) for i in range(10, 26)], stage="reconnaissance")
    assert title(draft) == "actor-a against 16 hosts"


def test_no_stage() -> None:
    assert "No stage is proven." in bottom_line(
        _draft([_actor("actor-a")], [_target(10)], stage=None)
    )


def test_activity_beyond_the_target_counts_the_investigations() -> None:
    targets = [_target(10), _target(99, beyond=True)]
    one = _draft([_actor("actor-a")], targets, stage="movement", beyond=1)
    two = _draft([_actor("actor-a")], targets, stage="movement", beyond=2)
    assert title(one) == "actor-a against 198.51.100.10"
    # The analyst reads investigations. "run" is a word of the system.
    assert bottom_line(one).endswith("Activity beyond the target: 1 investigation.")
    assert bottom_line(two).endswith(
        "Stage reached: Movement beyond the target. Activity beyond the target: 2 investigations."
    )


# The words of each stage in every text that a person reads.
_STAGE_WORDS = {
    "reconnaissance": "Reconnaissance",
    "attempt": "Attempt",
    "access": "Access",
    "action": "Action on the target",
    "movement": "Movement beyond the target",
}


def test_every_stage_has_its_words() -> None:
    assert set(_STAGE_WORDS) == set(STAGES)
    for stage, words in _STAGE_WORDS.items():
        assert stage_words(stage) == words
        assert stage_sentence(stage) == f"Stage reached: {words}."


def test_no_stage_and_an_unknown_stage_print_no_raw_value() -> None:
    # Negative control: a value off the ladder never reaches a sentence.
    assert stage_words(None) is None
    assert stage_words("pivot") is None
    assert stage_sentence(None) == "No stage is proven."
    assert stage_sentence("pivot") == "No stage is proven."


def test_the_backend_texts_of_a_stage_use_the_words() -> None:
    from soc_ai.api.webui.routes_meta import _campaign_items, campaign_change_title

    class _Row:
        id = 7
        title = "actor-a against web-1"
        alerts = None
        waits_since = None
        first_event = datetime(2026, 1, 10, 1)
        last_event = datetime(2026, 1, 10, 2)
        targets = ()
        actors = ()
        targets_more = 0

    for stage, words in _STAGE_WORDS.items():
        bell = campaign_change_title("stage", "actor-a against web-1", {"from": None, "to": stage})
        assert bell == f"The campaign actor-a against web-1 reached the stage {words}."
        row = _Row()
        row.stage = stage  # type: ignore[attr-defined]
        (item,) = _campaign_items([row])
        assert item.detail == f"Stage reached: {words}."
        assert item.stage == stage, "the API field keeps the raw value for the color"
        line = bottom_line(_draft([_actor("actor-a")], [_target(10)], stage=stage))
        assert f"Stage reached: {words}." in line
    unknown = campaign_change_title("stage", "actor-a against web-1", {"to": "pivot"})
    assert "pivot" not in unknown

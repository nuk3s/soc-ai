"""The geometry requirement, as a test rather than a paragraph.

The design states two cases that MUST form a lead, and then says the half-life,
floor and threshold are chosen to satisfy them rather than the other way round.
That is a testable claim, so it is tested here. If someone moves a number and
these fail, the number was wrong — not the requirement.

It also pins the scenario the whole layer was designed around: a workstation
that visits a new external destination one evening and opens a connection to a
new internal port the next day. That chain formed no lead at all in the first
cut, because every novelty clause had been collapsed into a single kind and a
lead needs two.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from soc_ai.config import Settings
from soc_ai.hunting.leads import content_fingerprint, form_leads, record_observation
from soc_ai.hunting.weight import (
    DEFAULT_HALF_LIFE_HOURS,
    DEFAULT_LEAD_THRESHOLD,
    KIND_WEIGHT_CAP,
    Kind,
    birth_weight,
    lead_total,
    live_weight,
)
from soc_ai.store.db import make_engine, make_sessionmaker, run_migrations
from soc_ai.store.models import Lead
from sqlalchemy import select

pytestmark = pytest.mark.asyncio

_NOW = datetime(2026, 9, 15, 17, 0, tzinfo=UTC)
_HOST = ("host", "10.1.10.21")

# The longest two observations can be apart and still sit inside one working
# day. The requirement says "inside one working day", so the arithmetic has to
# hold at the far end of that, not at the convenient end.
_WORKING_DAY_HOURS = 8.0


async def _db(settings: Settings):  # type: ignore[no-untyped-def]
    engine = make_engine(settings)
    await run_migrations(engine)
    return engine, make_sessionmaker(engine)


def _pairs(pairs: list[tuple[Kind, float]]) -> list[tuple[Kind, float]]:
    return [
        (
            kind,
            live_weight(birth_weight(kind), born_at=_NOW - timedelta(hours=age), count=1, now=_NOW),
        )
        for kind, age in pairs
    ]


def _sum(pairs: list[tuple[Kind, float]]) -> float:
    return sum(weight for _kind, weight in _pairs(pairs))


def _total(pairs: list[tuple[Kind, float]]) -> float:
    """The same weights through the per-type cap, which is what formation reads."""
    return lead_total(_pairs(pairs))


# ---------------------------------------------------------------------------
# The arithmetic the design requires
# ---------------------------------------------------------------------------


async def test_two_of_the_strongest_kind_in_a_working_day_reach_the_threshold() -> None:
    """The design's first geometry case.

    Two at 0.5 sum to exactly 1.0 only with ZERO decay. Eight hours apart at a
    48-hour half-life they reach 0.945, so a threshold of 1.0 makes this case
    impossible — which is why the threshold is 0.85.
    """
    total = _sum([(Kind.NOVEL_DESTINATION, 0.0), (Kind.NOVEL_DESTINATION, _WORKING_DAY_HOURS)])
    assert total >= DEFAULT_LEAD_THRESHOLD, (
        f"two strongest-kind observations across a working day reach {total:.3f}, "
        f"under the threshold of {DEFAULT_LEAD_THRESHOLD}"
    )


async def test_three_of_the_weakest_kind_in_a_working_day_reach_the_threshold() -> None:
    """The design's second geometry case, and the binding one.

    Three at 0.3 spread across a working day reach 0.850. That is the tightest
    of the two requirements, so it is what sets the threshold.
    """
    total = _sum(
        [
            (Kind.OFF_HOURS, 0.0),
            (Kind.OFF_HOURS, _WORKING_DAY_HOURS / 2),
            (Kind.OFF_HOURS, _WORKING_DAY_HOURS),
        ]
    )
    assert total >= DEFAULT_LEAD_THRESHOLD, (
        f"three weakest-kind observations across a working day reach {total:.3f}, "
        f"under the threshold of {DEFAULT_LEAD_THRESHOLD}"
    )


async def test_the_threshold_is_not_so_low_that_two_weak_signals_suffice() -> None:
    # The other side of the calibration. If two off-hours observations formed a
    # lead, the layer would fire on any machine whose owner works late twice.
    total = _sum([(Kind.OFF_HOURS, 0.0), (Kind.OFF_HOURS, _WORKING_DAY_HOURS)])
    assert total < DEFAULT_LEAD_THRESHOLD


async def test_decay_still_ends_a_chain_that_stopped() -> None:
    # A week later the same three observations must be worth nothing like a
    # lead, or the layer accumulates forever and every host eventually forms one.
    total = _sum([(Kind.NOVEL_DESTINATION, 24.0 * 7)] * 3)
    assert total < DEFAULT_LEAD_THRESHOLD


async def test_the_half_life_is_the_one_the_design_named() -> None:
    # Pinned so a change to the half-life has to come with a change to this
    # file, where the requirement it must satisfy is written down.
    assert DEFAULT_HALF_LIFE_HOURS == 48.0


async def test_the_per_type_cap_leaves_both_required_cases_intact() -> None:
    # The cap is 2 x the threshold. Both required cases sit under it, so the
    # capped total and the plain sum are the same number.
    two_strong = [(Kind.NOVEL_DESTINATION, 0.0), (Kind.NOVEL_DESTINATION, _WORKING_DAY_HOURS)]
    three_weak = [
        (Kind.OFF_HOURS, 0.0),
        (Kind.OFF_HOURS, _WORKING_DAY_HOURS / 2),
        (Kind.OFF_HOURS, _WORKING_DAY_HOURS),
    ]
    assert _total(two_strong) == pytest.approx(_sum(two_strong))
    assert _total(three_weak) == pytest.approx(_sum(three_weak))
    assert _total(two_strong) >= DEFAULT_LEAD_THRESHOLD
    assert _total(three_weak) >= DEFAULT_LEAD_THRESHOLD


async def test_ten_of_one_kind_reach_the_cap_and_no_further() -> None:
    ten = [(Kind.NOVEL_DESTINATION, 0.0)] * 10
    assert _sum(ten) == pytest.approx(5.0)
    assert _total(ten) == pytest.approx(KIND_WEIGHT_CAP)


# ---------------------------------------------------------------------------
# The scenario the layer was designed around
# ---------------------------------------------------------------------------


async def test_the_github_then_switch_chain_forms_a_lead(
    settings_kratos: Settings,
) -> None:
    """A workstation that never goes to GitHub goes there at 7PM, and the next
    day opens an encrypted connection to a switch on port 1234.

    This is the scenario the hybrid design was chosen for, and in the first cut
    it formed nothing: both steps were "a member this baseline does not hold",
    both were therefore one kind, and a lead needs two. Splitting the novelty
    clauses into the kinds the design's layer-2 vocabulary already names is what
    makes it work.
    """
    _engine, maker = await _db(settings_kratos)
    evening = _NOW - timedelta(hours=24)

    async with maker() as db:
        # 7PM: a destination this host has never used...
        await record_observation(
            db,
            entity_kind=_HOST[0],
            entity_key=_HOST[1],
            kind=Kind.NOVEL_DESTINATION,
            spec_id="profile-novel-destination",
            fingerprint=content_fingerprint("peers_out", "140.82.121.4"),
            summary="first connection to 140.82.121.4 (github.com)",
            now=evening,
        )
        # ...at an hour this host is not normally active.
        await record_observation(
            db,
            entity_kind=_HOST[0],
            entity_key=_HOST[1],
            kind=Kind.OFF_HOURS,
            spec_id="profile-off-hours",
            fingerprint=content_fingerprint("hour", "19"),
            summary="active at 19:00, outside this host's measured hours",
            now=evening,
        )
        # Next day: a port this host has never connected out on.
        await record_observation(
            db,
            entity_kind=_HOST[0],
            entity_key=_HOST[1],
            kind=Kind.NOVEL_CONSUMED_PORT,
            spec_id="profile-novel-consumed-port",
            fingerprint=content_fingerprint("consumed_ports", "1234"),
            summary="first outbound connection on tcp/1234",
            now=_NOW,
        )

        outcome = await form_leads(db, entity_keys=[_HOST], now=_NOW)
        leads = (await db.execute(select(Lead))).scalars().all()

    assert len(outcome.formed) == 1, "the scenario the design exists for formed no lead"
    assert len(leads) == 1
    assert set(leads[0].kinds_json) == {
        "novel_destination",
        "off_hours",
        "novel_consumed_port",
    }


async def test_two_new_destinations_alone_still_do_not_form_a_lead(
    settings_kratos: Settings,
) -> None:
    """Splitting the kinds must not quietly repeal the two-kind rule.

    A host that talks to two new addresses is a host that talks to two new
    addresses. Both are NOVEL_DESTINATION, so this is still one kind and still
    not a chain — which is the whole point of the rule.
    """
    _engine, maker = await _db(settings_kratos)
    async with maker() as db:
        for addr in ("140.82.121.4", "151.101.1.6"):
            await record_observation(
                db,
                entity_kind=_HOST[0],
                entity_key=_HOST[1],
                kind=Kind.NOVEL_DESTINATION,
                spec_id="profile-novel-destination",
                fingerprint=content_fingerprint("peers_out", addr),
                now=_NOW,
            )
        outcome = await form_leads(db, entity_keys=[_HOST], now=_NOW)
    assert outcome.formed == ()


async def test_an_address_and_its_dns_name_are_one_kind_not_two(
    settings_kratos: Settings,
) -> None:
    """One connection must not satisfy the two-kind rule by itself.

    A new address and the name that resolved to it are the same outbound flow
    seen twice. Giving them separate kinds would let any single novel
    connection form a lead, which is the false-positive failure the rule
    exists to prevent.
    """
    from soc_ai.hunting.weight import kind_for_dimension

    assert kind_for_dimension("peers_out") is kind_for_dimension("dns_names")

    _engine, maker = await _db(settings_kratos)
    async with maker() as db:
        await record_observation(
            db,
            entity_kind=_HOST[0],
            entity_key=_HOST[1],
            kind=kind_for_dimension("peers_out"),
            spec_id="p",
            fingerprint=content_fingerprint("peers_out", "140.82.121.4"),
            now=_NOW,
        )
        await record_observation(
            db,
            entity_kind=_HOST[0],
            entity_key=_HOST[1],
            kind=kind_for_dimension("dns_names"),
            spec_id="p",
            fingerprint=content_fingerprint("dns_names", "github.com"),
            now=_NOW,
        )
        outcome = await form_leads(db, entity_keys=[_HOST], now=_NOW)
    assert outcome.formed == ()

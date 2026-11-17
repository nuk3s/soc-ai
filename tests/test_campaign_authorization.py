"""The authorization of a campaign: which investigations a campaign record covers (A2).

A campaign record lists machines, each an actor or a target, and no rule. An
investigation is inside when its source is a listed actor, its target is a
listed target and its event time is in the period. A finding investigation
with a target and no source is inside when its target is listed and each
machine that it names is listed. Each other investigation that touches a
listed machine is outside and gets normal handling. Each loud case has a
negative control: a wrong "inside" hides an attack.

The data is synthetic: placeholder addresses and names.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

import pytest
from soc_ai.agent import authorized_activity as aam
from soc_ai.campaigns import authorization as auth
from soc_ai.campaigns.types import KIND_ALERT, KIND_FINDING
from soc_ai.config import Settings
from soc_ai.store import authorized_activity as aa
from soc_ai.store import investigations as inv_svc
from soc_ai.store.auth import utcnow
from soc_ai.store.db import make_engine, make_sessionmaker, run_migrations
from soc_ai.store.models import Investigation

from tests.test_campaign_facts import (
    ACTOR,
    ACTOR_2,
    RULE,
    TARGET,
    TARGET_2,
    alert_doc,
    seed_hosts,
)

NOW = datetime(2026, 11, 15, 12, 0, 0)


def scope(**over: Any) -> aa.Scope:
    fields: dict[str, Any] = {
        "id": 7,
        "label": "Red team test",
        "sources": (),
        "target": aa.ScopeEntry(""),
        "rule_names": (),
        "rule_class": "",
        "starts_at": NOW - timedelta(days=1),
        "expires_at": NOW + timedelta(days=6),
        "created_by": "casey",
        "campaign_id": 3,
        "parties": (
            aa.PartyEntry("agent:a1", "actor", "actor-a", (ACTOR,)),
            aa.PartyEntry("ip:t1", "target", "web-1", (TARGET,)),
        ),
    }
    fields.update(over)
    return aa.Scope(**fields)


def ends(**over: Any) -> auth.RunEnds:
    fields: dict[str, Any] = {
        "run_id": "run-1",
        "kind": KIND_ALERT,
        "source_address": ACTOR,
        "target_address": TARGET,
        "source_key": "agent:a1",
        "target_key": "ip:t1",
        "event_time": NOW - timedelta(hours=2),
    }
    fields.update(over)
    return auth.RunEnds(**fields)


# ── The pure rules ─────────────────────────────────────────────────────────


def test_a_report_that_names_a_third_machine_is_outside() -> None:
    """The two ends are listed. The text of the report names one more
    machine, so the investigation is about more than the listed machines."""
    by_name = ends(mentions=(("web-2", frozenset({"ip:t2"})),))
    assert auth.why_outside(scope(), by_name) == auth.WHY_MACHINE
    no_machine = ends(mentions=(("203.0.113.77", frozenset()),))
    assert auth.why_outside(scope(), no_machine) == auth.WHY_MACHINE
    unread = ends(mentions=(auth._NAMES_UNREAD,))
    assert auth.why_outside(scope(), unread) == auth.WHY_MACHINE
    finding = ends(kind=KIND_FINDING, mentions=(("web-2", frozenset({"ip:t2"})),))
    assert auth.why_outside(scope(), finding) == auth.WHY_MACHINE


def test_a_report_that_names_only_listed_machines_is_inside() -> None:
    """A name that a listed machine carries is inside, also when a second
    machine carries the same name."""
    own = ends(
        mentions=(
            ("web-1", frozenset({"ip:t1"})),
            (ACTOR, frozenset({"agent:a1"})),
            ("shared", frozenset({"ip:t1", "ip:zz"})),
        )
    )
    assert auth.why_outside(scope(), own) is None


def test_the_mentions_of_a_text_are_its_addresses_and_its_whole_machine_names() -> None:
    names = {
        "web-1": frozenset({"ip:t1"}),
        "web-2": frozenset({"ip:t2"}),
        "blue": frozenset({"ip:b1"}),
    }
    text = "actor-a at 192.0.2.10 reached WEB-2. The blueprint and sky-blue are no machine."
    assert dict(auth.mentions_of([text], names)) == {
        "192.0.2.10": None,
        "web-2": frozenset({"ip:t2"}),
    }
    assert auth.mentions_of([], names) == []
    # Unreadable machine names: nothing shows what a name in the text is.
    assert auth.mentions_of([text], None) == [auth._NAMES_UNREAD]


def test_an_alert_between_a_listed_actor_and_a_listed_target_in_the_period_is_inside() -> None:
    assert auth.why_outside(scope(), ends()) is None
    assert auth.judge([scope()], ends()) == (scope(), None)


def test_the_answer_of_a_listed_target_to_a_listed_actor_is_inside() -> None:
    """An alert on the answer of the server has the target as its source and
    the actor as its destination. It is between the same two machines."""
    answer = ends(
        source_key="ip:t1", source_address=TARGET, target_key="agent:a1", target_address=ACTOR
    )
    assert auth.why_outside(scope(), answer) is None
    # The time and the text of the report still count for an answer.
    late = ends(
        source_key="ip:t1",
        source_address=TARGET,
        target_key="agent:a1",
        target_address=ACTOR,
        event_time=NOW + timedelta(days=7),
    )
    assert auth.why_outside(scope(), late) == auth.WHY_EXPIRED
    third = ends(
        source_key="ip:t1",
        source_address=TARGET,
        target_key="agent:a1",
        target_address=ACTOR,
        mentions=(("web-2", frozenset({"ip:t2"})),),
    )
    assert auth.why_outside(scope(), third) == auth.WHY_MACHINE


@pytest.mark.parametrize(
    ("label", "over", "why"),
    [
        (
            "a source that is not listed",
            {"source_key": "agent:a2", "source_address": ACTOR_2},
            "source",
        ),
        ("no source address", {"source_key": None, "source_address": None}, "source"),
        (
            "a listed target as the source against an unlisted machine",
            {
                "source_key": "ip:t1",
                "source_address": TARGET,
                "target_key": "ip:t2",
                "target_address": TARGET_2,
            },
            "source",
        ),
        (
            "a listed actor against another listed actor",
            {"target_key": "agent:a1", "target_address": ACTOR},
            "target",
        ),
        (
            "a listed actor against a target that is not listed",
            {"target_key": "ip:t2", "target_address": TARGET_2},
            "target",
        ),
        ("an event after the expiry", {"event_time": NOW + timedelta(days=7)}, "expired"),
        ("an event before the start", {"event_time": NOW - timedelta(days=2)}, "expired"),
        ("no event time", {"event_time": None}, "expired"),
        (
            "a source address that now resolves to another machine",
            {"source_key": "agent:a2"},
            "machine",
        ),
        ("a target address that now resolves to no machine", {"target_key": None}, "machine"),
        ("a hit of a deception sensor", {"decoy": True}, "target"),
    ],
)
def test_each_loud_case_is_outside(label: str, over: dict[str, Any], why: str) -> None:
    answer = auth.judge([scope()], ends(**over))
    assert answer is not None, label
    assert answer[1] == why, label


def test_a_finding_between_listed_machines_that_names_only_listed_machines_is_inside() -> None:
    finding = ends(kind=KIND_FINDING, named=((ACTOR, "agent:a1"), (TARGET, "ip:t1")))
    assert auth.why_outside(scope(), finding) is None


def test_a_finding_with_a_listed_target_and_no_source_is_inside() -> None:
    finding = ends(
        kind=KIND_FINDING, source_address=None, source_key=None, named=((TARGET, "ip:t1"),)
    )
    assert auth.why_outside(scope(), finding) is None
    # A negative control: the same finding on a target that is not listed.
    other = ends(
        kind=KIND_FINDING,
        source_address=None,
        source_key=None,
        target_address=TARGET_2,
        target_key="ip:t2",
        named=((TARGET_2, "ip:t2"),),
    )
    assert auth.why_outside(scope(), other) == "target"


@pytest.mark.parametrize(
    ("label", "named"),
    [
        ("an unlisted machine", ((TARGET, "ip:t1"), (TARGET_2, "ip:t2"))),
        ("an address with no machine", ((TARGET, "ip:t1"), ("198.51.100.99", None))),
        ("a host by its name", ((TARGET, "ip:t1"), ("web-1", None))),
    ],
)
def test_a_finding_that_names_a_machine_beyond_the_list_is_outside(
    label: str, named: tuple[tuple[str, str | None], ...]
) -> None:
    finding = ends(kind=KIND_FINDING, source_address=None, source_key=None, named=named)
    assert auth.why_outside(scope(), finding) == "machine", label


def test_an_investigation_of_other_machines_gets_no_answer() -> None:
    other = ends(
        source_key="agent:a2",
        source_address=ACTOR_2,
        target_key="ip:t2",
        target_address=TARGET_2,
    )
    assert auth.judge([scope()], other) is None


def test_a_revoked_record_and_a_rule_list_record_cover_nothing() -> None:
    revoked = scope(revoked_at=NOW - timedelta(hours=1))
    rule_list = scope(campaign_id=None, parties=())
    assert auth.judge([revoked, rule_list], ends()) is None


def test_the_match_of_the_rule_list_form_skips_a_campaign_record() -> None:
    alert = SimpleNamespace(
        source_ip=ACTOR,
        destination_ip=TARGET,
        rule_name=RULE,
        timestamp=NOW,
        classtype="web-application-attack",
        event_dataset="suricata.alert",
        event_module="suricata",
        tags=[],
        observer_name=None,
    )
    answer = aam.match(
        alert,
        [],
        verdict="true_positive",
        run_flags=aam.RunFlags(),
        authorizations=[scope()],
        memberships={},
    )
    assert answer is None


def test_the_outside_line_names_the_reason() -> None:
    assert auth.outside_line("Red team test", "source") == (
        "This activity is outside the authorization Red team test: "
        "the source is not a listed actor."
    )


# ── The store form ─────────────────────────────────────────────────────────


@pytest.fixture
async def maker(settings_kratos: Settings) -> Any:
    engine = make_engine(settings_kratos)
    await run_migrations(engine)
    try:
        yield make_sessionmaker(engine)
    finally:
        await engine.dispose()


def parties(*roles: str) -> list[aa.PartyEntry]:
    entries = {
        "actor": aa.PartyEntry("agent:a1", "actor", "actor-a", (ACTOR,)),
        "target": aa.PartyEntry("ip:t1", "target", "web-1", (TARGET,)),
    }
    return [entries[r] for r in roles]


async def record(db: Any, **over: Any) -> aa.AuthorizedActivity:
    now = utcnow()
    fields: dict[str, Any] = {
        "campaign_id": 3,
        "label": "Red team test",
        "parties": parties("actor", "target"),
        "starts_at": now - timedelta(hours=6),
        "expires_at": now + timedelta(days=7),
        "created_by": "casey",
        "now": now,
    }
    fields.update(over)
    return await aa.create_for_campaign(db, **fields)


async def test_a_campaign_record_stores_machines_and_no_rule(maker: Any) -> None:
    async with maker() as db:
        row = await record(db)
        assert (row.rule_names, row.rule_class, row.target_address, row.sources) == ([], "", "", [])
        assert row.campaign_id == 3
        assert row.parties == [
            {"machine_key": "agent:a1", "role": "actor", "name": "actor-a", "addresses": [ACTOR]},
            {"machine_key": "ip:t1", "role": "target", "name": "web-1", "addresses": [TARGET]},
        ]
        held = aa.scope_of(row)
        assert (held.actors, held.targets) == (frozenset({"agent:a1"}), frozenset({"ip:t1"}))
        assert await aa.campaign_record(db, row.id) == held


@pytest.mark.parametrize(
    ("label", "over", "reason"),
    [
        ("no actor", {"parties": parties("target")}, "actor_required"),
        ("no target", {"parties": parties("actor")}, "target_required"),
        ("an empty label", {"label": "  "}, "label_required"),
        (
            "an expiry in the past",
            {"expires_at": utcnow() - timedelta(minutes=1)},
            "expiry_in_past",
        ),
        ("an expiry past 30 days", {"expires_at": utcnow() + timedelta(days=31)}, "expiry_too_far"),
    ],
)
async def test_the_store_refuses_a_bad_campaign_record(
    maker: Any, label: str, over: dict[str, Any], reason: str
) -> None:
    async with maker() as db:
        with pytest.raises(aa.ScopeError) as caught:
            await record(db, **over)
        assert caught.value.reason == reason, label


# ── The finish of a run ────────────────────────────────────────────────────


class _Audit:
    def __init__(self) -> None:
        self.records: list[tuple[str, dict[str, Any]]] = []

    async def log_kind(self, _session: str, kind: str, payload: dict[str, Any], **_: Any) -> None:
        self.records.append((kind, payload))


REPORT: dict[str, Any] = {
    "verdict": "true_positive",
    "confidence": 0.85,
    "summary": "The source sent exploit requests to the web server.",
    "recommended_actions": [],
}


async def _running(
    db: Any, *, src: str, dst: str, finding: bool = False
) -> tuple[str, dict[str, Any]]:
    """One run that is not finalized yet, with its stored alert context."""
    extra: dict[str, Any] = {}
    if finding:
        extra = {
            "kind": "hunt",
            "hunt_id": "01JHUNT0000000000000000001",
            "finding_ordinal": 0,
            "subject": {
                "type": "hunt",
                "judges": "finding",
                "hunt_id": "01JHUNT0000000000000000001",
            },
        }
    inv = await inv_svc.create(
        db, alert_es_id="alert-9", started_by="auto-triage", rule_name=RULE, **extra
    )
    context = {
        "alert": alert_doc("alert-9", datetime.now(UTC) - timedelta(minutes=5), src=src, dst=dst)
    }
    await inv_svc.append_events(
        db, inv.id, [{"sequence": 1, "kind": "enriched_alert_context", "payload": context}]
    )
    return str(inv.id), context


async def _mark(maker: Any, inv_id: str, context: dict[str, Any], **kw: Any) -> dict[str, Any]:
    state = SimpleNamespace(db_sessionmaker=maker, audit=_Audit())
    out = await aam.mark_report(
        state,
        dict(kw.get("report") or REPORT),
        enriched_payload=context,
        started_by="auto-triage",
        kind=kw.get("kind"),
        synthetic=False,
        subject=kw.get("subject"),
        investigation_id=inv_id,
    )
    state.out = out
    return {"report": out, "audit": state.audit.records}


async def test_an_inside_alert_gets_the_mark_before_the_webhook(maker: Any) -> None:
    async with maker() as db:
        await seed_hosts(db)
        row = await record(db)
        inv_id, context = await _running(db, src=ACTOR, dst=TARGET)
    done = await _mark(maker, inv_id, context)
    mark = done["report"]["authorized_activity"]
    assert (mark["state"], mark["id"], mark["campaign_id"]) == ("matched", row.id, 3)
    assert aa.authorization_id_of(done["report"]) == row.id
    assert [kind for kind, _p in done["audit"]] == ["authorized_activity_matched"]
    # The verdict and the text of the model stay.
    assert done["report"]["verdict"] == "true_positive"
    assert done["report"]["summary"] == REPORT["summary"]


async def test_an_alert_whose_report_names_a_third_machine_stays_loud(maker: Any) -> None:
    """The alert is between a listed actor and a listed target. Its report
    states that the source then reached another machine."""
    async with maker() as db:
        await seed_hosts(db)
        await record(db)
        inv_id, context = await _running(db, src=ACTOR, dst=TARGET)
    report = dict(REPORT, summary=f"{REPORT['summary']} The source then reached web-2.")
    done = await _mark(maker, inv_id, context, report=report)
    mark = done["report"]["authorized_activity"]
    assert (mark["state"], mark["parts"]) == ("outside", ["machine"])
    assert aa.authorization_id_of(done["report"]) is None


async def test_an_alert_whose_report_names_its_own_machines_is_inside(maker: Any) -> None:
    async with maker() as db:
        await seed_hosts(db)
        row = await record(db)
        inv_id, context = await _running(db, src=ACTOR, dst=TARGET)
    report = dict(REPORT, summary=f"actor-a at {ACTOR} sent exploit requests to web-1 at {TARGET}.")
    done = await _mark(maker, inv_id, context, report=report)
    assert done["report"]["authorized_activity"]["state"] == "matched"
    assert aa.authorization_id_of(done["report"]) == row.id


async def test_unreadable_machine_names_leave_an_inside_alert_loud(maker: Any) -> None:
    async with maker() as db:
        await seed_hosts(db)
        await record(db)
        inv_id, context = await _running(db, src=ACTOR, dst=TARGET)
    with patch.object(aa, "machine_names", side_effect=RuntimeError("store")):
        done = await _mark(maker, inv_id, context)
    mark = done["report"].get("authorized_activity")
    assert mark is None or mark["state"] == "outside"
    assert aa.authorization_id_of(done["report"]) is None


async def test_an_alert_from_an_unlisted_source_stays_loud(maker: Any) -> None:
    async with maker() as db:
        await seed_hosts(db)
        await record(db)
        inv_id, context = await _running(db, src=ACTOR_2, dst=TARGET)
    done = await _mark(maker, inv_id, context)
    mark = done["report"]["authorized_activity"]
    assert mark["state"] == "outside"
    assert mark["parts"] == ["source"]
    assert aa.authorization_id_of(done["report"]) is None


async def test_an_inside_finding_is_marked_and_an_outside_finding_is_not(maker: Any) -> None:
    from soc_ai.store.models import Hunt

    async with maker() as db:
        await seed_hosts(db)
        await record(db)
        db.add(
            Hunt(
                id="01JHUNT0000000000000000001",
                objective="Find the upload.",
                status="complete",
                report={"findings": [{"title": "Upload", "hosts": [TARGET]}]},
            )
        )
        await db.commit()
        inside_id, inside_ctx = await _running(db, src=ACTOR, dst=TARGET, finding=True)
    subject = {"type": "hunt", "judges": "finding"}
    done = await _mark(maker, inside_id, inside_ctx, kind="hunt", subject=subject)
    assert done["report"]["authorized_activity"]["state"] == "matched"

    # A negative control: the finding names a machine that is not listed.
    async with maker() as db:
        hunt = await db.get(Hunt, "01JHUNT0000000000000000001")
        hunt.report = {"findings": [{"title": "Upload", "hosts": [TARGET, TARGET_2]}]}
        await db.commit()
        outside_id, outside_ctx = await _running(db, src=ACTOR, dst=TARGET, finding=True)
    done = await _mark(maker, outside_id, outside_ctx, kind="hunt", subject=subject)
    mark = done["report"]["authorized_activity"]
    assert (mark["state"], mark["parts"]) == ("outside", ["machine"])
    assert aa.authorization_id_of(done["report"]) is None


async def test_a_store_error_in_the_matcher_gives_normal_handling(maker: Any) -> None:
    async with maker() as db:
        await seed_hosts(db)
        await record(db)
        inv_id, context = await _running(db, src=ACTOR, dst=TARGET)
    with patch.object(auth, "ends_of", side_effect=RuntimeError("the store is locked")):
        done = await _mark(maker, inv_id, context)
    assert "authorized_activity" not in done["report"]
    assert done["audit"] == []


async def test_an_expired_record_leaves_a_later_event_loud(maker: Any) -> None:
    async with maker() as db:
        await seed_hosts(db)
        row = await record(db)
        # The record ended one hour ago. The event is five minutes old.
        row.expires_at = utcnow() - timedelta(hours=1)
        await db.commit()
        inv_id, context = await _running(db, src=ACTOR, dst=TARGET)
    done = await _mark(maker, inv_id, context)
    mark = done["report"]["authorized_activity"]
    assert (mark["state"], mark["parts"]) == ("outside", ["expired"])


async def test_a_rule_list_record_still_marks_its_alert_beside_a_campaign_record(
    maker: Any,
) -> None:
    async with maker() as db:
        await seed_hosts(db)
        now = utcnow()
        old = await aa.create(
            db,
            label="Rule list test",
            sources=[aa.ScopeEntry(ACTOR, "agent:a1", "actor-a")],
            target=aa.ScopeEntry(TARGET, "ip:t1"),
            rule_names=[RULE],
            rule_class="exploit_attempt",
            starts_at=now - timedelta(hours=1),
            expires_at=now + timedelta(days=7),
            created_by="casey",
            now=now,
        )
        await record(db)
        inv_id, context = await _running(db, src=ACTOR, dst=TARGET)
    done = await _mark(maker, inv_id, context)
    mark = done["report"]["authorized_activity"]
    assert (mark["state"], mark["id"]) == ("matched", old.id)
    assert "campaign_id" not in mark


async def test_a_lead_promotion_and_a_replay_get_no_campaign_answer(maker: Any) -> None:
    async with maker() as db:
        await seed_hosts(db)
        await record(db)
        inv_id, context = await _running(db, src=ACTOR, dst=TARGET)
    state = SimpleNamespace(db_sessionmaker=maker, audit=_Audit())
    for kind, started_by in (("lead", "auto-triage"), (None, "backtest")):
        out = await aam.mark_report(
            state,
            dict(REPORT),
            enriched_payload=context,
            started_by=started_by,
            kind=kind,
            synthetic=False,
            investigation_id=inv_id,
        )
        assert "authorized_activity" not in out


async def test_the_ends_of_a_stored_investigation_come_from_the_hosts_data_now(
    maker: Any,
) -> None:
    async with maker() as db:
        await seed_hosts(db)
        inv_id, _context = await _running(db, src=ACTOR, dst=TARGET)
        inv = await db.get(Investigation, inv_id)
        found = (await auth.ends_of(db, [inv]))[inv_id]
    assert (found.source_key, found.target_key, found.kind) == ("agent:a1", "ip:t1", KIND_ALERT)
    assert found.event_time is not None


async def test_a_revoke_clears_each_mark_and_the_decision_and_forms_no_lead(maker: Any) -> None:
    from soc_ai.campaigns import decisions
    from soc_ai.store.models import Campaign, CampaignChange
    from sqlalchemy import select

    from tests.test_campaign_facts import seed_run

    now = utcnow()
    async with maker() as db:
        await seed_hosts(db)
        run_id = await seed_run(db, "alert-0001")
        campaign = Campaign(
            seed_run_id=run_id,
            title="actor-a against web-1",
            bottom_line="actor-a acted against web-1.",
            first_event=now - timedelta(hours=3),
            last_event=now - timedelta(hours=1),
            member_count=1,
            detail={},
            built_at=now,
        )
        db.add(campaign)
        await db.flush()
        row = await record(db, campaign_id=campaign.id)
        decisions.write_authorize(
            db, campaign, authorization_id=row.id, label=row.label, by="casey", basis={}, now=now
        )
        inv = await db.get(Investigation, run_id)
        inv.authorization_id = row.id
        await db.commit()
        assert await aa.holds_run(db, inv)
        with patch.object(inv_svc, "_observe_verdict") as observed:
            revoked, changed = await auth.revoke_record(
                db, row.id, by="morgan", reason="The test ended early.", now=now
            )
            await db.commit()
        assert changed and revoked is not None
        assert observed.call_count == 0, "a revoke forms no lead for each investigation"
        inv = await db.get(Investigation, run_id)
        assert not await aa.holds_run(db, inv)
        held = await db.get(Campaign, campaign.id)
        assert (held.decision, held.authorization_id) == (None, row.id)
        changes = (
            await db.scalars(select(CampaignChange.detail).where(CampaignChange.type == "reopened"))
        ).all()
        assert changes == [{"cause": "revoked", "by": "morgan"}]

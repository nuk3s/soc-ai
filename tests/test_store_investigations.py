"""Tests for the investigations store service."""

from __future__ import annotations

from datetime import timedelta

import pytest
from soc_ai.config import Settings
from soc_ai.store import investigations as inv_svc
from soc_ai.store.auth import utcnow
from soc_ai.store.db import make_engine, make_sessionmaker, run_migrations
from soc_ai.store.models import Investigation
from sqlalchemy import select


async def _db(settings: Settings):  # type: ignore[no-untyped-def]
    engine = make_engine(settings)
    await run_migrations(engine)
    return engine, make_sessionmaker(engine)


# The inheritance key, always built through its constructor so a test can never
# assert against a shape the production callers do not produce.
key = inv_svc.pair_key


REPORT = {
    "verdict": "false_positive",
    "confidence": 0.85,
    "summary": "Benign ICMP echo between gateway and Mac. Nothing else.",
    "citations": ["x7KpQ2"],
    "recommended_actions": [
        {
            "tool_name": "ack_alert",
            "tool_args": {"alert_id": "x7KpQ2"},
            "rationale": "Routine gateway monitoring traffic.",
        }
    ],
}


async def test_a_hunt_subject_verdict_writes_no_alert_observation(
    settings_kratos: Settings,
) -> None:
    """The verdict is on the hunt, not on the anchor document.

    An alert observation on the anchor would feed a second lead on the ground
    the promoted lead already covered.
    """
    from soc_ai.store.models import EntityObservation, Investigation

    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        hunt_run = Investigation(
            id="01HUNTSUBJECT00000000000000",
            alert_es_id="doc-1",
            started_by="admin",
            kind="lead",
            status="complete",
            verdict="true_positive",
            confidence=0.8,
            src_ip="10.1.2.3",
            subject_json={"type": "hunt", "hunt_id": "h1", "document_ids": ["doc-1"]},
        )
        alert_run = Investigation(
            id="01ALERTRUN00000000000000000",
            alert_es_id="doc-2",
            started_by="admin",
            kind="suricata",
            status="complete",
            verdict="true_positive",
            confidence=0.8,
            src_ip="10.1.2.4",
        )
        db.add_all([hunt_run, alert_run])
        await db.flush()
        await inv_svc._observe_verdict(db, hunt_run)
        await inv_svc._observe_verdict(db, alert_run)
        await db.commit()
        rows = (await db.execute(select(EntityObservation))).scalars().all()
    assert [r.entity_key for r in rows] == ["10.1.2.4"]
    await engine.dispose()


async def test_create_seeds_rule_name_at_birth(settings_kratos: Settings) -> None:
    """create(rule_name=...) names the row immediately so it is never anonymous,
    even if the run dies before the first alert_context event. Empty/None seeds
    leave it NULL for the recorder's stream-backfill."""
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        named = await inv_svc.create(
            db, alert_es_id="a1", started_by="admin", rule_name="ET SCAN seeded"
        )
        assert named.rule_name == "ET SCAN seeded"

        # Empty string must NOT persist as "" — it stays NULL so backfill can fire.
        blank = await inv_svc.create(db, alert_es_id="a2", started_by="admin", rule_name="")
        assert blank.rule_name is None

        none = await inv_svc.create(db, alert_es_id="a3", started_by="admin")
        assert none.rule_name is None

        # Over-long names are truncated to the column bound (512).
        long = await inv_svc.create(db, alert_es_id="a4", started_by="admin", rule_name="x" * 600)
        assert long.rule_name is not None and len(long.rule_name) == 512
    await engine.dispose()


async def test_list_recent_notifications_is_column_scoped_and_bounds_finished_since(
    settings_kratos: Settings,
) -> None:
    """The bell's investigation query selects scalar columns only (never the
    report blob) and bounds the completed half in SQL by ``finished_since`` —
    where the endpoint used to take the newest-N page and drop out-of-window
    rows in Python."""
    engine, maker = await _db(settings_kratos)
    now = utcnow()
    async with maker() as db:
        fresh = await inv_svc.create(db, alert_es_id="ev-a", started_by="t", rule_name="ET Fresh")
        await inv_svc.finalize(
            db, fresh.id, status="complete", verdict="false_positive", report=REPORT
        )
        stale = await inv_svc.create(db, alert_es_id="ev-b", started_by="t", rule_name="ET Stale")
        await inv_svc.finalize(db, stale.id, status="complete", verdict="false_positive")
        stale_row = await db.get(Investigation, stale.id)
        assert stale_row is not None
        stale_row.finished_at = now - timedelta(hours=30)
        await db.commit()

        rows = await inv_svc.list_recent_notifications(
            db, status="complete", limit=20, finished_since=now - timedelta(hours=24)
        )
        ids = {r.id for r in rows}
        assert fresh.id in ids
        assert stale.id not in ids  # finished 30h ago → excluded IN SQL

        # The returned rows are the scalar NotifRow — no report attribute exists,
        # so the report column is provably never on this query's select list.
        assert all(isinstance(r, inv_svc.NotifRow) for r in rows)
        assert not hasattr(rows[0], "report")
        assert rows[0].rule_name == "ET Fresh"
    await engine.dispose()


async def test_lifecycle_create_append_finalize(settings_kratos: Settings) -> None:
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        inv = await inv_svc.create(db, alert_es_id="x7KpQ2", started_by="admin")
        assert len(inv.id) == 26  # ULID
        assert inv.status == "running"

        await inv_svc.append_events(
            db,
            inv.id,
            [
                {"kind": "session_start", "sequence": 1, "payload": {"alert_id": "x7KpQ2"}},
                {"kind": "alert_context", "sequence": 2, "payload": {"rule": {"name": "ET TEST"}}},
            ],
        )
        await inv_svc.set_rule_name(db, inv.id, "ET TEST Rule")
        await inv_svc.finalize(
            db,
            inv.id,
            status="complete",
            verdict="false_positive",
            confidence=0.85,
            rationale="Routine gateway monitoring traffic.",
            summary=REPORT["summary"],
            report=REPORT,
        )
        got = await inv_svc.get_with_events(db, inv.id)
        assert got is not None
        stored, events = got
        assert stored.status == "complete"
        assert stored.verdict == "false_positive"
        assert stored.rule_name == "ET TEST Rule"
        assert stored.finished_at is not None
        assert [e.kind for e in events] == ["session_start", "alert_context"]
        assert events[1].payload["rule"]["name"] == "ET TEST"
    await engine.dispose()


async def test_get_with_events_unknown_id(settings_kratos: Settings) -> None:
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        assert await inv_svc.get_with_events(db, "0" * 26) is None
    await engine.dispose()


async def test_latest_for_rules_and_alerts(settings_kratos: Settings) -> None:
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        a = await inv_svc.create(db, alert_es_id="ev-old", started_by="admin")
        await inv_svc.set_rule_name(db, a.id, "ET RULE A")
        await inv_svc.finalize(db, a.id, status="complete", verdict="true_positive")

        b = await inv_svc.create(db, alert_es_id="ev-new", started_by="admin")
        await inv_svc.set_rule_name(db, b.id, "ET RULE A")
        # b stays running — still the most recent for the rule

        c = await inv_svc.create(db, alert_es_id="ev-c", started_by="admin")
        await inv_svc.set_rule_name(db, c.id, "ET RULE C")
        await inv_svc.finalize(db, c.id, status="error")

        by_rule = await inv_svc.latest_for_rules(db, ["ET RULE A", "ET RULE C", "NOPE"])
        assert by_rule["ET RULE A"].id == b.id  # most recent wins, running included
        assert by_rule["ET RULE C"].status == "error"
        assert "NOPE" not in by_rule

        by_alert = await inv_svc.latest_for_alerts(db, ["ev-old", "ev-new", "missing"])
        assert by_alert["ev-old"].id == a.id
        assert by_alert["ev-new"].id == b.id
        assert "missing" not in by_alert
    await engine.dispose()


async def test_a_hunt_subject_run_is_not_its_anchor_alerts_run(
    settings_kratos: Settings,
) -> None:
    """D2. The subject is the hunt. The anchor document is a time anchor.

    A hunt-subject run carries one cited document in ``alert_es_id``, because
    the pipeline anchors its time windows on one timestamp. It is not that
    alert's run. Grouped under the alert, its verdict read as the alert's
    latest verdict: a benign explanation for a hunt hypothesis would have
    cleared an alert nobody investigated.
    """
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        own = await inv_svc.create(db, alert_es_id="ev-anchor", started_by="admin")
        await inv_svc.finalize(db, own.id, status="complete", verdict="true_positive")

        promoted = await inv_svc.create(
            db,
            alert_es_id="ev-anchor",
            started_by="admin",
            kind="lead",
            subject={"type": "hunt", "hunt_id": "01HUNT", "lead_id": 10},
        )
        await inv_svc.finalize(db, promoted.id, status="complete", verdict="false_positive")

        assert inv_svc.is_hunt_subject(promoted) is True
        assert inv_svc.is_hunt_subject(own) is False
        assert inv_svc.alert_group_id(promoted) is None
        assert inv_svc.alert_group_id(own) == "ev-anchor"

        # The alert keeps its own run, newer though the promotion is.
        by_alert = await inv_svc.latest_for_alerts(db, ["ev-anchor"])
        assert by_alert["ev-anchor"].id == own.id
        complete = await inv_svc.complete_for_alert(db, "ev-anchor")
        assert complete is not None and complete.id == own.id
        runs = await inv_svc.runs_for_alerts(db, ["ev-anchor"])
        assert [r.id for r in runs] == [own.id]
    await engine.dispose()


async def test_latest_for_rules_empty_input(settings_kratos: Settings) -> None:
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        assert await inv_svc.latest_for_rules(db, []) == {}
        assert await inv_svc.latest_for_alerts(db, []) == {}
    await engine.dispose()


async def test_latest_for_pairs(settings_kratos: Settings) -> None:
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        a = await inv_svc.create(
            db, alert_es_id="e1", started_by="x", src_ip="10.0.0.1", dest_ip="10.0.0.2"
        )
        await inv_svc.set_rule_name(db, a.id, "RULE A")
        await inv_svc.finalize(db, a.id, status="complete", verdict="false_positive")

        hit_key = key("RULE A", "10.0.0.1", "10.0.0.2")
        hits = await inv_svc.latest_for_pairs(
            db,
            [hit_key, key("RULE A", "10.0.0.1", "10.0.0.9")],
            window_days=7,
        )
        assert hits[hit_key].id == a.id
        assert key("RULE A", "10.0.0.1", "10.0.0.9") not in hits
        # outside the window → not inherited
        assert await inv_svc.latest_for_pairs(db, [hit_key], window_days=0) == {}
        # running/error rows do not propagate
        b = await inv_svc.create(
            db, alert_es_id="e2", started_by="x", src_ip="10.0.0.3", dest_ip="10.0.0.4"
        )
        await inv_svc.set_rule_name(db, b.id, "RULE B")
        assert (
            await inv_svc.latest_for_pairs(
                db, [key("RULE B", "10.0.0.3", "10.0.0.4")], window_days=7
            )
            == {}
        )
    await engine.dispose()


async def test_latest_for_pairs_excludes_hunt_kind_rows(settings_kratos: Settings) -> None:
    """A promoted finding's verdict is about its cited evidence, never a license
    to ack a whole detection group. Its rule_name is the finding TITLE, which
    can coincidentally collide with a live rule's name — a hunt-kind row must
    never come back as an inheritance source, or auto-triage's inherited-ack
    path would write unattended acks against real SO alerts it never
    investigated."""
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        hunt_row = await inv_svc.create(
            db,
            alert_es_id="tel-anchor-1",
            started_by="x",
            rule_name="Beaconing to rare external IP",
            src_ip="10.0.0.1",
            dest_ip="10.0.0.2",
            kind="hunt",
            hunt_id="01HUNTCOLLIDE00000000000000",
            finding_ordinal=0,
        )
        await inv_svc.finalize(db, hunt_row.id, status="complete", verdict="false_positive")

        hits = await inv_svc.latest_for_pairs(
            db,
            [key("Beaconing to rare external IP", "10.0.0.1", "10.0.0.2")],
            window_days=7,
        )
        assert key("Beaconing to rare external IP", "10.0.0.1", "10.0.0.2") not in hits

        # Control: an ordinary suricata-kind row with the SAME key still
        # inherits normally — the exclusion is kind-scoped, not a regression.
        plain = await inv_svc.create(
            db,
            alert_es_id="ev-plain-collide",
            started_by="x",
            rule_name="Beaconing to rare external IP",
            src_ip="10.0.0.5",
            dest_ip="10.0.0.6",
        )
        await inv_svc.finalize(db, plain.id, status="complete", verdict="true_positive")
        hits2 = await inv_svc.latest_for_pairs(
            db,
            [key("Beaconing to rare external IP", "10.0.0.5", "10.0.0.6")],
            window_days=7,
        )
        assert hits2[key("Beaconing to rare external IP", "10.0.0.5", "10.0.0.6")].id == plain.id
    await engine.dispose()


# ---- the key a verdict travels along ------------------------------------


def test_pair_key_puts_the_host_in_only_when_there_is_no_flow() -> None:
    """A flow's key must not carry a host, and a flowless detection's must.

    On a multi-sensor grid one flow is seen twice under two ``host.name``
    values, so a host in a flow's key splits one investigation into two of the
    same thing. A detection with no flow has the opposite problem: without the
    host it has no subject at all, and every machine on the estate shares one
    key.
    """
    assert key("R", "10.0.0.1", "10.0.0.2", "sensor-a") == ("R", "10.0.0.1", "10.0.0.2", "")
    assert key("R", "10.0.0.1", "10.0.0.2", "sensor-b") == key(
        "R", "10.0.0.1", "10.0.0.2", "sensor-a"
    )
    # One endpoint is still a flow.
    assert key("R", None, "10.0.0.2", "host-a") == ("R", "", "10.0.0.2", "")
    # No endpoints: the host is the subject.
    assert key("R", None, None, "host-a") == ("R", "", "", "host-a")
    assert key("R", None, None, "host-b") != key("R", None, None, "host-a")
    # Nothing at all.
    assert key("R", None, None, None) == ("R", "", "", "")
    assert not inv_svc.names_a_subject(key("R", None, None, None))
    assert inv_svc.names_a_subject(key("R", None, None, "host-a"))
    assert inv_svc.names_a_subject(key("R", "10.0.0.1", None, None))


async def test_latest_for_pairs_finds_a_no_ip_investigation_by_its_host(
    settings_kratos: Settings,
) -> None:
    """A NULL-endpoint investigation is reachable under its HOST's key.

    Endpoint/process-shaped detections (Sigma host rules, Zeek notices) carry no
    ``source.ip``/``destination.ip``, so the recorder leaves both columns NULL.
    They still have to inherit their own prior verdict or the sweep
    re-investigates them every time a newer event id turns up.
    """
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        a = await inv_svc.create(db, alert_es_id="ev-host", started_by="x", rule_name="SIGMA HOST")
        assert a.src_ip is None and a.dest_ip is None
        await inv_svc.set_alert_fields(db, a.id, host_name="ws-01")
        await inv_svc.finalize(db, a.id, status="complete", verdict="false_positive")

        hits = await inv_svc.latest_for_pairs(
            db, [key("SIGMA HOST", None, None, "ws-01")], window_days=7
        )
        assert hits[key("SIGMA HOST", None, None, "ws-01")].id == a.id

        # A half-endpoint row is keyed on the endpoint it DOES have, so it can
        # only be inherited by a cluster of the same shape.
        b = await inv_svc.create(
            db, alert_es_id="ev-half", started_by="x", rule_name="HALF RULE", dest_ip="1.2.3.4"
        )
        await inv_svc.finalize(db, b.id, status="complete", verdict="true_positive")
        half = await inv_svc.latest_for_pairs(
            db,
            [key("HALF RULE", None, "1.2.3.4"), key("HALF RULE", None, None, "ws-01")],
            window_days=7,
        )
        assert half[key("HALF RULE", None, "1.2.3.4")].id == b.id
        assert key("HALF RULE", None, None, "ws-01") not in half
    await engine.dispose()


async def test_a_no_ip_verdict_does_not_travel_to_another_machine(
    settings_kratos: Settings,
) -> None:
    """THE DEFECT. One benign verdict silenced a Sigma rule everywhere.

    Every address-free detection of a rule keyed as ``(rule, "", "")``, so the
    first verdict reached under it covered every later firing on every machine,
    and those firings were never investigated to contradict it. Measured on a
    live grid: 100 of 208 investigations carried that key, and one rule held a
    false positive and a true positive under it at the same time.
    """
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        benign = await inv_svc.create(
            db, alert_es_id="ev-a", started_by="x", rule_name="SIGMA HOST"
        )
        await inv_svc.set_alert_fields(db, benign.id, host_name="ws-01")
        await inv_svc.finalize(db, benign.id, status="complete", verdict="false_positive")

        hits = await inv_svc.latest_for_pairs(
            db,
            [key("SIGMA HOST", None, None, "ws-01"), key("SIGMA HOST", None, None, "dc-01")],
            window_days=7,
        )
        assert hits[key("SIGMA HOST", None, None, "ws-01")].id == benign.id
        assert key("SIGMA HOST", None, None, "dc-01") not in hits
    await engine.dispose()


async def test_a_key_naming_no_subject_inherits_nothing(settings_kratos: Settings) -> None:
    """``(rule, "", "", "")`` says a detection fired and nothing about where.

    A verdict reached under it was about the rule, not about anything that
    happened, so it is not handed to another alert. This is also what retires
    every legacy row: those runs recorded no host, so they key here, and here
    nothing matches.
    """
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        legacy = await inv_svc.create(
            db, alert_es_id="ev-legacy", started_by="x", rule_name="SIGMA HOST"
        )
        assert legacy.host_name is None
        await inv_svc.finalize(db, legacy.id, status="complete", verdict="false_positive")

        assert (
            await inv_svc.latest_for_pairs(db, [key("SIGMA HOST", None, None, None)], window_days=7)
            == {}
        )
        # Nor does it reach a cluster that DOES know its host.
        assert (
            await inv_svc.latest_for_pairs(
                db, [key("SIGMA HOST", None, None, "ws-01")], window_days=7
            )
            == {}
        )
    await engine.dispose()


async def test_running_for_pairs_still_blocks_a_subjectless_duplicate(
    settings_kratos: Settings,
) -> None:
    """NEGATIVE CONTROL for the refusal above: it must not spread.

    The in-flight guard answers a different question from the verdict lookup.
    A coarse stop is safe where a coarse verdict is not, and refusing the
    subjectless key here would let one sweep launch a run per address-free
    alert of a rule at once.
    """
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        running = await inv_svc.create(
            db, alert_es_id="ev-running", started_by="x", rule_name="SIGMA HOST"
        )
        assert running.status == "running" and running.host_name is None
        assert await inv_svc.running_for_pairs(db, [key("SIGMA HOST", None, None, None)]) == {
            key("SIGMA HOST", None, None, None)
        }
    await engine.dispose()


async def test_latest_for_pairs_ip_keyed_rows_unchanged(settings_kratos: Settings) -> None:
    """Regression guard for the ~99.99% path.

    Admitting NULL-endpoint rows must not disturb a both-endpoints lookup: a
    NULL row's coalesced key always carries an empty component, so it can never
    equal — nor outrank, since the map keeps the newest row per key — the key of
    a flow the caller asked about.
    """
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        flow = await inv_svc.create(
            db,
            alert_es_id="ev-flow",
            started_by="x",
            rule_name="ET FLOW",
            src_ip="10.0.0.1",
            dest_ip="1.2.3.4",
        )
        await inv_svc.finalize(db, flow.id, status="complete", verdict="true_positive")
        # Same rule, no endpoints, NEWER — the row that would hijack the flow's
        # key if coalescing collapsed the two shapes together.
        noip = await inv_svc.create(db, alert_es_id="ev-noip", started_by="x", rule_name="ET FLOW")
        await inv_svc.set_alert_fields(db, noip.id, host_name="ws-01")
        await inv_svc.finalize(db, noip.id, status="complete", verdict="false_positive")

        hits = await inv_svc.latest_for_pairs(
            db,
            [key("ET FLOW", "10.0.0.1", "1.2.3.4"), key("ET FLOW", None, None, "ws-01")],
            window_days=7,
        )
        assert hits[key("ET FLOW", "10.0.0.1", "1.2.3.4")].id == flow.id
        assert hits[key("ET FLOW", None, None, "ws-01")].id == noip.id
    await engine.dispose()


async def test_running_for_pairs_blocks_a_no_ip_duplicate(settings_kratos: Settings) -> None:
    """The in-flight guard has to cover no-IP clusters too.

    Without it a manual (or previous sweep's) investigation of a host-shaped rule
    is invisible to the planner: a newer event id defeats the direct id check and
    the pair check sees nothing, so the same rule is investigated concurrently —
    duplicate work and duplicate model spend at every 5-minute sweep.
    """
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        running = await inv_svc.create(
            db, alert_es_id="ev-host", started_by="x", rule_name="SIGMA HOST"
        )
        assert running.status == "running"
        # A completed run of the same shape must NOT be reported as in-flight.
        done = await inv_svc.create(
            db, alert_es_id="ev-host-old", started_by="x", rule_name="SIGMA DONE"
        )
        await inv_svc.finalize(db, done.id, status="complete", verdict="false_positive")
        # IP-bearing rows keep their own key, unaffected by the no-IP admission.
        flow = await inv_svc.create(
            db,
            alert_es_id="ev-flow",
            started_by="x",
            rule_name="ET FLOW",
            src_ip="10.0.0.1",
            dest_ip="1.2.3.4",
        )
        assert flow.status == "running"

        assert await inv_svc.running_for_pairs(
            db,
            [
                key("SIGMA HOST", None, None),
                key("SIGMA DONE", None, None),
                key("ET FLOW", "10.0.0.1", "1.2.3.4"),
                key("ET FLOW", None, None),
            ],
        ) == {key("SIGMA HOST", None, None), key("ET FLOW", "10.0.0.1", "1.2.3.4")}
    await engine.dispose()


async def test_running_for_pairs_ignores_hunt_kind_title_collision(
    settings_kratos: Settings,
) -> None:
    """An in-flight PROMOTED-FINDING investigation whose title equals a rule
    name must not mark that rule's pair as running — otherwise the sweep would
    skip the rule's real alerts for as long as the promotion runs."""
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        promo = await inv_svc.create(
            db,
            alert_es_id="ev-cited-doc",
            started_by="x",
            rule_name="SIGMA HOST",  # a finding title colliding with a rule name
            kind="hunt",
            hunt_id="01HUNTRFP0000000000000000000",
            finding_ordinal=0,
        )
        assert promo.status == "running"
        # A genuinely running alert investigation of the same shape still counts.
        await inv_svc.create(db, alert_es_id="ev-real", started_by="x", rule_name="ET REAL")

        assert await inv_svc.running_for_pairs(
            db, [key("SIGMA HOST", None, None), key("ET REAL", None, None)]
        ) == {key("ET REAL", None, None)}
    await engine.dispose()


async def test_verdict_counts_since_tallies_the_window_in_sql(
    settings_kratos: Settings,
) -> None:
    """Verdicts landed since a cutoff, counted in SQL over the WHOLE table.

    Aggregated rather than tallied from :func:`list_recent`: a capped scan
    reports a floor as a total the moment a backlog drain completes more
    investigations than the cap, and the dashboard chat states this number to the
    model as fact. Only settled, verdict-bearing rows count — a running or
    errored run has decided nothing.
    """
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        assert await inv_svc.verdict_counts_since(db, utcnow() - timedelta(hours=24)) == {}

        for n in range(2):
            fp = await inv_svc.create(db, alert_es_id=f"ev-fp{n}", started_by="t")
            await inv_svc.finalize(db, fp.id, status="complete", verdict="false_positive")
        tp = await inv_svc.create(db, alert_es_id="ev-tp", started_by="t")
        await inv_svc.finalize(db, tp.id, status="complete", verdict="true_positive")

        # Settled but verdictless, still running, and errored: none is a decision.
        no_verdict = await inv_svc.create(db, alert_es_id="ev-none", started_by="t")
        await inv_svc.finalize(db, no_verdict.id, status="complete")
        await inv_svc.create(db, alert_es_id="ev-running", started_by="t")
        errored = await inv_svc.create(db, alert_es_id="ev-err", started_by="t")
        await inv_svc.finalize(db, errored.id, status="error", verdict="true_positive")

        # Older than the cutoff — last quarter's story is not last night's.
        stale = await inv_svc.create(db, alert_es_id="ev-stale", started_by="t")
        await inv_svc.finalize(db, stale.id, status="complete", verdict="needs_more_info")
        stale_row = await db.get(Investigation, stale.id)
        assert stale_row is not None
        stale_row.created_at = utcnow() - timedelta(days=9)
        await db.commit()

        assert await inv_svc.verdict_counts_since(db, utcnow() - timedelta(hours=24)) == {
            "false_positive": 2,
            "true_positive": 1,
        }
        # Widening the cutoff picks the old row back up.
        assert (await inv_svc.verdict_counts_since(db, utcnow() - timedelta(days=30))).get(
            "needs_more_info"
        ) == 1
    await engine.dispose()


async def test_latest_complete_for_rules_window_bounds_inheritance(
    settings_kratos: Settings,
) -> None:
    """The rule-level fallback honours ``window_days`` for PER-ALERT inheritance:
    a standing verdict older than the window is not inherited (so the alert is
    re-triaged, not stuck on a stale verdict), while the unbounded call (the
    rule-group badge) still returns it. Regression for "inherited a verdict from
    18d ago, past the configured window"."""
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        a = await inv_svc.create(db, alert_es_id="e1", started_by="t", rule_name="RULE A")
        await inv_svc.finalize(
            db, a.id, status="complete", verdict="false_positive", confidence=0.9
        )
        row = await db.get(Investigation, a.id)
        assert row is not None
        row.created_at = utcnow() - timedelta(days=18)
        await db.commit()

        # Unbounded (group-badge use): the 18d-old standing verdict is returned.
        unbounded = await inv_svc.latest_complete_for_rules(db, ["RULE A"])
        assert unbounded["RULE A"].id == a.id
        # Bounded to a 7-day inherit window (per-alert use): the 18d verdict is excluded.
        assert await inv_svc.latest_complete_for_rules(db, ["RULE A"], window_days=7) == {}

        # A fresh verdict for the same rule IS inherited within the window.
        b = await inv_svc.create(db, alert_es_id="e2", started_by="t", rule_name="RULE A")
        await inv_svc.finalize(db, b.id, status="complete", verdict="true_positive", confidence=0.9)
        bounded = await inv_svc.latest_complete_for_rules(db, ["RULE A"], window_days=7)
        assert bounded["RULE A"].id == b.id
    await engine.dispose()


async def _age(db, inv_id: str, minutes: int) -> None:  # type: ignore[no-untyped-def]
    """Backdate a row's created_at so the periodic reaper sees it as stale."""
    row = await db.get(Investigation, inv_id)
    row.created_at = utcnow() - timedelta(minutes=minutes)
    await db.commit()


async def test_reap_all_running_when_age_none(settings_kratos: Settings) -> None:
    """older_than_minutes=None reaps EVERY running row (startup case)."""
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        r1 = await inv_svc.create(db, alert_es_id="r1", started_by="x")
        r2 = await inv_svc.create(db, alert_es_id="r2", started_by="x")
        done = await inv_svc.create(db, alert_es_id="ok", started_by="x")
        await inv_svc.finalize(db, done.id, status="complete", verdict="false_positive")

        n = await inv_svc.reap_stale_running(db, older_than_minutes=None)
        assert n == 2

        for rid in (r1.id, r2.id):
            row = await db.get(Investigation, rid)
            assert row.status == "error"
            assert row.finished_at is not None
            assert row.rationale  # a note was set
        # the completed one is untouched
        assert (await db.get(Investigation, done.id)).status == "complete"
    await engine.dispose()


async def test_reap_only_stale_when_age_set(settings_kratos: Settings) -> None:
    """A positive age reaps only rows older than it; a fresh hunt is spared."""
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        fresh = await inv_svc.create(db, alert_es_id="fresh", started_by="x")
        stale = await inv_svc.create(db, alert_es_id="stale", started_by="x")
        await _age(db, stale.id, minutes=60)

        n = await inv_svc.reap_stale_running(db, older_than_minutes=30)
        assert n == 1
        assert (await db.get(Investigation, stale.id)).status == "error"
        assert (await db.get(Investigation, fresh.id)).status == "running"
    await engine.dispose()


async def test_reap_preserves_existing_rationale(settings_kratos: Settings) -> None:
    """The reaper only fills a rationale when one is absent."""
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        inv = await inv_svc.create(db, alert_es_id="r", started_by="x")
        row = await db.get(Investigation, inv.id)
        row.rationale = "partial progress note"
        await db.commit()

        await inv_svc.reap_stale_running(db, older_than_minutes=None)
        row = await db.get(Investigation, inv.id)
        assert row.status == "error"
        assert row.rationale == "partial progress note"
    await engine.dispose()


async def test_reap_returns_zero_when_nothing_running(settings_kratos: Settings) -> None:
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        done = await inv_svc.create(db, alert_es_id="ok", started_by="x")
        await inv_svc.finalize(db, done.id, status="complete", verdict="true_positive")
        assert await inv_svc.reap_stale_running(db, older_than_minutes=None) == 0
        assert await inv_svc.reap_stale_running(db, older_than_minutes=30) == 0
    await engine.dispose()


async def test_reap_interrupted_status_marks_benign_state(settings_kratos: Settings) -> None:
    """The startup reap writes 'interrupted' (not 'error') so a clean restart never
    surfaces a scary failure in a healthy env — and the row stays re-huntable."""
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        inv = await inv_svc.create(db, alert_es_id="cut-off", started_by="x")

        n = await inv_svc.reap_stale_running(db, older_than_minutes=None, status="interrupted")
        assert n == 1
        row = await db.get(Investigation, inv.id)
        assert row.status == "interrupted"
        assert row.finished_at is not None
        # interrupted-specific note (distinct from the 'error' timeout note)
        assert "interrupted by a service restart" in row.rationale
        # re-huntable: continuous auto-triage / manual re-hunt must pick it back up
        assert inv_svc.blocks_rehunt(row) is False
    await engine.dispose()


async def test_reap_default_status_is_error(settings_kratos: Settings) -> None:
    """The periodic over-age sweep keeps the 'error' status — a hunt that ran too
    long is a genuine failure, not a benign restart."""
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        stale = await inv_svc.create(db, alert_es_id="ran-too-long", started_by="x")
        await _age(db, stale.id, minutes=60)

        n = await inv_svc.reap_stale_running(db, older_than_minutes=30)
        assert n == 1
        row = await db.get(Investigation, stale.id)
        assert row.status == "error"
        assert "interrupted by a service restart" not in (row.rationale or "")
    await engine.dispose()


async def test_resolve_changes_verdict_and_records_provenance(settings_kratos: Settings) -> None:
    engine = make_engine(settings_kratos)
    await run_migrations(engine)
    maker = make_sessionmaker(engine)
    async with maker() as db:
        inv = await inv_svc.create(db, alert_es_id="ev-r1", started_by="tester")
        await inv_svc.finalize(
            db,
            inv.id,
            status="complete",
            verdict="needs_more_info",
            confidence=0.4,
            rationale="Need PCAP.",
            report={"open_questions": ["q1"]},
        )
    async with maker() as db:
        updated = await inv_svc.resolve(
            db,
            inv.id,
            verdict="true_positive",
            confidence=0.82,
            rationale="PCAP confirmed C2 beacon.",
            recommended_actions=[
                {"tool_name": "escalate_to_case", "tool_args": {}, "rationale": "Active C2."}
            ],
            resolved_by="analyst",
            source_message_id=7,
        )
    assert updated is not None
    assert updated.verdict == "true_positive"
    assert updated.confidence == pytest.approx(0.82)
    res = updated.report["resolution"]
    assert res["original_verdict"] == "needs_more_info"
    assert res["resolved_via"] == "chat"
    assert res["resolved_by"] == "analyst"
    assert res["source_message_id"] == 7
    assert updated.report["open_questions"] == ["q1"]
    assert updated.report["recommended_actions"][0]["tool_name"] == "escalate_to_case"
    await engine.dispose()


@pytest.mark.asyncio
async def test_resolve_manual_sets_resolved_via_and_no_source_message(
    settings_kratos: Settings,
) -> None:
    engine = make_engine(settings_kratos)
    await run_migrations(engine)
    maker = make_sessionmaker(engine)
    async with maker() as db:
        inv = await inv_svc.create(db, alert_es_id="ev-manual1", started_by="tester")
        await inv_svc.finalize(
            db,
            inv.id,
            status="complete",
            verdict="needs_more_info",
            confidence=0.5,
            rationale="Unclear.",
        )
    async with maker() as db:
        updated = await inv_svc.resolve(
            db,
            inv.id,
            verdict="false_positive",
            confidence=1.0,
            rationale="Analyst confirmed benign.",
            recommended_actions=None,
            resolved_by="alice",
            resolved_via="manual",
            source_message_id=None,
        )
    assert updated is not None
    assert updated.verdict == "false_positive"
    res = updated.report["resolution"]
    assert res["resolved_via"] == "manual"
    assert res["resolved_by"] == "alice"
    assert res["original_verdict"] == "needs_more_info"
    assert "source_message_id" not in res
    await engine.dispose()


# ---------------------------------------------------------------------------
# override_counts_by_rule — the analyst-feedback signal (E4.3)
# ---------------------------------------------------------------------------


async def _complete_inv(
    db,  # type: ignore[no-untyped-def]
    *,
    rule_name: str,
    verdict: str,
    alert_es_id: str,
    report: dict | None = None,
) -> Investigation:
    inv = await inv_svc.create(db, alert_es_id=alert_es_id, started_by="t", rule_name=rule_name)
    await inv_svc.finalize(
        db, inv.id, status="complete", verdict=verdict, confidence=0.9, report=report
    )
    return inv


async def test_override_counts_by_rule_counts_analyst_overrides(
    settings_kratos: Settings,
) -> None:
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        # A manual override out of NMI to false_positive → overridden_to_fp + manual.
        m = await _complete_inv(
            db, rule_name="ET NOISE", verdict="needs_more_info", alert_es_id="o1"
        )
        await inv_svc.resolve(
            db,
            m.id,
            verdict="false_positive",
            confidence=1.0,
            rationale="Analyst confirmed benign.",
            recommended_actions=None,
            resolved_by="alice",
            resolved_via="manual",
        )
        # A chat resolution out of NMI to false_positive → overridden_to_fp + chat.
        c = await _complete_inv(
            db, rule_name="ET NOISE", verdict="needs_more_info", alert_es_id="o2"
        )
        await inv_svc.resolve(
            db,
            c.id,
            verdict="false_positive",
            confidence=0.95,
            rationale="Chat proposal applied.",
            recommended_actions=None,
            resolved_by="bob",
            resolved_via="chat",
            source_message_id=3,
        )
        # An override the OTHER direction (to true_positive) → overridden_to_tp.
        t = await _complete_inv(
            db, rule_name="ET NOISE", verdict="needs_more_info", alert_es_id="o3"
        )
        await inv_svc.resolve(
            db,
            t.id,
            verdict="true_positive",
            confidence=1.0,
            rationale="Analyst escalated.",
            recommended_actions=None,
            resolved_by="carol",
            resolved_via="manual",
        )

        counts = await inv_svc.override_counts_by_rule(db, ["ET NOISE"])
    assert counts["ET NOISE"] == {
        "overridden_to_fp": 2,
        "overridden_to_tp": 1,
        "chat_resolved": 1,
        "manual_resolved": 2,
    }
    await engine.dispose()


async def test_override_counts_by_rule_ignores_pipeline_fallback_and_plain(
    settings_kratos: Settings,
) -> None:
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        # A pipeline_fallback stamps report.resolution with `provenance` and NO
        # `resolved_via` — it is NOT an analyst override and must not be counted.
        await _complete_inv(
            db,
            rule_name="ET FB",
            verdict="needs_more_info",
            alert_es_id="f1",
            report={
                "resolution": {
                    "provenance": "pipeline_fallback",
                    "phase": "synth_first",
                    "error_type": "TimeoutError",
                }
            },
        )
        # A plain completed investigation (no resolution at all) is not counted.
        await _complete_inv(db, rule_name="ET FB", verdict="false_positive", alert_es_id="f2")

        counts = await inv_svc.override_counts_by_rule(db, ["ET FB"])
    # ET FB has no analyst overrides → absent from the result entirely.
    assert "ET FB" not in counts
    await engine.dispose()


async def test_override_counts_by_rule_empty(settings_kratos: Settings) -> None:
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        assert await inv_svc.override_counts_by_rule(db, []) == {}
    await engine.dispose()


# ---------------------------------------------------------------------------
# prior_outcomes — deterministic investigation memory (E4.2)
# ---------------------------------------------------------------------------

_MEM_RULE = "ET MALWARE Memory Beacon"
_MEM_SRC = "10.0.0.1"
_MEM_DST = "10.0.0.2"


async def _seed_prior(
    db,  # type: ignore[no-untyped-def]
    *,
    alert_es_id: str,
    rule_name: str = _MEM_RULE,
    verdict: str | None = "false_positive",
    src_ip: str | None = _MEM_SRC,
    dest_ip: str | None = _MEM_DST,
    rationale: str | None = "benign gateway heartbeat",
    report: dict | None = None,
    age_days: int = 0,
    kind: str = "suricata",
) -> Investigation:
    """Seed one COMPLETE candidate row (optionally backdated) for memory tests."""
    inv = await inv_svc.create(
        db,
        alert_es_id=alert_es_id,
        started_by="t",
        rule_name=rule_name,
        src_ip=src_ip,
        dest_ip=dest_ip,
        kind=kind,
    )
    await inv_svc.finalize(
        db,
        inv.id,
        status="complete",
        verdict=verdict,
        confidence=0.9,
        rationale=rationale,
        report=report,
    )
    if age_days:
        row = await db.get(Investigation, inv.id)
        row.created_at = utcnow() - timedelta(days=age_days)
        await db.commit()
    return inv


async def _lookup(
    db,  # type: ignore[no-untyped-def]
    *,
    src_ip: str | None = _MEM_SRC,
    dest_ip: str | None = _MEM_DST,
    exclude_id: str | None = None,
    window_days: int = 30,
    limit: int = 5,
) -> list[dict]:
    return await inv_svc.prior_outcomes(
        db,
        rule_name=_MEM_RULE,
        src_ip=src_ip,
        dest_ip=dest_ip,
        exclude_id=exclude_id,
        window_days=window_days,
        limit=limit,
    )


# ---------------------------------------------------------------------------
# session_verdicts — what one session has already been called
# ---------------------------------------------------------------------------

_SESSION = "1:hV6oYm5cQ8mQPWNQdCJvL5cM7YM="
_OTHER_SESSION = "1:0kZmS0V0mZLZoCk7hjfHVBjLmpQ="


async def _seed_session(
    db,  # type: ignore[no-untyped-def]
    *,
    alert_es_id: str,
    community_id: str | None = _SESSION,
    verdict: str | None = "true_positive",
    rule_name: str = _MEM_RULE,
    rationale: str | None = "smb session carried a service install",
    age_minutes: int = 0,
    kind: str = "suricata",
    is_synth_eval: bool = False,
    report: dict | None = None,
) -> Investigation:
    """One COMPLETE row stamped with a session, optionally backdated."""
    inv = await inv_svc.create(
        db,
        alert_es_id=alert_es_id,
        started_by="t",
        rule_name=rule_name,
        src_ip=_MEM_SRC,
        dest_ip=_MEM_DST,
        kind=kind,
        is_synth_eval=is_synth_eval,
    )
    if community_id:
        await inv_svc.set_alert_fields(db, inv.id, community_id=community_id)
    await inv_svc.finalize(
        db,
        inv.id,
        status="complete",
        verdict=verdict,
        confidence=0.8,
        rationale=rationale,
        report=report,
    )
    if age_minutes:
        row = await db.get(Investigation, inv.id)
        row.created_at = utcnow() - timedelta(minutes=age_minutes)
        await db.commit()
    return inv


async def test_session_verdicts_finds_the_other_alert_on_one_session(
    settings_kratos: Settings,
) -> None:
    """The defect. Two alerts, one TCP session, twenty-eight minutes apart. The
    rule-keyed lookup could not relate them (different rules, and no ports on
    the row at all); the session key can."""
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        tp = await _seed_session(
            db, alert_es_id="s1", rule_name="ET LATERAL Service Install", age_minutes=28
        )

        got = await inv_svc.session_verdicts(db, community_id=_SESSION)

        assert [d["id"] for d in got] == [tp.id]
        assert got[0]["verdict"] == "true_positive"
        assert got[0]["rationale_digest"] == "smb session carried a service install"
    await engine.dispose()


async def test_session_verdicts_never_matches_a_different_session(
    settings_kratos: Settings,
) -> None:
    """Negative control, and the one that matters: two unrelated alerts must not
    be made to agree. A different session, a row with no session at all, and an
    empty question all return nothing rather than reaching for the nearest
    verdict."""
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        await _seed_session(db, alert_es_id="u1", community_id=_OTHER_SESSION)
        await _seed_session(db, alert_es_id="u2", community_id=None)

        assert await inv_svc.session_verdicts(db, community_id=_SESSION) == []
        # No session on the alert being triaged is not a wildcard.
        assert await inv_svc.session_verdicts(db, community_id="") == []
    await engine.dispose()


async def test_session_verdicts_filters_window_status_and_noise(
    settings_kratos: Settings,
) -> None:
    """Only complete, verdict-bearing, non-fallback, non-hunt, non-synth rows
    inside the window bind anything. A synthetic evaluation run is allowed to
    see planted scenarios, so its verdict must never constrain a real one."""
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        keeper = await _seed_session(db, alert_es_id="f1", age_minutes=10)
        await _seed_session(db, alert_es_id="f2", age_minutes=60 * 48)  # outside the window
        await _seed_session(db, alert_es_id="f3", verdict=None)
        await _seed_session(db, alert_es_id="f4", kind="hunt")
        await _seed_session(db, alert_es_id="f5", is_synth_eval=True)
        await _seed_session(
            db,
            alert_es_id="f6",
            report={
                "verdict": "true_positive",
                "resolution": {"provenance": "pipeline_fallback"},
            },
        )
        # Still running: no verdict to hand out.
        running = await inv_svc.create(db, alert_es_id="f7", started_by="t")
        await inv_svc.set_alert_fields(db, running.id, community_id=_SESSION)

        got = await inv_svc.session_verdicts(db, community_id=_SESSION)

        assert [d["id"] for d in got] == [keeper.id]
        assert await inv_svc.session_verdicts(db, community_id=_SESSION, exclude_id=keeper.id) == []
    await engine.dispose()


async def test_session_verdicts_returns_the_newest_first(settings_kratos: Settings) -> None:
    """Newest first, capped at the limit."""
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        old = await _seed_session(db, alert_es_id="n1", age_minutes=90)
        mid = await _seed_session(db, alert_es_id="n2", age_minutes=45)
        new = await _seed_session(db, alert_es_id="n3", age_minutes=1)

        got = await inv_svc.session_verdicts(db, community_id=_SESSION, limit=2)

        assert [d["id"] for d in got] == [new.id, mid.id]
        assert old.id not in {d["id"] for d in got}
    await engine.dispose()


async def test_prior_outcomes_tier_ordering_beats_recency(settings_kratos: Settings) -> None:
    """Exact triple outranks endpoint-share outranks rule-only, whatever the age;
    WITHIN a tier the newest row wins."""
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        # Oldest row is the exact triple; the freshest is rule-only — tier must win.
        exact = await _seed_prior(db, alert_es_id="m1", age_days=5)
        ep_src = await _seed_prior(db, alert_es_id="m2", dest_ip="10.9.9.9", age_days=2)
        ep_dst = await _seed_prior(db, alert_es_id="m3", src_ip="10.5.5.5", age_days=3)
        rule_only = await _seed_prior(
            db, alert_es_id="m4", src_ip="10.7.7.7", dest_ip="10.9.9.9", age_days=0
        )

        got = await _lookup(db)
        # Tier first; within the endpoint tier, m2 (2d) is newer than m3 (3d).
        assert [d["id"] for d in got] == [exact.id, ep_src.id, ep_dst.id, rule_only.id]
        assert [d["matched_on"] for d in got] == [
            "rule+src+dest",
            "rule+endpoint",
            "rule+endpoint",
            "rule",
        ]
        # Digest shape: light fields only, rationale collapsed into the digest.
        assert got[0]["verdict"] == "false_positive"
        assert got[0]["confidence"] == pytest.approx(0.9)
        assert got[0]["rationale_digest"] == "benign gateway heartbeat"
    await engine.dispose()


async def test_prior_outcomes_filters_window_status_verdict_exclude(
    settings_kratos: Settings,
) -> None:
    """Only complete, verdict-bearing rows inside the window count; exclude_id
    drops the caller's own row."""
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        keeper = await _seed_prior(db, alert_es_id="k1", age_days=1)
        # Outside the window.
        await _seed_prior(db, alert_es_id="k2", age_days=40)
        # Still running (never finalized) — must never hand out a verdict.
        await inv_svc.create(
            db,
            alert_es_id="k3",
            started_by="t",
            rule_name=_MEM_RULE,
            src_ip=_MEM_SRC,
            dest_ip=_MEM_DST,
        )
        # Complete but verdictless (e.g. an interrupted finalize) — no verdict, no memory.
        await _seed_prior(db, alert_es_id="k4", verdict=None)

        got = await _lookup(db, window_days=30)
        assert [d["id"] for d in got] == [keeper.id]

        # exclude_id drops the caller's own (completed) row.
        assert await _lookup(db, exclude_id=keeper.id) == []
    await engine.dispose()


async def test_prior_outcomes_drops_pipeline_fallback_keeps_analyst_override(
    settings_kratos: Settings,
) -> None:
    """A pipeline-fallback verdict is failure noise, not memory; an analyst
    override (resolution with resolved_via, no provenance) is the OPPOSITE —
    the strongest conclusion we have — and must be kept."""
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        await _seed_prior(
            db,
            alert_es_id="f1",
            age_days=0,
            report={
                "resolution": {
                    "provenance": "pipeline_fallback",
                    "phase": "synth_first_round1",
                    "error_type": "TimeoutError",
                }
            },
        )
        overridden = await _seed_prior(
            db,
            alert_es_id="f2",
            age_days=1,
            report={"resolution": {"resolved_via": "manual", "resolved_by": "alice"}},
        )
        got = await _lookup(db)
        assert [d["id"] for d in got] == [overridden.id]
    await engine.dispose()


async def test_prior_outcomes_excludes_hunt_kind_title_collision(
    settings_kratos: Settings,
) -> None:
    """A promoted hunt finding whose TITLE equals a live rule's name must never
    surface as that rule's prior-outcome memory: its verdict is about its cited
    evidence, not the rule, and the name match is coincidence."""
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        # Newest, exact-triple, true_positive — would rank first if admitted.
        await _seed_prior(db, alert_es_id="h1", verdict="true_positive", kind="hunt")
        real = await _seed_prior(db, alert_es_id="h2", age_days=1)
        got = await _lookup(db)
        assert [d["id"] for d in got] == [real.id]
    await engine.dispose()


async def test_prior_outcomes_limit_applies_after_fallback_filter(
    settings_kratos: Settings,
) -> None:
    """``limit`` bounds the RETURNED digests (newest first within the tier), and
    a fallback row between real ones doesn't eat a slot (the ``is_fallback``
    column filter runs in SQL, before the LIMIT)."""
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        rows = [
            await _seed_prior(db, alert_es_id=f"l{i}", age_days=i) for i in range(1, 5)
        ]  # ages 1..4 — newest first is l1, l2, l3, l4
        await _seed_prior(
            db,
            alert_es_id="l0",
            age_days=0,  # newest of all, but a fallback → filtered out
            report={"resolution": {"provenance": "pipeline_fallback"}},
        )
        got = await _lookup(db, limit=3)
        assert [d["id"] for d in got] == [rows[0].id, rows[1].id, rows[2].id]
    await engine.dispose()


async def test_prior_outcomes_unknown_endpoints_rank_rule_only(
    settings_kratos: Settings,
) -> None:
    """With no known endpoint on the CURRENT alert, NULL never 'matches' NULL —
    every candidate is a rule-only match (shared absence isn't a shared endpoint)."""
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        await _seed_prior(db, alert_es_id="n1")
        got = await _lookup(db, src_ip=None, dest_ip=None)
        assert [d["matched_on"] for d in got] == ["rule"]
    await engine.dispose()


async def test_prior_outcomes_rationale_digest_truncates_on_word_boundary(
    settings_kratos: Settings,
) -> None:
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        long_rationale = "Solicited echo replies from the gateway monitor. " * 12  # ~588 chars
        await _seed_prior(db, alert_es_id="d1", rationale=long_rationale, age_days=1)
        await _seed_prior(db, alert_es_id="d2", rationale="short\n note", age_days=2)
        await _seed_prior(db, alert_es_id="d3", rationale=None, age_days=3)

        got = await _lookup(db)
        digest = got[0]["rationale_digest"]
        assert digest is not None and digest.endswith("…")
        assert len(digest) <= 281  # 280 + the ellipsis
        # Word boundary: the last token before the ellipsis is a whole word.
        assert digest[:-1].rstrip().split()[-1] in long_rationale.split()
        # Short rationales pass through with whitespace collapsed; None stays None.
        assert got[1]["rationale_digest"] == "short note"
        assert got[2]["rationale_digest"] is None
    await engine.dispose()


async def test_for_entity_excludes_synth_eval_rows(settings_kratos: Settings) -> None:
    """``for_entity`` feeds two surfaces that narrate a host's REAL history —
    the entity timeline and the host page's latest-investigation chip
    (``routes_dossier._investigation_lookup``, limit=1). A synthetic-evaluation
    run describes nothing that happened on the box, so it is excluded here
    rather than badged: at limit=1 a newer planted run would otherwise SHADOW
    the newest real one and become the host's "latest" disposition."""
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        real = await inv_svc.create(
            db,
            alert_es_id="fe-real",
            started_by="analyst",
            rule_name="ET real detection",
            src_ip="10.0.0.7",
        )
        # Created AFTER the real row, so it is the newest match by sort order.
        await inv_svc.create(
            db,
            alert_es_id="fe-synth",
            started_by="eval",
            rule_name="Planted C2 beacon",
            src_ip="10.0.0.7",
            is_synth_eval=True,
        )
        rows = await inv_svc.for_entity(db, "10.0.0.7")
        assert [r.id for r in rows] == [real.id]
        # The dossier chip's exact call shape: newest REAL run, not [] and not
        # the planted one.
        top = await inv_svc.for_entity(db, "10.0.0.7", limit=1)
        assert [r.id for r in top] == [real.id]
    await engine.dispose()


async def test_failed_triage_reaches_the_pipeline_error_filter(settings_kratos: Settings) -> None:
    """A run that ended in ``error`` with no verdict is a pipeline error.

    Production carried 188 of these: no verdict, no rationale, no report, and
    ``is_fallback`` never stamped because nothing ever wrote a report to stamp
    it from. The Dashboard's count and its deep link both run the
    ``pipeline_error`` verdict filter, so a row that filter cannot see is a
    failure no surface in the product mentions.
    """
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        died = await inv_svc.create(db, alert_es_id="ev-died", started_by="t", rule_name="ET Died")
        await inv_svc.finalize(db, died.id, status="error")
        # A healthy run: reached a verdict, so it is NOT a pipeline error.
        ok = await inv_svc.create(db, alert_es_id="ev-ok", started_by="t", rule_name="ET Fine")
        await inv_svc.finalize(db, ok.id, status="complete", verdict="false_positive")
        # An errored run that DID reach a verdict: it has an answer, so it is
        # reachable under its own verdict and does not belong here.
        late = await inv_svc.create(db, alert_es_id="ev-late", started_by="t", rule_name="ET Late")
        await inv_svc.finalize(db, late.id, status="error", verdict="false_positive")

        page = await inv_svc.query_page(db, verdicts=[inv_svc.PIPELINE_ERROR_VERDICT])
        assert [r.id for r in page.rows] == [died.id]
        assert page.total == 1

        # Negative control: the false-positive filter is unchanged by the
        # widening: a no-verdict row must not leak into a real verdict's set.
        fps = await inv_svc.query_page(db, verdicts=["false_positive"])
        assert {r.id for r in fps.rows} == {ok.id, late.id}
    await engine.dispose()


async def test_notifications_query_takes_the_display_status_and_hides_dismissed(
    settings_kratos: Settings,
) -> None:
    """The bell's query grades a row the way the screen renders it, and can be
    asked for only the failures nobody has acknowledged yet.

    ``complete`` with a blank verdict displays as an error everywhere else in
    the product (``_display_status_sql``), so asking this query for completions
    must not hand back a run that reached no decision, and asking it for errors
    must find it.
    """
    engine, maker = await _db(settings_kratos)
    now = utcnow()
    async with maker() as db:
        died = await inv_svc.create(db, alert_es_id="ev-d1", started_by="t", rule_name="ET Died")
        await inv_svc.finalize(db, died.id, status="error")
        blank = await inv_svc.create(db, alert_es_id="ev-d2", started_by="t", rule_name="ET Blank")
        await inv_svc.finalize(db, blank.id, status="complete", verdict="  ")
        acked = await inv_svc.create(db, alert_es_id="ev-d3", started_by="t", rule_name="ET Acked")
        await inv_svc.finalize(db, acked.id, status="error")
        await inv_svc.dismiss_error(db, acked.id)
        good = await inv_svc.create(db, alert_es_id="ev-d4", started_by="t", rule_name="ET Good")
        await inv_svc.finalize(db, good.id, status="complete", verdict="true_positive")

        since = now - timedelta(hours=24)
        failed = await inv_svc.list_recent_notifications(
            db,
            status="error",
            limit=20,
            finished_since=since,
            no_verdict=True,
            exclude_dismissed=True,
        )
        assert {r.id for r in failed} == {died.id, blank.id}

        done = await inv_svc.list_recent_notifications(
            db, status="complete", limit=20, finished_since=since
        )
        assert {r.id for r in done} == {good.id}
    await engine.dispose()


async def test_pipeline_fallback_stays_rehuntable(settings_kratos: Settings) -> None:
    """A fallback is a failure wearing a 'complete' status, so it must not block.

    This is the "pipeline errors that never heal" report. The investigations list
    counts a fallback as needing a retry; this predicate used to count it as
    finished, so the sweep skipped its alert as already_triaged. Nine alerts on
    the home deployment sat in that gap: permanently listed as needing attention,
    permanently ineligible for the only thing that would clear them.

    Both halves of the pair are asserted here. A future change that makes one of
    them treat a fallback as settled has to fail this test to do it.
    """
    from soc_ai.api.webui.routes_investigations import _needs_retry, _row
    from soc_ai.triage_models import PIPELINE_FALLBACK_PROVENANCE

    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        inv = await inv_svc.create(db, alert_es_id="fell-back", started_by="x")
        row = await db.get(Investigation, inv.id)
        row.status = "complete"
        row.verdict = "needs_more_info"
        row.is_fallback = True
        row.report = {"resolution": {"provenance": PIPELINE_FALLBACK_PROVENANCE}}
        await db.commit()
        row = await db.get(Investigation, inv.id)

        # The sweep must be willing to run the alert again …
        assert inv_svc.blocks_rehunt(row) is False
        # … and the list must still be asking someone to. Both, or the alert is
        # stuck in the gap between them.
        assert _needs_retry(_row(row, is_primary=True)) is True

        # The marker alone is enough, without the column — rows finalized before
        # is_fallback existed carry it only in the report.
        row.is_fallback = None
        await db.commit()
        assert inv_svc.blocks_rehunt(await db.get(Investigation, inv.id)) is False

        # A genuine needs_more_info the pipeline actually reasoned to is settled,
        # and must keep blocking: re-running it would loop on every sweep.
        row.is_fallback = None
        row.report = {"resolution": {"provenance": "analyst"}}
        await db.commit()
        settled = await db.get(Investigation, inv.id)
        assert inv_svc.blocks_rehunt(settled) is True
        assert _needs_retry(_row(settled, is_primary=True)) is False
    await engine.dispose()


async def test_the_subject_column_holds_a_hunt_subject(settings_kratos: Settings) -> None:
    """Migration 0050. An alert run leaves the subject NULL. A hunt run stores
    the hunt, the objective, the finding ordinals, the lead, the documents and
    the observations, so the row says what it was about."""
    engine, maker = await _db(settings_kratos)
    subject = {
        "type": "hunt",
        "hunt_id": "01HUNT0000000000000000000",
        "objective": "hunt for kerberoasting on the domain controllers",
        "finding_ordinals": [0, 2],
        "lead_id": 7,
        "document_ids": ["tel-1", "tel-2"],
        "observation_ids": [11, 12],
    }
    async with maker() as db:
        alert_run = await inv_svc.create(db, alert_es_id="a1", started_by="admin")
        assert alert_run.subject_json is None

        hunt_run = await inv_svc.create(
            db, alert_es_id="tel-1", started_by="admin", kind="hunt", subject=subject
        )
        assert hunt_run.subject_json == subject
        hunt_run_id = hunt_run.id

    async with maker() as db:
        read_back = await db.get(Investigation, hunt_run_id)
        assert read_back is not None
        assert read_back.subject_json == subject
    await engine.dispose()

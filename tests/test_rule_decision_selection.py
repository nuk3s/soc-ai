"""The one selection of the open false positives of a rule (round 3, RS1).

soc-ai gives a false positive verdict, and a guard of the automatic
acknowledge holds the write. The selection names each such investigation with
its rule, its group and its hold reason, and every surface reads it.

The plants sit on the paths that a careless selection would miss: an
acknowledge that an event carried out, a dismissal, a newer run of the same
alert, an analyst verdict on another run of the alert, and the runs that are
no live verdict on a Security Onion alert. The data is synthetic.
"""

from __future__ import annotations

import json
from typing import Any

import pytest
from soc_ai.config import Settings
from soc_ai.store import investigations as inv_svc
from soc_ai.store.db import make_engine, make_sessionmaker, run_migrations
from soc_ai.webui import rule_decisions as rd

RULE = "ET POLICY actor-a outbound check"
OTHER_RULE = "ET INFO web-1 update request"
# The setting auto_ack_fp_threshold of the selection: its default.
THRESHOLD = 0.7


async def maker_for(settings: Settings) -> Any:
    engine = make_engine(settings)
    await run_migrations(engine)
    return make_sessionmaker(engine)


def ack_action(alert_id: str) -> dict[str, Any]:
    return {
        "tool_name": "ack_alert",
        "tool_args": {"alert_id": alert_id},
        "rationale": "The flow is a known update check.",
    }


async def seed_fp(
    maker: Any,
    alert_id: str,
    *,
    rule: str = RULE,
    reason: str | None = "high_stakes",
    confidence: float = 0.9,
    verdict: str = "false_positive",
    actions: list[dict[str, Any]] | None = None,
    events: list[tuple[str, dict[str, Any]]] = (),  # type: ignore[assignment]
    src_ip: str | None = "192.0.2.10",
    dest_ip: str | None = "203.0.113.5",
    kind: str = "suricata",
    started_by: str = "auto-triage",
    synth: bool = False,
    report_extra: dict[str, Any] | None = None,
) -> str:
    """One complete run with a recommended acknowledge and its hold event."""
    async with maker() as db:
        inv = await inv_svc.create(
            db,
            alert_es_id=alert_id,
            started_by=started_by,
            rule_name=rule,
            src_ip=src_ip,
            dest_ip=dest_ip,
            kind=kind,
            is_synth_eval=synth,
        )
        report: dict[str, Any] = {
            "verdict": verdict,
            "confidence": confidence,
            "recommended_actions": [ack_action(alert_id)] if actions is None else actions,
            **(report_extra or {}),
        }
        await inv_svc.finalize(
            db,
            inv.id,
            status="complete",
            verdict=verdict,
            confidence=confidence,
            rationale="The flow is a known update check.",
            summary="soc-ai reads the flow as a known update check.",
            report=report,
        )
        stored: list[dict[str, Any]] = []
        sequence = 10
        if reason is not None:
            stored.append(
                {
                    "sequence": sequence,
                    "kind": "auto_ack_skipped",
                    "payload": {"es_id": alert_id, "reason": reason, "confidence": confidence},
                }
            )
        for kind_, payload in events:
            sequence += 1
            stored.append({"sequence": sequence, "kind": kind_, "payload": payload})
        if stored:
            await inv_svc.append_events(db, inv.id, stored)
        return str(inv.id)


async def select_all(maker: Any, **kw: Any) -> list[rd.OpenFalsePositive]:
    async with maker() as db:
        return await rd.open_false_positives(db, **{"threshold": THRESHOLD, **kw})


@pytest.mark.asyncio
async def test_each_hold_reason_lands_in_its_group(settings_kratos: Settings) -> None:
    maker = await maker_for(settings_kratos)
    held = await seed_fp(maker, "ev-held", reason="high_stakes")
    failed = await seed_fp(
        maker, "ev-failed", reason=None, events=[("auto_ack", {"success": False})]
    )
    off = await seed_fp(maker, "ev-off", reason=None)
    low = await seed_fp(maker, "ev-low", reason="below_threshold", confidence=0.5)
    blind = await seed_fp(maker, "ev-blind", reason="no_investigation")

    rows = {row.id: row for row in await select_all(maker)}

    assert {rid: (rows[rid].group, rows[rid].reason) for rid in rows} == {
        held: ("confident", "high_stakes"),
        failed: ("confident", "auto_ack_failed"),
        off: ("confident", "auto_ack_off"),
        low: ("weak", "below_threshold"),
        blind: ("weak", "no_investigation"),
    }
    assert rows[held].rule_name == RULE
    assert rows[held].action_index == 0


async def _set_counts(
    maker: Any, run_id: str, tool_calls: int | None, searches: int | None
) -> None:
    from soc_ai.store.models import Investigation

    async with maker() as db:
        inv = await db.get(Investigation, run_id)
        assert inv is not None
        inv.tool_calls, inv.es_searches = tool_calls, searches
        await db.commit()


@pytest.mark.asyncio
async def test_a_run_with_no_hold_event_meets_the_evidence_guards_of_now(
    settings_kratos: Settings,
) -> None:
    """F2: no guard looked at a run while the automatic acknowledge was off.

    A sample at 0.60 read as confident. Such a run now meets the threshold of
    now and the stored counts of its reads.
    """
    maker = await maker_for(settings_kratos)
    low = await seed_fp(maker, "ev-low", reason=None, confidence=0.6)
    blind = await seed_fp(maker, "ev-blind", reason=None, confidence=0.9)
    await _set_counts(maker, blind, 0, 0)
    read = await seed_fp(maker, "ev-read", reason=None, confidence=0.9)
    await _set_counts(maker, read, 0, 3)
    called = await seed_fp(maker, "ev-called", reason=None, confidence=0.9)
    await _set_counts(maker, called, 2, None)
    # NEGATIVE CONTROL: an older run with no stored count proves no empty read.
    old = await seed_fp(maker, "ev-old", reason=None, confidence=0.9)
    # NEGATIVE CONTROL: a hold event decides, whatever the confidence.
    held = await seed_fp(maker, "ev-held", reason="high_stakes", confidence=0.6)
    # NEGATIVE CONTROL: a failed write passed the guards on its way.
    failed = await seed_fp(
        maker, "ev-failed", reason=None, confidence=0.6, events=[("auto_ack", {"success": False})]
    )

    rows = {row.id: (row.group, row.reason) for row in await select_all(maker)}

    assert rows == {
        low: ("weak", "below_threshold"),
        blind: ("weak", "no_investigation"),
        read: ("confident", "auto_ack_off"),
        called: ("confident", "auto_ack_off"),
        old: ("confident", "auto_ack_off"),
        held: ("confident", "high_stakes"),
        failed: ("confident", "auto_ack_failed"),
    }
    # The threshold of now decides: a lower setting moves the run back.
    lower = {row.id: row.group for row in await select_all(maker, threshold=0.5)}
    assert lower[low] == "confident" and lower[blind] == "weak"


@pytest.mark.asyncio
async def test_a_carried_out_or_closed_acknowledge_is_not_open(settings_kratos: Settings) -> None:
    """NEGATIVE CONTROLS: each record that ends the wait leaves the run out."""
    maker = await maker_for(settings_kratos)
    keep = await seed_fp(maker, "ev-keep")
    await seed_fp(maker, "ev-auto", reason=None, events=[("auto_ack", {"success": True})])
    await seed_fp(
        maker,
        "ev-exec",
        events=[("action_executed", {"tool_name": "ack_alert", "success": True, "index": 0})],
    )
    key = json.dumps(ack_action("ev-dis"), sort_keys=True)
    await seed_fp(maker, "ev-dis", events=[("action_dismissed", {"action_key": key, "by": "a"})])
    restored_key = key.replace("ev-dis", "ev-back")
    back = await seed_fp(
        maker,
        "ev-back",
        events=[
            ("action_dismissed", {"action_key": restored_key, "by": "a"}),
            ("action_restored", {"action_key": restored_key, "by": "a"}),
        ],
    )
    await seed_fp(maker, "ev-approval", events=[("approval_request", {"tool_name": "ack_alert"})])
    # A failed manual acknowledge leaves the run open.
    tried = await seed_fp(
        maker,
        "ev-tried",
        events=[("action_executed", {"tool_name": "ack_alert", "success": False})],
    )

    ids = {row.id for row in await select_all(maker)}

    assert ids == {keep, back, tried}


@pytest.mark.asyncio
async def test_only_a_live_false_positive_on_a_security_onion_alert_is_open(
    settings_kratos: Settings,
) -> None:
    """NEGATIVE CONTROLS: a run that is no live verdict on an alert is in no group."""
    maker = await maker_for(settings_kratos)
    keep = await seed_fp(maker, "ev-keep")
    await seed_fp(maker, "ev-tp", verdict="true_positive")
    await seed_fp(maker, "ev-nmi", verdict="needs_more_info")
    await seed_fp(maker, "ev-hunt", kind="hunt")
    await seed_fp(maker, "ev-lead", kind="lead")
    await seed_fp(maker, "ev-replay", started_by=inv_svc.BACKTEST_ACTOR)
    await seed_fp(maker, "ev-synth", synth=True)
    await seed_fp(maker, "ev-none", actions=[])
    await seed_fp(maker, "ev-promoted", reason="promoted_finding")
    await seed_fp(
        maker,
        "ev-fallback",
        report_extra={"resolution": {"provenance": "pipeline_fallback"}},
    )
    # A newer run of the same alert replaces the older false positive.
    await seed_fp(maker, "ev-twice")
    newer = await seed_fp(maker, "ev-twice", verdict="needs_more_info")

    ids = {row.id for row in await select_all(maker)}

    assert ids == {keep}
    assert newer not in ids


@pytest.mark.asyncio
async def test_an_analyst_verdict_on_any_run_of_the_alert_takes_it_out(
    settings_kratos: Settings,
) -> None:
    """The analyst decided on the alert. The plant: the verdict is on an EARLIER
    run, and the newest run of the alert is a model false positive."""
    maker = await maker_for(settings_kratos)
    first = await seed_fp(maker, "ev-decided", reason=None)
    async with maker() as db:
        await inv_svc.resolve(
            db,
            first,
            verdict="true_positive",
            confidence=1.0,
            rationale="Verdict set by analyst1.",
            recommended_actions=[],
            resolved_by="analyst1",
            resolved_via="manual",
        )
    await seed_fp(maker, "ev-decided")
    other = await seed_fp(maker, "ev-other")

    ids = {row.id for row in await select_all(maker)}

    assert ids == {other}


@pytest.mark.asyncio
async def test_the_selection_groups_by_rule_and_reads_one_rule(settings_kratos: Settings) -> None:
    maker = await maker_for(settings_kratos)
    a1 = await seed_fp(maker, "ev-a1", confidence=0.8)
    a2 = await seed_fp(maker, "ev-a2", confidence=0.9)
    a3 = await seed_fp(maker, "ev-a3", reason="uncited", confidence=0.4)
    b1 = await seed_fp(maker, "ev-b1", rule=OTHER_RULE)

    grouped = rd.by_rule(await select_all(maker))
    assert {name: {r.id for r in rows} for name, rows in grouped.items()} == {
        RULE: {a1, a2, a3},
        OTHER_RULE: {b1},
    }
    # The median of the group confident; the weak run does not move it.
    assert rd.median_confidence(grouped[RULE]) == pytest.approx(0.85)
    one = await select_all(maker, rule_names=[OTHER_RULE])
    assert [r.id for r in one] == [b1]


def test_the_rule_key_is_base64url_with_no_padding() -> None:
    for name in (RULE, "GPL ICMP_INFO PING *NIX", "Regel für web-1", "a"):
        key = rd.rule_key(name)
        assert "=" not in key and "+" not in key and "/" not in key
        assert rd.rule_from_key(key) == name
    assert rd.rule_key("ab?") == "YWI_"
    for bad in ("", "!!", "YWI_=", "YWI/", " ", "x" * 2000):
        assert rd.rule_from_key(bad) is None


def test_each_hold_reason_has_one_label() -> None:
    assert rd.hold_label("high_stakes") == rd.HOLD_LABELS["high_stakes"]
    assert rd.hold_label("a_new_reason") == "soc-ai holds the acknowledge."
    for label in rd.HOLD_LABELS.values():
        assert label.endswith(".")
        assert "\u2014" not in label and "\u2013" not in label
    assert rd.group_of("high_stakes") == rd.CONFIDENT
    assert rd.group_of("below_threshold") == rd.WEAK
    assert rd.group_of("analyst_verdict_unknown") == rd.WEAK

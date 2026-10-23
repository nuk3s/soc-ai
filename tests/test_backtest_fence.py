"""A backtest replay is a measurement. It must not act like a live run.

The 2026-10-06 dogfood found 12 of 14 true positives of one week on the range
to be backtest replays, each offering "Escalate to case", and a lead that
formed 74 s after the replay of the same rule. The Backtest page says soc-ai
reads Security Onion and writes nothing back. These tests hold that sentence
true: a replay writes no observation, forms no lead, sends no notification,
writes nothing to Security Onion and offers no action to execute.

Each refusal has its negative control: the same report from a live run does
the thing the replay must not do. A fence that also stopped live runs would
pass every assertion about replays.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import AsyncIterator, Iterator
from datetime import timedelta
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr
from soc_ai.agent.orchestrator import StepEvent
from soc_ai.config import Settings
from soc_ai.main import create_app
from soc_ai.store.auth import utcnow
from soc_ai.store.models import EntityObservation, Investigation, Lead
from sqlalchemy import func, select

ADMIN_PW = "test-bt-fence-pw"

# A true positive is finding-grade: on a live run it writes an observation on
# the internal host and forms a lead alone. 10.0.0.0/8 is private, so the
# observation writer keeps the host.
TP_REPORT: dict[str, Any] = {
    "verdict": "true_positive",
    "confidence": 0.9,
    "summary": "Beacon to a known C2.",
    "citations": ["a1"],
    "recommended_actions": [
        {
            "tool_name": "escalate_to_case",
            "tool_args": {"alert_id": "a1"},
            "rationale": "Confirmed beacon.",
        }
    ],
}

SAMPLING_ES_RESPONSE: dict[str, Any] = {
    "took": 2,
    "hits": {
        "total": {"value": 1, "relation": "eq"},
        "hits": [
            {
                "_id": "bt-alert-1",
                "_source": {
                    "@timestamp": "2026-06-30T06:43:00.000Z",
                    "rule": {"name": "ET MALWARE beacon"},
                    "event": {"severity_label": "critical", "escalated": True},
                    "source": {"ip": "10.20.30.40"},
                    "destination": {"ip": "10.20.30.41"},
                },
            },
        ],
    },
}


async def _fake_investigate_tp(
    alert_id: str,
    *,
    ctx: Any,
    focus_hint: str | None = None,
    deep: bool = False,
    allow_so_writes: bool = True,
    focus_origin: str = "rerun",
    subject: Any = None,
) -> AsyncIterator[StepEvent]:
    sid = "fake-fence-sid"
    yield StepEvent(
        kind="session_start", session_id=sid, sequence=1, payload={"alert_id": alert_id}
    )
    yield StepEvent(
        kind="enriched_alert_context",
        session_id=sid,
        sequence=2,
        payload={
            "alert": {
                "rule_name": "ET MALWARE beacon",
                "id": alert_id,
                "timestamp": "2026-06-30T06:43:00Z",
                "source_ip": "10.20.30.40",
                "destination_ip": "10.20.30.41",
            },
        },
    )
    yield StepEvent(kind="triage_report", session_id=sid, sequence=3, payload=TP_REPORT)
    yield StepEvent(kind="done", session_id=sid, sequence=4, payload={"recommended_count": 1})


@pytest.fixture
def fence_settings(settings_kratos: Settings) -> Settings:
    return settings_kratos.model_copy(
        update={
            "bootstrap_admin_password": SecretStr(ADMIN_PW),
            "webui_extra_detections": False,
            "api_auth_required": False,
        }
    )


@pytest.fixture
def fence_client(fence_settings: Settings) -> Iterator[TestClient]:
    fake_es = AsyncMock()

    async def _search(*args: Any, **kwargs: Any) -> dict[str, Any]:
        return SAMPLING_ES_RESPONSE

    fake_es.search.side_effect = _search
    with (
        patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=fake_es),
        patch("soc_ai.main.make_auth", return_value=AsyncMock()),
        patch("soc_ai.main.get_settings", return_value=fence_settings),
        patch("soc_ai.api.runner.investigate", _fake_investigate_tp),
    ):
        app = create_app()
        with TestClient(app) as client:
            yield client


def _poll_backtest(client: TestClient, *, deadline_s: float = 30.0) -> dict[str, Any]:
    deadline = time.time() + deadline_s
    data: dict[str, Any] = {}
    while time.time() < deadline:
        data = client.get("/api/v1/backtest").json()
        if not data["active"] and data.get("status") in ("complete", "error"):
            return data
        time.sleep(0.1)
    # Fail at the deadline. A stuck run must not fall through to asserts
    # that a run in flight also passes.
    raise AssertionError(f"the backtest did not finish before the deadline: {data}")


def _count(client: TestClient, model: Any) -> int:
    async def _go() -> int:
        async with client.app.state.db_sessionmaker() as db:
            return int(await db.scalar(select(func.count()).select_from(model)) or 0)

    return asyncio.run(_go())


class TestABacktestReplayWritesNothing:
    def test_a_backtest_replay_writes_no_observation_and_forms_no_lead(
        self, fence_client: TestClient
    ) -> None:
        """The proof the dogfood asked for. The replay lands a true positive on
        an internal host. A live run with this report writes one observation
        and forms one lead (the control below). The replay must write none."""
        resp = fence_client.post("/api/v1/backtest", json={"window_days": 30, "sample_size": 5})
        assert resp.status_code == 200
        data = _poll_backtest(fence_client)
        assert data["status"] == "complete"
        # The replay ran and reached its verdict: the measurement still works.
        assert data["results"]["rows"][0]["soc_ai_verdict"] == "true_positive"
        assert _count(fence_client, EntityObservation) == 0
        assert _count(fence_client, Lead) == 0


# ---------------------------------------------------------------------------
# The observation writer: a replay's verdict is no observation
# ---------------------------------------------------------------------------


async def _store(settings: Settings) -> Any:
    from soc_ai.store.db import make_engine, make_sessionmaker, run_migrations

    engine = make_engine(settings)
    await run_migrations(engine)
    return make_sessionmaker(engine)


async def _observations_and_leads(db: Any) -> tuple[int, int]:
    obs = int(await db.scalar(select(func.count()).select_from(EntityObservation)) or 0)
    leads = int(await db.scalar(select(func.count()).select_from(Lead)) or 0)
    return obs, leads


async def _finalized_run(db: Any, *, started_by: str, alert_id: str) -> str:
    from soc_ai.store import investigations as inv_svc

    inv = await inv_svc.create(
        db,
        alert_es_id=alert_id,
        started_by=started_by,
        rule_name="ET MALWARE beacon",
        src_ip="10.20.30.40",
        dest_ip="203.0.113.9",
    )
    await inv_svc.finalize(
        db, inv.id, status="complete", verdict="true_positive", confidence=0.9, rationale="x"
    )
    return inv.id


class TestTheObservationWriter:
    async def test_a_replay_verdict_writes_no_observation(self, settings_kratos: Settings) -> None:
        maker = await _store(settings_kratos)
        async with maker() as db:
            await _finalized_run(db, started_by="backtest", alert_id="es-replay")
            assert await _observations_and_leads(db) == (0, 0)

    async def test_control_a_live_verdict_writes_an_observation_and_forms_a_lead(
        self, settings_kratos: Settings
    ) -> None:
        """The same verdict from a live run is evidence. A fence that stopped
        every run would pass the test above."""
        maker = await _store(settings_kratos)
        async with maker() as db:
            await _finalized_run(db, started_by="analyst", alert_id="es-live")
            assert await _observations_and_leads(db) == (1, 1)

    async def test_an_override_of_a_replay_writes_no_observation(
        self, settings_kratos: Settings
    ) -> None:
        """The analyst override goes through ``resolve``, the second writer."""
        from soc_ai.store import investigations as inv_svc

        maker = await _store(settings_kratos)
        async with maker() as db:
            inv = await inv_svc.create(
                db, alert_es_id="es-r2", started_by="backtest", src_ip="10.20.30.40"
            )
            await inv_svc.finalize(
                db, inv.id, status="complete", verdict="needs_more_info", confidence=0.5
            )
            await inv_svc.resolve(
                db,
                inv.id,
                verdict="true_positive",
                confidence=0.95,
                rationale="analyst says so",
                recommended_actions=None,
                resolved_by="analyst",
            )
            assert await _observations_and_leads(db) == (0, 0)


# ---------------------------------------------------------------------------
# The runner: a replay sends no notification
# ---------------------------------------------------------------------------


class _State:
    def __init__(self, settings: Settings, maker: Any) -> None:
        self.settings = settings
        self.db_sessionmaker = maker
        self.audit = None


async def _drain(state: _State, started_by: str) -> None:
    from soc_ai.api.runner import recorded_run

    async for _name, _data in recorded_run(
        state,
        alert_id="es-notify",
        started_by=started_by,
        event_stream=_fake_investigate_tp("es-notify", ctx=None),
    ):
        pass


class TestTheNotification:
    async def test_a_replay_sends_no_notification(self, settings_kratos: Settings) -> None:
        maker = await _store(settings_kratos)
        fire = AsyncMock()
        with (
            patch("soc_ai.notify.event_for_investigation", return_value=object()),
            patch("soc_ai.notify.fire_safe", fire),
        ):
            await _drain(_State(settings_kratos, maker), "backtest")
        fire.assert_not_awaited()

    async def test_control_a_live_true_positive_sends_one(self, settings_kratos: Settings) -> None:
        maker = await _store(settings_kratos)
        fire = AsyncMock()
        with (
            patch("soc_ai.notify.event_for_investigation", return_value=object()),
            patch("soc_ai.notify.fire_safe", fire),
        ):
            await _drain(_State(settings_kratos, maker), "analyst")
        fire.assert_awaited_once()


# ---------------------------------------------------------------------------
# The worker: a replay writes nothing to Security Onion
# ---------------------------------------------------------------------------


def _ctx(settings: Settings) -> Any:
    from soc_ai.agent.context import InvestigationContext

    return InvestigationContext(settings=settings, auth=AsyncMock(), elastic=AsyncMock())


class TestTheReplayWritesNothingToSecurityOnion:
    def test_the_replay_context_turns_auto_acknowledge_off(self, settings_kratos: Settings) -> None:
        from soc_ai.webui.backtest import replay_context

        live = settings_kratos.model_copy(update={"auto_ack_fp_enabled": True})
        ctx = _ctx(live)
        replay = replay_context(ctx)
        assert replay.settings.auto_ack_fp_enabled is False
        # Control: the live settings keep the operator's choice. A sweep that
        # runs beside the backtest still acknowledges.
        assert live.auto_ack_fp_enabled is True
        assert ctx.settings.auto_ack_fp_enabled is True

    def test_the_worker_replays_as_backtest_with_auto_acknowledge_off(
        self, settings_kratos: Settings
    ) -> None:
        from soc_ai.store import backtests as bt_svc
        from soc_ai.webui import backtest as bt

        live = settings_kratos.model_copy(update={"auto_ack_fp_enabled": True})
        seen: list[dict[str, Any]] = []

        def _run_recorded(*args: Any, **kwargs: Any) -> AsyncIterator[Any]:
            seen.append(kwargs)

            async def _gen() -> AsyncIterator[Any]:
                return
                yield  # pragma: no cover - makes this an async generator

            return _gen()

        async def _go() -> None:
            maker = await _store(live)
            async with maker() as db:
                row = await bt_svc.create(db, params={}, started_by="admin")
            sample = bt.BacktestSample(
                alert_es_id="es-1", rule_name="r", human_disposition=bt.HUMAN_FP
            )
            with (
                patch.object(bt, "run_recorded", _run_recorded),
                patch.object(bt, "ctx_from_state", lambda _s: _ctx(live)),
            ):
                await bt.run_backtest(
                    _State(live, maker), backtest_id=row.id, samples=[sample], params={}
                )

        asyncio.run(_go())
        assert len(seen) == 1
        assert seen[0]["started_by"] == "backtest"
        assert seen[0]["ctx"].settings.auto_ack_fp_enabled is False


# ---------------------------------------------------------------------------
# The list and the live verdict readers
# ---------------------------------------------------------------------------


def _inv(
    seq: int,
    *,
    alert: str,
    started_by: str,
    verdict: str | None = "true_positive",
    status: str = "complete",
    minutes_ago: int = 0,
    rule: str = "ET MALWARE beacon",
) -> Investigation:
    return Investigation(
        id=f"{seq:026d}",
        alert_es_id=alert,
        rule_name=rule,
        verdict=verdict,
        confidence=0.9,
        status=status,
        src_ip="10.20.30.40",
        dest_ip="10.20.30.41",
        started_by=started_by,
        created_at=utcnow() - timedelta(minutes=minutes_ago),
        report={
            "verdict": verdict,
            "recommended_actions": [
                {"tool_name": "ack_alert", "tool_args": {}, "rationale": "Close it."}
            ],
        },
        is_fallback=False,
    )


class TestTheLiveVerdictReaders:
    async def test_a_replay_is_no_standing_verdict_and_lends_nothing(
        self, settings_kratos: Settings
    ) -> None:
        """The Alerts grid and the Dashboard's true-positive tile read the
        rule's standing verdict. Auto-triage inherits along a pair."""
        from soc_ai.store import investigations as inv_svc

        maker = await _store(settings_kratos)
        async with maker() as db:
            db.add_all(
                [
                    _inv(1, alert="al-1", started_by="backtest", rule="replayed rule"),
                    _inv(2, alert="al-2", started_by="analyst", rule="live rule"),
                    # One run of each in flight, for the sweep's running guard.
                    _inv(
                        3,
                        alert="al-3",
                        started_by="backtest",
                        rule="replayed rule",
                        status="running",
                    ),
                    _inv(4, alert="al-4", started_by="analyst", rule="live rule", status="running"),
                ]
            )
            await db.commit()
            rules = ["replayed rule", "live rule"]
            keys = [inv_svc.pair_key(rule, "10.20.30.40", "10.20.30.41") for rule in rules]
            standing = await inv_svc.latest_complete_for_rules(db, rules)
            any_status = await inv_svc.latest_for_rules(db, rules)
            direct = await inv_svc.latest_for_alerts(db, ["al-1", "al-2"])
            pairs = await inv_svc.latest_for_pairs(db, keys, window_days=7)
            running = await inv_svc.running_for_pairs(db, keys)
            replays = await inv_svc.latest_replays_for_alerts(db, ["al-1", "al-2"])
        # The live run is the control on each reader.
        assert set(standing) == {"live rule"}
        assert set(any_status) == {"live rule"}
        assert set(direct) == {"al-2"}
        assert {key[0] for key in pairs} == {"live rule"}
        assert {key[0] for key in running} == {"live rule"}
        # The backtest reads its own verdict back through its own reader.
        assert set(replays) == {"al-1"}

    async def test_the_bell_lists_no_replay(self, settings_kratos: Settings) -> None:
        from soc_ai.store import investigations as inv_svc

        maker = await _store(settings_kratos)
        async with maker() as db:
            db.add_all(
                [
                    _inv(1, alert="al-1", started_by="backtest"),
                    _inv(2, alert="al-2", started_by="analyst"),
                ]
            )
            await db.commit()
            rows = await inv_svc.list_recent_notifications(db, status="complete")
        assert [r.id for r in rows] == [f"{2:026d}"]


# ---------------------------------------------------------------------------
# The repair: mark the leads that formed from replays
# ---------------------------------------------------------------------------


async def _lead_with(db: Any, observations: list[tuple[str, str]], host: str) -> int:
    """A lead on ``host`` holding one observation per ``(spec_id, fingerprint)``."""
    lead = Lead(status="open", entities_json=[["host", host]], kinds_json=["alert"])
    db.add(lead)
    await db.flush()
    for spec_id, fingerprint in observations:
        db.add(
            EntityObservation(
                entity_kind="host",
                entity_key=host,
                kind="alert" if spec_id == "alert" else "catalog_match",
                spec_id=spec_id,
                fingerprint=fingerprint,
                source="alert" if spec_id == "alert" else "catalog",
                lead_id=lead.id,
            )
        )
    await db.commit()
    return int(lead.id)


class TestTheBacktestLeadRepair:
    async def test_it_marks_only_the_leads_that_formed_from_replays(
        self, settings_kratos: Settings
    ) -> None:
        from soc_ai.store import leads as leads_store

        maker = await _store(settings_kratos)
        async with maker() as db:
            db.add_all(
                [
                    # Replays only.
                    _inv(1, alert="al-replay", started_by="backtest"),
                    _inv(2, alert="al-replay-2", started_by="backtest"),
                    # A live run, and a replay of the same alert.
                    _inv(3, alert="al-both", started_by="analyst"),
                    _inv(4, alert="al-both", started_by="backtest"),
                    # A live run only.
                    _inv(5, alert="al-live", started_by="scheduler"),
                    # A replay that holds a verdict, and a live run that died
                    # with none. A run with no verdict wrote no observation.
                    _inv(6, alert="al-dead", started_by="backtest"),
                    _inv(7, alert="al-dead", started_by="analyst", status="error", verdict=None),
                ]
            )
            await db.commit()
            replay_lead = await _lead_with(
                db, [("alert", "al-replay"), ("alert", "al-replay-2")], "10.20.30.1"
            )
            dead_lead = await _lead_with(db, [("alert", "al-dead")], "10.20.30.2")
            both_lead = await _lead_with(db, [("alert", "al-both")], "10.20.30.3")
            live_lead = await _lead_with(db, [("alert", "al-live")], "10.20.30.4")
            mixed_lead = await _lead_with(
                db, [("alert", "al-replay"), ("t-spec", "fp-1")], "10.20.30.5"
            )
            unknown_lead = await _lead_with(db, [("alert", "al-gone")], "10.20.30.6")

            assert await leads_store.mark_backtest_leads(db) == 2
            flags = {}
            for lead_id in (
                replay_lead,
                dead_lead,
                both_lead,
                live_lead,
                mixed_lead,
                unknown_lead,
            ):
                lead = await db.get(Lead, lead_id)
                assert lead is not None
                flags[lead_id] = leads_store.formed_from_backtest(lead)
        assert flags == {
            replay_lead: True,
            dead_lead: True,
            # The controls: a live verdict on the alert, live evidence of
            # another type, and an alert with no run left to say where the
            # observation came from.
            both_lead: False,
            live_lead: False,
            mixed_lead: False,
            unknown_lead: False,
        }

    async def test_the_repair_is_idempotent_and_changes_no_status(
        self, settings_kratos: Settings
    ) -> None:
        from soc_ai.store import leads as leads_store

        maker = await _store(settings_kratos)
        async with maker() as db:
            db.add(_inv(1, alert="al-replay", started_by="backtest"))
            await db.commit()
            lead_id = await _lead_with(db, [("alert", "al-replay")], "10.20.30.1")
            assert await leads_store.mark_backtest_leads(db) == 1
            assert await leads_store.mark_backtest_leads(db) == 0
            lead = await db.get(Lead, lead_id)
            assert lead is not None
            await db.refresh(lead)
            decisions = leads_store.decisions_of(lead)
            status = lead.status
        assert status == "open"
        assert [d["action"] for d in decisions] == [leads_store.BACKTEST_DECISION]
        assert decisions[0]["note"] == leads_store.BACKTEST_DECISION_NOTE

    async def test_the_mark_does_not_hide_a_hold_reason(self, settings_kratos: Settings) -> None:
        """The settle rule reads the last decision for its hold reason. The
        mark is a note on the lead and must not end the hold."""
        from soc_ai.store import leads as leads_store

        maker = await _store(settings_kratos)
        async with maker() as db:
            db.add(_inv(1, alert="al-replay", started_by="backtest"))
            await db.commit()
            lead_id = await _lead_with(db, [("alert", "al-replay")], "10.20.30.1")
            lead = await db.get(Lead, lead_id)
            assert lead is not None
            lead.hunt_id = "hunt-1"
            leads_store.record_decision(
                lead, "held", utcnow(), hunt_id="hunt-1", reason=leads_store.HOLD_PARTIAL_READ
            )
            await db.commit()
            assert await leads_store.mark_backtest_leads(db) == 1
            await db.refresh(lead)
            assert leads_store.hold_reason_of(lead) == leads_store.HOLD_PARTIAL_READ

"""Tests for the auto-triage feature: plan, run, status, guard rails.

Architecture notes
------------------
``plan_targets`` calls ES through ``aq.fetch_groups`` (which passes
``aggs=...``) and ``aq.fetch_group_events`` (which passes ``size>0``
without aggs).  The fake ES ``search.side_effect`` inspects the ``aggs``
keyword to decide which payload to return.

``run_auto_triage`` drains ``soc_ai.api.runner.run_recorded``; we patch
``soc_ai.api.runner.investigate`` so no real LLM traffic happens.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import AsyncIterator, Callable, Iterator
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr
from soc_ai.agent.orchestrator import StepEvent
from soc_ai.config import Settings
from soc_ai.main import create_app
from soc_ai.store import investigations as inv_svc
from soc_ai.store.db import make_engine, make_sessionmaker, run_migrations

ADMIN_PW = "test-at-pw"

REPORT = {
    "verdict": "false_positive",
    "confidence": 0.9,
    "summary": "Benign scan.",
    "citations": ["ev1"],
    "recommended_actions": [
        {
            "tool_name": "ack_alert",
            "tool_args": {"alert_id": "ev1"},
            "rationale": "Internal scanner.",
        }
    ],
}

# ES response for fetch_groups (has 'aggs' key in the ES result, size=0)
GROUPS_ES_RESPONSE: dict[str, Any] = {
    "took": 2,
    "hits": {"total": {"value": 5, "relation": "eq"}, "hits": []},
    "aggregations": {
        "rules": {
            "buckets": [
                {
                    "key": "ET SCAN thing",
                    "doc_count": 5,
                    "latest_ts": {"value": 1781246460000},
                    "latest": {
                        "hits": {
                            "hits": [
                                {
                                    "_id": "ev1",
                                    "_source": {
                                        "@timestamp": "2026-06-12T06:41:00.000Z",
                                        "event": {"severity_label": "high"},
                                    },
                                }
                            ]
                        }
                    },
                }
            ]
        }
    },
}

# ES response for fetch_group_events (flat hits, no aggregations)
EVENTS_ES_RESPONSE: dict[str, Any] = {
    "took": 1,
    "hits": {
        "total": {"value": 1, "relation": "eq"},
        "hits": [
            {
                "_id": "ev1",
                "_source": {
                    "@timestamp": "2026-06-12T06:41:00.000Z",
                    "source": {"ip": "10.0.0.41", "port": 51515},
                    "destination": {"ip": "10.0.0.1", "port": 443},
                    "event": {"severity_label": "high"},
                    "host": {"name": "sensor1"},
                },
            }
        ],
    },
}


def _make_es_side_effect(
    groups_resp: dict[str, Any] = GROUPS_ES_RESPONSE,
    events_resp: dict[str, Any] = EVENTS_ES_RESPONSE,
) -> Any:
    """Return a side_effect callable that returns groups or events response.

    ``fake_es`` mocks the low-level ``AsyncElasticsearch`` client; calls arrive
    as ``search(index=..., body={...})``.  fetch_groups sets ``body["aggs"]``;
    fetch_group_events does not, so we inspect the body kwarg to distinguish.
    """

    async def _call(*args: Any, **kwargs: Any) -> dict[str, Any]:
        body: dict[str, Any] = kwargs.get("body", {}) or (args[1] if len(args) > 1 else {})
        if body.get("aggs") is not None:
            return groups_resp
        return events_resp

    return _call


def _seed_investigation(
    settings: Settings,
    *,
    rule_name: str,
    alert_es_id: str,
    src_ip: str | None = None,
    dest_ip: str | None = None,
) -> str:
    async def _go() -> str:
        engine = make_engine(settings)
        await run_migrations(engine)
        maker = make_sessionmaker(engine)
        async with maker() as db:
            inv = await inv_svc.create(
                db,
                alert_es_id=alert_es_id,
                started_by="admin",
                src_ip=src_ip,
                dest_ip=dest_ip,
            )
            await inv_svc.set_rule_name(db, inv.id, rule_name)
            await inv_svc.finalize(
                db,
                inv.id,
                status="complete",
                verdict="false_positive",
                confidence=0.9,
                rationale="Internal scanner.",
            )
        await engine.dispose()
        return inv.id

    return asyncio.run(_go())


def _count_investigations(settings: Settings) -> int:
    async def _go() -> int:
        from soc_ai.store.models import Investigation
        from sqlalchemy import func, select

        engine = make_engine(settings)
        await run_migrations(engine)
        maker = make_sessionmaker(engine)
        async with maker() as db:
            result = await db.scalar(select(func.count()).select_from(Investigation))
        await engine.dispose()
        return result or 0

    return asyncio.run(_go())


@pytest.fixture
def at_settings(settings_kratos: Settings) -> Settings:
    # Single-source (Suricata) feed: these tests exercise auto-triage's severity
    # + planning logic against one fetch_groups aggregation. The multi-source
    # merge is covered in test_webui_alerts_query.
    # auto_ack_fp_enabled ships OFF (unattended SO writes are opt-in). These
    # auto-triage tests exercise the inherited-FP auto-ack path, so opt in
    # explicitly; the gate-off case is covered by
    # test_inherited_ack_gated_by_toggle_and_confidence, which overrides it back.
    return settings_kratos.model_copy(
        update={
            "bootstrap_admin_password": SecretStr(ADMIN_PW),
            "webui_extra_detections": False,
            "auto_ack_fp_enabled": True,
        }
    )


@pytest.fixture
def fake_es() -> AsyncMock:
    es = AsyncMock()
    es.search.side_effect = _make_es_side_effect()
    return es


async def _fake_investigate_success(
    alert_id: str,
    *,
    ctx: Any,
    focus_hint: str | None = None,
    deep: bool = False,
) -> AsyncIterator[StepEvent]:
    sid = "fake-at-sid"
    yield StepEvent(
        kind="session_start",
        session_id=sid,
        sequence=1,
        payload={"alert_id": alert_id},
    )
    yield StepEvent(
        kind="enriched_alert_context",
        session_id=sid,
        sequence=2,
        payload={
            "alert": {
                "rule_name": "ET SCAN thing",
                "id": alert_id,
                "timestamp": "2026-06-12T06:41:00Z",
                "source_ip": "10.0.0.41",
                "destination_ip": "10.0.0.1",
            },
            "community_id_events": [],
            "host_events": [],
            "user_events": [],
            "process_events": [],
            "file_events": [],
            "pivot_summary": {},
            "prefetch_gaps": {},
        },
    )
    yield StepEvent(
        kind="triage_report",
        session_id=sid,
        sequence=3,
        payload=REPORT,
    )
    yield StepEvent(
        kind="done",
        session_id=sid,
        sequence=4,
        payload={"recommended_count": 1},
    )


@pytest.fixture
def at_client(at_settings: Settings, fake_es: AsyncMock) -> Iterator[TestClient]:
    """A TestClient for the /api/v1/auto-triage surface.

    ``api_auth_required`` defaults to False (lab default), so the endpoint is
    open and no login/CSRF scaffolding is needed.
    """
    fake_auth = AsyncMock()
    with (
        patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=fake_es),
        patch("soc_ai.main.make_auth", return_value=fake_auth),
        patch("soc_ai.main.get_settings", return_value=at_settings),
        patch("soc_ai.api.runner.investigate", _fake_investigate_success),
    ):
        app = create_app()
        with TestClient(app) as client:
            yield client


def _poll_done(client: TestClient, *, deadline_s: float = 5.0) -> dict[str, Any]:
    """Poll GET /api/v1/auto-triage until the batch finishes; return final JSON."""
    deadline = time.time() + deadline_s
    data: dict[str, Any] = {}
    while time.time() < deadline:
        resp = client.get("/api/v1/auto-triage")
        assert resp.status_code == 200
        data = resp.json()
        if not data["active"] and data.get("finished_at"):
            return data
        time.sleep(0.1)
    return data


def _poll_until(
    client: TestClient,
    predicate: Callable[[dict[str, Any]], bool],
    *,
    deadline_s: float = 5.0,
) -> dict[str, Any]:
    """Poll GET /api/v1/auto-triage until *predicate* holds; return the JSON.

    Replaces a fixed sleep that raced the portal loop's cross-thread worker
    progress — under CI contention the sleep could elapse before the worker had
    advanced. Returns the last observed JSON on timeout so the caller's assertion
    reports the real final state.
    """
    deadline = time.time() + deadline_s
    data: dict[str, Any] = {}
    while time.time() < deadline:
        resp = client.get("/api/v1/auto-triage")
        assert resp.status_code == 200
        data = resp.json()
        if predicate(data):
            return data
        time.sleep(0.02)
    return data


class TestAutoTriageStartsAndCompletes:
    def test_autotriage_starts_and_completes(
        self, at_client: TestClient, at_settings: Settings
    ) -> None:
        resp = at_client.post("/api/v1/auto-triage", json={"range": "24h"})
        assert resp.status_code == 200

        data = _poll_done(at_client)
        assert data["active"] is False
        assert data["hunted"] >= 1

        # An investigation row must have been created
        count = _count_investigations(at_settings)
        assert count >= 1


class TestAutoTriageSkipsCoveredPairs:
    def test_autotriage_skips_covered_pairs(
        self, at_client: TestClient, at_settings: Settings
    ) -> None:
        # Seed a complete investigation matching (rule, src, dst) of ev1
        _seed_investigation(
            at_settings,
            rule_name="ET SCAN thing",
            alert_es_id="other-ev",
            src_ip="10.0.0.41",
            dest_ip="10.0.0.1",
        )

        resp = at_client.post("/api/v1/auto-triage", json={"range": "24h"})
        assert resp.status_code == 200

        data = _poll_done(at_client)
        # 0 hunted: the only candidate pair is already covered.
        assert data["hunted"] == 0
        # The pre-seeded investigation + no new ones
        count = _count_investigations(at_settings)
        assert count == 1  # only the seeded one


class TestInheritedFpAutoAck:
    """In-flight pair suppression + the inherited-verdict auto-ack path."""

    @staticmethod
    def _seed_running(settings: Settings) -> None:
        """A RUNNING (unfinalized) investigation on ev1's (rule, src, dst) pair,
        under a DIFFERENT alert id — the shape that used to produce duplicate
        investigations minutes apart."""

        async def _go() -> None:
            engine = make_engine(settings)
            await run_migrations(engine)
            maker = make_sessionmaker(engine)
            async with maker() as db:
                inv = await inv_svc.create(
                    db,
                    alert_es_id="ev-older",
                    started_by="t",
                    src_ip="10.0.0.41",
                    dest_ip="10.0.0.1",
                )
                await inv_svc.set_rule_name(db, inv.id, "ET SCAN thing")
            await engine.dispose()

        asyncio.run(_go())

    def test_running_pair_suppresses_duplicate_target(self, at_settings: Settings) -> None:
        """A pair whose first run is still RUNNING is not planned again for a
        newer event id (the 'same alert investigated minutes apart' bug: the
        direct id check misses the new id, and latest_for_pairs is
        complete-only so it couldn't see the in-flight run either)."""
        from soc_ai.webui import autotriage as at

        self._seed_running(at_settings)
        es = AsyncMock()
        es.search.side_effect = _make_es_side_effect()
        state = _FakeState(at_settings, es)

        targets, skipped, acks = asyncio.run(at.plan_targets(state, time_range="24h", oql=None))
        assert targets == []
        assert skipped >= 1
        assert acks == []  # a running run hands out no verdict — no ack either

    def test_inherited_fp_emits_ack_candidates(self, at_settings: Settings) -> None:
        """A cluster skipped via a qualifying inherited FP queues its events for
        acknowledgement — the verdict alone never reached Security Onion."""
        from soc_ai.webui import autotriage as at

        _seed_investigation(
            at_settings,
            rule_name="ET SCAN thing",
            alert_es_id="other-ev",
            src_ip="10.0.0.41",
            dest_ip="10.0.0.1",
        )
        es = AsyncMock()
        es.search.side_effect = _make_es_side_effect()
        state = _FakeState(at_settings, es)

        targets, skipped, acks = asyncio.run(at.plan_targets(state, time_range="24h", oql=None))
        assert targets == []
        assert skipped == 1
        assert [a.alert_es_id for a in acks] == ["ev1"]
        assert acks[0].rule_name == "ET SCAN thing"
        assert acks[0].confidence == 0.9

    def test_inherited_ack_gated_by_toggle_and_confidence(self, at_settings: Settings) -> None:
        """No candidates when auto-ack is off, or the inherited confidence is
        below the threshold — the skip itself is unaffected."""
        from soc_ai.webui import autotriage as at

        _seed_investigation(
            at_settings,
            rule_name="ET SCAN thing",
            alert_es_id="other-ev",
            src_ip="10.0.0.41",
            dest_ip="10.0.0.1",
        )
        for override in (
            {"auto_ack_fp_enabled": False},
            {"auto_ack_fp_threshold": 0.95},  # seeded verdict is 0.9
        ):
            es = AsyncMock()
            es.search.side_effect = _make_es_side_effect()
            state = _FakeState(at_settings.model_copy(update=override), es)
            targets, skipped, acks = asyncio.run(at.plan_targets(state, time_range="24h", oql=None))
            assert targets == []
            assert skipped == 1
            assert acks == []

    def test_ack_inherited_fps_worker_gates(self, at_settings: Settings) -> None:
        """The worker pass skips already-acked and high-stakes candidates and
        acks the rest through the audited write path."""
        from types import SimpleNamespace

        from soc_ai.webui import autotriage as at

        def _hit(es_id: str, sev: str, acked: bool = False) -> dict[str, Any]:
            event: dict[str, Any] = {"severity_label": sev}
            if acked:
                event["acknowledged"] = True
            return {
                "_id": es_id,
                "_source": {
                    "@timestamp": "2026-06-12T06:41:00.000Z",
                    "source": {"ip": "10.0.0.41"},
                    "destination": {"ip": "10.0.0.1"},
                    "rule": {"name": "ET SCAN thing"},
                    "event": event,
                },
            }

        es = AsyncMock()
        es.search.return_value = {
            "took": 1,
            "hits": {
                "total": {"value": 3, "relation": "eq"},
                "hits": [
                    _hit("ev-acked", "low", acked=True),
                    _hit("ev-high", "high"),
                    _hit("ev-low", "low"),
                ],
            },
        }
        state = _FakeState(at_settings, es)
        status = at.AutoTriageStatus()
        acks = [
            at.InheritedAck(
                alert_es_id=i, rule_name="ET SCAN thing", inherited_from="inv-1", confidence=0.9
            )
            for i in ("ev-acked", "ev-high", "ev-low")
        ]
        ctx = SimpleNamespace(auth=AsyncMock(), settings=at_settings, audit=None)

        mock_write = AsyncMock(return_value=({"ok": True}, None))
        with patch("soc_ai.tools.write_exec.execute_write_tool", mock_write):
            asyncio.run(at._ack_inherited_fps(state, ctx, acks, status))

        mock_write.assert_awaited_once()
        assert mock_write.await_args.args[1] == {"alert_id": "ev-low"}
        assert status.inherited_acked == 1


class TestAutoTriageSingleFlight:
    def test_autotriage_single_flight(self, at_settings: Settings, fake_es: AsyncMock) -> None:
        """Second POST while one run is active returns the status, not a new run."""
        gate = asyncio.Event()

        async def slow_investigate(
            alert_id: str,
            *,
            ctx: Any,
            focus_hint: str | None = None,
            deep: bool = False,
        ) -> AsyncIterator[StepEvent]:
            sid = "slow-sid"
            yield StepEvent(
                kind="session_start", session_id=sid, sequence=1, payload={"alert_id": alert_id}
            )
            # Wait until the gate is released
            await gate.wait()
            yield StepEvent(kind="triage_report", session_id=sid, sequence=2, payload=REPORT)
            yield StepEvent(
                kind="done", session_id=sid, sequence=3, payload={"recommended_count": 1}
            )

        fake_auth = AsyncMock()
        with (
            patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=fake_es),
            patch("soc_ai.main.make_auth", return_value=fake_auth),
            patch("soc_ai.main.get_settings", return_value=at_settings),
            patch("soc_ai.api.runner.investigate", slow_investigate),
        ):
            app = create_app()
            with TestClient(app) as client:
                # First POST — starts the run
                resp1 = client.post("/api/v1/auto-triage", json={"range": "24h"})
                assert resp1.status_code == 200

                # Small sleep to let the background task start
                time.sleep(0.1)

                # Second POST while the run is active — must not start a new run
                resp2 = client.post("/api/v1/auto-triage", json={"range": "24h"})
                assert resp2.status_code == 200
                assert resp2.json()["note"] == "already running"

                # Release the gate so the task can finish
                gate.set()
                _poll_done(client)

                # Only one investigation should exist (single flight honoured)
                count = _count_investigations(at_settings)
                assert count <= 1


class TestAutoTriageFailedCountsStreamErrors:
    def test_autotriage_failed_counts_stream_errors(
        self, at_settings: Settings, fake_es: AsyncMock
    ) -> None:
        """A stream that emits an 'error' event counts as failed, not hunted."""

        async def erroring_investigate(
            alert_id: str,
            *,
            ctx: Any,
            focus_hint: str | None = None,
            deep: bool = False,
        ) -> AsyncIterator[StepEvent]:
            sid = "err-sid"
            yield StepEvent(
                kind="session_start", session_id=sid, sequence=1, payload={"alert_id": alert_id}
            )
            yield StepEvent(
                kind="error",
                session_id=sid,
                sequence=2,
                payload={"message": "simulated stream error"},
            )

        fake_auth = AsyncMock()
        with (
            patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=fake_es),
            patch("soc_ai.main.make_auth", return_value=fake_auth),
            patch("soc_ai.main.get_settings", return_value=at_settings),
            patch("soc_ai.api.runner.investigate", erroring_investigate),
        ):
            app = create_app()
            with TestClient(app) as client:
                resp = client.post("/api/v1/auto-triage", json={"range": "24h"})
                assert resp.status_code == 200

                data = _poll_done(client)
                # 1 failed, 0 hunted
                assert data["failed"] == 1
                assert data["hunted"] == 0

    def test_autotriage_bounds_a_hung_target_and_moves_on(
        self, at_settings: Settings, fake_es: AsyncMock
    ) -> None:
        """A target whose stream hangs (no wall-clock bound on the LLM read) is
        bounded by ``auto_triage_per_target_timeout_s``, counted as failed, and
        the sweep proceeds — it does not stall the whole run."""

        async def _hanging_investigate(
            alert_id: str,
            *,
            ctx: Any,
            focus_hint: str | None = None,
            deep: bool = False,
        ) -> AsyncIterator[StepEvent]:
            sid = "hang-sid"
            yield StepEvent(
                kind="session_start", session_id=sid, sequence=1, payload={"alert_id": alert_id}
            )
            await asyncio.sleep(3600)  # never completes within the test's timeout
            yield StepEvent(kind="done", session_id=sid, sequence=2, payload={})

        # Tiny per-target backstop (model_copy skips int-field revalidation).
        # BOTH bounds must come down together: the per-target cap is floored at
        # `_PER_TARGET_HEADROOM_RATIO x investigation_run_timeout_s` so it can
        # never be the tighter of the two (a tighter outer cap cancels the
        # generator and lands a silent, event-less error — the 2026-08-03 prod
        # failure this floor exists to prevent). Leaving the inner backstop at its
        # 900s default would floor the effective cap at 1125s and hang this test.
        tight = at_settings.model_copy(
            update={
                "auto_triage_per_target_timeout_s": 0.1,
                "investigation_run_timeout_s": 0.08,
            }
        )

        from soc_ai.webui import autotriage as at
        from soc_ai.webui.autotriage import Target

        targets = [
            Target(alert_es_id="a1", rule_name="ET RULE A", src_ip="10.0.0.1", dst_ip="10.0.0.2"),
        ]
        fake_auth = AsyncMock()
        with (
            patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=fake_es),
            patch("soc_ai.main.make_auth", return_value=fake_auth),
            patch("soc_ai.main.get_settings", return_value=tight),
            patch("soc_ai.api.runner.investigate", _hanging_investigate),
        ):
            app = create_app()
            with TestClient(app):
                app.state.settings = tight
                status = at.get_status(app.state)
                status.reset(active=True, total=1, skipped=0)

                async def _drive() -> None:
                    await asyncio.wait_for(
                        at.run_auto_triage(app.state, targets=targets, started_by="test"),
                        timeout=10,  # the sweep itself must finish well under this
                    )

                asyncio.run(_drive())

                assert status.failed == 1
                assert status.hunted == 0
                assert status.active is False


class _FakeState:
    """Minimal stand-in for app.state used by plan_targets unit tests.

    ``state.elastic`` must be the real :class:`ElasticClient` wrapper (that is
    what the app stores); we inject *low_level_es* as its underlying client so
    ``ElasticClient.search`` returns a proper ``EsSearchResult``.
    """

    def __init__(self, settings: Settings, low_level_es: Any) -> None:
        from soc_ai.so_client.elastic import ElasticClient

        self.settings = settings
        with patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=low_level_es):
            self.elastic = ElasticClient(settings)
        engine = make_engine(settings)
        asyncio.run(run_migrations(engine))
        self.db_sessionmaker = make_sessionmaker(engine)


def _severities_from_groups_calls(es: AsyncMock) -> list[str]:
    """Extract the severity term each fetch_groups call (body has 'aggs') filtered on."""
    seen: list[str] = []
    for call in es.search.call_args_list:
        body = call.kwargs.get("body", {})
        if body.get("aggs") is None:
            continue  # this was a fetch_group_events call
        for f in body.get("query", {}).get("bool", {}).get("filter", []):
            term = f.get("term", {})
            if "event.severity_label" in term:
                seen.append(term["event.severity_label"])
    return seen


class TestAutoTriageSeveritySelector:
    def test_plan_targets_filters_to_chosen_severity(self, at_settings: Settings) -> None:
        """plan_targets only queries the severities it is given."""
        from soc_ai.webui import autotriage as at

        es = AsyncMock()
        es.search.side_effect = _make_es_side_effect()
        state = _FakeState(at_settings, es)

        asyncio.run(at.plan_targets(state, time_range="24h", oql=None, severities=("medium",)))
        sevs = _severities_from_groups_calls(es)
        assert sevs == ["medium"]  # only medium queried, not critical/high

    def test_inheritance_toggle_gates_the_pair_query(self, at_settings: Settings) -> None:
        """#3: with inheritance ON the sweep consults latest_for_pairs (to skip
        already-covered clusters); with it OFF that query is never run, so every
        cluster is investigated independently."""
        from soc_ai.webui import autotriage as at

        def _await_count(flag: bool) -> int:
            es = AsyncMock()
            es.search.side_effect = _make_es_side_effect()
            settings = at_settings.model_copy(update={"auto_triage_inheritance_enabled": flag})
            state = _FakeState(settings, es)
            with patch(
                "soc_ai.webui.autotriage.inv_svc.latest_for_pairs",
                AsyncMock(return_value={}),
            ) as m:
                asyncio.run(at.plan_targets(state, time_range="24h", oql=None))
            return int(m.await_count)

        assert _await_count(True) == 1  # inheritance on → pair query runs
        assert _await_count(False) == 0  # inheritance off → pair query skipped

    def test_plan_targets_defaults_to_critical_high(self, at_settings: Settings) -> None:
        """The default severities are critical + high (no caller choice)."""
        from soc_ai.webui import autotriage as at

        es = AsyncMock()
        es.search.side_effect = _make_es_side_effect()
        state = _FakeState(at_settings, es)

        asyncio.run(at.plan_targets(state, time_range="24h", oql=None))
        sevs = _severities_from_groups_calls(es)
        assert set(sevs) == {"critical", "high"}

    def test_route_passes_chosen_severity_and_shows_it(
        self, at_settings: Settings, fake_es: AsyncMock
    ) -> None:
        """A medium-only POST plans medium groups and the status shows the choice."""
        captured: dict[str, Any] = {}

        async def _capturing_plan_targets(
            state: Any,
            *,
            time_range: str,
            oql: str | None,
            severities: tuple[str, ...],
        ) -> tuple[list[Any], int, list[Any]]:
            captured["severities"] = severities
            return [], 0, []  # nothing to hunt → immediate "done" with chosen sevs

        fake_auth = AsyncMock()
        with (
            patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=fake_es),
            patch("soc_ai.main.make_auth", return_value=fake_auth),
            patch("soc_ai.main.get_settings", return_value=at_settings),
            patch("soc_ai.api.webui_api.at.plan_targets", _capturing_plan_targets),
        ):
            app = create_app()
            with TestClient(app) as client:
                resp = client.post(
                    "/api/v1/auto-triage",
                    json={"range": "24h", "severities": ["medium"]},
                )
                assert resp.status_code == 200
                assert captured["severities"] == ("medium",)
                # The chosen severity is surfaced in the status payload
                assert resp.json()["severities"] == ["medium"]

    def test_route_empty_severities_defaults_to_config_floor(
        self, at_settings: Settings, fake_es: AsyncMock
    ) -> None:
        """Omitting severities falls back to the config-floor band (default high)."""
        captured: dict[str, Any] = {}

        async def _capturing_plan_targets(
            state: Any,
            *,
            time_range: str,
            oql: str | None,
            severities: tuple[str, ...],
        ) -> tuple[list[Any], int, list[Any]]:
            captured["severities"] = severities
            return [], 0, []

        fake_auth = AsyncMock()
        with (
            patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=fake_es),
            patch("soc_ai.main.make_auth", return_value=fake_auth),
            patch("soc_ai.main.get_settings", return_value=at_settings),
            patch("soc_ai.api.webui_api.at.plan_targets", _capturing_plan_targets),
        ):
            app = create_app()
            with TestClient(app) as client:
                resp = client.post("/api/v1/auto-triage", json={"range": "24h"})
                assert resp.status_code == 200
                # Default auto_triage_min_severity="high" → band is (critical, high).
                assert captured["severities"] == ("critical", "high")


class TestAutoTriageSingleFlightBlocksBeforePlanning:
    def test_single_flight_blocks_before_planning(
        self, at_settings: Settings, fake_es: AsyncMock
    ) -> None:
        """When status.active is True a POST returns the 'already running' note."""
        fake_auth = AsyncMock()
        with (
            patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=fake_es),
            patch("soc_ai.main.make_auth", return_value=fake_auth),
            patch("soc_ai.main.get_settings", return_value=at_settings),
            patch("soc_ai.api.runner.investigate", _fake_investigate_success),
        ):
            app = create_app()
            with TestClient(app) as client:
                # Directly set status.active = True to simulate an in-flight run
                from soc_ai.webui.autotriage import get_status

                get_status(app.state).active = True

                resp = client.post("/api/v1/auto-triage", json={"range": "24h"})
                assert resp.status_code == 200
                # The 'already running' note must appear in the response
                assert resp.json()["note"] == "already running"


def _events_response_with_n_clusters(n: int) -> dict[str, Any]:
    """A fetch_group_events response with n hits, each a distinct src IP."""
    return {
        "took": 1,
        "hits": {
            "total": {"value": n, "relation": "eq"},
            "hits": [
                {
                    "_id": f"ev{i}",
                    "_source": {
                        "@timestamp": "2026-06-12T06:41:00.000Z",
                        "source": {"ip": f"10.0.0.{i}", "port": 51515},
                        "destination": {"ip": "10.0.0.1", "port": 443},
                        "event": {"severity_label": "high"},
                        "host": {"name": "sensor1"},
                    },
                }
                for i in range(1, n + 1)
            ],
        },
    }


class TestAutoTriageMaxTargetsCap:
    def test_plan_targets_caps_to_max(self, at_settings: Settings) -> None:
        """A single run queues at most auto_triage_max_targets targets."""
        from soc_ai.webui import autotriage as at

        settings = at_settings.model_copy(update={"auto_triage_max_targets": 5})
        es = AsyncMock()
        es.search.side_effect = _make_es_side_effect(
            events_resp=_events_response_with_n_clusters(30)
        )
        state = _FakeState(settings, es)

        targets, _, _acks = asyncio.run(at.plan_targets(state, time_range="24h", oql=None))
        assert len(targets) == 5

    def test_plan_targets_cap_zero_disables(self, at_settings: Settings) -> None:
        """auto_triage_max_targets=0 disables the cap (all clusters queued)."""
        from soc_ai.webui import autotriage as at

        settings = at_settings.model_copy(update={"auto_triage_max_targets": 0})
        es = AsyncMock()
        es.search.side_effect = _make_es_side_effect(
            events_resp=_events_response_with_n_clusters(30)
        )
        state = _FakeState(settings, es)

        targets, _, _acks = asyncio.run(at.plan_targets(state, time_range="24h", oql=None))
        assert len(targets) == 30


class TestAutoTriagePlanTargetsForIds:
    """Explicit-selection planning: honour the operator's picks, skip verdicted."""

    def test_skips_verdicted_and_dedupes(self, at_settings: Settings) -> None:
        """An id that already carries a verdict is skipped; duplicates collapse."""
        from soc_ai.webui import autotriage as at

        # ev1 already has a completed verdict.
        _seed_investigation(
            at_settings,
            rule_name="ET SCAN thing",
            alert_es_id="ev1",
            src_ip="10.0.0.41",
            dest_ip="10.0.0.1",
        )
        es = AsyncMock()
        es.search.side_effect = _make_es_side_effect()
        state = _FakeState(at_settings, es)

        targets, skipped = asyncio.run(
            at.plan_targets_for_ids(state, alert_ids=["ev1", "ev2", "ev2", "ev3"])
        )
        ids = [t.alert_es_id for t in targets]
        assert ids == ["ev2", "ev3"]  # ev1 skipped (verdict), ev2 de-duped
        assert skipped == 1

    def test_ignores_max_targets_cap(self, at_settings: Settings) -> None:
        """A deliberate selection bypasses the auto_triage_max_targets cap."""
        from soc_ai.webui import autotriage as at

        settings = at_settings.model_copy(update={"auto_triage_max_targets": 5})
        es = AsyncMock()
        es.search.side_effect = _make_es_side_effect()
        state = _FakeState(settings, es)

        ids = [f"sel{i}" for i in range(30)]
        targets, skipped = asyncio.run(at.plan_targets_for_ids(state, alert_ids=ids))
        assert len(targets) == 30  # no cap on explicit selections
        assert skipped == 0

    def test_empty_selection_returns_nothing(self, at_settings: Settings) -> None:
        """No ids → no targets, no DB hit required."""
        from soc_ai.webui import autotriage as at

        es = AsyncMock()
        es.search.side_effect = _make_es_side_effect()
        state = _FakeState(at_settings, es)

        targets, skipped = asyncio.run(at.plan_targets_for_ids(state, alert_ids=["", ""]))
        assert targets == []
        assert skipped == 0


class TestAutoTriageLiveProgress:
    """tool_calls counter and current-target label are updated during the run."""

    def test_tool_calls_and_current_tracked(
        self, at_settings: Settings, fake_es: AsyncMock
    ) -> None:
        """A fake investigate that emits tool_call events causes tool_calls to increment;
        current is set while the target is being hunted and cleared when done."""

        async def _fake_with_tool_calls(
            alert_id: str,
            *,
            ctx: Any,
            focus_hint: str | None = None,
            deep: bool = False,
        ) -> AsyncIterator[StepEvent]:
            sid = "tc-sid"
            yield StepEvent(
                kind="session_start",
                session_id=sid,
                sequence=1,
                payload={"alert_id": alert_id},
            )
            # Two tool_call events — each should bump status.tool_calls
            yield StepEvent(
                kind="tool_call",
                session_id=sid,
                sequence=2,
                payload={"tool": "query_events", "args": {}},
            )
            yield StepEvent(
                kind="tool_call",
                session_id=sid,
                sequence=3,
                payload={"tool": "whois_lookup", "args": {}},
            )
            yield StepEvent(
                kind="triage_report",
                session_id=sid,
                sequence=4,
                payload=REPORT,
            )
            yield StepEvent(
                kind="done",
                session_id=sid,
                sequence=5,
                payload={"recommended_count": 1},
            )

        fake_auth = AsyncMock()
        with (
            patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=fake_es),
            patch("soc_ai.main.make_auth", return_value=fake_auth),
            patch("soc_ai.main.get_settings", return_value=at_settings),
            patch("soc_ai.api.runner.investigate", _fake_with_tool_calls),
        ):
            app = create_app()
            with TestClient(app) as client:
                resp = client.post("/api/v1/auto-triage", json={"range": "24h"})
                assert resp.status_code == 200

                # Poll until the batch finishes, then check final counts.
                data = _poll_done(client)
                assert data["active"] is False, "batch never finished"

                # tool_calls must reflect the two tool_call events fired.
                assert data["tool_calls"] == 2, f"expected tool_calls=2, got {data['tool_calls']}"
                # current must be None after the run finishes.
                assert data["current"] is None, (
                    f"expected current=None after run, got {data['current']!r}"
                )
                # The target should have been hunted (not failed).
                assert data["hunted"] >= 1

    def test_current_set_to_rule_name_during_hunt(
        self, at_settings: Settings, fake_es: AsyncMock
    ) -> None:
        """current is set to the rule_name of the target while being investigated."""
        # Use a gate so we can observe current mid-flight.
        gate = asyncio.Event()
        observed_current: list[str | None] = []

        async def _gated_investigate(
            alert_id: str,
            *,
            ctx: Any,
            focus_hint: str | None = None,
            deep: bool = False,
        ) -> AsyncIterator[StepEvent]:
            sid = "gate-sid"
            yield StepEvent(
                kind="session_start",
                session_id=sid,
                sequence=1,
                payload={"alert_id": alert_id},
            )
            await gate.wait()
            yield StepEvent(kind="triage_report", session_id=sid, sequence=2, payload=REPORT)
            yield StepEvent(
                kind="done", session_id=sid, sequence=3, payload={"recommended_count": 1}
            )

        fake_auth = AsyncMock()
        with (
            patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=fake_es),
            patch("soc_ai.main.make_auth", return_value=fake_auth),
            patch("soc_ai.main.get_settings", return_value=at_settings),
            patch("soc_ai.api.runner.investigate", _gated_investigate),
        ):
            app = create_app()
            with TestClient(app) as client:
                client.post("/api/v1/auto-triage", json={"range": "24h"})

                # While gated, current should be the rule name for the target.
                # Poll until the worker has set `current` rather than racing a
                # fixed sleep against the portal loop's cross-thread progress.
                mid_data = _poll_until(client, lambda d: d.get("current") is not None)
                observed_current.append(mid_data["current"])

                # Release the gate so the task can finish.
                gate.set()
                _poll_done(client)

                # The rule name used in GROUPS_ES_RESPONSE is "ET SCAN thing".
                assert observed_current[0] == "ET SCAN thing", (
                    f"expected current='ET SCAN thing', got {observed_current[0]!r}"
                )


# ---------------------------------------------------------------------------
# maybe_auto_ack_fp unit tests
# ---------------------------------------------------------------------------


class TestMaybeAutoAckFp:
    """Unit tests for the maybe_auto_ack_fp orchestrator helper.

    Stubs out execute_write_tool and the _ev/_audit helpers so no real I/O
    occurs. Mirrors the orchestrator's own stubbing style.
    """

    @staticmethod
    def _make_report(
        verdict: str = "false_positive",
        confidence: float = 0.85,
    ) -> Any:
        from soc_ai.agent.triage import TriageReport

        return TriageReport(
            verdict=verdict,
            confidence=confidence,
            summary="test",
            citations=["ev1"],
            recommended_actions=[],
        )

    @staticmethod
    def _make_alert(
        *,
        classtype: str | None = "misc-activity",
        severity_label: str | None = "low",
        severity_score: int | None = 1,
        rule_name: str = "ET INFO benign chatter",
        signature_severity: str | None = "Informational",
    ) -> Any:
        """Build a SoAlert. Defaults to a benign, low-severity, info-class alert."""
        from soc_ai.so_client.models import RuleMetadata, SoAlert

        return SoAlert(
            id="ev-x",
            rule_name=rule_name,
            classtype=classtype,
            severity_label=severity_label,
            severity_score=severity_score,
            rule_metadata=RuleMetadata(signature_severity=signature_severity),
        )

    @staticmethod
    def _make_ctx(
        settings_override: dict[str, Any],
    ) -> Any:
        """Build a minimal InvestigationContext with stubbed auth."""
        from unittest.mock import AsyncMock

        from soc_ai.agent.orchestrator import InvestigationContext
        from soc_ai.config import Settings

        base = {
            "so_host": "https://so.example.com",
            "so_username": "analyst",
            "so_password": "pw",
            "es_hosts": ["https://so.example.com:9200"],
            "litellm_base_url": "http://localhost:4000",
        }
        base.update(settings_override)
        s = Settings(**base)
        auth = AsyncMock()
        elastic = AsyncMock()
        return InvestigationContext(settings=s, auth=auth, elastic=elastic)

    @staticmethod
    def _make_emit_audit() -> tuple[Any, Any, list[Any]]:
        """Return (_ev callable, _audit callable, captured events list)."""
        captured: list[Any] = []
        seq = [0]

        from soc_ai.agent.orchestrator import StepEvent

        def _ev(kind: str, payload: dict[str, Any]) -> StepEvent:
            seq[0] += 1
            ev = StepEvent(kind=kind, session_id="test-sid", sequence=seq[0], payload=payload)
            captured.append(ev)
            return ev

        async def _audit(ev: StepEvent) -> None:
            pass

        return _ev, _audit, captured

    def test_auto_ack_fires_on_fp_above_threshold(self) -> None:
        """With toggle on, FP verdict at high confidence triggers exactly one ack_alert call."""
        from unittest.mock import AsyncMock, patch

        from soc_ai.agent.orchestrator import maybe_auto_ack_fp

        ctx = self._make_ctx({"auto_ack_fp_enabled": True, "auto_ack_fp_threshold": 0.7})
        report = self._make_report(verdict="false_positive", confidence=0.85)
        _ev, _audit, _captured = self._make_emit_audit()

        alert = self._make_alert()
        mock_write = AsyncMock(return_value=({"ok": True}, None))
        with patch("soc_ai.agent.orchestrator.execute_write_tool", mock_write):
            result = asyncio.run(
                maybe_auto_ack_fp(
                    report, "ev-abc", alert=alert, ctx=ctx, emit_ev=_ev, audit_ev=_audit
                )
            )

        # One ack_alert call with the correct alert_id
        mock_write.assert_awaited_once()
        call_args = mock_write.call_args
        assert call_args.args[0] == "ack_alert"
        assert call_args.args[1] == {"alert_id": "ev-abc"}

        # Returns an auto_ack event
        assert result is not None
        assert result.kind == "auto_ack"
        assert result.payload["es_id"] == "ev-abc"
        assert result.payload["success"] is True

    def test_auto_ack_off_by_default_no_unattended_write(self) -> None:
        """SHIPPED DEFAULT must not write to SO unattended (regression for F17).

        With no ``auto_ack_fp_enabled`` override, the setting is False, so a
        confident false-positive verdict — even one grounded only in a
        prefetched pivot — never reaches ``execute_write_tool``. The unattended
        ack requires an explicit operator opt-in.
        """
        from unittest.mock import AsyncMock, patch

        from soc_ai.agent.orchestrator import maybe_auto_ack_fp

        ctx = self._make_ctx({})  # no override → shipped default
        assert ctx.settings.auto_ack_fp_enabled is False
        report = self._make_report(verdict="false_positive", confidence=0.99)
        _ev, _audit, _ = self._make_emit_audit()

        alert = self._make_alert()
        mock_write = AsyncMock(return_value=(None, None))
        with patch("soc_ai.agent.orchestrator.execute_write_tool", mock_write):
            result = asyncio.run(
                maybe_auto_ack_fp(
                    report, "ev-default", alert=alert, ctx=ctx, emit_ev=_ev, audit_ev=_audit
                )
            )

        mock_write.assert_not_awaited()
        assert result is None

    def test_auto_ack_disabled_when_opted_out(self) -> None:
        """No ack write when auto_ack_fp_enabled=False (operator opt-out)."""
        from unittest.mock import AsyncMock, patch

        from soc_ai.agent.orchestrator import maybe_auto_ack_fp

        ctx = self._make_ctx({"auto_ack_fp_enabled": False})
        report = self._make_report(verdict="false_positive", confidence=0.99)
        _ev, _audit, _ = self._make_emit_audit()

        alert = self._make_alert()
        mock_write = AsyncMock(return_value=(None, None))
        with patch("soc_ai.agent.orchestrator.execute_write_tool", mock_write):
            result = asyncio.run(
                maybe_auto_ack_fp(
                    report, "ev-xyz", alert=alert, ctx=ctx, emit_ev=_ev, audit_ev=_audit
                )
            )

        mock_write.assert_not_awaited()
        assert result is None

    def test_auto_ack_not_fired_for_non_fp_verdicts(self) -> None:
        """True positives and needs_more_info are never auto-acked."""
        from unittest.mock import AsyncMock, patch

        from soc_ai.agent.orchestrator import maybe_auto_ack_fp

        for verdict in ("true_positive", "needs_more_info"):
            ctx = self._make_ctx({"auto_ack_fp_enabled": True, "auto_ack_fp_threshold": 0.5})
            report = self._make_report(verdict=verdict, confidence=0.95)
            _ev, _audit, _ = self._make_emit_audit()

            alert = self._make_alert()
            mock_write = AsyncMock(return_value=(None, None))
            with patch("soc_ai.agent.orchestrator.execute_write_tool", mock_write):
                result = asyncio.run(
                    maybe_auto_ack_fp(
                        report, "ev-tp", alert=alert, ctx=ctx, emit_ev=_ev, audit_ev=_audit
                    )
                )

            mock_write.assert_not_awaited(), f"should not ack for verdict={verdict!r}"
            assert result is None, f"should return None for verdict={verdict!r}"

    def test_auto_ack_suppressed_for_critical_severity_fp(self) -> None:
        """A confident FP on a CRITICAL-severity alert is NOT auto-acked (blast-radius cap)."""
        from unittest.mock import AsyncMock, patch

        from soc_ai.agent.orchestrator import maybe_auto_ack_fp

        ctx = self._make_ctx({"auto_ack_fp_enabled": True, "auto_ack_fp_threshold": 0.7})
        report = self._make_report(verdict="false_positive", confidence=0.95)
        # Critical severity, but otherwise benign class — severity alone blocks it.
        alert = self._make_alert(
            classtype="misc-activity",
            severity_label="critical",
            severity_score=4,
            rule_name="ET INFO something",
            signature_severity="Informational",
        )
        _ev, _audit, _ = self._make_emit_audit()

        mock_write = AsyncMock(return_value=({"ok": True}, None))
        with patch("soc_ai.agent.orchestrator.execute_write_tool", mock_write):
            result = asyncio.run(
                maybe_auto_ack_fp(
                    report, "ev-crit", alert=alert, ctx=ctx, emit_ev=_ev, audit_ev=_audit
                )
            )

        mock_write.assert_not_awaited()
        # The skip is RECORDED with its reason so the drawer can explain why
        # the pending ack needs a human (dogfood 2026-07-15).
        assert result is not None
        assert result.kind == "auto_ack_skipped"
        assert result.payload["reason"] == "high_stakes"

    def test_auto_ack_suppressed_for_malware_class_fp(self) -> None:
        """A confident FP on a malware/exploit-class alert is NOT auto-acked."""
        from unittest.mock import AsyncMock, patch

        from soc_ai.agent.orchestrator import maybe_auto_ack_fp

        ctx = self._make_ctx({"auto_ack_fp_enabled": True, "auto_ack_fp_threshold": 0.7})
        report = self._make_report(verdict="false_positive", confidence=0.95)
        # trojan-activity classtype → POST_COMPROMISE; low severity_label must
        # NOT rescue it (rule class is high-stakes regardless of SO's bucket).
        alert = self._make_alert(
            classtype="trojan-activity",
            severity_label="low",
            severity_score=1,
            rule_name="ET MALWARE BPFDoor",
            signature_severity=None,
        )
        _ev, _audit, _ = self._make_emit_audit()

        mock_write = AsyncMock(return_value=({"ok": True}, None))
        with patch("soc_ai.agent.orchestrator.execute_write_tool", mock_write):
            result = asyncio.run(
                maybe_auto_ack_fp(
                    report, "ev-mal", alert=alert, ctx=ctx, emit_ev=_ev, audit_ev=_audit
                )
            )

        mock_write.assert_not_awaited()
        assert result is not None
        assert result.kind == "auto_ack_skipped"
        assert result.payload["reason"] == "high_stakes"

    def test_auto_ack_suppressed_for_attack_classtype_fp(self) -> None:
        """A confident FP on an attack-class alert (denial-of-service /
        exploit-kit) is NOT auto-acked, even when the rule name carries no
        malware token and SO's own severity is low.

        These classtypes are in decision_templates._ATTACK_CLASSTYPES (they
        escalate to the Oracle) but classify_alert()'s _CLASSTYPE_MAP has no
        entry for them and their rule names don't hit _alert_signals_malware —
        so the high-stakes guard must consult the same attack-classtype set the
        escalation guard does, or these would auto-ack unsupervised.
        """
        from unittest.mock import AsyncMock, patch

        from soc_ai.agent.orchestrator import maybe_auto_ack_fp

        cases = [
            ("denial-of-service", "ET DOS Excessive ICMP", "ev-dos"),
            ("exploit-kit", "ET CURRENT_EVENTS Possible RIG EK Landing", "ev-ek"),
        ]
        for classtype, rule_name, es_id in cases:
            ctx = self._make_ctx({"auto_ack_fp_enabled": True, "auto_ack_fp_threshold": 0.7})
            report = self._make_report(verdict="false_positive", confidence=0.95)
            # Attack classtype, but a generically-named rule (no malware token)
            # and low SO severity — only the attack-classtype signal blocks it.
            alert = self._make_alert(
                classtype=classtype,
                severity_label="low",
                severity_score=1,
                rule_name=rule_name,
                signature_severity=None,
            )
            _ev, _audit, _ = self._make_emit_audit()

            mock_write = AsyncMock(return_value=({"ok": True}, None))
            with patch("soc_ai.agent.orchestrator.execute_write_tool", mock_write):
                result = asyncio.run(
                    maybe_auto_ack_fp(
                        report, es_id, alert=alert, ctx=ctx, emit_ev=_ev, audit_ev=_audit
                    )
                )

            mock_write.assert_not_awaited(), f"should not ack for classtype={classtype!r}"
            assert result is not None, f"classtype={classtype!r}"
            assert result.kind == "auto_ack_skipped", f"classtype={classtype!r}"
            assert result.payload["reason"] == "high_stakes", f"classtype={classtype!r}"

    def test_auto_ack_fires_for_low_severity_benign_class_fp(self) -> None:
        """The benign low-severity info-class FP still auto-acks (cap doesn't over-block)."""
        from unittest.mock import AsyncMock, patch

        from soc_ai.agent.orchestrator import maybe_auto_ack_fp

        ctx = self._make_ctx({"auto_ack_fp_enabled": True, "auto_ack_fp_threshold": 0.7})
        report = self._make_report(verdict="false_positive", confidence=0.9)
        alert = self._make_alert()  # benign defaults
        _ev, _audit, _ = self._make_emit_audit()

        mock_write = AsyncMock(return_value=({"ok": True}, None))
        with patch("soc_ai.agent.orchestrator.execute_write_tool", mock_write):
            result = asyncio.run(
                maybe_auto_ack_fp(
                    report, "ev-ok", alert=alert, ctx=ctx, emit_ev=_ev, audit_ev=_audit
                )
            )

        mock_write.assert_awaited_once()
        assert result is not None
        assert result.payload["success"] is True

    def test_auto_ack_not_fired_below_threshold(self) -> None:
        """FP verdict below the threshold does not trigger auto-ack."""
        from unittest.mock import AsyncMock, patch

        from soc_ai.agent.orchestrator import maybe_auto_ack_fp

        ctx = self._make_ctx({"auto_ack_fp_enabled": True, "auto_ack_fp_threshold": 0.9})
        report = self._make_report(verdict="false_positive", confidence=0.85)
        alert = self._make_alert()
        _ev, _audit, _ = self._make_emit_audit()

        mock_write = AsyncMock(return_value=(None, None))
        with patch("soc_ai.agent.orchestrator.execute_write_tool", mock_write):
            result = asyncio.run(
                maybe_auto_ack_fp(
                    report, "ev-low", alert=alert, ctx=ctx, emit_ev=_ev, audit_ev=_audit
                )
            )

        mock_write.assert_not_awaited()
        assert result is not None
        assert result.kind == "auto_ack_skipped"
        assert result.payload["reason"] == "below_threshold"
        assert result.payload["confidence"] == 0.85
        assert result.payload["threshold"] == 0.9

    def test_auto_ack_fires_at_exact_threshold(self) -> None:
        """A confidence exactly equal to the threshold is accepted."""
        from unittest.mock import AsyncMock, patch

        from soc_ai.agent.orchestrator import maybe_auto_ack_fp

        ctx = self._make_ctx({"auto_ack_fp_enabled": True, "auto_ack_fp_threshold": 0.7})
        report = self._make_report(verdict="false_positive", confidence=0.7)
        alert = self._make_alert()
        _ev, _audit, _ = self._make_emit_audit()

        mock_write = AsyncMock(return_value=({"ok": True}, None))
        with patch("soc_ai.agent.orchestrator.execute_write_tool", mock_write):
            result = asyncio.run(
                maybe_auto_ack_fp(
                    report, "ev-exact", alert=alert, ctx=ctx, emit_ev=_ev, audit_ev=_audit
                )
            )

        mock_write.assert_awaited_once()
        assert result is not None
        assert result.payload["success"] is True

    def test_auto_ack_best_effort_on_write_error(self) -> None:
        """A write failure is logged but does NOT propagate — investigation survives."""
        from unittest.mock import AsyncMock, patch

        from soc_ai.agent.orchestrator import maybe_auto_ack_fp

        ctx = self._make_ctx({"auto_ack_fp_enabled": True, "auto_ack_fp_threshold": 0.7})
        report = self._make_report(verdict="false_positive", confidence=0.9)
        alert = self._make_alert()
        _ev, _audit, _ = self._make_emit_audit()

        mock_write = AsyncMock(return_value=(None, "SO API error: connection refused"))
        with patch("soc_ai.agent.orchestrator.execute_write_tool", mock_write):
            # Must not raise
            result = asyncio.run(
                maybe_auto_ack_fp(
                    report, "ev-err", alert=alert, ctx=ctx, emit_ev=_ev, audit_ev=_audit
                )
            )

        # Event still emitted, success=False
        assert result is not None
        assert result.kind == "auto_ack"
        assert result.payload["success"] is False

    def test_auto_ack_executes_directly(self) -> None:
        """Auto-ack WRITES via execute_write_tool — no human step in between.

        This is the "auto isn't automatic" regression guard: a confident,
        low-stakes FP with the toggle on must go straight to the SO write. If
        auto-ack ever parked the write behind a human step, the operator's
        opt-in would silently do nothing — exactly the reported dogfood bug.
        (The old approval gate this once guarded against was removed entirely;
        the direct-write guarantee is what remains load-bearing.)
        """
        from unittest.mock import AsyncMock, patch

        from soc_ai.agent.orchestrator import maybe_auto_ack_fp

        ctx = self._make_ctx({"auto_ack_fp_enabled": True, "auto_ack_fp_threshold": 0.7})
        report = self._make_report(verdict="false_positive", confidence=0.9)
        alert = self._make_alert()  # benign low-severity info-class FP
        _ev, _audit, _ = self._make_emit_audit()

        mock_write = AsyncMock(return_value=({"ok": True}, None))
        with patch("soc_ai.agent.orchestrator.execute_write_tool", mock_write):
            result = asyncio.run(
                maybe_auto_ack_fp(
                    report, "ev-direct", alert=alert, ctx=ctx, emit_ev=_ev, audit_ev=_audit
                )
            )

        # The write happened directly.
        mock_write.assert_awaited_once()
        assert mock_write.call_args.args[0] == "ack_alert"
        assert result is not None
        assert result.payload["success"] is True

    def test_auto_ack_routes_audit_logger_for_unattended_write(self) -> None:
        """The unattended ack write carries ctx.audit so it lands in the audit trail.

        An analyst-review-free write must always be auditable — execute_write_tool
        writes a fail-closed *intent* record before touching SO when an audit
        logger is provided, so maybe_auto_ack_fp must forward ctx.audit.
        """
        from unittest.mock import AsyncMock, patch

        from soc_ai.agent.orchestrator import maybe_auto_ack_fp

        ctx = self._make_ctx({"auto_ack_fp_enabled": True, "auto_ack_fp_threshold": 0.7})
        audit_logger = AsyncMock()
        ctx.audit = audit_logger  # type: ignore[assignment]
        report = self._make_report(verdict="false_positive", confidence=0.9)
        alert = self._make_alert()
        _ev, _audit, _ = self._make_emit_audit()

        mock_write = AsyncMock(return_value=({"ok": True}, None))
        with patch("soc_ai.agent.orchestrator.execute_write_tool", mock_write):
            result = asyncio.run(
                maybe_auto_ack_fp(
                    report, "ev-audit", alert=alert, ctx=ctx, emit_ev=_ev, audit_ev=_audit
                )
            )

        mock_write.assert_awaited_once()
        # The audit logger from ctx is forwarded to the write executor.
        assert mock_write.call_args.kwargs.get("audit") is audit_logger
        assert result is not None
        assert result.payload["success"] is True


# ---------------------------------------------------------------------------
# Config floor: auto_triage_min_severity drives the sweep band
# ---------------------------------------------------------------------------


class TestAutoTriageProgress:
    """status.current tracks the single in-flight target (the sequential worker
    investigates one at a time); it clears when the run finishes."""

    def test_current_tracks_the_in_flight_target(
        self, at_settings: Settings, fake_es: AsyncMock
    ) -> None:
        """While the first target is gated mid-investigation, status.current is that
        target; after the run finishes it is None. (The old pending_rules set that
        marked the whole queue as 'triaging' was removed — the live "Triaging…"
        badge now keys off the DB run status, not a scheduler set.)"""
        gate = asyncio.Event()
        # Snapshots of status.current taken while the first target is gated.
        observed_current: list[str | None] = []

        async def _gated_investigate(
            alert_id: str,
            *,
            ctx: Any,
            focus_hint: str | None = None,
            deep: bool = False,
        ) -> AsyncIterator[StepEvent]:
            sid = "pend-sid"
            yield StepEvent(
                kind="session_start",
                session_id=sid,
                sequence=1,
                payload={"alert_id": alert_id},
            )
            await gate.wait()
            yield StepEvent(kind="triage_report", session_id=sid, sequence=2, payload=REPORT)
            yield StepEvent(
                kind="done", session_id=sid, sequence=3, payload={"recommended_count": 1}
            )

        from soc_ai.webui import autotriage as at
        from soc_ai.webui.autotriage import Target

        targets = [
            Target(alert_es_id="a1", rule_name="ET RULE A", src_ip="10.0.0.1", dst_ip="10.0.0.2"),
            Target(alert_es_id="b2", rule_name="ET RULE B", src_ip="10.0.0.3", dst_ip="10.0.0.4"),
        ]

        fake_auth = AsyncMock()
        with (
            patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=fake_es),
            patch("soc_ai.main.make_auth", return_value=fake_auth),
            patch("soc_ai.main.get_settings", return_value=at_settings),
            patch("soc_ai.api.runner.investigate", _gated_investigate),
        ):
            app = create_app()
            # TestClient context triggers lifespan startup (db_sessionmaker etc.);
            # this test drives run_auto_triage directly, no HTTP calls needed.
            with TestClient(app):
                status = at.get_status(app.state)
                status.reset(active=True, total=2, skipped=0)

                async def _drive() -> None:
                    run_task = asyncio.create_task(
                        at.run_auto_triage(app.state, targets=targets, started_by="test")
                    )
                    # Let the first iteration start and hit the gate.
                    await asyncio.sleep(0.05)
                    observed_current.append(status.current)
                    # Release so the run can finish.
                    gate.set()
                    await run_task

                asyncio.run(_drive())

        # While the first target was running, current pointed at it (only it).
        assert observed_current[0] == "ET RULE A", (
            f"expected current=ET RULE A mid-run, got {observed_current[0]!r}"
        )
        # After the run finishes, current is cleared and active is False.
        assert status.current is None
        assert status.active is False


class TestAutoTriageConfigFloor:
    """Verify that settings.auto_triage_min_severity controls the severity band
    used when the caller does not supply explicit severities."""

    def _make_client_with_floor(
        self, at_settings: Settings, fake_es: AsyncMock, floor: str
    ) -> Iterator[TestClient]:
        settings = at_settings.model_copy(update={"auto_triage_min_severity": floor})
        fake_auth = AsyncMock()
        with (
            patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=fake_es),
            patch("soc_ai.main.make_auth", return_value=fake_auth),
            patch("soc_ai.main.get_settings", return_value=settings),
        ):
            app = create_app()
            with TestClient(app) as client:
                yield client

    def test_medium_floor_plans_critical_high_medium(
        self, at_settings: Settings, fake_es: AsyncMock
    ) -> None:
        """auto_triage_min_severity=medium → sweep covers critical, high, medium."""
        captured: dict[str, Any] = {}

        async def capturing_plan(state: Any, *, time_range: str, oql, severities):
            captured["severities"] = severities
            return [], 0

        with patch("soc_ai.api.webui_api.at.plan_targets", capturing_plan):
            client = next(self._make_client_with_floor(at_settings, fake_es, "medium"))
            client.post("/api/v1/auto-triage", json={})

        assert set(captured["severities"]) == {"critical", "high", "medium"}

    def test_critical_floor_plans_only_critical(
        self, at_settings: Settings, fake_es: AsyncMock
    ) -> None:
        """auto_triage_min_severity=critical → sweep covers only critical."""
        captured: dict[str, Any] = {}

        async def capturing_plan(state: Any, *, time_range: str, oql, severities):
            captured["severities"] = severities
            return [], 0

        with patch("soc_ai.api.webui_api.at.plan_targets", capturing_plan):
            client = next(self._make_client_with_floor(at_settings, fake_es, "critical"))
            client.post("/api/v1/auto-triage", json={})

        assert captured["severities"] == ("critical",)

    def test_explicit_severities_override_config_floor(
        self, at_settings: Settings, fake_es: AsyncMock
    ) -> None:
        """Explicit body.severities overrides the config floor entirely."""
        captured: dict[str, Any] = {}

        async def capturing_plan(state: Any, *, time_range: str, oql, severities):
            captured["severities"] = severities
            return [], 0

        with patch("soc_ai.api.webui_api.at.plan_targets", capturing_plan):
            # Config floor is critical-only, but caller asks for critical+high+medium
            client = next(self._make_client_with_floor(at_settings, fake_es, "critical"))
            client.post(
                "/api/v1/auto-triage",
                json={"severities": ["critical", "high", "medium"]},
            )

        assert set(captured["severities"]) == {"critical", "high", "medium"}


def test_request_stop_signals_cancel_only_when_active() -> None:
    """F6: request_stop is a no-op when idle, and sets cancelled on an active run
    so the worker loop aborts before the next target."""
    import types

    from soc_ai.webui import autotriage as at

    state = types.SimpleNamespace()
    assert at.request_stop(state) is False  # idle → nothing to stop
    status = at.get_status(state)
    assert status.cancelled is False
    status.active = True
    assert at.request_stop(state) is True
    assert status.cancelled is True


class TestConfigSeverityBand:
    """``config_severity_band`` maps the configured floor to the sweep scope —
    everything at/above it, critical-first. This is what the continuous scheduler
    triages, so a 'low' floor must drain ALL four severities, not just crit/high."""

    @pytest.mark.parametrize(
        ("floor", "expected"),
        [
            ("low", ("critical", "high", "medium", "low")),
            ("medium", ("critical", "high", "medium")),
            ("high", ("critical", "high")),
            ("critical", ("critical",)),
        ],
    )
    def test_floor_expands_to_band(self, floor: str, expected: tuple[str, ...]) -> None:
        import types

        from soc_ai.webui import autotriage as at

        s = types.SimpleNamespace(auto_triage_min_severity=floor)
        assert at.config_severity_band(s) == expected

    def test_unset_floor_defaults_to_high(self) -> None:
        import types

        from soc_ai.webui import autotriage as at

        assert at.config_severity_band(types.SimpleNamespace()) == ("critical", "high")

    def test_bogus_floor_defaults_to_high(self) -> None:
        import types

        from soc_ai.webui import autotriage as at

        s = types.SimpleNamespace(auto_triage_min_severity="not-a-severity")
        assert at.config_severity_band(s) == ("critical", "high")


class TestStartConfigSweep:
    """``start_config_sweep`` is the scheduler's entry point: plan the config band,
    claim the single-flight slot, launch ``run_auto_triage``. Never raises."""

    def _state(self, floor: str = "low") -> Any:
        import types

        return types.SimpleNamespace(settings=types.SimpleNamespace(auto_triage_min_severity=floor))

    @pytest.mark.asyncio
    async def test_returns_zero_when_a_sweep_is_already_running(self) -> None:
        from soc_ai.webui import autotriage as at

        state = self._state()
        at.get_status(state).active = True  # a manual ⚡ press already owns the slot

        async def _boom(*a: Any, **k: Any) -> Any:  # planning must never be reached
            raise AssertionError("plan_targets called while a sweep was active")

        with patch("soc_ai.webui.autotriage.plan_targets", _boom):
            assert await at.start_config_sweep(state, started_by="scheduler") == 0
        assert at.get_status(state).active is True  # slot untouched

    @pytest.mark.asyncio
    async def test_empty_plan_resets_to_idle(self) -> None:
        from soc_ai.webui import autotriage as at

        state = self._state(floor="high")

        async def _empty(_s: Any, *, time_range: str, oql: Any, severities: Any) -> Any:
            assert severities == ("critical", "high")  # planned the config band
            return [], 4, []

        with patch("soc_ai.webui.autotriage.plan_targets", _empty):
            assert await at.start_config_sweep(state, started_by="scheduler") == 0
        st = at.get_status(state)
        assert st.active is False  # released the slot — backlog was already clear
        assert st.finished_at is not None
        assert st.skipped == 4

    @pytest.mark.asyncio
    async def test_launches_targets_and_claims_slot(self) -> None:
        from soc_ai.webui import autotriage as at

        state = self._state(floor="low")
        targets = [object(), object(), object()]
        ran: dict[str, Any] = {}

        async def _plan(_s: Any, *, time_range: str, oql: Any, severities: Any) -> Any:
            assert severities == ("critical", "high", "medium", "low")
            return targets, 2, []

        async def _run(
            _s: Any, *, targets: Any, started_by: str, inherited_acks: Any = None
        ) -> None:
            ran["targets"] = targets
            ran["started_by"] = started_by

        with (
            patch("soc_ai.webui.autotriage.plan_targets", _plan),
            patch("soc_ai.webui.autotriage.run_auto_triage", _run),
        ):
            n = await at.start_config_sweep(state, started_by="auto-triage:scheduler")
            st = at.get_status(state)
            assert n == 3
            assert st.active is True
            assert st.total == 3
            assert st.skipped == 2
            assert st._task is not None
            await st._task  # let the launched worker run to completion

        assert ran["targets"] == targets
        assert ran["started_by"] == "auto-triage:scheduler"


class TestResolveRuleNames:
    """plan_targets_for_ids batch-resolves rule names so selected-id runs are named
    at creation even if they die before their first alert_context event."""

    def _state(self, es: Any) -> Any:
        import types

        return types.SimpleNamespace(
            elastic=es, settings=types.SimpleNamespace(events_index_pattern="logs-*")
        )

    def test_batch_resolves_rule_then_dataset(self) -> None:
        import types

        from soc_ai.webui import autotriage as at

        es = AsyncMock()
        es.search = AsyncMock(
            return_value=types.SimpleNamespace(
                hits=[
                    {"_id": "a1", "_source": {"rule": {"name": "ET SCAN x"}}},
                    {"_id": "a2", "_source": {"event": {"dataset": "zeek.notice"}}},
                    {"_id": "a3", "_source": {}},  # no name → omitted
                ]
            )
        )
        out, answered = asyncio.run(at._resolve_rule_names(self._state(es), ["a1", "a2", "a3"]))
        assert out == {"a1": "ET SCAN x", "a2": "zeek.notice"}
        assert answered is True
        # one batched ES call against the events index, sized to the whole selection
        _args, _kwargs = es.search.call_args
        assert _args[0] == "logs-*"
        assert _args[1] == {"ids": {"values": ["a1", "a2", "a3"]}}

    def test_a_reply_with_no_matches_still_counts_as_an_answer(self) -> None:
        """The empty map is ambiguous and the flag is what disambiguates it: the
        grid replied, it just had no docs for these ids."""
        import types

        from soc_ai.webui import autotriage as at

        es = AsyncMock()
        es.search = AsyncMock(return_value=types.SimpleNamespace(hits=[]))
        assert asyncio.run(at._resolve_rule_names(self._state(es), ["a1"])) == ({}, True)

    def test_es_failure_returns_empty_map(self) -> None:
        from soc_ai.webui import autotriage as at

        es = AsyncMock()
        es.search = AsyncMock(side_effect=RuntimeError("es down"))
        # Best-effort: a lookup failure must not raise — names just stay blank,
        # and the caller is told the grid did not answer.
        assert asyncio.run(at._resolve_rule_names(self._state(es), ["a1"])) == ({}, False)

    def test_empty_ids_makes_no_es_call(self) -> None:
        from soc_ai.webui import autotriage as at

        es = AsyncMock()
        assert asyncio.run(at._resolve_rule_names(self._state(es), [])) == ({}, False)
        es.search.assert_not_called()


class TestAutoTriageSkippedReasons:
    """E2.2: the planner stashes a per-reason skip breakdown on the run's status
    so the completion note can explain WHY work was skipped (not just a count)."""

    def test_plan_targets_reasons_sum_to_skipped(self, at_settings: Settings) -> None:
        """A direct verdict on the only candidate skips it under 'already_triaged',
        and the per-reason tally sums to the returned skipped count."""
        from soc_ai.webui import autotriage as at

        # ev1 (the sole clustered event) already carries a verdict → direct hit.
        _seed_investigation(
            at_settings,
            rule_name="ET SCAN thing",
            alert_es_id="ev1",
            src_ip="10.0.0.41",
            dest_ip="10.0.0.1",
        )
        es = AsyncMock()
        es.search.side_effect = _make_es_side_effect()
        state = _FakeState(at_settings, es)

        targets, skipped, _acks = asyncio.run(at.plan_targets(state, time_range="24h", oql=None))
        reasons = at.get_status(state).skipped_reasons
        assert targets == []
        assert skipped == 1
        assert reasons == {"already_triaged": 1}
        assert sum(reasons.values()) == skipped

    def test_plan_targets_inherited_reason(self, at_settings: Settings) -> None:
        """A pair-inherited skip is tallied under 'inherited'."""
        from soc_ai.webui import autotriage as at

        # A FP on the SAME (rule, src, dst) pair under a different id → ev1's
        # cluster is skipped by inheritance, not a direct hit.
        _seed_investigation(
            at_settings,
            rule_name="ET SCAN thing",
            alert_es_id="other-ev",
            src_ip="10.0.0.41",
            dest_ip="10.0.0.1",
        )
        es = AsyncMock()
        es.search.side_effect = _make_es_side_effect()
        state = _FakeState(at_settings, es)

        _targets, skipped, _acks = asyncio.run(at.plan_targets(state, time_range="24h", oql=None))
        reasons = at.get_status(state).skipped_reasons
        assert reasons == {"inherited": 1}
        assert sum(reasons.values()) == skipped

    def test_plan_targets_clean_run_has_empty_reasons(self, at_settings: Settings) -> None:
        """A run with nothing to skip lands an empty (not stale) breakdown."""
        from soc_ai.webui import autotriage as at

        es = AsyncMock()
        es.search.side_effect = _make_es_side_effect()
        state = _FakeState(at_settings, es)

        targets, skipped, _acks = asyncio.run(at.plan_targets(state, time_range="24h", oql=None))
        assert len(targets) == 1  # ev1 is fresh → one target
        assert skipped == 0
        assert at.get_status(state).skipped_reasons == {}

    def test_plan_targets_for_ids_reasons_sum(self, at_settings: Settings) -> None:
        """plan_targets_for_ids tallies already-verdicted skips under
        'already_triaged', summing to the skipped count."""
        from soc_ai.webui import autotriage as at

        _seed_investigation(
            at_settings,
            rule_name="ET SCAN thing",
            alert_es_id="ev1",
            src_ip="10.0.0.41",
            dest_ip="10.0.0.1",
        )
        es = AsyncMock()
        es.search.side_effect = _make_es_side_effect()
        state = _FakeState(at_settings, es)

        targets, skipped = asyncio.run(at.plan_targets_for_ids(state, alert_ids=["ev1", "ev2"]))
        reasons = at.get_status(state).skipped_reasons
        assert [t.alert_es_id for t in targets] == ["ev2"]
        assert skipped == 1
        assert reasons == {"already_triaged": 1}
        assert sum(reasons.values()) == skipped


def _no_ip_hit(es_id: str, timestamp: str) -> dict[str, Any]:
    """A host/process-shaped detection hit: no ``source.*``/``destination.*``.

    Shaped after the prod Sigma detection "Potential Exploitation of
    CVE-2024-3094 - Suspicious SSH Child Process", which carries no network
    endpoints at all.
    """
    return {
        "_id": es_id,
        "_source": {
            "@timestamp": timestamp,
            "event": {"severity_label": "high"},
            "process": {"name": "sshd"},
        },
    }


def _events_response(hits: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "took": 1,
        "hits": {"total": {"value": len(hits), "relation": "eq"}, "hits": hits},
    }


def _groups_response_for_rules(rule_names: list[str]) -> dict[str, Any]:
    """A fetch_groups aggregation with one bucket per rule name."""
    return {
        "took": 2,
        "hits": {"total": {"value": len(rule_names), "relation": "eq"}, "hits": []},
        "aggregations": {
            "rules": {
                "buckets": [
                    {
                        "key": name,
                        "doc_count": 1,
                        "latest_ts": {"value": 1781246460000},
                        "latest": {
                            "hits": {
                                "hits": [
                                    {
                                        "_id": f"latest-{name}",
                                        "_source": {
                                            "@timestamp": "2026-06-12T06:41:00.000Z",
                                            "event": {"severity_label": "high"},
                                        },
                                    }
                                ]
                            }
                        },
                    }
                    for name in rule_names
                ]
            }
        },
    }


def _rule_aware_es_side_effect(
    groups_resp: dict[str, Any],
    events_by_rule: dict[str, dict[str, Any]],
) -> Any:
    """Like :func:`_make_es_side_effect`, but serves a different event page per
    rule — fetch_group_events filters on a ``rule.name`` term, so the fake reads
    that term back out of the query body to decide which page to return."""

    async def _call(*args: Any, **kwargs: Any) -> dict[str, Any]:
        body: dict[str, Any] = kwargs.get("body", {}) or (args[1] if len(args) > 1 else {})
        if body.get("aggs") is not None:
            return groups_resp
        rule = ""
        for f in body.get("query", {}).get("bool", {}).get("filter", []):
            term = f.get("term", {})
            if "rule.name" in term:
                rule = term["rule.name"]
        return events_by_rule.get(rule, _events_response([]))

    return _call


def _half_keyed_events_response(n: int) -> dict[str, Any]:
    """n hits with a source IP but NO destination — the other previously-dropped
    shape (one endpoint missing is enough to lose the event)."""
    return _events_response(
        [
            {
                "_id": f"half{i}",
                "_source": {
                    "@timestamp": "2026-06-12T06:41:00.000Z",
                    "source": {"ip": f"10.0.0.{i}", "port": 51515},
                    "event": {"severity_label": "high"},
                },
            }
            for i in range(1, n + 1)
        ]
    )


class TestAutoTriageNoIpEvents:
    """Endpoint-shaped detections must be triageable by the SCHEDULED sweep.

    The planner used to key every candidate on (rule, src_ip, dst_ip) and drop
    anything missing either IP under the skip reason "no_ip". That made every
    host/process-shaped detection structurally un-triageable: seen and discarded
    on every sweep, forever. Prod proof: 11 no-IP investigations, every one
    started by a human, none by 'auto-triage:scheduler'.
    """

    def _ev(
        self,
        es_id: str,
        *,
        src_ip: str | None = None,
        dst_ip: str | None = None,
        host: str = "—",
    ) -> Any:
        from soc_ai.webui.alerts_query import AlertEvent

        return AlertEvent(
            es_id=es_id,
            timestamp="2026-06-12T06:41:00.000Z",
            src="—",
            dst="—",
            severity="high",
            host=host,
            src_ip=src_ip,
            dst_ip=dst_ip,
        )

    def test_cluster_events_keeps_no_ip_event(self) -> None:
        """A no-IP event is clustered, not dropped."""
        from soc_ai.webui import autotriage as at

        clusters = at._cluster_events({"CVE-2024-3094 SSH child": [self._ev("ev-no-ip")]})
        assert [ev.es_id for ev in clusters.values()] == ["ev-no-ip"]

    def test_cluster_events_collapses_no_ip_events_of_one_rule(self) -> None:
        """Many no-IP events of ONE rule become ONE cluster (dedupe preserved),
        represented by the newest — the same choice the IP path makes."""
        from soc_ai.webui import autotriage as at

        # fetch_group_events returns newest-first.
        events = [self._ev(f"ev{i}") for i in range(5)]
        clusters = at._cluster_events({"CVE-2024-3094 SSH child": events})
        assert len(clusters) == 1
        assert next(iter(clusters.values())).es_id == "ev0"

    def test_cluster_events_keeps_rules_separate(self) -> None:
        """No-IP events of DIFFERENT rules stay separate clusters."""
        from soc_ai.webui import autotriage as at

        clusters = at._cluster_events(
            {
                "CVE-2024-3094 SSH child": [self._ev("ev-a1"), self._ev("ev-a2")],
                "Suspicious sudo child": [self._ev("ev-b1")],
            }
        )
        assert len(clusters) == 2
        assert sorted(ev.es_id for ev in clusters.values()) == ["ev-a1", "ev-b1"]

    def test_cluster_events_ip_keys_unchanged(self) -> None:
        """The IP path is byte-for-byte what it was: keyed on the (rule, src,
        dst) triple ONLY. The host is deliberately NOT part of the key — a
        multi-sensor grid seeing one flow twice must stay one cluster."""
        from soc_ai.webui import autotriage as at

        clusters = at._cluster_events(
            {
                "ET SCAN thing": [
                    self._ev("ev1", src_ip="10.0.0.41", dst_ip="10.0.0.1", host="sensor1"),
                    self._ev("ev2", src_ip="10.0.0.41", dst_ip="10.0.0.1", host="sensor2"),
                    self._ev("ev3", src_ip="10.0.0.42", dst_ip="10.0.0.1", host="sensor1"),
                ]
            }
        )
        assert set(clusters) == {
            ("ET SCAN thing", "10.0.0.41", "10.0.0.1"),
            ("ET SCAN thing", "10.0.0.42", "10.0.0.1"),
        }
        # newest-first wins within a cluster
        assert clusters[("ET SCAN thing", "10.0.0.41", "10.0.0.1")].es_id == "ev1"

    def test_plan_targets_queues_no_ip_event(self, at_settings: Settings) -> None:
        """End to end: a no-IP detection is queued and NOT tallied as skipped."""
        from soc_ai.webui import autotriage as at

        rule = "Potential Exploitation of CVE-2024-3094"
        es = AsyncMock()
        es.search.side_effect = _rule_aware_es_side_effect(
            _groups_response_for_rules([rule]),
            {rule: _events_response([_no_ip_hit("ev-no-ip", "2026-08-07T01:10:37.000Z")])},
        )
        state = _FakeState(at_settings, es)

        targets, skipped, _acks = asyncio.run(at.plan_targets(state, time_range="24h", oql=None))
        assert [t.alert_es_id for t in targets] == ["ev-no-ip"]
        assert targets[0].rule_name == rule
        assert (targets[0].src_ip, targets[0].dst_ip) == ("", "")
        assert skipped == 0
        assert at.get_status(state).skipped_reasons == {}

    def test_plan_targets_no_ip_multiple_events_one_target(self, at_settings: Settings) -> None:
        """A chatty no-IP rule mints ONE target per sweep, not one per event."""
        from soc_ai.webui import autotriage as at

        rule = "Potential Exploitation of CVE-2024-3094"
        hits = [_no_ip_hit(f"ev-no-ip-{i}", f"2026-08-07T01:1{i}:00.000Z") for i in range(6)]
        es = AsyncMock()
        es.search.side_effect = _rule_aware_es_side_effect(
            _groups_response_for_rules([rule]), {rule: _events_response(hits)}
        )
        state = _FakeState(at_settings, es)

        targets, skipped, _acks = asyncio.run(at.plan_targets(state, time_range="24h", oql=None))
        assert [t.alert_es_id for t in targets] == ["ev-no-ip-0"]
        assert skipped == 0

    def test_plan_targets_no_ip_rules_stay_separate(self, at_settings: Settings) -> None:
        """Two different no-IP rules each get their own target."""
        from soc_ai.webui import autotriage as at

        rule_a = "Potential Exploitation of CVE-2024-3094"
        rule_b = "Suspicious sudo child process"
        es = AsyncMock()
        es.search.side_effect = _rule_aware_es_side_effect(
            _groups_response_for_rules([rule_a, rule_b]),
            {
                rule_a: _events_response([_no_ip_hit("ev-a", "2026-08-07T01:10:00.000Z")]),
                rule_b: _events_response([_no_ip_hit("ev-b", "2026-08-07T01:11:00.000Z")]),
            },
        )
        state = _FakeState(at_settings, es)

        targets, _skipped, _acks = asyncio.run(at.plan_targets(state, time_range="24h", oql=None))
        assert sorted(t.alert_es_id for t in targets) == ["ev-a", "ev-b"]
        assert sorted(t.rule_name for t in targets) == sorted([rule_a, rule_b])

    def test_plan_targets_no_ip_respects_direct_verdict(self, at_settings: Settings) -> None:
        """The id-keyed coverage check still fires for a no-IP cluster: an event
        that already carries a verdict is skipped under 'already_triaged', not
        re-queued (its investigation row has NULL src/dest ips)."""
        from soc_ai.webui import autotriage as at

        rule = "Potential Exploitation of CVE-2024-3094"
        _seed_investigation(at_settings, rule_name=rule, alert_es_id="ev-no-ip")
        es = AsyncMock()
        es.search.side_effect = _rule_aware_es_side_effect(
            _groups_response_for_rules([rule]),
            {rule: _events_response([_no_ip_hit("ev-no-ip", "2026-08-07T01:10:37.000Z")])},
        )
        state = _FakeState(at_settings, es)

        targets, skipped, _acks = asyncio.run(at.plan_targets(state, time_range="24h", oql=None))
        assert targets == []
        assert skipped == 1
        assert at.get_status(state).skipped_reasons == {"already_triaged": 1}

    def test_plan_targets_cap_applies_to_partially_keyed_events(
        self, at_settings: Settings
    ) -> None:
        """auto_triage_max_targets still bounds a sweep made of the newly-kept
        shapes (here: source IP present, destination missing)."""
        from soc_ai.webui import autotriage as at

        settings = at_settings.model_copy(update={"auto_triage_max_targets": 5})
        es = AsyncMock()
        es.search.side_effect = _make_es_side_effect(events_resp=_half_keyed_events_response(30))
        state = _FakeState(settings, es)

        targets, _skipped, _acks = asyncio.run(at.plan_targets(state, time_range="24h", oql=None))
        assert len(targets) == 5
        assert all(t.dst_ip == "" for t in targets)


# ---------------------------------------------------------------------------
# G3 (degraded-grid sweep, 2026-08-13) — a dead grid is not a drained queue.
#
# plan_targets used to swallow every fetch_groups / fetch_group_events failure
# and return ([], 0, []) through the identical path a genuinely empty backlog
# takes, so the route answered 200 "nothing to hunt" with failed=0 and the
# dashboard tile read "Last batch · 0 investigated" for the whole blind window.
# ---------------------------------------------------------------------------


def _es_severity_of(body: dict[str, Any]) -> str | None:
    """The severity a fetch_groups body filtered on (None for event fetches)."""
    for f in body.get("query", {}).get("bool", {}).get("filter", []):
        term = f.get("term", {})
        if "event.severity_label" in term:
            return str(term["event.severity_label"])
    return None


def _down_grid_es() -> AsyncMock:
    """A low-level ES mock that refuses every search, as an unreachable grid does."""
    from elastic_transport import ConnectionError as EsConnectionError

    es = AsyncMock()
    es.search.side_effect = EsConnectionError("connection refused")
    return es


def _half_blind_es(down_severity: str = "critical") -> AsyncMock:
    """A grid that fails the *down_severity* group query and answers the rest.

    The realistic shape of a sick (rather than dead) grid — and the case that
    must still run the sweep, so the fix cannot be "raise on any error".
    """
    from elastic_transport import ConnectionError as EsConnectionError

    async def _call(*args: Any, **kwargs: Any) -> dict[str, Any]:
        body: dict[str, Any] = kwargs.get("body", {}) or (args[1] if len(args) > 1 else {})
        if body.get("aggs") is not None:
            if _es_severity_of(body) == down_severity:
                raise EsConnectionError("connection refused")
            return GROUPS_ES_RESPONSE
        return EVENTS_ES_RESPONSE

    es = AsyncMock()
    es.search.side_effect = _call
    return es


def _client_for(at_settings: Settings, es: AsyncMock) -> Iterator[TestClient]:
    fake_auth = AsyncMock()
    with (
        patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=es),
        patch("soc_ai.main.make_auth", return_value=fake_auth),
        patch("soc_ai.main.get_settings", return_value=at_settings),
        patch("soc_ai.api.runner.investigate", _fake_investigate_success),
    ):
        app = create_app()
        with TestClient(app) as client:
            yield client


def _saturated_grid_es() -> AsyncMock:
    """A grid that answers 429 to every search, as a saturated one does.

    The message is the one the console showed verbatim during the dogfood run:
    a parent circuit breaker tripping on an aggregation. ``ElasticClient`` sets
    ``retry_on_status=(429, ...)``, so by the time application code sees this the
    transport has already retried and lost — it is sustained saturation.
    """
    from elastic_transport import ApiResponseMeta, HttpHeaders
    from elasticsearch import ApiError

    meta = ApiResponseMeta(429, "HTTP/1.1", HttpHeaders(), 0.0, None)
    es = AsyncMock()
    es.search.side_effect = ApiError("circuit_breaking_exception", meta=meta, body={})
    return es


def _timed_out_grid_es() -> AsyncMock:
    """A grid whose searches are cut off with 408 by whatever sits in front of it.

    Same outage as :func:`_saturated_grid_es` wearing a different status code: a
    load balancer or proxy running out of patience while Elasticsearch is still
    working. Nothing about the query is wrong, and nothing an analyst can type
    makes the search finish sooner.
    """
    from elastic_transport import ApiResponseMeta, HttpHeaders
    from elasticsearch import ApiError

    meta = ApiResponseMeta(408, "HTTP/1.1", HttpHeaders(), 0.0, None)
    es = AsyncMock()
    es.search.side_effect = ApiError("request timeout", meta=meta, body={})
    return es


@pytest.fixture
def down_grid_client(at_settings: Settings) -> Iterator[TestClient]:
    yield from _client_for(at_settings, _down_grid_es())


@pytest.fixture
def half_blind_client(at_settings: Settings) -> Iterator[TestClient]:
    yield from _client_for(at_settings, _half_blind_es())


@pytest.fixture
def saturated_grid_client(at_settings: Settings) -> Iterator[TestClient]:
    yield from _client_for(at_settings, _saturated_grid_es())


class TestAutoTriageDoesNotReportADeadGridAsQuiet:
    def test_post_on_a_dead_grid_is_503_not_nothing_to_hunt(
        self, down_grid_client: TestClient
    ) -> None:
        """Every severity's fetch failed — nothing could be READ, so there is no
        claim to make about the backlog. Status code is the assertion: a changed
        note still passes if the route keeps answering 200."""
        resp = down_grid_client.post("/api/v1/auto-triage", json={"range": "24h"})
        assert resp.status_code == 503
        assert resp.json()["detail"]["reason"] == "grid_unavailable"

    def test_a_dead_grid_leaves_a_durable_degraded_mark(self, down_grid_client: TestClient) -> None:
        """The 503 is a toast the analyst can miss; the polled status is what the
        dashboard tile renders for the rest of the blind window."""
        down_grid_client.post("/api/v1/auto-triage", json={"range": "24h"})
        status = down_grid_client.get("/api/v1/auto-triage").json()
        assert status["degraded"] is True
        assert status["active"] is False
        # ...and it names the queries it could not read, which is what the tile
        # counts. (A `note != "nothing to hunt"` assertion here would pin
        # nothing: GET always serializes note=None — the note rides on POST.)
        assert status["grid_errors"] == ["severity critical", "severity high"]

    def test_es_client_error_is_a_400_not_a_500(self, at_settings: Settings) -> None:
        """An ES 4xx is a bad query, not an outage — the alerts-route split.

        And it must not plant the degraded mark: the tile would then claim a grid
        outage, for hours, over a query the grid answered (rejected) just fine.
        A degraded signal that cries wolf is the signal being trained away."""
        from elastic_transport import ApiResponseMeta, HttpHeaders
        from elasticsearch import BadRequestError

        meta = ApiResponseMeta(400, "HTTP/1.1", HttpHeaders(), 0.0, None)
        es = AsyncMock()
        es.search.side_effect = BadRequestError("bad", meta=meta, body={})
        for client in _client_for(at_settings, es):
            resp = client.post("/api/v1/auto-triage", json={"range": "24h"})
            assert resp.status_code == 400
            status = client.get("/api/v1/auto-triage").json()
            assert status["degraded"] is False
            assert status["grid_errors"] == []
            assert status["active"] is False

    def test_a_half_blind_grid_still_sweeps_but_reports_degraded(
        self, half_blind_client: TestClient
    ) -> None:
        """One severity readable, one not: the sweep MUST still run (a flaky grid
        can't stop triage) and the status must admit the partial blindness."""
        resp = half_blind_client.post("/api/v1/auto-triage", json={"range": "24h"})
        assert resp.status_code == 200
        assert resp.json()["degraded"] is True
        data = _poll_done(half_blind_client)
        assert data["hunted"] >= 1
        assert data["degraded"] is True

    def test_a_healthy_sweep_is_not_marked_degraded(self, at_client: TestClient) -> None:
        """The control: without it the fix could be 'always degraded'."""
        resp = at_client.post("/api/v1/auto-triage", json={"range": "24h"})
        assert resp.status_code == 200
        data = _poll_done(at_client)
        assert data["degraded"] is False
        assert data["grid_errors"] == []

    def test_plan_targets_propagates_a_total_grid_failure(self, at_settings: Settings) -> None:
        """Unit-level: the planner raises rather than returning a plausible zero."""
        from elastic_transport import TransportError
        from soc_ai.webui import autotriage as at

        state = _FakeState(at_settings, _down_grid_es())
        with pytest.raises(TransportError):
            asyncio.run(at.plan_targets(state, time_range="24h", oql=None))
        assert at.get_status(state).degraded is True

    def test_plan_targets_propagates_when_every_group_event_fetch_fails(
        self, at_settings: Settings
    ) -> None:
        """The second blind spot: groups read fine, every per-rule event fetch
        fails, so clusters is empty and the old code returned a clean zero."""
        from elastic_transport import ConnectionError as EsConnectionError
        from elastic_transport import TransportError
        from soc_ai.webui import autotriage as at

        async def _call(*args: Any, **kwargs: Any) -> dict[str, Any]:
            body: dict[str, Any] = kwargs.get("body", {}) or (args[1] if len(args) > 1 else {})
            if body.get("aggs") is not None:
                return GROUPS_ES_RESPONSE
            raise EsConnectionError("connection refused")

        es = AsyncMock()
        es.search.side_effect = _call
        state = _FakeState(at_settings, es)
        with pytest.raises(TransportError):
            asyncio.run(at.plan_targets(state, time_range="24h", oql=None))

    def test_scheduled_sweep_records_the_outage_instead_of_a_clean_zero(
        self, at_settings: Settings
    ) -> None:
        """The scheduler swallows planning failures by design (it must not die),
        so the persisted status is the ONLY place the blind window can show up."""
        from soc_ai.webui import autotriage as at

        state = _FakeState(at_settings, _down_grid_es())
        launched = asyncio.run(at.start_config_sweep(state, started_by="scheduler"))
        status = at.get_status(state)
        assert launched == 0
        assert status.degraded is True
        assert status.active is False
        # ...and the slot is released, or the next cycle never runs.
        assert status.finished_at is not None


class TestDegradedMeansTheGridCouldNotBeRead:
    """The other half of the honesty contract: `degraded` must stay a signal
    about the GRID. A mark planted by a malformed query or an app-side crash on
    a healthy grid is a false alarm that trains the analyst to ignore the tile —
    the same failure as the false all-clear, pointed the other way."""

    def test_a_malformed_oql_sweep_is_a_400_and_leaves_the_grid_unaccused(
        self, at_client: TestClient
    ) -> None:
        """A typo'd filter is deterministic and query-class: it never reached
        the grid, so it says nothing about the grid's health."""
        resp = at_client.post("/api/v1/auto-triage", json={"range": "24h", "q": "this is (bad"})
        assert resp.status_code == 400
        assert resp.json()["detail"]["reason"] == "bad_oql"
        status = at_client.get("/api/v1/auto-triage").json()
        assert status["degraded"] is False
        assert status["grid_errors"] == []
        # the single-flight slot is released too, or the next sweep is refused
        assert status["active"] is False

    def test_a_non_grid_planning_crash_does_not_land_a_fresh_clean_batch(
        self, at_settings: Settings
    ) -> None:
        """Scheduled cycle, healthy grid, app-side failure after the backlog was
        read (a DB error in the coverage maps). Landing a finished-zero here
        would stamp a brand-new "Last batch · 0 investigated" over the previous
        cycle's real numbers — a fresh false all-clear for a cycle that crashed
        without looking at a single alert."""
        from soc_ai.webui import autotriage as at

        es = AsyncMock()
        es.search.side_effect = _make_es_side_effect()
        state = _FakeState(at_settings, es)
        status = at.get_status(state)
        # a real, completed previous cycle
        status.reset(active=False, total=5, skipped=1, severities=("critical", "high"))
        status.hunted = 4
        status.finished_at = "2026-08-13T01:00:00+00:00"

        async def _boom(*args: Any, **kwargs: Any) -> Any:
            raise RuntimeError("database is locked")

        with patch.object(at, "_coverage_maps", _boom):
            launched = asyncio.run(at.start_config_sweep(state, started_by="scheduler"))

        assert launched == 0
        # The grid was fine — do not accuse it.
        assert status.degraded is False
        # The slot is released so the next cycle can run...
        assert status.active is False
        # ...but nothing was investigated and nothing may be claimed: the last
        # real batch stands, unreplaced by a fabricated fresh zero.
        assert (status.total, status.hunted, status.finished_at) == (
            5,
            4,
            "2026-08-13T01:00:00+00:00",
        )


# ---------------------------------------------------------------------------
# D4 (degraded-grid dogfood, 2026-08-14) — a refused sweep is not a completed one.
#
# The gap the sweep above left: ``_is_query_class`` bucketed every 4xx as the
# operator's fault, so a saturated grid's 429 was re-raised unlabelled, no
# grid_errors were stashed, and the tile printed "Last batch · 0 investigated"
# over a sweep that never read a single alert. Two classifiers for one question
# (this one and ``routes_alerts._es_api_error_http``) had drifted apart.
# ---------------------------------------------------------------------------


class TestASaturatedGridRefusesTheSweepRatherThanEmptyingIt:
    def test_a_refused_sweep_is_503_not_nothing_to_hunt(
        self, saturated_grid_client: TestClient
    ) -> None:
        """A 429 is the grid's story, not the query's: the same request works
        unchanged once the cluster is under its limits again."""
        resp = saturated_grid_client.post("/api/v1/auto-triage", json={"range": "24h"})
        assert resp.status_code == 503
        assert resp.json()["detail"]["reason"] == "grid_unavailable"

    def test_a_refused_sweep_is_not_recorded_as_a_finished_empty_batch(
        self, saturated_grid_client: TestClient
    ) -> None:
        """The durable half, and the one the analyst actually reads. The toast
        fades; the polled status is what the Auto-Investigate tile renders for
        the rest of the outage. It used to render "Last batch · 0 investigated"
        — a completed batch that found nothing, for a sweep that was refused."""
        saturated_grid_client.post("/api/v1/auto-triage", json={"range": "24h"})
        status = saturated_grid_client.get("/api/v1/auto-triage").json()
        assert status["degraded"] is True
        # ...naming the queries it could not read, never the exception text
        # (which carries the grid's host:port).
        assert status["grid_errors"] == ["severity critical", "severity high"]
        # the slot is released and the batch claims nothing
        assert status["active"] is False
        assert (status["total"], status["hunted"], status["failed"]) == (0, 0, 0)

    def test_plan_targets_marks_a_saturated_grid_degraded(self, at_settings: Settings) -> None:
        """Unit-level: fetch_groups raising 429 for every severity leaves the
        planner's mark behind before the exception propagates."""
        from elasticsearch import ApiError
        from soc_ai.webui import autotriage as at

        state = _FakeState(at_settings, _saturated_grid_es())
        with pytest.raises(ApiError):
            asyncio.run(at.plan_targets(state, time_range="24h", oql=None))
        status = at.get_status(state)
        assert status.degraded is True
        assert status.grid_errors == ["severity critical", "severity high"]

    def test_scheduled_sweep_records_the_saturation_instead_of_a_clean_zero(
        self, at_settings: Settings
    ) -> None:
        """The scheduler swallows planning failures by design, so a 429 cycle
        that leaves no mark is invisible — and the tile keeps the last clean
        batch on screen while every cycle in the outage reads nothing."""
        from soc_ai.webui import autotriage as at

        state = _FakeState(at_settings, _saturated_grid_es())
        launched = asyncio.run(at.start_config_sweep(state, started_by="scheduler"))
        status = at.get_status(state)
        assert launched == 0
        assert status.degraded is True
        assert status.active is False
        assert status.finished_at is not None

    @pytest.mark.parametrize("status_code", [400, 403, 404, 408, 422, 429, 500, 503])
    def test_the_query_class_split_matches_the_route_helper(self, status_code: int) -> None:
        """The drift guard, which is the actual defect here — 429 was only the
        symptom. Two independent classifiers answer one question ("is this the
        query's fault or the grid's?") on two paths through the same failure, and
        when the routes learned about 429 the planner did not. Pin them to each
        other so the next status code cannot be taught to one alone: whatever
        ``_es_api_error_http`` maps to 400 is exactly what the planner may
        re-raise unlabelled, and everything else must earn a degraded mark.

        The pin is symmetric on purpose, and it has already done its job once:
        408 was taught to the route first (batch G, task #97) and this test went
        red until the planner followed. That pairing is what keeps the outcome
        coherent — a route that files a timeout as the grid's while the planner
        files it as the analyst's produces a 503 with no degraded mark behind
        it."""
        from elastic_transport import ApiResponseMeta, HttpHeaders
        from elasticsearch import ApiError
        from soc_ai.api.webui.routes_alerts import _es_api_error_http
        from soc_ai.webui import autotriage as at

        meta = ApiResponseMeta(status_code, "HTTP/1.1", HttpHeaders(), 0.0, None)
        exc = ApiError("boom", meta=meta, body={})
        route_says_bad_query = _es_api_error_http(exc).status_code == 400
        assert at._is_query_class(exc) is route_says_bad_query

    @pytest.mark.parametrize("status_code", [400, 403, 404, 408, 409, 422, 429, 500, 502, 503, 504])
    def test_the_agent_toolset_tells_the_same_story(self, status_code: int) -> None:
        """There is a THIRD classifier, and it is the one the model reads.

        ``toolset._is_grid_unavailable`` decides whether a failed tool call comes
        back to the model as a query it can fix or as ``grid_unavailable`` — the
        stamp the hunt runner counts to stop a blind hunt landing as a clean
        sweep. Same question, third answer, and until now nothing held it to the
        other two, so the drift D4 is about could re-open here on any status code
        somebody teaches to one file.

        This guard lives in the planner's test file, next to the pin it extends,
        because the three only matter as a set: the harm is not any one of them
        being wrong, it is two of them disagreeing about the same outage.

        408 is IN the list. It was the one status the three split on when this
        guard was written — the toolset called it the grid, the other two called
        it the query — and it was excluded here with a red-on-arrival note
        recording the gap. Task #97 closed it in the toolset's favour, so the
        exclusion went with the note."""
        from elastic_transport import ApiResponseMeta, HttpHeaders
        from elasticsearch import ApiError
        from soc_ai.agent.toolset import _is_grid_unavailable
        from soc_ai.api.webui.routes_alerts import _es_api_error_http

        meta = ApiResponseMeta(status_code, "HTTP/1.1", HttpHeaders(), 0.0, None)
        exc = ApiError("boom", meta=meta, body={})
        route_says_bad_query = _es_api_error_http(exc).status_code == 400
        assert _is_grid_unavailable(exc) is not route_says_bad_query

    def test_a_timed_out_sweep_leaves_the_same_mark_a_saturated_one_does(
        self, at_settings: Settings
    ) -> None:
        """The durable half of task #97, and the reason the classifier split
        mattered rather than being a wording argument.

        A 408 in front of Elasticsearch is a proxy giving up under load — 429's
        outage with a different number on it. Filed as the analyst's bad query it
        was re-raised unlabelled, so the sweep that read nothing left no mark and
        the tile kept rendering the last clean batch through the whole blind
        window. The status is what the analyst reads; the toast is not.

        Twin of ``test_plan_targets_marks_a_saturated_grid_degraded`` above, and
        deliberately a behavioural assertion rather than a call to
        ``_is_query_class``: the classifier is the mechanism, the missing mark is
        the defect."""
        from elasticsearch import ApiError
        from soc_ai.webui import autotriage as at

        state = _FakeState(at_settings, _timed_out_grid_es())
        with pytest.raises(ApiError):
            asyncio.run(at.plan_targets(state, time_range="24h", oql=None))
        status = at.get_status(state)
        assert status.degraded is True
        assert status.grid_errors == ["severity critical", "severity high"]


class TestASelectionDoesNotEraseWhatTheSweepLearned:
    """A selected-id run reads nothing off the grid, so it cannot report the
    grid healthy.

    ``plan_targets_for_ids`` used to clear ``grid_errors`` unconditionally, on
    the reasoning that a selection can never be blind the way a severity sweep
    can. True, and beside the point: an empty ``grid_errors`` is not "this run
    was not blind", it is the claim "the grid is readable", and this path never
    learns that. Mid-outage the sequence is one click apart — a refused sweep
    lands the degraded mark, the analyst ticks two rows on the (stale) alerts
    list and hits Bulk Investigate, and the tile goes back to "Last batch · 2
    investigated" while every search is still answering 429.

    The one thing this path DOES learn is :func:`_resolve_rule_names`: one real
    query, best-effort, whose answer says whether the grid is talking. Clearing
    on the strength of that is earned; clearing regardless is not.
    """

    def test_a_selection_during_the_outage_keeps_the_degraded_mark(
        self, saturated_grid_client: TestClient
    ) -> None:
        """The dogfood sequence, one click further on: refused sweep, then Bulk
        Investigate over a selection while the grid still refuses everything."""
        saturated_grid_client.post("/api/v1/auto-triage", json={"range": "24h"})
        assert saturated_grid_client.get("/api/v1/auto-triage").json()["degraded"] is True

        # The selection is still honoured: degrade the claim, not the screen.
        resp = saturated_grid_client.post("/api/v1/auto-triage", json={"alert_ids": ["e1", "e2"]})
        assert resp.status_code == 200

        status = saturated_grid_client.get("/api/v1/auto-triage").json()
        assert status["degraded"] is True
        assert status["grid_errors"] == ["severity critical", "severity high"]

    def test_plan_targets_for_ids_keeps_a_mark_it_could_not_disprove(
        self, at_settings: Settings
    ) -> None:
        """Unit-level: the rule-name lookup is refused, so this run learned
        nothing about the grid and the standing mark stands."""
        from soc_ai.webui import autotriage as at

        state = _FakeState(at_settings, _saturated_grid_es())
        at.get_status(state).grid_errors = ["severity critical"]

        targets, _skipped = asyncio.run(at.plan_targets_for_ids(state, alert_ids=["e1", "e2"]))
        assert [t.alert_es_id for t in targets] == ["e1", "e2"]  # the batch still runs
        assert at.get_status(state).grid_errors == ["severity critical"]

    def test_a_selection_on_a_recovered_grid_clears_the_mark(self, at_settings: Settings) -> None:
        """The over-correction control, and the reason this is keyed off a real
        answer rather than off the path taken: once the grid replies, the mark
        goes. A degraded note nothing can clear is a note analysts learn to
        ignore, which is the same defect as the false all-clear aimed the other
        way."""
        from soc_ai.webui import autotriage as at

        es = AsyncMock()
        es.search.side_effect = _make_es_side_effect()
        state = _FakeState(at_settings, es)
        at.get_status(state).grid_errors = ["severity critical"]

        asyncio.run(at.plan_targets_for_ids(state, alert_ids=["e1", "e2"]))
        assert at.get_status(state).grid_errors == []

    def test_an_empty_selection_asserts_nothing_either(self, at_settings: Settings) -> None:
        """No ids means no query was sent, so there is no news about the grid
        and nothing to overwrite the last run's finding with."""
        from soc_ai.webui import autotriage as at

        state = _FakeState(at_settings, _saturated_grid_es())
        at.get_status(state).grid_errors = ["severity critical"]

        targets, skipped = asyncio.run(at.plan_targets_for_ids(state, alert_ids=["", ""]))
        assert (targets, skipped) == ([], 0)
        assert at.get_status(state).grid_errors == ["severity critical"]

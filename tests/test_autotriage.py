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
from collections.abc import AsyncIterator, Iterator
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
    return settings_kratos.model_copy(
        update={"bootstrap_admin_password": SecretStr(ADMIN_PW), "webui_extra_detections": False}
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
    agent: Any = None,
    investigator: Any = None,
    synthesizer: Any = None,
    session_id: str | None = None,
) -> AsyncIterator[StepEvent]:
    sid = session_id or "fake-at-sid"
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


class TestAutoTriageSingleFlight:
    def test_autotriage_single_flight(self, at_settings: Settings, fake_es: AsyncMock) -> None:
        """Second POST while one run is active returns the status, not a new run."""
        gate = asyncio.Event()

        async def slow_investigate(
            alert_id: str,
            *,
            ctx: Any,
            agent: Any = None,
            investigator: Any = None,
            synthesizer: Any = None,
            session_id: str | None = None,
        ) -> AsyncIterator[StepEvent]:
            sid = session_id or "slow-sid"
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
            agent: Any = None,
            investigator: Any = None,
            synthesizer: Any = None,
            session_id: str | None = None,
        ) -> AsyncIterator[StepEvent]:
            sid = session_id or "err-sid"
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
        ) -> tuple[list[Any], int]:
            captured["severities"] = severities
            return [], 0  # nothing to hunt → immediate "done" with chosen sevs

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
        ) -> tuple[list[Any], int]:
            captured["severities"] = severities
            return [], 0

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

        targets, _ = asyncio.run(at.plan_targets(state, time_range="24h", oql=None))
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

        targets, _ = asyncio.run(at.plan_targets(state, time_range="24h", oql=None))
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
            agent: Any = None,
            investigator: Any = None,
            synthesizer: Any = None,
            session_id: str | None = None,
        ) -> AsyncIterator[StepEvent]:
            sid = session_id or "tc-sid"
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
            agent: Any = None,
            investigator: Any = None,
            synthesizer: Any = None,
            session_id: str | None = None,
        ) -> AsyncIterator[StepEvent]:
            sid = session_id or "gate-sid"
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
                time.sleep(0.15)

                # While gated, current should be the rule name for the target.
                mid_resp = client.get("/api/v1/auto-triage")
                assert mid_resp.status_code == 200
                mid_data = mid_resp.json()
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
        with patch("soc_ai.api.approvals.execute_write_tool", mock_write):
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

    def test_auto_ack_disabled_by_default(self) -> None:
        """No ack write when auto_ack_fp_enabled=False (the default)."""
        from unittest.mock import AsyncMock, patch

        from soc_ai.agent.orchestrator import maybe_auto_ack_fp

        ctx = self._make_ctx({})  # defaults: auto_ack_fp_enabled=False
        report = self._make_report(verdict="false_positive", confidence=0.99)
        _ev, _audit, _ = self._make_emit_audit()

        alert = self._make_alert()
        mock_write = AsyncMock(return_value=(None, None))
        with patch("soc_ai.api.approvals.execute_write_tool", mock_write):
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
            with patch("soc_ai.api.approvals.execute_write_tool", mock_write):
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
        with patch("soc_ai.api.approvals.execute_write_tool", mock_write):
            result = asyncio.run(
                maybe_auto_ack_fp(
                    report, "ev-crit", alert=alert, ctx=ctx, emit_ev=_ev, audit_ev=_audit
                )
            )

        mock_write.assert_not_awaited()
        assert result is None

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
        with patch("soc_ai.api.approvals.execute_write_tool", mock_write):
            result = asyncio.run(
                maybe_auto_ack_fp(
                    report, "ev-mal", alert=alert, ctx=ctx, emit_ev=_ev, audit_ev=_audit
                )
            )

        mock_write.assert_not_awaited()
        assert result is None

    def test_auto_ack_fires_for_low_severity_benign_class_fp(self) -> None:
        """The benign low-severity info-class FP still auto-acks (cap doesn't over-block)."""
        from unittest.mock import AsyncMock, patch

        from soc_ai.agent.orchestrator import maybe_auto_ack_fp

        ctx = self._make_ctx({"auto_ack_fp_enabled": True, "auto_ack_fp_threshold": 0.7})
        report = self._make_report(verdict="false_positive", confidence=0.9)
        alert = self._make_alert()  # benign defaults
        _ev, _audit, _ = self._make_emit_audit()

        mock_write = AsyncMock(return_value=({"ok": True}, None))
        with patch("soc_ai.api.approvals.execute_write_tool", mock_write):
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
        with patch("soc_ai.api.approvals.execute_write_tool", mock_write):
            result = asyncio.run(
                maybe_auto_ack_fp(
                    report, "ev-low", alert=alert, ctx=ctx, emit_ev=_ev, audit_ev=_audit
                )
            )

        mock_write.assert_not_awaited()
        assert result is None

    def test_auto_ack_fires_at_exact_threshold(self) -> None:
        """A confidence exactly equal to the threshold is accepted."""
        from unittest.mock import AsyncMock, patch

        from soc_ai.agent.orchestrator import maybe_auto_ack_fp

        ctx = self._make_ctx({"auto_ack_fp_enabled": True, "auto_ack_fp_threshold": 0.7})
        report = self._make_report(verdict="false_positive", confidence=0.7)
        alert = self._make_alert()
        _ev, _audit, _ = self._make_emit_audit()

        mock_write = AsyncMock(return_value=({"ok": True}, None))
        with patch("soc_ai.api.approvals.execute_write_tool", mock_write):
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
        with patch("soc_ai.api.approvals.execute_write_tool", mock_write):
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
            agent: Any = None,
            investigator: Any = None,
            synthesizer: Any = None,
            session_id: str | None = None,
        ) -> AsyncIterator[StepEvent]:
            sid = session_id or "pend-sid"
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
            return [], 4

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
            return targets, 2

        async def _run(_s: Any, *, targets: Any, started_by: str) -> None:
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
        out = asyncio.run(at._resolve_rule_names(self._state(es), ["a1", "a2", "a3"]))
        assert out == {"a1": "ET SCAN x", "a2": "zeek.notice"}
        # one batched ES call against the events index, sized to the whole selection
        _args, _kwargs = es.search.call_args
        assert _args[0] == "logs-*"
        assert _args[1] == {"ids": {"values": ["a1", "a2", "a3"]}}

    def test_es_failure_returns_empty_map(self) -> None:
        from soc_ai.webui import autotriage as at

        es = AsyncMock()
        es.search = AsyncMock(side_effect=RuntimeError("es down"))
        # Best-effort: a lookup failure must not raise — names just stay blank.
        assert asyncio.run(at._resolve_rule_names(self._state(es), ["a1"])) == {}

    def test_empty_ids_makes_no_es_call(self) -> None:
        from soc_ai.webui import autotriage as at

        es = AsyncMock()
        assert asyncio.run(at._resolve_rule_names(self._state(es), [])) == {}
        es.search.assert_not_called()

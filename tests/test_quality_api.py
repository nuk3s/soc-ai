"""Tests for the GET /api/v1/quality/trend read-model (I4).

Mirrors the tests/test_webui_api.py idiom: a real ``create_app()`` under
TestClient with ES/auth stubbed at the client boundary, seeding the app's own
SQLite store through ``app.state.db_sessionmaker``. Asserts the light shape
the Quality card consumes: oldest-first ordering, the 30-point cap, honest
nulls, the persisted alarm fields, and the admin gate.
"""

from __future__ import annotations

import asyncio
from collections.abc import Iterator
from datetime import datetime
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient
from soc_ai.config import Settings
from soc_ai.main import create_app
from soc_ai.store import quality as quality_svc


def _client(settings: Settings) -> Iterator[TestClient]:
    fake_es = AsyncMock()
    fake_auth = AsyncMock()
    with (
        patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=fake_es),
        patch("soc_ai.main.make_auth", return_value=fake_auth),
        patch("soc_ai.main.get_settings", return_value=settings),
    ):
        app = create_app()
        with TestClient(app) as client:
            yield client


@pytest.fixture
def client(settings_kratos: Settings) -> Iterator[TestClient]:
    yield from _client(settings_kratos)


def _seed(client: TestClient, snapshots: list[dict[str, Any]]) -> None:
    """Insert snapshot rows through the app's own sessionmaker."""

    async def _go() -> None:
        maker = client.app.state.db_sessionmaker
        async with maker() as db:
            for snap in snapshots:
                await quality_svc.insert_snapshot(db, **snap)

    asyncio.run(_go())


def _snap(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "mode": "graded",
        "n_ok": 5,
        "n_error": 0,
        "agreement_rate": 0.8,
        "fallback_rate": 0.0,
        "error_rate": 0.0,
        "verdict_counts": {"false_positive": 4, "true_positive": 1},
        "latency_p50_ms": 90_000,
        "batch_dir": "evals/batch-x",
        "alarmed": False,
        "alarm_reasons": None,
    }
    base.update(overrides)
    return base


def test_trend_empty_is_ok_not_error(client: TestClient) -> None:
    """No history → 200 with an empty list: the card's 'schedule the nightly'
    empty state renders from data, never from an error path."""
    resp = client.get("/api/v1/quality/trend")
    assert resp.status_code == 200
    assert resp.json() == {"points": []}


def test_trend_shape_ordering_and_honest_nulls(client: TestClient) -> None:
    _seed(
        client,
        [
            _snap(mode="local", agreement_rate=None, fallback_rate=None, n_ok=0, n_error=3),
            _snap(
                mode="graded",
                agreement_rate=0.4,
                alarmed=True,
                alarm_reasons=["agreement_rate 0.40 is more than 0.15 below the trailing median"],
            ),
        ],
    )
    body = client.get("/api/v1/quality/trend").json()
    points = body["points"]
    assert len(points) == 2
    # Oldest first — ready for left-to-right plotting.
    first, second = points
    assert first["mode"] == "local"
    assert first["agreement_rate"] is None  # honest null, not 0
    assert first["fallback_rate"] is None
    assert first["alarmed"] is False
    assert first["alarm_reasons"] == []  # NULL column → [] on the wire
    assert second["mode"] == "graded"
    assert second["agreement_rate"] == 0.4
    assert second["alarmed"] is True
    assert second["alarm_reasons"] and "trailing median" in second["alarm_reasons"][0]
    # timezone-aware timestamps (the browser must localize correctly)
    assert first["ts"].endswith("+00:00")
    assert second["verdict_counts"] == {"false_positive": 4, "true_positive": 1}


def test_trend_caps_at_30_points_newest_kept(client: TestClient) -> None:
    _seed(client, [_snap(latency_p50_ms=i) for i in range(35)])
    points = client.get("/api/v1/quality/trend").json()["points"]
    assert len(points) == 30
    # The NEWEST 30 survive the cap: the last-inserted point is last (newest),
    # and the oldest five (p50 0..4) fell off the front.
    assert points[-1]["latency_p50_ms"] == 34
    assert points[0]["latency_p50_ms"] == 5


def test_trend_exposes_the_counts_and_the_bundle_behind_a_point(client: TestClient) -> None:
    """Two things an operator needs to adjudicate an alarm and the card needs
    to be honest: the grade counts behind the rate (a bare 0.60 hides whether
    the two non-agreements were flat disagreements or thin-reasoning
    ``partial`` calls) and the bundle path the critiques live in."""
    _seed(
        client,
        [
            _snap(
                agreement_rate=0.6,
                n_yes=3,
                n_partial=1,
                n_no=1,
                n_classified=5,
                batch_dir="/var/lib/soc-ai/evals/batch-20260807",
            )
        ],
    )
    point = client.get("/api/v1/quality/trend").json()["points"][0]
    assert (point["n_yes"], point["n_partial"], point["n_no"]) == (3, 1, 1)
    assert point["n_classified"] == 5
    assert point["batch_dir"] == "/var/lib/soc-ai/evals/batch-20260807"


def test_trend_exposes_the_alarm_identity_and_its_duration(client: TestClient) -> None:
    """The card cannot render "still the same problem" from prose: every reason
    string embeds the run's live numbers, so one unchanged condition reads as a
    new sentence every night. The codes are what let it say "ongoing since
    08-06" and give the pipeline-health alarm (``error_ceiling`` — the eval runs
    themselves failing) a different headline from a verdict-quality one."""
    _seed(
        client,
        [
            _snap(
                agreement_rate=0.4,
                error_rate=0.6,
                alarmed=True,
                alarm_reasons=["agreement_rate 0.40 ...", "error_rate 0.60 ..."],
                alarm_key="agreement_drop+error_ceiling",
                alarm_since=datetime(2026, 8, 6, 2, 17),
            )
        ],
    )
    point = client.get("/api/v1/quality/trend").json()["points"][0]
    assert point["alarm_codes"] == ["agreement_drop", "error_ceiling"]
    assert point["alarm_key"] == "agreement_drop+error_ceiling"
    # Timezone-aware like every other timestamp on the wire, or the browser
    # renders "ongoing since" off by the client's UTC offset.
    assert point["alarm_since"] == "2026-08-06T02:17:00+00:00"


def test_trend_serves_no_codes_for_a_clean_or_pre_0027_point(client: TestClient) -> None:
    """A clean row has no condition, and a pre-0027 row's condition was never
    recorded — both must serve empty/null rather than an invented code, so the
    card falls back to the prose reasons it has always shown."""
    _seed(
        client,
        [
            _snap(),
            _snap(alarmed=True, alarm_reasons=["agreement_rate 0.40 ..."]),  # pre-0027
        ],
    )
    clean, legacy = client.get("/api/v1/quality/trend").json()["points"]
    assert (clean["alarm_codes"], clean["alarm_key"], clean["alarm_since"]) == ([], None, None)
    assert legacy["alarmed"] is True
    assert legacy["alarm_codes"] == []
    assert legacy["alarm_since"] is None
    assert legacy["alarm_reasons"] == ["agreement_rate 0.40 ..."]


def test_trend_serves_null_counts_for_pre_0026_rows(client: TestClient) -> None:
    """Rows written before the counts existed must read back as null, not 0 —
    "we never recorded this" and "nothing agreed" are different facts."""
    _seed(client, [_snap()])
    point = client.get("/api/v1/quality/trend").json()["points"][0]
    assert point["n_yes"] is None
    assert point["n_classified"] is None


def test_trend_requires_auth_when_enabled(settings_kratos: Settings) -> None:
    """With API auth on and no session, the trend is refused (admin-gated like
    the other posture read-models)."""
    secured = settings_kratos.model_copy(update={"api_auth_required": True})
    for client in _client(secured):
        resp = client.get("/api/v1/quality/trend")
        assert resp.status_code in (401, 403)


# ---------------------------------------------------------------------------
# Run-now + status (schedulable from the UI, 2026-07-16)
# ---------------------------------------------------------------------------


def test_quality_eval_run_now_single_flight(client: TestClient) -> None:
    """POST /quality/eval/run starts one background eval; a second POST while
    it runs joins it (no double batch). Status reflects running → done."""
    import asyncio as aio

    release = aio.Event()

    async def _slow_eval(*a: Any, **kw: Any) -> Any:
        from soc_ai.eval.nightly import NightlyRunResult

        await release.wait()
        return NightlyRunResult(exit_code=0, mode="local")

    with patch("soc_ai.api.webui.routes_quality.run_eval_nightly", _slow_eval):
        first = client.post("/api/v1/quality/eval/run").json()
        assert first["running"] is True

        second = client.post("/api/v1/quality/eval/run").json()
        assert second["running"] is True
        assert second.get("note") == "already running"

        status = client.get("/api/v1/quality/eval/status").json()
        assert status["running"] is True

        release.set()
        # bounded wait for the worker to land
        for _ in range(40):
            status = client.get("/api/v1/quality/eval/status").json()
            if not status["running"]:
                break
            import time

            time.sleep(0.05)
        assert status["running"] is False
        assert status["last_exit_code"] == 0
        assert status["last_run"] is not None


def test_quality_eval_run_now_records_failure_detail(client: TestClient) -> None:
    async def _failing_eval(*a: Any, **kw: Any) -> Any:
        from soc_ai.eval.nightly import NightlyRunResult

        return NightlyRunResult(exit_code=2, mode="local", detail="no eligible alerts")

    with patch("soc_ai.api.webui.routes_quality.run_eval_nightly", _failing_eval):
        assert client.post("/api/v1/quality/eval/run").json()["running"] is True
        import time

        for _ in range(40):
            status = client.get("/api/v1/quality/eval/status").json()
            if not status["running"]:
                break
            time.sleep(0.05)
    assert status["last_exit_code"] == 2
    assert "no eligible alerts" in status["last_detail"]

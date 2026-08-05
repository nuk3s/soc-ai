"""Model fitness battery: probe the knob configurations, recommend the winner.

Design: docs/superpowers/specs/2026-08-05-model-battery-design.md. The
recommendation rule is deterministic on purpose — an operator must be able to
read WHY a configuration was recommended, and a re-run on the same numbers must
recommend the same thing.
"""

from __future__ import annotations

import asyncio
from datetime import UTC

from pydantic import SecretStr
from soc_ai.config import Settings


def _settings(**over) -> Settings:
    kwargs = {
        "so_host": "https://so.example.com",
        "so_username": "analyst",
        "so_password": SecretStr("password123"),
        "so_verify_ssl": False,
        "es_hosts": ["https://so.example.com:9200"],
        "litellm_base_url": "http://localhost:4000",
        "api_auth_required": False,
    }
    kwargs.update(over)
    return Settings(**kwargs)


def _cfg(mode: str, required: bool, ok: int, n: int = 2, elapsed: float = 60.0) -> dict:
    """A probe report in the summarize_probe shape."""
    return {
        "model": "m",
        "output_mode": mode,
        "tool_choice_required": required,
        "n": n,
        "ok": ok,
        "usable_rate": ok / n if n else 0.0,
        "tally": {"OK": ok} if ok == n else {"OK": ok, "schema_retry_exhausted": n - ok},
        "failures": [],
        "served_backend": None,
        "elapsed_s": elapsed,
    }


# --------------------------------------------------------------------------
# The recommendation rule
# --------------------------------------------------------------------------


def test_recommends_native_when_it_beats_baseline_on_rate():
    from soc_ai.model_probe import recommend

    rec = recommend(
        [
            _cfg("tool", False, ok=1, elapsed=90.0),
            _cfg("native", False, ok=2, elapsed=20.0),
            _cfg("prompted", False, ok=1, elapsed=70.0),
            _cfg("tool", True, ok=1, elapsed=85.0),
        ]
    )
    assert rec is not None
    assert rec["synthesizer_output_mode"] == "native"
    assert rec["analyst_tool_choice_required"] is False
    assert "native" in rec["reason"]


def test_recommends_on_speed_only_when_25pct_faster_at_equal_rate():
    from soc_ai.model_probe import recommend

    # native equal rate, 4x faster -> recommended
    rec = recommend(
        [_cfg("tool", False, ok=2, elapsed=95.0), _cfg("native", False, ok=2, elapsed=14.0)]
    )
    assert rec is not None and rec["synthesizer_output_mode"] == "native"

    # native equal rate, only 10% faster -> baseline stands
    rec2 = recommend(
        [_cfg("tool", False, ok=2, elapsed=100.0), _cfg("native", False, ok=2, elapsed=90.0)]
    )
    assert rec2 is None


def test_no_recommendation_when_baseline_wins_or_all_fail():
    from soc_ai.model_probe import recommend

    assert (
        recommend(
            [_cfg("tool", False, ok=2, elapsed=30.0), _cfg("native", False, ok=1, elapsed=20.0)]
        )
        is None
    )
    assert (
        recommend(
            [_cfg("tool", False, ok=0, elapsed=30.0), _cfg("native", False, ok=0, elapsed=20.0)]
        )
        is None
    )


def test_prompted_recommended_only_as_sole_survivor():
    from soc_ai.model_probe import recommend

    # prompted ties with native above baseline -> native wins even if prompted faster
    rec = recommend(
        [
            _cfg("tool", False, ok=0, elapsed=60.0),
            _cfg("native", False, ok=2, elapsed=40.0),
            _cfg("prompted", False, ok=2, elapsed=20.0),
        ]
    )
    assert rec is not None and rec["synthesizer_output_mode"] == "native"

    # prompted is the ONLY working configuration -> recommended
    rec2 = recommend(
        [
            _cfg("tool", False, ok=0),
            _cfg("native", False, ok=0),
            _cfg("prompted", False, ok=2, elapsed=50.0),
        ]
    )
    assert rec2 is not None and rec2["synthesizer_output_mode"] == "prompted"


def test_tool_required_recommendation_sets_the_bool_knob():
    from soc_ai.model_probe import recommend

    rec = recommend(
        [_cfg("tool", False, ok=1, elapsed=60.0), _cfg("tool", True, ok=2, elapsed=60.0)]
    )
    assert rec is not None
    assert rec["synthesizer_output_mode"] == "tool"
    assert rec["analyst_tool_choice_required"] is True


def test_recommendation_reason_is_human_readable():
    from soc_ai.model_probe import recommend

    rec = recommend(
        [_cfg("tool", False, ok=2, elapsed=95.1), _cfg("native", False, ok=2, elapsed=13.7)]
    )
    assert rec is not None
    # Names the config, the rate, and the speedup — the operator reads WHY.
    assert "2/2" in rec["reason"]
    assert "x faster" in rec["reason"]


# --------------------------------------------------------------------------
# Battery orchestration
# --------------------------------------------------------------------------


def test_battery_runs_the_four_configs_in_order_with_progress():
    from soc_ai import model_probe

    seen_modes: list[tuple[str, bool]] = []
    progress: list[str] = []

    async def fake_run_once(agent, prompt):
        return ("OK", "false_positive conf=0.8")

    async def go():
        return await model_probe.run_battery(
            _settings(),
            model="candidate-x",
            n=1,
            run_once=fake_run_once,
            on_progress=lambda label, i, total: progress.append(f"{i}/{total}:{label}"),
        )

    result = asyncio.run(go())
    configs = result["configs"]
    seen_modes = [(c["output_mode"], c["tool_choice_required"]) for c in configs]
    assert seen_modes == [("tool", False), ("native", False), ("prompted", False), ("tool", True)]
    assert result["model"] == "candidate-x"
    assert progress[0].startswith("1/4:") and progress[-1].startswith("4/4:")
    # All configs perfect at equal speed -> baseline stands, no recommendation.
    assert result["recommendation"] is None


def test_battery_recommends_from_its_own_results():
    from soc_ai import model_probe

    async def flaky_tool_runner(agent, prompt):
        # Tool-mode agents fail, others succeed: keyed on the agent's output
        # schema class the builder produced.
        schema = type(agent._output_schema).__name__
        if schema == "AutoOutputSchema":
            return ("schema_retry_exhausted", "Exceeded maximum output retries (3)")
        return ("OK", "false_positive conf=0.9")

    result = asyncio.run(
        model_probe.run_battery(_settings(), model="m", n=1, run_once=flaky_tool_runner)
    )
    rec = result["recommendation"]
    assert rec is not None
    assert rec["synthesizer_output_mode"] == "native"


def test_battery_attempt_timeout_lands_as_timeout_outcome():
    from soc_ai import model_probe

    async def hangs(agent, prompt):
        await asyncio.sleep(3600)

    result = asyncio.run(
        model_probe.run_battery(
            _settings(), model="m", n=1, run_once=hangs, per_attempt_timeout_s=0.05
        )
    )
    for c in result["configs"]:
        assert c["tally"].get("timeout") == 1
    assert result["recommendation"] is None


# --------------------------------------------------------------------------
# Persistence: last battery result per model (migration 0022)
# --------------------------------------------------------------------------


def test_battery_result_upserts_and_reads_back(tmp_path):
    from soc_ai.store import model_battery as mb_svc
    from soc_ai.store.db import make_engine, make_sessionmaker, run_migrations

    settings = _settings(db_path=str(tmp_path / "b.db"))

    async def go():
        engine = make_engine(settings)
        await run_migrations(engine)
        maker = make_sessionmaker(engine)
        result = {"model": "m1", "configs": [], "recommendation": None, "elapsed_s": 1.0}
        async with maker() as db:
            await mb_svc.upsert(db, model="m1", result=result)
            first = await mb_svc.get(db, model="m1")
        # Upsert replaces: one row per model, newest wins.
        result2 = {**result, "elapsed_s": 2.0}
        async with maker() as db:
            await mb_svc.upsert(db, model="m1", result=result2)
            second = await mb_svc.get(db, model="m1")
            missing = await mb_svc.get(db, model="never-probed")
        await engine.dispose()
        return first, second, missing

    first, second, missing = asyncio.run(go())
    assert first is not None and first["result"]["elapsed_s"] == 1.0
    assert second["result"]["elapsed_s"] == 2.0
    assert "created_at" in second
    assert missing is None


# --------------------------------------------------------------------------
# API: start / poll / persist / 409 / audit
# --------------------------------------------------------------------------


def _client(settings):
    from unittest.mock import AsyncMock, patch

    from fastapi.testclient import TestClient
    from soc_ai.main import create_app

    fake_es = AsyncMock()
    fake_auth = AsyncMock()
    return (
        patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=fake_es),
        patch("soc_ai.main.make_auth", return_value=fake_auth),
        patch("soc_ai.main.get_settings", return_value=settings),
        TestClient,
        create_app,
    )


def _fake_battery_result(model="probe-me", rec=None):
    return {
        "model": model,
        "n_per_config": 2,
        "configs": [_cfg("tool", False, ok=2), _cfg("native", False, ok=2, elapsed=10.0)],
        "recommendation": rec,
        "elapsed_s": 12.0,
    }


def test_battery_api_start_poll_persist(tmp_path):
    """POST starts the battery in the background; GET polls it to completion;
    the finished result persists and is served on later GETs."""
    import time as _time
    from unittest.mock import patch

    settings = _settings(db_path=str(tmp_path / "api.db"))
    p1, p2, p3, TestClient, create_app = _client(settings)

    async def fake_run_battery(s, *, model=None, n=2, on_progress=None, **kw):
        if on_progress:
            on_progress("tool", 1, 4)
        return _fake_battery_result(model or s.analyst_model)

    with p1, p2, p3, patch("soc_ai.model_probe.run_battery", fake_run_battery):
        app = create_app()
        with TestClient(app) as client:
            r = client.post("/api/v1/config/model-battery", json={"model": "probe-me"})
            assert r.status_code == 202

            deadline = _time.monotonic() + 10
            data = None
            while _time.monotonic() < deadline:
                data = client.get("/api/v1/config/model-battery?model=probe-me").json()
                if not data["running"] and data.get("result"):
                    break
                _time.sleep(0.05)
            assert data is not None and data["result"]["model"] == "probe-me"
            assert data["stored_at"] is not None  # persisted, with a timestamp


def test_battery_api_rejects_concurrent_runs(tmp_path):
    from unittest.mock import patch

    settings = _settings(db_path=str(tmp_path / "conc.db"))
    p1, p2, p3, TestClient, create_app = _client(settings)
    release = asyncio.Event()

    async def slow_battery(s, *, model=None, **kw):
        await release.wait()  # hold the battery "running"
        return _fake_battery_result(model)

    with p1, p2, p3, patch("soc_ai.model_probe.run_battery", slow_battery):
        app = create_app()
        with TestClient(app) as client:
            assert (
                client.post("/api/v1/config/model-battery", json={"model": "a"}).status_code == 202
            )
            # Second start while the first runs -> 409, single-flight.
            assert (
                client.post("/api/v1/config/model-battery", json={"model": "b"}).status_code == 409
            )
            release.set()


def test_battery_api_serves_stored_result_when_idle(tmp_path):
    """No live run: GET returns the persisted last result for the model."""
    settings = _settings(db_path=str(tmp_path / "stored.db"))
    p1, p2, p3, TestClient, create_app = _client(settings)

    with p1, p2, p3:
        app = create_app()
        with TestClient(app) as client:
            from soc_ai.store import model_battery as mb_svc

            async def seed():
                async with app.state.db_sessionmaker() as db:
                    await mb_svc.upsert(db, model="seeded", result=_fake_battery_result("seeded"))

            asyncio.run(seed())
            data = client.get("/api/v1/config/model-battery?model=seeded").json()
            assert data["running"] is False
            assert data["result"]["model"] == "seeded"
            assert data["stored_at"] is not None

            none_data = client.get("/api/v1/config/model-battery?model=never").json()
            assert none_data["running"] is False
            assert none_data["result"] is None


# --------------------------------------------------------------------------
# Fitness cache (dogfood 2026-08-05: "Checking fitness…" on every page load)
# --------------------------------------------------------------------------


def test_fitness_result_stores_and_reads_back(tmp_path):
    from soc_ai.store import model_battery as mb_svc
    from soc_ai.store.db import make_engine, make_sessionmaker, run_migrations

    settings = _settings(db_path=str(tmp_path / "f.db"))

    async def go():
        engine = make_engine(settings)
        await run_migrations(engine)
        maker = make_sessionmaker(engine)
        fitness = {"grade": "pass", "model": "m1", "legs": [], "detail": "ok"}
        async with maker() as db:
            assert await mb_svc.get_fitness(db, model="m1") is None
            await mb_svc.upsert_fitness(db, model="m1", result=fitness)
            first = await mb_svc.get_fitness(db, model="m1")
            # A later battery upsert must not clobber the fitness columns.
            await mb_svc.upsert(db, model="m1", result={"configs": []})
            second = await mb_svc.get_fitness(db, model="m1")
        await engine.dispose()
        return first, second

    first, second = asyncio.run(go())
    assert first is not None and first["result"]["grade"] == "pass"
    assert "checked_at" in first
    assert second is not None and second["result"]["grade"] == "pass"


def test_fitness_api_serves_cache_within_ttl(tmp_path):
    """Page loads must NOT re-probe: within the TTL the route answers from the
    stored result (cached=true + its timestamp) without touching the gateway."""
    from unittest.mock import patch

    settings = _settings(db_path=str(tmp_path / "ttl.db"))
    p1, p2, p3, TestClient, create_app = _client(settings)
    calls = []

    async def fake_probe(s):
        calls.append(1)
        return {"grade": "pass", "model": s.analyst_model, "legs": [], "detail": "ok"}

    with p1, p2, p3, patch("soc_ai.webui.probes.probe_model_fitness", fake_probe):
        app = create_app()
        with TestClient(app) as client:
            first = client.get("/api/v1/config/model-fitness").json()
            assert first["grade"] == "pass"
            assert first["cached"] is False
            assert len(calls) == 1

            second = client.get("/api/v1/config/model-fitness").json()
            assert second["grade"] == "pass"
            assert second["cached"] is True
            assert second["checked_at"]
            assert len(calls) == 1  # no second probe


def test_fitness_api_force_bypasses_cache(tmp_path):
    from unittest.mock import patch

    settings = _settings(db_path=str(tmp_path / "force.db"))
    p1, p2, p3, TestClient, create_app = _client(settings)
    calls = []

    async def fake_probe(s):
        calls.append(1)
        return {"grade": "pass", "model": s.analyst_model, "legs": [], "detail": "ok"}

    with p1, p2, p3, patch("soc_ai.webui.probes.probe_model_fitness", fake_probe):
        app = create_app()
        with TestClient(app) as client:
            client.get("/api/v1/config/model-fitness")
            forced = client.get("/api/v1/config/model-fitness?force=true").json()
            assert forced["cached"] is False
            assert len(calls) == 2


def test_fitness_api_stale_cache_reprobes(tmp_path):
    """Past the TTL the cache is stale and the route probes again."""
    from datetime import datetime, timedelta
    from unittest.mock import patch

    from soc_ai.store.models import ModelBatteryResult
    from sqlalchemy import update

    settings = _settings(db_path=str(tmp_path / "stale.db"))
    p1, p2, p3, TestClient, create_app = _client(settings)
    calls = []

    async def fake_probe(s):
        calls.append(1)
        return {"grade": "pass", "model": s.analyst_model, "legs": [], "detail": "ok"}

    with p1, p2, p3, patch("soc_ai.webui.probes.probe_model_fitness", fake_probe):
        app = create_app()
        with TestClient(app) as client:
            client.get("/api/v1/config/model-fitness")

            async def backdate():
                stale = datetime.now(UTC).replace(tzinfo=None) - timedelta(hours=25)
                async with app.state.db_sessionmaker() as db:
                    await db.execute(update(ModelBatteryResult).values(fitness_at=stale))
                    await db.commit()

            asyncio.run(backdate())
            again = client.get("/api/v1/config/model-fitness").json()
            assert again["cached"] is False
            assert len(calls) == 2

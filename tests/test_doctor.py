"""Tests for the ``soc-ai doctor`` dependency-surface checks.

Everything network-shaped is a test double: the gateway listing + fitness probe
are AsyncMock-patched at the doctor module's namespace (they are imported into
it), the ES/SO clients are stub classes patched over ``doctor.ElasticClient`` /
``doctor.make_auth`` — following the idiom of ``test_model_fitness.py`` (patch
where the callee looks the name up). The store checks run against a REAL
tmp-path SQLite so the migration-head derivation is exercised for real.
"""

from __future__ import annotations

import json
import os
import time
from argparse import Namespace
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from elasticsearch import AuthenticationException
from pydantic import SecretStr
from soc_ai import doctor
from soc_ai.cli import _doctor
from soc_ai.config import Settings
from soc_ai.doctor import CheckResult, exit_code, run_doctor
from soc_ai.errors import SoAuthError
from soc_ai.so_client.elastic import EsSearchResult
from soc_ai.store.db import make_engine, run_migrations
from sqlalchemy import text

# ── helpers / doubles ─────────────────────────────────────────────────────────


def _settings(tmp_path: Path, **overrides: Any) -> Settings:
    """Settings with all doctor-relevant paths pinned under tmp_path.

    Every field the doctor reads is passed explicitly so a developer's local
    ``.env`` (pydantic-settings reads it for any *unspecified* field) can't
    leak into assertions.
    """
    kwargs: dict[str, Any] = {
        "so_host": "https://so.example.com",
        "so_username": "analyst",
        "so_password": SecretStr("password123"),
        "so_verify_ssl": False,
        "es_hosts": ["https://so.example.com:9200"],
        "litellm_base_url": "http://localhost:4000",
        "api_auth_required": False,
        "soc_ai_data_dir": tmp_path / "data",
        "blocklist_data_dir": tmp_path / "blocklists",
        "blocklist_sources": ["urlhaus", "threatfox", "feodo", "tor", "internal_seed"],
        "rag_embed_model": "",
        "rag_rerank_model": "",
    }
    kwargs.update(overrides)
    return Settings(**kwargs)


def _by_name(results: list[CheckResult], name: str) -> CheckResult:
    matches = [r for r in results if r.name == name]
    assert matches, f"no result named {name!r} in {[r.name for r in results]}"
    return matches[0]


class _StubElastic:
    """ElasticClient double: scripted ping/search outcomes."""

    def __init__(
        self,
        *,
        ping_exc: Exception | None = None,
        search_exc: Exception | None = None,
        total: int = 42,
    ) -> None:
        self._ping_exc = ping_exc
        self._search_exc = search_exc
        self._total = total
        self.closed = False

    async def ping(self) -> dict[str, Any]:
        if self._ping_exc is not None:
            raise self._ping_exc
        return {"cluster": "so-grid", "version": "8.14.3"}

    async def search(self, index: str, query: dict[str, Any], **kwargs: Any) -> EsSearchResult:
        if self._search_exc is not None:
            raise self._search_exc
        return EsSearchResult(total=self._total, took_ms=1)

    async def aclose(self) -> None:
        self.closed = True


class _StubAuth:
    """SoAuthClient double: scripted /api/info outcome."""

    def __init__(self, *, exc: Exception | None = None, status: int = 200) -> None:
        self._exc = exc
        self._status = status
        self.closed = False

    async def request(self, method: str, url: str, **kwargs: Any) -> Any:
        if self._exc is not None:
            raise self._exc
        return SimpleNamespace(status_code=self._status)

    async def aclose(self) -> None:
        self.closed = True


def _fitness(grade: str, detail: str = "graded") -> dict[str, Any]:
    return {"grade": grade, "model": "m", "legs": [], "detail": detail}


def _touch_fresh_feeds(settings: Settings) -> None:
    settings.blocklist_data_dir.mkdir(parents=True, exist_ok=True)
    for fname in ("urlhaus.csv", "threatfox.json", "feodo.csv", "tor_exits.txt"):
        (settings.blocklist_data_dir / fname).write_text("x")


async def _migrate(settings: Settings) -> None:
    engine = make_engine(settings)
    try:
        await run_migrations(engine)
    finally:
        await engine.dispose()


# ── exit-code contract ────────────────────────────────────────────────────────


def test_exit_code_fail_wins() -> None:
    ok = [CheckResult("a", "PASS", "x"), CheckResult("b", "INFO", "x")]
    warn_only = [*ok, CheckResult("c", "WARN", "x")]
    failing = [*warn_only, CheckResult("d", "FAIL", "x")]
    assert exit_code(ok) == 0
    assert exit_code(warn_only) == 0  # warnings never fail the doctor
    assert exit_code(failing) == 1


# ── check 1: config ───────────────────────────────────────────────────────────


def test_check_config_names_offending_fields(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # No .env in cwd + required env vars absent → validation error naming fields.
    monkeypatch.chdir(tmp_path)
    for var in ("SO_HOST", "SO_USERNAME", "SO_PASSWORD", "ES_HOSTS", "LITELLM_BASE_URL"):
        monkeypatch.delenv(var, raising=False)
    settings, result = doctor.check_config()
    assert settings is None
    assert result.status == "FAIL"
    assert "so_host" in result.detail
    assert ".env" in result.hint


async def test_run_doctor_config_fail_skips_dependent_checks() -> None:
    broken = (None, CheckResult("config", "FAIL", "boom", hint="fix .env"))
    with patch("soc_ai.doctor.check_config", return_value=broken):
        results = await run_doctor()
    assert [r.status for r in results] == ["FAIL", "INFO"]
    assert "skipped" in results[1].detail
    assert exit_code(results) == 1


# ── check 2: store ────────────────────────────────────────────────────────────


async def test_check_store_fresh_db_passes(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    results = await doctor.check_store(settings)
    store = _by_name(results, "store")
    assert store.status == "PASS"
    assert "fresh" in store.detail


async def test_check_store_at_head_passes(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    await _migrate(settings)
    results = await doctor.check_store(settings)
    store = _by_name(results, "store")
    assert store.status == "PASS"
    assert "migration head" in store.detail


async def test_check_store_head_mismatch_fails(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    await _migrate(settings)
    engine = make_engine(settings)
    try:
        async with engine.begin() as conn:
            await conn.execute(text("UPDATE alembic_version SET version_num = '0001'"))
    finally:
        await engine.dispose()
    results = await doctor.check_store(settings)
    store = _by_name(results, "store")
    assert store.status == "FAIL"
    assert "0001" in store.detail
    assert "mismatch" in store.detail
    assert "serve" in store.hint  # actionable: restart migrates to head


async def test_check_store_reports_fts5(tmp_path: Path) -> None:
    # CPython's bundled SQLite ships FTS5 — the check must land INFO, not WARN.
    results = await doctor.check_store(_settings(tmp_path))
    fts = _by_name(results, "store fts5")
    assert fts.status == "INFO"
    assert "FTS5" in fts.detail


# ── check 3: SO API + Elasticsearch ──────────────────────────────────────────


async def test_check_so_api_pass(tmp_path: Path) -> None:
    stub = _StubAuth(status=200)
    with patch("soc_ai.doctor.make_auth", return_value=stub):
        results = await doctor.check_so_api(_settings(tmp_path))
    assert _by_name(results, "security onion").status == "PASS"
    assert stub.closed


async def test_check_so_api_bad_credentials(tmp_path: Path) -> None:
    stub = _StubAuth(exc=SoAuthError("Kratos rejected credentials (HTTP 400)"))
    with patch("soc_ai.doctor.make_auth", return_value=stub):
        results = await doctor.check_so_api(_settings(tmp_path))
    so = _by_name(results, "security onion")
    assert so.status == "FAIL"
    assert "SO_USERNAME" in so.hint


async def test_check_so_api_unreachable(tmp_path: Path) -> None:
    stub = _StubAuth(exc=SoAuthError("Kratos login flow init failed: connect timeout"))
    with patch("soc_ai.doctor.make_auth", return_value=stub):
        results = await doctor.check_so_api(_settings(tmp_path))
    so = _by_name(results, "security onion")
    assert so.status == "FAIL"
    assert "unreachable" in so.detail
    assert "SO_HOST" in so.hint


async def test_check_elasticsearch_pass(tmp_path: Path) -> None:
    stub = _StubElastic(total=42)
    with patch("soc_ai.doctor.ElasticClient", return_value=stub):
        results = await doctor.check_elasticsearch(_settings(tmp_path))
    es = _by_name(results, "elasticsearch")
    assert es.status == "PASS"
    assert "so-grid" in es.detail
    assert stub.closed


async def test_check_elasticsearch_auth_fail(tmp_path: Path) -> None:
    exc = AuthenticationException("security_exception: unable to authenticate", None, None)
    stub = _StubElastic(ping_exc=exc)
    with patch("soc_ai.doctor.ElasticClient", return_value=stub):
        results = await doctor.check_elasticsearch(_settings(tmp_path))
    es = _by_name(results, "elasticsearch")
    assert es.status == "FAIL"
    assert "authentication failed" in es.detail
    assert "ES_USERNAME" in es.hint


async def test_check_elasticsearch_unreachable(tmp_path: Path) -> None:
    stub = _StubElastic(ping_exc=ConnectionError("connection refused"))
    with patch("soc_ai.doctor.ElasticClient", return_value=stub):
        results = await doctor.check_elasticsearch(_settings(tmp_path))
    es = _by_name(results, "elasticsearch")
    assert es.status == "FAIL"
    assert "unreachable" in es.detail
    assert "ES_HOSTS" in es.hint


async def test_check_elasticsearch_zero_match_pattern_warns(tmp_path: Path) -> None:
    stub = _StubElastic(total=0)
    with patch("soc_ai.doctor.ElasticClient", return_value=stub):
        results = await doctor.check_elasticsearch(_settings(tmp_path))
    es = _by_name(results, "elasticsearch")
    assert es.status == "WARN"  # a WARN, not a FAIL — auth worked, pattern is off
    assert "matched no documents" in es.detail
    assert "EVENTS_INDEX_PATTERN" in es.hint


# ── check 4: gateway ─────────────────────────────────────────────────────────


async def test_check_gateway_down_fails(tmp_path: Path) -> None:
    listing = AsyncMock(return_value=([], "ConnectError: All connection attempts failed"))
    with patch("soc_ai.doctor.list_gateway_models", listing):
        results = await doctor.check_gateway(_settings(tmp_path))
    gw = _by_name(results, "gateway")
    assert gw.status == "FAIL"
    assert "LITELLM_BASE_URL" in gw.hint


async def test_check_gateway_analyst_model_missing_warns(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    listing = AsyncMock(return_value=(["some-other-model"], None))
    with patch("soc_ai.doctor.list_gateway_models", listing):
        results = await doctor.check_gateway(settings)
    assert _by_name(results, "gateway").status == "PASS"
    analyst = _by_name(results, "analyst model")
    assert analyst.status == "WARN"  # may still resolve via a gateway alias
    assert "alias" in analyst.hint


async def test_check_gateway_rag_models(tmp_path: Path) -> None:
    settings = _settings(tmp_path, rag_embed_model="embed-x", rag_rerank_model="rerank-y")
    listing = AsyncMock(return_value=([settings.analyst_model, "embed-x"], None))
    with patch("soc_ai.doctor.list_gateway_models", listing):
        results = await doctor.check_gateway(settings)
    assert _by_name(results, "rag embed model").status == "PASS"
    rerank = _by_name(results, "rag rerank model")
    assert rerank.status == "WARN"
    assert "fail-soft" in rerank.hint


async def test_check_gateway_unset_rag_models_skipped(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    listing = AsyncMock(return_value=([settings.analyst_model], None))
    with patch("soc_ai.doctor.list_gateway_models", listing):
        results = await doctor.check_gateway(settings)
    names = [r.name for r in results]
    assert "rag embed model" not in names
    assert "rag rerank model" not in names


# ── check 5: model fitness ───────────────────────────────────────────────────


async def test_check_model_fitness_unfit_is_fail(tmp_path: Path) -> None:
    probe = AsyncMock(return_value=_fitness("fail", "m: structured_output=fail"))
    with patch("soc_ai.doctor.probe_model_fitness", probe):
        results = await doctor.check_model_fitness(_settings(tmp_path))
    fit = _by_name(results, "model fitness")
    assert fit.status == "FAIL"  # the silent all-fallback-verdicts trap
    assert "all-fallback" in fit.hint


async def test_check_model_fitness_degraded_is_warn(tmp_path: Path) -> None:
    probe = AsyncMock(return_value=_fitness("degraded", "m: reasoning_budget=degraded"))
    with patch("soc_ai.doctor.probe_model_fitness", probe):
        results = await doctor.check_model_fitness(_settings(tmp_path))
    assert _by_name(results, "model fitness").status == "WARN"


# ── check 6: egress posture (INFO only, never pass/fail) ─────────────────────


def test_check_egress_posture_is_info_only(tmp_path: Path) -> None:
    settings = _settings(
        tmp_path,
        oracle_enabled=True,  # even an enabled egress is INFO, never WARN/FAIL
        notify_enabled=False,
        analyst_cloud_redaction=False,
    )
    results = doctor.check_egress_posture(settings)
    assert results, "expected egress posture lines"
    assert all(r.status == "INFO" for r in results)
    names = {r.name for r in results}
    assert {"egress", "egress: oracle", "egress: analyst_cloud"} <= names
    oracle = _by_name(results, "egress: oracle")
    assert oracle.detail.startswith("ON")


# ── check 7: blocklist freshness ─────────────────────────────────────────────


def test_check_blocklists_fresh_passes(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    _touch_fresh_feeds(settings)
    results = doctor.check_blocklists(settings)
    assert _by_name(results, "blocklists").status == "PASS"


def test_check_blocklists_missing_and_stale_warn(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    settings.blocklist_data_dir.mkdir(parents=True, exist_ok=True)
    stale = settings.blocklist_data_dir / "urlhaus.csv"
    stale.write_text("x")
    thirty_days_ago = time.time() - 30 * 86400
    os.utime(stale, (thirty_days_ago, thirty_days_ago))
    results = doctor.check_blocklists(settings)
    bl = _by_name(results, "blocklists")
    assert bl.status == "WARN"  # never FAIL — triage is fail-open on stale feeds
    assert "stale" in bl.detail
    assert "urlhaus" in bl.detail
    assert "never refreshed" in bl.detail  # the other feeds have no file at all
    assert "blocklists refresh" in bl.hint


# ── run_doctor end to end (all mocked upstreams) ─────────────────────────────


async def test_run_doctor_all_green(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    await _migrate(settings)
    _touch_fresh_feeds(settings)
    listing = AsyncMock(return_value=([settings.analyst_model], None))
    probe = AsyncMock(return_value=_fitness("pass", "model passed all fitness checks"))
    with (
        patch("soc_ai.doctor.make_auth", return_value=_StubAuth()),
        patch("soc_ai.doctor.ElasticClient", return_value=_StubElastic()),
        patch("soc_ai.doctor.list_gateway_models", listing),
        patch("soc_ai.doctor.probe_model_fitness", probe),
    ):
        results = await run_doctor(settings)
    bad = [r for r in results if r.status in ("FAIL", "WARN")]
    assert not bad, f"expected all-green, got {[(r.name, r.status, r.detail) for r in bad]}"
    names = {r.name for r in results}
    assert {
        "config",
        "store",
        "store fts5",
        "security onion",
        "elasticsearch",
        "gateway",
        "analyst model",
        "model fitness",
        "egress",
        "blocklists",
    } <= names
    assert exit_code(results) == 0


async def test_run_doctor_isolation_one_failure_never_blocks_others(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    await _migrate(settings)
    _touch_fresh_feeds(settings)
    # Gateway is DOWN and ES auth is broken — the store/SO checks still run.
    listing = AsyncMock(return_value=([], "ConnectError: connection refused"))
    probe = AsyncMock(return_value=_fitness("fail", "gateway down"))
    es_exc = AuthenticationException("unable to authenticate", None, None)
    with (
        patch("soc_ai.doctor.make_auth", return_value=_StubAuth()),
        patch("soc_ai.doctor.ElasticClient", return_value=_StubElastic(ping_exc=es_exc)),
        patch("soc_ai.doctor.list_gateway_models", listing),
        patch("soc_ai.doctor.probe_model_fitness", probe),
    ):
        results = await run_doctor(settings)
    assert _by_name(results, "gateway").status == "FAIL"
    assert _by_name(results, "elasticsearch").status == "FAIL"
    assert _by_name(results, "model fitness").status == "FAIL"
    # ...while unrelated checks still landed their own verdicts.
    assert _by_name(results, "store").status == "PASS"
    assert _by_name(results, "security onion").status == "PASS"
    assert _by_name(results, "blocklists").status == "PASS"
    assert exit_code(results) == 1


# ── CLI subcommand: --json shape + table + exit codes ────────────────────────


def _fixed_results() -> list[CheckResult]:
    return [
        CheckResult("config", "PASS", "settings loaded"),
        CheckResult("gateway", "FAIL", "cannot list models", hint="check LITELLM_BASE_URL"),
        CheckResult("egress", "INFO", "zero egress: yes"),
    ]


def test_cli_doctor_json_shape(capsys: pytest.CaptureFixture[str]) -> None:
    run = AsyncMock(return_value=_fixed_results())
    with patch("soc_ai.doctor.run_doctor", run):
        rc = _doctor(Namespace(json=True))
    assert rc == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["ok"] is False
    assert [r["name"] for r in payload["results"]] == ["config", "gateway", "egress"]
    assert set(payload["results"][0]) == {"name", "status", "detail", "hint"}
    assert payload["results"][1]["status"] == "FAIL"
    assert payload["results"][1]["hint"] == "check LITELLM_BASE_URL"


def test_cli_doctor_table_output_and_exit_code(capsys: pytest.CaptureFixture[str]) -> None:
    run = AsyncMock(return_value=_fixed_results())
    with patch("soc_ai.doctor.run_doctor", run):
        rc = _doctor(Namespace(json=False))
    out = capsys.readouterr().out
    assert rc == 1
    assert "PASS" in out
    assert "FAIL" in out
    assert "fix: check LITELLM_BASE_URL" in out  # hint rendered on its own line
    assert "1 passed, 0 warning(s), 1 failure(s)" in out


def test_cli_doctor_warn_only_exits_zero(capsys: pytest.CaptureFixture[str]) -> None:
    results = [
        CheckResult("config", "PASS", "settings loaded"),
        CheckResult("analyst model", "WARN", "not listed", hint="maybe an alias"),
    ]
    run = AsyncMock(return_value=results)
    with patch("soc_ai.doctor.run_doctor", run):
        rc = _doctor(Namespace(json=False))
    assert rc == 0
    assert "1 warning(s)" in capsys.readouterr().out

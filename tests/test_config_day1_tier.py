"""Day-1 config tier: at most ten visible decisions, everything else behind Advanced.

The bound is the product promise from the Wave-2 spec ("At most ten items,
matching the snapshot-tested bound") — this file IS that snapshot test.
"""

from __future__ import annotations

from collections.abc import Iterator
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient
from soc_ai.config import Settings
from soc_ai.main import create_app
from soc_ai.store import config_overrides as cfg

# The four auto-triage keys are the ones setup.sh already asks about at install
# time ("every 5 min, ≤25 targets/sweep, high-severity+"); three more are the
# connection-shaped decisions (which model, which index pattern, which alerts
# filter) that make the console show anything at all; the eighth,
# notify_enabled, is the outbound-webhook master toggle (final-review I6) —
# hot, non-danger, non-secret, so it passes the invariant test below, and the
# one opt-in egress decision worth a day-one look rather than a trip behind
# Advanced.
DAY1_EXPECTED = {
    "analyst_model",
    "events_index_pattern",
    "webui_alerts_query",
    "auto_triage_schedule_enabled",
    "auto_triage_schedule_interval_minutes",
    "auto_triage_max_targets",
    "auto_triage_min_severity",
    "notify_enabled",
}


def test_day1_set_is_exactly_the_curated_eight() -> None:
    """Pins the curation: adding a day1 flag elsewhere must be a deliberate,
    test-updating act, not a drive-by."""
    day1 = {s.key for s in cfg.WHITELIST if s.day1}
    assert day1 == DAY1_EXPECTED


def test_day1_never_exceeds_ten() -> None:
    """The spec's hard bound — the wall must not silently regrow."""
    assert sum(1 for s in cfg.WHITELIST if s.day1) <= 10


def test_day1_specs_are_hot_and_never_danger_or_secret() -> None:
    """Danger/secret specs render through dedicated panels, not the tiered view.
    And day1 items must be hot-applied — a day-1 setting that needs a restart
    is a bad day-1 experience."""
    for s in cfg.WHITELIST:
        if s.day1:
            assert not s.danger and not s.secret, s.key
            assert s.hot, s.key


# Module-local `_client`/`client` fixture: same shape as tests/test_webui_api.py
# (plain client, settings_kratos, api_auth_required unset so require_admin_api
# no-ops) — that file defines it module-local rather than sharing it via
# conftest, so this replicates the same pattern here.
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


def test_config_api_serializes_day1(client: TestClient) -> None:
    """The FE tier split depends on the flag reaching SettingOut."""
    resp = client.get("/api/v1/config")
    assert resp.status_code == 200
    items = [i for g in resp.json()["groups"] for i in g["items"]]
    flags = {i["key"]: i["day1"] for i in items}
    assert flags["analyst_model"] is True
    assert flags["oracle_enabled"] is False

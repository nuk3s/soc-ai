"""Severity, MITRE, hosts and actions say what the narrative says (dogfood 2026-10-06 C5).

The lead 16 hunt confirmed root command execution and its finding read MEDIUM
with a note that held an em dash. The lead 6 hunt found no DCSync and showed
T1003.006. A hunt that found no traffic showed "Affected hosts 2". The actions
listed steps the analyst cannot take from the console.
"""

from __future__ import annotations

import asyncio
from collections.abc import Iterator
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient
from soc_ai.config import Settings
from soc_ai.hunting.hunt_words import ALERT_ONLY_NOTE, is_operator_step, validator_note
from soc_ai.main import create_app
from soc_ai.store import hunts as hunt_svc

_LEGACY_DASH = (
    "Only detector alerts cited — corroborate before asserting compromise; "
    "severity capped to medium."
)
_LEGACY_GATE = (
    "This finding cites only detector alerts, so soc-ai lowered the severity to medium. "
    "Corroborate it before you claim a compromise."
)


def test_the_alert_only_note_reads_in_three_sentences() -> None:
    assert ALERT_ONLY_NOTE == (
        "Severity held at medium. The finding cites alerts only. An investigation can raise it."
    )
    assert validator_note(_LEGACY_DASH) == ALERT_ONLY_NOTE
    assert validator_note(_LEGACY_GATE) == ALERT_ONLY_NOTE
    # Negative controls: another note stays as stored, and no note is no note.
    other = "The citations did not resolve to gathered evidence, so soc-ai lowered the severity."
    assert validator_note(other) == other
    assert validator_note(None) is None
    assert "—" not in ALERT_ONLY_NOTE


def test_a_step_that_needs_the_grid_is_an_operator_step() -> None:
    assert is_operator_step("Re-extend the events window beyond 30 days")
    assert is_operator_step("Review imported or replayed corpora")
    assert is_operator_step("Enable DCE-RPC logging on the domain controllers")
    # Negative controls: the analyst takes these from the console or the desk.
    assert not is_operator_step("Promote finding F2 to an investigation")
    assert not is_operator_step("Isolate 10.99.0.30 from the network")
    assert not is_operator_step("Review the lead 16 observations")


@pytest.fixture
def client(settings_kratos: Settings) -> Iterator[TestClient]:
    with (
        patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=AsyncMock()),
        patch("soc_ai.main.make_auth", return_value=AsyncMock()),
        patch("soc_ai.main.get_settings", return_value=settings_kratos),
    ):
        app = create_app()
        with TestClient(app) as c:
            yield c


def _seed(client: TestClient, report: dict[str, Any]) -> str:
    async def go() -> str:
        async with client.app.state.db_sessionmaker() as db:
            hunt = await hunt_svc.create(db, objective="hunt for dcsync", started_by="t")
            await hunt_svc.finalize(db, hunt.id, status="complete", narrative="n", report=report)
            return hunt.id

    return asyncio.run(go())


_ACTIONS = [
    {"title": "Promote finding F1 to an investigation", "rationale": "r1"},
    {"title": "Re-extend the events window beyond 30 days", "rationale": "r2"},
]


def test_a_hunt_with_no_threat_names_no_technique(client: TestClient) -> None:
    hunt_id = _seed(
        client,
        {
            "findings": [{"title": "attribute writes", "category": "observation"}],
            "mitre_techniques": ["T1003.006"],
            "affected_hosts": ["10.1.10.11"],
            "recommended_actions": _ACTIONS,
        },
    )
    body = client.get(f"/api/v1/hunts/{hunt_id}").json()
    assert body["outcome"] == "no_threat"
    assert body["mitreTechniques"] == []
    assert [a["title"] for a in body["recommendedActions"]] == [
        "Promote finding F1 to an investigation"
    ]
    assert [a["title"] for a in body["operatorActions"]] == [
        "Re-extend the events window beyond 30 days"
    ]


def test_a_threat_keeps_the_techniques_its_findings_name(client: TestClient) -> None:
    # Negative control: a threat finding supports its technique.
    hunt_id = _seed(
        client,
        {
            "findings": [
                {
                    "title": "replication request",
                    "category": "threat",
                    "validator_note": _LEGACY_DASH,
                    "mitre_techniques": ["T1003.006"],
                },
                {"title": "No telemetry for x", "category": "visibility_gap"},
            ],
            "mitre_techniques": ["T1003.006", "T1059"],
        },
    )
    body = client.get(f"/api/v1/hunts/{hunt_id}").json()
    assert body["outcome"] == "threat_found"
    assert body["mitreTechniques"] == ["T1003.006"]
    assert body["findings"][0]["validatorNote"] == ALERT_ONLY_NOTE

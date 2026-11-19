"""A machine name that the record of a finding does not support (dogfood 2026-11-17, AA2).

Two finding rows of campaign 2 read "against blue" for an address that holds
no name. The Hosts data gives that name to another machine. A finding whose
text names a known machine that is no host of the finding gets a note. The
model text stays.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Iterator
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient
from soc_ai.agent.hunt import HuntFinding
from soc_ai.agent.hunt_gates import _UNRESOLVED_NOTE
from soc_ai.api import hunt_runner
from soc_ai.api.webui import routes_campaigns
from soc_ai.campaigns import finding_names
from soc_ai.config import Settings
from soc_ai.hunting import hunt_words
from soc_ai.main import create_app
from soc_ai.store import hunts as hunt_svc
from soc_ai.store import investigations as inv_svc
from soc_ai.store.db import make_engine, make_sessionmaker, run_migrations
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from tests.test_campaign_facts import ACTOR, TARGET, TARGET_2, seed_hosts

NAMES = {"web-1": frozenset({"ip:t1"}), "web-2": frozenset({"ip:t2"})}
NOTE = "The text names web-2. The hosts of this finding do not include web-2."


# ── The rule ────────────────────────────────────────────────────────────────


def test_a_text_that_names_another_machine_gets_the_note() -> None:
    names = finding_names.foreign_names(
        ["PHP exploit probes against web-2"], [TARGET], NAMES, {"ip:t1"}
    )
    assert names == ["web-2"]
    assert finding_names.note_of(names) == NOTE


def test_the_name_of_a_host_of_the_finding_gets_no_note() -> None:
    """NEGATIVE CONTROL. The machine of the finding address carries the name."""
    assert finding_names.foreign_names(["probes against web-1"], [TARGET], NAMES, {"ip:t1"}) == []


def test_a_name_that_the_finding_lists_as_a_host_gets_no_note() -> None:
    assert finding_names.foreign_names(["probes against web-2"], ["WEB-2"], NAMES, set()) == []


def test_a_short_name_inside_a_longer_word_is_no_mention() -> None:
    """NEGATIVE CONTROL. web-1 in web-10 and in web-1x names no machine."""
    texts = ["probes against web-10 and web-1x and web-1-blue"]
    assert finding_names.foreign_names(texts, [TARGET_2], NAMES, {"ip:t2"}) == []


def test_no_hosts_data_names_nothing() -> None:
    """Nothing shows what a name is, so the check claims nothing."""
    assert finding_names.foreign_names(["against web-2"], [TARGET], None, set()) == []


def test_the_hunt_page_keeps_the_name_note_behind_a_reworded_gate_note() -> None:
    """The rewording of a gate note replaced the whole field and lost the note."""
    shown = hunt_words.validator_note(f"{_UNRESOLVED_NOTE} {NOTE}")
    assert shown is not None
    assert shown.endswith(NOTE)
    assert "lowered the severity to low" in shown
    assert hunt_words.validator_note(NOTE) == NOTE


# ── The store ───────────────────────────────────────────────────────────────


@pytest.fixture
async def maker(settings_kratos: Settings) -> AsyncIterator[async_sessionmaker[AsyncSession]]:
    engine = make_engine(settings_kratos)
    await run_migrations(engine)
    try:
        yield make_sessionmaker(engine)
    finally:
        await engine.dispose()


def _finding(title: str, hosts: list[str], note: str | None = None) -> HuntFinding:
    return HuntFinding(
        title=title,
        detail="The source sent exploit requests.",
        severity="high",
        category="threat",
        hosts=hosts,
        citations=[],
        validator_note=note,
    )


async def test_the_hunt_gate_notes_the_finding_and_keeps_the_model_text(maker: Any) -> None:
    async with maker() as db:
        await seed_hosts(db)
    findings = [
        _finding("Automated web exploitation against web-2 server", [TARGET, ACTOR]),
        _finding("Exploit against web-1", [TARGET], note=_UNRESOLVED_NOTE),
        _finding("actor-a probes web-1", [TARGET, ACTOR]),
    ]

    class Report:
        def __init__(self, fs: list[HuntFinding]) -> None:
            self.findings = fs

        def model_copy(self, update: dict[str, Any]) -> Report:
            return Report(update["findings"])

    ctx = type("C", (), {"db_sessionmaker": maker})()
    out = await hunt_runner._gate_finding_names(Report(findings), ctx)
    assert [f.validator_note for f in out.findings] == [NOTE, _UNRESOLVED_NOTE, None]
    assert out.findings[0].title == "Automated web exploitation against web-2 server"


async def test_the_campaign_rows_carry_the_note_of_their_finding(maker: Any) -> None:
    async with maker() as db:
        await seed_hosts(db)
        hunt = await hunt_svc.create(db, objective="read the web server", started_by="admin")
        await hunt_svc.finalize(
            db,
            hunt.id,
            status="complete",
            narrative="x",
            report={
                "findings": [
                    {"title": "Probes against web-2", "detail": "", "hosts": [TARGET]},
                    {"title": "Probes against web-1", "detail": "", "hosts": [TARGET]},
                ]
            },
        )
        runs = []
        for ordinal in (0, 1):
            inv = await inv_svc.create(
                db,
                alert_es_id=f"a{ordinal}",
                started_by="admin",
                kind="hunt",
                hunt_id=hunt.id,
                finding_ordinal=ordinal,
            )
            runs.append(inv.id)
        members = [
            routes_campaigns.CampaignMemberOut(
                runId=run_id,
                kind="finding",
                label="x",
                link="x",
                evidence=routes_campaigns.MemberEvidenceOut(),
                direction="x",
                tier="x",
            )
            for run_id in runs
        ]
        await routes_campaigns._name_notes(db, members)
    assert [m.nameNote for m in members] == [NOTE, None]


# ── The investigation page ──────────────────────────────────────────────────


@pytest.fixture
def client(settings_kratos: Settings) -> Iterator[TestClient]:
    with (
        patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=AsyncMock()),
        patch("soc_ai.main.make_auth", return_value=AsyncMock()),
        patch("soc_ai.main.get_settings", return_value=settings_kratos),
        TestClient(create_app()) as c,
    ):
        yield c


def test_the_finding_investigation_page_shows_the_same_note(client: TestClient) -> None:
    async def go() -> str:
        async with client.app.state.db_sessionmaker() as db:  # type: ignore[attr-defined]
            await seed_hosts(db)
            hunt = await hunt_svc.create(db, objective="read the web server", started_by="admin")
            await hunt_svc.finalize(
                db,
                hunt.id,
                status="complete",
                narrative="x",
                report={"findings": [{"title": "Probes against web-2", "hosts": [TARGET]}]},
            )
            inv = await inv_svc.create(
                db,
                alert_es_id="a0",
                started_by="admin",
                kind="hunt",
                hunt_id=hunt.id,
                finding_ordinal=0,
            )
            return str(inv.id)

    run = asyncio.run(go())
    body = client.get(f"/api/v1/investigations/{run}").json()
    assert body["promotedFinding"]["nameNote"] == NOTE
    assert body["promotedFinding"]["title"] == "Probes against web-2"

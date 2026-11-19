"""The source and the target of a finding investigation (dogfood 2026-11-17, AA1).

Prod run 01M7DPGFP4P5Q5HFR8QJM5QZXA judged a finding on a web server and one
client. It stored the flow of an anchor record between two other machines, and
the page called that flow lateral movement. The rule: the source and the
target of a finding run come from the hosts of the finding. An anchor whose
addresses are not hosts of the finding gives no pair.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Iterator
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient
from soc_ai.agent.context import HuntSubject, StepEvent, SubjectFinding
from soc_ai.api import runner
from soc_ai.api.runner import recorded_run
from soc_ai.config import Settings
from soc_ai.main import create_app
from soc_ai.store import first_line
from soc_ai.store import hunts as hunt_svc
from soc_ai.store import investigations as inv_svc
from soc_ai.store.db import make_engine, make_sessionmaker, run_migrations
from soc_ai.store.models import Investigation

_SERVER = "192.0.2.10"
_CLIENT = "192.0.2.26"
_OTHER_A = "198.51.100.58"
_OTHER_B = "198.51.100.8"


# ── The rule ────────────────────────────────────────────────────────────────


def test_an_anchor_between_other_machines_gives_no_pair() -> None:
    assert first_line.finding_pair(_OTHER_A, _OTHER_B, [_SERVER, _CLIENT]) == (None, None)


def test_an_anchor_with_one_end_on_a_host_of_the_finding_keeps_its_flow() -> None:
    assert first_line.finding_pair(_OTHER_A, _SERVER, [_SERVER]) == (_OTHER_A, _SERVER)
    assert first_line.finding_pair(_SERVER, _OTHER_A, [_SERVER]) == (_SERVER, _OTHER_A)


def test_an_anchor_between_two_hosts_of_the_finding_keeps_its_direction() -> None:
    assert first_line.finding_pair(_CLIENT, _SERVER, [_SERVER, _CLIENT]) == (_CLIENT, _SERVER)


def test_a_finding_with_no_host_takes_no_pair() -> None:
    assert first_line.finding_pair(_OTHER_A, _OTHER_B, []) == (None, None)


def test_an_address_that_only_starts_like_a_host_is_no_host() -> None:
    """NEGATIVE CONTROL. 192.0.2.1 is no prefix match of 192.0.2.10."""
    assert first_line.finding_pair("192.0.2.1", _OTHER_B, [_SERVER]) == (None, None)


def test_a_name_of_the_finding_is_no_address_match() -> None:
    """NEGATIVE CONTROL. The rule matches addresses, as the report ends do."""
    assert first_line.finding_pair(_OTHER_A, _OTHER_B, ["web-1"]) == (None, None)
    assert first_line.finding_ends(_OTHER_A, _OTHER_B, ["web-1"]) == (None, "web-1")


# ── The store ───────────────────────────────────────────────────────────────


async def _db(settings: Settings):  # type: ignore[no-untyped-def]
    engine = make_engine(settings)
    await run_migrations(engine)
    return engine, make_sessionmaker(engine)


def _context(src: str, dst: str, host: str = "ssh-box") -> StepEvent:
    return StepEvent(
        kind="alert_context",
        session_id="s",
        sequence=1,
        payload={"alert": {"source_ip": src, "destination_ip": dst, "host_name": host}},
    )


async def _stream(event: StepEvent) -> AsyncIterator[StepEvent]:
    yield event


async def _record(
    settings: Settings, event: StepEvent, finding_hosts: list[str] | None
) -> Investigation:
    engine, maker = await _db(settings)
    state = type("S", (), {"db_sessionmaker": maker})()
    created: dict[str, Any] = {}
    async for name, data in recorded_run(
        state,
        alert_id="anchor-1",
        started_by="admin",
        event_stream=_stream(event),
        kind="hunt" if finding_hosts is not None else "suricata",
        hunt_id="01HUNTC000000000000000000000" if finding_hosts is not None else None,
        finding_ordinal=0 if finding_hosts is not None else None,
        finding_hosts=finding_hosts,
    ):
        if name == "investigation_created":
            created = data
    async with maker() as db:
        inv = await db.get(Investigation, created["investigation_id"])
    await engine.dispose()
    assert inv is not None
    return inv


async def test_a_finding_run_stores_no_pair_for_an_anchor_off_its_hosts(
    settings_kratos: Settings,
) -> None:
    inv = await _record(settings_kratos, _context(_OTHER_A, _OTHER_B), [_SERVER, _CLIENT])
    assert (inv.src_ip, inv.dest_ip, inv.host_name) == (None, None, None)


async def test_a_finding_run_stores_the_flow_that_touches_its_host(
    settings_kratos: Settings,
) -> None:
    inv = await _record(settings_kratos, _context(_CLIENT, _SERVER, "web-1"), [_SERVER])
    assert (inv.src_ip, inv.dest_ip, inv.host_name) == (_CLIENT, _SERVER, "web-1")


async def test_an_alert_run_keeps_the_flow_of_its_anchor(settings_kratos: Settings) -> None:
    """NEGATIVE CONTROL. The rule is for a finding run only."""
    inv = await _record(settings_kratos, _context(_OTHER_A, _OTHER_B), None)
    assert (inv.src_ip, inv.dest_ip, inv.host_name) == (_OTHER_A, _OTHER_B, "ssh-box")


def test_run_recorded_hands_the_hosts_of_the_promoted_finding_to_the_store() -> None:
    seen: dict[str, Any] = {}

    def fake_investigate(*_a: Any, **_k: Any) -> AsyncIterator[Any]:
        async def gen() -> AsyncIterator[Any]:
            return
            yield  # pragma: no cover

        return gen()

    async def fake_recorded_run(_state: Any, **kwargs: Any) -> AsyncIterator[Any]:
        seen.update(kwargs)
        async for item in kwargs["event_stream"]:
            yield item

    def subject(promoted: bool) -> HuntSubject:
        return HuntSubject(
            hunt_id="01HUNT0000000000000000000",
            objective="read the web server",
            findings=[
                SubjectFinding(
                    ordinal=0, title="LFI read-back", hosts=[_SERVER, _CLIENT], promoted=promoted
                )
            ],
        )

    async def run(subj: HuntSubject) -> None:
        with (
            patch.object(runner, "investigate", fake_investigate),
            patch.object(runner, "recorded_run", fake_recorded_run),
        ):
            async for _ in runner.run_recorded(
                type("S", (), {})(),
                ctx=type("C", (), {})(),
                alert_id="a1",
                started_by="tester",
                subject=subj,
            ):
                pass

    asyncio.run(run(subject(promoted=True)))
    assert seen["finding_hosts"] == [_SERVER, _CLIENT]
    # NEGATIVE CONTROL: a lead promotion judges the hunt and has no finding.
    asyncio.run(run(subject(promoted=False)))
    assert seen["finding_hosts"] is None


# ── The page ────────────────────────────────────────────────────────────────


@pytest.fixture
def client(settings_kratos: Settings) -> Iterator[TestClient]:
    with (
        patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=AsyncMock()),
        patch("soc_ai.main.make_auth", return_value=AsyncMock()),
        patch("soc_ai.main.get_settings", return_value=settings_kratos),
        TestClient(create_app()) as c,
    ):
        yield c


def _seed(client: TestClient, src: str, dst: str) -> str:
    """A finding run whose row and anchor both hold the flow ``src`` to ``dst``."""

    async def go() -> str:
        async with client.app.state.db_sessionmaker() as db:  # type: ignore[attr-defined]
            hunt = await hunt_svc.create(db, objective="read the web server", started_by="admin")
            await hunt_svc.finalize(
                db,
                hunt.id,
                status="complete",
                narrative="LFI on the web server.",
                report={
                    "findings": [
                        {
                            "title": "Successful LFI read-back",
                            "detail": "The client read files on the server.",
                            "hosts": [_SERVER, _CLIENT],
                            "citations": [],
                        }
                    ]
                },
            )
            inv = await inv_svc.create(
                db,
                alert_es_id="anchor-ssh",
                started_by="admin",
                rule_name="Successful LFI read-back",
                kind="hunt",
                hunt_id=hunt.id,
                finding_ordinal=0,
            )
            # A row of the release before the rule: the columns hold the flow.
            inv.src_ip, inv.dest_ip = src, dst
            await db.commit()
            await inv_svc.append_events(
                db,
                inv.id,
                [
                    {
                        "kind": "alert_context",
                        "sequence": 1,
                        "payload": {
                            "alert": {"source_ip": src, "destination_ip": dst},
                            "host_alert_profiles": [
                                {"ip": src, "end": "source", "as_source": {"ET X": 3}}
                            ],
                        },
                    }
                ],
            )
            await inv_svc.finalize(
                db, inv.id, status="complete", verdict="true_positive", confidence=0.85
            )
            return inv.id

    return asyncio.run(go())


def test_the_page_names_no_flow_for_an_anchor_off_the_hosts_of_the_finding(
    client: TestClient,
) -> None:
    run = _seed(client, _OTHER_A, _OTHER_B)
    body = client.get(f"/api/v1/investigations/{run}").json()
    assert body["graphScope"] is None
    assert body["nodes"] == [] and body["edges"] == []
    assert (body["srcIp"], body["dstIp"]) == (None, _SERVER)
    assert body["hostContexts"] == [] and body["hostContext"] == []
    assert body["promotedFinding"]["hosts"] == [_SERVER, _CLIENT]


def test_the_page_keeps_the_flow_that_touches_a_host_of_the_finding(
    client: TestClient,
) -> None:
    """NEGATIVE CONTROL. A flow between the hosts of the finding stays on the page."""
    run = _seed(client, _CLIENT, _SERVER)
    body = client.get(f"/api/v1/investigations/{run}").json()
    assert body["graphScope"] == "lateral"
    assert body["nodes"]
    assert (body["srcIp"], body["dstIp"]) == (_CLIENT, _SERVER)
    assert [c["ip"] for c in body["hostContexts"]] == [_CLIENT]


def _list_row(client: TestClient, run: str) -> dict[str, Any]:
    rows = client.get("/api/v1/investigations?range=all").json()["rows"]
    return next(r for r in rows if r["id"] == run)


def test_the_list_row_names_no_flow_for_an_anchor_off_the_hosts_of_the_finding(
    client: TestClient,
) -> None:
    row = _list_row(client, _seed(client, _OTHER_A, _OTHER_B))
    assert (row["host"], row["dst"]) == ("—", _SERVER)
    # N5: the row names the hosts of the finding, so the list draws no arrow
    # from nothing.
    assert row["findingHosts"] == [_SERVER, _CLIENT]


def test_the_list_row_keeps_the_flow_that_touches_a_host_of_the_finding(
    client: TestClient,
) -> None:
    """NEGATIVE CONTROL. A flow on a host of the finding stays in the row."""
    row = _list_row(client, _seed(client, _CLIENT, _SERVER))
    assert (row["host"], row["dst"]) == (_CLIENT, _SERVER)
    assert row["findingHosts"] is None

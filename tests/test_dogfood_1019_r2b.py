"""The round 2 verify of the 2026-10-19 dogfood: hunts and leads.

R3-D4 residual: the lead page counted one investigated finding where two
findings shared one investigation. The stepper on the same page counted two.
Each promoted finding now names the other findings of its hunt that read the
same investigation.
"""

from __future__ import annotations

import asyncio
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient
from soc_ai.config import Settings
from soc_ai.main import create_app
from soc_ai.store import hunts as hunt_svc
from soc_ai.store.models import Hunt, Investigation, Lead


@pytest.fixture
def client(settings_kratos: Settings) -> Iterator[TestClient]:
    with (
        patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=AsyncMock()),
        patch("soc_ai.main.make_auth", return_value=AsyncMock()),
        patch("soc_ai.main.get_settings", return_value=settings_kratos),
    ):
        app = create_app()
        with TestClient(app) as test_client:
            yield test_client


def _threat(title: str, host: str) -> dict[str, Any]:
    return {"title": title, "category": "threat", "detail": "x", "hosts": [host]}


_OBSERVATION = {
    "title": "All abuse is historical",
    "category": "observation",
    "detail": "x",
    "hosts": ["192.0.2.10"],
}


def _seed(client: TestClient, plan: dict[str, dict[str, Any]], runs: list[dict[str, Any]]) -> int:
    """One lead, one hunt with three findings and its plan, and the runs."""

    async def go() -> int:
        async with client.app.state.db_sessionmaker() as db:
            lead = Lead(
                status="promoted",
                entities_json=[["host", "192.0.2.10"]],
                kinds_json=["catalog_match"],
                shadow=False,
            )
            db.add(lead)
            await db.commit()
            hunt = await hunt_svc.create(
                db,
                objective=f"[lead {lead.id}] look at this lead",
                started_by="auto-hunt",
                kind="lead",
                starter="lead",
                lead_id=int(lead.id),
            )
            findings = [
                _threat("Credential abuse on the domain controller", "192.0.2.10"),
                _threat("NTLM failures from one source", "192.0.2.10"),
                _OBSERVATION,
            ]
            await hunt_svc.finalize(
                db,
                hunt.id,
                status="complete",
                narrative="x",
                report={"findings": findings, "narrative": "x"},
                finding_plan=plan,
            )
            base = datetime.now(UTC).replace(tzinfo=None) - timedelta(hours=2)
            for i, run in enumerate(runs):
                db.add(
                    Investigation(
                        id=run["id"],
                        alert_es_id="es-1",
                        kind="hunt",
                        hunt_id=hunt.id,
                        finding_ordinal=run["ordinal"],
                        status="complete",
                        verdict="true_positive",
                        confidence=0.72,
                        started_by="system:hunt",
                        created_at=base + timedelta(minutes=i),
                    )
                )
            row = await db.get(Lead, lead.id)
            assert row is not None
            row.hunt_id = hunt.id
            assert await db.get(Hunt, hunt.id) is not None
            await db.commit()
            return int(lead.id)

    return asyncio.run(go())


def _entry(inv_id: str, origin: str) -> dict[str, Any]:
    return hunt_svc.plan_entry(hunt_svc.LINK_ENDED, investigation_id=inv_id, origin=origin)


def test_a_promoted_finding_names_the_findings_that_share_its_investigation(
    client: TestClient,
) -> None:
    shared = "01INVSHARED0000000000000F1"
    lead_id = _seed(
        client,
        {
            "0": _entry(shared, hunt_svc.ORIGIN_OPENED),
            "1": _entry(shared, hunt_svc.ORIGIN_REUSED),
            # An older row linked the observation to the same run. An
            # observation is no subject, so it shares nothing.
            "2": _entry(shared, hunt_svc.ORIGIN_REUSED),
        },
        [{"id": shared, "ordinal": 0}],
    )
    body = client.get(f"/api/v1/hunts/leads/{lead_id}").json()
    rows = body["promoted_findings"]
    assert [(r["investigation_id"], r["finding_ordinal"], r["shared_with"]) for r in rows] == [
        (shared, 0, [1])
    ]


def test_a_finding_with_its_own_newer_run_shares_nothing(client: TestClient) -> None:
    shared = "01INVSHARED0000000000000F2"
    own = "01INVOWNRUN0000000000000F2"
    lead_id = _seed(
        client,
        {
            "0": _entry(shared, hunt_svc.ORIGIN_OPENED),
            "1": _entry(shared, hunt_svc.ORIGIN_REUSED),
        },
        # An analyst opened a run of F2 after the hunt. The hunt page reads
        # the newer run on F2, so F2 no longer shares the first one.
        [{"id": shared, "ordinal": 0}, {"id": own, "ordinal": 1}],
    )
    rows = client.get(f"/api/v1/hunts/leads/{lead_id}").json()["promoted_findings"]
    by_id = {r["investigation_id"]: r["shared_with"] for r in rows}
    assert by_id == {shared: [], own: []}


# ---------------------------------------------------------------------------
# V1-H7: a catalog hunt stored before the plain words keeps the grid client's
# raw text: the index patterns, an em dash and "not 'nothing happened'". The
# header said "The grid refused the query" over a read that 45 of 289 shards
# answered. The page maps the stored text when it reads it.
# ---------------------------------------------------------------------------

_RAW = (
    "precondition: partial search results from .ds-logs-*-so-*,.ds-logs-*-default-*: "
    "244 of 289 shards failed (no_shard_available_action_exception) \u2014 the returned "
    "hits are incomplete, so an empty or short answer here means 'unknown', not "
    "'nothing happened'"
)
_TITLE = "A workstation requests a Kerberos service ticket for a service account"
_OLD_NARRATIVE = f"{_TITLE}: the run failed. The result is unknown. {_RAW}"
_OLD_DETAIL = (
    "The local-service-ticket-from-workstation hunt spec failed against the grid. "
    f"The result is unknown. {_RAW}"
)
_PLAIN = (
    "The grid answered from 45 of 289 shards during the precondition query. The answer is "
    "incomplete. An empty answer means that the result is unknown."
)


def test_restate_failure_maps_the_stored_shapes() -> None:
    from soc_ai.hunting.findings import restate_failure

    assert restate_failure(_OLD_NARRATIVE) == (
        f"{_TITLE}: the run failed. The result is unknown. {_PLAIN}"
    )
    assert restate_failure(_OLD_DETAIL) == (
        "The analytic local-service-ticket-from-workstation could not run on the grid. "
        f"The result is unknown. {_PLAIN}"
    )


@pytest.mark.parametrize(
    "text",
    [
        "",
        "The hunt found nothing.",
        # Today's words come back as they are.
        f"The analytic x could not run on the grid. The result is unknown. {_PLAIN}",
        # A raw text this build does not know stays as it was stored.
        "The result is unknown. ValueError: something odd",
        "The result is unknown. ",
    ],
)
def test_restate_failure_keeps_a_shape_it_does_not_know(text: str) -> None:
    from soc_ai.hunting.findings import restate_failure

    assert restate_failure(text) == text


def test_restate_failure_never_raises_on_a_stored_value_of_another_type() -> None:
    from soc_ai.hunting.findings import restate_failure

    assert restate_failure(None) == ""
    assert restate_failure(42) == "42"  # type: ignore[arg-type]


def _seed_catalog_failure(client: TestClient) -> str:
    async def go() -> str:
        async with client.app.state.db_sessionmaker() as db:
            hunt = await hunt_svc.create(
                db,
                objective=f"{_TITLE}, last 24 h",
                started_by="hunt-catalog",
                kind="triggered",
            )
            await hunt_svc.finalize(
                db,
                hunt.id,
                status="complete",
                narrative=_OLD_NARRATIVE,
                report={
                    "narrative": _OLD_NARRATIVE,
                    "findings": [
                        {
                            "title": f"{_TITLE}: could not run",
                            "detail": _OLD_DETAIL,
                            "severity": "medium",
                            "category": "visibility_gap",
                            "hosts": [],
                            "citations": [],
                        }
                    ],
                },
            )
            return str(hunt.id)

    return asyncio.run(go())


def test_the_hunt_page_states_a_stored_partial_read_in_plain_words(client: TestClient) -> None:
    hunt_id = _seed_catalog_failure(client)
    body = client.get(f"/api/v1/hunts/{hunt_id}").json()
    assert body["outcome"] == "could_not_run"
    assert body["outcome_headline"] == (
        "The grid answered from part of its shards. Hunt again when the grid is healthy."
    )
    assert body["narrative"] == f"{_TITLE}: the run failed. The result is unknown. {_PLAIN}"
    assert body["findings"][0]["detail"].endswith(_PLAIN)
    for text in (body["narrative"], body["findings"][0]["detail"]):
        assert "\u2014" not in text
        assert "nothing happened" not in text
        assert "*" not in text
    # The list row states the same headline.
    rows = {r["id"]: r for r in client.get("/api/v1/hunts?kind=triggered").json()}
    assert rows[hunt_id]["outcome_headline"] == body["outcome_headline"]


# ---------------------------------------------------------------------------
# V1-H8: the hunt timeline printed the text soc-ai writes for the model when
# the grid fails: "Do not re-send this exact call...". The model keeps that
# text. The page states what happened.
# ---------------------------------------------------------------------------

# The stored text of 2026-10-06 carried em dashes. The text of today has none.
_GRID_DOWN_STORED = (
    "The Security Onion grid did not answer this query \u2014 it is unreachable, timing out, "
    "or returned only partial results. This result is UNKNOWN, not empty: it is NOT evidence "
    "that nothing matched, and it rules nothing out. Do not describe the network as quiet, "
    "clean or clear on the strength of it. Do not re-send this exact call \u2014 an identical "
    "repeat short-circuits as a duplicate instead of re-querying; to re-check, vary the "
    "query, once. If the grid keeps failing, say plainly that the grid was unavailable and "
    "the question could not be answered."
)


@pytest.mark.parametrize("retried", [False, True])
def test_the_grid_down_tool_text_reads_in_plain_words(retried: bool) -> None:
    from soc_ai.agent.toolset import _GRID_UNAVAILABLE_MESSAGE
    from soc_ai.hunting.step_words import translate_tool_error

    words = "The grid did not answer this query. The result is unknown."
    if retried:
        words += " The agent tried again."
    for message in (_GRID_DOWN_STORED, _GRID_UNAVAILABLE_MESSAGE):
        assert translate_tool_error(message, retried=retried) == words


def test_the_hunt_timeline_drops_the_model_instruction() -> None:
    from soc_ai.api.webui.routes_hunts import _build_hunt_timeline
    from soc_ai.store.models import HuntEvent

    def ev(seq: int, kind: str, payload: dict[str, Any]) -> HuntEvent:
        return HuntEvent(hunt_id="h", sequence=seq, kind=kind, payload=payload)

    failed = {
        "error": True,
        "type": "ConnectionError",
        "reason": "grid_unavailable",
        "message": _GRID_DOWN_STORED,
    }
    events = [
        ev(1, "hunt_started", {"objective": "o"}),
        ev(2, "tool_call", {"tool_name": "t_get_event_raw", "args": {}, "tool_call_id": "a"}),
        ev(3, "tool_result", {"tool_call_id": "a", "result": failed}),
    ]
    titles = [s.title for s in _build_hunt_timeline(events, "complete")]
    assert titles[1] == "Raw event: The grid did not answer this query. The result is unknown."
    assert not any("re-send" in t or "\u2014" in t for t in titles)

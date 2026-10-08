"""The lead page chat's HTTP surface and the thin manager behind it.

The console has one chat panel. It is scoped to the object on the page, and a
lead page had no thread to scope it to. These tests pin the lead scope:

* **One SHARED thread per lead**, keyed ``lead:<id>`` in the existing
  ``GeneralChatMessage`` table. The key carries the lead and nothing about
  the caller, the host chat's precedent.
* **An unknown lead is a 404** on all three verbs, in the lead routes' words.
* **Clear deletes this lead's thread only.** A DELETE that truncated the
  shared table would wipe the host and the general threads with it.
* **The lead seeds the turn.** The entities, the kinds, the observations and
  the evidence documents go into ``seed_context``, the corpus the grounding
  gate grades against.
* **A hunt proposal reaches meta, and a verdict proposal does not exist.** A
  lead has no verdict to set.
* **The demo stores nothing.** The thread is shared, so a stored demo turn
  would show one visitor's question to the next.
"""

from __future__ import annotations

import asyncio
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient
from soc_ai.config import Settings
from soc_ai.store import general_chat as gc_svc

from tests.test_general_chat_api import ANON, _state
from tests.test_webui_api import _client

# TEST-NET / private-range fixtures only. The leak gate reads test files too.
HOST = "10.0.0.30"
PEER = "203.0.113.9"


@pytest.fixture
def client(settings_kratos: Settings) -> Iterator[TestClient]:
    yield from _client(settings_kratos)


@pytest.fixture
def demo_client(settings_kratos: Settings) -> Iterator[TestClient]:
    """The public demo: no auth, no grid, nothing may persist."""
    yield from _client(
        settings_kratos.model_copy(
            update={"soc_ai_demo": True, "es_hosts": ["http://127.0.0.1:9200"]}
        )
    )


@pytest.fixture
def general_chat_disabled_client(settings_kratos: Settings) -> Iterator[TestClient]:
    """The general chat's kill switch thrown. It must NOT touch this chat."""
    yield from _client(settings_kratos.model_copy(update={"general_chat_enabled": False}))


def _run(coro: Any) -> Any:
    return asyncio.run(coro)


def _seed_lead(client: TestClient) -> int:
    """One lead on one host from a new destination and off-hours activity.

    Born one hour ago, relative to now: a fixed date decays the weight to zero
    a few days later, and the formation then fails by the calendar.
    """
    from soc_ai.hunting.leads import content_fingerprint, form_leads, record_observation
    from soc_ai.hunting.weight import Kind

    async def go() -> int:
        now = datetime.now(UTC) - timedelta(hours=1)
        async with client.app.state.db_sessionmaker() as db:
            await record_observation(
                db,
                entity_kind="host",
                entity_key=HOST,
                kind=Kind.NOVEL_DESTINATION,
                spec_id="s",
                fingerprint=content_fingerprint("peers_out", PEER),
                summary=f"new outbound peer for this host: {PEER} (seen once)",
                evidence={"sample_ids": ["tel-doc-000003"]},
                now=now,
            )
            await record_observation(
                db,
                entity_kind="host",
                entity_key=HOST,
                kind=Kind.OFF_HOURS,
                spec_id="p",
                fingerprint=content_fingerprint("active_hours", "3"),
                summary="active around 03:00 UTC, outside the hours this host is normally active",
                now=now,
            )
            outcome = await form_leads(db, entity_keys=[("host", HOST)], now=now, threshold=0.7)
            return int(outcome.formed[0])

    return _run(go())  # type: ignore[no-any-return]


def _seed_rows(client: TestClient, thread_key: str, *contents: str) -> None:
    async def go() -> None:
        async with client.app.state.db_sessionmaker() as db:
            for content in contents:
                await gc_svc.add_user_message(db, thread_key, content)

    _run(go())


def _messages(client: TestClient, thread_key: str) -> list[Any]:
    async def go() -> list[Any]:
        async with client.app.state.db_sessionmaker() as db:
            return await gc_svc.list_messages(db, thread_key)

    return _run(go())  # type: ignore[no-any-return]


# ── the three routes ────────────────────────────────────────────────────────


def test_get_thread_is_empty_before_the_first_question(client: TestClient) -> None:
    lead_id = _seed_lead(client)
    resp = client.get(f"/api/v1/hunts/leads/{lead_id}/chat")
    assert resp.status_code == 200, resp.text
    assert resp.json() == {"messages": [], "pending": False, "progress_tools": []}


def test_an_unknown_lead_is_404_on_all_three_verbs(client: TestClient) -> None:
    with patch("soc_ai.webui.lead_chat_manager.get_manager", return_value=MagicMock()) as mgr:
        for call in (
            lambda: client.get("/api/v1/hunts/leads/999/chat"),
            lambda: client.post("/api/v1/hunts/leads/999/chat", json={"message": "hi"}),
            lambda: client.delete("/api/v1/hunts/leads/999/chat"),
        ):
            resp = call()
            assert resp.status_code == 404, resp.text
            assert resp.json()["detail"]["reason"] == "lead_not_found"
    mgr.return_value.start.assert_not_called()


def test_post_writes_the_turn_under_the_lead_and_spawns_it(client: TestClient) -> None:
    lead_id = _seed_lead(client)
    with patch("soc_ai.webui.lead_chat_manager.get_manager", return_value=MagicMock()) as mgr:
        resp = client.post(
            f"/api/v1/hunts/leads/{lead_id}/chat", json={"message": "why did this lead form?"}
        )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert [m["role"] for m in body["messages"]] == ["user", "assistant"]
    assert body["messages"][0]["text"] == "why did this lead form?"
    assert body["pending"] is True
    start = mgr.return_value.start
    start.assert_called_once()
    assert start.call_args.kwargs["lead_id"] == lead_id
    assert [m.role for m in _messages(client, f"lead:{lead_id}")] == ["user", "assistant"]
    # Negative control: the caller's general thread got nothing.
    assert _messages(client, ANON) == []


def test_post_rejects_an_empty_message(client: TestClient) -> None:
    lead_id = _seed_lead(client)
    with patch("soc_ai.webui.lead_chat_manager.get_manager", return_value=MagicMock()):
        resp = client.post(f"/api/v1/hunts/leads/{lead_id}/chat", json={"message": "   "})
    assert resp.status_code == 400
    assert resp.json()["detail"]["reason"] == "empty_message"


def test_second_post_while_pending_is_409(client: TestClient) -> None:
    lead_id = _seed_lead(client)

    async def go() -> None:
        async with client.app.state.db_sessionmaker() as db:
            await gc_svc.add_user_message(db, f"lead:{lead_id}", "first question")
            await gc_svc.create_pending_assistant(db, f"lead:{lead_id}")

    _run(go())
    with patch("soc_ai.webui.lead_chat_manager.get_manager", return_value=MagicMock()) as mgr:
        resp = client.post(f"/api/v1/hunts/leads/{lead_id}/chat", json={"message": "second"})
    assert resp.status_code == 409
    assert resp.json()["detail"]["reason"] == "chat_busy"
    mgr.return_value.start.assert_not_called()


def test_delete_clears_only_this_leads_thread(client: TestClient) -> None:
    lead_id = _seed_lead(client)
    _seed_rows(client, f"lead:{lead_id}", "about this lead")
    _seed_rows(client, f"host:{HOST}", "about the host")
    _seed_rows(client, ANON, "a general question")

    resp = client.delete(f"/api/v1/hunts/leads/{lead_id}/chat")
    assert resp.status_code == 200
    assert resp.json()["messages"] == []
    assert _messages(client, f"lead:{lead_id}") == []
    assert [m.content for m in _messages(client, f"host:{HOST}")] == ["about the host"]
    assert [m.content for m in _messages(client, ANON)] == ["a general question"]


def test_the_thread_is_keyed_on_the_lead_not_the_caller() -> None:
    from soc_ai.webui.lead_chat_manager import thread_key_for

    assert thread_key_for(18) == "lead:18"
    assert len(thread_key_for(2**63)) <= 64


def test_the_general_chat_kill_switch_does_not_touch_the_lead_chat(
    general_chat_disabled_client: TestClient,
) -> None:
    lead_id = _seed_lead(general_chat_disabled_client)
    resp = general_chat_disabled_client.get(f"/api/v1/hunts/leads/{lead_id}/chat")
    assert resp.status_code == 200
    with patch("soc_ai.webui.lead_chat_manager.get_manager", return_value=MagicMock()) as mgr:
        resp = general_chat_disabled_client.post(
            f"/api/v1/hunts/leads/{lead_id}/chat", json={"message": "still on?"}
        )
    assert resp.status_code == 200
    mgr.return_value.start.assert_called_once()


# ── the public demo ─────────────────────────────────────────────────────────


def test_demo_answers_the_turn_without_writing_a_row(demo_client: TestClient) -> None:
    from soc_ai.webui.lead_chat_manager import DEMO_REPLY

    lead_id = _seed_lead(demo_client)
    with patch("soc_ai.webui.lead_chat_manager.get_manager", return_value=MagicMock()) as mgr:
        resp = demo_client.post(
            f"/api/v1/hunts/leads/{lead_id}/chat", json={"message": "why did it form?"}
        )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["messages"][1]["text"] == DEMO_REPLY
    assert body["pending"] is False
    mgr.return_value.start.assert_not_called()
    assert _messages(demo_client, f"lead:{lead_id}") == []


def test_demo_delete_deletes_nothing(demo_client: TestClient) -> None:
    lead_id = _seed_lead(demo_client)
    _seed_rows(demo_client, f"lead:{lead_id}", "not the visitor's to delete")
    resp = demo_client.delete(f"/api/v1/hunts/leads/{lead_id}/chat")
    assert resp.status_code == 200
    assert resp.json()["messages"] == []
    assert demo_client.get(f"/api/v1/hunts/leads/{lead_id}/chat").json()["messages"] == []
    assert [m.content for m in _messages(demo_client, f"lead:{lead_id}")] == [
        "not the visitor's to delete"
    ]


# ── the manager ─────────────────────────────────────────────────────────────


def _prepare(client: TestClient, lead_id: int, question: str) -> Any:
    from soc_ai.webui.lead_chat_manager import _lead_spec

    state = _state(client)

    async def go() -> Any:
        async with state.db_sessionmaker() as db:
            await gc_svc.add_user_message(db, f"lead:{lead_id}", question)
            row = await gc_svc.create_pending_assistant(db, f"lead:{lead_id}")
        spec = _lead_spec(state, lead_id, row.id)
        return spec, await spec.prepare()

    return _run(go())


def test_prepare_builds_the_lead_shape(client: TestClient) -> None:
    from soc_ai.agent.chat_agent import LEAD_CHAT_SYSTEM_PROMPT

    lead_id = _seed_lead(client)
    spec, inputs = _prepare(client, lead_id, "why did this lead form?")
    assert spec.label == f"lead={lead_id}"
    assert inputs is not None
    assert inputs.system_prompt is LEAD_CHAT_SYSTEM_PROMPT
    assert inputs.oql_flavor == "hunt"
    assert inputs.question == "why did this lead form?"
    seed = inputs.seed_context
    # The lead, its entity, its kinds in words, and each observation.
    assert f"lead {lead_id}" in seed
    assert HOST in seed
    assert "new destination" in seed
    assert "off hours" in seed
    assert PEER in seed
    # The evidence document the first observation cites.
    assert "tel-doc-000003" in seed
    # Negative control: the kind identifiers stay out of the analyst words.
    assert "novel_destination" not in seed.split("Evidence")[0]


def test_the_lead_agent_can_propose_a_hunt_but_not_a_verdict(client: TestClient) -> None:
    from pydantic_ai.models.test import TestModel

    lead_id = _seed_lead(client)
    _spec, inputs = _prepare(client, lead_id, "every peer of this host in 7d?")
    assert inputs is not None

    async def go() -> dict[str, Any]:
        agent = inputs.build_agent(TestModel(), inputs.ctx, "sys")
        tools = agent._function_toolset.tools
        assert "propose_hunt" in tools
        assert "propose_verdict" not in tools
        await tools["propose_hunt"].function(
            objective=f"Sweep zeek.conn for every peer of {HOST} over 7d",
            why="one turn cannot cover a week",
        )
        meta: dict[str, Any] = {"tools": []}
        inputs.finalize_meta(meta, [], None)
        return meta

    meta = _run(go())
    assert meta["kind"] == "hunt_proposal"
    assert meta["proposal"]["objective"] == f"Sweep zeek.conn for every peer of {HOST} over 7d"


def test_no_proposal_leaves_meta_untouched(client: TestClient) -> None:
    lead_id = _seed_lead(client)
    _spec, inputs = _prepare(client, lead_id, "what does off hours mean here?")
    assert inputs is not None and inputs.finalize_meta is not None
    meta: dict[str, Any] = {"tools": ["t_query_events_oql"]}
    inputs.finalize_meta(meta, [], None)
    assert meta == {"tools": ["t_query_events_oql"]}


def test_demo_mode_answers_without_building_a_model(client: TestClient) -> None:
    from soc_ai.webui import lead_chat_manager as lcm

    lead_id = _seed_lead(client)
    demo = client.app.state.settings.model_copy(update={"soc_ai_demo": True})
    state = _state(client, settings=demo)

    async def go() -> list[Any]:
        async with state.db_sessionmaker() as db:
            row = await gc_svc.create_pending_assistant(db, f"lead:{lead_id}")
        with patch("soc_ai.webui.chat_turn.build_investigator_model") as build_model:
            await lcm._run_turn(state, lead_id, row.id)
        assert not build_model.called, "demo mode must never reach the gateway"
        async with state.db_sessionmaker() as db:
            return await gc_svc.list_messages(db, f"lead:{lead_id}")

    msgs = _run(go())
    assert [m.status for m in msgs] == ["done"]
    assert msgs[0].meta == {"demo": True}

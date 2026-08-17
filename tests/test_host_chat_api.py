"""The host page chat's HTTP surface + the thin manager behind it (task #65).

What these pin, and the failure each one is here to prevent:

* **One SHARED thread per host.** The subject is the machine, not the caller —
  the investigation-chat precedent for object-scoped chats. The thread key is
  ``host:<canonical ip>`` in the EXISTING ``GeneralChatMessage`` table: keying
  on the caller would give two analysts two half-conversations about one box,
  and a new table would be the chat-shape fork ``chat_turn.py`` exists to stop.
* **The key fits the column.** ``thread_key`` is ``String(64)``; a canonical
  IPv6 address tops out well under it even with the ``host:`` prefix, and two
  spellings of one address must land on ONE thread, not two.
* **No kill switch.** The host chat gates on what the investigation chat gates
  on — the subject must be addressable (a real IP, else 404) — and NOT on
  ``general_chat_enabled``, which kills the always-on dashboard box only.
* **The dossier seeds the turn.** ``seed_context`` is the corpus the grounding
  gate grades against, so naming the host correctly must come back GROUNDED,
  not wearing an Unverified caveat.
* **A hunt proposal reaches meta.** "Show me everything this host talked to in
  7d" is exactly a sweep; a proposal that dies in the sink is a hunt the
  analyst never sees.
"""

from __future__ import annotations

import asyncio
from collections.abc import Iterator
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient
from soc_ai.config import Settings
from soc_ai.store import general_chat as gc_svc

from tests.test_general_chat_api import ANON, _state
from tests.test_webui_api import _client

# TEST-NET / private-range fixtures only — this repo publishes to GitHub and the
# leak gate reads test files too.
HOST = "10.0.0.20"
OTHER_HOST = "10.0.0.21"
KEY = f"host:{HOST}"


@pytest.fixture
def client(settings_kratos: Settings) -> Iterator[TestClient]:
    yield from _client(settings_kratos)


@pytest.fixture
def demo_client(settings_kratos: Settings) -> Iterator[TestClient]:
    """The public Render demo: no auth, no grid, nothing may persist."""
    yield from _client(
        settings_kratos.model_copy(
            update={"soc_ai_demo": True, "es_hosts": ["http://127.0.0.1:9200"]}
        )
    )


@pytest.fixture
def general_chat_disabled_client(settings_kratos: Settings) -> Iterator[TestClient]:
    """The dashboard box's kill switch thrown — which must NOT touch this chat."""
    yield from _client(settings_kratos.model_copy(update={"general_chat_enabled": False}))


def _run(coro: Any) -> Any:
    return asyncio.run(coro)


def _seed(
    client: TestClient, thread_key: str, *rows: tuple[str, str, str, dict[str, Any] | None]
) -> list[int]:
    """Write (role, content, status, meta) rows straight into *thread_key*."""

    async def _go() -> list[int]:
        ids: list[int] = []
        async with client.app.state.db_sessionmaker() as db:
            for role, content, status, meta in rows:
                if role == "user":
                    msg = await gc_svc.add_user_message(db, thread_key, content)
                else:
                    msg = await gc_svc.create_pending_assistant(db, thread_key)
                    if status != "pending":
                        await gc_svc.finish_assistant(
                            db, msg.id, content=content, status=status, meta=meta
                        )
                ids.append(msg.id)
        return ids

    return _run(_go())  # type: ignore[no-any-return]


def _messages(client: TestClient, thread_key: str) -> list[Any]:
    async def _go() -> list[Any]:
        async with client.app.state.db_sessionmaker() as db:
            return await gc_svc.list_messages(db, thread_key)

    return _run(_go())  # type: ignore[no-any-return]


def _seed_host_dossier(client: TestClient, ip: str = HOST, hostname: str = "web-01") -> None:
    from tests.test_dossier_orchestrator import _seed_dossier

    async def _go() -> None:
        await _seed_dossier(client.app.state.db_sessionmaker, ip, hostname=hostname)

    _run(_go())


# ── the three routes ────────────────────────────────────────────────────────


def test_get_thread_is_empty_before_the_first_question(client: TestClient) -> None:
    resp = client.get(f"/api/v1/dossiers/{HOST}/chat")
    assert resp.status_code == 200
    body = resp.json()
    assert body["messages"] == []
    assert body["pending"] is False
    assert body["progress_tools"] == []


def test_a_segment_that_is_not_an_address_is_404_on_all_three(client: TestClient) -> None:
    """This resource is keyed on addresses — same contract as the dossier routes."""
    for call in (
        lambda: client.get("/api/v1/dossiers/not-a-host/chat"),
        lambda: client.post("/api/v1/dossiers/not-a-host/chat", json={"message": "hi"}),
        lambda: client.delete("/api/v1/dossiers/not-a-host/chat"),
    ):
        resp = call()
        assert resp.status_code == 404, resp.text
        assert resp.json()["detail"]["reason"] == "not_an_ip"


def test_post_writes_the_turn_and_spawns_it(client: TestClient) -> None:
    with patch("soc_ai.webui.host_chat_manager.get_manager", return_value=MagicMock()) as get_mgr:
        resp = client.post(f"/api/v1/dossiers/{HOST}/chat", json={"message": "what is this host?"})
    assert resp.status_code == 200
    body = resp.json()
    assert [m["role"] for m in body["messages"]] == ["user", "assistant"]
    assert body["messages"][0]["text"] == "what is this host?"
    assert body["pending"] is True
    start = get_mgr.return_value.start
    start.assert_called_once()
    assert start.call_args.kwargs["ip"] == HOST
    assert isinstance(start.call_args.kwargs["assistant_msg_id"], int)
    # The rows landed under the HOST's thread, in the shared general-chat table.
    assert [m.role for m in _messages(client, KEY)] == ["user", "assistant"]


def test_post_rejects_an_empty_message(client: TestClient) -> None:
    with patch("soc_ai.webui.host_chat_manager.get_manager", return_value=MagicMock()):
        resp = client.post(f"/api/v1/dossiers/{HOST}/chat", json={"message": "   "})
    assert resp.status_code == 400
    assert resp.json()["detail"]["reason"] == "empty_message"


def test_second_post_while_pending_is_409(client: TestClient) -> None:
    _seed(
        client,
        KEY,
        ("user", "first question", "done", None),
        ("assistant", "", "pending", None),
    )
    with patch("soc_ai.webui.host_chat_manager.get_manager", return_value=MagicMock()) as get_mgr:
        resp = client.post(f"/api/v1/dossiers/{HOST}/chat", json={"message": "second"})
    assert resp.status_code == 409
    assert resp.json()["detail"]["reason"] == "chat_busy"
    get_mgr.return_value.start.assert_not_called()


def test_delete_clears_only_this_hosts_thread(client: TestClient) -> None:
    """Clearing host A must leave host B's thread AND the dashboard threads alone
    — one DELETE that truncated the shared table would wipe them all."""
    _seed(client, KEY, ("user", "about host A", "done", None))
    _seed(client, f"host:{OTHER_HOST}", ("user", "about host B", "done", None))
    _seed(client, ANON, ("user", "a dashboard question", "done", None))

    resp = client.delete(f"/api/v1/dossiers/{HOST}/chat")
    assert resp.status_code == 200
    assert resp.json()["messages"] == []
    assert _messages(client, KEY) == []
    assert [m.content for m in _messages(client, f"host:{OTHER_HOST}")] == ["about host B"]
    assert [m.content for m in _messages(client, ANON)] == ["a dashboard question"]


# ── the thread key: per HOST, column-sized, one per address ─────────────────


def test_the_thread_is_keyed_on_the_host_not_the_caller(client: TestClient) -> None:
    """SHARED per host (the investigation-chat precedent for object-scoped
    chats) — the key carries the address and nothing about who is asking."""
    from soc_ai.webui.host_chat_manager import thread_key_for

    assert thread_key_for(HOST) == KEY


def test_an_ipv6_thread_key_fits_the_column(client: TestClient) -> None:
    """``thread_key`` is String(64); the worst-case canonical IPv6 plus the
    ``host:`` prefix must fit with no migration."""
    from soc_ai.store.host_dossier import normalize_host_key
    from soc_ai.webui.host_chat_manager import thread_key_for

    worst = normalize_host_key("abcd:abcd:abcd:abcd:abcd:abcd:abcd:abcd")
    key = thread_key_for(worst)
    assert key.startswith("host:")
    assert len(key) <= 64
    mapped = thread_key_for(normalize_host_key("::ffff:192.0.2.128"))
    assert len(mapped) <= 64


def test_two_spellings_of_one_address_share_one_thread(client: TestClient) -> None:
    """The key is the CANONICAL address, so ``2001:0DB8::1`` and ``2001:db8::1``
    read and write the same conversation instead of splitting it."""
    with patch("soc_ai.webui.host_chat_manager.get_manager", return_value=MagicMock()):
        client.post("/api/v1/dossiers/2001:0DB8::1/chat", json={"message": "who is this?"})
    body = client.get("/api/v1/dossiers/2001:db8::1/chat").json()
    assert [m["text"] for m in body["messages"]] == ["who is this?", ""]


# ── no kill switch: gated like the investigation chat, not the dashboard ────


def test_the_general_chat_kill_switch_does_not_touch_the_host_chat(
    general_chat_disabled_client: TestClient,
) -> None:
    """Deliberate: the host chat is scoped to an object (like the investigation
    chat, which has no switch), not an always-on landing-screen assistant. Its
    gate is the subject being addressable — the 404 above."""
    resp = general_chat_disabled_client.get(f"/api/v1/dossiers/{HOST}/chat")
    assert resp.status_code == 200
    with patch("soc_ai.webui.host_chat_manager.get_manager", return_value=MagicMock()) as get_mgr:
        resp = general_chat_disabled_client.post(
            f"/api/v1/dossiers/{HOST}/chat", json={"message": "still on?"}
        )
    assert resp.status_code == 200
    get_mgr.return_value.start.assert_called_once()


# ── the public demo: the thread is shared, so nothing may persist ───────────


def test_demo_answers_the_turn_without_writing_a_row(demo_client: TestClient) -> None:
    from soc_ai.webui.host_chat_manager import DEMO_REPLY

    with patch("soc_ai.webui.host_chat_manager.get_manager", return_value=MagicMock()) as get_mgr:
        resp = demo_client.post(
            f"/api/v1/dossiers/{HOST}/chat", json={"message": "what is this host?"}
        )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert [m["role"] for m in body["messages"]] == ["user", "assistant"]
    assert body["messages"][1]["text"] == DEMO_REPLY
    assert body["pending"] is False
    get_mgr.return_value.start.assert_not_called()
    assert _messages(demo_client, KEY) == []


def test_demo_get_never_serves_a_stored_thread(demo_client: TestClient) -> None:
    _seed(demo_client, KEY, ("user", "the previous visitor's question", "done", None))
    assert demo_client.get(f"/api/v1/dossiers/{HOST}/chat").json()["messages"] == []


def test_demo_delete_clears_nothing_and_deletes_nothing(demo_client: TestClient) -> None:
    _seed(demo_client, KEY, ("user", "not the visitor's to delete", "done", None))
    resp = demo_client.delete(f"/api/v1/dossiers/{HOST}/chat")
    assert resp.status_code == 200
    assert resp.json()["messages"] == []
    assert [m.content for m in _messages(demo_client, KEY)] == ["not the visitor's to delete"]


# ── the manager (thin by contract) ──────────────────────────────────────────


def test_prepare_builds_the_host_shape(client: TestClient) -> None:
    """The manager's whole job: a spec the shared engine can run. If this ever
    needs logic copied out of ``general_chat_manager``, the engine (or the
    shared helpers) is missing a seam."""
    from soc_ai.agent.chat_agent import HOST_CHAT_SYSTEM_PROMPT
    from soc_ai.webui.host_chat_manager import _host_spec

    state = _state(client)

    async def _go() -> Any:
        async with state.db_sessionmaker() as db:
            await gc_svc.add_user_message(db, KEY, "older question")
            await gc_svc.finish_assistant(
                db, (await gc_svc.create_pending_assistant(db, KEY)).id, content="older answer"
            )
            await gc_svc.add_user_message(db, KEY, "what is this host doing?")
            row = await gc_svc.create_pending_assistant(db, KEY)
        spec = _host_spec(state, HOST, row.id)
        return spec, await spec.prepare()

    spec, inputs = _run(_go())
    assert spec.label == f"host={HOST}"
    assert spec.timeout_s == state.settings.chat_turn_timeout_s
    assert spec.set_progress is not None
    assert inputs is not None
    assert inputs.system_prompt is HOST_CHAT_SYSTEM_PROMPT
    # Host questions slice telemetry, they do not pivot from an alert.
    assert inputs.oql_flavor == "hunt"
    assert inputs.question == "what is this host doing?"
    assert inputs.prior == [("user", "older question"), ("assistant", "older answer")]
    # The seed names the host the whole conversation is about.
    assert HOST in inputs.seed_context


def test_seed_context_carries_the_dossier_and_grounds_identity(client: TestClient) -> None:
    """seed_context is the corpus ``check_narrative_grounding`` grades against,
    so the correct answer about WHO this host is must come back grounded — the
    same payoff the investigation and general chats already bought."""
    from soc_ai.agent.narrative_grounding import check_narrative_grounding
    from soc_ai.dossier.prompt import HEADING
    from soc_ai.webui.host_chat_manager import _host_spec

    _seed_host_dossier(client)
    state = _state(client)

    async def _go() -> str:
        async with state.db_sessionmaker() as db:
            await gc_svc.add_user_message(db, KEY, "what is this host?")
            row = await gc_svc.create_pending_assistant(db, KEY)
        inputs = await _host_spec(state, HOST, row.id).prepare()
        assert inputs is not None
        return inputs.seed_context

    seed = _run(_go())
    assert HEADING in seed
    assert "role: hypervisor" in seed
    assert "web-01" in seed

    probe = check_narrative_grounding(
        f"**web-01 (hypervisor, {HOST})** — it runs this network's VMs.",
        seed_context=seed,
        tool_evidence=[],
    )
    assert probe.ungrounded == [], probe.ungrounded


def test_an_unswept_host_still_gets_a_seed_naming_it(client: TestClient) -> None:
    """No dossier row is a real state (the page says so out loud) — the chat
    must still anchor on the address rather than fail to prepare."""
    from soc_ai.webui.host_chat_manager import _host_spec

    state = _state(client)

    async def _go() -> str:
        async with state.db_sessionmaker() as db:
            await gc_svc.add_user_message(db, f"host:{OTHER_HOST}", "seen this box before?")
            row = await gc_svc.create_pending_assistant(db, f"host:{OTHER_HOST}")
        inputs = await _host_spec(state, OTHER_HOST, row.id).prepare()
        assert inputs is not None
        return inputs.seed_context

    seed = _run(_go())
    assert OTHER_HOST in seed


def test_the_host_agent_can_propose_a_hunt_but_not_a_verdict(client: TestClient) -> None:
    """ "Show me everything this host talked to in 7d" is exactly a sweep — the
    proposal path must work; and there is no alert here to disposition."""
    from pydantic_ai.models.test import TestModel
    from soc_ai.webui.host_chat_manager import _host_spec

    state = _state(client)

    async def _go() -> dict[str, Any]:
        async with state.db_sessionmaker() as db:
            await gc_svc.add_user_message(db, KEY, "everything this host talked to in 7d?")
            row = await gc_svc.create_pending_assistant(db, KEY)
        inputs = await _host_spec(state, HOST, row.id).prepare()
        assert inputs is not None
        agent = inputs.build_agent(TestModel(), inputs.ctx, "sys")  # type: ignore[misc]
        tools = agent._function_toolset.tools
        assert "propose_hunt" in tools
        assert "propose_verdict" not in tools
        await tools["propose_hunt"].function(
            objective=f"Sweep zeek.conn for every peer of {HOST} over 7d",
            why="one turn cannot cover a week of connections",
        )
        meta: dict[str, Any] = {"tools": []}
        assert inputs.finalize_meta is not None
        inputs.finalize_meta(meta, [], None)
        return meta

    meta = _run(_go())
    assert meta["kind"] == "hunt_proposal"
    assert meta["proposal"] == {
        "objective": f"Sweep zeek.conn for every peer of {HOST} over 7d",
        "why": "one turn cannot cover a week of connections",
    }


def test_no_proposal_leaves_meta_untouched(client: TestClient) -> None:
    from soc_ai.webui.host_chat_manager import _host_spec

    state = _state(client)

    async def _go() -> dict[str, Any]:
        async with state.db_sessionmaker() as db:
            await gc_svc.add_user_message(db, KEY, "what os does it run?")
            row = await gc_svc.create_pending_assistant(db, KEY)
        inputs = await _host_spec(state, HOST, row.id).prepare()
        assert inputs is not None and inputs.finalize_meta is not None
        meta: dict[str, Any] = {"tools": ["t_query_events_oql"]}
        inputs.finalize_meta(meta, [], None)
        return meta

    assert _run(_go()) == {"tools": ["t_query_events_oql"]}


def test_demo_mode_answers_without_building_a_model(client: TestClient) -> None:
    from soc_ai.webui import host_chat_manager as hcm

    demo = client.app.state.settings.model_copy(update={"soc_ai_demo": True})
    state = _state(client, settings=demo)

    async def _go() -> list[Any]:
        async with state.db_sessionmaker() as db:
            row = await gc_svc.create_pending_assistant(db, KEY)
        with patch("soc_ai.webui.chat_turn.build_investigator_model") as build_model:
            await hcm._run_turn(state, HOST, row.id)
        assert not build_model.called, "demo mode must never reach the gateway"
        async with state.db_sessionmaker() as db:
            return await gc_svc.list_messages(db, KEY)

    msgs = _run(_go())
    assert [m.status for m in msgs] == ["done"]
    assert msgs[0].meta == {"demo": True}

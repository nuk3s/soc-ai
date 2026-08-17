"""The Dashboard general chat's HTTP surface + the thin manager behind it (C5).

What these pin, and the failure each one is here to prevent:

* **One rolling thread per caller.** The thread key is the ``identify_caller``
  actor string — the same value ``started_by`` records. Keying it on anything
  else (a cookie, a client-generated id) would either lose the thread on the
  next login or leak one analyst's scratchpad into another's dashboard.
* **The busy 409.** A second POST while a turn is in flight would orphan a
  duplicate pending row and spawn a duplicate agent run — the investigation
  chat's guard, which this surface must not re-learn the hard way.
* **The enabled gate.** An always-available agent on the landing screen is the
  one feature that must be killable live, without a redeploy.
* **The demo short-circuit.** ``soc_ai.demo.chat.canned_reply`` only knows
  ``investigation`` and ``hunt``. Without a branch of its own the Render demo's
  LANDING SCREEN either builds a model (the egress guard raises) or renders an
  error — the first thing a visitor sees. And because that demo has no login,
  every visitor is the SAME caller, so the branch must also answer without
  persisting: a stored thread on a public site is one visitor reading the next
  one's questions.
* **A hunt proposal reaching the client.** ``propose_hunt`` is the whole reason
  this box beats the hand-off it replaces; a proposal that dies in ``meta`` is
  a hunt the analyst never sees.
"""

from __future__ import annotations

import asyncio
from collections.abc import Iterator
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient
from soc_ai.config import Settings
from soc_ai.store import general_chat as gc_svc

from tests.test_webui_api import _client

# With ``api_auth_required=False`` and no session cookie, ``identify_caller``
# resolves every request to this actor — so it is also the thread key the routes
# derive. Named here so a seeding helper and the route agree.
ANON = "anonymous"


@pytest.fixture
def client(settings_kratos: Settings) -> Iterator[TestClient]:
    yield from _client(settings_kratos)


@pytest.fixture
def demo_client(settings_kratos: Settings) -> Iterator[TestClient]:
    """The public Render demo: ``SOC_AI_DEMO`` on, no auth, no grid behind it.

    ``es_hosts`` is moved to loopback because the demo egress guard refuses to
    build an ElasticClient against anything else, and app startup constructs one.
    """
    yield from _client(
        settings_kratos.model_copy(
            update={"soc_ai_demo": True, "es_hosts": ["http://127.0.0.1:9200"]}
        )
    )


@pytest.fixture
def disabled_client(settings_kratos: Settings) -> Iterator[TestClient]:
    """A deployment with the kill switch thrown.

    ``model_copy(update=...)`` seeds the field without validation, so this test
    does not have to wait for the console/setting stage to declare it — and it
    keeps working unchanged once that field exists.
    """
    yield from _client(settings_kratos.model_copy(update={"general_chat_enabled": False}))


def _run(coro: Any) -> Any:
    return asyncio.run(coro)


def _seed(client: TestClient, *rows: tuple[str, str, str, dict[str, Any] | None]) -> list[int]:
    """Write (role, content, status, meta) rows straight into the thread."""

    async def _go() -> list[int]:
        ids: list[int] = []
        async with client.app.state.db_sessionmaker() as db:
            for role, content, status, meta in rows:
                if role == "user":
                    msg = await gc_svc.add_user_message(db, ANON, content)
                else:
                    msg = await gc_svc.create_pending_assistant(db, ANON)
                    if status != "pending":
                        await gc_svc.finish_assistant(
                            db, msg.id, content=content, status=status, meta=meta
                        )
                ids.append(msg.id)
        return ids

    return _run(_go())  # type: ignore[no-any-return]


# ── the three routes ────────────────────────────────────────────────────────


def test_get_thread_is_empty_before_the_first_question(client: TestClient) -> None:
    """Mount cost is one GET; a brand-new analyst must not 404 or error on it."""
    resp = client.get("/api/v1/chat")
    assert resp.status_code == 200
    body = resp.json()
    assert body["messages"] == []
    assert body["pending"] is False
    assert body["progress_tools"] == []


def test_post_writes_the_turn_and_spawns_it(client: TestClient) -> None:
    with patch(
        "soc_ai.webui.general_chat_manager.get_manager", return_value=MagicMock()
    ) as get_mgr:
        resp = client.post("/api/v1/chat", json={"message": "what datasets do I have?"})
    assert resp.status_code == 200
    body = resp.json()
    assert [m["role"] for m in body["messages"]] == ["user", "assistant"]
    assert body["messages"][0]["text"] == "what datasets do I have?"
    assert body["pending"] is True
    start = get_mgr.return_value.start
    start.assert_called_once()
    assert start.call_args.kwargs["thread_key"] == ANON
    assert isinstance(start.call_args.kwargs["assistant_msg_id"], int)


def test_post_rejects_an_empty_message(client: TestClient) -> None:
    with patch("soc_ai.webui.general_chat_manager.get_manager", return_value=MagicMock()):
        resp = client.post("/api/v1/chat", json={"message": "   "})
    assert resp.status_code == 400
    assert resp.json()["detail"]["reason"] == "empty_message"


def test_thread_persists_across_calls(client: TestClient) -> None:
    """The Dashboard is a launcher screen — analysts navigate away mid-answer.
    An ephemeral thread would lose the answer they came back for."""
    _seed(
        client,
        ("user", "what datasets do I have?", "done", None),
        ("assistant", "zeek.conn, zeek.dns, suricata.alert", "done", {"tools": ["t_field_values"]}),
    )
    first = client.get("/api/v1/chat").json()
    second = client.get("/api/v1/chat").json()
    assert [m["text"] for m in first["messages"]] == [
        "what datasets do I have?",
        "zeek.conn, zeek.dns, suricata.alert",
    ]
    assert second == first
    assert first["messages"][1]["tools"] == "t_field_values"


def test_delete_clears_the_thread(client: TestClient) -> None:
    _seed(
        client,
        ("user", "q1", "done", None),
        ("assistant", "a1", "done", None),
    )
    resp = client.delete("/api/v1/chat")
    assert resp.status_code == 200
    assert resp.json()["messages"] == []
    assert client.get("/api/v1/chat").json()["messages"] == []


def test_delete_leaves_other_threads_alone(client: TestClient) -> None:
    """Clearing is per-thread. A DELETE that truncated the table would wipe
    every analyst's history from one analyst's button."""

    async def _seed_other() -> None:
        async with client.app.state.db_sessionmaker() as db:
            await gc_svc.add_user_message(db, "someone-else", "their question")

    _run(_seed_other())
    _seed(client, ("user", "mine", "done", None))
    client.delete("/api/v1/chat")

    async def _others() -> list[Any]:
        async with client.app.state.db_sessionmaker() as db:
            return await gc_svc.list_messages(db, "someone-else")

    assert [m.content for m in _run(_others())] == ["their question"]


# ── one turn at a time ──────────────────────────────────────────────────────


def test_second_post_while_pending_is_409(client: TestClient) -> None:
    _seed(
        client,
        ("user", "first question", "done", None),
        ("assistant", "", "pending", None),
    )
    with patch(
        "soc_ai.webui.general_chat_manager.get_manager", return_value=MagicMock()
    ) as get_mgr:
        resp = client.post("/api/v1/chat", json={"message": "second"})
    assert resp.status_code == 409
    assert resp.json()["detail"]["reason"] == "chat_busy"
    # The guard must fire BEFORE any background turn is spawned.
    get_mgr.return_value.start.assert_not_called()


# ── per-caller keying ───────────────────────────────────────────────────────


def test_threads_are_keyed_per_caller(client: TestClient) -> None:
    """Two analysts on the same appliance get two threads, not one shared one."""
    with (
        patch(
            "soc_ai.api.webui.routes_chat.identify_caller",
            AsyncMock(side_effect=["ana", "ana", "bob"]),
        ),
        patch("soc_ai.webui.general_chat_manager.get_manager", return_value=MagicMock()),
    ):
        client.post("/api/v1/chat", json={"message": "ana's question"})
        ana = client.get("/api/v1/chat").json()
        bob = client.get("/api/v1/chat").json()
    # ana sees her question plus the pending assistant row the POST created.
    assert [m["text"] for m in ana["messages"]] == ["ana's question", ""]
    assert ana["pending"] is True
    assert bob["messages"] == []


def test_an_overlong_caller_string_still_fits_the_column(client: TestClient) -> None:
    """``thread_key`` is a 64-char column and ``token:<name>`` can exceed it. A
    blind truncation would silently merge two long-named tokens into one thread."""
    from soc_ai.api.webui.routes_chat import _thread_key_for

    a = _thread_key_for("token:" + "x" * 60 + "-alpha")
    b = _thread_key_for("token:" + "x" * 60 + "-beta")
    assert len(a) <= 64 and len(b) <= 64
    assert a != b


# ── the public demo: one identity, so nothing may persist ───────────────────
# The Render demo runs with ``api_auth_required=False`` and no login, so
# ``identify_caller`` answers "anonymous" for EVERY visitor. Persisting under
# that key would put one visitor's questions on the next visitor's landing
# screen. These pin the non-persisting demo path that makes that impossible.


def _all_rows(client: TestClient) -> list[Any]:
    """Every general-chat row in the database, whatever thread it is keyed on."""

    async def _go() -> list[Any]:
        from soc_ai.store.models import GeneralChatMessage
        from sqlalchemy import select

        async with client.app.state.db_sessionmaker() as db:
            return list((await db.scalars(select(GeneralChatMessage))).all())

    return _run(_go())  # type: ignore[no-any-return]


def _seed_raw(client: TestClient, thread_key: str, content: str) -> None:
    async def _go() -> None:
        async with client.app.state.db_sessionmaker() as db:
            await gc_svc.add_user_message(db, thread_key, content)

    _run(_go())


def test_demo_answers_the_turn_without_writing_a_row(demo_client: TestClient) -> None:
    """The reply rides back on the POST, so the visitor sees an answer; nothing
    reaches the store, so there is nothing for the next visitor to read."""
    from soc_ai.webui.general_chat_manager import DEMO_REPLY

    with patch(
        "soc_ai.webui.general_chat_manager.get_manager", return_value=MagicMock()
    ) as get_mgr:
        resp = demo_client.post("/api/v1/chat", json={"message": "what datasets do I have?"})
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert [m["role"] for m in body["messages"]] == ["user", "assistant"]
    assert body["messages"][0]["text"] == "what datasets do I have?"
    assert body["messages"][1]["text"] == DEMO_REPLY
    assert body["pending"] is False
    # No background turn: a spawned turn would build the model the egress guard
    # refuses, and would need a stored row to write its answer into.
    get_mgr.return_value.start.assert_not_called()
    assert _all_rows(demo_client) == []


def test_demo_still_rejects_an_empty_message(demo_client: TestClient) -> None:
    """The demo answers differently; it does not validate differently."""
    resp = demo_client.post("/api/v1/chat", json={"message": "   "})
    assert resp.status_code == 400
    assert resp.json()["detail"]["reason"] == "empty_message"


def test_demo_get_never_serves_a_stored_thread(demo_client: TestClient) -> None:
    """Even with a row sitting under the shared anonymous key, a demo GET is
    empty — the no-leak property is a property of this route, not a bet on the
    table having stayed empty."""
    _seed_raw(demo_client, ANON, "the previous visitor's question")
    assert demo_client.get("/api/v1/chat").json()["messages"] == []


def test_demo_delete_clears_nothing_and_deletes_nothing(demo_client: TestClient) -> None:
    """DELETE is allow-listed so the panel's "Clear conversation" control works
    (the demo thread lives in the browser). It must stay a no-op: an
    unauthenticated visitor cannot be given a delete primitive over the store."""
    _seed_raw(demo_client, ANON, "not the visitor's to delete")
    resp = demo_client.delete("/api/v1/chat")
    assert resp.status_code == 200
    assert resp.json()["messages"] == []
    assert [m.content for m in _all_rows(demo_client)] == ["not the visitor's to delete"]


# ── the kill switch ─────────────────────────────────────────────────────────


def test_disabled_refuses_all_three_routes(disabled_client: TestClient) -> None:
    for call in (
        lambda: disabled_client.get("/api/v1/chat"),
        lambda: disabled_client.post("/api/v1/chat", json={"message": "hi"}),
        lambda: disabled_client.delete("/api/v1/chat"),
    ):
        resp = call()
        assert resp.status_code == 403, resp.text
        assert resp.json()["detail"]["reason"] == "general_chat_disabled"


def test_disabled_never_spawns_a_turn(disabled_client: TestClient) -> None:
    with patch(
        "soc_ai.webui.general_chat_manager.get_manager", return_value=MagicMock()
    ) as get_mgr:
        disabled_client.post("/api/v1/chat", json={"message": "hi"})
    get_mgr.return_value.start.assert_not_called()


def test_enabled_by_default(client: TestClient) -> None:
    """Absent the setting entirely (it lands with the config console), the box
    works — a gate that fails closed on a missing field ships a dead feature."""
    assert client.get("/api/v1/chat").status_code == 200


# ── the hunt proposal ───────────────────────────────────────────────────────


def test_hunt_proposal_round_trips_into_the_response(client: TestClient) -> None:
    """The agent proposes; the analyst confirms. The card needs the objective,
    the reason, and the row id — all of which live in ``meta``."""
    ids = _seed(
        client,
        ("user", "is anything beaconing?", "done", None),
        (
            "assistant",
            "Nothing obvious in the last hour — a sweep would settle it.",
            "done",
            {
                "tools": ["t_query_events_oql"],
                "kind": "hunt_proposal",
                "proposal": {
                    "objective": "Sweep zeek.conn for periodic egress over 7d",
                    "why": "one turn cannot cover a week of connections",
                },
            },
        ),
    )
    msgs = client.get("/api/v1/chat").json()["messages"]
    card = [m for m in msgs if m.get("kind") == "hunt_proposal"]
    assert card, msgs
    assert card[0]["messageId"] == ids[1]
    assert card[0]["proposal"]["objective"] == "Sweep zeek.conn for periodic egress over 7d"
    assert card[0]["proposal"]["why"] == "one turn cannot cover a week of connections"


def test_every_route_serializes_the_proposal_the_same_way(client: TestClient) -> None:
    """The SPA renders the thread a POST returns rather than waiting for the next
    poll, so a proposal-blind POST response would blank an already-visible card
    the moment the analyst asked a follow-up. All three routes share one
    serializer; this is the test that notices if one of them stops."""
    _seed(
        client,
        ("user", "is anything beaconing?", "done", None),
        (
            "assistant",
            "A sweep would settle it.",
            "done",
            {"kind": "hunt_proposal", "proposal": {"objective": "Sweep zeek.conn", "why": "7d"}},
        ),
    )
    with patch("soc_ai.webui.general_chat_manager.get_manager", return_value=MagicMock()):
        posted = client.post("/api/v1/chat", json={"message": "what would it cost?"}).json()
    card = [m for m in posted["messages"] if m.get("kind") == "hunt_proposal"]
    assert card, posted["messages"]
    assert card[0]["proposal"]["objective"] == "Sweep zeek.conn"


def test_ordinary_answers_carry_no_proposal(client: TestClient) -> None:
    _seed(client, ("assistant", "3 datasets.", "done", {"tools": ["t_field_values"]}))
    msg = client.get("/api/v1/chat").json()["messages"][0]
    assert msg["kind"] is None
    assert msg["proposal"] is None


# ── the manager (thin by contract) ──────────────────────────────────────────


def _state(client: TestClient, **overrides: Any) -> Any:
    state = client.app.state
    base = {
        "settings": state.settings,
        "db_sessionmaker": state.db_sessionmaker,
        "auth": state.auth,
        "elastic": state.elastic,
        "misp": state.misp,
        "audit": state.audit,
        "enrichment": state.enrichment,
        "demo_fixtures": None,
    }
    base.update(overrides)
    return SimpleNamespace(**base)


def test_demo_mode_answers_without_building_a_model(client: TestClient) -> None:
    from soc_ai.webui import general_chat_manager as gcm

    demo = client.app.state.settings.model_copy(update={"soc_ai_demo": True})
    state = _state(client, settings=demo)

    async def _go() -> list[Any]:
        async with state.db_sessionmaker() as db:
            row = await gc_svc.create_pending_assistant(db, "demo-thread")
        with patch("soc_ai.webui.chat_turn.build_investigator_model") as build_model:
            await gcm._run_turn(state, "demo-thread", row.id)
        assert not build_model.called, "demo mode must never reach the gateway"
        async with state.db_sessionmaker() as db:
            return await gc_svc.list_messages(db, "demo-thread")

    msgs = _run(_go())
    assert [m.status for m in msgs] == ["done"]
    assert msgs[0].meta == {"demo": True}
    assert "demo" in msgs[0].content.lower()


def test_prepare_builds_the_general_shape(client: TestClient) -> None:
    """The manager's whole job: a spec the shared engine can run. If this ever
    needs logic copied out of ``chat_manager``, the engine is missing a seam."""
    from soc_ai.agent.chat_agent import GENERAL_CHAT_SYSTEM_PROMPT
    from soc_ai.webui.general_chat_manager import _general_spec

    state = _state(client)

    async def _go() -> Any:
        async with state.db_sessionmaker() as db:
            await gc_svc.add_user_message(db, "t1", "older question")
            await gc_svc.finish_assistant(
                db, (await gc_svc.create_pending_assistant(db, "t1")).id, content="older answer"
            )
            await gc_svc.add_user_message(db, "t1", "what datasets do I have?")
            row = await gc_svc.create_pending_assistant(db, "t1")
        spec = _general_spec(state, "t1", row.id)
        return spec, await spec.prepare()

    spec, inputs = _run(_go())
    assert spec.label == "thread=t1"
    assert spec.timeout_s == state.settings.chat_turn_timeout_s
    assert spec.set_progress is not None
    assert inputs is not None
    assert inputs.system_prompt is GENERAL_CHAT_SYSTEM_PROMPT
    # Sweep-shaped chat: telemetry-first OQL examples, not alert-pivot ones.
    assert inputs.oql_flavor == "hunt"
    assert inputs.question == "what datasets do I have?"
    assert inputs.prior == [("user", "older question"), ("assistant", "older answer")]
    assert "### This grid" in inputs.seed_context
    assert "Recent posture" in inputs.seed_context


def test_seed_context_carries_the_grid_and_grounds_an_answer_about_it(
    client: TestClient,
) -> None:
    """``seed_context`` is the corpus ``check_narrative_grounding`` grades
    against, so a correct answer about this network ("your internal range is
    192.168.10.0/24", "you collect zeek.dns") has to be IN it — otherwise the chat
    caveats its own true statements as unverified."""
    from ipaddress import ip_network

    from soc_ai.agent.narrative_grounding import check_narrative_grounding
    from soc_ai.oracle.identifiers import EffectiveIdentifiers
    from soc_ai.webui.alerts_query import AlertGroup
    from soc_ai.webui.general_chat_manager import _general_spec

    state = _state(client)
    idents = EffectiveIdentifiers(
        suffixes=("lab.example",), hosts=("sensor01",), cidrs=[ip_network("192.168.10.0/24")]
    )
    groups = [
        AlertGroup("ET NOISY RULE", 412, "medium", "", "e1"),
        AlertGroup("ET QUIETER", 3, "low", "", "e2"),
    ]

    async def _go() -> str:
        async with state.db_sessionmaker() as db:
            await gc_svc.add_user_message(db, "t4", "what do I collect?")
            row = await gc_svc.create_pending_assistant(db, "t4")
        with (
            patch(
                "soc_ai.webui.general_chat_manager.effective_internal_identifiers",
                AsyncMock(return_value=idents),
            ),
            patch(
                "soc_ai.webui.general_chat_manager.inventory_prompt_block",
                AsyncMock(return_value="## Data available on this grid\n- `zeek.dns` — 4k"),
            ),
            patch(
                "soc_ai.webui.general_chat_manager.aq.fetch_groups",
                AsyncMock(return_value=(groups, 415)),
            ),
        ):
            inputs = await _general_spec(state, "t4", row.id).prepare()
        assert inputs is not None
        return inputs.seed_context

    seed = _run(_go())
    assert "192.168.10.0/24" in seed
    assert "zeek.dns" in seed
    assert "ET NOISY RULE" in seed and "412" in seed
    probe = check_narrative_grounding(
        "**Your internal range is 192.168.10.0/24** and you collect zeek.dns.",
        seed_context=seed,
        tool_evidence=[],
    )
    assert probe.grounded, probe.ungrounded


def test_posture_counts_only_the_window(client: TestClient) -> None:
    """A rolling 24h posture line that quietly counted all history would tell an
    analyst last quarter's story as if it were last night's."""
    from datetime import timedelta

    from soc_ai.store import investigations as inv_svc
    from soc_ai.store.auth import utcnow
    from soc_ai.webui.general_chat_manager import _verdict_counts

    async def _go() -> dict[str, int] | None:
        async with client.app.state.db_sessionmaker() as db:
            fresh = await inv_svc.create(db, alert_es_id="ev-fresh", started_by="t")
            await inv_svc.finalize(
                db, fresh.id, status="complete", verdict="true_positive", confidence=0.9
            )
            stale = await inv_svc.create(db, alert_es_id="ev-stale", started_by="t")
            await inv_svc.finalize(
                db, stale.id, status="complete", verdict="false_positive", confidence=0.9
            )
            stale.created_at = utcnow() - timedelta(days=9)
            await db.commit()
            return await _verdict_counts(db)

    assert _run(_go()) == {"true_positive": 1}


def test_the_general_agent_can_propose_a_hunt_but_not_a_verdict(client: TestClient) -> None:
    from pydantic_ai.models.test import TestModel
    from soc_ai.webui.general_chat_manager import _general_spec

    state = _state(client)

    async def _go() -> dict[str, Any]:
        async with state.db_sessionmaker() as db:
            await gc_svc.add_user_message(db, "t2", "is anything beaconing?")
            row = await gc_svc.create_pending_assistant(db, "t2")
        inputs = await _general_spec(state, "t2", row.id).prepare()
        assert inputs is not None
        agent = inputs.build_agent(TestModel(), inputs.ctx, "sys")  # type: ignore[misc]
        tools = agent._function_toolset.tools
        assert "propose_hunt" in tools
        assert "propose_verdict" not in tools
        await tools["propose_hunt"].function(objective="Sweep 7d of zeek.conn", why="needs a week")
        meta: dict[str, Any] = {"tools": []}
        assert inputs.finalize_meta is not None
        inputs.finalize_meta(meta, [], None)
        return meta

    meta = _run(_go())
    assert meta["kind"] == "hunt_proposal"
    assert meta["proposal"] == {"objective": "Sweep 7d of zeek.conn", "why": "needs a week"}


def test_no_proposal_leaves_meta_untouched(client: TestClient) -> None:
    from soc_ai.webui.general_chat_manager import _general_spec

    state = _state(client)

    async def _go() -> dict[str, Any]:
        async with state.db_sessionmaker() as db:
            await gc_svc.add_user_message(db, "t3", "how many datasets?")
            row = await gc_svc.create_pending_assistant(db, "t3")
        inputs = await _general_spec(state, "t3", row.id).prepare()
        assert inputs is not None and inputs.finalize_meta is not None
        meta: dict[str, Any] = {"tools": ["t_field_values"]}
        inputs.finalize_meta(meta, [], None)
        return meta

    assert _run(_go()) == {"tools": ["t_field_values"]}


# ── Host identity for the hosts the thread already names ────────────────────
#
# The dashboard chat has no alert, so there is no endpoint pair to describe.
# What it does have is the conversation: an analyst who types an address has
# named the host they are asking about, and that is the whole in-scope set.
# Seeding the WHOLE network would be a different feature (and an unbounded
# prompt); `t_host_dossier` remains the on-demand route for anything else.

GC_HOST = "192.168.10.202"


def _seed_host_dossier(client: TestClient, ip: str = GC_HOST) -> None:
    from tests.test_dossier_orchestrator import _seed_dossier

    async def _go() -> None:
        await _seed_dossier(client.app.state.db_sessionmaker, ip, hostname="pve-01")

    _run(_go())


def _general_seed_for(client: TestClient, thread: str, question: str) -> str:
    from soc_ai.webui.general_chat_manager import _general_spec

    state = _state(client)

    async def _go() -> Any:
        async with state.db_sessionmaker() as db:
            await gc_svc.add_user_message(db, thread, question)
            row = await gc_svc.create_pending_assistant(db, thread)
        with (
            patch(
                "soc_ai.webui.general_chat_manager.inventory_prompt_block",
                AsyncMock(return_value=""),
            ),
            patch(
                "soc_ai.webui.general_chat_manager.aq.fetch_groups",
                AsyncMock(return_value=([], 0)),
            ),
        ):
            inputs = await _general_spec(state, thread, row.id).prepare()
        assert inputs is not None
        return inputs.seed_context

    return str(_run(_go()))


def test_general_chat_seeds_identity_for_a_host_the_thread_names(client: TestClient) -> None:
    from soc_ai.dossier.prompt import HEADING

    _seed_host_dossier(client)
    seed = _general_seed_for(client, "gc-host", f"what is {GC_HOST} and should it answer SSH?")

    assert HEADING in seed
    assert "role: hypervisor" in seed
    assert "pve-01" in seed


def test_general_chat_answer_naming_that_host_is_grounded(client: TestClient) -> None:
    """Same payoff as the investigation chat: seed_context is the grounding
    corpus, so the correct answer comes back grounded rather than caveated."""
    from soc_ai.agent.narrative_grounding import check_narrative_grounding

    _seed_host_dossier(client)
    seed = _general_seed_for(client, "gc-grounded", f"what is {GC_HOST}?")

    probe = check_narrative_grounding(
        f"**pve-01 (hypervisor, {GC_HOST})** — it runs the network's VMs.",
        seed_context=seed,
        tool_evidence=[],
    )
    assert probe.ungrounded == [], probe.ungrounded


def test_general_chat_seeds_nothing_for_a_thread_that_names_no_host(client: TestClient) -> None:
    """The dossier is not an ambient network dump. A question that names no host
    pays nothing — no block, no store reads."""
    from soc_ai.dossier.prompt import HEADING

    _seed_host_dossier(client)
    seed = _general_seed_for(client, "gc-nohost", "what datasets do I have?")

    assert HEADING not in seed


def test_general_chat_leaves_an_external_address_alone(client: TestClient) -> None:
    """A public address has no dossier and never will; naming it would spend the
    block on a line that only ever says "no record"."""
    from soc_ai.dossier.prompt import HEADING

    _seed_host_dossier(client)
    seed = _general_seed_for(client, "gc-external", "is 8.8.8.8 malicious?")

    assert HEADING not in seed


def test_an_unknown_address_in_the_thread_does_not_ground_itself(client: TestClient) -> None:
    """The self-grounding hole.

    ``check_narrative_grounding`` grounds by PRESENCE IN THE CORPUS, never by
    verifying the claim. This chat sources its addresses from the analyst's
    question AND from ``prior`` — which contains the model's own earlier turns.
    An address with no dossier record used to render a "no dossier" line, and
    that line's text is what grounded the address: so an address the analyst
    typed, or that the MODEL invented last turn, became self-grounding as soon
    as one other host in the thread had a record.

    That is the mixed anchor-plus-fabrication shape the gate exists for.
    """
    from soc_ai.agent.narrative_grounding import check_narrative_grounding

    _seed_host_dossier(client)  # 192.168.10.202 is real; 192.168.10.50 is not
    seed = _general_seed_for(client, "gc-selfground", f"did {GC_HOST} talk to 192.168.10.50?")

    # The real host is described; the address with no record is not mentioned.
    assert "role: hypervisor" in seed
    assert "192.168.10.50" not in seed

    ungrounded = check_narrative_grounding(
        "192.168.10.50 ran a brute-force against pve-01.",
        seed_context=seed,
        tool_evidence=[],
    ).ungrounded
    assert "192.168.10.50" in ungrounded, (
        "an address with no dossier record must still require a tool call"
    )

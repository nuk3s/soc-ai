"""The shared chat TURN ENGINE (design step C1).

``hunt_console_manager`` forked ``chat_manager`` instead of sharing it, and the
hunt chat consequently has no live tool progress, no grounding check and no
regrounding loop — it silently missed both features shipped 2026-08-06. A third
copy for the dashboard general chat would drift the same way, so the
chat-shape-generic half of a turn lives here and every chat shape becomes a
client of it.

These tests pin what "generic" has to mean for the extraction to be worth its
tax: the engine may not reach for one shape's store (it persists ONLY through
the spec's callables), every terminal path — including a failure while the spec
is still being prepared — must resolve the pending row, and the guardrails the
investigation chat earned (grounding caveat, regrounding loop, fabricated-tool
-citation gate, wall-clock timeout) must fire for a caller that is not an
investigation.
"""

from __future__ import annotations

import asyncio
import inspect
from collections.abc import Callable
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

from soc_ai.agent.context import InvestigationContext
from soc_ai.webui.chat_turn import ChatTaskManager, ChatTurnSpec, TurnInputs, run_chat_turn

_TEMPLATE = "You are a test assistant.\n\n## Context\n{context}"


async def _wait_until(
    predicate: Callable[[], bool], *, deadline_s: float = 2.0, interval_s: float = 0.005
) -> None:
    """Poll *predicate* until true or the deadline elapses.

    Replaces fixed sleeps that race a fire-and-forget resolution chain (runner
    step → done-callback via call_soon → backstop task → backstop step): under CI
    contention the process can be descheduled past a fixed sleep and read partial
    state. On timeout this returns quietly so the caller's own assertion reports
    the actual final state.
    """
    loop = asyncio.get_running_loop()
    deadline = loop.time() + deadline_s
    while loop.time() < deadline:
        if predicate():
            return
        await asyncio.sleep(interval_s)


class _Result:
    """Stand-in for a pydantic-ai RunResult: output plus an empty message log."""

    def __init__(self, output: str) -> None:
        self.output = output

    def all_messages(self) -> list[Any]:
        return []


class _Agent:
    """Agent double that replays queued outputs and can report tool progress."""

    def __init__(self, ctx: InvestigationContext, outputs: list[str], *, tools: list[str]) -> None:
        self._ctx = ctx
        self._outputs = list(outputs)
        self._tools = tools
        self.prompts: list[str] = []

    async def run(self, prompt: str) -> _Result:
        self.prompts.append(prompt)
        for name in self._tools:
            if self._ctx.on_tool_call is not None:
                self._ctx.on_tool_call(name)
        return _Result(self._outputs.pop(0) if len(self._outputs) > 1 else self._outputs[0])


def _state(**over: Any) -> MagicMock:
    settings = MagicMock()
    # `is True` comparisons in the engine keep a MagicMock from flipping
    # redaction on, but the regrounding budget is read with int() — pin it so a
    # test's loop count is explicit rather than MagicMock.__int__'s 1.
    settings.chat_regrounding_attempts = 0
    settings.analyst_cloud_redaction = False
    state = MagicMock()
    state.settings = settings
    for k, v in over.items():
        setattr(state.settings, k, v)
    return state


def _ctx(state: MagicMock) -> InvestigationContext:
    return InvestigationContext(settings=state.settings, auth=MagicMock(), elastic=MagicMock())


def _spec(
    *,
    prepare: Any,
    finish: Any,
    timeout_s: float = 30,
    set_progress: Any = None,
) -> ChatTurnSpec:
    return ChatTurnSpec(
        row_id=7,
        label="test=1",
        timeout_s=timeout_s,
        finish=finish,
        prepare=prepare,
        set_progress=set_progress,
    )


class _Finish:
    """Records the terminal write the engine makes through the spec."""

    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    async def __call__(self, *, content: str, status: str, meta: Any) -> None:
        self.calls.append({"content": content, "status": status, "meta": meta})

    @property
    def last(self) -> dict[str, Any]:
        return self.calls[-1]


def _patched() -> Any:
    """Patch the two gateway/grid calls the engine makes on every turn."""
    return patch.multiple(
        "soc_ai.webui.chat_turn",
        build_investigator_model=MagicMock(),
        inventory_prompt_block=AsyncMock(return_value=""),
    )


# ── shape-agnosticism ───────────────────────────────────────────────────────


def test_engine_never_reaches_for_one_shapes_store() -> None:
    """The whole point of the extraction: persistence goes through the spec.

    A direct ``chat_svc``/``hunt_svc`` call here would re-couple the engine to
    the investigation table and force the next chat shape to fork again.
    """
    from soc_ai.webui import chat_turn

    src = inspect.getsource(chat_turn)
    for coupled in (
        "chat_svc",
        "hunt_svc",
        "inv_svc",
        "finish_assistant",
        "get_alert_context",
        "investigation_id",
    ):
        assert coupled not in src, f"engine is coupled to {coupled}"


def test_investigation_manager_delegates_to_the_shared_engine() -> None:
    """The investigation chat must be a CLIENT of the engine — a manager that
    kept its own copy of the turn body is exactly the fork being removed."""
    from soc_ai.webui import chat_manager

    src = inspect.getsource(chat_manager)
    assert "run_chat_turn" in src
    assert "asyncio.timeout" not in src  # the wall clock lives in the engine now
    assert "check_narrative_grounding" not in src  # so does the grounding gate


# ── the happy path + the spec seams ─────────────────────────────────────────


async def test_success_persists_through_the_spec_finish() -> None:
    state = _state()
    ctx = _ctx(state)
    finish = _Finish()

    async def _prepare() -> TurnInputs:
        return TurnInputs(
            ctx=ctx,
            seed_context="Grid: lab",
            question="what is up?",
            system_prompt=_TEMPLATE,
            build_agent=lambda _m, c, _p: _Agent(c, ["Nothing unusual."], tools=[]),
        )

    with _patched():
        await run_chat_turn(state, _spec(prepare=_prepare, finish=finish))

    assert finish.last["status"] == "done"
    assert finish.last["content"] == "Nothing unusual."
    assert finish.last["meta"]["tools"] == []
    assert finish.last["meta"]["narrative_grounding"] == {"grounded": True}


async def test_prepare_returning_none_leaves_the_row_to_the_caller() -> None:
    """The demo short-circuit: prepare answers the row itself and tells the
    engine to stop, so no model is ever built (the egress guard would raise)."""
    state = _state()
    finish = _Finish()
    built = MagicMock()

    async def _prepare() -> None:
        return None

    with patch.multiple(
        "soc_ai.webui.chat_turn",
        build_investigator_model=built,
        inventory_prompt_block=AsyncMock(return_value=""),
    ):
        await run_chat_turn(state, _spec(prepare=_prepare, finish=finish))

    assert finish.calls == []
    built.assert_not_called()


async def test_prepare_failure_still_lands_a_terminal_row() -> None:
    """Spec building loads the grid/DB and can fail. If that failure escaped
    the engine the pending row would hang until the reaper swept it."""
    state = _state()
    finish = _Finish()

    async def _prepare() -> TurnInputs:
        raise RuntimeError("investigation not found")

    with _patched():
        await run_chat_turn(state, _spec(prepare=_prepare, finish=finish))

    assert finish.last["status"] == "error"
    assert "investigation not found" in finish.last["content"]


async def test_terminal_error_content_is_scrubbed() -> None:
    """The exception text becomes analyst-visible content — a verbose gateway
    body echoing an Authorization header must not be stored verbatim."""
    state = _state()
    finish = _Finish()
    secret = "sk-live-abc123SECRET"  # pragma: allowlist secret

    async def _prepare() -> TurnInputs:
        raise RuntimeError(f"gateway 401: Authorization: Bearer {secret}")

    with _patched():
        await run_chat_turn(state, _spec(prepare=_prepare, finish=finish))

    assert secret not in finish.last["content"]


async def test_timeout_uses_the_specs_clock_not_a_settings_key() -> None:
    """Each chat shape carries its own budget (the hunt chat's is minutes, the
    investigation chat's is seconds), so the deadline is spec state — and it
    must raise TimeoutError, which the error path catches, never a
    CancelledError that would leave the row pending forever."""
    state = _state()
    ctx = _ctx(state)
    finish = _Finish()

    class _Slow:
        async def run(self, _prompt: str) -> _Result:
            await asyncio.sleep(5)
            raise AssertionError("unreachable")

    async def _prepare() -> TurnInputs:
        return TurnInputs(
            ctx=ctx,
            seed_context="Grid: lab",
            question="q",
            system_prompt=_TEMPLATE,
            build_agent=lambda _m, _c, _p: _Slow(),
        )

    with _patched():
        await run_chat_turn(state, _spec(prepare=_prepare, finish=finish, timeout_s=0.01))

    assert finish.last["status"] == "error"
    assert "ran out of time" in finish.last["content"]
    assert "0.01" in finish.last["content"]
    assert "narrower" in finish.last["content"]


async def test_a_stuck_finish_after_the_answer_is_produced_still_resolves() -> None:
    """Live incident (2026-08-21): a turn's answer was already generated —
    the agent-run's own ``asyncio.timeout(spec.timeout_s)`` block had already
    exited normally — but the tail after it (grounding re-check, ground-or-
    strip redaction, finalize_meta, ``spec.finish``'s DB write) ran with NO
    wall clock at all, because it sits entirely outside that block. On the
    live turn this tail contended with a concurrent background job for the
    same SQLite database and took several minutes instead of the
    milliseconds it normally costs; nothing would have caught it even if the
    contention had never cleared. This pins that the tail now gets its own
    bounded timeout, distinct from the agent-run one (a different, accurate
    message — not "narrower follow-up", which is about the LLM/tool loop,
    not persistence)."""
    state = _state()
    ctx = _ctx(state)
    calls: list[dict[str, Any]] = []

    async def _stuck_finish(*, content: str, status: str, meta: Any) -> None:
        calls.append({"content": content, "status": status, "meta": meta})
        if status == "done":
            await asyncio.sleep(10)  # simulates a contended/stuck DB write

    async def _prepare() -> TurnInputs:
        return TurnInputs(
            ctx=ctx,
            seed_context="Grid: lab",
            question="q",
            system_prompt=_TEMPLATE,
            build_agent=lambda _m, c, _p: _Agent(c, ["Nothing unusual."], tools=[]),
        )

    with _patched(), patch("soc_ai.webui.chat_turn._TAIL_TIMEOUT_S", 0.02):
        # The wait_for is a test-harness safety net, not the mechanism under
        # test: on unfixed code this call never returns (spec.finish hangs
        # with nothing bounding it), so without it a regression would hang
        # the whole suite instead of failing this one test.
        await asyncio.wait_for(
            run_chat_turn(state, _spec(prepare=_prepare, finish=_stuck_finish)), timeout=2.0
        )

    assert calls[0]["status"] == "done"  # the answer was produced and an attempt made to save it
    assert calls[-1]["status"] == "error"  # the tail's own timeout unstuck the row
    assert "ran out of time saving the reply" in calls[-1]["content"]
    assert "narrower follow-up" not in calls[-1]["content"]  # not the agent-run's message


async def test_progress_rides_the_specs_writer() -> None:
    """Live tool progress is generic plumbing; only the WRITE is shape-specific
    (a different table per shape), so the engine hands snapshots to the spec."""
    state = _state()
    ctx = _ctx(state)
    finish = _Finish()
    seen: list[list[str]] = []

    async def _write(tools: list[str]) -> None:
        seen.append(tools)

    async def _prepare() -> TurnInputs:
        return TurnInputs(
            ctx=ctx,
            seed_context="Grid: lab",
            question="q",
            system_prompt=_TEMPLATE,
            build_agent=lambda _m, c, _p: _Agent(
                c, ["Nothing unusual."], tools=["t_query_events_oql", "t_enrich_ip"]
            ),
        )

    with _patched():
        await run_chat_turn(state, _spec(prepare=_prepare, finish=finish, set_progress=_write))
        await asyncio.sleep(0.05)  # progress writes are fire-and-forget tasks

    assert seen == [["t_query_events_oql"], ["t_query_events_oql", "t_enrich_ip"]]


async def test_progress_write_failure_never_fails_the_turn() -> None:
    """Progress is cosmetic — a broken writer must not cost the analyst the answer."""
    state = _state()
    ctx = _ctx(state)
    finish = _Finish()

    async def _write(_tools: list[str]) -> None:
        raise RuntimeError("db gone")

    async def _prepare() -> TurnInputs:
        return TurnInputs(
            ctx=ctx,
            seed_context="Grid: lab",
            question="q",
            system_prompt=_TEMPLATE,
            build_agent=lambda _m, c, _p: _Agent(c, ["Nothing unusual."], tools=["t_enrich_ip"]),
        )

    with _patched():
        await run_chat_turn(state, _spec(prepare=_prepare, finish=finish, set_progress=_write))
        await asyncio.sleep(0.05)

    assert finish.last["status"] == "done"


async def test_inventory_is_appended_by_default() -> None:
    """The investigation/hunt chats get the dataset inventory appended to their
    system prompt — they have no other route to knowing what telemetry exists."""
    state = _state()
    ctx = _ctx(state)
    finish = _Finish()
    prompts: list[str] = []

    def _build(_m: Any, c: InvestigationContext, p: str) -> _Agent:
        prompts.append(p)
        return _Agent(c, ["ok"], tools=[])

    async def _prepare() -> TurnInputs:
        return TurnInputs(
            ctx=ctx,
            seed_context="Grid: lab",
            question="q",
            system_prompt=_TEMPLATE,
            build_agent=_build,
        )

    with patch.multiple(
        "soc_ai.webui.chat_turn",
        build_investigator_model=MagicMock(),
        inventory_prompt_block=AsyncMock(return_value="\n## Datasets\nzeek.dns (12)"),
    ):
        await run_chat_turn(state, _spec(prepare=_prepare, finish=finish))

    assert prompts[0].count("zeek.dns (12)") == 1


async def test_a_shape_that_seeds_its_own_inventory_opts_out() -> None:
    """The general chat puts the inventory INSIDE seed_context, because
    seed_context is the corpus ``check_narrative_grounding`` grades the answer
    against — without it, "what datasets do I have" (the canonical question that
    chat exists to answer) comes back wearing an Unverified caveat. Appending it
    a second time would spend prompt budget restating what the anchor already
    says, and invite the model to treat two renderings as two sources.
    """
    state = _state()
    ctx = _ctx(state)
    finish = _Finish()
    prompts: list[str] = []

    def _build(_m: Any, c: InvestigationContext, p: str) -> _Agent:
        prompts.append(p)
        return _Agent(c, ["ok"], tools=[])

    async def _prepare() -> TurnInputs:
        return TurnInputs(
            ctx=ctx,
            seed_context="Grid: lab\n## Datasets\nzeek.dns (12)",
            question="q",
            system_prompt=_TEMPLATE,
            build_agent=_build,
            append_inventory=False,
        )

    with patch.multiple(
        "soc_ai.webui.chat_turn",
        build_investigator_model=MagicMock(),
        inventory_prompt_block=AsyncMock(return_value="\n## Datasets\nzeek.dns (12)"),
    ):
        await run_chat_turn(state, _spec(prepare=_prepare, finish=finish))

    assert prompts[0].count("zeek.dns (12)") == 1


async def test_finalize_meta_hook_sees_the_turns_evidence() -> None:
    """The verdict-proposal sink (and the general chat's hunt proposal) is
    shape-specific, so the engine offers a seam rather than knowing about either."""
    state = _state()
    ctx = _ctx(state)
    finish = _Finish()
    handed: dict[str, Any] = {}

    def _finalize(meta: dict[str, Any], evidence: list[dict[str, Any]], guard: Any) -> None:
        handed["evidence"] = evidence
        handed["guard"] = guard
        meta["kind"] = "hunt_proposal"

    async def _prepare() -> TurnInputs:
        return TurnInputs(
            ctx=ctx,
            seed_context="Grid: lab",
            question="q",
            system_prompt=_TEMPLATE,
            build_agent=lambda _m, c, _p: _Agent(c, ["Nothing unusual."], tools=[]),
            finalize_meta=_finalize,
        )

    with _patched():
        await run_chat_turn(state, _spec(prepare=_prepare, finish=finish))

    assert finish.last["meta"]["kind"] == "hunt_proposal"
    assert handed["evidence"] == []
    assert handed["guard"] is None


# ── the guardrails, exercised through a non-investigation shape ─────────────


async def test_ungrounded_answer_is_redacted_for_any_chat_shape() -> None:
    """Ground-or-strip (2026-08-20): once regrounding is exhausted, an
    ungrounded specific is mechanically replaced in the visible answer — not
    named inline under a "verify before acting" caveat. This must fire
    identically regardless of which chat shape is running (the whole point of
    the shared engine)."""
    state = _state()
    ctx = _ctx(state)
    finish = _Finish()

    async def _prepare() -> TurnInputs:
        return TurnInputs(
            ctx=ctx,
            seed_context="Grid: lab",
            question="q",
            system_prompt=_TEMPLATE,
            build_agent=lambda _m, c, _p: _Agent(
                c, ["The host resolved evil.example.com repeatedly."], tools=[]
            ),
        )

    with _patched():
        await run_chat_turn(state, _spec(prepare=_prepare, finish=finish))

    assert finish.last["meta"]["narrative_grounding"]["grounded"] is False
    assert "evil.example.com" in finish.last["meta"]["narrative_grounding"]["ungrounded"]
    assert finish.last["meta"]["narrative_grounding"]["stripped"] == ["evil.example.com"]
    assert "evil.example.com" not in finish.last["content"]
    assert "(unverified)" in finish.last["content"]
    assert "Some unverifiable specifics were removed" in finish.last["content"]
    assert "⚠" not in finish.last["content"]


async def test_ungrounded_artifact_and_fabricated_citation_both_get_redacted() -> None:
    """Leak found in review (2026-08-20): when Layer 2 (the ungrounded-artifact
    check) already fired, F1's merge branch updated meta's reason to say
    fabricated citations were caught but never actually redacted the citation
    text from the answer — the phrase shipped in the content while meta
    claimed it was handled. A confabulating zero-tool model is likely to
    produce BOTH shapes in the same breath (an ungrounded artifact AND a fake
    "verified by the tools" claim), so the intersection needs its own pin, not
    just each half alone."""
    state = _state()
    ctx = _ctx(state)
    finish = _Finish()

    async def _prepare() -> TurnInputs:
        return TurnInputs(
            ctx=ctx,
            seed_context="Grid: lab",
            question="q",
            system_prompt=_TEMPLATE,
            build_agent=lambda _m, c, _p: _Agent(
                c,
                ["The host resolved evil.example.com repeatedly. Verified by the tools."],
                tools=[],
            ),
        )

    with _patched():
        await run_chat_turn(state, _spec(prepare=_prepare, finish=finish))

    content = finish.last["content"]
    grounding = finish.last["meta"]["narrative_grounding"]

    assert grounding["grounded"] is False
    assert "evil.example.com" not in content
    assert "Verified by the tools" not in content
    assert "(unverified)" in content
    # Exactly one quiet line — not one per detector that fired.
    assert content.count("Some unverifiable specifics were removed") == 1
    assert "⚠" not in content
    # Both causes are on the record, not just whichever fired last.
    assert "evil.example.com" in grounding["ungrounded"]
    assert "evil.example.com" in grounding["reason"]
    assert "fabricated tool citations" in grounding["reason"]
    assert any("evil.example.com" in s for s in grounding["stripped"])
    assert any("verified by the tools" in s.lower() for s in grounding["stripped"])


async def test_regrounding_loop_reruns_the_agent_and_records_the_attempt() -> None:
    """Detecting a fabrication and publishing it anyway is not a guardrail: the
    finding goes back to the agent, bounded by chat_regrounding_attempts."""
    state = _state(chat_regrounding_attempts=1)
    ctx = _ctx(state)
    finish = _Finish()
    agents: list[_Agent] = []

    def _build(_m: Any, c: InvestigationContext, _p: str) -> _Agent:
        agent = _Agent(
            c,
            [
                "The host resolved evil.example.com repeatedly.",
                "I have not pulled that host's DNS.",
            ],
            tools=[],
        )
        agents.append(agent)
        return agent

    async def _prepare() -> TurnInputs:
        return TurnInputs(
            ctx=ctx,
            seed_context="Grid: lab",
            question="q",
            system_prompt=_TEMPLATE,
            build_agent=_build,
        )

    with _patched():
        await run_chat_turn(state, _spec(prepare=_prepare, finish=finish))

    assert len(agents[0].prompts) == 2
    assert "CORRECTION REQUIRED" in agents[0].prompts[1]
    assert finish.last["meta"]["regrounding_attempts"] == 1
    assert finish.last["meta"]["narrative_grounding"] == {"grounded": True}
    assert "Unverified" not in finish.last["content"]


async def test_fabricated_tool_citations_on_a_zero_tool_turn_are_redacted() -> None:
    """An answer that cites tools it never ran is fabricated evidence, even
    when it asserts no artifact for the grounding check to catch. Same
    ground-or-strip policy as an ungrounded identifier: the fabricated
    citation text is stripped, not caveated."""
    state = _state()
    ctx = _ctx(state)
    finish = _Finish()

    async def _prepare() -> TurnInputs:
        return TurnInputs(
            ctx=ctx,
            seed_context="Grid: lab",
            question="q",
            system_prompt=_TEMPLATE,
            build_agent=lambda _m, c, _p: _Agent(
                c, ["This looks benign. Verified by the tools."], tools=[]
            ),
        )

    with _patched():
        await run_chat_turn(state, _spec(prepare=_prepare, finish=finish))

    assert finish.last["meta"]["tools"] == []
    assert finish.last["meta"]["narrative_grounding"]["grounded"] is False
    assert finish.last["meta"]["narrative_grounding"]["stripped"]
    assert "Verified by the tools" not in finish.last["content"]
    assert "(unverified)" in finish.last["content"]
    assert "Some unverifiable specifics were removed" in finish.last["content"]
    assert "⚠" not in finish.last["content"]


# ── the task tracker ────────────────────────────────────────────────────────


async def test_clean_runner_does_not_fire_the_backstop() -> None:
    mgr = ChatTaskManager()
    fired: list[int] = []

    async def _ok() -> None:
        return None

    async def _backstop() -> None:
        fired.append(1)

    mgr.spawn(row_id=1, runner=_ok(), backstop=_backstop)
    # Wait for the done-callback to resolve the row (remove it from the registry)
    # instead of racing a fixed sleep against the resolution chain.
    await _wait_until(lambda: 1 not in mgr._tasks)
    assert 1 not in mgr._tasks
    assert fired == []  # a clean runner never spawns the backstop


async def test_backstop_fires_when_the_runner_raises() -> None:
    """Defense in depth: an exception that escapes the runner would otherwise
    leave the row pending forever."""
    mgr = ChatTaskManager()
    fired: list[int] = []

    async def _boom() -> None:
        raise RuntimeError("escaped")

    async def _backstop() -> None:
        fired.append(1)

    mgr.spawn(row_id=2, runner=_boom(), backstop=_backstop)
    # Wait for the backstop to actually fire, not a fixed sleep.
    await _wait_until(lambda: fired == [1])
    assert fired == [1]
    assert 2 not in mgr._tasks


async def test_backstop_fires_when_the_task_is_cancelled() -> None:
    """Shutdown cancels in-flight turns; CancelledError is a BaseException the
    runner's own handler never sees, so the tracker has to resolve the row."""
    mgr = ChatTaskManager()
    fired: list[int] = []

    async def _hang() -> None:
        await asyncio.sleep(10)

    async def _backstop() -> None:
        fired.append(1)

    mgr.spawn(row_id=3, runner=_hang(), backstop=_backstop)
    await asyncio.sleep(0)  # let the task reach its first await before cancelling
    mgr._tasks[3].cancel()
    # Wait for the cancellation to drive the backstop, not a fixed sleep.
    await _wait_until(lambda: fired == [1])
    assert fired == [1]

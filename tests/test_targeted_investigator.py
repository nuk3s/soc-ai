"""Tests for soc_ai.agent.targeted_investigator (Phase D)."""

from __future__ import annotations

from typing import Any, ClassVar

import pytest
from soc_ai.agent.targeted_investigator import (
    build_targeted_investigator_prompt,
    run_targeted_investigation,
)
from soc_ai.agent.triage import TargetedGap


def test_build_targeted_investigator_prompt_includes_args() -> None:
    gap = TargetedGap(
        question="What was the SSL SNI for community_id 1:abc?",
        tool_name="t_query_zeek_logs",
        tool_args={"community_id": "1:abc", "log_types": ["ssl"]},
        why_this_matters="If api.giphy.com -> FP.",
    )
    p = build_targeted_investigator_prompt(gap)
    assert "What was the SSL SNI" in p
    assert "t_query_zeek_logs" in p
    assert "community_id" in p
    assert "do not call any other tool" in p.lower()


@pytest.mark.asyncio
async def test_run_targeted_investigation_dispatches_named_tool(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """run_targeted_investigation invokes ONLY the named tool with the named args."""
    called: list[tuple[str, dict[str, Any]]] = []

    async def fake_dispatch(tool_name: str, tool_args: dict[str, Any], ctx: Any) -> dict[str, Any]:
        called.append((tool_name, dict(tool_args)))
        return {"sni_servers": ["api.giphy.com"]}

    monkeypatch.setattr("soc_ai.agent.targeted_investigator._dispatch_named_tool", fake_dispatch)

    gap = TargetedGap(
        question="What was the SSL SNI?",
        tool_name="t_query_zeek_logs",
        tool_args={"community_id": "1:abc"},
        why_this_matters="x",
    )

    class _StubCtx:
        pass

    result = await run_targeted_investigation(gap, ctx=_StubCtx())
    assert result == {"sni_servers": ["api.giphy.com"]}
    assert called == [("t_query_zeek_logs", {"community_id": "1:abc"})]


@pytest.mark.asyncio
async def test_run_targeted_investigation_returns_string_on_dispatch_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """If the named tool raises, return a string error message (not raise)."""

    async def boom(tool_name: str, tool_args: dict[str, Any], ctx: Any) -> dict[str, Any]:
        raise RuntimeError("simulated tool failure")

    monkeypatch.setattr("soc_ai.agent.targeted_investigator._dispatch_named_tool", boom)

    gap = TargetedGap(
        question="x",
        tool_name="t_enrich_ip",
        tool_args={"ip": "1.2.3.4"},
        why_this_matters="x",
    )

    class _StubCtx:
        pass

    result = await run_targeted_investigation(gap, ctx=_StubCtx())
    assert isinstance(result, str)
    assert "RuntimeError" in result
    assert "simulated tool failure" in result


@pytest.mark.asyncio
async def test_run_targeted_investigation_arg_type_error_returns_structured_message(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A wrong-typed value for a valid kwarg
    name must surface as a structured string error that names the tool, the
    offending args, and the exception message — NOT an opaque traceback.
    The error is returned (not raised) via run_targeted_investigation's
    existing exception→string error channel."""

    class _StubCtx:
        pass

    # Patch _dispatch_named_tool to raise a structured TypeError, simulating
    # what the new _raise_arg_type_error helper produces for valid-named /
    # wrong-typed args.
    async def _dispatch_raises_type_error(
        tool_name: str, tool_args: dict[str, Any], ctx: Any
    ) -> dict[str, Any]:
        raise TypeError(
            f"tool {tool_name} rejected arguments {tool_args!r}: "
            "expected str for 'domain', got int — re-call with corrected argument types"
        )

    monkeypatch.setattr(
        "soc_ai.agent.targeted_investigator._dispatch_named_tool",
        _dispatch_raises_type_error,
    )

    gap = TargetedGap(
        question="What MISP hits for this domain?",
        tool_name="t_enrich_domain",
        tool_args={"domain": 12345},  # wrong type: int instead of str
        why_this_matters="domain IOC check",
    )

    result = await run_targeted_investigation(gap, ctx=_StubCtx())

    # Must be returned as a string — not raised.
    assert isinstance(result, str), "error must be returned as a string, not raised"
    # Three required components: tool name, offending args, exception message.
    assert "t_enrich_domain" in result, "tool name must appear in the error string"
    assert "12345" in result or "domain" in result, (
        "offending arg value or name must appear in the error string"
    )
    assert "re-call with corrected argument types" in result, (
        "actionable hint must appear in the error string"
    )


@pytest.mark.asyncio
async def test_dispatch_named_tool_arg_type_error_structured(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """D4: _dispatch_named_tool on a valid-named, wrong-typed kwarg (no
    hallucinated kwarg names) produces a TypeError whose message contains
    the tool name, the offending args repr, and the original exception —
    so that run_targeted_investigation's error channel surfaces all three."""
    import soc_ai.tools.enrichment as enrich_mod

    class _StubCtx:
        class _Settings:
            pass

        def __init__(self) -> None:
            self.settings = self._Settings()
            self.misp = None
            self.blocklist = None

    # A replacement for enrich_domain that raises TypeError immediately.
    # It must NOT accept **kwargs (no VAR_KEYWORD) so the dispatch code hits
    # the "no unknown kwargs → _raise_arg_type_error" branch, not the
    # has_var_keyword branch.
    async def _strict_enrich_domain(domain: str, settings: Any, misp: Any, blocklist: Any) -> None:  # type: ignore[return]
        raise TypeError("domain must be str, got int")

    monkeypatch.setattr(enrich_mod, "enrich_domain", _strict_enrich_domain)

    from soc_ai.agent.targeted_investigator import run_targeted_investigation

    gap = TargetedGap(
        question="q",
        tool_name="t_enrich_domain",
        tool_args={"domain": 42},  # wrong type — valid kwarg name
        why_this_matters="type-error test",
    )

    result = await run_targeted_investigation(gap, ctx=_StubCtx())

    assert isinstance(result, str), "result must be a string error message"
    # Tool name must be present.
    assert "t_enrich_domain" in result, f"tool name missing from: {result!r}"
    # Offending arg value or name must be present.
    assert "42" in result or "domain" in result, f"offending arg missing from: {result!r}"
    # Exception message must be present.
    assert "domain must be str" in result or "TypeError" in result, (
        f"exception message missing from: {result!r}"
    )
    # Actionable re-call hint from _raise_arg_type_error.
    assert "re-call with corrected argument types" in result, (
        f"re-call hint missing from: {result!r}"
    )


@pytest.mark.asyncio
async def test_raise_arg_type_error_clamps_long_repr(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """_raise_arg_type_error clamps args repr to 400 chars so a giant arg value
    does not waste tokens in the synth-visible error string."""
    import soc_ai.tools.enrichment as enrich_mod

    class _StubCtx:
        class _Settings:
            pass

        def __init__(self) -> None:
            self.settings = self._Settings()
            self.misp = None
            self.blocklist = None

    # enrich_domain stub with no **kwargs so the dispatch hits _raise_arg_type_error.
    async def _strict_enrich_domain(domain: str, settings: Any, misp: Any, blocklist: Any) -> None:  # type: ignore[return]
        raise TypeError("domain must be str, got int")

    monkeypatch.setattr(enrich_mod, "enrich_domain", _strict_enrich_domain)

    from soc_ai.agent.targeted_investigator import run_targeted_investigation

    # A >400-char arg value to trigger the clamp.
    long_value = "x" * 500
    gap = TargetedGap(
        question="q",
        tool_name="t_enrich_domain",
        tool_args={"domain": long_value},
        why_this_matters="clamp test",
    )

    result = await run_targeted_investigation(gap, ctx=_StubCtx())

    assert isinstance(result, str), "result must be a string error message"
    # The clamp marker must appear in the error string.
    assert "…" in result, "clamp ellipsis must appear when repr exceeds 400 chars"
    # The error string itself must be bounded — repr({'domain': 'x'*500}) is ~506 chars,
    # so without clamping the result would be much longer. With the 400-char clamp,
    # the total error string must be well under 600 chars.
    assert len(result) <= 600, f"clamped error string must be bounded; got {len(result)} chars"


@pytest.mark.asyncio
async def test_dispatch_es_query_tools_bind_without_auth_typeerror(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Regression: Phase D must bind the ES-query tool family without injecting
    kwargs the target signatures reject.

    The dispatcher injects ``elastic`` (and historically ``auth``) for the five
    ES-query tools, but none of ``query_events_oql`` / ``query_zeek_logs`` /
    ``query_cases`` / ``query_detections`` / ``get_playbooks`` declares ``auth``
    or ``**kwargs`` — so an ``auth`` injection made every real dispatch raise
    ``TypeError: ... unexpected keyword argument 'auth'``. Every prior test
    monkeypatched ``_dispatch_named_tool`` itself, so the real binding was never
    exercised. This test drives the real dispatcher with a stub elastic and
    asserts the tool runs (no arg-binding TypeError leaks out as an error
    string).
    """
    from soc_ai.agent.targeted_investigator import _dispatch_named_tool

    class _StubElastic:
        async def search(self, *a: Any, **k: Any) -> dict[str, Any]:
            return {"hits": {"hits": [], "total": {"value": 0}}, "aggregations": {}}

    class _Settings:
        events_index_pattern = "logs-*"
        oql_allowed_fields: ClassVar[set[str]] = set()

    class _StubCtx:
        settings = _Settings()
        elastic = _StubElastic()
        auth = object()  # present on ctx — must NOT be forwarded to the query tools

    # A minimal valid OQL query; the stub elastic returns an empty result set.
    out = await _dispatch_named_tool(
        "t_query_events_oql",
        {"query": "event.dataset:zeek.dns", "time_range_minutes": 240},
        _StubCtx(),
    )
    # A successful bind returns a dict (model_dump of EsSearchResult); a binding
    # failure would have raised TypeError inside the dispatcher.
    assert isinstance(out, dict)

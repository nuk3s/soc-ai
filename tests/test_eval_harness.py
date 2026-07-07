"""Integration tests for the eval harness end-to-end flow.

These tests stub two boundaries — :func:`investigate` (so we never
hit Elasticsearch / LiteLLM) and :func:`call_oracle` (so we never
hit the network) — and verify the harness wires sanitize, prompt
build, mapping, and bundle save together correctly.

The contract under test:

- the bundle directory layout is exactly the five files the spec
  promised (``response.md``, ``events.jsonl``, ``request.json``,
  ``mapping.json``, ``meta.json``);
- the response written to ``response.md`` is *de-sanitized* (the
  operator should read real internal hostnames in the oracle's
  critique, not opaque labels);
- what gets sent to LiteLLM is *sanitized* — no raw private IPs
  or internal hostnames in the user message;
- ``meta.json`` records the verdict, model, token usage, and
  redaction summary so we can compare runs;
- if no LITELLM_API_KEY is configured, the harness raises before
  spending money or doing the run.
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import pytest
from pydantic import SecretStr
from soc_ai.agent.orchestrator import StepEvent
from soc_ai.config import Settings
from soc_ai.eval import harness as harness_mod
from soc_ai.eval.harness import run as harness_run
from soc_ai.eval.oracle_client import OracleError, OracleResponse

# --------------------------------------------------------------------
# Fixtures
# --------------------------------------------------------------------


def _settings_for_eval() -> Settings:
    """Settings with the LiteLLM env populated so the harness proceeds."""
    return Settings(
        so_host="https://so.example.com",
        so_username="analyst",
        so_password=SecretStr("password123"),
        so_verify_ssl=False,
        es_hosts=["https://so.example.com:9200"],
        litellm_base_url="http://litellm.test:4000",
        litellm_api_key=SecretStr("test-litellm-key"),
        litellm_verify_ssl=False,
        claude_oracle_model="claude-opus-4-7",
        claude_oracle_max_tokens=4096,
    )


def _fake_events(alert_id: str) -> list[StepEvent]:
    """A canned event trail with deliberately internal-looking strings.

    Mirrors the shape of a real soc-ai investigation:
    session_start → alert_context → tool_call → tool_result →
    investigation_transcript → triage_report → done.
    """
    sid = "sess0001"
    return [
        StepEvent(
            kind="session_start",
            session_id=sid,
            sequence=1,
            payload={"alert_id": alert_id},
        ),
        StepEvent(
            kind="alert_context",
            session_id=sid,
            sequence=2,
            payload={
                "alert": {
                    "_id": alert_id,
                    "source.ip": "10.20.30.148",
                    "destination.ip": "8.8.8.8",
                    "host.name": "app01.lan",
                    "process.executable": "/home/user/bin/agent",
                }
            },
        ),
        StepEvent(
            kind="tool_call",
            session_id=sid,
            sequence=3,
            payload={
                "tool_name": "t_enrich_ip",
                "args": {"ip": "10.20.30.148"},
            },
        ),
        StepEvent(
            kind="tool_result",
            session_id=sid,
            sequence=4,
            payload={
                "tool_name": "t_enrich_ip",
                "result": {"ip": "10.20.30.148", "internal": True},
            },
        ),
        StepEvent(
            kind="investigation_transcript",
            session_id=sid,
            sequence=5,
            payload={
                "evidence": ["10.20.30.148 is internal RFC1918"],
                "tentative_summary": "app01.lan made a benign DNS query.",
                "open_questions": [],
            },
        ),
        StepEvent(
            kind="triage_report",
            session_id=sid,
            sequence=6,
            payload={
                "verdict": "false_positive",
                "confidence": 0.85,
                "summary": "app01.lan resolved storyblok.com — benign.",
                "citations": ["alert-abc"],
                "recommended_actions": [],
            },
        ),
        StepEvent(
            kind="done",
            session_id=sid,
            sequence=7,
            payload={"status": "ok"},
        ),
    ]


@pytest.fixture
def patch_investigate(monkeypatch: pytest.MonkeyPatch) -> list[StepEvent]:
    """Replace harness.investigate with an async iterator over canned events.

    Also stubs ``_build_context`` so we don't try to construct an
    aiohttp ElasticClient or auth client during a unit test.
    """
    events = _fake_events("KDG7CZ4BVBs3R9hXQbPY")

    async def _fake_investigate(_alert_id: str, **_kw: Any) -> AsyncIterator[StepEvent]:
        for ev in events:
            yield ev

    class _StubAuth:
        async def aclose(self) -> None:
            return None

    class _StubElastic:
        async def aclose(self) -> None:
            return None

    def _fake_build_context(_settings: Settings, **_kw: Any) -> Any:
        # Only `.elastic.aclose()` and `.auth.aclose()` are touched by
        # the harness's `finally` block — give them no-op coroutines.
        class _Ctx:
            elastic = _StubElastic()
            auth = _StubAuth()

        return _Ctx()

    monkeypatch.setattr(harness_mod, "investigate", _fake_investigate)
    monkeypatch.setattr(harness_mod, "_build_context", _fake_build_context)
    return events


def _stub_oracle(text: str) -> Any:
    """Build an oracle_caller stub that returns a canned response."""
    captured: dict[str, Any] = {}

    def _caller(**kwargs: Any) -> OracleResponse:
        captured.update(kwargs)
        return OracleResponse(
            text=text,
            model=kwargs["model"],
            usage={
                "input_tokens": 1234,
                "output_tokens": 567,
                "cache_read_input_tokens": 0,
                "cache_creation_input_tokens": 1200,
            },
            elapsed_ms=2500,
        )

    _caller.captured = captured  # type: ignore[attr-defined]
    return _caller


# --------------------------------------------------------------------
# Tests
# --------------------------------------------------------------------


async def test_run_writes_complete_bundle(
    tmp_path: Path,
    patch_investigate: list[StepEvent],
) -> None:
    """Happy path: full five-file bundle lands at evals/<ts>-<alert>/."""
    response_text = (
        "## 1. Verdict\n"
        "Yes, the verdict looks correct.\n\n"
        "## 2. Why\n"
        "IP_01 is internal RFC1918 traffic to a public DNS resolver.\n\n"
        "## 3. Architecture\n"
        "Consider lowering the synthesis_confidence_floor for this class.\n"
    )
    caller = _stub_oracle(response_text)

    result = await harness_run(
        "KDG7CZ4BVBs3R9hXQbPY",
        settings=_settings_for_eval(),
        out_dir=tmp_path,
        oracle_caller=caller,
    )

    # Bundle dir lives under tmp_path with a timestamped name including
    # the alert id.
    assert result.bundle_dir.parent == tmp_path
    assert "KDG7CZ4BVBs3R9hXQbPY" in result.bundle_dir.name

    # All five files exist.
    for fname in ("response.md", "events.jsonl", "request.json", "mapping.json", "meta.json"):
        assert (result.bundle_dir / fname).exists(), f"missing {fname}"


async def test_response_md_is_desanitized(
    tmp_path: Path,
    patch_investigate: list[StepEvent],
) -> None:
    """The oracle's response goes back through desanitize before being saved.

    The operator wants to read real internal hostnames in the
    critique (the labels are only for the wire to the oracle). If
    the oracle refers to ``IP_01``, ``response.md`` should show
    ``10.20.30.148``.
    """
    # Reference a label that the sanitizer is *guaranteed* to mint
    # (the alert_context payload contains 10.20.30.148, which the
    # sanitizer rewrites to IP_01 deterministically because it's the
    # first IP encountered during the walk).
    response_text = "The oracle says IP_01 is suspicious and HOST_01 should be quarantined."
    caller = _stub_oracle(response_text)

    result = await harness_run(
        "KDG7CZ4BVBs3R9hXQbPY",
        settings=_settings_for_eval(),
        out_dir=tmp_path,
        oracle_caller=caller,
    )

    saved = (result.bundle_dir / "response.md").read_text()
    # The labels the oracle used are restored to their originals.
    assert "10.20.30.148" in saved
    assert "app01.lan" in saved
    # And the labels are gone — the operator doesn't see them.
    assert "IP_01" not in saved
    assert "HOST_01" not in saved


async def test_what_was_sent_is_sanitized(
    tmp_path: Path,
    patch_investigate: list[StepEvent],
) -> None:
    """The user message that hit LiteLLM must contain zero raw internals."""
    caller = _stub_oracle("ok")

    await harness_run(
        "KDG7CZ4BVBs3R9hXQbPY",
        settings=_settings_for_eval(),
        out_dir=tmp_path,
        oracle_caller=caller,
    )

    sent = caller.captured["user_message"]  # type: ignore[attr-defined]
    # Hard checks — these are the most reliable smell tests.
    assert "10.20.30.148" not in sent
    assert "app01.lan" not in sent
    # Username inside `/home/<user>/` is rewritten; the path tail stays.
    assert "/home/user" not in sent
    assert "/bin/agent" in sent
    # Public IOCs pass through (they're what the oracle needs to reason about).
    assert "8.8.8.8" in sent
    assert "storyblok.com" in sent


async def test_oracle_call_uses_litellm_settings(
    tmp_path: Path,
    patch_investigate: list[StepEvent],
) -> None:
    """The oracle caller receives the LiteLLM base URL + key (not a separate proxy)."""
    caller = _stub_oracle("ok")

    await harness_run(
        "KDG7CZ4BVBs3R9hXQbPY",
        settings=_settings_for_eval(),
        out_dir=tmp_path,
        oracle_caller=caller,
    )

    captured = caller.captured  # type: ignore[attr-defined]
    assert captured["base_url"].startswith("http://litellm.test:4000")
    assert captured["api_key"] == "test-litellm-key"
    assert captured["verify_ssl"] is False
    assert captured["model"] == "claude-opus-4-7"
    assert captured["max_tokens"] == 4096


async def test_meta_json_records_verdict_and_usage(
    tmp_path: Path,
    patch_investigate: list[StepEvent],
) -> None:
    """``meta.json`` is the audit row for cross-run comparison."""
    caller = _stub_oracle("done")

    result = await harness_run(
        "KDG7CZ4BVBs3R9hXQbPY",
        settings=_settings_for_eval(),
        out_dir=tmp_path,
        oracle_caller=caller,
    )

    meta = json.loads((result.bundle_dir / "meta.json").read_text())
    assert meta["alert_id"] == "KDG7CZ4BVBs3R9hXQbPY"
    assert meta["verdict"] == "false_positive"
    assert meta["confidence"] == 0.85
    assert meta["model"] == "claude-opus-4-7"
    assert meta["usage"]["input_tokens"] == 1234
    assert meta["usage"]["output_tokens"] == 567
    assert meta["events_count"] == len(patch_investigate)
    # Redaction summary records that we minted at least one IP + HOST + USER label.
    assert meta["redaction_summary"].get("IP", 0) >= 1
    assert meta["redaction_summary"].get("HOST", 0) >= 1


async def test_events_jsonl_is_one_event_per_line_sanitized(
    tmp_path: Path,
    patch_investigate: list[StepEvent],
) -> None:
    """``events.jsonl`` is the source of truth for the run trail."""
    caller = _stub_oracle("ok")

    result = await harness_run(
        "KDG7CZ4BVBs3R9hXQbPY",
        settings=_settings_for_eval(),
        out_dir=tmp_path,
        oracle_caller=caller,
    )

    raw = (result.bundle_dir / "events.jsonl").read_text()
    # One JSON doc per non-empty line, no raw internal strings on any line.
    lines = [ln for ln in raw.splitlines() if ln.strip()]
    assert len(lines) == len(patch_investigate)
    for ln in lines:
        parsed = json.loads(ln)
        assert {"kind", "sequence", "payload"} <= parsed.keys()
        assert "10.20.30.148" not in ln
        assert "app01.lan" not in ln


async def test_mapping_json_round_trips(
    tmp_path: Path,
    patch_investigate: list[StepEvent],
) -> None:
    """``mapping.json`` lets a future run replay against the same labels."""
    caller = _stub_oracle("ok")

    result = await harness_run(
        "KDG7CZ4BVBs3R9hXQbPY",
        settings=_settings_for_eval(),
        out_dir=tmp_path,
        oracle_caller=caller,
    )

    mapping = json.loads((result.bundle_dir / "mapping.json").read_text())
    # forward = original→label, reverse = label→original.
    assert mapping["forward"]["10.20.30.148"] in mapping["reverse"]
    assert mapping["reverse"][mapping["forward"]["10.20.30.148"]] == "10.20.30.148"


async def test_missing_litellm_api_key_raises_before_running(
    tmp_path: Path,
) -> None:
    """The CLI maps this exception to exit 4 — must fire before investigate()."""
    settings = _settings_for_eval()
    settings.litellm_api_key = None

    with pytest.raises(RuntimeError, match="LITELLM_API_KEY"):
        await harness_run(
            "KDG7CZ4BVBs3R9hXQbPY",
            settings=settings,
            out_dir=tmp_path,
            oracle_caller=_stub_oracle("never called"),
        )


async def test_oracle_error_is_wrapped(
    tmp_path: Path,
    patch_investigate: list[StepEvent],
) -> None:
    """Network-side errors get re-wrapped so the CLI can map to exit 4."""

    def _failing_caller(**_kw: Any) -> OracleResponse:
        raise OracleError("connection refused")

    with pytest.raises(RuntimeError, match="LiteLLM/oracle call failed"):
        await harness_run(
            "KDG7CZ4BVBs3R9hXQbPY",
            settings=_settings_for_eval(),
            out_dir=tmp_path,
            oracle_caller=_failing_caller,
        )


async def test_run_with_no_triage_report_still_succeeds(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """If synthesis errors out, the harness still ships the partial trail.

    The plan calls this out: "Investigation error event during the
    run → save the bundle anyway; the oracle can still critique the
    partial trail."
    """
    sid = "sess_err"
    only_partial = [
        StepEvent(kind="session_start", session_id=sid, sequence=1, payload={"alert_id": "abc"}),
        StepEvent(kind="error", session_id=sid, sequence=2, payload={"message": "synth failed"}),
    ]

    async def _fake_investigate(_alert_id: str, **_kw: Any) -> AsyncIterator[StepEvent]:
        for ev in only_partial:
            yield ev

    class _StubAuth:
        async def aclose(self) -> None:
            return None

    class _StubElastic:
        async def aclose(self) -> None:
            return None

    def _fake_build_context(_s: Settings, **_kw: Any) -> Any:
        class _Ctx:
            elastic = _StubElastic()
            auth = _StubAuth()

        return _Ctx()

    monkeypatch.setattr(harness_mod, "investigate", _fake_investigate)
    monkeypatch.setattr(harness_mod, "_build_context", _fake_build_context)

    caller = _stub_oracle("partial-trail critique")
    result = await harness_run(
        "abc",
        settings=_settings_for_eval(),
        out_dir=tmp_path,
        oracle_caller=caller,
    )

    assert result.sanitized_report is None
    meta = json.loads((result.bundle_dir / "meta.json").read_text())
    assert meta["verdict"] is None
    assert meta["events_count"] == 2


async def test_expected_verdict_injected_into_oracle_prompt(
    tmp_path: Path,
    patch_investigate: list[StepEvent],
) -> None:
    """When expected_verdict is supplied (synth scenario), the oracle's user
    message must contain the ground-truth block so grading is factual."""
    caller = _stub_oracle("ok")

    await harness_run(
        "KDG7CZ4BVBs3R9hXQbPY",
        settings=_settings_for_eval(),
        out_dir=tmp_path,
        oracle_caller=caller,
        expected_verdict="true_positive",
    )

    sent = caller.captured["user_message"]  # type: ignore[attr-defined]
    assert "## Ground truth (synthetic scenario)" in sent
    assert "true_positive" in sent


async def test_expected_verdict_absent_leaves_prompt_unchanged(
    tmp_path: Path,
    patch_investigate: list[StepEvent],
) -> None:
    """Without expected_verdict the oracle prompt must not contain a ground-truth
    block (real-alert grading is unaffected)."""
    caller = _stub_oracle("ok")

    await harness_run(
        "KDG7CZ4BVBs3R9hXQbPY",
        settings=_settings_for_eval(),
        out_dir=tmp_path,
        oracle_caller=caller,
    )

    sent = caller.captured["user_message"]  # type: ignore[attr-defined]
    assert "Ground truth" not in sent

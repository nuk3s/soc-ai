"""Unit tests for the meta-analysis map-reduce.

Stubs the oracle caller so no LiteLLM/oracle traffic happens. What's
under test:

- ``extract_section`` pulls the right body from a markdown response.
- ``load_slim_rows`` reads `## 3. Architecture` from real bundles and
  ALSO reads `## 2. Why` only when ``agreement="no"``.
- ``chunk_runs`` arithmetic.
- ``build_map_prompt`` includes architecture sections + carves out
  disagreement Why sections.
- ``parse_map_response`` and ``parse_reduce_response`` survive
  fenced JSON / leading prose / malformed input.
- ``run_meta_analysis`` end-to-end produces ``meta_analysis.{md,json}``
  with the expected shape; uses the **distinct** META system prompt;
  records elapsed_ms; degrades gracefully on a single bad map chunk.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from pydantic import SecretStr
from soc_ai.config import Settings
from soc_ai.eval.meta_analysis import (
    META_SYSTEM_PROMPT,
    ArchitectureChange,
    RunSlim,
    build_map_prompt,
    build_reduce_prompt,
    chunk_runs,
    extract_section,
    load_slim_rows,
    parse_map_response,
    parse_reduce_response,
    run_meta_analysis,
)
from soc_ai.eval.oracle_client import OracleError, OracleResponse


def _settings() -> Settings:
    return Settings(
        so_host="https://so.example.com",
        so_username="analyst",
        so_password=SecretStr("password123"),
        so_verify_ssl=False,
        es_hosts=["https://so.example.com:9200"],
        litellm_base_url="http://litellm.test:4000",
        litellm_api_key=SecretStr("test-key"),
        litellm_verify_ssl=False,
        claude_oracle_model="claude-opus-4-7",
        claude_oracle_max_tokens=4096,
    )


# --------------------------------------------------------------------
# extract_section
# --------------------------------------------------------------------


def test_extract_section_pulls_named_body() -> None:
    md = (
        "## 1. Verdict\n\nYes.\n\n"
        "## 2. Why\n\nBecause IP_01 is internal.\n\n"
        "## 3. Architecture\n\nLower the floor.\n"
    )
    assert "Yes" in (extract_section(md, 1) or "")
    assert "Because IP_01 is internal." in (extract_section(md, 2) or "")
    assert "Lower the floor" in (extract_section(md, 3) or "")


def test_extract_section_returns_none_when_missing() -> None:
    md = "## 1. Verdict\n\nYes.\n"
    assert extract_section(md, 3) is None


def test_extract_section_handles_extra_whitespace() -> None:
    md = "##   3.  Architecture\n\nbody here\n"
    assert extract_section(md, 3) == "body here"


def test_extract_section_empty_input() -> None:
    assert extract_section("", 1) is None


# --------------------------------------------------------------------
# load_slim_rows
# --------------------------------------------------------------------


def _write_bundle(
    base: Path,
    alert_id: str,
    *,
    md: str = (
        "## 1. Verdict\n\nYes.\n\n## 2. Why\n\nReason A.\n\n## 3. Architecture\n\nSuggestion X.\n"
    ),
) -> Path:
    bundle = base / alert_id
    bundle.mkdir()
    (bundle / "response.md").write_text(md, encoding="utf-8")
    return bundle


def _row(
    alert_id: str,
    bundle_path: str | None,
    *,
    verdict: str = "false_positive",
    agreement: str = "yes",
    retask_count: int = 0,
    error: str | None = None,
) -> dict[str, Any]:
    return {
        "alert_id": alert_id,
        "bundle_path": bundle_path,
        "verdict": verdict,
        "agreement": agreement,
        "retask_count": retask_count,
        "error": error,
    }


def test_load_slim_rows_reads_architecture_section(tmp_path: Path) -> None:
    bundle = _write_bundle(tmp_path, "a1")
    rows = [_row("a1", str(bundle))]
    slim = load_slim_rows(rows)
    assert len(slim) == 1
    assert "Suggestion X" in slim[0].architecture_section


def test_load_slim_rows_carves_out_why_only_for_disagreements(tmp_path: Path) -> None:
    b1 = _write_bundle(tmp_path, "agree")
    b2 = _write_bundle(tmp_path, "disagree")
    rows = [
        _row("agree", str(b1), agreement="yes"),
        _row("disagree", str(b2), agreement="no"),
    ]
    slim = load_slim_rows(rows)
    assert {s.alert_id for s in slim} == {"agree", "disagree"}
    yes_run = next(s for s in slim if s.alert_id == "agree")
    no_run = next(s for s in slim if s.alert_id == "disagree")
    # Why only loaded for the disagreement.
    assert yes_run.why_section is None
    assert no_run.why_section is not None
    assert "Reason A" in no_run.why_section


def test_load_slim_rows_skips_errored_and_missing(tmp_path: Path) -> None:
    b = _write_bundle(tmp_path, "ok")
    rows = [
        _row("ok", str(b)),
        _row("err", str(tmp_path / "noexist"), error="boom"),
        _row("nobundle", None),
        _row("missing_md", str(tmp_path / "ghost")),  # bundle dir missing
    ]
    slim = load_slim_rows(rows)
    assert [s.alert_id for s in slim] == ["ok"]


# --------------------------------------------------------------------
# chunk_runs
# --------------------------------------------------------------------


def _slim(alert_id: str, *, agreement: str = "yes", arch: str = "x") -> RunSlim:
    return RunSlim(
        alert_id=alert_id,
        verdict="false_positive",
        agreement=agreement,
        retask_count=0,
        architecture_section=arch,
    )


def test_chunk_runs_basic() -> None:
    slim = [_slim(f"a{i}") for i in range(53)]
    chunks = chunk_runs(slim, 25)
    assert len(chunks) == 3
    assert [len(c) for c in chunks] == [25, 25, 3]


def test_chunk_runs_smaller_than_chunk() -> None:
    slim = [_slim("a1")]
    chunks = chunk_runs(slim, 25)
    assert len(chunks) == 1
    assert len(chunks[0]) == 1


def test_chunk_runs_invalid_size() -> None:
    with pytest.raises(ValueError, match="positive"):
        chunk_runs([_slim("a1")], 0)


# --------------------------------------------------------------------
# Prompt builders
# --------------------------------------------------------------------


def test_build_map_prompt_includes_architecture_for_every_run() -> None:
    chunk = [
        _slim("a1", arch="Tighten the stop condition."),
        _slim("a2", arch="Add zeek pivot."),
    ]
    msg = build_map_prompt(chunk)
    assert "Tighten the stop condition" in msg
    assert "Add zeek pivot" in msg
    assert "a1" in msg
    assert "a2" in msg
    # Returns instructions to cluster + JSON output requirement.
    assert "Cluster" in msg
    assert "JSON array" in msg


def test_build_map_prompt_carves_out_why_for_disagreements() -> None:
    disagree = RunSlim(
        alert_id="d1",
        verdict="escalate",
        agreement="no",
        retask_count=1,
        architecture_section="Add tool X.",
        why_section="Agent missed the lateral movement signal.",
    )
    msg = build_map_prompt([disagree])
    assert "lateral movement" in msg
    assert "Why the oracle disagreed" in msg


def test_build_map_prompt_skips_why_when_section_unset() -> None:
    """Agreement-yes runs come out of load_slim_rows with
    why_section=None; the prompt builder should leave the disagreement
    heading out entirely."""
    yes_run = _slim("a1", agreement="yes")
    assert yes_run.why_section is None
    msg = build_map_prompt([yes_run])
    assert "Why the oracle disagreed" not in msg


def test_build_reduce_prompt_includes_aggregates_and_themes() -> None:
    aggregates = {
        "n_total": 100,
        "agreement_rate": 0.74,
        "retask_rate": 0.31,
    }
    map_results = [
        [
            {
                "theme": "tighten stop condition",
                "count_in_chunk": 8,
                "representative_quote": "stop after 3 evidences",
            },
        ],
        [
            {
                "theme": "add zeek pivot",
                "count_in_chunk": 5,
                "representative_quote": "we should have a zeek tool",
            },
        ],
    ]
    msg = build_reduce_prompt(aggregates, map_results)
    assert "agreement_rate" in msg
    assert "tighten stop condition" in msg
    assert "add zeek pivot" in msg
    assert "5 highest-impact" in msg
    assert "EXACTLY 5 entries" in msg


# --------------------------------------------------------------------
# parse_*
# --------------------------------------------------------------------


def test_parse_map_response_clean_json() -> None:
    text = json.dumps(
        [
            {
                "theme": "x",
                "count_in_chunk": 3,
                "representative_quote": "q",
                "expected_impact": "agreement_rate",
                "supporting_alert_ids": ["a1", "a2"],
            }
        ]
    )
    out = parse_map_response(text)
    assert len(out) == 1
    assert out[0]["theme"] == "x"


def test_parse_map_response_strips_fences() -> None:
    text = '```json\n[{"theme": "x", "count_in_chunk": 1}]\n```'
    out = parse_map_response(text)
    assert out == [{"theme": "x", "count_in_chunk": 1}]


def test_parse_map_response_returns_empty_on_garbage() -> None:
    """A single bad map response shouldn't kill the whole reduce."""
    assert parse_map_response("not json at all") == []
    assert parse_map_response('{"oops": "wrong type"}') == []


def test_parse_reduce_response_extracts_changes_and_narrative() -> None:
    payload = {
        "changes": [
            {
                "change": "Tighten investigator stop condition",
                "description": "Stop after 3 evidence items.",
                "evidence": "themes 1, 4, 7 (combined count 23)",
                "expected_lift": "retask_rate -0.10",
                "risk": "may lose edge-case context",
                "priority": "high",
            }
        ]
    }
    text = json.dumps(payload) + "\n\n---\n\nThe top change is X because Y."
    changes, narrative = parse_reduce_response(text)
    assert len(changes) == 1
    assert changes[0].change.startswith("Tighten")
    assert changes[0].priority == "high"
    assert "top change is X" in narrative


def test_parse_reduce_response_handles_leading_prose() -> None:
    payload = {"changes": [{"change": "X", "priority": "high"}]}
    text = "Here's my answer:\n\n" + json.dumps(payload) + "\n\nNarrative tail."
    changes, narrative = parse_reduce_response(text)
    assert len(changes) == 1
    assert "Narrative tail" in narrative


def test_parse_reduce_response_no_json_returns_raw_as_narrative() -> None:
    changes, narrative = parse_reduce_response("just prose, no json")
    assert changes == []
    assert "just prose" in narrative


# --------------------------------------------------------------------
# run_meta_analysis end-to-end (stubbed oracle)
# --------------------------------------------------------------------


def _stub_oracle_caller(canned_map: list[dict[str, Any]], canned_reduce: dict[str, Any]):
    """Build a stub oracle_caller that returns canned map/reduce responses.

    The first call is the reduce step? No — map calls happen first
    (in parallel). The first ``len(chunks)`` calls return the map
    payload; the last call returns the reduce payload. We track call
    count internally and switch.
    """
    captured: list[dict[str, Any]] = []
    map_text = json.dumps(canned_map)
    reduce_text = json.dumps(canned_reduce) + "\n\n---\n\nNarrative summary of the top change."

    def _caller(**kwargs: Any) -> OracleResponse:
        captured.append(kwargs)
        # Heuristic: the reduce prompt mentions "5 highest-impact"; map
        # prompts ask to "Cluster" architecture suggestions.
        is_reduce = "5 highest-impact" in kwargs.get("user_message", "")
        return OracleResponse(
            text=reduce_text if is_reduce else map_text,
            model=kwargs["model"],
            usage={
                "input_tokens": 1000,
                "output_tokens": 500,
                "cache_read_input_tokens": 0,
                "cache_creation_input_tokens": 0,
            },
            elapsed_ms=1000,
        )

    _caller.captured = captured  # type: ignore[attr-defined]
    return _caller


async def test_run_meta_analysis_writes_outputs(tmp_path: Path) -> None:
    # Build a small batch with 3 successful runs (1 chunk).
    rows = []
    for i in range(3):
        bundle = _write_bundle(
            tmp_path,
            f"a{i}",
            md=(
                "## 1. Verdict\n\nYes.\n\n"
                "## 2. Why\n\nbecause.\n\n"
                "## 3. Architecture\n\n"
                f"Suggestion #{i}: tighten stops.\n"
            ),
        )
        rows.append(_row(f"a{i}", str(bundle)))

    canned_map = [
        {
            "theme": "tighten stop condition",
            "count_in_chunk": 3,
            "representative_quote": "tighten stops",
            "expected_impact": "retask_rate",
            "supporting_alert_ids": ["a0", "a1", "a2"],
        }
    ]
    canned_reduce = {
        "changes": [
            {
                "change": f"Change {i}",
                "description": f"Do {i}.",
                "evidence": "themes seen N times",
                "expected_lift": "retask_rate -0.10",
                "risk": "minimal",
                "priority": "high" if i == 0 else "medium",
            }
            for i in range(5)
        ]
    }
    caller = _stub_oracle_caller(canned_map, canned_reduce)

    aggregates = {"n_total": 3, "agreement_rate": 1.0, "retask_rate": 0.0}
    result = await run_meta_analysis(
        rows=rows,
        batch_dir=tmp_path,
        aggregates=aggregates,
        settings=_settings(),
        oracle_caller=caller,
        map_chunk_size=10,  # all 3 in one chunk
        map_concurrency=2,
    )

    # File outputs landed.
    assert (tmp_path / "meta_analysis.md").exists()
    assert (tmp_path / "meta_analysis.json").exists()

    # Structured fields populated.
    assert result.n_runs_in_meta == 3
    assert result.n_chunks == 1
    assert result.n_themes_total == 1
    assert len(result.changes) == 5
    assert isinstance(result.changes[0], ArchitectureChange)
    assert result.changes[0].priority == "high"

    # The Markdown shows top-5 with priorities + narrative.
    md = (tmp_path / "meta_analysis.md").read_text()
    assert "Change 0" in md
    assert "Narrative summary" in md


async def test_run_meta_analysis_uses_meta_system_prompt(tmp_path: Path) -> None:
    """Critical: the meta path uses the META_SYSTEM_PROMPT, not the
    per-alert system prompt. Otherwise the model produces per-alert
    critiques instead of cross-alert recommendations."""
    bundle = _write_bundle(tmp_path, "a1")
    rows = [_row("a1", str(bundle))]

    caller = _stub_oracle_caller(
        canned_map=[{"theme": "x", "count_in_chunk": 1, "representative_quote": "q"}],
        canned_reduce={"changes": [{"change": "x", "priority": "low"} for _ in range(5)]},
    )

    await run_meta_analysis(
        rows=rows,
        batch_dir=tmp_path,
        aggregates={"n_total": 1},
        settings=_settings(),
        oracle_caller=caller,
        map_chunk_size=10,
    )

    captured = caller.captured  # type: ignore[attr-defined]
    assert len(captured) >= 2  # map + reduce
    # Every call uses the meta system prompt.
    for call in captured:
        assert call["system_prompt"] == META_SYSTEM_PROMPT
        # arch_context is None for the meta path (no agent prompts in ctx).
        assert call.get("arch_context") is None


async def test_run_meta_analysis_survives_one_bad_map_chunk(tmp_path: Path) -> None:
    """If one map call returns garbage, the reduce step should still
    run with the surviving chunks' themes."""
    rows = []
    for i in range(50):  # 2 chunks of 25
        bundle = _write_bundle(tmp_path, f"a{i}")
        rows.append(_row(f"a{i}", str(bundle)))

    n_calls = 0
    canned_reduce = {"changes": [{"change": f"X{i}", "priority": "low"} for i in range(5)]}
    canned_map = [{"theme": "t", "count_in_chunk": 1, "representative_quote": "q"}]

    def _caller(**kwargs: Any) -> OracleResponse:
        nonlocal n_calls
        n_calls += 1
        is_reduce = "5 highest-impact" in kwargs.get("user_message", "")
        if is_reduce:
            return OracleResponse(
                text=json.dumps(canned_reduce),
                model=kwargs["model"],
                usage={
                    "input_tokens": 1,
                    "output_tokens": 1,
                    "cache_read_input_tokens": 0,
                    "cache_creation_input_tokens": 0,
                },
                elapsed_ms=1,
            )
        # First map call: garbage. Second: clean.
        text = "totally not json" if n_calls == 1 else json.dumps(canned_map)
        return OracleResponse(
            text=text,
            model=kwargs["model"],
            usage={
                "input_tokens": 1,
                "output_tokens": 1,
                "cache_read_input_tokens": 0,
                "cache_creation_input_tokens": 0,
            },
            elapsed_ms=1,
        )

    result = await run_meta_analysis(
        rows=rows,
        batch_dir=tmp_path,
        aggregates={"n_total": 50},
        settings=_settings(),
        oracle_caller=_caller,
        map_chunk_size=25,
        map_concurrency=2,
    )

    assert result.n_chunks == 2
    # One bad chunk contributed 0 themes; the other contributed 1.
    assert result.n_themes_total == 1
    # Reduce still got changes.
    assert len(result.changes) == 5


async def test_run_meta_analysis_propagates_reduce_failure(tmp_path: Path) -> None:
    bundle = _write_bundle(tmp_path, "a1")
    rows = [_row("a1", str(bundle))]

    canned_theme = [{"theme": "x", "count_in_chunk": 1, "representative_quote": "q"}]

    def _caller(**kwargs: Any) -> OracleResponse:
        is_reduce = "5 highest-impact" in kwargs.get("user_message", "")
        if is_reduce:
            raise OracleError("LiteLLM 503")
        # Return a real theme so n_themes_total > 0; the guard lets us
        # reach the reduce step where we want to see the error propagate.
        return OracleResponse(
            text=json.dumps(canned_theme),
            model=kwargs["model"],
            usage={
                "input_tokens": 0,
                "output_tokens": 0,
                "cache_read_input_tokens": 0,
                "cache_creation_input_tokens": 0,
            },
            elapsed_ms=0,
        )

    with pytest.raises(RuntimeError, match="reduce step failed"):
        await run_meta_analysis(
            rows=rows,
            batch_dir=tmp_path,
            aggregates={"n_total": 1},
            settings=_settings(),
            oracle_caller=_caller,
        )


async def test_run_meta_analysis_refuses_when_no_usable_runs(tmp_path: Path) -> None:
    """All-errored input → no slim rows → raise before any oracle call."""
    rows = [_row("a1", None, error="boom")]
    caller = _stub_oracle_caller([], {"changes": []})

    with pytest.raises(RuntimeError, match="no usable runs"):
        await run_meta_analysis(
            rows=rows,
            batch_dir=tmp_path,
            aggregates={"n_total": 1},
            settings=_settings(),
            oracle_caller=caller,
        )

    # Caller never invoked.
    assert caller.captured == []  # type: ignore[attr-defined]


async def test_run_meta_analysis_aborts_when_all_map_chunks_fail(tmp_path: Path) -> None:
    """All map calls raise OracleError → n_themes_total == 0 → RuntimeError
    mentioning 'no themes' before the reduce step fires."""
    bundle = _write_bundle(tmp_path, "a1")
    rows = [_row("a1", str(bundle))]

    def _all_map_fail(**kwargs: Any) -> OracleResponse:
        is_reduce = "5 highest-impact" in kwargs.get("user_message", "")
        if not is_reduce:
            raise OracleError("LiteLLM 503")
        # Reduce should never be reached — if it is, return a valid response
        # so the error is clearly the RuntimeError we expect, not a different one.
        return OracleResponse(
            text=json.dumps({"changes": []}),
            model=kwargs["model"],
            usage={
                "input_tokens": 0,
                "output_tokens": 0,
                "cache_read_input_tokens": 0,
                "cache_creation_input_tokens": 0,
            },
            elapsed_ms=0,
        )

    with pytest.raises(RuntimeError, match="no themes"):
        await run_meta_analysis(
            rows=rows,
            batch_dir=tmp_path,
            aggregates={"n_total": 1},
            settings=_settings(),
            oracle_caller=_all_map_fail,
        )


async def test_run_meta_analysis_refuses_without_api_key(tmp_path: Path) -> None:
    bundle = _write_bundle(tmp_path, "a1")
    rows = [_row("a1", str(bundle))]
    settings = _settings()
    settings.litellm_api_key = None

    with pytest.raises(RuntimeError, match="LITELLM_API_KEY"):
        await run_meta_analysis(
            rows=rows,
            batch_dir=tmp_path,
            aggregates={"n_total": 1},
            settings=settings,
            oracle_caller=_stub_oracle_caller([], {"changes": []}),
        )

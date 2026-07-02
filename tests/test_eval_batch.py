"""Unit tests for the batch eval orchestrator.

These tests stub two boundaries:

- :func:`sample_diverse_alerts` (so we never hit ES) — replaced with
  an async generator over a fixed list.
- ``harness.run`` (so we never hit LiteLLM/the oracle) — replaced with a
  stub that returns canned :class:`EvalResult` instances or raises on
  demand.

What's under test:

- one ``IndexRow`` per alert lands in ``index.jsonl`` (and on
  ``--resume`` we skip already-completed IDs);
- the failure-budget abort triggers after N consecutive failures;
- the per-alert ``wait_for`` timeout records ``error="timeout..."``;
- a partial-batch run leaves ``index.jsonl`` complete-as-far-as-it-got;
- agreement extraction + retask counting end up on the row;
- ``LITELLM_API_KEY`` missing raises before doing any work.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import pytest
from pydantic import SecretStr
from soc_ai.config import Settings
from soc_ai.eval.batch import (
    BatchConfig,
    extract_agreement,
    read_retask_count,
    run_batch,
)
from soc_ai.eval.harness import EvalResult
from soc_ai.eval.oracle_client import OracleResponse
from soc_ai.eval.sanitize import Mapping


def _settings(*, with_litellm_key: bool = True) -> Settings:
    return Settings(
        so_host="https://so.example.com",
        so_username="analyst",
        so_password=SecretStr("password123"),
        so_verify_ssl=False,
        es_hosts=["https://so.example.com:9200"],
        litellm_base_url="http://localhost:4000",
        litellm_api_key=SecretStr("test-key") if with_litellm_key else None,
        litellm_verify_ssl=False,
    )


def _stub_eval_result(
    bundle_dir: Path,
    *,
    response_md: str = "## 1. Verdict\n\nYes, agreed.\n",
    verdict: str = "false_positive",
    confidence: float = 0.85,
    retask_events: int = 0,
) -> EvalResult:
    """Materialize a bundle dir + return the EvalResult that points at it."""
    bundle_dir.mkdir(parents=True, exist_ok=True)
    (bundle_dir / "response.md").write_text(response_md, encoding="utf-8")
    events: list[dict[str, Any]] = [
        {"kind": "session_start", "sequence": 1, "payload": {}},
    ]
    for i in range(retask_events):
        events.append({"kind": "retask", "sequence": i + 2, "payload": {}})
    (bundle_dir / "events.jsonl").write_text(
        "\n".join(json.dumps(e) for e in events) + "\n", encoding="utf-8"
    )
    return EvalResult(
        bundle_dir=bundle_dir,
        response_md=response_md,
        sanitized_events=[],
        sanitized_report={"verdict": verdict, "confidence": confidence},
        mapping=Mapping(),
        oracle_response=OracleResponse(
            text=response_md,
            model="claude-opus-4-7",
            usage={
                "input_tokens": 1000,
                "output_tokens": 500,
                "cache_read_input_tokens": 700,
                "cache_creation_input_tokens": 300,
            },
            elapsed_ms=2000,
        ),
        investigation_elapsed_ms=15_000,
    )


def _make_sampler(ids: list[str]) -> Any:
    async def _sampler(_oql: str, **_kw: Any) -> AsyncIterator[str]:
        for aid in ids:
            yield aid

    return _sampler


def _make_runner(
    *,
    canned: dict[str, dict[str, Any]] | None = None,
    raise_for: dict[str, Exception] | None = None,
    delays_for: dict[str, float] | None = None,
) -> Any:
    """Build a stub harness.run callable.

    canned[alert_id] supplies fields for _stub_eval_result; missing
    alerts get defaults. raise_for[alert_id] raises that exception
    instead of returning. delays_for[alert_id] sleeps that many seconds
    before responding (used for the timeout test).
    """
    canned = canned or {}
    raise_for = raise_for or {}
    delays_for = delays_for or {}

    async def _run(alert_id: str, *, settings: Settings, out_dir: Path, **_kw: Any) -> EvalResult:
        if alert_id in delays_for:
            await asyncio.sleep(delays_for[alert_id])
        if alert_id in raise_for:
            raise raise_for[alert_id]
        bundle = out_dir / f"2026-05-09T120000Z-{alert_id}"
        return _stub_eval_result(bundle, **canned.get(alert_id, {}))

    return _run


# --------------------------------------------------------------------
# extract_agreement / read_retask_count
# --------------------------------------------------------------------


def test_extract_agreement_yes_phrasing() -> None:
    md = "## 1. Verdict\n\nYes — the verdict is correct given the evidence.\n"
    assert extract_agreement(md) == "yes"


def test_extract_agreement_no_phrasing() -> None:
    md = "## 1. Verdict\n\nNo, I disagree with the verdict.\n"
    assert extract_agreement(md) == "no"


def test_extract_agreement_partial_phrasing() -> None:
    md = "## 1. Verdict\n\nPartially — the agent got the IP right but missed the rule.\n"
    assert extract_agreement(md) == "partial"


def test_extract_agreement_double_negation_is_not_no() -> None:
    """A double negation ('not incorrect' / 'isn't wrong') means AGREEMENT — the
    prose parser must not misfire on the bare words 'incorrect'/'wrong'."""
    assert extract_agreement("## 1. Verdict\n\nThe agent's conclusion is not incorrect.\n") != "no"
    assert extract_agreement("## 1. Verdict\n\nYes — the verdict isn't wrong here.\n") == "yes"


def test_extract_agreement_partial_beats_agree() -> None:
    """`partial` is more specific than `yes`/`agree` — must win when
    both phrases appear in the verdict paragraph."""
    md = "## 1. Verdict\n\nI agree, but only partially — see notes.\n"
    assert extract_agreement(md) == "partial"


def test_extract_agreement_disagree_phrasing() -> None:
    md = "## 1. Verdict\n\nI disagree with the conclusion.\n"
    assert extract_agreement(md) == "no"


def test_extract_agreement_yes_with_benign_no_in_prose() -> None:
    """An agreement whose prose contains a benign "no" must stay "yes".

    Regression: the old `\\bno\\b` match flagged "no malicious activity" /
    "no indicators of compromise" as disagreement, biasing agreement_rate
    (the GO/NO-GO metric) downward."""
    md = (
        "## 1. Verdict\n\n"
        "Yes — I agree with the false_positive call; the traffic shows no "
        "malicious activity and no indicators of compromise.\n"
    )
    assert extract_agreement(md) == "yes"


def test_extract_agreement_agree_lead_with_benign_no() -> None:
    """Leads with 'Agree' (not 'Yes') and still contains a benign 'no'."""
    md = "## 1. Verdict\n\nAgree — benign east-west traffic, no signs of compromise.\n"
    assert extract_agreement(md) == "yes"


def test_extract_agreement_not_correct_is_disagreement() -> None:
    """Negated agreement word must read as disagreement, not a bare 'correct'."""
    md = "## 1. Verdict\n\nThe analyst's call is not correct here.\n"
    assert extract_agreement(md) == "no"


def test_extract_agreement_unknown_when_silent() -> None:
    md = "## 1. Verdict\n\nThe situation is complex and depends on context.\n"
    assert extract_agreement(md) == "unknown"


def test_extract_agreement_no_section_falls_back() -> None:
    """If the heading is missing, scan the whole document."""
    md = "Yes, the agent was correct.\n"
    assert extract_agreement(md) == "yes"


def test_extract_agreement_empty() -> None:
    assert extract_agreement("") == "unknown"


class TestExtractAgreementHardening:
    def test_structured_line_wins(self) -> None:
        assert extract_agreement("AGREEMENT: no\n\nYes, mostly fine otherwise.") == "no"

    def test_structured_line_case_insensitive(self) -> None:
        assert extract_agreement("Agreement: Partial\n\nDetails…") == "partial"

    def test_negated_correct_is_disagreement(self) -> None:
        assert extract_agreement("The verdict is not actually correct here.") == "no"

    def test_isnt_correct_is_disagreement(self) -> None:
        assert extract_agreement("This isn't correct — the alert was benign.") == "no"

    def test_formatted_leading_no(self) -> None:
        assert extract_agreement("**Verdict:** No — I disagree with the conclusion.") == "no"

    def test_agreeing_no_prose_still_yes(self) -> None:
        assert (
            extract_agreement("Yes — correct, there was no malicious activity and no IOCs.")
            == "yes"
        )

    def test_negated_correct_three_word_window(self) -> None:
        """'not by any measure correct' has three intervening words — must be 'no'."""
        assert extract_agreement("This is not by any measure correct.") == "no"

    def test_echoed_instruction_then_real_agreement(self) -> None:
        """If the model echoes the fill-in-the-blank instruction before giving
        a real AGREEMENT line, the parser must return the real verdict, not
        misclassify the placeholder text."""
        md = "AGREEMENT: <yes|no|partial>\nAGREEMENT: no\n"
        assert extract_agreement(md) == "no"


def test_read_retask_count_counts_kind_retask(tmp_path: Path) -> None:
    bundle = tmp_path / "b"
    bundle.mkdir()
    (bundle / "events.jsonl").write_text(
        "\n".join(
            [
                json.dumps({"kind": "session_start", "sequence": 1}),
                json.dumps({"kind": "tool_call", "sequence": 2}),
                json.dumps({"kind": "retask", "sequence": 3}),
                json.dumps({"kind": "tool_call", "sequence": 4}),
                json.dumps({"kind": "retask", "sequence": 5}),
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    assert read_retask_count(bundle) == 2


def test_read_retask_count_handles_missing_file(tmp_path: Path) -> None:
    assert read_retask_count(tmp_path / "nope") == 0


def test_read_retask_count_skips_corrupt_lines(tmp_path: Path) -> None:
    bundle = tmp_path / "b"
    bundle.mkdir()
    (bundle / "events.jsonl").write_text(
        json.dumps({"kind": "retask", "sequence": 1}) + "\nnot json\n",
        encoding="utf-8",
    )
    assert read_retask_count(bundle) == 1


# --------------------------------------------------------------------
# run_batch — happy path + edge cases
# --------------------------------------------------------------------


async def test_happy_path_writes_one_row_per_alert(tmp_path: Path) -> None:
    cfg = BatchConfig(oql="x", n=3, concurrency=2, out_dir=tmp_path)
    sampler = _make_sampler(["a1", "a2", "a3"])
    runner = _make_runner()

    summary = await run_batch(
        cfg,
        settings=_settings(),
        elastic=None,  # type: ignore[arg-type]
        sampler=sampler,
        runner=runner,
    )

    assert summary.n_ok == 3
    assert summary.n_error == 0
    assert summary.aborted_reason is None

    rows = [
        json.loads(line)
        for line in (summary.batch_dir / "index.jsonl").read_text().splitlines()
        if line
    ]
    assert {r["alert_id"] for r in rows} == {"a1", "a2", "a3"}
    for r in rows:
        assert r["error"] is None
        assert r["verdict"] == "false_positive"
        assert r["agreement"] == "yes"
        assert r["bundle_path"]
        # Non-synth path: rows are marked not-synth, no scenario id.
        assert r["is_synth"] is False
        assert r["synth_scenario_id"] is None


async def test_synth_set_ingests_and_tags_rows(tmp_path: Path) -> None:
    """When BatchConfig.synth_set is set, the runner ingests those
    scenarios, mixes their triage IDs into the alert stream, and tags
    each resulting row with is_synth + synth_scenario_id.
    """
    from datetime import UTC, datetime

    from soc_ai.eval.synth_ingest import IngestResult
    from soc_ai.eval.synth_loader import Scenario

    # Two fake scenarios that the stub ingester will translate to specific
    # OS doc IDs the runner then has to triage.
    scenarios = [
        Scenario.model_construct(id="scen-A", events=[], tier="easy", ground_truth=None),
        Scenario.model_construct(id="scen-B", events=[], tier="hard", ground_truth=None),
    ]
    ingest_calls: list[Any] = []

    async def stub_ingester(
        scens: list[Scenario], *, elastic: Any, run_time: Any
    ) -> list[IngestResult]:
        ingest_calls.append((tuple(s.id for s in scens), run_time))
        return [
            IngestResult(
                scenario_id=s.id,
                triage_doc_id=f"synth-doc-{s.id}",
                triage_index="logs-synth-suricata-alert",
                doc_count=1,
            )
            for s in scens
        ]

    cfg = BatchConfig(
        oql="x",
        n=2,
        concurrency=2,
        out_dir=tmp_path,
        synth_scenarios=tuple(scenarios),
        synth_run_time=datetime(2026, 5, 13, 22, 30, 0, tzinfo=UTC),
    )
    sampler = _make_sampler(["real-a1", "real-a2"])
    runner = _make_runner()

    summary = await run_batch(
        cfg,
        settings=_settings(),
        elastic=None,  # type: ignore[arg-type]
        sampler=sampler,
        runner=runner,
        synth_ingester=stub_ingester,
    )

    assert summary.n_ok == 4  # 2 real + 2 synth
    rows = [
        json.loads(line)
        for line in (summary.batch_dir / "index.jsonl").read_text().splitlines()
        if line
    ]
    by_id = {r["alert_id"]: r for r in rows}
    assert by_id["real-a1"]["is_synth"] is False
    assert by_id["real-a1"]["synth_scenario_id"] is None
    assert by_id["synth-doc-scen-A"]["is_synth"] is True
    assert by_id["synth-doc-scen-A"]["synth_scenario_id"] == "scen-A"
    assert by_id["synth-doc-scen-B"]["is_synth"] is True
    assert by_id["synth-doc-scen-B"]["synth_scenario_id"] == "scen-B"
    # Ingester was called once with both scenarios and the configured run_time.
    assert len(ingest_calls) == 1
    assert ingest_calls[0][0] == ("scen-A", "scen-B")
    assert ingest_calls[0][1] == cfg.synth_run_time


async def test_failure_budget_aborts_after_consecutive_errors(tmp_path: Path) -> None:
    """Three consecutive failures with budget=2 → abort."""
    cfg = BatchConfig(
        oql="x",
        n=10,
        concurrency=1,  # serialize so consecutive-counting is deterministic
        out_dir=tmp_path,
        max_consecutive_failures=2,
    )
    sampler = _make_sampler(["a1", "a2", "a3", "a4"])
    runner = _make_runner(
        raise_for={
            "a1": RuntimeError("nope"),
            "a2": RuntimeError("nope"),
            "a3": RuntimeError("nope"),
        }
    )

    summary = await run_batch(
        cfg,
        settings=_settings(),
        elastic=None,  # type: ignore[arg-type]
        sampler=sampler,
        runner=runner,
    )

    assert summary.aborted_reason is not None
    assert "consecutive failures" in summary.aborted_reason
    # First failure (warmup) + at least one more → budget hit. We don't
    # care exactly how many tasks completed before the cancel; what
    # matters is that we did NOT process all 4.
    assert summary.n_error >= 2


async def test_consecutive_counter_resets_on_success(tmp_path: Path) -> None:
    """fail, succeed, fail, fail must NOT abort when budget=3 — the
    middle success resets the counter."""
    cfg = BatchConfig(
        oql="x",
        n=10,
        concurrency=1,
        out_dir=tmp_path,
        max_consecutive_failures=3,
    )
    sampler = _make_sampler(["a1", "a2", "a3", "a4"])
    runner = _make_runner(
        raise_for={
            "a1": RuntimeError("err1"),
            "a3": RuntimeError("err2"),
            "a4": RuntimeError("err3"),
        }
    )

    summary = await run_batch(
        cfg,
        settings=_settings(),
        elastic=None,  # type: ignore[arg-type]
        sampler=sampler,
        runner=runner,
    )

    assert summary.aborted_reason is None
    assert summary.n_ok == 1
    assert summary.n_error == 3


async def test_per_run_timeout_records_error(tmp_path: Path) -> None:
    cfg = BatchConfig(oql="x", n=2, concurrency=1, out_dir=tmp_path, per_run_timeout_s=1)
    sampler = _make_sampler(["slow", "fast"])
    runner = _make_runner(delays_for={"slow": 5.0})

    summary = await run_batch(
        cfg,
        settings=_settings(),
        elastic=None,  # type: ignore[arg-type]
        sampler=sampler,
        runner=runner,
    )

    assert summary.n_error == 1
    assert summary.n_ok == 1
    rows = [
        json.loads(line)
        for line in (summary.batch_dir / "index.jsonl").read_text().splitlines()
        if line
    ]
    timeout_row = next(r for r in rows if r["alert_id"] == "slow")
    assert "timeout" in timeout_row["error"]


async def test_resume_skips_completed_alert_ids(tmp_path: Path) -> None:
    # First run: 2 of 3.
    cfg1 = BatchConfig(oql="x", n=3, concurrency=1, out_dir=tmp_path)
    sampler1 = _make_sampler(["a1", "a2"])
    runner = _make_runner()

    summary1 = await run_batch(
        cfg1,
        settings=_settings(),
        elastic=None,  # type: ignore[arg-type]
        sampler=sampler1,
        runner=runner,
    )
    batch_dir = summary1.batch_dir
    assert summary1.n_ok == 2

    # Resume in the same dir, sampler offers a1 a2 a3 — only a3 should run.
    cfg2 = BatchConfig(oql="x", n=3, concurrency=1, out_dir=batch_dir, resume=True)
    sampler2 = _make_sampler(["a1", "a2", "a3"])
    summary2 = await run_batch(
        cfg2,
        settings=_settings(),
        elastic=None,  # type: ignore[arg-type]
        sampler=sampler2,
        runner=runner,
    )
    assert summary2.batch_dir == batch_dir
    assert summary2.n_planned == 1  # only a3 was planned


async def test_resume_does_not_skip_errored_alerts(tmp_path: Path) -> None:
    """Errored runs aren't 'completed' — a resume should retry them."""
    cfg1 = BatchConfig(oql="x", n=2, concurrency=1, out_dir=tmp_path)
    sampler1 = _make_sampler(["a1"])
    summary1 = await run_batch(
        cfg1,
        settings=_settings(),
        elastic=None,  # type: ignore[arg-type]
        sampler=sampler1,
        runner=_make_runner(raise_for={"a1": RuntimeError("first try")}),
    )
    assert summary1.n_error == 1

    cfg2 = BatchConfig(oql="x", n=2, concurrency=1, out_dir=summary1.batch_dir, resume=True)
    sampler2 = _make_sampler(["a1"])
    summary2 = await run_batch(
        cfg2,
        settings=_settings(),
        elastic=None,  # type: ignore[arg-type]
        sampler=sampler2,
        runner=_make_runner(),  # success this time
    )
    # a1 was retried (errored != completed).
    assert summary2.n_planned == 1
    assert summary2.n_ok == 1


async def test_missing_litellm_api_key_raises_before_running(tmp_path: Path) -> None:
    cfg = BatchConfig(oql="x", n=1, out_dir=tmp_path)
    sampler = _make_sampler(["a1"])
    runner = _make_runner()

    with pytest.raises(RuntimeError, match="LITELLM_API_KEY"):
        await run_batch(
            cfg,
            settings=_settings(with_litellm_key=False),
            elastic=None,  # type: ignore[arg-type]
            sampler=sampler,
            runner=runner,
        )


async def test_empty_sampler_returns_planned_zero(tmp_path: Path) -> None:
    cfg = BatchConfig(oql="x", n=10, out_dir=tmp_path)
    sampler = _make_sampler([])
    runner = _make_runner()

    summary = await run_batch(
        cfg,
        settings=_settings(),
        elastic=None,  # type: ignore[arg-type]
        sampler=sampler,
        runner=runner,
    )

    assert summary.n_planned == 0
    assert summary.aborted_reason is not None
    assert "no eligible alerts" in summary.aborted_reason


async def test_retask_count_lands_on_index_row(tmp_path: Path) -> None:
    cfg = BatchConfig(oql="x", n=1, out_dir=tmp_path)
    sampler = _make_sampler(["a1"])
    runner = _make_runner(canned={"a1": {"retask_events": 2}})

    summary = await run_batch(
        cfg,
        settings=_settings(),
        elastic=None,  # type: ignore[arg-type]
        sampler=sampler,
        runner=runner,
    )
    rows = [
        json.loads(line)
        for line in (summary.batch_dir / "index.jsonl").read_text().splitlines()
        if line
    ]
    assert rows[0]["retask_count"] == 2


async def test_citations_from_report_land_on_index_row(tmp_path: Path) -> None:
    """citations from the triage report must propagate to the IndexRow
    so report.py's synth_stratum scoring can check citation coverage."""
    cfg = BatchConfig(oql="x", n=1, out_dir=tmp_path)
    sampler = _make_sampler(["a1"])

    # A bespoke runner (instead of _make_runner) so the result carries
    # citations in the sanitized_report.
    from pathlib import Path as _Path

    from soc_ai.eval.harness import EvalResult
    from soc_ai.eval.oracle_client import OracleResponse
    from soc_ai.eval.sanitize import Mapping

    async def _runner_with_citations(
        alert_id: str, *, settings: Any, out_dir: _Path, **_kw: Any
    ) -> EvalResult:
        bundle = out_dir / f"2026-01-01T000000Z-{alert_id}"
        bundle.mkdir(parents=True, exist_ok=True)
        md = "## 1. Verdict\n\nAGREEMENT: yes\n\nLooked correct.\n"
        (bundle / "response.md").write_text(md, encoding="utf-8")
        import json as _json

        (bundle / "events.jsonl").write_text(
            _json.dumps({"kind": "session_start", "sequence": 1, "payload": {}}) + "\n",
            encoding="utf-8",
        )
        return EvalResult(
            bundle_dir=bundle,
            response_md=md,
            sanitized_events=[],
            sanitized_report={
                "verdict": "true_positive",
                "confidence": 0.9,
                "citations": ["zeek_conn:uid=CX12", "blocklist_hit:ip=1.2.3.4"],
            },
            mapping=Mapping(),
            oracle_response=OracleResponse(
                text=md,
                model="test",
                usage={
                    "input_tokens": 10,
                    "output_tokens": 5,
                    "cache_read_input_tokens": 0,
                    "cache_creation_input_tokens": 0,
                },
                elapsed_ms=100,
            ),
            investigation_elapsed_ms=1000,
        )

    import json

    summary = await run_batch(
        cfg,
        settings=_settings(),
        elastic=None,  # type: ignore[arg-type]
        sampler=sampler,
        runner=_runner_with_citations,
    )
    rows = [
        json.loads(line)
        for line in (summary.batch_dir / "index.jsonl").read_text().splitlines()
        if line
    ]
    assert len(rows) == 1
    assert rows[0]["citations"] == ["zeek_conn:uid=CX12", "blocklist_hit:ip=1.2.3.4"]


async def test_progress_callback_sees_each_completion(tmp_path: Path) -> None:
    cfg = BatchConfig(oql="x", n=3, concurrency=1, out_dir=tmp_path)
    sampler = _make_sampler(["a1", "a2", "a3"])
    runner = _make_runner()
    seen: list[str] = []

    await run_batch(
        cfg,
        settings=_settings(),
        elastic=None,  # type: ignore[arg-type]
        sampler=sampler,
        runner=runner,
        progress=seen.append,
    )

    # One progress line per completion (warmup + 2 fan-out completions).
    assert len(seen) == 3
    assert "1/3" in seen[0]
    assert "3/3" in seen[-1]

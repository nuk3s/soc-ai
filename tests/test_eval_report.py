"""Unit tests for the batch aggregator + Markdown renderer.

Pure-function tests against hand-built ``IndexRow`` fixtures. No file
I/O for the math; tmp_path covers the round-trip ``build_report`` end
of the contract.

The agreement-extraction regex is already exercised in
``test_eval_batch.py`` (Step A) since both modules reuse the same
``extract_agreement`` function.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from soc_ai.eval import report as report_mod
from soc_ai.eval.report import (
    aggregate,
    build_report,
    load_index,
    render_markdown,
)


def _row(
    alert_id: str,
    *,
    verdict: str | None = "false_positive",
    confidence: float | None = 0.85,
    agreement: str | None = "yes",
    retask_count: int | None = 0,
    investigation_ms: int | None = 22_000,
    claude_ms: int | None = 30_000,
    input_tokens: int | None = 12_000,
    output_tokens: int | None = 5_000,
    cache_read_tokens: int | None = 8_000,
    error: str | None = None,
) -> dict[str, Any]:
    return {
        "alert_id": alert_id,
        "bundle_path": f"/tmp/evals/batch/{alert_id}",
        "verdict": verdict,
        "confidence": confidence,
        "agreement": agreement,
        "retask_count": retask_count,
        "investigation_ms": investigation_ms,
        "claude_ms": claude_ms,
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
        "cache_read_tokens": cache_read_tokens,
        "error": error,
    }


# --------------------------------------------------------------------
# aggregate() — math
# --------------------------------------------------------------------


def test_aggregate_counts_ok_and_error_rows() -> None:
    rows = [
        _row("a1"),
        _row("a2", error="boom"),
        _row("a3"),
    ]
    agg = aggregate(rows)
    assert agg.n_total == 3
    assert agg.n_ok == 2
    assert agg.n_error == 1


def test_aggregate_verdict_counts() -> None:
    rows = [
        _row("a1", verdict="false_positive"),
        _row("a2", verdict="false_positive"),
        _row("a3", verdict="escalate"),
        _row("a4", verdict=None),  # null verdict bucketed as "unknown"
    ]
    agg = aggregate(rows)
    assert agg.verdict_counts["false_positive"] == 2
    assert agg.verdict_counts["escalate"] == 1
    assert agg.verdict_counts["unknown"] == 1


def test_agreement_rate_excludes_synth_rows() -> None:
    """agreement_rate must be computed over real rows only.

    2 real rows: yes, no  -> agreement_rate must be 0.5
    2 synth rows (is_synth=True): yes, yes -> must NOT raise it to 0.75
    Also asserts the new n_synth_excluded field equals 2.
    """
    real_yes = _row("real-1", agreement="yes")
    real_no = _row("real-2", agreement="no")
    synth_yes_a = {**_row("synth-a", agreement="yes"), "is_synth": True}
    synth_yes_b = {**_row("synth-b", agreement="yes"), "is_synth": True}
    rows = [real_yes, real_no, synth_yes_a, synth_yes_b]
    agg = aggregate(rows)
    assert agg.agreement_rate == pytest.approx(0.5)
    assert agg.n_synth_excluded == 2


def test_aggregate_agreement_rate_excludes_unknown() -> None:
    """``agreement_rate`` is yes / (yes + no + partial) — unknown
    answers don't show up in either side. This makes the metric
    robust to extraction misses."""
    rows = [
        _row("a1", agreement="yes"),
        _row("a2", agreement="yes"),
        _row("a3", agreement="yes"),
        _row("a4", agreement="no"),
        _row("a5", agreement="unknown"),  # excluded from rate
    ]
    agg = aggregate(rows)
    assert agg.agreement_counts["yes"] == 3
    assert agg.agreement_counts["no"] == 1
    assert agg.agreement_counts["unknown"] == 1
    assert agg.agreement_rate == pytest.approx(3 / 4)


def test_aggregate_agreement_rate_none_when_all_unknown() -> None:
    rows = [_row("a1", agreement="unknown"), _row("a2", agreement="unknown")]
    agg = aggregate(rows)
    assert agg.agreement_rate is None


def test_aggregate_retask_metrics() -> None:
    rows = [
        _row("a1", retask_count=0),
        _row("a2", retask_count=0),
        _row("a3", retask_count=1),
        _row("a4", retask_count=2),
    ]
    agg = aggregate(rows)
    assert agg.retask_rate == pytest.approx(0.5)  # 2 of 4 retasked
    # mean of (1, 2) = 1.5
    assert agg.mean_retasks_when_retasked == pytest.approx(1.5)


def test_aggregate_retask_rate_none_when_no_data() -> None:
    rows = [_row("a1", retask_count=None)]
    agg = aggregate(rows)
    assert agg.retask_rate is None
    assert agg.mean_retasks_when_retasked is None


def test_aggregate_cache_hit_rate() -> None:
    rows = [
        _row("a1", input_tokens=1_000, cache_read_tokens=4_000),
        _row("a2", input_tokens=2_000, cache_read_tokens=6_000),
    ]
    # total_input=3000, total_cache=10000, denom=13000, hit_rate=10/13
    agg = aggregate(rows)
    assert agg.cache_hit_rate == pytest.approx(10_000 / 13_000)


def test_aggregate_cache_hit_rate_none_when_no_tokens() -> None:
    rows = [_row("a1", input_tokens=None, cache_read_tokens=None)]
    agg = aggregate(rows)
    assert agg.cache_hit_rate is None


def test_aggregate_histogram_basic_shape() -> None:
    rows = [_row(f"a{i}", investigation_ms=i * 1000) for i in range(1, 11)]
    agg = aggregate(rows)
    h = agg.histograms["investigation_ms"]
    assert h.n == 10
    assert h.min == 1000
    assert h.max == 10_000
    # 10 buckets requested when input is non-degenerate
    assert len(h.buckets) == 10
    # Sum of bucket counts equals n
    assert sum(h.buckets) == 10


def test_aggregate_histogram_collapses_when_all_equal() -> None:
    rows = [_row(f"a{i}", investigation_ms=5000) for i in range(5)]
    agg = aggregate(rows)
    h = agg.histograms["investigation_ms"]
    assert h.n == 5
    assert h.min == h.max == 5000
    assert h.buckets == [5]
    # p50/p95/mean all equal the single value


def test_aggregate_histogram_handles_empty_column() -> None:
    rows = [_row("a1", investigation_ms=None)]
    agg = aggregate(rows)
    assert agg.histograms["investigation_ms"].n == 0


def test_aggregate_cross_tab_verdict_x_agreement() -> None:
    rows = [
        _row("a1", verdict="false_positive", agreement="yes"),
        _row("a2", verdict="false_positive", agreement="yes"),
        _row("a3", verdict="false_positive", agreement="no"),
        _row("a4", verdict="escalate", agreement="partial"),
    ]
    agg = aggregate(rows)
    table = agg.cross_tabs["verdict_x_agreement"]
    assert table["false_positive"]["yes"] == 2
    assert table["false_positive"]["no"] == 1
    assert table["false_positive"]["partial"] == 0
    assert table["escalate"]["partial"] == 1


def test_aggregate_cross_tab_retask_x_agreement() -> None:
    rows = [
        _row("a1", retask_count=0, agreement="yes"),
        _row("a2", retask_count=0, agreement="yes"),
        _row("a3", retask_count=1, agreement="no"),
        _row("a4", retask_count=2, agreement="partial"),
    ]
    agg = aggregate(rows)
    table = agg.cross_tabs["retask_x_agreement"]
    assert table["no_retask"]["yes"] == 2
    assert table["with_retask"]["no"] == 1
    assert table["with_retask"]["partial"] == 1


def test_aggregate_top_errors_orders_by_count() -> None:
    rows = [
        _row("a1", error="connection refused"),
        _row("a2", error="connection refused"),
        _row("a3", error="connection refused"),
        _row("a4", error="timeout after 900s"),
        _row("a5", error="alert not found"),
    ]
    agg = aggregate(rows)
    assert agg.top_errors[0]["reason"].startswith("connection refused")
    assert agg.top_errors[0]["count"] == 3
    # All three distinct errors recorded.
    assert len(agg.top_errors) == 3


def test_aggregate_empty_rows() -> None:
    """Edge case: aggregating an empty list shouldn't crash."""
    agg = aggregate([])
    assert agg.n_total == 0
    assert agg.n_ok == 0
    assert agg.agreement_rate is None
    assert agg.retask_rate is None
    assert agg.cache_hit_rate is None


# --------------------------------------------------------------------
# render_markdown — sections present, edge cases
# --------------------------------------------------------------------


def test_render_markdown_contains_all_required_sections(tmp_path: Path) -> None:
    rows = [
        _row("a1", verdict="false_positive", agreement="yes"),
        _row("a2", verdict="escalate", agreement="no"),
        _row("a3", error="boom"),
    ]
    agg = aggregate(rows)
    md = render_markdown(tmp_path, rows, agg)

    # Required headings
    assert "# Eval batch report" in md
    assert "## Verdict × agreement" in md
    assert "## Retask × agreement" in md
    assert "## Synthetic-scenario stratum" in md
    assert "## Performance histograms" in md
    assert "## Top errors" in md
    assert "## Meta-analysis" in md
    assert "## Disagreements" in md


def test_render_markdown_synth_stratum_note_when_absent(tmp_path: Path) -> None:
    """Real-only batch (no synth_stratum) still renders the section header
    with a 'no synth-tagged rows' note."""
    agg = aggregate([_row("a1")])
    md = render_markdown(tmp_path, [_row("a1")], agg, None)
    assert "## Synthetic-scenario stratum" in md
    assert "no synth-tagged rows" in md


def test_render_markdown_surfaces_precision_recall_and_counts(tmp_path: Path) -> None:
    """When a synth_stratum is present, the report surfaces escalation
    precision + recall + TP/FP/FN/TN counts — the objective metrics that
    answer the skeptic test but were previously JSON-only."""
    agg = aggregate([_row("a1")])
    synth_stratum = {
        "true_positive_count": 3,
        "false_positive_count": 1,
        "false_negative_count": 2,
        "true_negative_count": 4,
        "escalation_precision": 0.75,
        "escalation_recall": 0.60,
        "escalation_precision_ci": [0.30, 0.95],
        "escalation_recall_ci": [0.23, 0.88],
        "per_scenario": {},
        "per_tier": {
            "easy": {
                "tier": "easy",
                "true_positive_count": 2,
                "false_negative_count": 0,
                "recall": 1.0,
            },
            "medium": {
                "tier": "medium",
                "true_positive_count": 1,
                "false_negative_count": 1,
                "recall": 0.5,
            },
            "hard": {
                "tier": "hard",
                "true_positive_count": 0,
                "false_negative_count": 1,
                "recall": 0.0,
            },
        },
        "unmatched_scenario_ids": [],
    }
    md = render_markdown(tmp_path, [_row("a1")], agg, synth_stratum)

    assert "## Synthetic-scenario stratum" in md
    assert "Escalation precision" in md
    assert "Escalation recall" in md
    assert "75.0%" in md  # precision
    assert "60.0%" in md  # recall
    # TP/FP/FN/TN counts row present.
    assert "| 3 | 1 | 2 | 4 |" in md
    # Per-tier recall table present.
    assert "Recall by tier" in md


def test_build_report_synth_stratum_rendered_in_markdown(tmp_path: Path) -> None:
    """End-to-end: a batch with benign + TP synth rows produces a report.md
    that surfaces escalation precision (benign correctly closed → precision
    stays 1.0; TP caught → recall 1.0)."""
    real = _row("real-1")
    synth_tp = _row("synth-e1", verdict="true_positive", confidence=0.92)
    synth_tp["is_synth"] = True
    synth_tp["synth_scenario_id"] = "e1-emotet-feodo-c2"
    synth_tp["citations"] = ["blocklist_hit", "typed_path", "prefetch_pivot"]

    synth_benign_closed = _row(
        "synth-b1", verdict="false_positive", confidence=0.8
    )
    synth_benign_closed["is_synth"] = True
    synth_benign_closed["synth_scenario_id"] = "b1-cdn-update-beacon"
    synth_benign_closed["citations"] = ["prefetch_pivot", "typed_path"]

    (tmp_path / "index.jsonl").write_text(
        "\n".join(
            json.dumps(r) for r in (real, synth_tp, synth_benign_closed)
        )
        + "\n",
        encoding="utf-8",
    )

    json_path, md_path, _ = build_report(tmp_path)
    saved = json.loads(json_path.read_text())
    md = md_path.read_text()

    # Benign correctly closed → true negative; TP caught → precision + recall 1.0.
    synth = saved["synth_stratum"]
    assert synth["true_negative_count"] == 1
    assert synth["false_positive_count"] == 0
    assert synth["escalation_precision"] == 1.0
    assert synth["escalation_recall"] == 1.0
    # And the human-readable report surfaces the precision line.
    assert "## Synthetic-scenario stratum" in md
    assert "Escalation precision" in md


def test_render_markdown_handles_empty_batch(tmp_path: Path) -> None:
    """Rendering must not crash on n=0; produce a coherent shell."""
    agg = aggregate([])
    md = render_markdown(tmp_path, [], agg)
    assert "Total rows:** 0" in md
    assert "no errored runs" in md or "Top errors" in md


def test_render_markdown_lists_disagreements(tmp_path: Path) -> None:
    rows = [
        _row("a1", agreement="no", verdict="false_positive", confidence=0.4),
        _row("a2", agreement="yes"),
        _row("a3", agreement="no", verdict="escalate", confidence=0.9),
    ]
    agg = aggregate(rows)
    md = render_markdown(tmp_path, rows, agg)
    assert "/tmp/evals/batch/a1" in md
    assert "/tmp/evals/batch/a3" in md
    # Yes-agreement bundle is NOT listed in the disagreement appendix.
    assert "/tmp/evals/batch/a2" not in md


def test_render_markdown_meta_pointer_when_file_exists(tmp_path: Path) -> None:
    (tmp_path / "meta_analysis.md").write_text("placeholder", encoding="utf-8")
    agg = aggregate([_row("a1")])
    md = render_markdown(tmp_path, [_row("a1")], agg)
    assert "[`meta_analysis.md`]" in md


def test_render_markdown_meta_pointer_when_file_absent(tmp_path: Path) -> None:
    agg = aggregate([_row("a1")])
    md = render_markdown(tmp_path, [_row("a1")], agg)
    assert "Run `soc-ai eval-report --rerun-meta" in md


def test_render_markdown_histogram_includes_percentiles(tmp_path: Path) -> None:
    rows = [_row(f"a{i}", investigation_ms=i * 1000) for i in range(1, 11)]
    agg = aggregate(rows)
    md = render_markdown(tmp_path, rows, agg)
    assert "p50=" in md
    assert "p95=" in md


# --------------------------------------------------------------------
# load_index + build_report — file I/O round-trip
# --------------------------------------------------------------------


def test_load_index_skips_blank_and_corrupt_lines(tmp_path: Path) -> None:
    (tmp_path / "index.jsonl").write_text(
        "\n".join(
            [
                json.dumps(_row("a1")),
                "",
                "not json",
                json.dumps(_row("a2")),
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    rows = load_index(tmp_path)
    assert [r["alert_id"] for r in rows] == ["a1", "a2"]


def test_load_index_missing_file_raises(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        load_index(tmp_path / "no-such-batch")


def test_build_report_writes_both_files(tmp_path: Path) -> None:
    (tmp_path / "index.jsonl").write_text(
        json.dumps(_row("a1")) + "\n" + json.dumps(_row("a2", error="boom")) + "\n",
        encoding="utf-8",
    )
    json_path, md_path, agg = build_report(tmp_path)

    assert json_path.exists()
    assert md_path.exists()
    assert agg.n_total == 2

    saved = json.loads(json_path.read_text())
    assert saved["n_total"] == 2
    assert saved["n_ok"] == 1
    assert saved["n_error"] == 1


def test_build_report_emits_synth_stratum_when_synth_rows_present(
    tmp_path: Path,
) -> None:
    """When index.jsonl contains is_synth=True rows, aggregates.json
    carries a `synth_stratum` block with escalation P/R + Wilson CI
    keyed off the catalogue ground truth."""
    real = _row("real-1")
    synth_correct = _row(
        "synth-doc-e1",
        verdict="true_positive",
        confidence=0.92,
    )
    synth_correct["is_synth"] = True
    synth_correct["synth_scenario_id"] = "e1-emotet-feodo-c2"

    synth_missed = _row(
        "synth-doc-h1",
        verdict="false_positive",  # wrong — h1 expects true_positive
        confidence=0.9,
    )
    synth_missed["is_synth"] = True
    synth_missed["synth_scenario_id"] = "h1-kerberoasting"

    (tmp_path / "index.jsonl").write_text(
        "\n".join(json.dumps(r) for r in (real, synth_correct, synth_missed)) + "\n",
        encoding="utf-8",
    )

    json_path, _, _ = build_report(tmp_path)
    saved = json.loads(json_path.read_text())

    assert "synth_stratum" in saved
    synth = saved["synth_stratum"]
    assert synth["true_positive_count"] == 1
    assert synth["false_negative_count"] == 1
    assert synth["escalation_recall"] == pytest.approx(0.5)
    # Wilson CI lives in synth_stratum, not the top-level aggregates.
    assert isinstance(synth["escalation_recall_ci"], list)
    assert len(synth["escalation_recall_ci"]) == 2
    # Per-scenario detail surfaces both rows.
    assert "e1-emotet-feodo-c2" in synth["per_scenario"]
    assert synth["per_scenario"]["e1-emotet-feodo-c2"]["correct"] is True
    assert synth["per_scenario"]["h1-kerberoasting"]["correct"] is False
    # Per-tier breakdown.
    assert synth["per_tier"]["easy"]["recall"] == 1.0
    assert synth["per_tier"]["hard"]["recall"] == 0.0


def test_build_report_omits_synth_stratum_when_no_synth_rows(tmp_path: Path) -> None:
    """No synth rows → no synth_stratum key (don't pollute real-stratum
    runs with empty-stratum metadata)."""
    (tmp_path / "index.jsonl").write_text(
        json.dumps(_row("real-1")) + "\n",
        encoding="utf-8",
    )
    json_path, _, _ = build_report(tmp_path)
    saved = json.loads(json_path.read_text())
    assert "synth_stratum" not in saved


def test_build_report_is_idempotent(tmp_path: Path) -> None:
    (tmp_path / "index.jsonl").write_text(
        json.dumps(_row("a1")) + "\n",
        encoding="utf-8",
    )
    json_path1, md_path1, _ = build_report(tmp_path)
    text1 = (json_path1, json_path1.read_text(), md_path1.read_text())

    json_path2, md_path2, _ = build_report(tmp_path)
    text2 = (json_path2, json_path2.read_text(), md_path2.read_text())

    assert text1 == text2


# --------------------------------------------------------------------
# private helpers — quick sanity
# --------------------------------------------------------------------


def test_percentile_basics() -> None:
    assert report_mod._percentile([1, 2, 3, 4, 5], 0.5) == pytest.approx(3.0)
    # p95 of 0..99 ≈ 94.05 (linear interp)
    vals = list(range(100))
    assert report_mod._percentile(vals, 0.95) == pytest.approx(94.05)


def test_percentile_single_value() -> None:
    assert report_mod._percentile([42.0], 0.5) == 42.0
    assert report_mod._percentile([42.0], 0.95) == 42.0


def test_bar_zero_value_is_empty_string() -> None:
    assert report_mod._bar(0, 100) == ""


def test_bar_full_value_fills_width() -> None:
    bar = report_mod._bar(100, 100, width=10)
    assert bar == "█" * 10

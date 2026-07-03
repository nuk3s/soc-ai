"""Aggregate a batch's ``index.jsonl`` into ``aggregates.json`` + ``report.md``.

Reads the streaming row file written by :func:`soc_ai.eval.batch.run_batch`,
computes verdict/agreement/retask/perf statistics, and renders a
human-readable Markdown report. Pure and idempotent — re-running on the
same batch dir rebuilds both files from the same input. No oracle calls
in this module; meta-analysis lives in :mod:`soc_ai.eval.meta_analysis`
(Step C).

The renderer's output is the deliverable an operator reads to decide
the next round of soc-ai prompt edits, flow tweaks, or tool-surface
changes.
"""

from __future__ import annotations

import json
import logging
from collections import Counter
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

_LOGGER = logging.getLogger(__name__)

# Ordered so the verdict table's columns line up across runs.
_AGREEMENT_KEYS: tuple[str, ...] = ("yes", "no", "partial", "unknown")

# Number of disagreement bundles to surface in the report appendix.
# The operator reads these by hand to validate the oracle's "no" calls
# before pulling the trigger on prompt changes.
_DISAGREEMENT_LIST_MAX = 20


@dataclass
class Histogram:
    """Compact summary of a numeric column. Always 10 buckets when
    possible; degenerate cases (n<2 or all-equal) collapse to a
    single-bucket shape so consumers can render uniformly."""

    n: int
    min: float | None = None
    max: float | None = None
    mean: float | None = None
    p50: float | None = None
    p95: float | None = None
    buckets: list[int] = field(default_factory=list)
    edges: list[float] = field(default_factory=list)


@dataclass
class Aggregates:
    """The structured summary of one batch.

    Persisted as ``aggregates.json``. The renderer projects this into
    Markdown for ``report.md``; downstream tooling (cross-batch diff,
    eventually) consumes the JSON directly.
    """

    n_total: int
    n_ok: int
    n_error: int
    verdict_counts: dict[str, int]
    agreement_counts: dict[str, int]
    agreement_rate: float | None
    n_synth_excluded: int
    retask_rate: float | None
    mean_retasks_when_retasked: float | None
    cache_hit_rate: float | None
    histograms: dict[str, Histogram]
    cross_tabs: dict[str, dict[str, dict[str, int]]]
    top_errors: list[dict[str, Any]]


# --------------------------------------------------------------------
# index.jsonl loading
# --------------------------------------------------------------------


def load_index(batch_dir: Path) -> list[dict[str, Any]]:
    """Read every row from ``<batch_dir>/index.jsonl``.

    Returns dicts (not :class:`IndexRow` instances) so a future schema
    addition doesn't break the loader. Skips malformed lines.
    """
    path = batch_dir / "index.jsonl"
    if not path.exists():
        raise FileNotFoundError(f"no index.jsonl at {path}")

    rows: list[dict[str, Any]] = []
    with path.open(encoding="utf-8") as f:
        for raw in f:
            line = raw.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                _LOGGER.warning("skipping malformed index.jsonl line: %r", line[:200])
    return rows


# --------------------------------------------------------------------
# aggregation
# --------------------------------------------------------------------


def _percentile(sorted_values: list[float], p: float) -> float:
    """Linear-interpolated percentile. ``sorted_values`` MUST be sorted."""
    if not sorted_values:
        raise ValueError("empty values")
    k = (len(sorted_values) - 1) * p
    f = int(k)
    c = min(f + 1, len(sorted_values) - 1)
    if f == c:
        return float(sorted_values[f])
    return float(sorted_values[f] + (sorted_values[c] - sorted_values[f]) * (k - f))


def _histogram(values: list[float], n_buckets: int = 10) -> Histogram:
    """Build a Histogram over ``values``.

    Non-numeric / None entries are filtered before this is called.
    Edge case: all-equal values → one bucket with the full count.
    """
    if not values:
        return Histogram(n=0)
    sorted_v = sorted(values)
    lo, hi = sorted_v[0], sorted_v[-1]
    mean = sum(sorted_v) / len(sorted_v)
    p50 = _percentile(sorted_v, 0.50)
    p95 = _percentile(sorted_v, 0.95)
    if lo == hi:
        return Histogram(
            n=len(sorted_v),
            min=lo,
            max=hi,
            mean=mean,
            p50=p50,
            p95=p95,
            buckets=[len(sorted_v)],
            edges=[lo, hi],
        )
    span = hi - lo
    width = span / n_buckets
    buckets = [0] * n_buckets
    for v in sorted_v:
        idx = min(int((v - lo) / width), n_buckets - 1)
        buckets[idx] += 1
    edges = [lo + i * width for i in range(n_buckets + 1)]
    return Histogram(
        n=len(sorted_v),
        min=lo,
        max=hi,
        mean=mean,
        p50=p50,
        p95=p95,
        buckets=buckets,
        edges=edges,
    )


def _safe_int(v: Any) -> int | None:
    if v is None:
        return None
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def aggregate(rows: list[dict[str, Any]]) -> Aggregates:  # noqa: PLR0915 - single linear pass over every metric family
    """Compute :class:`Aggregates` from a list of index.jsonl row dicts.

    Tolerates missing fields on individual rows (a row without an
    ``investigation_ms`` is just absent from that histogram); errors
    show up only in ``n_error`` + ``top_errors``.
    """
    n_total = len(rows)
    ok_rows = [r for r in rows if not r.get("error")]
    err_rows = [r for r in rows if r.get("error")]
    n_ok = len(ok_rows)
    n_error = len(err_rows)

    verdict_counts = dict(Counter(r.get("verdict") or "unknown" for r in ok_rows))

    # agreement_rate is computed over the REAL stratum only — synth rows already
    # have known ground truth and their own objective metrics (_compute_synth_stratum).
    # Including synth "yes" rows would inflate the GO/NO-GO gate.
    real_ok_rows = [r for r in ok_rows if not r.get("is_synth")]
    n_synth_excluded = len(ok_rows) - len(real_ok_rows)

    agreement_counts = {k: 0 for k in _AGREEMENT_KEYS}
    for r in real_ok_rows:
        a = r.get("agreement") or "unknown"
        if a not in agreement_counts:
            a = "unknown"
        agreement_counts[a] += 1

    classified = sum(agreement_counts[k] for k in ("yes", "no", "partial"))
    agreement_rate: float | None = agreement_counts["yes"] / classified if classified > 0 else None

    # retask_rate over the REAL stratum only, consistent with agreement_rate —
    # synth rows would otherwise skew the rate without disclosure.
    retasks = [r["retask_count"] for r in real_ok_rows if isinstance(r.get("retask_count"), int)]
    retask_rate: float | None = None
    mean_retasks_when_retasked: float | None = None
    if retasks:
        retask_rate = sum(1 for x in retasks if x > 0) / len(retasks)
        non_zero = [x for x in retasks if x > 0]
        if non_zero:
            mean_retasks_when_retasked = sum(non_zero) / len(non_zero)

    histograms: dict[str, Histogram] = {}
    for col in (
        "investigation_ms",
        "claude_ms",
        "input_tokens",
        "output_tokens",
        "cache_read_tokens",
    ):
        values = [float(v) for r in ok_rows if (v := _safe_int(r.get(col))) is not None]
        histograms[col] = _histogram(values)

    # cache_hit_rate: cache_read / (input + cache_read) — cached
    # tokens are not counted in input_tokens by the upstream's accounting,
    # so the denominator is the sum.
    total_input = sum(_safe_int(r.get("input_tokens")) or 0 for r in ok_rows)
    total_cache = sum(_safe_int(r.get("cache_read_tokens")) or 0 for r in ok_rows)
    denom = total_input + total_cache
    cache_hit_rate: float | None = total_cache / denom if denom > 0 else None

    # Cross-tabs: verdict × agreement, retask × agreement. Built over the REAL
    # stratum (synth excluded), consistent with agreement_rate — otherwise the
    # cross-tab `yes` column overstates the headline by the synth-row count and
    # the report's own tables don't reconcile with its headline number.
    verdict_x_agreement: dict[str, dict[str, int]] = {}
    for r in real_ok_rows:
        # Note: distinct name from the walrus-bound `v` (int | None) above so
        # the verdict key stays typed as a str.
        verdict_key = r.get("verdict") or "unknown"
        a = r.get("agreement") or "unknown"
        if a not in _AGREEMENT_KEYS:
            a = "unknown"
        verdict_x_agreement.setdefault(verdict_key, dict.fromkeys(_AGREEMENT_KEYS, 0))[a] += 1

    retask_x_agreement: dict[str, dict[str, int]] = {
        "with_retask": dict.fromkeys(_AGREEMENT_KEYS, 0),
        "no_retask": dict.fromkeys(_AGREEMENT_KEYS, 0),
    }
    for r in real_ok_rows:
        rc = _safe_int(r.get("retask_count"))
        if rc is None:
            continue
        bucket = "with_retask" if rc > 0 else "no_retask"
        a = r.get("agreement") or "unknown"
        if a not in _AGREEMENT_KEYS:
            a = "unknown"
        retask_x_agreement[bucket][a] += 1

    err_counter: Counter[str] = Counter()
    for r in err_rows:
        err = r.get("error") or "(empty)"
        # Truncate to keep distinct error messages from drowning the
        # top-N when a tail is just a stack trace's address.
        key = err[:120]
        err_counter[key] += 1
    top_errors = [
        {"reason": reason, "count": count} for reason, count in err_counter.most_common(10)
    ]

    return Aggregates(
        n_total=n_total,
        n_ok=n_ok,
        n_error=n_error,
        verdict_counts=verdict_counts,
        agreement_counts=agreement_counts,
        agreement_rate=agreement_rate,
        n_synth_excluded=n_synth_excluded,
        retask_rate=retask_rate,
        mean_retasks_when_retasked=mean_retasks_when_retasked,
        cache_hit_rate=cache_hit_rate,
        histograms=histograms,
        cross_tabs={
            "verdict_x_agreement": verdict_x_agreement,
            "retask_x_agreement": retask_x_agreement,
        },
        top_errors=top_errors,
    )


# --------------------------------------------------------------------
# JSON serialization
# --------------------------------------------------------------------


def aggregates_to_json(
    agg: Aggregates, synth_stratum: dict[str, Any] | None = None
) -> dict[str, Any]:
    """Project :class:`Aggregates` into a JSON-friendly dict.

    ``synth_stratum`` is included only when synth-TP rows were present in
    the source index.jsonl — keeps real-only batches' output unchanged.
    """
    out = asdict(agg)
    # asdict turns Histogram dataclasses into dicts already; nothing
    # else to flatten.
    if synth_stratum is not None:
        out["synth_stratum"] = synth_stratum
    return out


def write_aggregates_json(
    batch_dir: Path,
    agg: Aggregates,
    synth_stratum: dict[str, Any] | None = None,
) -> Path:
    path = batch_dir / "aggregates.json"
    path.write_text(
        json.dumps(aggregates_to_json(agg, synth_stratum), indent=2),
        encoding="utf-8",
    )
    return path


# --------------------------------------------------------------------
# Markdown rendering
# --------------------------------------------------------------------

# Unicode block-elements for the histogram bars.
_BARS = "▁▂▃▄▅▆▇█"


def _bar(value: int, peak: int, width: int = 20) -> str:
    if peak <= 0 or value <= 0:
        return ""
    frac = value / peak
    full_blocks = int(frac * width)
    rem = (frac * width) - full_blocks
    bar = "█" * full_blocks
    if full_blocks < width:
        idx = int(rem * (len(_BARS) - 1))
        if idx > 0:
            bar += _BARS[idx]
    return bar


def _fmt_num(v: float | None, *, ndigits: int = 0) -> str:
    if v is None:
        return "—"
    if ndigits == 0:
        return f"{v:,.0f}"
    return f"{v:,.{ndigits}f}"


def _fmt_pct(v: float | None) -> str:
    if v is None:
        return "—"
    return f"{v * 100:.1f}%"


def _render_header(
    batch_dir: Path,
    rows: list[dict[str, Any]],
    agg: Aggregates,
) -> str:
    synth_note = (
        f" ({agg.n_synth_excluded} synth rows excluded — see synth stratum)"
        if agg.n_synth_excluded > 0
        else ""
    )
    return (
        f"# Eval batch report\n\n"
        f"- **Batch dir:** `{batch_dir}`\n"
        f"- **Total rows:** {agg.n_total}\n"
        f"- **OK / errored:** {agg.n_ok} / {agg.n_error}\n"
        f"- **Agreement rate (real stratum, yes / classified):** "
        f"{_fmt_pct(agg.agreement_rate)}{synth_note}\n"
        f"- **Retask rate:** {_fmt_pct(agg.retask_rate)}\n"
        f"- **Cache hit rate:** {_fmt_pct(agg.cache_hit_rate)}\n"
    )


def _render_verdict_table(agg: Aggregates) -> str:
    lines = ["## Verdict × agreement\n"]
    header = "| verdict | yes | no | partial | unknown | total |\n"
    sep = "|---|---:|---:|---:|---:|---:|\n"
    lines.append(header)
    lines.append(sep)
    cross = agg.cross_tabs.get("verdict_x_agreement") or {}
    # Stable ordering: largest verdict first, with totals on the right.
    sorted_verdicts = sorted(
        cross.keys(),
        key=lambda v: -sum(cross[v].values()),
    )
    for v in sorted_verdicts:
        row = cross[v]
        total = sum(row.values())
        lines.append(
            f"| `{v}` | {row.get('yes', 0)} | {row.get('no', 0)} | "
            f"{row.get('partial', 0)} | {row.get('unknown', 0)} | "
            f"{total} |\n"
        )
    return "".join(lines)


def _render_retask(agg: Aggregates) -> str:
    cross = agg.cross_tabs.get("retask_x_agreement") or {}
    return (
        f"## Retask × agreement\n\n"
        f"- **Retask rate:** {_fmt_pct(agg.retask_rate)} "
        f"(fraction of OK runs that retasked at least once)\n"
        f"- **Mean retasks when retasked:** "
        f"{_fmt_num(agg.mean_retasks_when_retasked, ndigits=2)}\n\n"
        f"| | yes | no | partial | unknown |\n"
        f"|---|---:|---:|---:|---:|\n"
        f"| **retasked** | "
        f"{cross.get('with_retask', {}).get('yes', 0)} | "
        f"{cross.get('with_retask', {}).get('no', 0)} | "
        f"{cross.get('with_retask', {}).get('partial', 0)} | "
        f"{cross.get('with_retask', {}).get('unknown', 0)} |\n"
        f"| **no retask** | "
        f"{cross.get('no_retask', {}).get('yes', 0)} | "
        f"{cross.get('no_retask', {}).get('no', 0)} | "
        f"{cross.get('no_retask', {}).get('partial', 0)} | "
        f"{cross.get('no_retask', {}).get('unknown', 0)} |\n"
    )


def _render_histogram(name: str, h: Histogram) -> str:
    if h.n == 0:
        return f"### {name}\n\n_(no data)_\n"
    peak = max(h.buckets) if h.buckets else 0
    lines = [
        f"### {name}\n",
        f"- n={h.n}, min={_fmt_num(h.min)}, p50={_fmt_num(h.p50)}, "
        f"p95={_fmt_num(h.p95)}, max={_fmt_num(h.max)}\n",
        "```",
    ]
    for i, count in enumerate(h.buckets):
        if i + 1 < len(h.edges):
            lo, hi = h.edges[i], h.edges[i + 1]
        else:
            lo, hi = h.edges[i], h.edges[-1]
        bar = _bar(count, peak)
        lines.append(f"  [{_fmt_num(lo):>10} .. {_fmt_num(hi):>10})  {count:>5}  {bar}")
    lines.append("```\n")
    return "\n".join(lines)


def _render_histograms(agg: Aggregates) -> str:
    sections = ["## Performance histograms\n"]
    label_map = {
        "investigation_ms": "Investigation latency (ms)",
        "claude_ms": "oracle latency (ms)",
        "input_tokens": "Input tokens (per run)",
        "output_tokens": "Output tokens (per run)",
        "cache_read_tokens": "Cache-read input tokens (per run)",
    }
    for col, h in agg.histograms.items():
        sections.append(_render_histogram(label_map.get(col, col), h))
    return "\n".join(sections)


def _render_top_errors(agg: Aggregates) -> str:
    if not agg.top_errors:
        return "## Top errors\n\n_(no errored runs)_\n"
    lines = ["## Top errors\n", "| count | reason |", "|---:|---|"]
    for e in agg.top_errors:
        reason = str(e.get("reason", "")).replace("|", "\\|")
        lines.append(f"| {e.get('count', 0)} | `{reason}` |")
    return "\n".join(lines) + "\n"


def _render_disagreement_appendix(rows: list[dict[str, Any]]) -> str:
    """List bundle paths where the oracle said "no" — highest-signal cases.

    These are what the operator reads by hand to validate the
    aggregate findings before changing prompts.
    """
    disagreements = [r for r in rows if not r.get("error") and r.get("agreement") == "no"]
    if not disagreements:
        return "## Disagreements (oracle said `no`)\n\n_(none)_\n"
    sample = disagreements[:_DISAGREEMENT_LIST_MAX]
    lines = [
        f"## Disagreements (oracle said `no`) — top {len(sample)}\n",
        "Read these by hand to validate the aggregate findings.\n",
    ]
    for r in sample:
        bp = r.get("bundle_path") or "(missing)"
        v = r.get("verdict") or "?"
        c = r.get("confidence")
        c_str = f"{c:.2f}" if isinstance(c, (int, float)) else "?"
        lines.append(f"- `{bp}` — verdict={v} confidence={c_str}")
    if len(disagreements) > len(sample):
        lines.append(
            f"\n_(plus {len(disagreements) - len(sample)} more — "
            f"see `index.jsonl` filtered by `agreement == 'no'`)_"
        )
    return "\n".join(lines) + "\n"


def _render_synth_stratum(synth_stratum: dict[str, Any] | None) -> str:
    """Render the synthetic-scenario stratum: escalation precision + recall.

    The synth stratum has known ground truth, so it reports the objective
    metrics the real stratum can't — escalation **precision** (did the system
    escalate benign traffic it shouldn't have?) alongside **recall** (did it
    catch the seeded true positives?). Precision is only meaningful once the
    catalogue carries benign (expected≠TP) scenarios; with a TP-only catalogue
    ``false_positive_count`` / ``true_negative_count`` stay 0 and precision
    pins to 1.0 or is undefined. Absent (real-only batch) → a short note.
    """
    if synth_stratum is None:
        return "## Synthetic-scenario stratum\n\n_(no synth-tagged rows in this batch)_\n"

    tp = synth_stratum.get("true_positive_count", 0)
    fp = synth_stratum.get("false_positive_count", 0)
    fn = synth_stratum.get("false_negative_count", 0)
    tn = synth_stratum.get("true_negative_count", 0)
    precision = synth_stratum.get("escalation_precision")
    recall = synth_stratum.get("escalation_recall")
    recall_vo = synth_stratum.get("escalation_recall_verdict_only")
    p_ci = synth_stratum.get("escalation_precision_ci") or [None, None]
    r_ci = synth_stratum.get("escalation_recall_ci") or [None, None]
    r_vo_ci = synth_stratum.get("escalation_recall_verdict_only_ci") or [None, None]
    fn_break = synth_stratum.get("false_negative_breakdown") or {}

    def _ci(ci: list[Any]) -> str:
        lo, hi = [*ci, None, None][:2]
        if lo is None or hi is None:
            return "—"
        return f"[{_fmt_pct(lo)}, {_fmt_pct(hi)}]"

    lines = [
        "## Synthetic-scenario stratum\n",
        "Objective escalation metrics against seeded ground truth. "
        "Precision answers the skeptic test — did the system escalate benign "
        "traffic it should have closed? (Needs benign scenarios in the "
        "catalogue to be meaningful.)\n",
        "| metric | value | 95% CI |",
        "|---|---:|:---:|",
        f"| **Escalation precision** (TP / (TP+FP)) | {_fmt_pct(precision)} | {_ci(p_ci)} |",
        f"| **Escalation recall — verdict-only** (correct escalation, any conf) "
        f"| {_fmt_pct(recall_vo)} | {_ci(r_vo_ci)} |",
        f"| Escalation recall — high-confidence (≥ floor) | {_fmt_pct(recall)} | {_ci(r_ci)} |",
        "",
        "| TP | FP | FN | TN |",
        "|---:|---:|---:|---:|",
        f"| {tp} | {fp} | {fn} | {tn} |",
    ]
    if fn_break:
        # Split FN so a confidence-floor miss or an errored run (infra loss) isn't
        # read as a detection failure. `errored` in particular is infra, not the model.
        lines += [
            "",
            "**False-negative breakdown** "
            "(missed = wrong verdict · low_confidence = correct escalation below floor · "
            "errored = no result row / infra loss)\n",
            "| missed | low_confidence | errored |",
            "|---:|---:|---:|",
            f"| {fn_break.get('missed', 0)} | {fn_break.get('low_confidence', 0)} "
            f"| {fn_break.get('errored', 0)} |",
        ]

    per_tier = synth_stratum.get("per_tier") or {}
    if per_tier:
        lines.append("\n**Recall by tier**\n")
        lines.append("| tier | TP | FN | recall |")
        lines.append("|---|---:|---:|---:|")
        for tier in ("easy", "medium", "hard"):
            t = per_tier.get(tier)
            if not t:
                continue
            lines.append(
                f"| {tier} | {t.get('true_positive_count', 0)} | "
                f"{t.get('false_negative_count', 0)} | {_fmt_pct(t.get('recall'))} |"
            )

    unmatched = synth_stratum.get("unmatched_scenario_ids") or []
    if unmatched:
        lines.append(
            f"\n_Unmatched synth rows (no catalogue scenario): "
            f"{', '.join(str(u) for u in unmatched)}_"
        )
    return "\n".join(lines) + "\n"


def _render_meta_pointer(batch_dir: Path) -> str:
    """Pointer to meta_analysis.md if it exists; placeholder otherwise.

    Step C populates the file. Step B's report just notes whether
    it's there yet.
    """
    meta_path = batch_dir / "meta_analysis.md"
    if meta_path.exists():
        return (
            f"## Meta-analysis\n\nSee [`meta_analysis.md`]({meta_path.name}) "
            f"for the oracle's batch-level architecture recommendations.\n"
        )
    return (
        "## Meta-analysis\n\n_Run `soc-ai eval-report --rerun-meta "
        f"{batch_dir}` to generate the oracle's batch-level architecture "
        "recommendations._\n"
    )


def render_markdown(
    batch_dir: Path,
    rows: list[dict[str, Any]],
    agg: Aggregates,
    synth_stratum: dict[str, Any] | None = None,
) -> str:
    """Render the full ``report.md`` body.

    ``synth_stratum`` (when present) is rendered as its own section so the
    objective escalation precision/recall the synth stratum measures is
    visible in the human-readable report — not just buried in
    ``aggregates.json``.
    """
    sections = [
        _render_header(batch_dir, rows, agg),
        _render_verdict_table(agg),
        _render_retask(agg),
        _render_synth_stratum(synth_stratum),
        _render_histograms(agg),
        _render_top_errors(agg),
        _render_meta_pointer(batch_dir),
        _render_disagreement_appendix(rows),
    ]
    return "\n".join(sections)


def write_report_markdown(
    batch_dir: Path,
    rows: list[dict[str, Any]],
    agg: Aggregates,
    synth_stratum: dict[str, Any] | None = None,
) -> Path:
    path = batch_dir / "report.md"
    path.write_text(render_markdown(batch_dir, rows, agg, synth_stratum), encoding="utf-8")
    return path


# --------------------------------------------------------------------
# Top-level entry: read index.jsonl, write aggregates.json + report.md
# --------------------------------------------------------------------


_DEFAULT_SCENARIOS_DIR = Path(__file__).parent / "synth_scenarios"


def _compute_synth_stratum(
    rows: list[dict[str, Any]], scenarios_dir: Path
) -> dict[str, Any] | None:
    """Score the synth subset of ``rows`` against the catalogue.

    Returns ``None`` when no rows are tagged ``is_synth=True`` (so
    real-only batches don't grow a synth_stratum key in aggregates.json).
    Errors loading the catalogue surface as a logged warning and a
    None return — meta-analysis should still run on the real stratum.
    """
    # ALL synth rows, including errored/timed-out runs (which carry is_synth=True
    # + an error and no verdict). The attempted set is derived from these so an
    # errored expected-TP run counts as a miss (FN), not a silently-dropped row
    # that shrinks the recall denominator.
    synth_rows_all = [r for r in rows if r.get("is_synth")]
    if not synth_rows_all:
        return None
    attempted_ids = {
        r.get("synth_scenario_id") for r in synth_rows_all if r.get("synth_scenario_id")
    }
    try:
        from soc_ai.eval.synth_loader import load_all_scenarios  # noqa: PLC0415
        from soc_ai.eval.synth_score import SynthRow, score_synth_stratum  # noqa: PLC0415

        # Score only against scenarios actually attempted this batch — a subset
        # --synth-set must not be penalised for catalogue scenarios it never ran.
        scenarios = [s for s in load_all_scenarios(scenarios_dir) if s.id in attempted_ids]
    except Exception as e:
        _LOGGER.warning("synth stratum scoring skipped — catalogue load failed: %s", e)
        return None

    if not scenarios:
        return None

    # Only successfully-scored runs contribute a verdict row; errored runs are
    # folded in as false negatives by the catalogue-level pass in the scorer.
    synth_rows_raw = [r for r in synth_rows_all if not r.get("error")]
    synth_rows = [
        SynthRow(
            scenario_id=r.get("synth_scenario_id") or "",
            verdict=r.get("verdict") or "unknown",
            confidence=float(r.get("confidence") or 0.0),
            citations=list(r.get("citations") or []),
        )
        for r in synth_rows_raw
    ]
    score = score_synth_stratum(synth_rows, scenarios=scenarios)
    return score.to_dict()


def build_report(
    batch_dir: Path, *, scenarios_dir: Path = _DEFAULT_SCENARIOS_DIR
) -> tuple[Path, Path, Aggregates]:
    """Read ``index.jsonl``, compute aggregates, write JSON + Markdown.

    When the batch contains synth-tagged rows (``is_synth=True``), an
    additional ``synth_stratum`` block is computed against the scenario
    catalogue at ``scenarios_dir`` and embedded in ``aggregates.json``.
    The real-stratum metric ``agreement_rate`` is computed over non-synth
    rows only — synth rows have known ground truth and their own objective
    metrics in the synth_stratum block; blending them inflates the GO/NO-GO
    gate.

    Idempotent: re-running overwrites both output files.
    """
    rows = load_index(batch_dir)
    agg = aggregate(rows)
    synth_stratum = _compute_synth_stratum(rows, scenarios_dir)
    json_path = write_aggregates_json(batch_dir, agg, synth_stratum)
    md_path = write_report_markdown(batch_dir, rows, agg, synth_stratum)
    return json_path, md_path, agg

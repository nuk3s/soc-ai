#!/usr/bin/env python3
"""Compare two arms of the synthetic eval: verdict quality and cost per run.

Usage::

    scripts/eval/compare-arms.py <batch-dir-A> <batch-dir-B>

Each argument is a batch directory that ``soc-ai validate-batch`` wrote. It
holds ``index.jsonl``, ``aggregates.json`` and one bundle directory per run.
An arm directory also works: the newest ``batch-<ts>`` in it with an
``index.jsonl`` is read.

Per arm the script prints the run counts, the synth stratum metrics from
``aggregates.json``, the mean model usage per run and the median
investigation wall time. The usage is the sum of the ``usage`` events in each
bundle's ``events.jsonl``. The wall time is ``investigation_ms`` from
``index.jsonl``. Then it prints the strict passes k/N of each scenario for A
and B with the change in pass rate, and the change in input tokens per run.

Standard library only, so any Python 3.12 runs it without the install's
environment. See ``docs/dev/eval-arms.md`` for the runbook.

Exit codes: 0 compared, 2 an argument is not a readable batch directory.
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

# The payload keys of a ``usage`` event, summed per run.
USAGE_KEYS: tuple[str, ...] = ("input_tokens", "output_tokens", "requests", "tool_calls")
NA = "n/a"


class BatchDirError(Exception):
    """An argument names no readable batch directory."""


@dataclass(frozen=True)
class Arm:
    """One batch directory, read."""

    label: str
    batch_dir: Path
    rows: tuple[dict[str, Any], ...]
    aggregates: dict[str, Any] | None
    # One entry per run whose bundle has an events.jsonl: the summed usage.
    usage: tuple[dict[str, int], ...]

    @property
    def ok_rows(self) -> list[dict[str, Any]]:
        return [r for r in self.rows if not r.get("error")]

    @property
    def stratum(self) -> dict[str, Any]:
        return _as_dict((self.aggregates or {}).get("synth_stratum"))

    def mean_usage(self, key: str) -> float | None:
        if not self.usage:
            return None
        return statistics.fmean(u[key] for u in self.usage)

    def median_wall_s(self) -> float | None:
        walls = [
            int(r["investigation_ms"])
            for r in self.rows
            if isinstance(r.get("investigation_ms"), int | float)
        ]
        return statistics.median(walls) / 1000 if walls else None


def _as_dict(value: object) -> dict[str, Any]:
    return dict(value) if isinstance(value, Mapping) else {}


def _as_int(value: object) -> int:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int | float):
        return int(value)
    return 0


def resolve_batch_dir(path: Path) -> Path:
    """The batch directory ``path`` names: itself, or its newest ``batch-*`` child."""
    if (path / "index.jsonl").is_file():
        return path
    if path.is_dir():
        batches = sorted(
            p for p in path.glob("batch-*") if p.is_dir() and (p / "index.jsonl").is_file()
        )
        if batches:
            return batches[-1]
    raise BatchDirError(
        f"{path}: no index.jsonl here and no batch-* directory with one. "
        "Pass the batch directory that validate-batch wrote."
    )


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    """Every JSON object line of ``path``. A line that does not parse is skipped."""
    out: list[dict[str, Any]] = []
    with path.open(encoding="utf-8") as f:
        for raw in f:
            line = raw.strip()
            if not line:
                continue
            try:
                value = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(value, dict):
                out.append(value)
    return out


def bundle_dir(row: Mapping[str, Any], batch_dir: Path) -> Path | None:
    """The bundle of one run. A relative path that moved with the batch is found by name."""
    raw = row.get("bundle_path")
    if not isinstance(raw, str) or not raw:
        return None
    path = Path(raw)
    if (path / "events.jsonl").is_file():
        return path
    moved = batch_dir / path.name
    if (moved / "events.jsonl").is_file():
        return moved
    return None


def read_usage(bundle: Path) -> dict[str, int]:
    """The sum of every ``usage`` event's counts in one bundle."""
    totals = dict.fromkeys(USAGE_KEYS, 0)
    for event in read_jsonl(bundle / "events.jsonl"):
        if event.get("kind") != "usage":
            continue
        payload = _as_dict(event.get("payload"))
        for key in USAGE_KEYS:
            totals[key] += _as_int(payload.get(key))
    return totals


def load_arm(label: str, path: Path) -> Arm:
    """Read one batch directory. Raises :class:`BatchDirError` when there is none."""
    batch = resolve_batch_dir(path)
    rows = tuple(read_jsonl(batch / "index.jsonl"))
    aggregates: dict[str, Any] | None = None
    agg_path = batch / "aggregates.json"
    if agg_path.is_file():
        try:
            aggregates = _as_dict(json.loads(agg_path.read_text(encoding="utf-8")))
        except json.JSONDecodeError:
            aggregates = None
    usage: list[dict[str, int]] = []
    for row in rows:
        bundle = bundle_dir(row, batch)
        if bundle is not None:
            usage.append(read_usage(bundle))
    return Arm(label=label, batch_dir=batch, rows=rows, aggregates=aggregates, usage=tuple(usage))


def fmt_rate(value: object) -> str:
    return f"{value:.3f}" if isinstance(value, int | float) else NA


def fmt_ci(value: object) -> str:
    if isinstance(value, Sequence) and not isinstance(value, str) and len(value) == 2:
        lo, hi = value
        if isinstance(lo, int | float) and isinstance(hi, int | float):
            return f"[{lo:.3f}, {hi:.3f}]"
    return NA


def fmt_mean(value: float | None, digits: int) -> str:
    return NA if value is None else f"{value:.{digits}f}"


def summary_lines(arm: Arm) -> list[str]:
    """The block one arm prints: counts, quality, cost."""
    ok = arm.ok_rows
    fallbacks = sum(1 for r in ok if r.get("is_fallback"))
    lines = [
        f"== arm {arm.label}: {arm.batch_dir}",
        f"runs {len(arm.rows)}  ok {len(ok)}  errors {len(arm.rows) - len(ok)}  "
        f"fallbacks {fallbacks}",
    ]
    if arm.aggregates is None:
        lines.append(f"no aggregates.json. Run: soc-ai eval-report --no-meta {arm.batch_dir}")
    s = arm.stratum
    if arm.aggregates is not None and not s:
        lines.append("no synth stratum in aggregates.json")
    if s:
        m = _as_dict(s.get("macro"))
        lines += [
            f"strict recall (macro)           {fmt_rate(m.get('strict_recall_macro'))}  "
            f"ci {fmt_ci(m.get('strict_recall_macro_ci'))}",
            f"verdict-only recall (macro)     {fmt_rate(m.get('verdict_only_recall_macro'))}  "
            f"ci {fmt_ci(m.get('verdict_only_recall_macro_ci'))}",
            f"benign strict (macro)           {fmt_rate(m.get('benign_strict_macro'))}  "
            f"ci {fmt_ci(m.get('benign_strict_macro_ci'))}",
            f"false escalation rate (macro)   {fmt_rate(m.get('false_escalation_rate_macro'))}",
            f"escalation precision            {fmt_rate(s.get('escalation_precision'))}  "
            f"ci {fmt_ci(s.get('escalation_precision_ci'))}",
            f"escalation recall               {fmt_rate(s.get('escalation_recall'))}  "
            f"ci {fmt_ci(s.get('escalation_recall_ci'))}",
            f"escalation recall, verdict only {fmt_rate(s.get('escalation_recall_verdict_only'))}",
            f"flip rate                       {fmt_rate(s.get('flip_rate'))}",
        ]
    lines.append(
        f"per run ({len(arm.usage)} bundles): "
        f"input tokens {fmt_mean(arm.mean_usage('input_tokens'), 0)}  "
        f"output tokens {fmt_mean(arm.mean_usage('output_tokens'), 0)}  "
        f"requests {fmt_mean(arm.mean_usage('requests'), 2)}  "
        f"tool calls {fmt_mean(arm.mean_usage('tool_calls'), 2)}"
    )
    lines.append(f"median investigation wall time {fmt_mean(arm.median_wall_s(), 1)} s")
    return lines


def scenario_passes(arm: Arm) -> dict[str, tuple[int, int]]:
    """Strict passes and attempted runs per scenario.

    ``per_scenario_stability`` carries k/N. An older aggregates.json without
    it has one run per scenario, read from ``per_scenario`` as 1/1 or 0/1.
    """
    s = arm.stratum
    stability = _as_dict(s.get("per_scenario_stability"))
    if stability:
        return {
            str(sid): (
                _as_int(_as_dict(v).get("strict_passes")),
                _as_int(_as_dict(v).get("repeats")),
            )
            for sid, v in stability.items()
        }
    return {
        str(sid): (1 if _as_dict(v).get("correct") else 0, 1)
        for sid, v in _as_dict(s.get("per_scenario")).items()
    }


def scenario_lines(a: Arm, b: Arm) -> list[str]:
    """The per-scenario table: k/N for A and B, and B's pass rate less A's."""
    pa, pb = scenario_passes(a), scenario_passes(b)
    keys = sorted(set(pa) | set(pb))
    if not keys:
        return []
    width = max(len("scenario"), *(len(k) for k in keys))
    lines = [f"{'scenario':<{width}}  {'A k/N':>7}  {'B k/N':>7}  {'delta':>6}"]
    for key in keys:
        ka, na = pa.get(key, (0, 0))
        kb, nb = pb.get(key, (0, 0))
        delta = f"{kb / nb - ka / na:+.2f}" if na and nb else NA
        cell_a = f"{ka}/{na}" if key in pa else NA
        cell_b = f"{kb}/{nb}" if key in pb else NA
        lines.append(f"{key:<{width}}  {cell_a:>7}  {cell_b:>7}  {delta:>6}")
    return lines


def token_change_line(a: Arm, b: Arm) -> str:
    ia, ib = a.mean_usage("input_tokens"), b.mean_usage("input_tokens")
    change = f"{(ib - ia) / ia * 100:+.1f}%" if ia and ib is not None else NA
    return f"input tokens per run: A {fmt_mean(ia, 0)}  B {fmt_mean(ib, 0)}  change {change}"


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Compare two validate-batch directories: quality and cost per run."
    )
    parser.add_argument("batch_a", type=Path, help="batch directory of arm A")
    parser.add_argument("batch_b", type=Path, help="batch directory of arm B")
    args = parser.parse_args(argv)
    try:
        a = load_arm("A", args.batch_a)
        b = load_arm("B", args.batch_b)
    except BatchDirError as exc:
        print(f"compare-arms: {exc}", file=sys.stderr)
        return 2
    out = [*summary_lines(a), "", *summary_lines(b)]
    table = scenario_lines(a, b)
    if table:
        out += ["", *table]
    out += ["", token_change_line(a, b)]
    print("\n".join(out))
    return 0


if __name__ == "__main__":
    sys.exit(main())

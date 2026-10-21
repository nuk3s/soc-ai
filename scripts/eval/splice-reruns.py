#!/usr/bin/env python3
"""scripts/eval/splice-reruns.py: splice a rerun batch's rows into a main batch.

Usage::

    scripts/eval/splice-reruns.py <main-batch-dir> <rerun-batch-dir> [--out <dir>]

An aborted run is a row with a non-null ``error``, or a row with a null
``error`` and a null ``verdict`` (the run completed but the pipeline never
reached a verdict, for example a retry budget the gateway exhausted). The
stage-1 eval of 2026-10-04 reran its arm B's aborted rows alone and spliced
them back into the repeat slots they replace
(``docs/dev/reviews/2026-10-05-stage1-eval.md``). This script does that
splice.

Each row of the main batch is matched against the rerun batch by its synth
scope key (``synth_scenario_id``, ``synth_repeat``) when it carries one, or
by ``alert_id`` otherwise. It never matches by ``bundle_path``, which names a fresh
directory on every attempt. An aborted main row with a match in the rerun
batch is replaced; its replacement's bundle directory is copied under the
output directory so ``bundle_path`` still resolves there. An aborted row
with no match stays in the output as it was, and is named on stderr.

The output is a new batch directory, ``index.jsonl`` plus the copied
bundles, default ``<main-batch-dir>-spliced``. It carries no
``aggregates.json``: build a fresh one with ``soc-ai eval-report`` once the
splice is done, the same as any batch.

Standard library only. See ``docs/dev/eval-arms.md`` for the runbook. Row
shapes are documented in ``soc_ai/eval/batch.py`` at the ``IndexRow``
dataclass and at ``_run_one``'s return.
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

NA = "n/a"


class BatchDirError(Exception):
    """An argument names no readable batch directory."""


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


def is_aborted(row: dict[str, Any]) -> bool:
    """A row the batch never settled: an error, or an ok run with no verdict."""
    if row.get("error"):
        return True
    return row.get("verdict") is None


def row_key(row: dict[str, Any]) -> tuple[str, ...]:
    """The scenario-repeat slot a row fills, or its alert when it carries no scenario id."""
    scenario_id = row.get("synth_scenario_id")
    if scenario_id:
        return ("synth", str(scenario_id), str(row.get("synth_repeat", 0)))
    return ("alert", str(row.get("alert_id")))


def copy_bundle(row: dict[str, Any], dest_batch: Path) -> dict[str, Any]:
    """A copy of ``row`` whose ``bundle_path`` points at a copy of its bundle under ``dest_batch``.

    A row with no bundle, or whose bundle directory is unreadable, is
    returned unchanged. An aborted row commonly has neither.
    """
    raw = row.get("bundle_path")
    if not raw:
        return row
    src = Path(raw)
    if not src.is_dir():
        return row
    dest = dest_batch / src.name
    if not dest.exists():
        shutil.copytree(src, dest)
    return {**row, "bundle_path": str(dest)}


@dataclass(frozen=True)
class SpliceResult:
    """Counts from one splice: how many rows the main batch carried, and what changed."""

    total: int
    aborted: int
    replaced: int
    unresolved: tuple[str, ...]


def splice(
    main_rows: list[dict[str, Any]], rerun_rows: list[dict[str, Any]], dest_batch: Path
) -> tuple[list[dict[str, Any]], SpliceResult]:
    """Merge ``rerun_rows`` into ``main_rows`` wherever a main row is aborted and matched.

    One rerun row per key: the first row the rerun batch carries for a
    slot wins. Pure aside from the bundle copy, so a test can check the
    merged rows without writing ``index.jsonl``.
    """
    rerun_by_key: dict[tuple[str, ...], dict[str, Any]] = {}
    for row in rerun_rows:
        rerun_by_key.setdefault(row_key(row), row)

    out_rows: list[dict[str, Any]] = []
    aborted = 0
    replaced = 0
    unresolved: list[str] = []
    for row in main_rows:
        if not is_aborted(row):
            out_rows.append(row)
            continue
        aborted += 1
        replacement = rerun_by_key.get(row_key(row))
        if replacement is None:
            unresolved.append(str(row.get("alert_id") or "-"))
            out_rows.append(row)
            continue
        out_rows.append(copy_bundle(replacement, dest_batch))
        replaced += 1

    return out_rows, SpliceResult(
        total=len(main_rows), aborted=aborted, replaced=replaced, unresolved=tuple(unresolved)
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Splice a rerun batch's rows for aborted scenarios into a main batch."
    )
    parser.add_argument("main_batch", type=Path, help="the main batch directory")
    parser.add_argument("rerun_batch", type=Path, help="the batch that reran the aborted rows")
    parser.add_argument(
        "--out", type=Path, default=None, help="output directory, default <main-batch>-spliced"
    )
    args = parser.parse_args(argv)

    try:
        main_dir = resolve_batch_dir(args.main_batch)
        rerun_dir = resolve_batch_dir(args.rerun_batch)
    except BatchDirError as exc:
        print(f"splice-reruns: {exc}", file=sys.stderr)
        return 2

    out_dir = args.out or main_dir.parent / f"{main_dir.name}-spliced"
    out_dir.mkdir(parents=True, exist_ok=True)

    main_rows = read_jsonl(main_dir / "index.jsonl")
    rerun_rows = read_jsonl(rerun_dir / "index.jsonl")
    out_rows, result = splice(main_rows, rerun_rows, out_dir)

    with (out_dir / "index.jsonl").open("w", encoding="utf-8") as f:
        for row in out_rows:
            f.write(json.dumps(row))
            f.write("\n")

    print(f"splice-reruns: {main_dir} + {rerun_dir} -> {out_dir}")
    print(
        f"splice-reruns: {result.total} rows, {result.aborted} aborted, {result.replaced} replaced"
    )
    if result.unresolved:
        print(
            "splice-reruns: no rerun row matched these aborted rows, so they stay aborted: "
            + ", ".join(result.unresolved),
            file=sys.stderr,
        )
    print(f"splice-reruns: build fresh aggregates with: soc-ai eval-report --no-meta {out_dir}")
    return 1 if result.unresolved else 0


if __name__ == "__main__":
    sys.exit(main())

"""scripts/eval/compare-arms.py: two batch directories, compared.

Two small batch directories are written under tmp_path, in the shape
``soc-ai validate-batch`` writes: ``index.jsonl``, ``aggregates.json`` and a
bundle per run with an ``events.jsonl``. The tests read the printed numbers.
The negative controls: a directory with no ``index.jsonl`` prints one clear
line and exits 2, and an event that is not a ``usage`` event adds nothing.
"""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

_SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "eval" / "compare-arms.py"


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location("compare_arms", _SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["compare_arms"] = module
    spec.loader.exec_module(module)
    return module


compare_arms = _load()


def _usage(input_tokens: int, output_tokens: int, requests: int, tool_calls: int) -> dict[str, Any]:
    return {
        "kind": "usage",
        "session_id": "s",
        "sequence": 1,
        "payload": {
            "phase": "synthesizer",
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "requests": requests,
            "tool_calls": tool_calls,
        },
    }


# Not a usage event. Its token count must not reach the sums.
_NOT_USAGE = {"kind": "tool_call", "payload": {"input_tokens": 999_999, "tool_name": "t"}}


def _bundle(batch: Path, name: str, events: list[dict[str, Any]]) -> Path:
    path = batch / name
    path.mkdir()
    (path / "events.jsonl").write_text(
        "\n".join(json.dumps(e) for e in events) + "\n", encoding="utf-8"
    )
    return path


def _stratum(
    *, strict: float, precision: float, flip: float, stability: dict[str, tuple[int, int]]
) -> dict[str, Any]:
    return {
        "escalation_precision": precision,
        "escalation_precision_ci": [0.5, 0.95],
        "escalation_recall": 0.6,
        "escalation_recall_ci": [0.4, 0.8],
        "escalation_recall_verdict_only": 0.7,
        "escalation_recall_verdict_only_ci": [0.5, 0.85],
        "per_scenario": {
            sid: {"scenario_id": sid, "correct": k > n // 2} for sid, (k, n) in stability.items()
        },
        "per_scenario_stability": {
            sid: {"scenario_id": sid, "repeats": n, "strict_passes": k}
            for sid, (k, n) in stability.items()
        },
        "flip_rate": flip,
        "macro": {
            "strict_recall_macro": strict,
            "strict_recall_macro_ci": [strict - 0.2, strict + 0.1],
            "verdict_only_recall_macro": 0.8,
            "verdict_only_recall_macro_ci": [0.6, 0.9],
            "benign_strict_macro": 0.9,
            "benign_strict_macro_ci": [0.75, 1.0],
            "false_escalation_rate_macro": 0.1,
        },
    }


def _batch(
    root: Path,
    *,
    usages: list[list[dict[str, Any]]],
    walls: list[int],
    stratum: dict[str, Any],
) -> Path:
    """A batch: one ok run per bundle, then one errored run with no bundle.

    The second bundle's path is stored relative to a working directory that
    no longer exists, as a batch copied off its host carries it.
    """
    batch = root / "batch-2026-10-04T120000Z"
    batch.mkdir(parents=True)
    rows: list[dict[str, Any]] = []
    for n, (events, wall) in enumerate(zip(usages, walls, strict=True)):
        bundle = _bundle(batch, f"2026-10-04T12000{n}Z-alert{n}", [*events, _NOT_USAGE])
        path = str(bundle) if n == 0 else f"gone/evals/arms/x/{batch.name}/{bundle.name}"
        rows.append(
            {
                "alert_id": f"alert{n}",
                "bundle_path": path,
                "investigation_ms": wall,
                "error": None,
                "is_fallback": n == 1,
                "is_synth": True,
            }
        )
    rows.append({"alert_id": "alert-err", "bundle_path": None, "error": "timeout"})
    (batch / "index.jsonl").write_text(
        "\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8"
    )
    (batch / "aggregates.json").write_text(json.dumps({"synth_stratum": stratum}), encoding="utf-8")
    return batch


@pytest.fixture
def arms(tmp_path: Path) -> tuple[Path, Path]:
    a = _batch(
        tmp_path / "A",
        # Per run: input (1500 + 3000) / 2 = 2250, output 225, requests 2, tool calls 3.
        usages=[[_usage(1000, 100, 1, 2), _usage(500, 50, 1, 3)], [_usage(3000, 300, 2, 1)]],
        walls=[10_000, 30_000],
        stratum=_stratum(
            strict=0.6, precision=0.9, flip=0.25, stability={"e1": (3, 5), "h1": (0, 5)}
        ),
    )
    b = _batch(
        tmp_path / "B",
        # Per run: input (2400 + 3000) / 2 = 2700, output 250, requests 3, tool calls 4.
        usages=[[_usage(2400, 200, 3, 4)], [_usage(3000, 300, 3, 4)]],
        walls=[20_000, 40_000],
        stratum=_stratum(
            strict=0.8,
            precision=1.0,
            flip=0.1,
            stability={"e1": (5, 5), "h1": (1, 5), "m1": (2, 5)},
        ),
    )
    return a, b


def _run(capsys: pytest.CaptureFixture[str], *argv: Path) -> tuple[int, list[str], str]:
    code = compare_arms.main([str(p) for p in argv])
    captured = capsys.readouterr()
    return code, captured.out.splitlines(), captured.err


def test_each_arm_prints_its_counts_quality_and_cost(
    arms: tuple[Path, Path], capsys: pytest.CaptureFixture[str]
) -> None:
    a, b = arms
    code, lines, err = _run(capsys, a, b)

    assert code == 0, err
    assert lines[0] == f"== arm A: {a}"
    assert lines[1] == "runs 3  ok 2  errors 1  fallbacks 1"
    assert "strict recall (macro)           0.600  ci [0.400, 0.700]" in lines
    assert "verdict-only recall (macro)     0.800  ci [0.600, 0.900]" in lines
    assert "benign strict (macro)           0.900  ci [0.750, 1.000]" in lines
    assert "false escalation rate (macro)   0.100" in lines
    assert "escalation precision            0.900  ci [0.500, 0.950]" in lines
    assert "escalation recall               0.600  ci [0.400, 0.800]" in lines
    assert "escalation recall, verdict only 0.700" in lines
    assert "flip rate                       0.250" in lines
    # The non-usage event's 999,999 tokens are not in the mean.
    assert (
        "per run (2 bundles): input tokens 2250  output tokens 225  requests 2.00  tool calls 3.00"
        in lines
    )
    assert "median investigation wall time 20.0 s" in lines

    b_start = lines.index(f"== arm B: {b}")
    b_block = lines[b_start:]
    assert "strict recall (macro)           0.800  ci [0.600, 0.900]" in b_block
    assert "flip rate                       0.100" in b_block
    assert (
        "per run (2 bundles): input tokens 2700  output tokens 250  requests 3.00  tool calls 4.00"
        in b_block
    )
    assert "median investigation wall time 30.0 s" in b_block


def test_the_scenario_table_and_the_token_change(
    arms: tuple[Path, Path], capsys: pytest.CaptureFixture[str]
) -> None:
    a, b = arms
    _code, lines, _err = _run(capsys, a, b)

    header = lines.index("scenario    A k/N    B k/N   delta")
    assert lines[header + 1 : header + 4] == [
        "e1            3/5      5/5   +0.40",
        "h1            0/5      1/5   +0.20",
        "m1            n/a      2/5     n/a",
    ]
    assert lines[-1] == "input tokens per run: A 2250  B 2700  change +20.0%"


def test_an_arm_directory_reads_its_newest_batch(
    arms: tuple[Path, Path], capsys: pytest.CaptureFixture[str]
) -> None:
    a, b = arms
    # An older batch with an index, and a newer one that never wrote one.
    older = a.parent / "batch-2026-10-01T000000Z"
    older.mkdir()
    (older / "index.jsonl").write_text((a / "index.jsonl").read_text(), encoding="utf-8")
    (a.parent / "batch-2026-10-05T000000Z").mkdir()
    code, lines, _err = _run(capsys, a.parent, b.parent)

    assert code == 0
    assert lines[0] == f"== arm A: {a}"


def test_a_batch_with_no_aggregates_says_how_to_build_them(
    arms: tuple[Path, Path], capsys: pytest.CaptureFixture[str]
) -> None:
    a, b = arms
    (b / "aggregates.json").unlink()
    code, lines, _err = _run(capsys, a, b)

    assert code == 0
    assert f"no aggregates.json. Run: soc-ai eval-report --no-meta {b}" in lines
    # The usage still reads from the bundles.
    assert lines[-1] == "input tokens per run: A 2250  B 2700  change +20.0%"


def test_a_directory_with_no_index_prints_one_line_and_exits_2(
    arms: tuple[Path, Path], tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    a, _b = arms
    empty = tmp_path / "not-a-batch"
    empty.mkdir()
    (empty / "aggregates.json").write_text("{}", encoding="utf-8")

    code, lines, err = _run(capsys, a, empty)

    assert code == 2
    assert lines == []
    assert err.splitlines() == [
        f"compare-arms: {empty}: no index.jsonl here and no batch-* directory with one. "
        "Pass the batch directory that validate-batch wrote."
    ]


def test_the_script_runs_with_the_standard_library_alone(arms: tuple[Path, Path]) -> None:
    """No PYTHONPATH and an isolated interpreter: the script imports nothing of soc_ai."""
    a, b = arms
    env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
    done = subprocess.run(
        [sys.executable, "-I", str(_SCRIPT), str(a), str(b)],
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )
    assert done.returncode == 0, done.stderr
    assert "change +20.0%" in done.stdout

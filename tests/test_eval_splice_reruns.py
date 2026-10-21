"""scripts/eval/splice-reruns.py: a rerun batch, spliced into a main batch.

The pure :func:`splice` function is exercised directly for the merge logic
(an aborted row replaced by its rerun match, one left alone with no match),
and :func:`main` end to end for the file I/O: the merged ``index.jsonl``,
the copied bundle directories, and the printed counts.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

_SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "eval" / "splice-reruns.py"


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location("splice_reruns", _SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["splice_reruns"] = module
    spec.loader.exec_module(module)
    return module


splice_reruns = _load()


def _ok_row(alert_id: str, **extra: Any) -> dict[str, Any]:
    row: dict[str, Any] = {
        "alert_id": alert_id,
        "bundle_path": None,
        "verdict": "true_positive",
        "error": None,
        "is_synth": False,
        "synth_scenario_id": None,
        "synth_repeat": 0,
    }
    row.update(extra)
    return row


def _aborted_row(alert_id: str, *, error: str | None = None, **extra: Any) -> dict[str, Any]:
    row = _ok_row(alert_id, verdict=None, error=error, **extra)
    return row


def test_an_aborted_synth_row_is_matched_by_scenario_and_repeat_not_by_alert_id() -> None:
    main_rows = [
        _ok_row("alert-good"),
        _aborted_row(
            "alert-h6-try1", is_synth=True, synth_scenario_id="h6", synth_repeat=2, bundle_path=None
        ),
    ]
    rerun_rows = [
        # A fresh plant id for the same scenario and repeat. Never alert-h6-try1.
        _ok_row(
            "alert-h6-try2", is_synth=True, synth_scenario_id="h6", synth_repeat=2, bundle_path=None
        )
    ]

    out_rows, result = splice_reruns.splice(main_rows, rerun_rows, Path("/unused"))

    assert result.total == 2
    assert result.aborted == 1
    assert result.replaced == 1
    assert result.unresolved == ()
    assert out_rows[0] == main_rows[0]
    assert out_rows[1]["alert_id"] == "alert-h6-try2"
    assert out_rows[1]["verdict"] == "true_positive"


def test_an_error_row_is_matched_by_alert_id_when_it_carries_no_scenario_id() -> None:
    main_rows = [_aborted_row("alert-1", error="timeout after 1800s")]
    rerun_rows = [_ok_row("alert-1")]

    out_rows, result = splice_reruns.splice(main_rows, rerun_rows, Path("/unused"))

    assert result.aborted == 1
    assert result.replaced == 1
    assert out_rows[0]["error"] is None
    assert out_rows[0]["verdict"] == "true_positive"


def test_an_aborted_row_with_no_rerun_match_stays_and_is_named_unresolved() -> None:
    main_rows = [_aborted_row("alert-lonely", error="boom")]

    out_rows, result = splice_reruns.splice(main_rows, [], Path("/unused"))

    assert result.aborted == 1
    assert result.replaced == 0
    assert result.unresolved == ("alert-lonely",)
    assert out_rows == main_rows


def test_an_ok_row_is_never_touched_even_with_a_same_key_rerun_row() -> None:
    main_rows = [_ok_row("alert-fine")]
    rerun_rows = [_ok_row("alert-fine", verdict="false_positive")]

    out_rows, result = splice_reruns.splice(main_rows, rerun_rows, Path("/unused"))

    assert result.aborted == 0
    assert out_rows[0]["verdict"] == "true_positive"


def _write_batch(root: Path, rows: list[dict[str, Any]]) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    (root / "index.jsonl").write_text(
        "\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8"
    )
    return root


def test_main_writes_the_merged_index_and_copies_the_replacement_bundle(tmp_path: Path) -> None:
    main_dir = tmp_path / "main" / "batch-2026-10-04T120000Z"
    rerun_dir = tmp_path / "rerun" / "batch-2026-10-06T090000Z"

    rerun_bundle = rerun_dir / "2026-10-06T090000Z-alert-h6-try2"
    rerun_bundle.mkdir(parents=True)
    (rerun_bundle / "events.jsonl").write_text('{"kind": "usage"}\n', encoding="utf-8")

    _write_batch(
        main_dir,
        [
            _ok_row("alert-good"),
            _aborted_row("alert-h6-try1", is_synth=True, synth_scenario_id="h6", synth_repeat=2),
        ],
    )
    _write_batch(
        rerun_dir,
        [
            _ok_row(
                "alert-h6-try2",
                is_synth=True,
                synth_scenario_id="h6",
                synth_repeat=2,
                bundle_path=str(rerun_bundle),
            )
        ],
    )

    code = splice_reruns.main([str(main_dir), str(rerun_dir)])

    assert code == 0
    out_dir = main_dir.parent / f"{main_dir.name}-spliced"
    rows = [json.loads(line) for line in (out_dir / "index.jsonl").read_text().splitlines()]
    assert rows[0]["alert_id"] == "alert-good"
    assert rows[1]["alert_id"] == "alert-h6-try2"
    copied_bundle = out_dir / rerun_bundle.name
    assert copied_bundle.is_dir()
    assert rows[1]["bundle_path"] == str(copied_bundle)
    assert (copied_bundle / "events.jsonl").read_text() == '{"kind": "usage"}\n'


def test_main_exits_1_and_warns_when_a_row_stays_unresolved(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    main_dir = tmp_path / "main" / "batch-2026-10-04T120000Z"
    rerun_dir = tmp_path / "rerun" / "batch-2026-10-06T090000Z"
    _write_batch(main_dir, [_aborted_row("alert-lonely", error="boom")])
    _write_batch(rerun_dir, [])

    code = splice_reruns.main([str(main_dir), str(rerun_dir)])
    err = capsys.readouterr().err

    assert code == 1
    assert "alert-lonely" in err


def test_main_exits_2_when_an_argument_is_not_a_batch_directory(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    empty = tmp_path / "not-a-batch"
    empty.mkdir()
    main_dir = tmp_path / "main" / "batch-2026-10-04T120000Z"
    _write_batch(main_dir, [_ok_row("alert-good")])

    code = splice_reruns.main([str(main_dir), str(empty)])
    err = capsys.readouterr().err

    assert code == 2
    assert "no index.jsonl" in err


def test_the_out_flag_overrides_the_default_output_directory(tmp_path: Path) -> None:
    main_dir = tmp_path / "main" / "batch-2026-10-04T120000Z"
    rerun_dir = tmp_path / "rerun" / "batch-2026-10-06T090000Z"
    _write_batch(main_dir, [_ok_row("alert-good")])
    _write_batch(rerun_dir, [])
    out_dir = tmp_path / "custom-out"

    code = splice_reruns.main([str(main_dir), str(rerun_dir), "--out", str(out_dir)])

    assert code == 0
    assert (out_dir / "index.jsonl").is_file()

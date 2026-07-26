#!/usr/bin/env python3
"""Idempotently enrich ``soc_ai/demo/fixtures.json`` with 1.2.x showcase content.

WHY THIS SCRIPT EXISTS
----------------------
``fixtures.json`` is no longer a pure ``build_fixtures.py`` artifact — it is now
**part hand-authored**. A full rebuild from recorded runs is impossible: the
backtest's source store sqlite (``--db``) is gone, so re-running
``scripts/demo/build_fixtures.py`` would drop the backtest section entirely. The
1.2.x screens (Hunts → Scheduled hunts, Dashboard → Quality card, Dashboard →
pipeline-errors KPI) also need content the recorded bundles never produced.

Rather than ship an 892 KB regenerated diff for owner review, this script BOTH
DOCUMENTS and APPLIES the authored additions: the reviewer reads the authored
rows below, not a machine diff. Everything it adds is:

* **Additive** — existing sections/rows are never modified or reordered; the two
  new top-level arrays (``hunt_schedules``, ``quality_snapshots``) are appended
  after ``chats`` and the one pipeline-fallback row is appended to
  ``investigations``.
* **Idempotent** — a second run adds nothing and exits 0 (dedup by row ``id`` /
  investigation ``id``).
* **Leak-gated** — the authored payload is run through BOTH publish gates
  (:func:`scan_for_leaks` mirror-pattern arm + :func:`residue_scan` raw-value
  arm) from ``build_fixtures.py``; a non-empty result aborts with a non-zero
  exit and writes nothing.

LEAK-SAFETY NOTE (IP values)
----------------------------
The committed fixture set carries **zero** literal IPs for internal hosts — the
builder's ``sanitize()`` pass converts every private/reserved address (which,
per :mod:`ipaddress`, INCLUDES the RFC-5737 TEST-NET documentation ranges) into
an ``IP_NN`` pseudonym. ``residue_scan`` therefore flags a bare ``198.51.100.x``
just as it would a real internal address, so hand-authored rows must use the
file's native ``IP_NN`` pseudonym scheme (not TEST-NET literals) to pass the
gate. That is also what keeps the fallback row visually consistent with its
eight sibling investigations.

The file is written with the SAME formatting as ``build_fixtures.py``
(``json.dumps(indent=1, ensure_ascii=False)`` + a single trailing newline).
Still requires owner review before commit.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parents[2]
if str(REPO) not in sys.path:  # allow ``python scripts/demo/enrich_demo_fixtures.py``
    sys.path.insert(0, str(REPO))

from scripts.demo.build_fixtures import residue_scan, scan_for_leaks  # noqa: E402

FIXTURES = REPO / "soc_ai" / "demo" / "fixtures.json"


# ---------------------------------------------------------------------------
# Authored content (hand-reviewed — this IS the owner-review surface)
# ---------------------------------------------------------------------------

# (1) Scheduled hunts — the Hunts → "Scheduled hunts" panel. Two enabled rows
# render the 1.2.4 "on (paused)" pill (the demo master switch stays off), one
# disabled row renders "paused". Objectives are fictional and CIDR-free (a bare
# TEST-NET CIDR like "203.0.113.0/24" trips residue_scan's private-IPv4 arm).
HUNT_SCHEDULES: list[dict[str, Any]] = [
    {
        "id": 9001,
        "objective": (
            "Sweep for repeated Kerberos pre-authentication failures across the "
            "remote-access VPN pool"
        ),
        "interval_minutes": 360,
        "enabled": True,
        "last_run_at": "2026-07-20T04:00:00Z",
        "created_by": "demo",
        "created_at": "2026-07-05T09:15:00Z",
    },
    {
        "id": 9002,
        "objective": (
            "Daily outbound-TLS review to newly-registered domains from the finance VLAN"
        ),
        "interval_minutes": 1440,
        "enabled": False,
        "last_run_at": None,
        "created_by": "demo",
        "created_at": "2026-07-08T13:30:00Z",
    },
    {
        "id": 9003,
        "objective": (
            "Hunt for internal hosts beaconing to rare external IPs over the last 24h "
            "— regular cadence, low data volume, novel destinations"
        ),
        "interval_minutes": 720,
        "enabled": True,
        "last_run_at": "2026-07-20T02:30:00Z",
        "created_by": "demo",
        "created_at": "2026-07-10T08:00:00Z",
    },
]

# (2) Quality-trend series — the Dashboard → Quality card sparkline. ALL
# ``mode="graded"`` (mixing modes drops points from the sparkline). Distinct
# created_at, ~2 days apart over ~2 weeks (the seeder rebases them so the newest
# lands at "now"). agreement_rate rises with a realistic wobble; no alarmed
# points (a fabricated red regression would just scare a demo visitor).
QUALITY_SNAPSHOTS: list[dict[str, Any]] = [
    {
        "id": 9001,
        "created_at": "2026-07-07T03:00:00Z",
        "mode": "graded",
        "n_ok": 8,
        "n_error": 0,
        "agreement_rate": 0.79,
        "fallback_rate": 0.0,
        "error_rate": 0.0,
        "verdict_counts": {"true_positive": 2, "false_positive": 5, "needs_more_info": 1},
        "latency_p50_ms": 72000,
        "batch_dir": None,
        "alarmed": False,
        "alarm_reasons": None,
    },
    {
        "id": 9002,
        "created_at": "2026-07-09T03:00:00Z",
        "mode": "graded",
        "n_ok": 8,
        "n_error": 1,
        "agreement_rate": 0.82,
        "fallback_rate": 0.125,
        "error_rate": 0.11,
        "verdict_counts": {"true_positive": 3, "false_positive": 4, "needs_more_info": 1},
        "latency_p50_ms": 68000,
        "batch_dir": None,
        "alarmed": False,
        "alarm_reasons": None,
    },
    {
        "id": 9003,
        "created_at": "2026-07-11T03:00:00Z",
        "mode": "graded",
        "n_ok": 9,
        "n_error": 0,
        "agreement_rate": 0.85,
        "fallback_rate": 0.0,
        "error_rate": 0.0,
        "verdict_counts": {"true_positive": 2, "false_positive": 6, "needs_more_info": 1},
        "latency_p50_ms": 61000,
        "batch_dir": None,
        "alarmed": False,
        "alarm_reasons": None,
    },
    {
        "id": 9004,
        "created_at": "2026-07-13T03:00:00Z",
        "mode": "graded",
        "n_ok": 8,
        "n_error": 0,
        "agreement_rate": 0.83,
        "fallback_rate": 0.0,
        "error_rate": 0.0,
        "verdict_counts": {"true_positive": 3, "false_positive": 4, "needs_more_info": 1},
        "latency_p50_ms": 65000,
        "batch_dir": None,
        "alarmed": False,
        "alarm_reasons": None,
    },
    {
        "id": 9005,
        "created_at": "2026-07-15T03:00:00Z",
        "mode": "graded",
        "n_ok": 9,
        "n_error": 0,
        "agreement_rate": 0.88,
        "fallback_rate": 0.0,
        "error_rate": 0.0,
        "verdict_counts": {"true_positive": 3, "false_positive": 5, "needs_more_info": 1},
        "latency_p50_ms": 58000,
        "batch_dir": None,
        "alarmed": False,
        "alarm_reasons": None,
    },
    {
        "id": 9006,
        "created_at": "2026-07-17T03:00:00Z",
        "mode": "graded",
        "n_ok": 8,
        "n_error": 1,
        "agreement_rate": 0.90,
        "fallback_rate": 0.125,
        "error_rate": 0.11,
        "verdict_counts": {"true_positive": 2, "false_positive": 5, "needs_more_info": 1},
        "latency_p50_ms": 55000,
        "batch_dir": None,
        "alarmed": False,
        "alarm_reasons": None,
    },
    {
        "id": 9007,
        "created_at": "2026-07-19T03:00:00Z",
        "mode": "graded",
        "n_ok": 9,
        "n_error": 0,
        "agreement_rate": 0.91,
        "fallback_rate": 0.0,
        "error_rate": 0.0,
        "verdict_counts": {"true_positive": 3, "false_positive": 5, "needs_more_info": 1},
        "latency_p50_ms": 52000,
        "batch_dir": None,
        "alarmed": False,
        "alarm_reasons": None,
    },
]

# (3) One pipeline-fallback investigation — the Dashboard "N pipeline errors"
# KPI and the failure-driven-needs_more_info rendering. The ONLY thing that
# makes ``is_pipeline_fallback()`` true is ``report["resolution"]["provenance"]
# == "pipeline_fallback"`` (see soc_ai/triage_models.py); this mirrors the
# orchestrator's ``_synth_failure_fallback_report`` shape exactly. No
# ``error_dismissed_at`` (absent → the KPI counts it). Timestamps sit INSIDE the
# existing investigations' span (all 2026-07-11) so section-rebasing keeps this
# row recent WITHOUT dragging its siblings out of the default time window.
PIPELINE_FALLBACK_INVESTIGATION: dict[str, Any] = {
    "id": "01DEMOFA11BACKSYNTHERR0000",
    "alert_es_id": "9F4kTp8BwxVkvmc70zZ9",
    "rule_name": "ET MALWARE Possible Cobalt Strike Beacon (GET)",
    "verdict": "needs_more_info",
    "confidence": 0.3,
    "rationale": (
        "The triage pipeline hit a synthesizer error and recorded why instead of "
        "guessing; re-run to get a full verdict."
    ),
    "summary": (
        "The triage pipeline hit a synthesizer error and recorded why instead of "
        "guessing; re-run to get a full verdict."
    ),
    "report": {
        "verdict": "needs_more_info",
        "confidence": 0.3,
        "summary": (
            "Synth-first pipeline fallback: the synthesizer raised "
            "UnexpectedModelBehavior after retries. The alert is recorded as "
            "needs_more_info pending an investigator-path re-run — no verdict was "
            "guessed."
        ),
        "citations": [],
        "recommended_actions": [],
        "field_reconciliation": None,
        "validator_note": None,
        "local_verdict": None,
        # The provenance marker — the single field is_pipeline_fallback() reads.
        "resolution": {
            "provenance": "pipeline_fallback",
            "phase": "synthesizer",
            "error_type": "UnexpectedModelBehavior",
            "hint": (
                "The model returned malformed structured output after retries; "
                "re-run the investigation."
            ),
        },
    },
    "src_ip": "IP_41",
    "dest_ip": "IP_42",
    "status": "complete",
    "started_by": "scheduler",
    "created_at": "2026-07-11T13:45:00.000000+00:00",
    "finished_at": "2026-07-11T13:46:05.000000+00:00",
    "events": [
        {
            "kind": "session_start",
            "sequence": 1,
            "payload": {"alert_id": "9F4kTp8BwxVkvmc70zZ9", "pipeline": "synth_first"},
        },
        {
            "kind": "error",
            "sequence": 2,
            "payload": {
                "phase": "synthesizer",
                "error_type": "UnexpectedModelBehavior",
                "detail": (
                    "The model returned malformed structured output after retries; "
                    "recorded as a pipeline fallback."
                ),
            },
        },
    ],
}


# ---------------------------------------------------------------------------
# Apply
# ---------------------------------------------------------------------------


def _gate_or_exit(new_content: Any) -> None:
    """Run BOTH publish gates over the authored payload; abort on any hit.

    Mirrors ``build_fixtures._gate_or_exit``: the mirror-pattern arm
    (:func:`scan_for_leaks`) scans the serialized blob (what CI greps); the
    residue arm (:func:`residue_scan`) scans the raw string values. A non-empty
    result from either means the authored content carries an identifier that
    must not ship — write nothing and exit non-zero.
    """
    blob = json.dumps(new_content, ensure_ascii=False)
    patterns = scan_for_leaks(blob)
    residue = residue_scan(new_content)
    if patterns or residue:
        sys.exit(f"LEAK GATE FAILED — patterns={patterns} residue={residue}")


def enrich(path: Path = FIXTURES) -> bool:
    """Apply the authored additions idempotently. Returns True if anything changed.

    Preserves key order (``json.load`` keeps it) and appends the two new
    top-level arrays AFTER ``chats``. Writes the file only when at least one row
    was added, matching ``build_fixtures.py``'s formatting exactly.
    """
    data: dict[str, Any] = json.loads(path.read_text())
    if data.get("version") != 1:
        sys.exit(f"unexpected fixtures version: {data.get('version')!r}")

    # Gate the FULL authored payload every run — the write is idempotent, but the
    # safety check is unconditional (a clean re-run still proves the content safe).
    _gate_or_exit([*HUNT_SCHEDULES, *QUALITY_SNAPSHOTS, PIPELINE_FALLBACK_INVESTIGATION])

    changed = False

    # (1) hunt_schedules[] — new top-level array after "chats", deduped by id.
    schedules = data.setdefault("hunt_schedules", [])
    have = {row.get("id") for row in schedules}
    for row in HUNT_SCHEDULES:
        if row["id"] not in have:
            schedules.append(row)
            changed = True

    # (2) quality_snapshots[] — new top-level array after "chats", deduped by id.
    snapshots = data.setdefault("quality_snapshots", [])
    have = {row.get("id") for row in snapshots}
    for row in QUALITY_SNAPSHOTS:
        if row["id"] not in have:
            snapshots.append(row)
            changed = True

    # (3) the pipeline-fallback investigation — appended to investigations[].
    investigations = data.setdefault("investigations", [])
    inv_ids = {row.get("id") for row in investigations}
    if PIPELINE_FALLBACK_INVESTIGATION["id"] not in inv_ids:
        investigations.append(PIPELINE_FALLBACK_INVESTIGATION)
        changed = True

    if not changed:
        print(f"{path}: already enriched — no changes")
        return False

    blob = json.dumps(data, indent=1, ensure_ascii=False)
    path.write_text(blob + "\n", encoding="utf-8")
    print(
        f"wrote {path} (+{len(HUNT_SCHEDULES)} hunt_schedules, "
        f"+{len(QUALITY_SNAPSHOTS)} quality_snapshots, +1 pipeline-fallback "
        "investigation) — owner review required before commit"
    )
    return True


if __name__ == "__main__":
    enrich()

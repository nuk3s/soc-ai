"""Leak gate for the demo fixture builder (scripts/demo/build_fixtures.py).

The builder parses its leak patterns at run time out of the mirror build
script — the publish gate's single source of truth — so the two scans can
never drift, and neither the builder nor this file has to spell a lab
identifier out (both ship in the public tree; the mirror script does not).
On a public clone the mirror script is absent, so the whole module skips.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]

# scripts/build-public-mirror.sh is excluded from the public mirror (the leak
# scanners necessarily spell out the very patterns they scrub) — on a public
# clone there is no pattern source, so the gate tests cannot run there.
pytestmark = pytest.mark.skipif(
    not (REPO / "scripts/build-public-mirror.sh").exists(),
    reason="mirror build script not in this tree (public clone) — no leak-pattern source",
)

from scripts.demo.build_fixtures import (  # noqa: E402
    build,
    leak_patterns,
    residue_scan,
    scan_for_leaks,
)


def test_patterns_match_mirror_script():
    """The builder's patterns come FROM scripts/build-public-mirror.sh — never drift."""
    mirror = (REPO / "scripts/build-public-mirror.sh").read_text()
    for pat in leak_patterns():
        assert pat in mirror, f"pattern {pat!r} not in build-public-mirror.sh"
    assert len(leak_patterns()) >= 8


def test_scan_catches_lab_identifier():
    # assemble the needle from fragments so this test file itself passes the mirror scan
    needle = ".".join(["10", "9", "8", "253"])
    assert scan_for_leaks(json.dumps({"ip": needle}))


def test_scan_passes_clean_payload():
    assert not scan_for_leaks(json.dumps({"ip": "SRC_IP_01", "host": "HOST_02"}))


def test_committed_fixtures_are_clean():
    fx = REPO / "soc_ai/demo/fixtures.json"
    if not fx.exists():
        pytest.skip("fixture set not built yet")
    assert not scan_for_leaks(fx.read_text())


def test_residue_gate_ignores_real_newlines_in_values():
    """A newline after a word is content, not a DOMAIN\\logon shape.

    (json.dumps would escape it to backslash + ``n``, which the credential
    residue net used to flag as ``residual credential username: n`` — the
    residue arm therefore scans raw values, never the serialized blob.)
    """
    record = {"summary": "beacon cadence held.\nNo other internal host contacted it."}
    assert not residue_scan(record)


def test_residue_gate_still_catches_domain_logon_forms():
    """A genuine DOMAIN\\user credential form in a value must trip the gate."""
    record = {"summary": "logon as CORP\\jdoe failed twice"}
    findings = residue_scan(record)
    assert findings
    assert any("jdoe" in f for f in findings)


def _write_bundle(d: Path, alert_label: str, summary: str, *, with_alert: bool = False) -> Path:
    """A minimal, complete eval bundle (meta.json + events.jsonl) for build().

    ``with_alert`` adds an ``enriched_alert_context`` event (TEST-NET values),
    which is what makes the builder emit an alerts[] queue doc for the bundle.
    """
    d.mkdir()
    (d / "meta.json").write_text(
        json.dumps(
            {
                "alert_id": alert_label,
                "alert_id_label": alert_label,
                "timestamp_utc": "2026-07-03T21:26:23+00:00",
                "verdict": "false_positive",
                "confidence": 0.5,
                "investigation_elapsed_ms": 30000,
            }
        )
    )
    events: list[dict] = [{"kind": "session_start", "sequence": 1, "payload": {}}]
    if with_alert:
        events.append(
            {
                "kind": "enriched_alert_context",
                "sequence": 2,
                "payload": {
                    "alert": {
                        "rule_name": "ET SCAN Test Rule",
                        "source_ip": "203.0.113.7",
                        "destination_ip": "198.51.100.2",
                        "event_dataset": "suricata.alert",
                    }
                },
            }
        )
    events.append(
        {
            "kind": "triage_report",
            "sequence": len(events) + 1,
            "payload": {"verdict": "false_positive", "confidence": 0.5, "summary": summary},
        }
    )
    (d / "events.jsonl").write_text("\n".join(json.dumps(r) for r in events))
    return d


def test_duplicate_alert_bundles_fail_loudly(tmp_path: Path):
    """Two bundles recording the same alert would collide on the derived row id
    (and the idempotent seeder would silently drop one) — the build must exit
    naming both bundles instead."""
    bundles = [
        _write_bundle(tmp_path / name, "same-alert-1", "clean") for name in ("bundle-a", "bundle-b")
    ]
    with pytest.raises(SystemExit, match=r"duplicate investigation id.*bundle-a.*bundle-b"):
        build(bundles, None, tmp_path / "out.json")
    assert not (tmp_path / "out.json").exists()


def test_poisoned_build_fails_and_names_the_record(tmp_path: Path):
    """End-to-end: content carrying a mirror-pattern needle aborts the build,
    names the offending record for the operator, and writes nothing."""
    needle = "".join(["daed", "elus"])  # fragment-assembled lab hostname
    bundle = _write_bundle(
        tmp_path / "poisoned", "poisoned-alert-1", f"host talked to {needle} overnight"
    )
    out = tmp_path / "out.json"
    with pytest.raises(SystemExit, match=r"LEAK GATE FAILED.*investigations\[0\] \(id=01DEMO"):
        build([bundle], None, out)
    assert not out.exists()


def test_replay_bundle_lands_in_replays_not_investigations(tmp_path: Path):
    """--replay emits {alert_es_id, investigation, events} into replays[] (the
    exact shape soc_ai.demo.replay.find_replay consumes, triage_report included
    so the recorder lands the verdict) plus the alert doc into alerts[] — and
    keeps the bundle OUT of investigations[] so the queue shows the alert as
    not-yet-investigated for the click."""
    inv = _write_bundle(tmp_path / "inv-bundle", "alert-inv-1", "clean", with_alert=True)
    rep = _write_bundle(tmp_path / "replay-bundle", "alert-replay-1", "clean", with_alert=True)
    out = tmp_path / "out.json"
    build([inv], None, out, replay_dirs=[rep])
    data = json.loads(out.read_text())

    assert [r["alert_es_id"] for r in data["replays"]] == ["alert-replay-1"]
    replay = data["replays"][0]
    assert replay["investigation"]["verdict"] == "false_positive"
    assert "events" not in replay["investigation"]  # events live at the top level
    assert "triage_report" in [e["kind"] for e in replay["events"]]

    assert [r["alert_es_id"] for r in data["investigations"]] == ["alert-inv-1"]
    # Both alerts sit in the queue; the replay one has no investigation row.
    assert sorted(a["_id"] for a in data["alerts"]) == ["alert-inv-1", "alert-replay-1"]


def test_replay_bundle_without_alert_context_fails_loudly(tmp_path: Path):
    """A replay nobody can click (no alert doc for the queue) is a curation
    error — the build must refuse and name the bundle."""
    rep = _write_bundle(tmp_path / "replay-bundle", "alert-replay-2", "clean")
    with pytest.raises(SystemExit, match=r"replay-bundle.*no enriched alert context"):
        build([], None, tmp_path / "out.json", replay_dirs=[rep])
    assert not (tmp_path / "out.json").exists()


def test_duplicate_id_check_spans_bundles_and_replays(tmp_path: Path):
    """The same alert passed via --bundles AND --replay would seed a completed
    investigation for an alert the queue also offers as click-to-investigate —
    the build must exit naming both bundles."""
    inv = _write_bundle(tmp_path / "inv-bundle", "same-alert-2", "clean", with_alert=True)
    rep = _write_bundle(tmp_path / "replay-bundle", "same-alert-2", "clean", with_alert=True)
    with pytest.raises(SystemExit, match=r"duplicate investigation id.*inv-bundle.*replay-bundle"):
        build([inv], None, tmp_path / "out.json", replay_dirs=[rep])
    assert not (tmp_path / "out.json").exists()


def test_poisoned_replay_build_fails_and_names_the_record(tmp_path: Path):
    """The leak gates cover replays[] content exactly like investigations[]:
    a mirror-pattern needle inside a replay bundle aborts the build, names the
    replay record, and writes nothing."""
    needle = "".join(["daed", "elus"])  # fragment-assembled lab hostname
    rep = _write_bundle(
        tmp_path / "poisoned-replay",
        "poisoned-replay-1",
        f"host talked to {needle} overnight",
        with_alert=True,
    )
    out = tmp_path / "out.json"
    with pytest.raises(
        SystemExit, match=r"LEAK GATE FAILED.*replays\[0\] \(id=poisoned-replay-1\)"
    ):
        build([], None, out, replay_dirs=[rep])
    assert not out.exists()


def test_hunts_and_chats_files_flow_into_fixtures(tmp_path: Path):
    """--hunts-file rows land in fixtures['hunts'] and --chats-file threads in
    fixtures['chats'], driven through the real argparse/main path (a build with
    no bundles/replay/db is valid when authored files are supplied)."""
    import subprocess
    import sys

    hunts = [
        {
            "id": "01DEMOHUNT000000000000TST1",
            "objective": "o",
            "kind": "chat",
            "status": "complete",
            "narrative": "HOST_02 clean",
            "report": {"findings": [], "narrative": "HOST_02 clean", "confidence": 0.8},
            "started_by": "demo",
            "created_at": "2026-07-01T00:00:00Z",
            "finished_at": "2026-07-01T00:05:00Z",
            "events": [{"kind": "hunt_started", "sequence": 0, "payload": {}}],
        }
    ]
    chats = [
        {
            "target": "investigation",
            "id": "inv-x",
            "messages": [
                {"role": "user", "content": "q"},
                {"role": "assistant", "content": "recorded demo answer"},
            ],
        }
    ]
    hf = tmp_path / "h.json"
    hf.write_text(json.dumps(hunts))
    cf = tmp_path / "c.json"
    cf.write_text(json.dumps(chats))
    out = tmp_path / "fx.json"
    r = subprocess.run(
        [
            sys.executable,
            str(REPO / "scripts/demo/build_fixtures.py"),
            "--hunts-file",
            str(hf),
            "--chats-file",
            str(cf),
            "--out",
            str(out),
        ],
        cwd=REPO,
        capture_output=True,
        text=True,
        check=False,
    )
    assert r.returncode == 0, r.stderr
    data = json.loads(out.read_text())
    assert any(h["id"] == "01DEMOHUNT000000000000TST1" for h in data["hunts"])
    assert any(c["id"] == "inv-x" for c in data["chats"])


def test_authored_hunt_leaks_are_caught(tmp_path: Path):
    """The leak gates cover the hunts[] section: a lab identifier inside an
    authored hunt aborts the build (via build() directly, so the SystemExit is
    observable) and names the hunts record."""
    needle = "".join(["daed", "elus"])  # fragment-assembled lab hostname
    hunts = [
        {
            "id": "01DEMOHUNT00000000000LEAK1",
            "objective": "o",
            "kind": "chat",
            "status": "complete",
            "narrative": f"host talked to {needle} overnight",
            "report": {"findings": [], "narrative": "x", "confidence": 0.5},
            "started_by": "demo",
            "created_at": "2026-07-01T00:00:00Z",
            "finished_at": "2026-07-01T00:05:00Z",
            "events": [{"kind": "hunt_started", "sequence": 0, "payload": {}}],
        }
    ]
    hf = tmp_path / "h.json"
    hf.write_text(json.dumps(hunts))
    out = tmp_path / "out.json"
    with pytest.raises(
        SystemExit, match=r"LEAK GATE FAILED.*hunts\[0\] \(id=01DEMOHUNT00000000000LEAK1\)"
    ):
        build([], None, out, hunts_file=hf)
    assert not out.exists()


def test_malformed_bundle_failure_names_the_bundle(tmp_path: Path):
    """A broken bundle in a multi-bundle run must be attributed to its path."""
    good = _write_bundle(tmp_path / "good-bundle", "alert-ok-1", "clean")
    bad = tmp_path / "bad-bundle"
    bad.mkdir()
    (bad / "meta.json").write_text("{not json")
    (bad / "events.jsonl").write_text("")
    with pytest.raises(SystemExit, match=r"bad-bundle.*JSONDecodeError"):
        build([good, bad], None, tmp_path / "out.json")
    assert not (tmp_path / "out.json").exists()

"""End-to-end browser walkthrough of the READ-ONLY public demo (SOC_AI_DEMO).

The final acceptance check for demo mode. Unlike ``test_smoke.py`` (which drives
the docs-screenshot capture stack), this exercises the demo *product* path via
the ``demo_mode_stack`` fixture: the app's own startup hook seeds the committed
``soc_ai/demo/fixtures.json``, the read-only middleware blocks mutations, the
``/demo-status`` flag lights the honesty banner, and the two replay triggers
play recorded runs back through the live recorder + SSE encoder.

Each test is one checkpoint from the plan. They share the session-scoped
demo-mode server (a fresh Playwright page per test) and assert user-visible
behaviour — nothing is weakened to pass. Runs only under ``-m browser`` (see the
``browser`` marker; the default coverage-gated run ignores ``tests/browser``).

The replay checkpoint drives the ``POST /investigate`` SSE stream directly (the
demo server, same origin) rather than through a UI click: the existing browser
tests show no investigate-then-watch-SSE UI pattern, and the plan sanctions the
API-level stream + resulting row as the substitute. It still runs the REAL demo
replay path (recorder → SSE → recorded verdict).
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request

import pytest
from playwright.sync_api import Page, expect

# Playwright per-action / assertion timeout — a broken selector fails fast.
_WAIT_MS = 15000

# The one honesty-banner copy (soc_ai frontend src/lib/demo.tsx). A distinctive
# substring: avoids coupling to the surrounding em-dashes while still proving the
# real banner rendered.
_BANNER = "these investigations were run by soc-ai and recorded"

# A recorded replay alert (committed fixtures.json). Its recorded verdict is read
# from the fixture rather than hardcoded, so a data refresh can't silently pass.
_REPLAY_ALERT_ID = "9N6cTp8BwxVkvmc70vrs"  # ET MALWARE Quasar RAT CnC Checkin

# A mutating route the demo read-only middleware must refuse (webui router under
# /api/v1). NOT one of the two allowlisted replay triggers.
_BLOCKED_ROUTE = "/api/v1/alerts/escalate-group"

# soc-ai verdict → the VerdictPill label the SPA renders (frontend lib/tokens.ts).
_VERDICT_LABEL = {
    "true_positive": "True positive",
    "false_positive": "False positive",
    "needs_more_info": "Needs info",
}


# --- fixture-derived selectors ------------------------------------------------


def _first_investigation(fixtures: dict, verdict: str) -> dict:
    """The first seeded, complete investigation with *verdict* (fail loud if none)."""
    for inv in fixtures.get("investigations", []):
        if inv.get("status") == "complete" and inv.get("verdict") == verdict:
            return inv
    raise AssertionError(f"no seeded complete {verdict} investigation in fixtures")


def _recorded_verdict(fixtures: dict, alert_es_id: str) -> str:
    """The terminal verdict a replay recording lands on (its triage_report event)."""
    replay = next(
        (r for r in fixtures.get("replays", []) if r.get("alert_es_id") == alert_es_id),
        None,
    )
    assert replay is not None, f"no recorded replay for alert {alert_es_id}"
    for ev in reversed(replay.get("events") or []):
        if ev.get("kind") == "triage_report":
            verdict = (ev.get("payload") or {}).get("verdict")
            assert verdict, f"replay {alert_es_id} triage_report has no verdict"
            return str(verdict)
    raise AssertionError(f"replay {alert_es_id} has no triage_report event")


def _seeded_hunt(fixtures: dict) -> dict:
    """The first seeded hunt with a narrative + timeline events (fail loud if none)."""
    for hunt in fixtures.get("hunts", []):
        if (hunt.get("narrative") or "").strip() and hunt.get("events"):
            return hunt
    raise AssertionError("no seeded hunt with a narrative + events in fixtures")


def _canned_investigation_chat(fixtures: dict) -> tuple[str, str, str]:
    """A canned investigation chat thread → (investigation_id, user_turn, expected_reply).

    The expected reply is the LAST authored assistant turn — exactly what
    ``soc_ai.demo.chat.canned_reply`` serves — so the checkpoint proves the demo
    short-circuit returned the SCRIPTED answer, not a generic fallback or a live
    call. The id is cross-checked against the seeded investigations so a fixture
    rebuild that orphans the chat can't silently pass.
    """
    seeded = {inv.get("id") for inv in fixtures.get("investigations", [])}
    for entry in fixtures.get("chats", []):
        if entry.get("target") != "investigation":
            continue
        msgs = entry.get("messages") or []
        user = next((m.get("content") for m in msgs if m.get("role") == "user"), None)
        reply = next(
            (
                m.get("content")
                for m in reversed(msgs)
                if m.get("role") == "assistant" and m.get("content")
            ),
            None,
        )
        if entry.get("id") in seeded and user and reply:
            return str(entry["id"]), str(user), str(reply)
    raise AssertionError("no canned investigation chat bound to a seeded investigation")


# --- tiny HTTP helpers (same-origin demo server) ------------------------------


def _post_json(url: str, body: dict, timeout: float = 10.0) -> tuple[int, dict]:
    """POST JSON; return (status, parsed-body). 4xx/5xx are returned, not raised."""
    data = json.dumps(body).encode()
    req = urllib.request.Request(
        url, data=data, headers={"Content-Type": "application/json"}, method="POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, json.loads(resp.read() or b"{}")
    except urllib.error.HTTPError as exc:  # the refusal path we're testing
        raw = exc.read() or b"{}"
        try:
            return exc.code, json.loads(raw)
        except ValueError:
            return exc.code, {}


def _get_json(url: str, timeout: float = 10.0) -> tuple[int, dict]:
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            return resp.status, json.loads(resp.read() or b"{}")
    except urllib.error.HTTPError as exc:
        return exc.code, {}


def _stream_investigate_sse(
    base_url: str, alert_id: str, *, deadline_s: float = 120.0
) -> list[tuple[str, dict]]:
    """POST /investigate and read the SSE stream to natural EOF.

    Reading to EOF (not breaking early) lets the demo replay finish cleanly —
    the recorder commits ``complete`` before the stream closes, so the resulting
    row lands the recorded verdict (an early client disconnect would land it
    'error' by design, see soc_ai/demo/replay.py). Returns the parsed
    ``(event_name, data_dict)`` pairs.
    """
    body = json.dumps({"alert_id": alert_id}).encode()
    req = urllib.request.Request(
        f"{base_url}/investigate",
        data=body,
        headers={"Content-Type": "application/json", "Accept": "text/event-stream"},
        method="POST",
    )
    events: list[tuple[str, dict]] = []
    deadline = time.monotonic() + deadline_s
    cur_event: str | None = None
    data_lines: list[str] = []
    with urllib.request.urlopen(req, timeout=deadline_s) as resp:
        for raw in resp:
            if time.monotonic() > deadline:
                raise AssertionError("replay SSE stream did not close within the deadline")
            line = raw.decode("utf-8", "replace").rstrip("\r\n")
            if line.startswith(":"):
                continue  # SSE comment / keep-alive ping
            if line.startswith("event:"):
                cur_event = line[len("event:") :].strip()
            elif line.startswith("data:"):
                data_lines.append(line[len("data:") :].lstrip(" "))
            elif line == "":  # blank line dispatches the accumulated event
                if cur_event is not None:
                    try:
                        payload = json.loads("\n".join(data_lines)) if data_lines else {}
                    except ValueError:
                        payload = {}
                    events.append((cur_event, payload))
                cur_event, data_lines = None, []
    return events


# --- checkpoints --------------------------------------------------------------


@pytest.mark.browser
def test_banner_and_alerts_queue(page: Page, demo_mode_stack: dict) -> None:
    """Honesty banner on the alerts list + the seeded mock-ES alert queue is non-empty."""
    base: str = demo_mode_stack["base_url"]
    page.goto(f"{base}/app/alerts", wait_until="networkidle")

    expect(page.get_by_text(_BANNER, exact=False).first).to_be_visible(timeout=_WAIT_MS)

    # The seeded alert docs group into rows; a distinctive rule row must render.
    emotet_row = page.get_by_text(
        "ETPRO TROJAN Win32/Emotet CnC Activity (POST)", exact=False
    ).first
    expect(emotet_row).to_be_visible(timeout=_WAIT_MS)
    # And it's a real queue, not a single lucky row — several grouped rows show.
    assert page.get_by_text("ET MALWARE Quasar RAT CnC Checkin", exact=False).first.is_visible(), (
        "expected multiple seeded alert rows in the demo queue"
    )


@pytest.mark.browser
def test_investigation_detail_verdict_and_recorded_chip(page: Page, demo_mode_stack: dict) -> None:
    """A seeded investigation: banner + verdict pill + 'recorded run' chip + timeline."""
    base: str = demo_mode_stack["base_url"]
    fixtures: dict = demo_mode_stack["fixtures"]
    inv = _first_investigation(fixtures, "true_positive")

    page.goto(f"{base}/app/investigation/{inv['id']}", wait_until="networkidle")

    expect(page.get_by_text(_BANNER, exact=False).first).to_be_visible(timeout=_WAIT_MS)
    # Verdict pill renders the recorded verdict's label.
    expect(page.get_by_text(_VERDICT_LABEL["true_positive"], exact=False).first).to_be_visible(
        timeout=_WAIT_MS
    )
    # Demo-only chip: this is a replayed recording, labelled as such.
    expect(page.get_by_text("recorded run", exact=False).first).to_be_visible(timeout=_WAIT_MS)
    # Timeline of the recorded run renders.
    expect(page.get_by_text("Investigation timeline", exact=False).first).to_be_visible(
        timeout=_WAIT_MS
    )


@pytest.mark.browser
def test_banner_on_backtest(page: Page, demo_mode_stack: dict) -> None:
    """The seeded backtest renders its headline numbers, under the banner."""
    base: str = demo_mode_stack["base_url"]
    page.goto(f"{base}/app/backtest", wait_until="networkidle")

    expect(page.get_by_text(_BANNER, exact=False).first).to_be_visible(timeout=_WAIT_MS)

    # Headline metric cards from the recorded backtest (100% agreement, 0 missed).
    expect(page.get_by_text("Agreement with analysts", exact=False).first).to_be_visible(
        timeout=_WAIT_MS
    )
    expect(page.get_by_text("Missed true positives", exact=False).first).to_be_visible(
        timeout=_WAIT_MS
    )
    expect(page.get_by_text("False-positive toil cleared", exact=False).first).to_be_visible(
        timeout=_WAIT_MS
    )
    # The agreement number itself (recorded metrics: agreement_rate=1.0 → 100%).
    assert page.get_by_text("100%", exact=False).first.is_visible(), "backtest metrics missing"


@pytest.mark.browser
def test_banner_on_config(page: Page, demo_mode_stack: dict) -> None:
    """The config screen renders under the banner (read-only demo)."""
    base: str = demo_mode_stack["base_url"]
    page.goto(f"{base}/app/config", wait_until="networkidle")

    expect(page.get_by_text(_BANNER, exact=False).first).to_be_visible(timeout=_WAIT_MS)
    # A stable config control — the analyst-model row's fitness check.
    expect(page.get_by_role("button", name="Check fitness").first).to_be_visible(timeout=_WAIT_MS)


@pytest.mark.browser
def test_replay_streams_and_lands_recorded_verdict(demo_mode_stack: dict) -> None:
    """POST /investigate on a replay alert → the SSE streams events and the row
    lands the recorded verdict (the real demo replay path: recorder → SSE)."""
    base: str = demo_mode_stack["base_url"]
    fixtures: dict = demo_mode_stack["fixtures"]
    expected_verdict = _recorded_verdict(fixtures, _REPLAY_ALERT_ID)

    events = _stream_investigate_sse(base, _REPLAY_ALERT_ID)
    kinds = [name for name, _ in events]

    # The stream produced a real recorded run: the leading created event carries
    # the new row id, the session started, and it reached a triage_report.
    assert "investigation_created" in kinds, f"no investigation_created in {kinds[:5]}"
    assert "session_start" in kinds, f"replay stream never started: {kinds[:5]}"
    assert "triage_report" in kinds, f"replay stream never reached a verdict: {kinds}"
    assert len(events) > 5, f"replay produced too few events to be a real run: {kinds}"

    inv_id = next(
        data.get("investigation_id") for name, data in events if name == "investigation_created"
    )
    assert inv_id, "investigation_created carried no id"

    # Recorded events stream as {session_id, sequence, payload}; the verdict is
    # inside the triage_report payload (soc_ai/demo/replay.py).
    report = next(data for name, data in events if name == "triage_report")
    sse_verdict = (report.get("payload") or {}).get("verdict")
    assert sse_verdict == expected_verdict, (
        f"SSE landed verdict {sse_verdict!r}, expected recorded {expected_verdict!r}"
    )

    # …and it's persisted: the resulting row is complete with the recorded verdict.
    status_code, row = 0, {}
    for _ in range(20):
        status_code, row = _get_json(f"{base}/api/v1/investigations/{inv_id}")
        if status_code == 200 and row.get("status") == "complete":
            break
        time.sleep(0.5)
    assert status_code == 200, f"investigation row not readable (HTTP {status_code})"
    assert row.get("status") == "complete", f"row did not complete: {row.get('status')!r}"
    assert row.get("verdict") == expected_verdict, (
        f"persisted verdict {row.get('verdict')!r} != recorded {expected_verdict!r}"
    )


@pytest.mark.browser
def test_mutation_is_refused(demo_mode_stack: dict) -> None:
    """A mutating request to a blocked route gets the structured demo refusal."""
    base: str = demo_mode_stack["base_url"]

    status_code, body = _post_json(f"{base}{_BLOCKED_ROUTE}", {"rule_name": "whatever"})

    assert status_code == 403, f"expected 403 demo refusal, got HTTP {status_code}: {body}"
    detail = body.get("detail") or {}
    assert detail.get("reason") == "demo_mode", f"missing demo_mode reason: {body}"
    assert "disabled" in (detail.get("hint") or "").lower(), f"missing refusal hint: {body}"


@pytest.mark.browser
def test_hunt_console_lists_hunts_and_detail_renders(page: Page, demo_mode_stack: dict) -> None:
    """The Hunt Console lists the seeded hunts; opening one shows its narrative + timeline."""
    base: str = demo_mode_stack["base_url"]
    fixtures: dict = demo_mode_stack["fixtures"]
    hunts = fixtures.get("hunts") or []
    assert len(hunts) >= 2, f"expected >=2 seeded hunts, got {len(hunts)}"

    # The Hunt Console lists every seeded hunt by its objective (the row renders
    # the full objective under CSS truncation, so the text stays in the DOM).
    page.goto(f"{base}/app/hunts", wait_until="networkidle")
    expect(page.get_by_text(_BANNER, exact=False).first).to_be_visible(timeout=_WAIT_MS)
    for hunt in hunts:
        objective = (hunt.get("objective") or "").strip()
        assert objective, f"seeded hunt {hunt.get('id')} has no objective"
        expect(page.get_by_text(objective, exact=False).first).to_be_visible(timeout=_WAIT_MS)

    # Opening a hunt shows its recorded narrative and the execution timeline.
    hunt = _seeded_hunt(fixtures)
    narrative_probe = " ".join((hunt["narrative"]).split())[:48]
    page.goto(f"{base}/app/hunts/{hunt['id']}", wait_until="networkidle")
    expect(page.get_by_text(_BANNER, exact=False).first).to_be_visible(timeout=_WAIT_MS)
    expect(page.get_by_text(hunt["objective"], exact=False).first).to_be_visible(timeout=_WAIT_MS)
    expect(page.get_by_text(narrative_probe, exact=False).first).to_be_visible(timeout=_WAIT_MS)
    expect(page.get_by_text("Hunt timeline", exact=False).first).to_be_visible(timeout=_WAIT_MS)


@pytest.mark.browser
def test_investigation_chat_returns_canned_reply(demo_mode_stack: dict) -> None:
    """A chat turn on a seeded investigation returns the SCRIPTED canned reply.

    Drives the real demo chat path against the demo server: POST the authored
    user turn, poll the thread until the assistant turn settles, and assert the
    persisted assistant text is the exact authored reply (zero egress — a live
    call would hit the demo egress guard and never produce this text).
    """
    base: str = demo_mode_stack["base_url"]
    fixtures: dict = demo_mode_stack["fixtures"]
    inv_id, user_turn, expected_reply = _canned_investigation_chat(fixtures)

    status_code, _ = _post_json(
        f"{base}/api/v1/investigations/{inv_id}/chat", {"message": user_turn}
    )
    assert status_code == 200, f"chat POST not accepted (HTTP {status_code}) — demo allowlist?"

    thread: dict = {}
    for _ in range(40):
        code, thread = _get_json(f"{base}/api/v1/investigations/{inv_id}/chat")
        if code == 200 and not thread.get("pending"):
            break
        time.sleep(0.5)
    assert code == 200, f"chat thread not readable (HTTP {code})"
    assert not thread.get("pending"), "assistant turn never settled"

    replies = [m.get("text") for m in thread.get("messages") or [] if m.get("role") == "assistant"]
    assert replies, f"no assistant turn in the thread: {thread}"
    assert expected_reply in replies, (
        f"canned reply not served — got {replies!r}, expected authored {expected_reply!r}"
    )


@pytest.mark.browser
def test_hunt_start_replays_canned_hunt(demo_mode_stack: dict) -> None:
    """POST /hunts/chat starts a replayed canned hunt that completes with a narrative.

    The Hunt Console 'start hunt' path in demo mode replays a recorded hunt
    through the live recorder rather than building the egress-blocked agent:
    the POST returns a real hunt_id, and polling the row lands it complete WITH
    its recorded narrative + timeline (the real demo hunt-replay path)."""
    base: str = demo_mode_stack["base_url"]

    status_code, body = _post_json(
        f"{base}/api/v1/hunts/chat", {"objective": "Demo walkthrough: sweep for beaconing"}
    )
    assert status_code == 200, f"hunt-start not accepted (HTTP {status_code}): {body}"
    hunt_id = body.get("hunt_id")
    assert hunt_id, f"hunt-start returned no hunt_id: {body}"

    row: dict = {}
    for _ in range(80):  # replay is paced (~seconds); poll generously
        code, row = _get_json(f"{base}/api/v1/hunts/{hunt_id}")
        if code == 200 and row.get("status") == "complete":
            break
        time.sleep(0.5)
    assert code == 200, f"hunt row not readable (HTTP {code})"
    assert row.get("status") == "complete", f"replayed hunt did not complete: {row.get('status')!r}"
    assert (row.get("narrative") or "").strip(), "replayed hunt completed without a narrative"
    assert row.get("timeline"), "replayed hunt completed without a timeline"

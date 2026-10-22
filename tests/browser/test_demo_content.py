"""Every page of the public demo shows content: the guard that keeps it from going stale.

One check per page against the real demo stack (``demo_mode_stack``: the app in
SOC_AI_DEMO mode seeding ``soc_ai/demo/fixtures.json``, behind the bundled mock
grid). Each check asserts the feature's key content: a non-empty list, a count
above zero, the control that only renders with data. A console change that
empties a page in the demo, or a fixture rebuild that drops a feature, fails
here.

The checks read counts from the API where the page prints them, so they assert
that the pages agree with each other, not a number copied into this file.
Runs only under ``-m browser`` (the default coverage run ignores tests/browser).
"""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from typing import Any
from urllib.parse import quote

import pytest
from playwright.sync_api import Browser, Page, expect

_WAIT_MS = 15000

pytestmark = pytest.mark.browser


def _get(base: str, path: str) -> Any:
    with urllib.request.urlopen(f"{base}{path}", timeout=15) as resp:
        return json.loads(resp.read() or b"null")


def _open(page: Page, base: str, path: str) -> None:
    page.goto(f"{base}/app{path}", wait_until="networkidle")


def _see(page: Page, text: str | re.Pattern[str]) -> None:
    expect(page.get_by_text(text).first).to_be_visible(timeout=_WAIT_MS)


def _in_dom(page: Page, text: str | re.Pattern[str]) -> None:
    """The text is on the page, scrolled into view or not."""
    expect(page.get_by_text(text).first).to_be_attached(timeout=_WAIT_MS)


def _lead(base: str, state: str) -> dict[str, Any]:
    leads = _get(base, "/api/v1/leads?status=all&limit=200")
    for lead in leads:
        hunted = lead.get("hunt_status") == "complete" and (lead.get("hunt_threat_count") or 0)
        if state == "hunted_threat" and hunted and lead["status"] == "hunting":
            return lead
        if state == lead["status"]:
            return lead
    raise AssertionError(f"no lead in state {state}")


# --- Dashboard ------------------------------------------------------------------


def test_dashboard_tiles_and_panels_hold_data(page: Page, demo_mode_stack: dict) -> None:
    base = demo_mode_stack["base_url"]
    needs = _get(base, "/api/v1/needs-you")
    parts = (
        "leads_needing_decision",
        "unread_shadow_hits",
        "untriaged_groups",
        "needs_more_info",
        "pending_actions",
    )
    assert all(needs[p] > 0 for p in parts), needs
    assert needs["total"] == sum(needs[p] for p in parts)
    _open(page, base, "/dashboard")
    _see(page, "Needs you")
    _see(page, f"{needs['leads_needing_decision']} leads wait on a decision")
    _see(page, f"{needs['unread_shadow_hits']} shadow hits are unread")
    _see(page, re.compile(r"Review \d+ hits in this gap"))
    _in_dom(page, "Investigation outcomes")
    _in_dom(page, re.compile(r"Last batch at .* investigated"))


# --- Alerts ----------------------------------------------------------------------


def test_alerts_show_groups_a_verdict_mix_and_a_shared_flow(
    page: Page, demo_mode_stack: dict
) -> None:
    base = demo_mode_stack["base_url"]
    groups = _get(base, "/api/v1/alerts?range=24h&hide_acked=true&links=true")["groups"]
    assert len(groups) >= 8
    assert any(g.get("siblings") for g in groups), "no group shares a flow"
    _open(page, base, "/alerts")
    _see(page, "ETPRO TROJAN Win32/Emotet CnC Activity (POST)")
    _in_dom(page, re.compile(r"1 true positive, 1 false positive"))
    _in_dom(page, "A true positive shares this flow.")


def test_alerts_link_an_escalated_alert_to_its_case(demo_mode_stack: dict) -> None:
    base = demo_mode_stack["base_url"]
    groups = _get(base, "/api/v1/alerts?range=24h&hide_acked=false&links=true")["groups"]
    linked = [g for g in groups if g.get("escalatedCount") and g.get("cases")]
    assert linked, "no escalated group names its case"


def test_alert_group_expands_to_its_events(demo_mode_stack: dict) -> None:
    base = demo_mode_stack["base_url"]
    rule = quote("ET WEB_SPECIFIC_APPS Possible SQL Injection UNION SELECT")
    rows = _get(base, f"/api/v1/alerts/events?rule_name={rule}&range=24h")
    assert len(rows) >= 5


# --- Investigations ------------------------------------------------------------


def test_investigations_list_waiting_actions_and_replays(page: Page, demo_mode_stack: dict) -> None:
    base = demo_mode_stack["base_url"]
    listing = _get(base, "/api/v1/investigations?limit=100")
    assert listing["total"] >= 10
    assert listing["backtestReplays"] >= 1
    _open(page, base, "/investigations")
    _see(page, re.compile(r"\d+ backtest replays not counted"))
    _open(page, base, "/investigations?actions=pending")
    _see(page, "Escalate to case")


def test_investigation_page_shows_citations_follow_up_note_and_blocked_action(
    page: Page, demo_mode_stack: dict
) -> None:
    base = demo_mode_stack["base_url"]
    runs = {i["id"]: i for i in demo_mode_stack["fixtures"]["investigations"]}
    psexec = "01DEMOMN84EQQ566EMY50AFMFS"
    # A cited grid document opens in the drawer.
    cite = next(c for c in runs[psexec]["report"]["citations"] if re.fullmatch(r"\w{20}", c))
    assert _get(base, f"/api/v1/events/{cite}")["id"] == cite
    _open(page, base, f"/investigation/{psexec}")
    _see(page, "Cited evidence:")
    # The answered follow-up of a needs-more-info run.
    nmi = next(
        i for i in runs.values() if (i.get("report") or {}).get("follow_up") and i["verdict"]
    )
    _open(page, base, f"/investigation/{nmi['id']}")
    _see(page, re.compile(r"A newer run on this alert reached true positive"))
    # The analyst's verdict note.
    noted = next(
        i for i in runs.values() if (i.get("rationale") or "").startswith("Verdict set by")
    )
    _open(page, base, f"/investigation/{noted['id']}")
    _see(page, re.compile(r"Verdict set by \S+:"))
    # A backtest replay: its action is blocked, and the page says why.
    replay = next(i for i in runs.values() if i.get("started_by") == "backtest")
    _open(page, base, f"/investigation/{replay['id']}")
    _in_dom(page, "Not executable. This run is a backtest replay.")


def test_investigation_page_shows_the_same_flow_block(page: Page, demo_mode_stack: dict) -> None:
    base = demo_mode_stack["base_url"]
    smb = next(
        i
        for i in demo_mode_stack["fixtures"]["investigations"]
        if i["rule_name"].startswith("ET POLICY SMB2")
    )
    _open(page, base, f"/investigation/{smb['id']}")
    _in_dom(page, "A true positive shares this flow.")


# --- Hunts, analytics, leads -----------------------------------------------------


def test_hunts_page_holds_leads_hits_hunts_and_schedules(page: Page, demo_mode_stack: dict) -> None:
    base = demo_mode_stack["base_url"]
    leads = _get(base, "/api/v1/leads?status=all&limit=200")
    states = {(lead["status"], lead.get("hunt_status")) for lead in leads}
    assert ("open", None) in states  # new, left to the analyst
    assert ("hunting", "running") in states  # in progress
    assert ("hunting", "complete") in states  # hunted, waits on a decision
    assert ("promoted", "complete") in states  # closed by soc-ai on verdicts
    assert any(lead.get("dismissed_reason") not in (None, "hunt_clean") for lead in leads)
    hits = _get(base, "/api/v1/hunts/hits?days=7&filter=all&limit=50&offset=0")
    assert hits["hits"], "no analytic hit in 7 days"
    assert _get(base, "/api/v1/hunts/shadow-hits?limit=10")["unread"] > 0
    kinds = {h["kind"] for h in _get(base, "/api/v1/hunts")}
    assert {"chat", "lead", "scheduled", "triggered"} <= kinds
    assert len(_get(base, "/api/v1/hunt-schedules")) >= 2
    _open(page, base, "/hunts")
    _see(page, "Hunted · Threat found")
    _in_dom(page, re.compile(r"Analytic hits last 7 days · [1-9]"))
    _in_dom(page, "Scheduled hunts")


def test_analytics_tab_shows_a_held_analytic_and_a_failed_sweep(
    page: Page, demo_mode_stack: dict
) -> None:
    base = demo_mode_stack["base_url"]
    held = [a for a in _get(base, "/api/v1/analytics")["analytics"] if a.get("held_by_system")]
    assert held, "no analytic held by soc-ai"
    detail = _get(base, f"/api/v1/analytics/{held[0]['id']}")
    assert detail["gap_hold"] and detail["gap_hold"]["return_offered"]
    _open(page, base, "/hunts?tab=analytics")
    _in_dom(page, "Paused by soc-ai")
    _in_dom(page, re.compile(r"\d+ of \d+ runs failed in 24 h"))


def test_hunt_page_shows_finding_verdicts_and_a_shared_investigation(
    page: Page, demo_mode_stack: dict
) -> None:
    base = demo_mode_stack["base_url"]
    promoted = _lead(base, "promoted")
    _open(page, base, f"/hunts/{promoted['hunt_id']}")
    _see(page, "True positive")
    _in_dom(page, re.compile(r"F\d shares this investigation\."))


def test_lead_page_shows_the_timeline_and_a_grid_gap_mark(
    page: Page, demo_mode_stack: dict
) -> None:
    base = demo_mode_stack["base_url"]
    lead = _lead(base, "hunted_threat")
    _open(page, base, f"/leads/{lead['id']}")
    _see(page, "Hunted · Threat found")
    _in_dom(page, re.compile(r"Timeline · \d+ observations"))
    _in_dom(page, re.compile(r"Marked benign by \S+: The grid held no data"))


# --- Hosts and entities ----------------------------------------------------------


def test_hosts_list_holds_the_estate(page: Page, demo_mode_stack: dict) -> None:
    base = demo_mode_stack["base_url"]
    rows = _get(base, "/api/v1/hosts?limit=200")["rows"]
    assert len(rows) >= 12
    roles = {r["role"]["state"] for r in rows}
    assert {"declared", "inferred"} <= roles
    assert roles & {"low_confidence", "stale"}
    assert any(r["flags"]["conflict"] for r in rows)
    _open(page, base, "/hosts")
    _see(page, f"{len(rows)} machines")
    _in_dom(page, "domain controller")


def test_host_page_agrees_with_its_entity_page(page: Page, demo_mode_stack: dict) -> None:
    base = demo_mode_stack["base_url"]
    rows = _get(base, "/api/v1/hosts?limit=200")["rows"]
    jump = next(r for r in rows if r["name"] == "jump01")
    host_runs = _get(
        base, f"/api/v1/investigations?entity={quote(jump['key'])}&limit=100&since=2000-01-01"
    )
    summary = _get(base, f"/api/v1/entity/{jump['primary_ip']}")["summary"]
    leads = _get(base, f"/api/v1/leads/count?status=all&entity={jump['primary_ip']}")
    seen = _get(base, f"/api/v1/hunts/observations?entity={jump['primary_ip']}&days=7")
    assert host_runs["total"] >= 2
    assert host_runs["total"] == summary["investigationCount"]
    assert leads["total"] == summary["leadCount"] >= 1
    assert len(seen["observations"]) == summary["observationCount"] >= 1
    _open(page, base, f"/hosts/{quote(jump['key'], safe='')}")
    _see(page, "jump01")
    _in_dom(page, re.compile(r"Investigations on this host · all time · [1-9]"))
    _in_dom(page, "Users · 24h")
    _in_dom(page, "Peers · 24h")
    _in_dom(page, re.compile(r"Observations on this host · last 7 days · [1-9]"))


def test_entity_pages_for_an_address_and_a_user(page: Page, demo_mode_stack: dict) -> None:
    base = demo_mode_stack["base_url"]
    _open(page, base, "/entity/162.243.103.246")
    _see(page, "162.243.103.246")
    _in_dom(page, re.compile(r"[1-9] investigations?"))
    _open(page, base, "/entity/it-admin-07")
    _see(page, "it-admin-07 is a user account.")
    _in_dom(page, re.compile(r"[1-9] leads?"))


# --- Notifications, Status, Backtest, Runbooks, Settings ---------------------------


def test_notifications_hold_the_gap_and_the_held_analytic(
    page: Page, demo_mode_stack: dict
) -> None:
    base = demo_mode_stack["base_url"]
    ids = [n["id"] for n in _get(base, "/api/v1/notifications?limit=60")]
    assert any(i.startswith("grid-gap:") for i in ids)
    assert any(i.startswith("analytic-held:") for i in ids)
    assert any(i.startswith("lead:") for i in ids)
    _open(page, base, "/notifications")
    _see(page, re.compile(r"Most hosts sent no network flow documents"))
    _in_dom(page, re.compile(r"soc-ai moved the analytic"))


def test_status_page_shows_jobs_sweeps_and_an_unanswered_escalation(
    page: Page, demo_mode_stack: dict
) -> None:
    base = demo_mode_stack["base_url"]
    assert _get(base, "/api/v1/escalations/stranded")["total"] >= 1
    _open(page, base, "/operate")
    _see(page, "Dependencies")
    _in_dom(page, re.compile(r"The last run investigated \d+ alerts"))
    _in_dom(page, "Escalations awaiting an answer")
    _in_dom(page, re.compile(r"\d+ of \d+ runs failed in 24 h"))


def test_backtest_lists_past_runs_with_a_cancelled_one(page: Page, demo_mode_stack: dict) -> None:
    base = demo_mode_stack["base_url"]
    runs = _get(base, "/api/v1/backtests?limit=20")["runs"]
    assert len(runs) >= 3
    assert "cancelled" in {r["status"] for r in runs}
    _open(page, base, "/backtest")
    _see(page, "Past runs")
    _in_dom(page, "Cancelled")


def test_runbooks_list_several_and_one_links_a_rule(page: Page, demo_mode_stack: dict) -> None:
    base = demo_mode_stack["base_url"]
    books = _get(base, "/api/v1/runbooks")
    assert len(books) >= 4
    assert any(b["linked_rules"] for b in books)
    _open(page, base, "/runbooks")
    _see(page, books[0]["title"])


def test_settings_render_locked(page: Page, demo_mode_stack: dict) -> None:
    _open(page, demo_mode_stack["base_url"], "/config")
    _see(page, "Read-only demo")


# --- Tours and chat ------------------------------------------------------------------


def test_a_visitor_gets_the_welcome_tour(browser: Browser, demo_mode_stack: dict) -> None:
    """Automation never sees a tour (navigator.webdriver). A visitor does: the
    demo keeps the tour state in localStorage and starts the welcome tour."""
    ctx = browser.new_context()
    ctx.add_init_script("Object.defineProperty(navigator, 'webdriver', {get: () => false})")
    page = ctx.new_page()
    try:
        _open(page, demo_mode_stack["base_url"], "/dashboard")
        expect(page.get_by_role("dialog").first).to_be_visible(timeout=_WAIT_MS)
        _see(page, "SOC-AI TOUR")
    finally:
        ctx.close()


@pytest.mark.parametrize(
    ("path", "body"),
    [
        ("/api/v1/hunts/leads/4/chat", {"message": "What did the hunt find?"}),
        ("/api/v1/chat", {"message": "What did overnight look like?"}),
    ],
)
def test_lead_and_general_chat_answer_in_the_demo(
    demo_mode_stack: dict, path: str, body: dict
) -> None:
    req = urllib.request.Request(
        f"{demo_mode_stack['base_url']}{path}",
        data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            reply = json.loads(resp.read())
    except urllib.error.HTTPError as exc:  # pragma: no cover - the failure message
        raise AssertionError(f"{path}: {exc.code} {exc.read()[:200]!r}") from exc
    texts = [m.get("text") or m.get("content") for m in reply.get("messages", [])]
    assert any(t for t in texts[1:]), reply

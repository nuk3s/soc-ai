"""The public demo shows a campaign on the Campaigns list and on the campaign page.

The checks run against the real demo stack (``demo_mode_stack``): the app in
SOC_AI_DEMO mode seeds ``soc_ai/demo/fixtures.json`` and builds the
campaigns at startup. The demo story holds one campaign: the PsExec run from
jump01 to fs01 seeds it, and the SMB write on the same flow joins it as a
verdict that differs.

The checks read the title, the bottom line, the parties, the members and the
sections from the API, and assert that the pages show them: the three
graphics first, then the folds that hold the tables. A fixture rebuild that
loses the campaign, or a console change that empties a graphic or a fold,
fails here. Runs only under ``-m browser``.

The API checks read the other pages of the demo: the Investigations list, the
investigation page, the Alerts groups, the host pages of the parties and the
confirmed threats. Each names the campaign of a member investigation, and an
investigation in no campaign has ``campaign`` null.

The decision checks read the campaign as the demo starts: no decision, a wait
since the first event, the change ``formed`` of the startup build, one Needs
you item and one bell row. The demo lock refuses a close. The campaign holds
no authorization and no override, and the demo lock refuses each write of
them. The campaign holds no case, the case scope answers in its shape, and the
demo lock refuses the case and its retry.
"""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

import pytest
from playwright.sync_api import Page, expect

_WAIT_MS = 15000

pytestmark = pytest.mark.browser

# The text of an error state, a not found state and a stale notice.
_FAILED = re.compile(r"Could not load|No such campaign|Refresh failed|This data is from")


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


def _no_failure(page: Page) -> None:
    expect(page.get_by_text(_FAILED)).to_have_count(0)


def _campaign(base: str) -> tuple[dict[str, Any], dict[str, Any]]:
    """The newest campaign of the list, and its page."""
    listing = _get(base, "/api/v1/campaigns")
    assert listing["rows"], listing
    assert listing["total"] == len(listing["rows"])
    assert listing["stale"] is False
    row = listing["rows"][0]
    return row, _get(base, f"/api/v1/campaigns/{row['id']}")


def test_the_demo_holds_a_campaign_with_a_seed_two_parties_and_a_reached_stage(
    demo_mode_stack: dict,
) -> None:
    row, detail = _campaign(demo_mode_stack["base_url"])
    assert detail["title"] == row["title"]
    assert detail["stale"] is False
    assert detail["bottomLine"]
    assert {p["role"] for p in detail["parties"]} == {"actor", "target"}
    assert any(m["link"] == "seed" for m in detail["members"])
    assert any(step["reached"] for step in detail["ladder"])
    # The SMB write of the story is a false positive on the flow of the seed.
    assert any(m["verdictDiffers"] for m in detail["members"])
    # The seed gives one arrow of the attack graph between two parties.
    keys = {p["machineKey"] for p in detail["parties"]}
    assert detail["graph"]["edges"], detail["graph"]
    for edge in detail["graph"]["edges"]:
        assert {edge["source"], edge["target"]} <= keys, edge
    seed = next(m for m in detail["members"] if m["link"] == "seed")
    assert {seed["sourceKey"], seed["targetKey"]} <= keys, seed


def test_the_campaigns_list_shows_the_title_of_the_campaign(
    page: Page, demo_mode_stack: dict
) -> None:
    base = demo_mode_stack["base_url"]
    row, _detail = _campaign(base)
    _open(page, base, "/campaigns")
    _see(page, "Campaigns")
    row_cell = page.get_by_test_id(f"campaign-row-{row['id']}")
    expect(row_cell.get_by_role("link", name=row["title"])).to_be_visible(timeout=_WAIT_MS)
    expect(page.get_by_test_id("campaigns-empty")).to_have_count(0)
    _no_failure(page)


def test_the_campaign_page_shows_the_bottom_line_the_graphics_and_the_folds(
    page: Page, demo_mode_stack: dict
) -> None:
    base = demo_mode_stack["base_url"]
    row, detail = _campaign(base)
    _open(page, base, f"/campaigns/{row['id']}")
    header = page.get_by_test_id("campaign-header")
    expect(header.get_by_role("heading", name=detail["title"])).to_be_visible(timeout=_WAIT_MS)
    expect(page.get_by_test_id("campaign-bottom-line")).to_have_text(detail["bottomLine"])
    if detail["authorizations"]:
        expect(header.get_by_test_id("campaign-authorizations")).to_be_visible()
    # The three graphics lead the page.
    for heading in ("Stage ladder", "Attack graph", "Timeline"):
        _in_dom(page, re.compile(rf"^{re.escape(heading)}$"))
    nodes = page.get_by_test_id("graph-node")
    expect(nodes.first).to_be_visible(timeout=_WAIT_MS)
    assert nodes.count() == len(detail["parties"])
    expect(page.get_by_test_id("timeline-mark").first).to_be_attached(timeout=_WAIT_MS)
    # The folds that always render, then the folds that render with data.
    folds = ["Machines", "Investigations"]
    if any(pair["rules"] for pair in detail["events"]["pairs"]):
        folds.insert(0, "Alerts")
    related = detail["related"]
    if any(related[k] for k in ("needsMoreInfo", "sessions", "named", "falsePositiveFromTargets")):
        folds.append("Related, not proven")
    if any(m["verdictDiffers"] for m in detail["members"]):
        folds.append("Verdicts that differ")
    if detail["detection"]:
        folds.append("Detection record")
    for title in folds:
        expect(page.get_by_role("button", name=f"Expand {title}")).to_be_visible()
    # A closed fold holds no table. A click opens it.
    expect(page.get_by_test_id("campaign-members")).to_have_count(0)
    page.get_by_role("button", name="Expand Investigations").click()
    expect(page.get_by_role("button", name="Collapse Investigations")).to_be_visible(
        timeout=_WAIT_MS
    )
    for m in detail["members"]:
        if not m["verdictDiffers"]:
            expect(page.get_by_test_id(f"member-{m['runId']}")).to_be_attached()
    page.get_by_role("button", name="Expand Machines").click()
    for p in detail["parties"]:
        expect(page.get_by_test_id(f"party-{p['machineKey']}")).to_be_attached()
    # The page speaks of events and investigations. It never says "run" or "member".
    text = page.get_by_test_id("campaign-view").inner_text()
    assert not re.search(r"\b(runs?|members?)\b", text, re.IGNORECASE), text[:400]
    assert detail["events"]["source"] in ("grid", "stored")
    assert detail["events"]["alerts"] >= 1
    _no_failure(page)


def test_the_tooltip_of_a_graphic_stays_whole_in_the_window(
    page: Page, demo_mode_stack: dict
) -> None:
    base = demo_mode_stack["base_url"]
    row, _ = _campaign(base)
    page.set_viewport_size({"width": 1280, "height": 640})
    _open(page, base, f"/campaigns/{row['id']}")
    marks = (
        (page.get_by_test_id("graph-node").last, "graph-tooltip"),
        (
            page.locator('[data-testid="timeline-mark"] rect[role="button"]').last,
            "timeline-tooltip",
        ),
    )
    for mark, tip_id in marks:
        expect(mark).to_be_attached(timeout=_WAIT_MS)
        # The mark goes to the bottom edge of the window: the room below it is too small.
        mark.evaluate("el => el.scrollIntoView({block: 'end'})")
        mark.hover()
        tip = page.get_by_test_id(tip_id)
        expect(tip).to_be_visible(timeout=_WAIT_MS)
        box = tip.bounding_box()
        assert box is not None
        assert box["x"] >= 0 and box["x"] + box["width"] <= 1280, box
        assert box["y"] >= 0 and box["y"] + box["height"] <= 640, box
        # No panel holds the tooltip, so no panel cuts it.
        assert tip.evaluate("el => el.parentElement === document.body")
        assert not re.search(r"\b(runs?|members?)\b", tip.inner_text(), re.IGNORECASE)
    _no_failure(page)


_LINK_KEYS = {"id", "title", "status", "stage", "differs", "decision"}


def _link(row: dict[str, Any], *, differs: bool = False) -> dict[str, Any]:
    return {
        "id": row["id"],
        "title": row["title"],
        "status": row["status"],
        "stage": row["stage"],
        "differs": differs,
        "decision": row["decision"],
    }


def test_the_investigations_of_the_demo_name_their_campaign(demo_mode_stack: dict) -> None:
    base = demo_mode_stack["base_url"]
    row, detail = _campaign(base)
    members = {m["runId"]: m for m in detail["members"]}
    listing = _get(base, "/api/v1/investigations?limit=200&include_backtest=true")
    rows = {r["id"]: r for r in listing["rows"]}
    on_page = [run_id for run_id in members if run_id in rows]
    assert on_page, sorted(members)
    for run_id in on_page:
        link = rows[run_id]["campaign"]
        assert set(link) == _LINK_KEYS
        assert link == _link(row, differs=members[run_id]["verdictDiffers"])
    # An investigation in no campaign has no link.
    others = [r for run_id, r in rows.items() if run_id not in members]
    assert others
    assert all(r["campaign"] is None for r in others)
    seed = next(m for m in detail["members"] if m["link"] == "seed")
    page = _get(base, f"/api/v1/investigations/{seed['runId']}")
    assert page["campaign"] == _link(row)


def test_the_alert_groups_and_the_host_pages_of_the_demo_name_the_campaign(
    demo_mode_stack: dict,
) -> None:
    base = demo_mode_stack["base_url"]
    row, detail = _campaign(base)
    members = {m["runId"]: m for m in detail["members"]}
    groups = _get(base, "/api/v1/alerts?range=30d")["groups"]
    assert groups
    for group in groups:
        if group.get("invId") in members:
            assert group["campaign"] == _link(
                row, differs=members[group["invId"]]["verdictDiffers"]
            ), group["name"]
        else:
            assert group["campaign"] is None, group["name"]
    # The group of the seed alert names the campaign.
    assert any(group["campaign"] for group in groups), [g["name"] for g in groups]
    for party in detail["parties"]:
        key = urllib.parse.quote(party["machineKey"], safe="")
        host = _get(base, f"/api/v1/hosts/{key}")
        (held,) = [c for c in host["campaigns"] if c["id"] == row["id"]]
        assert held["role"] in (party["role"], "both"), party
        assert held["title"] == row["title"]
        assert (held["firstEvent"], held["lastEvent"]) == (row["firstEvent"], row["lastEvent"])


def test_the_confirmed_threats_of_the_demo_lead_with_the_campaign(demo_mode_stack: dict) -> None:
    base = demo_mode_stack["base_url"]
    row, detail = _campaign(base)
    members = {m["runId"] for m in detail["members"] if not m["verdictDiffers"]}
    threats = _get(base, "/api/v1/threats?since=2000-01-01T00:00:00Z")
    (entry,) = [c for c in threats["campaigns"] if c["id"] == row["id"]]
    # The detail read can refresh the alert count, so it is not compared.
    assert {k: entry[k] for k in row if k != "alerts"} == {
        k: v for k, v in row.items() if k != "alerts"
    }
    assert 1 <= entry["investigations"] <= len(members)
    assert entry["waiting"] + entry["authorized"] <= entry["investigations"]
    # The investigations of the campaign are in no row.
    assert not {r["newestInvestigationId"] for r in threats["rows"]} & members
    assert threats["total"] >= entry["investigations"]


def _post(base: str, path: str, body: dict[str, Any]) -> int:
    req = urllib.request.Request(
        f"{base}{path}",
        data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return int(resp.status)
    except urllib.error.HTTPError as exc:
        return int(exc.code)


def test_the_campaign_of_the_demo_waits_on_a_decision_with_its_changes(
    demo_mode_stack: dict,
) -> None:
    base = demo_mode_stack["base_url"]
    row, detail = _campaign(base)
    assert (row["decision"], detail["decision"]) == (None, None)
    assert row["waitsSince"] == detail["waitsSince"] == detail["firstEvent"]
    # The startup build formed the campaign. The newest change is first.
    assert detail["changes"], detail["changes"]
    assert detail["changes"][-1]["type"] == "formed"
    for change in detail["changes"]:
        assert set(change) == {"id", "type", "at", "detail"}, change


def test_the_campaign_of_the_demo_lists_its_leads_and_its_hunts(demo_mode_stack: dict) -> None:
    """The fold "Leads and hunts" reads ``leads`` and ``hunts``. Both are lists.

    The demo may hold no lead and no hunt of the campaign. Each row that it
    holds has the shape of the contract, and no lead of the campaign is a
    Needs you item.
    """
    base = demo_mode_stack["base_url"]
    _row, detail = _campaign(base)
    assert isinstance(detail["leads"], list)
    assert isinstance(detail["hunts"], list)
    states = {"open", "hunting", "dismissed", "promoted", "fleet_condition"}
    for lead in detail["leads"]:
        assert set(lead) == {"id", "title", "state", "hunted", "related"}, lead
        assert lead["state"] in states, lead
        assert isinstance(lead["hunted"], bool) and isinstance(lead["related"], bool)
    for hunt in detail["hunts"]:
        assert set(hunt) == {
            "id",
            "starter",
            "status",
            "startedAt",
            "findings",
            "threatFindings",
        }, hunt
        assert hunt["starter"] in {"analyst", "schedule", "lead", "campaign", "catalog"}, hunt
    started = [h["startedAt"] for h in detail["hunts"]]
    assert started == sorted(started, reverse=True)
    assert len(detail["hunts"]) <= 20
    own = {str(lead["id"]) for lead in detail["leads"] if not lead["related"]}
    items = _get(base, "/api/v1/needs-you/items")
    assert not own & {i["id"] for i in items["items"] if i["type"] == "lead"}


def test_the_campaign_of_the_demo_is_one_needs_you_item_and_one_bell_row(
    demo_mode_stack: dict,
) -> None:
    base = demo_mode_stack["base_url"]
    row, detail = _campaign(base)
    count = _get(base, "/api/v1/needs-you")
    assert count["campaigns"] >= 1
    items = _get(base, "/api/v1/needs-you/items")
    (item,) = [i for i in items["items"] if i["type"] == "campaign" and i["id"] == str(row["id"])]
    assert item["href"] == f"/campaigns/{row['id']}"
    assert item["title"] == row["title"]
    assert item["stage"] == detail["stage"]
    assert items["total"] >= len(items["items"])
    # No investigation of the campaign is an item of its own.
    held = {m["runId"] for m in detail["members"] if not m["verdictDiffers"]}
    assert not {i["id"] for i in items["items"] if i["type"] == "investigation"} & held
    bell = _get(base, "/api/v1/notifications?limit=50")
    rows = [n for n in bell if n["id"].startswith("campaign:")]
    assert any(n["href"] == f"/campaigns/{row['id']}" for n in rows), bell
    assert all(n["tone"] == "danger" for n in rows)


def test_the_demo_lock_refuses_a_close_and_the_campaign_keeps_no_decision(
    demo_mode_stack: dict,
) -> None:
    base = demo_mode_stack["base_url"]
    row, _detail = _campaign(base)
    status = _post(base, f"/api/v1/campaigns/{row['id']}/close", {"reason": "test_over"})
    assert status == 403
    assert _post(base, f"/api/v1/campaigns/{row['id']}/reopen", {}) == 403
    _row, after = _campaign(base)
    assert after["decision"] is None


def _status(base: str, path: str) -> int:
    try:
        with urllib.request.urlopen(f"{base}{path}", timeout=15) as resp:
            return int(resp.status)
    except urllib.error.HTTPError as exc:
        return int(exc.code)


def test_the_campaign_of_the_demo_holds_no_authorization_and_no_override(
    demo_mode_stack: dict,
) -> None:
    row, detail = _campaign(demo_mode_stack["base_url"])
    assert (row["authorization"], row["beyond"]) == (None, 0)
    assert (detail["authorization"], detail["beyond"], detail["excluded"]) == (None, [], [])
    for member in detail["members"]:
        assert (member["authorized"], member["included"]) == (False, False), member["runId"]


def test_the_demo_lock_refuses_each_authorization_and_override_write(
    demo_mode_stack: dict,
) -> None:
    base = demo_mode_stack["base_url"]
    row, detail = _campaign(base)
    seed = next(m for m in detail["members"] if m["link"] == "seed")
    url = f"/api/v1/campaigns/{row['id']}"
    # The draft is for an admin, and the demo has none.
    assert _status(base, f"{url}/authorize-draft") == 403
    writes = (
        (
            f"{url}/authorize",
            {"label": "Red team test", "expiresAt": row["lastEvent"], "machineKeys": []},
        ),
        (f"{url}/revoke-authorization", {"reason": "The test ended."}),
        (f"{url}/exclude", {"runId": seed["runId"], "reason": "Another test."}),
        (f"{url}/include", {"runId": seed["runId"], "reason": "The same test."}),
        (f"{url}/overrides/{seed['runId']}/undo", {}),
    )
    for path, body in writes:
        assert _post(base, path, body) == 403, path
    _row, after = _campaign(base)
    assert (after["decision"], after["authorization"], after["excluded"]) == (None, None, [])


def test_the_campaign_of_the_demo_holds_no_case_and_states_the_case_scope(
    demo_mode_stack: dict,
) -> None:
    base = demo_mode_stack["base_url"]
    row, detail = _campaign(base)
    assert (row["case"], detail["case"]) == (None, None)
    scope = _get(base, f"/api/v1/campaigns/{row['id']}/case-scope")
    assert set(scope) == {"title", "alerts", "capped", "skipped", "existing"}
    assert scope["title"] == f"soc-ai campaign: {row['title']}"
    assert set(scope["skipped"]) == {"acknowledged", "escalated", "noAlert"}
    assert scope["existing"] is None
    # A failed grid read gives null, never a number below 0.
    assert scope["alerts"] is None or 0 <= scope["alerts"] <= 25


def test_the_demo_lock_refuses_the_case_of_a_campaign(demo_mode_stack: dict) -> None:
    base = demo_mode_stack["base_url"]
    row, _detail = _campaign(base)
    url = f"/api/v1/campaigns/{row['id']}"
    assert _post(base, f"{url}/case", {"note": ""}) == 403
    assert _post(base, f"{url}/case/retry", {}) == 403
    _row, after = _campaign(base)
    assert (after["decision"], after["case"]) == (None, None)
    # The Escalate of an investigation that the campaign holds names the campaign.
    seed = next(m for m in after["members"] if m["link"] == "seed")
    page = _get(base, f"/api/v1/investigations/{seed['runId']}")
    for action in page["actions"]:
        if action["tag"] == "escalate" and not action["applied"] and not action["dismissed"]:
            assert action["blockedReason"] == "Open the case on the campaign."
            assert action["noteCode"] == "campaign"
            assert action["noteHref"] == f"/campaigns/{row['id']}"


def _number(text: str) -> int:
    """The first number of a text: "14 decisions wait on you." is 14."""
    found = re.search(r"\d[\d,]*", text)
    assert found, text
    return int(found.group(0).replace(",", ""))


def test_the_top_bar_the_tile_and_the_needs_you_page_state_one_number(
    page: Page, demo_mode_stack: dict
) -> None:
    """The top bar counted each waiting action, and the page counted each investigation.

    The number of ``GET /needs-you`` is the total of ``GET /needs-you/items``,
    and the bell badge, the Dashboard tile and the heading of the Needs you
    page state it. The page lists the campaign first.
    """
    base = demo_mode_stack["base_url"]
    count = _get(base, "/api/v1/needs-you")
    items = _get(base, "/api/v1/needs-you/items")
    assert count["unknown"] == [], count
    assert items["unknown"] == [], items
    assert count["decisions"] == items["total"] > 0, (count, items["total"])
    # The detail of the investigations is no part of the number.
    assert count["decisions"] == (
        count["campaigns"]
        + count["investigations_waiting"]
        + count["leads_needing_decision"]
        + count["untriaged_groups"]
    )

    _open(page, base, "/needs-you")
    heading = page.get_by_test_id("needs-you-total")
    words = re.compile(r"^[\d,]+ decisions? waits? on you\.$")
    expect(heading).to_have_text(words, timeout=_WAIT_MS)
    badge = page.get_by_test_id("notif-badge")
    expect(badge).to_have_text(re.compile(r"^\d+$"), timeout=_WAIT_MS)
    assert _number(badge.inner_text()) == _number(heading.inner_text()) == count["decisions"]
    # The campaign is the unit of work: its row leads the list.
    first = page.get_by_test_id("needs-you-item").first
    expect(first).to_have_attribute("data-type", "campaign", timeout=_WAIT_MS)
    titles = {row["title"] for row in _get(base, "/api/v1/campaigns")["rows"]}
    assert first.get_by_test_id("needs-you-item-title").inner_text() in titles
    expect(first.get_by_test_id("stage-meter")).to_be_visible()
    _no_failure(page)

    _open(page, base, "/dashboard")
    tile = page.get_by_test_id("kpi-needs-you").get_by_test_id("needs-you-total")
    expect(tile).to_have_text(str(count["decisions"]), timeout=_WAIT_MS)
    # The lines of the tile add up to the number above them.
    lines = page.get_by_test_id("kpi-needs-you").get_by_role("listitem")
    expect(lines.first).to_be_visible(timeout=_WAIT_MS)
    assert sum(_number(text) for text in lines.all_inner_texts()) == count["decisions"]
    expect(page.get_by_text("last all")).to_have_count(0)

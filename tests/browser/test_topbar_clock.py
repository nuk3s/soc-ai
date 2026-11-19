"""The clocks of the top bar at 1100 px (round 4, C1 to C5).

The top bar states the time now in UTC, and the analyst can add a second
clock for a local time. At 1100 px with both clocks, the longest breadcrumb
and a large needs-you count, no text of the top bar is cut and nothing wraps
to a second line. The search field gives way first, and the clocks stay.
Below the smallest supported width the second clock shows in its panel only.

The test fixes the time of the page at 12:00 UTC on Thursday 2026-11-19. The
second clock of Pacific/Chatham then reads "Fri 01:45 GMT+13:45", the longest
form of a second clock. The browser zone is America/Chicago, so the tooltips
of "Off" state CST. The needs-you answer holds 9999 decisions and a part that
the server could not read, so the badge reads "9999+".

Set ``WIDTH_SHOTS_DIR`` to a directory to keep a screenshot of the top bar.

Runs with the browser suite: ``uv run pytest -m browser --no-cov
tests/browser/test_topbar_clock.py`` after ``npm run build``.
"""

from __future__ import annotations

import datetime as dt
import json
import os
import re
import urllib.request
from collections.abc import Iterator
from itertools import pairwise
from pathlib import Path
from typing import Any
from urllib.parse import quote

import pytest
from playwright.sync_api import Browser, Page, Route, expect

pytestmark = pytest.mark.browser

_WAIT_MS = 15000
_NOW = dt.datetime(2026, 11, 19, 12, 0, tzinfo=dt.UTC)
_ZONE = "Pacific/Chatham"
_SECOND = "Fri 01:45 GMT+13:45"

# Each element of the top bar that holds text: its scroll width and its
# client width, so a cut text shows, and the lines of each of its own text
# nodes, so a wrap shows. An inline element has no client width: its box is
# the box of its parent, which the list holds.
_TOPBAR_TEXT = """() => {
  const bar = document.querySelector('[data-testid="topbar"]');
  const texts = [];
  for (const el of bar.querySelectorAll('*')) {
    if (el.closest('[role="dialog"]')) continue;
    const own = [...el.childNodes].filter((n) => n.nodeType === 3 && n.textContent.trim());
    if (!own.length) continue;
    const cs = getComputedStyle(el);
    if (el.getBoundingClientRect().width === 0) continue;
    let lines = 0;
    for (const node of own) {
      const range = document.createRange();
      range.selectNodeContents(node);
      const tops = new Set([...range.getClientRects()].filter((r) => r.width > 0)
        .map((r) => Math.round(r.top)));
      lines = Math.max(lines, tops.size);
    }
    texts.push({text: el.textContent.trim(), inline: cs.display === 'inline',
                scroll: el.scrollWidth, client: el.clientWidth, lines});
  }
  const box = (el) => {
    const r = el.getBoundingClientRect();
    return {left: r.left, right: r.right, top: r.top, bottom: r.bottom,
            scroll: el.scrollWidth, client: el.clientWidth,
            text: (el.textContent || '').trim()};
  };
  const items = [...bar.children]
    .filter((el) => el.getBoundingClientRect().width > 0)
    .filter((el) => getComputedStyle(el).position !== 'absolute')
    .map(box);
  return {texts, items, bar: box(bar)};
}"""


def _get(base: str, path: str) -> Any:
    with urllib.request.urlopen(f"{base}{path}", timeout=15) as resp:
        return json.loads(resp.read() or b"null")


def _large_count(route: Route) -> None:
    """The real needs-you answer with 9999 decisions, a floor."""
    response = route.fetch()
    body = response.json()
    body["decisions"] = 9999
    body["leads_needing_decision"] = 9999
    body["unknown"] = ["leads_needing_decision"]
    route.fulfill(response=response, json=body)


@pytest.fixture
def chicago_page(browser: Browser) -> Iterator[Page]:
    """A page in a browser whose zone is America/Chicago, at a fixed time."""
    context = browser.new_context(
        viewport={"width": 1100, "height": 900}, timezone_id="America/Chicago"
    )
    page = context.new_page()
    page.clock.set_fixed_time(_NOW)
    page.route(re.compile(r".*/api/v1/needs-you(\?.*)?$"), _large_count)
    yield page
    context.close()


def _pick_zone(page: Page, filter_text: str, zone: str) -> None:
    page.get_by_test_id("topbar-clock-button").click()
    panel = page.get_by_role("dialog", name="Second clock")
    expect(panel).to_be_visible(timeout=_WAIT_MS)
    panel.get_by_role("radio", name="Another zone").check()
    panel.get_by_role("textbox", name="Filter the zones").fill(filter_text)
    panel.get_by_role("button", name=zone, exact=True).click()
    expect(panel).to_be_hidden()


def _pages(base: str) -> dict[str, tuple[str, str]]:
    """The pages with the longest breadcrumbs, and the text of each one.

    An id stays on one line. A name may wrap only when the search field has
    no more room to give, so a short machine name stays on one line.
    """
    inv_id = _get(base, "/api/v1/investigations?limit=1")["rows"][0]["id"]
    campaign = _get(base, "/api/v1/campaigns")["rows"][0]
    leads = _get(base, "/api/v1/leads?status=all&limit=200")
    hunt_id = next(lead["hunt_id"] for lead in leads if lead.get("hunt_id"))
    rows = _get(base, "/api/v1/hosts?limit=200")["rows"]
    jump = next(r for r in rows if r["name"] == "jump01")
    return {
        "investigation": (f"/investigation/{inv_id}", inv_id),
        "campaign": (f"/campaigns/{campaign['id']}", f"Campaign {campaign['id']}"),
        "hunt": (f"/hunts/{hunt_id}", hunt_id),
        "host": (f"/hosts/{quote(jump['key'], safe='')}", "jump01"),
    }


def _holds_whole(page: Page, where: str, width: int) -> dict:
    page.wait_for_timeout(200)
    boxes = page.evaluate(_TOPBAR_TEXT)
    shots = os.environ.get("WIDTH_SHOTS_DIR")
    if shots:
        Path(shots).mkdir(parents=True, exist_ok=True)
        clip = {"x": 0, "y": 0, "width": width, "height": boxes["bar"]["bottom"] + 4}
        name = where.replace(" ", "-")
        page.screenshot(path=str(Path(shots) / f"topbar-clock-{name}.png"), clip=clip)
    bar = boxes["bar"]
    assert bar["scroll"] <= bar["client"], f"{where}: the bar overflows {bar}"
    for t in boxes["texts"]:
        assert t["lines"] == 1, f"{where}: a text wraps {t}"
        if not t["inline"]:
            assert t["scroll"] <= t["client"], f"{where}: a text is cut {t}"
    items = boxes["items"]
    for left, right in pairwise(items):
        assert left["right"] <= right["left"] + 0.5, f"{where}: {left} runs into {right}"
    assert items[-1]["right"] <= width, f"{where}: the bar runs off the window"
    for item in items:
        assert bar["top"] <= item["top"] and item["bottom"] <= bar["bottom"], where
    return boxes


def test_the_top_bar_holds_both_clocks_whole_at_1100(
    chicago_page: Page, demo_mode_stack: dict
) -> None:
    page = chicago_page
    base = demo_mode_stack["base_url"]
    pages = _pages(base)
    page.goto(f"{base}/app{pages['investigation'][0]}", wait_until="networkidle")
    expect(page.get_by_test_id("topbar-clock-utc")).to_have_text("12:00 UTC", timeout=_WAIT_MS)
    expect(page.get_by_test_id("topbar-clock-utc")).to_have_attribute(
        "title", "2026-11-19 12:00 UTC"
    )
    _pick_zone(page, "chatham", _ZONE)
    for name, (path, shown) in pages.items():
        page.goto(f"{base}/app{path}", wait_until="networkidle")
        expect(page.get_by_test_id("topbar-crumb2")).to_have_text(shown, timeout=_WAIT_MS)
        expect(page.get_by_test_id("notif-badge")).to_have_text("9999+", timeout=_WAIT_MS)
        # The stored choice holds on each new page. UTC comes first.
        clocks = page.get_by_test_id("topbar-clock-button")
        expect(clocks).to_have_text(f"12:00 UTC{_SECOND}")
        second = page.get_by_test_id("topbar-clock-second")
        expect(second).to_be_visible()
        expect(second).to_have_attribute("title", f"2026-11-20 01:45 GMT+13:45, {_ZONE}")
        _holds_whole(page, f"{name} at 1100 px", 1100)
        if name == "investigation":
            # The words of the Ask button may hide whole. Its name stays whole.
            ask = page.get_by_role("button", name="Ask soc-ai about this investigation")
            expect(ask).to_be_visible()
            expect(ask).to_have_attribute(
                "title", re.compile(r"^Ask soc-ai about this investigation\.")
            )


def test_a_picked_zone_is_the_local_time_of_each_tooltip(
    chicago_page: Page, demo_mode_stack: dict
) -> None:
    page = chicago_page
    base = demo_mode_stack["base_url"]
    page.goto(f"{base}/app/campaigns", wait_until="networkidle")
    times = page.locator('[data-time][title*="Local time:"]')
    expect(times.first).to_be_attached(timeout=_WAIT_MS)
    # Negative control: with "Off" the tooltips state the zone of the browser.
    off = times.evaluate_all("els => els.map((el) => el.title)")
    assert off and all(" CST" in t for t in off), off
    _pick_zone(page, "chatham", _ZONE)
    # The open page follows the change with no reload.
    expect(times.first).to_have_attribute("title", re.compile(r"GMT\+13:45"))
    picked = times.evaluate_all("els => els.map((el) => el.title)")
    assert picked and all("GMT+13:45" in t and " CST" not in t for t in picked), picked
    # The local time of this browser reads as "Off" did.
    page.get_by_test_id("topbar-clock-button").click()
    page.get_by_role("radio", name=re.compile(r"^Local time of this browser")).check()
    page.keyboard.press("Escape")
    expect(page.get_by_test_id("topbar-clock-second")).to_have_text("06:00 CST")
    expect(times.first).to_have_attribute("title", re.compile(r" CST"))
    assert times.evaluate_all("els => els.map((el) => el.title)") == off


def test_below_the_smallest_width_the_second_clock_shows_in_its_panel(
    chicago_page: Page, demo_mode_stack: dict
) -> None:
    page = chicago_page
    base = demo_mode_stack["base_url"]
    inv_id = _get(base, "/api/v1/investigations?limit=1")["rows"][0]["id"]
    page.goto(f"{base}/app/investigation/{inv_id}", wait_until="networkidle")
    _pick_zone(page, "chatham", _ZONE)
    expect(page.get_by_test_id("topbar-clock-second")).to_be_visible()
    # 1000 px is below the smallest supported width. The UTC clock stays.
    page.set_viewport_size({"width": 1000, "height": 900})
    expect(page.get_by_test_id("topbar-clock-second")).to_be_hidden()
    expect(page.get_by_test_id("topbar-clock-utc")).to_be_visible()
    _holds_whole(page, "investigation at 1000 px", 1000)
    page.get_by_test_id("topbar-clock-button").click()
    reading = page.get_by_test_id("clock-menu-second")
    expect(reading).to_be_visible()
    expect(reading).to_have_text(f"{_SECOND} · {_ZONE}")

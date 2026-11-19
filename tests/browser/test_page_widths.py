"""The pages of the 2026-11-17 dogfood round at 1440 px and 1100 px (AB6).

The host page, the entity page, a hunt page, a lead page and the
Investigations list with the top bar open on the public demo data at both
widths. Each page must fit its width: no horizontal scroll of the document.
The host page shows its window counts with the page window in their labels,
and the hunt page shows its pictures before its narrative. At 1280 px and
1100 px the breadcrumb of the top bar stays whole beside the search field on an
investigation page, a campaign page and a hunt page.

Set ``WIDTH_SHOTS_DIR`` to a directory to keep a screenshot of each page
for a visual check.

Runs with the browser suite: ``uv run pytest -m browser --no-cov
tests/browser/test_page_widths.py`` after ``npm run build``.
"""

from __future__ import annotations

import json
import os
import re
import urllib.request
from itertools import pairwise
from pathlib import Path
from typing import Any
from urllib.parse import quote

import pytest
from playwright.sync_api import Page, expect

pytestmark = pytest.mark.browser

_WAIT_MS = 15000
_WIDTHS = (1440, 1100)
_UTC_ROW_TIME = re.compile(r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} UTC$")
_LOCAL_TITLE = re.compile(r"^Local time: \d{4}-\d{2}-\d{2} \d{2}:\d{2} \S+$")


def _get(base: str, path: str) -> Any:
    with urllib.request.urlopen(f"{base}{path}", timeout=15) as resp:
        return json.loads(resp.read() or b"null")


def _fits(page: Page, name: str, width: int) -> None:
    """The document holds no horizontal scroll at this width."""
    page.wait_for_timeout(300)
    over = page.evaluate("document.documentElement.scrollWidth - window.innerWidth")
    shots = os.environ.get("WIDTH_SHOTS_DIR")
    if shots:
        Path(shots).mkdir(parents=True, exist_ok=True)
        page.screenshot(path=str(Path(shots) / f"{name}-{width}.png"), full_page=True)
    assert over <= 1, f"{name} at {width} px scrolls sideways by {over} px"


def _pages(base: str) -> dict[str, str]:
    rows = _get(base, "/api/v1/hosts?limit=200")["rows"]
    jump = next(r for r in rows if r["name"] == "jump01")
    leads = _get(base, "/api/v1/leads?status=all&limit=200")
    lead = next(lead for lead in leads if lead.get("hunt_id"))
    # A complete hunt with findings: the hunt of a promoted lead.
    done = next(
        (lead for lead in leads if lead["status"] == "promoted" and lead.get("hunt_id")), lead
    )
    return {
        "host-24h": f"/hosts/{quote(jump['key'], safe='')}",
        "host-7d": f"/hosts/{quote(jump['key'], safe='')}?range=7d",
        "entity": "/entity/162.243.103.246",
        "hunt": f"/hunts/{done['hunt_id']}",
        "lead": f"/leads/{lead['id']}",
        "investigations": "/investigations",
    }


@pytest.mark.parametrize("width", _WIDTHS)
def test_the_changed_pages_fit_1440_and_1100(page: Page, demo_mode_stack: dict, width: int) -> None:
    base = demo_mode_stack["base_url"]
    page.set_viewport_size({"width": width, "height": 1000})
    row_times = 0
    for name, path in _pages(base).items():
        page.goto(f"{base}/app{path}", wait_until="networkidle")
        if name.startswith("host"):
            window = "7d" if name.endswith("7d") else "24h"
            expect(page.get_by_test_id("kpi-alerts")).to_contain_text(
                f"Alerts raised · {window}", timeout=_WAIT_MS
            )
            expect(page.get_by_test_id("kpi-services")).to_have_attribute("data-fact", "true")
            expect(page.get_by_test_id("host-investigations-title")).to_contain_text(
                f"Investigations on this host · {window}", timeout=_WAIT_MS
            )
        if name == "hunt":
            narrative = page.get_by_text("Narrative", exact=True)
            pictures = page.get_by_text("Visual summary", exact=True)
            if pictures.count() and narrative.count():
                above = pictures.first.bounding_box()
                below = narrative.first.bounding_box()
                assert above and below and above["y"] < below["y"]
        if name == "investigations":
            pill = page.get_by_role("button", name=re.compile("^(connected|checking|soc-ai)"))
            expect(pill).to_be_visible(timeout=_WAIT_MS)
        # Round 3, T3: a row time reads in UTC with the label, and its tooltip
        # states the local time with its zone.
        row_time = {"host-24h": "host-investigation-when", "entity": "entity-row-time"}.get(name)
        if row_time and page.get_by_test_id(row_time).count():
            when = page.get_by_test_id(row_time).first
            expect(when).to_have_text(_UTC_ROW_TIME)
            if name == "entity":
                expect(when).to_have_attribute("title", _LOCAL_TITLE)
            row_times += 1
        _fits(page, name, width)
    assert row_times, "no page showed a row time to check"


# The boxes of the top bar in the page: the second part of the breadcrumb, the
# breadcrumb, the search field and each item of the bar in its order. A box
# reports its scroll width and its client width, so a cut text shows.
_TOPBAR_BOXES = """() => {
  const box = (el) => {
    if (!el) return null;
    const r = el.getBoundingClientRect();
    return {left: r.left, right: r.right, top: r.top, bottom: r.bottom,
            scroll: el.scrollWidth, client: el.clientWidth,
            text: (el.textContent || '').trim()};
  };
  const q = (id) => document.querySelector(`[data-testid="${id}"]`);
  const bar = q('topbar-search').parentElement;
  const items = [...bar.children]
    .filter((el) => el.getBoundingClientRect().width > 0)
    .filter((el) => getComputedStyle(el).position !== 'absolute')
    .map(box);
  const shown = (id) => getComputedStyle(q(id)).display !== 'none';
  return {crumb2: box(q('topbar-crumb2')), trail: box(q('topbar-breadcrumb')),
          search: box(q('topbar-search')), bar: box(bar), items,
          words: shown('topbar-search-words'), key: shown('topbar-search-key')};
}"""


def _overlap(a: dict, b: dict) -> bool:
    return (
        a["left"] < b["right"] - 0.5
        and b["left"] < a["right"] - 0.5
        and a["top"] < b["bottom"] - 0.5
        and b["top"] < a["bottom"] - 0.5
    )


def _topbar_pages(base: str) -> dict[str, tuple[str, str]]:
    """A page with an id in the breadcrumb, a campaign page and a hunt page.

    Each value is the path and the text that the breadcrumb shows when the
    page is ready: the id, or the number of the campaign.
    """
    inv_id = _get(base, "/api/v1/investigations?limit=1")["rows"][0]["id"]
    campaign = _get(base, "/api/v1/campaigns")["rows"][0]
    leads = _get(base, "/api/v1/leads?status=all&limit=200")
    hunt_id = next(lead["hunt_id"] for lead in leads if lead.get("hunt_id"))
    return {
        "investigation": (f"/investigation/{inv_id}", inv_id),
        "campaign": (f"/campaigns/{campaign['id']}", f"Campaign {campaign['id']}"),
        "hunt": (f"/hunts/{hunt_id}", hunt_id),
    }


# Round 3, T1: at 1100 px the id of an investigation in the top bar ran under
# the search field (shot v08). The earlier fix read CSS classes in jsdom only.
# This check reads the boxes in a real browser.
@pytest.mark.parametrize("width", [1280, 1100])
def test_the_breadcrumb_is_whole_beside_the_search_field(
    page: Page, demo_mode_stack: dict, width: int
) -> None:
    base = demo_mode_stack["base_url"]
    page.set_viewport_size({"width": width, "height": 900})
    for name, (path, shown) in _topbar_pages(base).items():
        page.goto(f"{base}/app{path}", wait_until="networkidle")
        expect(page.get_by_test_id("topbar-crumb2")).to_have_text(shown, timeout=_WAIT_MS)
        page.wait_for_timeout(200)
        boxes = page.evaluate(_TOPBAR_BOXES)
        crumb2, trail, search = boxes["crumb2"], boxes["trail"], boxes["search"]
        where = f"{name} at {width} px"
        shots = os.environ.get("WIDTH_SHOTS_DIR")
        if shots:
            Path(shots).mkdir(parents=True, exist_ok=True)
            bar = boxes["bar"]
            clip = {"x": 0, "y": 0, "width": width, "height": bar["bottom"] + 4}
            page.screenshot(path=str(Path(shots) / f"topbar-{name}-{width}.png"), clip=clip)
        assert not _overlap(crumb2, search), f"{where}: the search field covers {crumb2}"
        assert crumb2["scroll"] <= crumb2["client"], f"{where}: the breadcrumb cuts {crumb2}"
        assert trail["scroll"] <= trail["client"], f"{where}: the breadcrumb overflows {trail}"
        assert search["scroll"] <= search["client"], f"{where}: the search field cuts {search}"
        # A name that wraps stays inside the height of the bar.
        bar = boxes["bar"]
        assert bar["top"] <= crumb2["top"] and crumb2["bottom"] <= bar["bottom"], where
        # The field keeps its shortcut at both widths. The words may hide.
        assert boxes["key"], f"{where}: the search field hides its shortcut {boxes}"
        # Each item of the bar stays in its own box, in its order.
        items = boxes["items"]
        for left, right in pairwise(items):
            assert left["right"] <= right["left"] + 0.5, f"{where}: {left} runs into {right}"
        assert items[-1]["right"] <= width, f"{where}: the bar runs off the window"


def test_the_search_field_keeps_its_words_where_it_has_room(
    page: Page, demo_mode_stack: dict
) -> None:
    # Negative control: the field hides its words only when it lacks room.
    base = demo_mode_stack["base_url"]
    page.set_viewport_size({"width": 1440, "height": 900})
    page.goto(f"{base}/app/investigations", wait_until="networkidle")
    expect(page.get_by_test_id("topbar-search-words")).to_be_visible(timeout=_WAIT_MS)
    boxes = page.evaluate(_TOPBAR_BOXES)
    assert boxes["words"] and boxes["key"], boxes
    assert boxes["search"]["scroll"] <= boxes["search"]["client"], boxes["search"]

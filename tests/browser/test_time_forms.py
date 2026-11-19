"""One time form on every page (round 3 part 2, P1).

An absolute time reads UTC with the label, and its tooltip states the local
time with its zone. A relative time ("14h", "4h ago") has a tooltip that
states the UTC time and the local time. The Alerts rows gave the local time
alone, the Hunts rows a raw ISO time, the Investigations list the UTC time
alone, and the rule samples, the Campaigns list and the lead page gave no
tooltip.

Each time of the console renders through ``<UtcTime>`` (``data-time=
"absolute"``) or ``<RelTime>`` (``data-time="relative"``). On each page the
test reads every such element, and it hovers one of each type that the page
shows. Runs only under ``-m browser``, after ``npm run build``.
"""

from __future__ import annotations

import json
import re
import urllib.request
from typing import Any
from urllib.parse import quote

import pytest
from playwright.sync_api import Page, expect

pytestmark = pytest.mark.browser

_WAIT_MS = 15000
_LOCAL = r"Local time: \d{4}-\d{2}-\d{2} \d{2}:\d{2} \S+"
_UTC = r"\d{4}-\d{2}-\d{2} \d{2}:\d{2} UTC"
# A relative time: an optional name ("Event"), the UTC time, the local time,
# then an optional sentence ("Recorded 2026-11-18 15:20 UTC.").
_RELATIVE_TITLE = re.compile(rf"^(?:[A-Z][a-z]+(?: [a-z]+)? )?{_UTC}\. {_LOCAL}(?:\. .+)?$")
# An absolute time: the local time, or the local times of both ends.
_ABSOLUTE_TITLE = re.compile(rf"^{_LOCAL}(?: to \d{{4}}-\d{{2}}-\d{{2}} \d{{2}}:\d{{2}} \S+)?$")
_ABSOLUTE_TEXT = re.compile(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}(?::\d{2})?.* UTC$")
_ISO = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}")

_TIMES = """() => [...document.querySelectorAll('[data-time]')]
  .filter((el) => el.getBoundingClientRect().width > 0)
  .map((el) => ({type: el.dataset.time, text: (el.textContent || '').trim(),
                 title: el.getAttribute('title')}))"""


def _get(base: str, path: str) -> Any:
    with urllib.request.urlopen(f"{base}{path}", timeout=15) as resp:
        return json.loads(resp.read() or b"null")


def _pages(base: str) -> dict[str, tuple[str, set[str]]]:
    """Each page with the types of time that it must show."""
    rows = _get(base, "/api/v1/hosts?limit=200")["rows"]
    jump = next(r for r in rows if r["name"] == "jump01")
    leads = _get(base, "/api/v1/leads?status=all&limit=200")
    lead = next(lead for lead in leads if lead.get("hunt_id"))
    items = _get(base, "/api/v1/needs-you/items")["items"]
    rule = next(i for i in items if i["type"] == "rule")
    return {
        "alerts": ("/alerts?range=30d", {"relative", "absolute"}),
        "hunts": ("/hunts", {"relative", "absolute"}),
        "investigations": ("/investigations", {"relative"}),
        "rule": (f"/needs-you/rule/{rule['id']}", {"absolute"}),
        "campaigns": ("/campaigns", {"absolute"}),
        "lead": (f"/leads/{lead['id']}", {"relative"}),
        "host": (f"/hosts/{quote(jump['key'], safe='')}", {"absolute"}),
    }


def _check(page: Page, name: str, wanted: set[str]) -> None:
    times = page.evaluate(_TIMES)
    shown = {t["type"] for t in times}
    assert wanted <= shown, f"{name} shows {shown}, wants {wanted}"
    for t in times:
        assert not _ISO.search(t["text"]), f"{name}: raw ISO time {t}"
        if t["text"] in ("", "—"):
            assert t["title"] is None, f"{name}: no time with a tooltip {t}"
            continue
        if t["type"] == "relative":
            assert t["title"] and _RELATIVE_TITLE.match(t["title"]), f"{name}: {t}"
        else:
            assert _ABSOLUTE_TEXT.search(t["text"]), f"{name}: {t}"
            assert t["title"] and _ABSOLUTE_TITLE.match(t["title"]), f"{name}: {t}"
    # A hover on one time of each type: the tooltip is the title of the
    # element under the pointer.
    for kind in sorted(shown):
        one = page.locator(f'[data-time="{kind}"]').filter(has_text=re.compile(r"\d")).first
        one.scroll_into_view_if_needed()
        one.hover()
        title = one.get_attribute("title") or ""
        pattern = _RELATIVE_TITLE if kind == "relative" else _ABSOLUTE_TITLE
        assert pattern.match(title), f"{name}: hover on a {kind} time read {title!r}"


def test_each_page_states_its_times_in_one_form(page: Page, demo_mode_stack: dict) -> None:
    base = demo_mode_stack["base_url"]
    page.set_viewport_size({"width": 1440, "height": 1000})
    for name, (path, wanted) in _pages(base).items():
        page.goto(f"{base}/app{path}", wait_until="networkidle")
        first = "relative" if "relative" in wanted else "absolute"
        expect(page.locator(f'[data-time="{first}"]').first).to_be_visible(timeout=_WAIT_MS)
        if name == "alerts":
            # The event rows of a group state absolute times. Open the first group.
            page.get_by_test_id("alert-last-seen").first.click()
            expect(page.get_by_test_id("event-time").first).to_be_visible(timeout=_WAIT_MS)
        _check(page, name, wanted)

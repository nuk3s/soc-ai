"""The same-flow popover at 1280x800 (dogfood 2026-10-19, V3-N7).

The popover of 16 siblings was 1149 px tall on a 800 px screen. It had no
maximum height and no inner scroll, and the note sat below the screen. The
demo grid holds no shared flow, so the test adds 16 siblings to the first
row of the real list response. The browser then lays the popover out.

Runs only under ``-m browser``. See ``conftest.py`` for the stack fixture.
"""

from __future__ import annotations

import re

import pytest
from playwright.sync_api import Page, Route, expect

pytestmark = pytest.mark.browser

_WAIT_MS = 15000
_VIEW = {"width": 1280, "height": 800}

_SIBLINGS = [
    {
        "name": f"ET TEST sibling rule {i:02d} with a long name that wraps",
        "kind": "suricata",
        "verdict": "untriaged",
        "conf": None,
        "invId": None,
        "signals": ["hosts"],
    }
    for i in range(16)
]


def _with_siblings(route: Route) -> None:
    """The real list response, with 16 siblings on its first row."""
    response = route.fetch()
    body = response.json()
    groups = body.get("groups") or []
    if groups:
        groups[0]["siblings"] = _SIBLINGS
        groups[0]["siblingCount"] = len(_SIBLINGS)
        groups[0]["siblingsPartial"] = False
    route.fulfill(response=response, json=body)


def test_the_popover_of_sixteen_siblings_fits_the_screen(page: Page, demo_stack: dict) -> None:
    base: str = demo_stack["base_url"]
    manifest: dict = demo_stack["manifest"]
    page.set_viewport_size(_VIEW)
    page.goto(f"{base}/app/login", wait_until="networkidle")
    page.fill("#username", manifest["admin_user"])
    page.fill("#password", manifest["admin_password"])
    page.click('button:has-text("Sign in")')
    page.wait_for_url(re.compile(r"/app/(dashboard|alerts)"), timeout=20000)

    page.route(re.compile(r".*/api/v1/alerts\?.*"), _with_siblings)
    page.goto(f"{base}/app/alerts", wait_until="networkidle")
    chip = page.get_by_test_id("same-flow-chip").first
    expect(chip).to_be_visible(timeout=_WAIT_MS)
    chip.click()

    popover = page.get_by_test_id("same-flow-popover")
    expect(popover).to_be_visible(timeout=_WAIT_MS)
    box = popover.bounding_box()
    assert box is not None
    # The cap is min(440px, 60vh): 440 px on this screen.
    assert box["height"] <= 441, box
    # The list scrolls inside the popover.
    listing = page.get_by_test_id("same-flow-list")
    assert listing.evaluate("el => el.scrollHeight > el.clientHeight + 10")
    # The note sits inside the popover box, below the list.
    note = page.get_by_test_id("same-flow-note")
    note_box = note.bounding_box()
    assert note_box is not None
    assert note_box["y"] >= box["y"]
    assert note_box["y"] + note_box["height"] <= box["y"] + box["height"] + 1
    expect(note).to_contain_text("within 1 hour of the other")

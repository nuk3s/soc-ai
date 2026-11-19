"""The public demo shows a rule with open false positives and its page (round 3).

The checks run against the real demo stack (``demo_mode_stack``). The demo
story holds the rule "ET POLICY Dropbox.com Offsite File Backup in Use" with
three open false positives: two confident and one with weak evidence. The
beacon rule holds an open false positive beside a true positive, and the
rule of the IP lookups holds a standing decision in force.

The test opens Needs you, opens the page of the rule from its row, and reads
the count, the chart and the buttons. It presses no button that writes. Runs
only under ``-m browser``.
"""

from __future__ import annotations

import json
import re
import urllib.request
from typing import Any

import pytest
from playwright.sync_api import Page, expect

_WAIT_MS = 15000

pytestmark = pytest.mark.browser

DROPBOX = "ET POLICY Dropbox.com Offsite File Backup in Use"
BEACON = "ET HUNTING Periodic Outbound HTTPS Connection Possible Beacon"


def _get(base: str, path: str) -> Any:
    with urllib.request.urlopen(f"{base}{path}", timeout=15) as resp:
        return json.loads(resp.read() or b"null")


def _open(page: Page, base: str, path: str) -> None:
    page.goto(f"{base}/app{path}", wait_until="networkidle")


def _rule(items: dict[str, Any], title: str) -> dict[str, Any]:
    (found,) = [i for i in items["items"] if i["type"] == "rule" and i["title"] == title]
    return found


def test_needs_you_opens_the_page_of_a_rule_with_its_facts(
    page: Page, demo_mode_stack: dict
) -> None:
    base = demo_mode_stack["base_url"]
    count = _get(base, "/api/v1/needs-you")
    items = _get(base, "/api/v1/needs-you/items")
    assert count["rules_waiting"] >= 2, count
    assert count["decisions"] == items["total"], (count, items["total"])
    dropbox = _rule(items, DROPBOX)
    assert (dropbox["count"], dropbox["confident"], dropbox["weak"]) == (3, 2, 1)
    facts = _get(base, f"/api/v1/rule-decisions/{dropbox['id']}")
    assert facts["confident"]["count"] == 2 and facts["weak"]["count"] == 1
    # The demo stack leaves automatic acknowledge off, so the rule takes no
    # standing decision and the page states why.
    assert facts["canStanding"] is False
    assert "Automatic acknowledge is off" in facts["canStandingWhy"]
    days = sum(d["confident"] + d["weak"] for d in facts["histogram"])
    assert days == 3

    _open(page, base, "/needs-you")
    row = page.get_by_test_id("needs-you-item").filter(has_text=DROPBOX)
    expect(row).to_have_count(1, timeout=_WAIT_MS)
    expect(page.get_by_test_id("needs-you-standing")).to_be_attached(timeout=_WAIT_MS)
    row.get_by_test_id("needs-you-item-title").click()

    expect(page).to_have_url(re.compile(rf"/needs-you/rule/{dropbox['id']}$"), timeout=_WAIT_MS)
    expect(page.get_by_test_id("rule-name")).to_have_text(DROPBOX, timeout=_WAIT_MS)
    expect(page.get_by_test_id("rule-group-confident-count")).to_have_text("2")
    expect(page.get_by_test_id("rule-group-weak-count")).to_have_text("1")
    expect(page.get_by_test_id("rule-day-bars")).to_be_visible()
    expect(page.get_by_test_id("rule-day")).to_have_count(len(facts["histogram"]))
    button = page.get_by_test_id("rule-acknowledge")
    expect(button).to_have_text(
        re.compile(r"Acknowledge the 2 false positives with checked evidence")
    )
    expect(page.get_by_test_id("rule-include-weak")).to_be_attached()
    expect(page.get_by_test_id("rule-standing-refused")).to_contain_text(
        "Automatic acknowledge is off"
    )
    expect(page.get_by_test_id("rule-standing-choice")).to_have_count(0)


def test_a_rule_with_a_true_positive_states_it_and_takes_no_standing_decision(
    page: Page, demo_mode_stack: dict
) -> None:
    base = demo_mode_stack["base_url"]
    beacon = _rule(_get(base, "/api/v1/needs-you/items"), BEACON)
    facts = _get(base, f"/api/v1/rule-decisions/{beacon['id']}")
    assert facts["truePositives"], facts
    assert facts["canStanding"] is False and facts["canStandingWhy"]

    _open(page, base, f"/needs-you/rule/{beacon['id']}")
    expect(page.get_by_test_id("rule-true-positive")).to_have_count(
        len(facts["truePositives"]), timeout=_WAIT_MS
    )
    expect(page.get_by_test_id("rule-standing-refused")).to_be_visible()
    expect(page.get_by_test_id("rule-standing-choice")).to_have_count(0)


def test_the_demo_lists_its_standing_decision(demo_mode_stack: dict) -> None:
    base = demo_mode_stack["base_url"]
    listing = _get(base, "/api/v1/rule-decisions")
    (entry,) = listing["standing"]
    assert entry["decision"] == "standing" and entry["acknowledged"] == 4
    assert entry["endsAt"] and entry["endedAt"] is None

"""End-to-end browser smoke against the seeded demo stack.

Drives the real SPA (login → alerts → investigation permalink → hunt → config)
and asserts the walkthrough checklist last night's manual pass validated, plus
ZERO console errors across the whole run. The mock gateway means no real model
is called — the run is deterministic.

Runs only under ``-m browser`` (see the ``browser`` marker); the default
coverage-gated ``pytest`` run ignores ``tests/browser`` entirely (pyproject
``addopts`` carries ``--ignore=tests/browser``), and its own CI job installs
chromium + builds the SPA. See ``conftest.py`` for the stack fixture.
"""

from __future__ import annotations

import re

import pytest
from playwright.sync_api import Page, expect

# Playwright's per-action / assertion timeout. Each wait is bounded so a broken
# selector fails the smoke fast instead of hanging the job.
_WAIT_MS = 15000

# The seeded hunt has only observation + a visibility-gap finding (no `threat`),
# so its disposition renders "No threat observed — visibility gaps". Accept any
# of the honest disposition labels so a data tweak doesn't spuriously break the
# smoke — the point is that A disposition rendered, not which one.
_DISPOSITION_RE = re.compile(
    r"No threat observed|No malicious activity found|Malicious activity found"
    r"|Suspicious activity found|Low-severity findings",
    re.IGNORECASE,
)


@pytest.mark.browser
def test_walkthrough_smoke(page: Page, demo_stack: dict) -> None:
    base: str = demo_stack["base_url"]
    manifest: dict = demo_stack["manifest"]

    # Collect console errors across the ENTIRE run. A single genuine error fails
    # the smoke — the manual walkthrough it replaces caught real regressions by
    # watching this. No allowlist: prefer zero.
    console_errors: list[str] = []
    page.on(
        "console",
        lambda msg: console_errors.append(msg.text) if msg.type == "error" else None,
    )
    page.on("pageerror", lambda exc: console_errors.append(f"pageerror: {exc}"))

    # ---- login -------------------------------------------------------------
    page.goto(f"{base}/app/login", wait_until="networkidle")
    page.fill("#username", manifest["admin_user"])
    page.fill("#password", manifest["admin_password"])
    page.click('button:has-text("Sign in")')
    page.wait_for_url(re.compile(r"/app/(dashboard|alerts)"), timeout=20000)

    # ---- alerts: a detection row appears; expand the first group -----------
    page.goto(f"{base}/app/alerts", wait_until="networkidle")
    emotet_row = page.get_by_text("ET MALWARE Win32/Emotet CnC Activity (POST)", exact=False).first
    expect(emotet_row).to_be_visible(timeout=_WAIT_MS)
    emotet_row.click()
    # Expanded per-event rows carry an "alert time" column header/label.
    page.wait_for_timeout(1200)

    # ---- investigation permalink: the "alert time" row I recently added ----
    page.goto(f"{base}/app/investigation/{manifest['inv_emotet']}", wait_until="networkidle")
    expect(page.get_by_text("alert time", exact=False).first).to_be_visible(timeout=_WAIT_MS)

    # ---- hunt: disposition text + a "Visual summary" section ----------------
    page.goto(f"{base}/app/hunts/{manifest['hunt']}", wait_until="networkidle")
    expect(page.get_by_text(_DISPOSITION_RE).first).to_be_visible(timeout=_WAIT_MS)
    expect(page.get_by_text("Visual summary", exact=False).first).to_be_visible(timeout=_WAIT_MS)

    # ---- failed hunt: the prominent "Re-hunt" affordance (accent on a failed
    # run) — the seed's status="error" hunt exercises the HuntDetail failed→
    # re-hunt path. Assert the control exists; don't couple to its styling.
    page.goto(f"{base}/app/hunts/{manifest['hunt_error']}", wait_until="networkidle")
    expect(page.get_by_role("button", name="Re-hunt").first).to_be_visible(timeout=_WAIT_MS)

    # ---- config (master-detail): the default pane, nav switching, search ----
    page.goto(f"{base}/app/config", wait_until="networkidle")
    # Default pane is the first section (Agent) — its analyst-model row is the
    # only one carrying a "Check fitness" button.
    expect(page.get_by_role("button", name="Check fitness").first).to_be_visible(timeout=_WAIT_MS)
    # The master nav switches the pane: click a standalone section and assert
    # its collapsible chevron ("Expand/Collapse section" aria-label) — the same
    # chevron regression the old single-scroll assertion pinned, now behind a
    # real nav switch.
    page.locator("aside").get_by_text("Diagnostics", exact=True).first.click()
    chevrons = page.locator('button[aria-label$="section"]')
    expect(chevrons.first).to_be_visible(timeout=_WAIT_MS)
    # Settings search spans sections: a concept query surfaces a hit, and
    # clicking it lands on the owning section with the exact row flashed.
    page.get_by_placeholder("Search settings").first.fill("inherit")
    hit = page.locator('[data-testid^="search-result-"]').first
    expect(hit).to_be_visible(timeout=_WAIT_MS)
    hit.click()
    expect(page.locator('[data-highlighted="true"]').first).to_be_visible(timeout=_WAIT_MS)

    # ---- final: ZERO console errors across the whole run --------------------
    assert not console_errors, "console errors during smoke:\n" + "\n".join(console_errors)

"""First-run honesty: a stack with dead upstreams must SAY so, not present as broken.

Wave-2 acceptance scenario (docs/superpowers/specs/2026-08-18-fresh-view-refit-
design.md): "boot unconfigured, confirm the UI says unconfigured and lists what
is missing rather than presenting as broken." This drives the Dashboard's
persistent setup-health card (Task 4) against the preflight API (Task 3) and
asserts it renders a named degraded state instead of crashing or claiming green.

Uses the ``demo_stack`` fixture, NOT ``demo_mode_stack``: full demo mode
(``SOC_AI_DEMO=true``) short-circuits ``GET /health/preflight`` straight to
green by design (the demo egress guard would otherwise fail every check
unconditionally and misreport a *product* carve-out as a real outage — see
``soc_ai.api.webui.routes_meta._cached_preflight``), which would make the
degraded assertion below unreachable. ``demo_stack`` boots the real, non-demo
app with a fake ``SO_HOST`` (``securityonion.demo.example.com``, an RFC 2606
reserved domain — DNS resolution fails inside the container) and mock ES/LLM
on loopback, so the doctor's upstream-reachability check genuinely FAILs
(``soc_ai.doctor.check_upstream_reachability``) and the preflight summary is
genuinely "degraded", not merely stubbed that way.

Auth: ``demo_stack`` never overrides ``API_AUTH_REQUIRED`` (defaults True —
``soc_ai/config.py``), so the Dashboard is unreachable without a session; the
test logs in as the seeded admin user first (mirrors ``test_smoke.py``). That
also means the admin (per-row) branch of the card is the one exercised here —
the analyst (counts-only) branch is covered by
``frontend/src/screens/Dashboard.setupHealth.test.tsx``.
"""

from __future__ import annotations

import re

import pytest
from playwright.sync_api import Page, expect

pytestmark = pytest.mark.browser

# Playwright's per-action / assertion timeout. The preflight summary's first
# (cold-cache) read runs the doctor gather for real — bounded at ~15s
# (soc_ai.doctor._REACH_TIMEOUT_S) — so the degraded copy can legitimately
# take that long to land after the page itself has settled.
_WAIT_MS = 15000


def test_dashboard_setup_health_card_degrades_honestly(page: Page, demo_stack: dict) -> None:
    base: str = demo_stack["base_url"]
    manifest: dict = demo_stack["manifest"]

    # ---- log in: auth is required in this stack ----------------------------
    page.goto(f"{base}/app/login", wait_until="networkidle")
    page.fill("#username", manifest["admin_user"])
    page.fill("#password", manifest["admin_password"])
    page.click('button:has-text("Sign in")')
    page.wait_for_url(re.compile(r"/app/(dashboard|alerts)"), timeout=20000)

    # ---- land on the Dashboard explicitly (login may redirect to /app/alerts) --
    page.goto(f"{base}/app/dashboard", wait_until="networkidle")

    # The setup-health card is PERSISTENT (renders in every state, unlike every
    # other right-rail panel) and first in the rail — it must be present.
    setup_health = page.locator("div.rounded-panel").filter(has_text="Setup health")
    expect(setup_health.first).to_be_visible(timeout=_WAIT_MS)

    # Against a fake SO host + loopback-only ES/LLM mocks, the preflight is
    # degraded, never green — and it must be NAMED as such, not hidden behind
    # a crash. Both the admin and analyst copy in SetupHealthCard carry the
    # word "failing" (frontend/src/screens/Dashboard.tsx); the assertion is
    # scoped to the card so an unrelated "failing" elsewhere on the page can't
    # produce a false pass.
    expect(setup_health.get_by_text("failing", exact=False).first).to_be_visible(timeout=_WAIT_MS)

    # ---- and the screen itself did not crash to an error boundary: another,
    # unrelated Dashboard panel rendered alongside the degraded card ----------
    expect(page.get_by_text("Recent investigations", exact=False).first).to_be_visible(
        timeout=_WAIT_MS
    )

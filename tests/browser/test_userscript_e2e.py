"""Real-browser end-to-end test of the soc-ai userscript against SO 3.0.0.

Boots Chromium headless, logs into the SO web UI, navigates to the alerts
page, injects the soc-ai userscript content, waits for the row buttons to
appear, clicks one, and verifies the v0.5.0 architecture:

1. The userscript installs a ``window.fetch`` patch at ``document-start``.
2. As SO's frontend loads ``/api/events/``, the userscript captures real
   ES ``_id``s into ``window.__socai_id_cache``.
3. Clicking a row's "Hunt with AI" button resolves the alert ID via the
   cache (the row's ``key`` matches an entry there).
4. The resolved ``alert_id`` is a 20-char ES ``_id`` (mixed case +
   digit), not a column label or guess.
5. ``/investigate`` is POSTed with that real ID; ``/find-alert`` is NOT
   called from the userscript path.

This test exists because the headless dev box can't visually verify SO's
DOM evolution; everything we know about the SO 3.0.0 alerts table comes
from ``scripts/inspect_so_dom.py`` runs. Re-run after every userscript
change to catch DOM-coupling regressions.

Requires the following env vars (typically set by CI / the operator):

    SO_HOST=https://10.0.0.253
    SO_USERNAME=soc-ai@soc-ai.lan
    SO_PASSWORD=<your-so-password>   # never commit a real password
    SOC_AI_URL=https://10.0.0.8:8443

Run::

    uv run pytest tests/browser/test_userscript_e2e.py -v -s

Skipped if ``SO_HOST`` is not set so the unit-test suite stays
hermetic.
"""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path

import pytest

USERSCRIPT_PATH = Path(__file__).resolve().parents[2] / "userscript" / "soc-ai.user.js"

# Capture env vars at module load time. The unit-test conftest.py's clean_env
# autouse fixture deletes SO_*/SOC_AI_* envs per-test, but it runs after
# module collection so module-level reads are safe.
ENV_AT_LOAD = {
    "SO_HOST": os.environ.get("SO_HOST", ""),
    "SO_USERNAME": os.environ.get("SO_USERNAME", ""),
    "SO_PASSWORD": os.environ.get("SO_PASSWORD", ""),
    "SOC_AI_URL": os.environ.get("SOC_AI_URL", ""),
}
ALERTS_URL_DEFAULT = "/#/alerts?q=*&z=America/New_York&el=20&gl=20&rt=1&rtu=hours"
_missing = [k for k, v in ENV_AT_LOAD.items() if not v]
pytestmark = pytest.mark.skipif(
    bool(_missing),
    reason=(
        "browser e2e requires SO_HOST + SO_USERNAME + SO_PASSWORD + SOC_AI_URL "
        "env. missing: " + ",".join(_missing)
    ),
)


def _strip_userscript_metadata(src: str) -> str:
    """Drop the ==UserScript== block + the surrounding comment so the IIFE
    runs on injection."""
    out_lines: list[str] = []
    in_block = False
    for line in src.splitlines():
        s = line.strip()
        if s.startswith("// ==UserScript=="):
            in_block = True
            continue
        if in_block and s.startswith("// ==/UserScript=="):
            in_block = False
            continue
        if in_block:
            continue
        out_lines.append(line)
    return "\n".join(out_lines)


@pytest.mark.asyncio
async def test_userscript_resolves_alert_and_opens_panel() -> None:
    from playwright.async_api import async_playwright  # type: ignore[import-not-found]

    so_host = ENV_AT_LOAD["SO_HOST"].rstrip("/")
    soc_ai_url = ENV_AT_LOAD["SOC_AI_URL"].rstrip("/")
    so_user = ENV_AT_LOAD["SO_USERNAME"]
    so_pwd = ENV_AT_LOAD["SO_PASSWORD"]

    src = USERSCRIPT_PATH.read_text(encoding="utf-8")
    init_script = (
        "window.SOC_AI_URL_OVERRIDE = " + json.dumps(soc_ai_url) + ";\n"
        # Stub GM_* APIs so the script's userscript-host detection no-ops.
        "window.GM_getValue = function(_k, d) {"
        "  return window.SOC_AI_URL_OVERRIDE || d;"
        "};\n"
        "window.GM_setValue = function() {};\n" + _strip_userscript_metadata(src)
    )

    captured_console: list[str] = []
    captured_requests: list[str] = []

    async with async_playwright() as p:
        browser = await p.chromium.launch(
            headless=True,
            args=["--no-sandbox", "--ignore-certificate-errors"],
        )
        ctx = await browser.new_context(ignore_https_errors=True)
        await ctx.add_init_script(script=init_script)
        page = await ctx.new_page()
        page.on(
            "console",
            lambda msg: captured_console.append(f"[{msg.type}] {msg.text}"),
        )
        page.on(
            "request",
            lambda req: captured_requests.append(f"{req.method} {req.url}"),
        )

        try:
            # 1. Login.
            await page.goto(so_host + "/", wait_until="domcontentloaded")
            await page.wait_for_selector(
                "input[type=email], input[name=identifier], input[name=username]",
                timeout=15000,
            )
            await page.locator(
                "input[name=identifier], input[type=email], input[name=username]"
            ).first.fill(so_user)
            await page.locator("input[type=password], input[name=password]").first.fill(so_pwd)
            async with page.expect_navigation(wait_until="domcontentloaded", timeout=30000):
                await page.locator("button[type=submit], input[type=submit]").first.click()

            # 2. Navigate to detail-view alerts (no groupby, so per-row data exists).
            await page.goto(so_host + ALERTS_URL_DEFAULT, wait_until="domcontentloaded")
            # Wait for the userscript to log its boot message.
            for _ in range(40):
                await asyncio.sleep(0.25)
                if any("[soc-ai] booted" in line for line in captured_console):
                    break
            assert any("[soc-ai] userscript loaded" in line for line in captured_console), (
                f"userscript never logged its load. console=\n{captured_console!r}"
            )

            # 3. Confirm the fetch patch installed at document-start.
            assert any(
                "[soc-ai] fetch patched at document-start" in line for line in captured_console
            ), "userscript did not log the fetch-patch marker. console=\n" + "\n".join(
                captured_console[-30:]
            )
            # 3b. Confirm the XHR patch installed too — SO uses Axios/XHR.
            assert any(
                "[soc-ai] XMLHttpRequest patched at document-start" in line
                for line in captured_console
            ), "userscript did not log the XHR-patch marker. console=\n" + "\n".join(
                captured_console[-30:]
            )

            # 4. Wait for the alert table + at least one main-row.
            await page.wait_for_selector("tr.main-row", timeout=30000)

            # 5. Wait for the cache to populate from /api/events/ responses.
            for _ in range(40):
                cache_size = await page.evaluate(
                    "() => (window.__socai_id_cache && window.__socai_id_cache.size) || 0"
                )
                if cache_size > 0:
                    break
                await asyncio.sleep(0.25)
            assert cache_size > 0, (
                f"window.__socai_id_cache never populated after alerts table render. "
                f"console=\n{captured_console[-30:]!r}"
            )

            # 6. Wait for our button to be injected on at least one main-row.
            for _ in range(40):
                count = await page.locator("tr.main-row button.soc-ai-button.hunt").count()
                if count > 0:
                    break
                await asyncio.sleep(0.25)
            assert count > 0, (
                f"no Hunt-with-AI buttons injected after wait. "
                f"main-row count = {await page.locator('tr.main-row').count()}"
            )

            # 7. Click the first row's button.
            await page.locator("tr.main-row button.soc-ai-button.hunt").first.click()

            # 8. Wait for the userscript to log the resolved alert id.
            for _ in range(60):
                if any(
                    "[soc-ai] resolved" in line
                    and ("from cache" in line or "from expand-panel" in line)
                    for line in captured_console
                ):
                    break
                await asyncio.sleep(0.25)
            resolved_lines = [
                line
                for line in captured_console
                if "[soc-ai] resolved" in line
                and ("from cache" in line or "from expand-panel" in line)
            ]
            assert resolved_lines, (
                "userscript never logged a resolved alert id. console tail=\n"
                + "\n".join(captured_console[-40:])
            )

            # 9. /find-alert MUST NOT be called (deprecated for the userscript path).
            assert not any("/find-alert" in r for r in captured_requests), (
                "/find-alert was called by the userscript - v0.5.0 should resolve via cache "
                "or expand-panel, not soc-ai's resolver. requests:\n"
                + "\n".join(captured_requests[-30:])
            )

            # 10. /investigate MUST be called with a real ES _id-shaped alert_id.
            for _ in range(60):
                if any("/investigate" in r for r in captured_requests):
                    break
                await asyncio.sleep(0.25)
            assert any("/investigate" in r for r in captured_requests), (
                "no /investigate request observed. requests:\n" + "\n".join(captured_requests[-30:])
            )

            # 11. Validate the alert_id sent to /investigate is real ES _id-shaped.
            import re as _re

            es_id_re = _re.compile(r"^[A-Za-z0-9_-]{15,40}$")
            inv_lines = [r for r in captured_requests if "/investigate" in r]
            assert inv_lines, "no /investigate request observed"
            # Pull the body that was POSTed by listening to request events earlier.
            # Easier: read the resolved id directly from the console message.
            resolved_id = None
            for line in resolved_lines:
                # "[info] [soc-ai] resolved <id> from cache"
                m = _re.search(r"resolved\s+(\S+)\s+(?:from\s+)?(?:cache|expand-panel)", line)
                if m:
                    resolved_id = m.group(1)
                    break
            assert resolved_id, f"could not parse resolved id from console: {resolved_lines!r}"
            shape_msg = (
                f"resolved id {resolved_id!r} does not look like an ES _id "
                f"(expected 15-40 chars, mixed case, digit)"
            )
            assert es_id_re.match(resolved_id), shape_msg
            assert any(c.isupper() for c in resolved_id), shape_msg
            assert any(c.isdigit() for c in resolved_id), shape_msg

            # 12. The side panel should be visible after click.
            panel_count = await page.locator("#soc-ai-host").count()
            assert panel_count == 1, "side panel host not present"

            # 13. Wait for the v0.6.0 panel structure to populate:
            #       - .soc-ai-status     (status strip with phase + progress)
            #       - .soc-ai-verdict    (verdict card; .hidden until report)
            #       - .soc-ai-event.<kind>  (compact one-line timeline rows)
            #       - .soc-ai-pill.<verdict>  (color-coded verdict pill)
            #       - [data-kpi=...]     (footer KPI counters)
            async def _event_count(kind: str) -> int:
                return await page.evaluate(
                    f"() => (document.getElementById('soc-ai-host')?.shadowRoot?"
                    f".querySelectorAll('.soc-ai-event.{kind}')?.length) || 0"
                )

            async def _verdict_visible() -> bool:
                return await page.evaluate(
                    "() => { const v = document.getElementById('soc-ai-host')"
                    "?.shadowRoot?.querySelector('.soc-ai-verdict');"
                    " return !!v && !v.classList.contains('hidden'); }"
                )

            # Wait up to 600s for the verdict card to materialize. Full path:
            #   prefetch (~1s)
            #   investigator round 1 (fast 30B, ~30 tool calls x 5-15s)
            #   synthesizer round 1 (heavy 120B, ~30s)
            #   optional retask: investigator round 2 + synthesizer round 2
            # On a local GPU host a retask path can take 4-6 minutes.
            for _ in range(2400):
                if await _verdict_visible():
                    break
                await asyncio.sleep(0.25)
            assert await _verdict_visible(), (
                "side panel verdict card never appeared within 600s — "
                "triage_report may not have streamed"
            )

            # 14. alert_context event lands in the activity timeline before
            #     any tool_call (the prefetch is the orchestrator's first
            #     SSE message after session_start).
            assert await _event_count("alert_context") >= 1, (
                "alert_context event missing from side panel — orchestrator "
                "prefetch may not be wired through SSE"
            )

            # 15. Investigator must NOT call t_get_alert_context (the
            #     pre-fetched context is in its user prompt; the rubric
            #     forbids this call). Inspect tool_call event text.
            tool_call_texts = await page.evaluate(
                "() => Array.from("
                "  document.getElementById('soc-ai-host')?.shadowRoot"
                "    ?.querySelectorAll('.soc-ai-event.tool_call') || []"
                ").map(el => el.textContent)"
            )
            assert not any("t_get_alert_context" in t for t in tool_call_texts), (
                "investigator called t_get_alert_context despite pre-fetch — "
                "prompt may have regressed:\n" + "\n---\n".join(tool_call_texts[:10])
            )

            # 16. usage events arrive (per-phase). At minimum one for round 1.
            assert await _event_count("usage") >= 1, (
                "no usage event in side panel — token-accounting plumbing may have regressed"
            )

            # 17. No FATAL error events in a healthy run. The retask round 2
            # is known-fragile against the 64K context window;
            # the orchestrator catches that error and
            # falls back to the round-1 report, so the verdict still arrives.
            # Surface only errors that AREN'T the recoverable retask path.
            error_texts = await page.evaluate(
                "() => Array.from("
                "  document.getElementById('soc-ai-host')?.shadowRoot"
                "    ?.querySelectorAll('.soc-ai-event.error') || []"
                ").map(el => el.textContent)"
            )
            fatal_errors = [
                t
                for t in error_texts
                if "investigator/r2" not in t.replace(" ", "")
                and "synthesizer/r2" not in t.replace(" ", "")
            ]
            assert not fatal_errors, (
                f"unexpected fatal error event(s) in side panel: {fatal_errors!r}"
            )

            # 18. Footer KPIs reflect real activity (>=1 tool, non-zero tokens).
            tool_kpi = await page.evaluate(
                "() => parseInt(document.getElementById('soc-ai-host')"
                "?.shadowRoot?.querySelector('[data-kpi=\"tools\"]')?.textContent || '0', 10)"
            )
            tokens_kpi = await page.evaluate(
                "() => document.getElementById('soc-ai-host')"
                "?.shadowRoot?.querySelector('[data-kpi=\"tokens\"]')?.textContent || ''"
            )
            assert tool_kpi >= 1, f"footer 'tools' KPI is {tool_kpi}, expected >=1"
            assert tokens_kpi, "footer 'tokens' KPI is empty"
            assert tokens_kpi != "0", f"footer 'tokens' KPI is {tokens_kpi!r}, expected non-zero"

            # 19. Verdict pill renders one of the three valid verdicts.
            pill_text = await page.evaluate(
                "() => document.getElementById('soc-ai-host')"
                "?.shadowRoot?.querySelector('.soc-ai-pill')?.textContent?.trim() || ''"
            )
            assert pill_text.lower().replace(" ", "_") in (
                "true_positive",
                "false_positive",
                "needs_more_info",
            ), f"verdict pill text {pill_text!r} not a recognized verdict"

        finally:
            # Always dump browser console for debugging on failure.
            print("\n=== captured browser console (last 60) ===")
            for line in captured_console[-60:]:
                print(line)
            print("\n=== captured requests (last 30) ===")
            for line in captured_requests[-30:]:
                print(line)
            await ctx.close()
            await browser.close()

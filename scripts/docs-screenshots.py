#!/usr/bin/env python3
"""Capture docs/img/screenshot-*.png from a local, synthetic demo instance.

Boots the same stack ``tests/browser/conftest.py``'s ``demo_stack`` fixture
does — ``seed_demo.py`` (fresh SQLite, TEST-NET-only data) + ``mock_es.py``
(local ES/LLM mock) + the real app under ``uvicorn``, launched with a scrubbed
env and cwd'd OUTSIDE the repo so a developer ``.env`` can never leak in — then
drives the built SPA with sync Playwright and writes each named shot.

Requires ``frontend/dist`` to exist (``cd frontend && npm ci && npm run
build``) so the app has something to serve at ``/app``, and the Playwright
Python package + a chromium browser installed (``uv run playwright install
chromium`` if the cache is empty).

Usage:
    uv run python scripts/docs-screenshots.py
    uv run python scripts/docs-screenshots.py --out docs/img --viewport 1440x900 --scale 2
    uv run python scripts/docs-screenshots.py --only alerts,operate   # iterate on a subset
    uv run python scripts/docs-screenshots.py --headed --keep         # watch it / poke around after

    # Point at a stack you already booted (skips seed+boot — fast iteration):
    uv run python scripts/docs-screenshots.py --base http://127.0.0.1:8921 \\
        --manifest /tmp/soc-ai-docshots-XXXX/manifest.json --only dashboard

NEVER point ``--base`` at anything but a stack this script (or the fixture it
mirrors) itself booted — the whole point of the seed-locally pipeline is that
no real alert, IP, or hostname can ever land in a shipped screenshot.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import signal
import subprocess
import sys
import time
import urllib.error
import urllib.request
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from playwright.sync_api import Page

REPO = Path(__file__).resolve().parents[1]
# The repo's own interpreter (uv-managed venv) — same fallback conftest.py uses
# so this also works when invoked with a bare `python3` outside `uv run`.
_VENV_PY = REPO / ".venv" / "bin" / "python"
PY = str(_VENV_PY) if _VENV_PY.exists() else sys.executable

# Distinct from the browser-test harness (ES 19402 / app 8913) and the older
# scripts/demo/run_demo_capture.sh (ES 19200 / app 8901), so this script can
# run alongside either without a port collision.
DEFAULT_ES_PORT = 19420
DEFAULT_APP_PORT = 8921

_HEALTH_TIMEOUT_S = 45.0  # bounded startup wait (seed + migrations + uvicorn boot)
_SETTLE_MS = 700  # let count-up / fade-in animations finish before the shot

# ---------------------------------------------------------------------------
# stack boot — mirrors tests/browser/conftest.py's demo_stack fixture exactly
# ---------------------------------------------------------------------------


def _healthy(url: str) -> bool:
    try:
        with urllib.request.urlopen(url, timeout=2) as resp:
            return resp.status == 200
    except (urllib.error.URLError, TimeoutError, ConnectionError, OSError):
        return False


def _terminate(proc: subprocess.Popen[bytes] | None) -> None:
    """Best-effort clean shutdown: SIGTERM the whole process group, then wait."""
    if proc is None or proc.poll() is not None:
        return
    try:
        os.killpg(proc.pid, signal.SIGTERM)
    except (ProcessLookupError, PermissionError):
        proc.terminate()
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            proc.kill()
        proc.wait(timeout=5)


@contextmanager
def demo_stack(es_port: int, app_port: int) -> Iterator[dict]:
    """Boot seed_demo.py + mock_es.py + uvicorn; yield ``{base_url, manifest}``.

    Tears both long-lived processes down on exit, even if a shot fails.
    """
    if _healthy(f"http://127.0.0.1:{app_port}/healthz"):
        raise RuntimeError(
            f"something is already serving :{app_port} — kill the stale demo app first "
            "(pkill -f 'uvicorn soc_ai.main') or pass a different --app-port"
        )

    with TemporaryDirectory(prefix="soc-ai-docshots-") as workdir:
        work = Path(workdir)
        data = work / "data"

        print("== seeding demo store ==")
        subprocess.run(
            [PY, str(REPO / "scripts" / "demo" / "seed_demo.py"), "--data-dir", str(data)],
            check=True,
            cwd=str(REPO),
            capture_output=True,
        )
        manifest_path = data.parent / "manifest.json"  # seed writes <data>/../manifest.json
        manifest = json.loads(manifest_path.read_text())

        mock_proc: subprocess.Popen[bytes] | None = None
        app_proc: subprocess.Popen[bytes] | None = None
        app_log = work / "app.log"
        try:
            print(f"== starting mock ES/LLM on :{es_port} ==")
            mock_proc = subprocess.Popen(
                [PY, str(REPO / "scripts" / "demo" / "mock_es.py"), str(es_port)],
                cwd=str(REPO),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
            )

            print(f"== starting soc-ai on :{app_port} (cwd={work}, no .env reachable) ==")
            # Scrubbed environment: only the demo settings + a minimal PATH, so a
            # developer .env can NEVER leak in. Every host is a 127.0.0.1 mock or a
            # reserved example.com placeholder — nothing here can carry a real IP,
            # hostname, or credential into a screenshot.
            mock_base = f"http://127.0.0.1:{es_port}"
            env = {
                "PATH": "/usr/bin:/bin",
                "HOME": str(work),
                "SOC_AI_DATA_DIR": str(data),
                "SO_HOST": "https://securityonion.demo.example.com",
                "SO_USERNAME": "soc-ai@demo.example.com",
                "SO_PASSWORD": "demo-password-unused",
                "ES_HOSTS": mock_base,
                "LITELLM_BASE_URL": mock_base,
            }
            with app_log.open("wb") as logf:
                app_proc = subprocess.Popen(
                    [
                        PY,
                        "-m",
                        "uvicorn",
                        "soc_ai.main:app",
                        "--host",
                        "127.0.0.1",
                        "--port",
                        str(app_port),
                    ],
                    cwd=str(work),  # OUTSIDE the repo — no .env reachable
                    env=env,
                    stdout=logf,
                    stderr=subprocess.STDOUT,
                    start_new_session=True,
                )

            base_url = f"http://127.0.0.1:{app_port}"
            print("== waiting for the app to report healthy ==")
            deadline = time.monotonic() + _HEALTH_TIMEOUT_S
            while time.monotonic() < deadline:
                if _healthy(f"{base_url}/healthz"):
                    break
                if app_proc.poll() is not None:
                    log = app_log.read_text(errors="replace") if app_log.exists() else ""
                    raise RuntimeError(
                        f"app exited during startup (rc={app_proc.returncode}).\n{log}"
                    )
                time.sleep(0.5)
            else:
                log = app_log.read_text(errors="replace") if app_log.exists() else ""
                raise RuntimeError(f"app did not become healthy in {_HEALTH_TIMEOUT_S}s.\n{log}")

            yield {"base_url": base_url, "manifest": manifest}
        finally:
            _terminate(app_proc)
            _terminate(mock_proc)


# ---------------------------------------------------------------------------
# shots — each takes (page, base, manifest, out_dir), navigates, waits for a
# known element (never a spinner), settles, and writes the PNG.
# ---------------------------------------------------------------------------


def _login(page: Page, base: str, manifest: dict) -> None:
    page.goto(f"{base}/app/login", wait_until="networkidle")
    page.fill("#username", manifest["admin_user"])
    page.fill("#password", manifest["admin_password"])
    page.click('button:has-text("Sign in")')
    page.wait_for_url(re.compile(r"/app/(dashboard|alerts)"), timeout=20000)


def _settle(page: Page, ms: int = _SETTLE_MS) -> None:
    page.wait_for_timeout(ms)


def shoot_alerts(page: Page, base: str, manifest: dict, out: Path) -> None:
    """/app/alerts — grouped queue, Operate collapsed (the day-1 sidebar look)."""
    page.goto(f"{base}/app/alerts", wait_until="networkidle")
    page.get_by_text("ET MALWARE Win32/Emotet CnC Activity (POST)", exact=False).first.wait_for(
        state="visible", timeout=20000
    )
    # "Tune rule" renders statically on every group row (no hover needed) —
    # wait for it directly so the shot never lands before rows finish paint.
    page.get_by_text("Tune rule", exact=True).first.wait_for(state="visible", timeout=10000)
    _settle(page)
    page.screenshot(path=str(out / "screenshot-alerts.png"))
    print("  captured screenshot-alerts.png")


def shoot_investigation(page: Page, base: str, manifest: dict, out: Path) -> None:
    """/app/investigation/<id> — verdict, actions, timeline."""
    page.goto(f"{base}/app/investigation/{manifest['inv_emotet']}", wait_until="networkidle")
    page.get_by_text(
        re.compile(r"investigation timeline|model reasoning|verdict", re.IGNORECASE)
    ).first.wait_for(state="visible", timeout=15000)
    _settle(page, 1200)  # timeline + graph render
    page.screenshot(path=str(out / "screenshot-investigation.png"))
    print("  captured screenshot-investigation.png")


def shoot_investigations(page: Page, base: str, manifest: dict, out: Path) -> None:
    """/app/investigations — the list, verdicts + confidence."""
    page.goto(f"{base}/app/investigations", wait_until="networkidle")
    page.get_by_text("Emotet", exact=False).first.wait_for(state="visible", timeout=20000)
    _settle(page)
    page.screenshot(path=str(out / "screenshot-investigations.png"))
    print("  captured screenshot-investigations.png")


def shoot_dashboard(page: Page, base: str, manifest: dict, out: Path) -> None:
    """/app/dashboard — with the setup-health card DEGRADED.

    Against this stack's mock upstreams (a fake SO_HOST that fails DNS inside
    the container, ES/LLM only reachable on loopback) the doctor's real
    upstream-reachability probe genuinely fails, so the card shows named
    failing rows instead of a green "all checks passing" line. That is the
    HONEST, more informative state (see tests/browser/test_first_run_setup_
    health.py) — the shot captures it on purpose rather than racing to catch
    an early placeholder before the checks resolve.
    """
    page.goto(f"{base}/app/dashboard", wait_until="networkidle")
    card = page.locator("div.rounded-panel").filter(has_text="Setup health")
    card.first.wait_for(state="visible", timeout=15000)
    card.get_by_text("failing", exact=False).first.wait_for(state="visible", timeout=20000)
    _settle(page, 1500)  # KPI cards + recent lists
    page.screenshot(path=str(out / "screenshot-dashboard.png"))
    print("  captured screenshot-dashboard.png")


def shoot_hunt(page: Page, base: str, manifest: dict, out: Path) -> None:
    """/app/hunts/<id> — a completed hunt's disposition + visual summary."""
    page.goto(f"{base}/app/hunts/{manifest['hunt']}", wait_until="networkidle")
    page.get_by_text(
        re.compile(
            r"No threat observed|No malicious activity found|Malicious activity found"
            r"|Suspicious activity found|Low-severity findings",
            re.IGNORECASE,
        )
    ).first.wait_for(state="visible", timeout=15000)
    page.get_by_text("Visual summary", exact=False).first.wait_for(state="visible", timeout=10000)
    _settle(page, 1000)
    page.screenshot(path=str(out / "screenshot-hunt.png"))
    print("  captured screenshot-hunt.png")


def shoot_operate(page: Page, base: str, manifest: dict, out: Path) -> None:
    """/app/operate — the six trust-instrument cards, Operate force-expanded.

    /operate is itself one of the Sidebar "Operate" group's own routes, so the
    group force-expands automatically (Sidebar.tsx's operateForceExpanded) —
    correct behavior, nothing to click.
    """
    page.goto(f"{base}/app/operate", wait_until="networkidle")
    page.get_by_text("Model fitness", exact=True).first.wait_for(state="visible", timeout=15000)
    page.get_by_text("Runbooks", exact=True).first.wait_for(state="visible", timeout=10000)
    _settle(page)
    page.screenshot(path=str(out / "screenshot-operate.png"))
    print("  captured screenshot-operate.png")


def shoot_config_day1(page: Page, base: str, manifest: dict, out: Path) -> None:
    """/app/config#triage-automation — day-1 rows + the collapsed Advanced fold.

    Triage automation carries all four day-1 auto-triage knobs plus several
    non-day1 settings (auto-ack, inheritance, scheduled hunts, ...), so a
    fresh session (no localStorage) renders exactly the wave's thesis: the
    day-1 rows up front, everything else behind a collapsed "Advanced (N)"
    fold. Being inside the Operate group, this also force-expands that
    sidebar group — same correct behavior as the /operate shot.
    """
    page.goto(f"{base}/app/config#triage-automation", wait_until="networkidle")
    page.get_by_text("Triage automation", exact=True).first.wait_for(state="visible", timeout=15000)
    page.get_by_text("Continuous auto-investigate", exact=False).first.wait_for(
        state="visible", timeout=10000
    )
    page.get_by_text(re.compile(r"Advanced \(\d+\)")).first.wait_for(state="visible", timeout=10000)
    _settle(page)
    page.screenshot(path=str(out / "screenshot-config-day1.png"))
    print("  captured screenshot-config-day1.png")


SHOTS: dict[str, Callable[[Page, str, dict, Path], None]] = {
    "alerts": shoot_alerts,
    "investigation": shoot_investigation,
    "investigations": shoot_investigations,
    "dashboard": shoot_dashboard,
    "hunt": shoot_hunt,
    "operate": shoot_operate,
    "config-day1": shoot_config_day1,
}


# ---------------------------------------------------------------------------
# orchestration
# ---------------------------------------------------------------------------


def _parse_viewport(spec: str) -> tuple[int, int]:
    m = re.fullmatch(r"(\d+)x(\d+)", spec)
    if not m:
        raise SystemExit(f"--viewport must look like 1440x900, got {spec!r}")
    return int(m.group(1)), int(m.group(2))


def _run_shots(
    base: str,
    manifest: dict,
    names: list[str],
    out_dir: Path,
    width: int,
    height: int,
    scale: float,
    headed: bool,
) -> int:
    from playwright.sync_api import sync_playwright

    failures: list[str] = []
    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=not headed)
        try:
            ctx = browser.new_context(
                viewport={"width": width, "height": height},
                device_scale_factor=scale,
            )
            page = ctx.new_page()
            page.emulate_media(reduced_motion="reduce")
            page.on(
                "pageerror", lambda exc: print(f"  PAGE ERROR: {str(exc)[:200]}", file=sys.stderr)
            )

            _login(page, base, manifest)
            print(f"logged in as {manifest['admin_user']}")

            for name in names:
                try:
                    SHOTS[name](page, base, manifest, out_dir)
                except Exception as exc:  # report and keep shooting the rest
                    failures.append(name)
                    print(f"  FAILED {name}: {exc}", file=sys.stderr)
        finally:
            browser.close()

    if failures:
        print(f"\n{len(failures)} shot(s) failed: {', '.join(failures)}", file=sys.stderr)
        return 1
    print(f"\ndone — {len(names)} shot(s) written to {out_dir}")
    return 0


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--out", default=str(REPO / "docs" / "img"), help="output directory")
    ap.add_argument("--viewport", default="1440x900", help="WIDTHxHEIGHT CSS viewport")
    ap.add_argument(
        "--scale", type=float, default=2, help="device scale factor (2 -> 2880x1800 PNGs)"
    )
    ap.add_argument("--only", default=None, help=f"comma-separated subset of: {', '.join(SHOTS)}")
    ap.add_argument("--headed", action="store_true", help="show the browser window")
    ap.add_argument(
        "--keep",
        action="store_true",
        help="leave the booted demo stack running after the shots (Ctrl-C to stop)",
    )
    ap.add_argument(
        "--base", default=None, help="use an already-running instance instead of booting one"
    )
    ap.add_argument("--manifest", default=None, help="manifest.json path (required with --base)")
    ap.add_argument("--es-port", type=int, default=DEFAULT_ES_PORT)
    ap.add_argument("--app-port", type=int, default=DEFAULT_APP_PORT)
    return ap.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    width, height = _parse_viewport(args.viewport)
    names = args.only.split(",") if args.only else list(SHOTS)
    unknown = [n for n in names if n not in SHOTS]
    if unknown:
        print(f"unknown shot name(s): {unknown} — choices: {list(SHOTS)}", file=sys.stderr)
        return 2

    if args.base:
        if not args.manifest:
            print("--base requires --manifest <path to manifest.json>", file=sys.stderr)
            return 2
        manifest = json.loads(Path(args.manifest).read_text())
        return _run_shots(
            args.base, manifest, names, out_dir, width, height, args.scale, args.headed
        )

    with demo_stack(args.es_port, args.app_port) as stack:
        rc = _run_shots(
            stack["base_url"],
            stack["manifest"],
            names,
            out_dir,
            width,
            height,
            args.scale,
            args.headed,
        )
        if args.keep:
            print(f"--keep set: stack still running at {stack['base_url']} — Ctrl-C to stop")
            try:
                while True:
                    time.sleep(3600)
            except KeyboardInterrupt:
                print("\nstopping.")
        return rc


if __name__ == "__main__":
    sys.exit(main())

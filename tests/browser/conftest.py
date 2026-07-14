"""Session fixture that stands up the seeded demo stack for the browser smoke.

Mirrors ``scripts/demo/run_demo_capture.sh`` exactly, in-process for pytest:

  1. ``seed_demo.py`` — fresh SQLite store with TEST-NET-only demo data; writes
     ``<data-dir>/../manifest.json`` with the seeded investigation/hunt ids +
     the demo admin credentials.
  2. ``mock_es.py`` — local mock of Elasticsearch + the LLM gateway on one port
     (serves ``/`` ES-info, ``/v1/models`` so the LLM health dot goes green, and
     the canned ``*_search`` alert data). No real model is ever called.
  3. ``uvicorn`` — the REAL soc-ai app, launched with ``env -i`` (a scrubbed
     environment) and cwd'd OUTSIDE the repo so it can never read a developer
     ``.env``; every setting points only at the 127.0.0.1 mocks.

The app serves the built SPA at ``/app`` from ``frontend/dist`` — the CI job
runs ``npm run build`` first so that directory exists.

Ports default to values distinct from the dev harness (ES 19200 / app 8901) and
the run_demo_capture defaults, so a smoke run never collides with a demo capture
running on the same box. Override with ``SMOKE_ES_PORT`` / ``SMOKE_APP_PORT``.
"""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import time
import urllib.error
import urllib.request
from collections.abc import Iterator
from pathlib import Path
from tempfile import TemporaryDirectory

import pytest

REPO = Path(__file__).resolve().parents[2]
# The repo's own interpreter (uv-managed venv). Fall back to the runner's python
# (uv sets sys.executable to the project venv under ``uv run``).
_VENV_PY = REPO / ".venv" / "bin" / "python"
PY = str(_VENV_PY) if _VENV_PY.exists() else sys.executable

ES_PORT = int(os.environ.get("SMOKE_ES_PORT", "19402"))
APP_PORT = int(os.environ.get("SMOKE_APP_PORT", "8913"))

# Distinct ports for the read-only demo-mode stack (test_demo_walkthrough), so a
# demo walkthrough and the capture smoke never collide when run in one session.
DEMO_ES_PORT = int(os.environ.get("SMOKE_DEMO_ES_PORT", "19404"))
DEMO_APP_PORT = int(os.environ.get("SMOKE_DEMO_APP_PORT", "8915"))

# The committed, owner-reviewed demo fixture set — the same file the app seeds at
# startup (soc_ai/main.py demo hook) and the mock ES serves alerts[] from.
DEMO_FIXTURES = REPO / "soc_ai" / "demo" / "fixtures.json"

_HEALTH_TIMEOUT_S = 45.0  # bounded startup wait (seed migrations + uvicorn boot)


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


@pytest.fixture(scope="session")
def demo_stack() -> Iterator[dict]:
    """Launch seed + mock_es + uvicorn; yield ``{base_url, manifest}``.

    Tears both long-lived processes down on exit, even if a test failed.
    """
    with TemporaryDirectory(prefix="soc-ai-smoke-") as workdir:
        work = Path(workdir)
        data = work / "data"

        # --- 1. seed the throwaway store (blocking; writes work/manifest.json) --
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
            # --- 2. mock ES + LLM gateway on one port (background) --------------
            mock_proc = subprocess.Popen(
                [PY, str(REPO / "scripts" / "demo" / "mock_es.py"), str(ES_PORT)],
                cwd=str(REPO),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,  # own process group for clean teardown
            )

            # --- 3. the real app, env-isolated (mirrors run_demo_capture.sh) ---
            # A scrubbed environment: only the demo settings + a minimal PATH so
            # a developer .env can NEVER leak in. Every host is a 127.0.0.1 mock
            # or a reserved example.com placeholder.
            mock_base = f"http://127.0.0.1:{ES_PORT}"
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
                        str(APP_PORT),
                    ],
                    cwd=str(work),  # OUTSIDE the repo — no .env reachable
                    env=env,
                    stdout=logf,
                    stderr=subprocess.STDOUT,
                    start_new_session=True,
                )

            # --- poll /healthz until 200 (bounded) -----------------------------
            base_url = f"http://127.0.0.1:{APP_PORT}"
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


@pytest.fixture(scope="session")
def demo_mode_stack() -> Iterator[dict]:
    """The REAL public-demo stack (``SOC_AI_DEMO=true``), in-process for pytest.

    Distinct from :func:`demo_stack` (the docs-screenshot capture path, which
    pre-seeds a store with ``seed_demo.py``): this fixture exercises the demo
    *product* path — the app's own startup hook seeds the committed
    ``soc_ai/demo/fixtures.json``, the read-only middleware blocks mutations,
    the ``/demo-status`` flag lights the honesty banner, and the mock ES serves
    that same file's ``alerts[]`` grid. It mirrors ``docker-compose.demo.yml`` /
    ``docker/demo-entrypoint.sh`` exactly (same env; the app connects to the
    bundled mock over loopback — the one path the egress guard sanctions):

      * ``mock_es.py --fixtures soc_ai/demo/fixtures.json`` on loopback, and
      * the real app with ``SOC_AI_DEMO=true`` + ``API_AUTH_REQUIRED=false``, so
        visitors land straight in the read-only UI (login is demo-blocked).

    No seed step and no manifest: the app seeds itself at startup. Yields
    ``{base_url, fixtures}`` where ``fixtures`` is the loaded fixture document
    (investigation/replay/backtest ids for the walkthrough to drive).
    """
    fixtures = json.loads(DEMO_FIXTURES.read_text())

    with TemporaryDirectory(prefix="soc-ai-demo-") as workdir:
        work = Path(workdir)
        data = work / "data"

        mock_proc: subprocess.Popen[bytes] | None = None
        app_proc: subprocess.Popen[bytes] | None = None
        app_log = work / "app.log"
        try:
            # --- bundled mock ES + LLM gateway, serving the demo fixtures ------
            mock_proc = subprocess.Popen(
                [
                    PY,
                    str(REPO / "scripts" / "demo" / "mock_es.py"),
                    "--port",
                    str(DEMO_ES_PORT),
                    "--fixtures",
                    str(DEMO_FIXTURES),
                ],
                cwd=str(REPO),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
            )

            # --- the real app in read-only demo mode (docker-compose.demo.yml) -
            # Scrubbed env cwd'd OUTSIDE the repo so no developer .env leaks in;
            # every host is the 127.0.0.1 mock (the demo egress guard refuses any
            # non-loopback client) or an inert placeholder Settings requires.
            mock_base = f"http://127.0.0.1:{DEMO_ES_PORT}"
            env = {
                "PATH": "/usr/bin:/bin",
                "HOME": str(work),
                "SOC_AI_DATA_DIR": str(data),
                "SOC_AI_DEMO": "true",
                "API_AUTH_REQUIRED": "false",
                "ES_HOSTS": mock_base,
                "SO_HOST": mock_base,
                "SO_USERNAME": "demo",
                "SO_PASSWORD": "demo-placeholder-unused",
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
                        str(DEMO_APP_PORT),
                    ],
                    cwd=str(work),  # OUTSIDE the repo — no .env reachable
                    env=env,
                    stdout=logf,
                    stderr=subprocess.STDOUT,
                    start_new_session=True,
                )

            base_url = f"http://127.0.0.1:{DEMO_APP_PORT}"
            deadline = time.monotonic() + _HEALTH_TIMEOUT_S
            while time.monotonic() < deadline:
                if _healthy(f"{base_url}/healthz"):
                    break
                if app_proc.poll() is not None:
                    log = app_log.read_text(errors="replace") if app_log.exists() else ""
                    raise RuntimeError(
                        f"demo app exited during startup (rc={app_proc.returncode}).\n{log}"
                    )
                time.sleep(0.5)
            else:
                log = app_log.read_text(errors="replace") if app_log.exists() else ""
                raise RuntimeError(
                    f"demo app did not become healthy in {_HEALTH_TIMEOUT_S}s.\n{log}"
                )

            yield {"base_url": base_url, "fixtures": fixtures}
        finally:
            _terminate(app_proc)
            _terminate(mock_proc)

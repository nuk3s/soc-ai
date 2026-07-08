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

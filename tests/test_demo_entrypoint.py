"""Harness for docker/demo-entrypoint.sh: runs the real script in a private PID
namespace with a stub ``python`` on PATH.

Past starting its two processes, the entrypoint's one job is to stop the app
(PID 1) when the mock ES dies, so the platform restarts the whole container
instead of serving empty grids. That only shows up with a real PID 1, so the
script runs under ``unshare --pid``; where an unprivileged pid namespace is not
available the runtime test skips rather than let ``kill 1`` reach the real init,
and the static pin below still holds the line.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
ENTRYPOINT = REPO / "docker" / "demo-entrypoint.sh"

# User + pid + mount namespaces, forked so the script is PID 1 of the new
# namespace; --kill-child tears the namespace down if the harness times out
# and kills unshare, so a failing run leaves no stray sleeper behind.
UNSHARE = ["unshare", "-Urpf", "--mount-proc", "--kill-child"]


def _pid_namespace_available() -> bool:
    if shutil.which("unshare") is None:
        return False
    try:
        probe = subprocess.run([*UNSHARE, "true"], capture_output=True, timeout=10, check=False)
    except (OSError, subprocess.SubprocessError):
        return False
    return probe.returncode == 0


needs_pid_namespace = pytest.mark.skipif(
    not _pid_namespace_available(),
    reason="unprivileged pid namespaces are not available here (unshare -Urpf failed)",
)


def _stub_python(stubbin: Path) -> None:
    """``python`` as the entrypoint sees it. The mock ES call exits after a
    second (long enough for the exec into the app to have happened, so the
    kill lands on the app and not on the shell that is about to exec).
    Anything else is the app: it must be PID 1 with a SIGTERM handler
    installed (the kernel delivers a signal to a namespace's init only when a
    handler exists) and otherwise runs for 30 s, well past the harness timeout.
    """
    real = Path(sys.executable).resolve()
    (stubbin / "python").write_text(
        "#!/bin/sh\n"
        'case "${1:-}" in *mock_es.py) sleep 1; exit 0 ;; esac\n'
        f"exec '{real}' -c 'import signal, sys, time\n"
        "signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))\n"
        "time.sleep(30)'\n"
    )
    (stubbin / "python").chmod(0o755)


@needs_pid_namespace
def test_mock_exit_stops_the_app(tmp_path: Path) -> None:
    """Pins: when the mock ES process exits after startup, the entrypoint stops
    the app (PID 1) and says so on stderr.

    The old supervisor polled ``kill -0 $mock_pid`` from a detached subshell.
    Once the script had exec'd into uvicorn, the dead mock was reparented to
    PID 1, which never wait()s for it, so it stayed a zombie that ``kill -0``
    accepts; the loop never ended and the demo kept serving empty grids while
    /healthz reported healthy. The supervising subshell is now the mock's
    parent, so its own wait sees the exit.
    """
    stubbin = tmp_path / "stubbin"
    stubbin.mkdir()
    _stub_python(stubbin)
    script = tmp_path / "demo-entrypoint.sh"
    script.write_text(ENTRYPOINT.read_text())
    env = {
        "PATH": f"{stubbin}:{os.environ['PATH']}",
        "SOC_AI_DEMO": "true",
        "HOME": str(tmp_path),
    }
    try:
        proc = subprocess.run(
            [*UNSHARE, "sh", str(script)],
            env=env,
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
    except subprocess.TimeoutExpired:
        pytest.fail("the app kept running after the mock ES exited")
    assert proc.returncode == 0, proc.stderr
    assert "stopping the app" in proc.stderr


def test_supervisor_is_the_mocks_parent() -> None:
    """Static pin for hosts without a usable pid namespace: the mock is started
    from inside the supervising subshell (which waits for it directly), and no
    ``kill -0`` poll is left anywhere in the script — on a zombie that test
    succeeds forever.
    """
    text = ENTRYPOINT.read_text()
    # Code lines only: the comment above the subshell names the old idiom to
    # explain why it is gone.
    code = "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))
    assert "kill -0" not in code
    assert re.search(r"\(\s*set \+e\s*\n\s*python /opt/soc-ai/scripts/demo/mock_es\.py", code)

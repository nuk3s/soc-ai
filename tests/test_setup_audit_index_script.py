"""Harness for scripts/setup-audit-index.sh: runs the real script under bash
with a stub ``so-elasticsearch-query`` on PATH.

The script refuses to run unless EUID is 0 (so-elasticsearch-query needs the
root-only curl.config), so it runs inside a user namespace where the caller
maps to uid 0; where ``unshare -Ur`` is unavailable the test skips.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
SCRIPT = REPO / "scripts" / "setup-audit-index.sh"

UNSHARE = ["unshare", "-Ur"]

# A stock analyst role plus the one thing the PUT API rejects, and a
# document-level-security query — a JSON string whose own quotes are
# backslash-escaped, the shape any real role with a DLS/FLS query carries.
ROLE_JSON = {
    "analyst": {
        "cluster": ["monitor"],
        "indices": [
            {
                "names": ["logs-*"],
                "privileges": ["read"],
                "query": '{"match_all":{}}',
                "allow_restricted_indices": False,
            }
        ],
        "applications": [],
        "run_as": [],
        "metadata": {},
        "transient_metadata": {"enabled": True},
    }
}

# GET answers with the role; PUT records its -d body and answers like ES;
# anything else (the bootstrap index PUT) answers {}.
STUB = """#!/bin/sh
case "${1:-}" in
  _security/role/*)
    if [ "${2:-}" = "-X" ]; then
      while [ $# -gt 1 ]; do [ "$1" = "-d" ] && printf '%s' "$2" > "$STUB_LOG"; shift; done
      echo '{"role":{"created":true}}'
    else cat "$STUB_ROLE"; fi ;;
  *) echo '{}' ;;
esac
"""


def _user_namespace_available() -> bool:
    if shutil.which("unshare") is None:
        return False
    try:
        probe = subprocess.run([*UNSHARE, "true"], capture_output=True, timeout=10, check=False)
    except (OSError, subprocess.SubprocessError):
        return False
    return probe.returncode == 0


needs_user_namespace = pytest.mark.skipif(
    not _user_namespace_available(),
    reason="unprivileged user namespaces are not available here (unshare -Ur failed)",
)


def _run(tmp_path: Path) -> tuple[subprocess.CompletedProcess[str], Path]:
    stubbin = tmp_path / "stubbin"
    stubbin.mkdir()
    (stubbin / "so-elasticsearch-query").write_text(STUB)
    (stubbin / "so-elasticsearch-query").chmod(0o755)
    role = tmp_path / "role.json"
    role.write_text(json.dumps(ROLE_JSON))
    log = tmp_path / "put-body.json"
    # python3 and date must resolve too; the interpreter running this suite is
    # the one guaranteed to exist.
    path = f"{stubbin}:{Path(sys.executable).parent}:{os.environ['PATH']}"
    env = {"PATH": path, "HOME": str(tmp_path), "STUB_ROLE": str(role), "STUB_LOG": str(log)}
    proc = subprocess.run(
        [*UNSHARE, "bash", str(SCRIPT)],
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    return proc, log


@needs_user_namespace
def test_role_with_escaped_query_is_granted_intact(tmp_path: Path) -> None:
    """Pins: a role whose JSON carries backslash escapes (a DLS ``query`` string
    here) is read, amended and PUT back with the escapes intact.

    The role body used to be spliced into Python source as a triple-quoted
    literal, so Python's own escape processing ran on it first: ``\\"`` became
    ``"`` and json.loads failed with a traceback after step [1/3], under
    ``set -e``, before the PUT — the documented remedy for "audit log write
    failed (event dropped)" died on exactly the roles that carry a query. The
    body now reaches Python through the environment.
    """
    proc, log = _run(tmp_path)
    assert proc.returncode == 0, proc.stderr + proc.stdout
    assert "JSONDecodeError" not in proc.stderr
    body = json.loads(log.read_text())
    assert "transient_metadata" not in body
    blocks = {tuple(block["names"]): block for block in body["indices"]}
    assert blocks[("logs-*",)]["query"] == '{"match_all":{}}'
    grant = blocks[("soc-ai-audit-*",)]
    assert grant["privileges"] == [
        "auto_configure",
        "create_index",
        "index",
        "read",
        "view_index_metadata",
        "write",
    ]
    assert grant["allow_restricted_indices"] is False

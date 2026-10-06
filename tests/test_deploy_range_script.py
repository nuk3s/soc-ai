"""Harness for scripts/deploy-range.sh: the real script under bash with a stubbed PATH.

Range dogfood C7 (2026-10-05): ``GET /api/v1/about`` named no commit on the
range, which runs unreleased main from a synced tree with no version control
tool on the box. ``scripts/deploy.sh`` already stamps ``SOC_AI_COMMIT`` into the
production ``.env``. The range script now does the same.

Every outside tool is a stub. The ssh stub runs the one remote command that
writes the stamp against a local directory that stands in for the range, and
only logs the others: nothing here reaches a host, installs a package or
restarts a unit.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
SCRIPT = REPO / "scripts" / "deploy-range.sh"
SHA = "0123456789abcdef0123456789abcdef01234567"

_OK = "#!/bin/sh\nexit 0\n"
_REV_PARSE = f"#!/bin/sh\necho {SHA}\n"
# ssh TARGET COMMAND. The stamp command runs here, against the stand-in directory.
_SSH = """#!/bin/sh
printf '%s\\n' "$2" >> "$SSH_LOG"
case "$2" in
  *SOC_AI_COMMIT=*) sh -c "$2" ;;
esac
exit 0
"""
_STUBS = (("npm", _OK), ("rsync", _OK), ("uv", _OK), ("ssh", _SSH), ("git", _REV_PARSE))


def _deploy(tmp_path: Path, env_text: str | None = None) -> subprocess.CompletedProcess[str]:
    """Run the script once against ``tmp_path/range``. ``env_text`` replaces its .env."""
    if shutil.which("bash") is None:
        pytest.skip("bash is not installed")
    stubs = tmp_path / "bin"
    stubs.mkdir(exist_ok=True)
    for name, body in _STUBS:
        path = stubs / name
        path.write_text(body)
        path.chmod(0o755)
    dest = tmp_path / "range"
    dest.mkdir(exist_ok=True)
    if env_text is not None:
        (dest / ".env").write_text(env_text)
    env = {
        "PATH": f"{stubs}:{os.environ.get('PATH', '/usr/bin:/bin')}",
        "HOME": str(tmp_path),
        "SSH_LOG": str(tmp_path / "ssh.log"),
    }
    return subprocess.run(
        ["bash", str(SCRIPT), "range-test", str(dest)],
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )


def _env_file(tmp_path: Path) -> Path:
    return tmp_path / "range" / ".env"


def test_the_range_deploy_stamps_the_commit_and_keeps_every_other_line(tmp_path: Path) -> None:
    before = [
        "SO_HOST=https://so.example.com",
        "SOC_AI_COMMIT=0000000000000000000000000000000000000000",
        "API_AUTH_REQUIRED=true",
        "# a comment the operator wrote",
        # Negative control: the sed is anchored, so a longer key stays.
        "MY_SOC_AI_COMMIT=keep-me",
        "ES_USERNAME=soc-ai",
    ]
    # The last line has no newline. The stamp must not join it.
    proc = _deploy(tmp_path, "\n".join(before))
    assert proc.returncode == 0, proc.stderr
    text = _env_file(tmp_path).read_text()
    assert text.endswith("\n")
    kept = [line for line in before if not line.startswith("SOC_AI_COMMIT=")]
    assert text.splitlines() == [*kept, f"SOC_AI_COMMIT={SHA}"]
    assert f"commit {SHA} stamped" in proc.stdout


def test_a_second_deploy_leaves_one_stamp(tmp_path: Path) -> None:
    assert _deploy(tmp_path, "SO_HOST=https://so.example.com\n").returncode == 0
    first = _env_file(tmp_path).read_text()
    proc = _deploy(tmp_path)
    assert proc.returncode == 0, proc.stderr
    assert _env_file(tmp_path).read_text() == first
    assert first == f"SO_HOST=https://so.example.com\nSOC_AI_COMMIT={SHA}\n"


def test_a_range_with_no_env_file_gets_one_line(tmp_path: Path) -> None:
    proc = _deploy(tmp_path)
    assert proc.returncode == 0, proc.stderr
    assert _env_file(tmp_path).read_text() == f"SOC_AI_COMMIT={SHA}\n"


def test_the_stamp_runs_before_the_restart(tmp_path: Path) -> None:
    """The unit reads .env at start, so the stamp must land before systemctl restart."""
    proc = _deploy(tmp_path, "")
    assert proc.returncode == 0, proc.stderr
    log = (tmp_path / "ssh.log").read_text()
    assert log.index("SOC_AI_COMMIT=") < log.index("systemctl restart soc-ai")

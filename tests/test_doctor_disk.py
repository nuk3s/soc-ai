"""The doctor disk row, the compose health check and the memory limit.

Measured (production review 2026-11-12, ops findings 2, 9 and 11).

* The root volume had 1.9 G free. One backup needs 770 MB and one deploy needs
  up to 1.4 G. The doctor had no row for free space.
* The health check asked HTTPS first on a server that speaks plain HTTP behind
  the proxy. The server logged "Invalid HTTP request received" each 30 s:
  37,402 lines in 13 days, 98% of all warnings.
* The container reached its 1G memory limit 6,631 times in nine days.
"""

from __future__ import annotations

import os
import stat
import subprocess
from pathlib import Path
from typing import Any

import pytest
import yaml
from soc_ai import doctor
from soc_ai.config import Settings
from soc_ai.doctor import check_disk

_REPO = Path(__file__).resolve().parents[1]
_G = 1024**3


def _volume(monkeypatch: pytest.MonkeyPatch, *, total: float, free: float) -> None:
    monkeypatch.setattr(doctor, "_disk_usage", lambda _path: (int(total * _G), int(free * _G)))


def _settings(settings: Settings, tmp_path: Path) -> Settings:
    settings.soc_ai_data_dir = tmp_path / "data"
    return settings


# ---------------------------------------------------------------------------
# The doctor row
# ---------------------------------------------------------------------------


def test_the_measured_host_gets_a_warning(
    settings_kratos: Settings, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """1.9 G free of 15 G: under 2 G and under 15%."""
    _volume(monkeypatch, total=15, free=1.9)
    (row,) = check_disk(_settings(settings_kratos, tmp_path))
    assert row.name == "disk space"
    assert row.status == "WARN"
    assert "1.9 G of 15.0 G is free" in row.detail
    assert "That is 13%." in row.detail
    assert "The limits are 2 G and 15%." in row.detail
    # The text names the fix.
    assert "Make the volume larger, or remove files from it." in row.hint
    assert "docker image prune" in row.hint and "docker builder prune" in row.hint
    assert "stops every write to the store" in row.hint


def test_under_two_gigabytes_warns_on_a_small_volume(
    settings_kratos: Settings, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """1.5 G free of 4 G is 38% free. The 2 G limit alone gives the warning."""
    _volume(monkeypatch, total=4, free=1.5)
    (row,) = check_disk(_settings(settings_kratos, tmp_path))
    assert row.status == "WARN"


def test_under_fifteen_percent_warns_on_a_large_volume(
    settings_kratos: Settings, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """50 G free of 500 G is above 2 G. The 15% limit alone gives the warning."""
    _volume(monkeypatch, total=500, free=50)
    (row,) = check_disk(_settings(settings_kratos, tmp_path))
    assert row.status == "WARN"
    assert "That is 10%." in row.detail


@pytest.mark.parametrize(("total", "free"), [(60, 30), (500, 76), (14, 2.2)])
def test_a_volume_with_space_passes(
    settings_kratos: Settings,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    total: float,
    free: float,
) -> None:
    """Negative control: above both limits the row is green and has no hint."""
    _volume(monkeypatch, total=total, free=free)
    (row,) = check_disk(_settings(settings_kratos, tmp_path))
    assert row.status == "PASS"
    assert row.hint == ""


def test_a_volume_that_cannot_be_read_is_a_warning(
    settings_kratos: Settings, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def _refuse(_path: Path) -> tuple[int, int]:
        raise PermissionError("no access")

    monkeypatch.setattr(doctor, "_disk_usage", _refuse)
    (row,) = check_disk(_settings(settings_kratos, tmp_path))
    assert row.status == "WARN"
    assert "cannot read the free space" in row.detail


def test_the_row_measures_the_real_volume_of_the_data_directory(
    settings_kratos: Settings, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The data directory does not exist yet. The row measures the volume of its parent."""
    seen: list[Path] = []

    def _record(path: Path) -> tuple[int, int]:
        seen.append(path)
        return (100 * _G, 60 * _G)

    monkeypatch.setattr(doctor, "_disk_usage", _record)
    settings = _settings(settings_kratos, tmp_path)
    assert not settings.soc_ai_data_dir.exists()
    check_disk(settings)
    assert seen == [tmp_path.resolve()]


def test_the_real_reader_returns_the_numbers_of_this_host(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The one test that reads this host. conftest gives every other test a roomy volume."""
    monkeypatch.undo()
    total, free = doctor._disk_usage(tmp_path)
    assert total > 0
    assert 0 <= free <= total


def test_the_doctor_run_holds_the_disk_row() -> None:
    """The row is in the doctor, between the backups row and the prompt assets row."""
    import inspect

    source = inspect.getsource(doctor.run_doctor)
    backups = source.index("check_backups(settings)")
    disk = source.index("check_disk(settings)")
    assets = source.index("check_prompt_assets()")
    assert backups < disk < assets


# ---------------------------------------------------------------------------
# The compose health check
# ---------------------------------------------------------------------------


def _compose() -> dict[str, Any]:
    return yaml.safe_load((_REPO / "docker-compose.yml").read_text(encoding="utf-8"))  # type: ignore[no-any-return]


def _health_command() -> str:
    test = _compose()["services"]["soc-ai"]["healthcheck"]["test"]
    assert test[0] == "CMD-SHELL"
    # Compose turns $$ into $ before the container shell reads the command.
    return str(test[1]).replace("$$", "$")


def _run_check(
    tmp_path: Path, *, cert: str, failing: tuple[str, ...] = ()
) -> tuple[int, list[str]]:
    """Run the health command with a stub curl. Returns the exit code and the URLs asked."""
    log = tmp_path / "curl.log"
    stub = tmp_path / "bin" / "curl"
    stub.parent.mkdir(exist_ok=True)
    fail_lines = "\n".join(f'case "$url" in {scheme}://*) exit 7;; esac' for scheme in failing)
    stub.write_text(
        "#!/bin/sh\n"
        'for arg in "$@"; do url="$arg"; done\n'
        f'echo "$url" >> "{log}"\n'
        f"{fail_lines}\n"
        "exit 0\n",
        encoding="utf-8",
    )
    stub.chmod(stub.stat().st_mode | stat.S_IEXEC)
    env = {"PATH": f"{stub.parent}:{os.environ['PATH']}", "SOC_AI_TLS_CERT": cert}
    done = subprocess.run(
        ["/bin/sh", "-c", _health_command()], env=env, capture_output=True, check=False
    )
    asked = log.read_text(encoding="utf-8").split() if log.exists() else []
    return done.returncode, asked


def test_the_check_asks_plain_http_on_the_proxy_path(tmp_path: Path) -> None:
    """SOC_AI_TLS_CERT is blank behind the proxy. No HTTPS request reaches the server."""
    code, asked = _run_check(tmp_path, cert="")
    assert code == 0
    assert asked == ["http://127.0.0.1:8443/healthz"]


def test_the_check_asks_https_on_the_direct_path(tmp_path: Path) -> None:
    code, asked = _run_check(tmp_path, cert="/etc/soc-ai/cert.pem")
    assert code == 0
    assert asked == ["https://127.0.0.1:8443/healthz"]


def test_the_other_scheme_is_the_second_try(tmp_path: Path) -> None:
    """A server that an override started in the other scheme still reads as live."""
    code, asked = _run_check(tmp_path, cert="", failing=("http",))
    assert code == 0
    assert asked == ["http://127.0.0.1:8443/healthz", "https://127.0.0.1:8443/healthz"]


@pytest.mark.parametrize("cert", ["", "/etc/soc-ai/cert.pem"])
def test_a_dead_server_still_fails_the_check(tmp_path: Path, cert: str) -> None:
    """Negative control: the change must not make a dead server read as live."""
    code, asked = _run_check(tmp_path, cert=cert, failing=("http", "https"))
    assert code != 0
    assert len(asked) == 2


def test_the_dockerfile_check_follows_the_same_rule() -> None:
    text = (_REPO / "Dockerfile").read_text(encoding="utf-8")
    start = text.index("HEALTHCHECK ")
    block = text[start : text.index("\n\n", start)]
    assert 'if [ -n "${SOC_AI_TLS_CERT}" ]; then' in block
    cert_branch, plain_branch = block.split("else")
    assert cert_branch.index("https://") < cert_branch.index("http://127")
    assert plain_branch.index("http://127") < plain_branch.index("https://")


# ---------------------------------------------------------------------------
# The memory limit
# ---------------------------------------------------------------------------


def test_the_container_memory_limit_is_three_gigabytes() -> None:
    limits = _compose()["services"]["soc-ai"]["deploy"]["resources"]["limits"]
    assert limits["memory"] == "3G"

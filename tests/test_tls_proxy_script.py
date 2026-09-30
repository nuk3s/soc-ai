"""Harness for scripts/tls-proxy.sh: the real script under bash with a stubbed PATH.

A fake docker records every argv line in DOCKER_LOG and answers the calls the
script depends on. A fake curl records its argv in CURL_LOG and answers 200.
The .env starts as a copy of .env.example, the way a fresh install leaves it
before setup.sh appends its block.
"""

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path
from typing import NamedTuple

import pytest

REPO = Path(__file__).resolve().parent.parent
SCRIPT = REPO / "scripts" / "tls-proxy.sh"
DOMAIN = "soc-ai.example.test"
ROOT_IN_CADDY = "caddy:/data/caddy/pki/authorities/local/root.crt"
PROXY_KEYS = (
    "SOC_AI_BIND",
    "SOC_AI_DOMAIN",
    "SOC_AI_CADDY_TLS",
    "COMPOSE_PROFILES",
    "PROXY_TRUSTED_IPS",
)

# `network inspect` fails until `compose up --no-start` has run, the way a fresh
# checkout has no compose network yet. `compose logs caddy` carries the line the
# script waits for. `compose cp` writes its last argument.
DOCKER_STUB = """#!/bin/sh
printf '%s\\n' "$*" >> "$DOCKER_LOG"
case "$*" in
  info) exit 0 ;;
  "network inspect "*)
    if [ -f "$STUB_STATE/network" ]; then echo 172.20.0.0/16; exit 0; fi
    echo "Error: No such network" >&2; exit 1 ;;
  "compose up --no-start") : > "$STUB_STATE/network" ;;
  "compose ps -q caddy") [ -f "$STUB_STATE/caddy-running" ] && echo 0123456789ab ;;
  "compose logs "*) echo '{"logger":"tls.obtain","msg":"certificate obtained successfully"}' ;;
  "compose cp "*)
    for a in "$@"; do dest=$a; done
    echo "-----BEGIN CERTIFICATE-----stub" > "$dest" ;;
esac
exit 0
"""

CURL_STUB = """#!/bin/sh
printf '%s\\n' "$*" >> "$CURL_LOG"
echo 200
exit 0
"""

_KV_LINE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")


class Run(NamedTuple):
    proc: subprocess.CompletedProcess[str]
    env_text: str
    workdir: Path
    docker_log: str
    curl_log: str


def env_values(text: str) -> dict[str, str]:
    """Effective .env: last value wins, one pair of quotes stripped."""
    out: dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            v = v.strip()
            if len(v) >= 2 and v[0] == v[-1] and v[0] in "'\"":
                v = v[1:-1]
            out[k.strip()] = v
    return out


def make_workdir(tmp_path: Path, *, network_exists: bool = False) -> Path:
    workdir = tmp_path / "repo"
    (workdir / "scripts").mkdir(parents=True)
    (workdir / "scripts" / "tls-proxy.sh").write_text(SCRIPT.read_text())
    (workdir / "scripts" / "tls-proxy.sh").chmod(0o755)
    for name in ("docker-compose.yml", "Caddyfile"):
        (workdir / name).write_text((REPO / name).read_text())
    (workdir / ".env").write_text((REPO / ".env.example").read_text())
    certs = workdir / "certs"
    certs.mkdir()
    (certs / "cert.pem").write_text("cert")
    (certs / "key.pem").write_text("key")
    stubbin = tmp_path / "stubbin"
    stubbin.mkdir(exist_ok=True)
    for tool, body in (("docker", DOCKER_STUB), ("curl", CURL_STUB)):
        p = stubbin / tool
        p.write_text(body)
        p.chmod(0o755)
    state = tmp_path / "state"
    state.mkdir(exist_ok=True)
    if network_exists:
        (state / "network").write_text("")
    return workdir


def run(tmp_path: Path, workdir: Path, *args: str) -> Run:
    env = {
        "PATH": f"{tmp_path / 'stubbin'}:{os.environ['PATH']}",
        "HOME": str(tmp_path),
        "DOCKER_LOG": str(tmp_path / "docker.log"),
        "CURL_LOG": str(tmp_path / "curl.log"),
        "STUB_STATE": str(tmp_path / "state"),
        "TLS_PROXY_POLL_S": "0",
    }
    proc = subprocess.run(
        ["bash", "scripts/tls-proxy.sh", *args],
        cwd=workdir,
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    env_text = (workdir / ".env").read_text()
    docker_log = (tmp_path / "docker.log").read_text() if (tmp_path / "docker.log").exists() else ""
    curl_log = (tmp_path / "curl.log").read_text() if (tmp_path / "curl.log").exists() else ""
    return Run(proc, env_text, workdir, docker_log, curl_log)


def _backups(workdir: Path) -> list[Path]:
    return sorted(workdir.glob(".env.bak-*"))


def test_script_parses() -> None:
    proc = subprocess.run(["bash", "-n", str(SCRIPT)], capture_output=True, text=True, check=False)
    assert proc.returncode == 0, proc.stderr


def test_script_carries_no_dash() -> None:
    text = SCRIPT.read_text(encoding="utf-8")
    assert "—" not in text and "–" not in text


def test_usage_names_the_three_verbs() -> None:
    proc = subprocess.run(
        ["bash", str(SCRIPT), "--help"], capture_output=True, text=True, check=False
    )
    assert proc.returncode == 0
    for verb in ("enable <domain>", "disable", "status", "--dry-run"):
        assert verb in proc.stdout, verb


def test_enable_internal_writes_env_starts_caddy_and_exports_the_root(tmp_path: Path) -> None:
    workdir = make_workdir(tmp_path)
    original = (workdir / ".env").read_text()
    r = run(tmp_path, workdir, "enable", DOMAIN, "internal")
    assert r.proc.returncode == 0, r.proc.stderr + r.proc.stdout
    v = env_values(r.env_text)
    assert v["SOC_AI_TLS_CERT"] == ""
    assert v["SOC_AI_TLS_KEY"] == ""
    assert v["SOC_AI_BIND"] == "127.0.0.1"
    assert v["SOC_AI_DOMAIN"] == DOMAIN
    assert v["SOC_AI_CADDY_TLS"] == "tls internal"
    assert v["COMPOSE_PROFILES"] == "proxy"
    assert v["PROXY_TRUSTED_IPS"] == "172.20.0.0/16"
    # Every other line survives. Only the managed keys change.
    managed = re.compile(r"^(SOC_AI_TLS_CERT|SOC_AI_TLS_KEY)=")
    kept = [ln for ln in original.splitlines() if not managed.match(ln)]
    for ln in kept:
        assert ln in r.env_text.splitlines(), ln
    backups = _backups(workdir)
    assert len(backups) == 1
    assert backups[0].read_text() == original
    # The command sequence: the network read fails, compose creates it, the read
    # succeeds, the stack comes up, the log wait, the root export.
    calls = r.docker_log.splitlines()
    assert calls[0] == "info"
    i_inspect = calls.index("network inspect repo_default -f {{(index .IPAM.Config 0).Subnet}}")
    i_create = calls.index("compose up --no-start")
    i_up = calls.index("compose up -d")
    i_logs = next(
        i for i, c in enumerate(calls) if c.startswith("compose logs") and c.endswith("caddy")
    )
    i_cp = calls.index(f"compose cp {ROOT_IN_CADDY} ./caddy-root.crt")
    assert i_inspect < i_create < i_up < i_logs < i_cp
    assert (workdir / "caddy-root.crt").read_text().startswith("-----BEGIN CERTIFICATE-----")
    assert f"--resolve {DOMAIN}:443:127.0.0.1" in r.curl_log
    assert f"https://{DOMAIN}/healthz" in r.curl_log
    out = r.proc.stdout
    assert f"https://{DOMAIN}/" in out
    assert "PROXY_TRUSTED_IPS=172.20.0.0/16" in out
    assert "update-ca-trust" in out and "update-ca-certificates" in out
    assert "security add-trusted-cert" in out and "certutil -addstore" in out
    assert "Firefox" in out
    assert "scripts/tls-proxy.sh disable" in out


def test_enable_auto_leaves_the_tls_directive_blank_and_exports_no_root(tmp_path: Path) -> None:
    workdir = make_workdir(tmp_path, network_exists=True)
    r = run(tmp_path, workdir, "enable", DOMAIN)
    assert r.proc.returncode == 0, r.proc.stderr + r.proc.stdout
    v = env_values(r.env_text)
    assert v["SOC_AI_CADDY_TLS"] == ""
    assert v["SOC_AI_DOMAIN"] == DOMAIN
    assert "compose up --no-start" not in r.docker_log
    assert "compose cp" not in r.docker_log
    assert not (workdir / "caddy-root.crt").exists()
    assert "Let's Encrypt" in r.proc.stdout


def test_enable_with_files_copies_them_into_certs(tmp_path: Path) -> None:
    workdir = make_workdir(tmp_path, network_exists=True)
    cert = tmp_path / "my-cert.pem"
    key = tmp_path / "my-key.pem"
    cert.write_text("CERT")
    key.write_text("KEY")
    r = run(tmp_path, workdir, "enable", DOMAIN, str(cert), str(key))
    assert r.proc.returncode == 0, r.proc.stderr + r.proc.stdout
    v = env_values(r.env_text)
    assert v["SOC_AI_CADDY_TLS"] == "tls /certs/proxy-cert.pem /certs/proxy-key.pem"
    c = workdir / "certs" / "proxy-cert.pem"
    k = workdir / "certs" / "proxy-key.pem"
    assert c.read_text() == "CERT" and k.read_text() == "KEY"
    assert oct(c.stat().st_mode & 0o777) == "0o644"
    assert oct(k.stat().st_mode & 0o777) == "0o640"
    # The files case waits on the health URL, not on the certificate log line.
    assert "compose logs" not in r.docker_log
    assert f"https://{DOMAIN}/healthz" in r.curl_log


def test_renewed_files_reload_a_running_caddy(tmp_path: Path) -> None:
    """A second run with new files must reach Caddy. `up -d` alone does not."""
    workdir = make_workdir(tmp_path, network_exists=True)
    cert = tmp_path / "renewed-cert.pem"
    key = tmp_path / "renewed-key.pem"
    cert.write_text("CERT2")
    key.write_text("KEY2")
    first = run(tmp_path, workdir, "enable", DOMAIN, str(cert), str(key))
    assert first.proc.returncode == 0, first.proc.stderr
    assert "caddy reload" not in first.docker_log
    (tmp_path / "state" / "caddy-running").write_text("")
    second = run(tmp_path, workdir, "enable", DOMAIN, str(cert), str(key))
    assert second.proc.returncode == 0, second.proc.stderr
    assert "compose exec -T caddy caddy reload --config /etc/caddy/Caddyfile" in second.docker_log
    assert "Caddy reloaded the certificate files." in second.proc.stdout


def test_enable_with_a_missing_file_refuses(tmp_path: Path) -> None:
    workdir = make_workdir(tmp_path, network_exists=True)
    r = run(tmp_path, workdir, "enable", DOMAIN, "/nonexistent/cert.pem", "/nonexistent/key.pem")
    assert r.proc.returncode == 2
    assert not _backups(workdir)


@pytest.mark.parametrize(
    "domain", ["nodots", "bad_name.test", "-lead.test", "trail.test.", "a..b", "sp ace.test"]
)
def test_enable_refuses_a_bad_domain(tmp_path: Path, domain: str) -> None:
    workdir = make_workdir(tmp_path)
    before = (workdir / ".env").read_text()
    r = run(tmp_path, workdir, "enable", domain)
    assert r.proc.returncode == 2
    assert r.proc.stderr.count("\n") == 1, r.proc.stderr
    assert "domain" in r.proc.stderr.lower()
    assert r.env_text == before
    assert not _backups(workdir)
    assert r.docker_log == ""


def test_enable_refuses_a_bad_source(tmp_path: Path) -> None:
    workdir = make_workdir(tmp_path)
    r = run(tmp_path, workdir, "enable", DOMAIN, "letsencrypt")
    assert r.proc.returncode == 2
    assert not _backups(workdir)


def test_enable_refuses_when_the_direct_pair_is_missing(tmp_path: Path) -> None:
    """The main stack bind-mounts certs/cert.pem and certs/key.pem. Without the files
    Docker creates two directories with those names and a later disable fails."""
    workdir = make_workdir(tmp_path)
    (workdir / "certs" / "key.pem").unlink()
    r = run(tmp_path, workdir, "enable", DOMAIN, "internal")
    assert r.proc.returncode != 0
    assert "certs/key.pem" in r.proc.stderr
    assert not _backups(workdir)


def test_dry_run_prints_the_plan_and_changes_nothing(tmp_path: Path) -> None:
    workdir = make_workdir(tmp_path)
    before = (workdir / ".env").read_text()
    r = run(tmp_path, workdir, "--dry-run", "enable", DOMAIN, "internal")
    assert r.proc.returncode == 0, r.proc.stderr + r.proc.stdout
    assert r.env_text == before
    assert not _backups(workdir)
    assert r.docker_log == ""
    assert r.curl_log == ""
    out = r.proc.stdout
    for line in (
        "SOC_AI_TLS_CERT=",
        "SOC_AI_BIND=127.0.0.1",
        f"SOC_AI_DOMAIN={DOMAIN}",
        "SOC_AI_CADDY_TLS=tls internal",
        "COMPOSE_PROFILES=proxy",
        "PROXY_TRUSTED_IPS=",
        "compose up -d",
        f"compose cp {ROOT_IN_CADDY}",
    ):
        assert line in out, line


def test_disable_restores_the_direct_path(tmp_path: Path) -> None:
    workdir = make_workdir(tmp_path)
    r1 = run(tmp_path, workdir, "enable", DOMAIN, "internal")
    assert r1.proc.returncode == 0, r1.proc.stderr
    (tmp_path / "docker.log").unlink()
    (tmp_path / "curl.log").unlink()
    r = run(tmp_path, workdir, "disable")
    assert r.proc.returncode == 0, r.proc.stderr + r.proc.stdout
    v = env_values(r.env_text)
    assert v["SOC_AI_TLS_CERT"] == "/etc/soc-ai/cert.pem"
    assert v["SOC_AI_TLS_KEY"] == "/etc/soc-ai/key.pem"
    for key in PROXY_KEYS:
        assert key not in v, key
        assert not re.search(rf"^{key}=", r.env_text, re.M), key
    # The commented examples from .env.example stay.
    assert "# SOC_AI_DOMAIN=soc-ai.example.com" in r.env_text
    assert len(_backups(workdir)) == 2
    calls = r.docker_log.splitlines()
    i_stop = calls.index("compose --profile proxy stop caddy")
    i_rm = calls.index("compose --profile proxy rm -f caddy")
    i_up = calls.index("compose up -d")
    assert i_stop < i_rm < i_up
    assert "https://127.0.0.1:8443/healthz" in r.curl_log
    assert "200" in r.proc.stdout


def test_dry_run_disable_changes_nothing(tmp_path: Path) -> None:
    workdir = make_workdir(tmp_path)
    run(tmp_path, workdir, "enable", DOMAIN, "internal")
    before = (workdir / ".env").read_text()
    (tmp_path / "docker.log").unlink()
    r = run(tmp_path, workdir, "--dry-run", "disable")
    assert r.proc.returncode == 0, r.proc.stderr
    assert r.env_text == before
    assert r.docker_log == ""
    assert len(_backups(workdir)) == 1
    assert "compose --profile proxy rm -f caddy" in r.proc.stdout


def test_status_reports_the_mode(tmp_path: Path) -> None:
    workdir = make_workdir(tmp_path)
    r = run(tmp_path, workdir, "status")
    assert r.proc.returncode == 0, r.proc.stderr
    assert "direct" in r.proc.stdout
    assert "https://127.0.0.1:8443/healthz" in r.curl_log
    run(tmp_path, workdir, "enable", DOMAIN, "internal")
    (tmp_path / "curl.log").unlink()
    r = run(tmp_path, workdir, "status")
    assert r.proc.returncode == 0, r.proc.stderr
    assert "proxy" in r.proc.stdout
    assert DOMAIN in r.proc.stdout
    assert "internal" in r.proc.stdout
    assert f"https://{DOMAIN}/healthz" in r.curl_log


def test_project_name_from_env_names_the_network(tmp_path: Path) -> None:
    workdir = make_workdir(tmp_path, network_exists=True)
    with (workdir / ".env").open("a") as fh:
        fh.write("COMPOSE_PROJECT_NAME=Soc-AI\n")
    r = run(tmp_path, workdir, "enable", DOMAIN, "internal")
    assert r.proc.returncode == 0, r.proc.stderr
    assert "network inspect soc-ai_default" in r.docker_log


def test_unknown_verb_exits_two(tmp_path: Path) -> None:
    workdir = make_workdir(tmp_path)
    r = run(tmp_path, workdir, "renew")
    assert r.proc.returncode == 2
    assert not _backups(workdir)

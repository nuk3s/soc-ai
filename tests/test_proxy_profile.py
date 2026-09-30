"""The Caddy service lives in docker-compose.yml under the proxy profile."""

from __future__ import annotations

import re
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent


def _compose() -> dict:
    return yaml.safe_load((REPO_ROOT / "docker-compose.yml").read_text(encoding="utf-8"))


def test_caddy_service_sits_under_the_proxy_profile() -> None:
    caddy = _compose()["services"]["caddy"]
    assert caddy["profiles"] == ["proxy"]
    assert re.fullmatch(r"caddy:\d+\.\d+\.\d+@sha256:[0-9a-f]{64}", caddy["image"]), caddy["image"]
    assert caddy["container_name"] == "soc-ai-caddy"
    assert caddy["restart"] == "unless-stopped"
    assert caddy["depends_on"] == ["soc-ai"]
    assert set(caddy["ports"]) == {"80:80", "443:443", "443:443/udp"}
    assert set(caddy["volumes"]) == {
        "./Caddyfile:/etc/caddy/Caddyfile:ro,Z",
        "./certs:/certs:ro,Z",
        "caddy_data:/data",
        "caddy_config:/config",
    }
    assert "no-new-privileges:true" in caddy["security_opt"]
    assert caddy["logging"]["driver"] == "json-file"
    assert caddy["logging"]["options"] == {"max-size": "20m", "max-file": "3"}
    volumes = _compose()["volumes"]
    assert "caddy_data" in volumes and "caddy_config" in volumes


def test_caddy_gets_two_variables_and_none_of_soc_ai_secrets() -> None:
    """The service must not hand the Caddy container the whole .env.

    A required form (``:?``) is interpolated even when the profile is off, so it
    would break ``docker compose up`` on the direct path. Both keys use the
    default form. The script validates the domain before it writes .env.
    """
    caddy = _compose()["services"]["caddy"]
    assert "env_file" not in caddy
    assert set(caddy["environment"]) == {"SOC_AI_DOMAIN", "SOC_AI_CADDY_TLS"}
    assert caddy["environment"]["SOC_AI_DOMAIN"] == "${SOC_AI_DOMAIN:-}"
    assert caddy["environment"]["SOC_AI_CADDY_TLS"] == "${SOC_AI_CADDY_TLS:-}"


def test_the_separate_proxy_project_is_gone() -> None:
    assert not (REPO_ROOT / "docker-compose.proxy.yml").exists()
    text = (REPO_ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    assert "docker-compose.proxy.yml" not in text
    assert "COMPOSE_PROFILES=proxy" in text
    assert "docker-compose.proxy.yml" not in (REPO_ROOT / "Caddyfile").read_text(encoding="utf-8")


def test_caddyfile_proxies_to_soc_ai_over_plain_http_and_reads_the_two_variables() -> None:
    text = (REPO_ROOT / "Caddyfile").read_text(encoding="utf-8")
    assert "{$SOC_AI_DOMAIN}" in text
    assert "{$SOC_AI_CADDY_TLS}" in text
    assert "reverse_proxy soc-ai:8443" in text
    assert "https://soc-ai" not in text


def test_container_healthchecks_try_https_then_http() -> None:
    test = " ".join(_compose()["services"]["soc-ai"]["healthcheck"]["test"])
    assert "https://127.0.0.1:8443/healthz" in test and "http://127.0.0.1:8443/healthz" in test
    dockerfile = (REPO_ROOT / "Dockerfile").read_text(encoding="utf-8")
    m = re.search(r"HEALTHCHECK[^\n]*\n[^\n]*CMD ([^\n]+)", dockerfile)
    assert m is not None
    assert "https://127.0.0.1:8443/healthz" in m.group(1)
    assert "http://127.0.0.1:8443/healthz" in m.group(1)


def test_env_example_documents_the_proxy_path() -> None:
    text = (REPO_ROOT / ".env.example").read_text(encoding="utf-8")
    for key in ("SOC_AI_DOMAIN", "SOC_AI_CADDY_TLS", "PROXY_TRUSTED_IPS", "COMPOSE_PROFILES=proxy"):
        assert key in text, key
    assert "scripts/tls-proxy.sh" in text
    assert "docker-compose.proxy.yml" not in text

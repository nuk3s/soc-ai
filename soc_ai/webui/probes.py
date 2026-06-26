"""Read-only connectivity probes for the admin config console.

Each probe targets one upstream (the LiteLLM gateway, the Security Onion
Elasticsearch cluster), is bounded by a timeout so a hung upstream cannot wedge
the request, and returns a small ``{"ok": bool, "detail": str}`` dict.

SECURITY: the ``detail`` string is rendered verbatim in an HTTP response and is
NEVER allowed to contain a secret — no API key, no ES/SO password, no
``user:pass@`` userinfo. Probes catch ALL exceptions and build ``detail`` from a
secret-free summary (exception type + a sanitized message), then pass it through
:func:`_scrub` defensively before returning.
"""

from __future__ import annotations

import asyncio
import re
from typing import Any

import httpx

# Default timeout (seconds) for every outbound probe. Kept short so the admin
# UI stays responsive when an upstream is down or hanging.
_PROBE_TIMEOUT_S = 10.0

# Defensive scrubbing patterns. Even though we build details from safe pieces,
# we strip anything that *looks* like a credential as a last line of defence.
_SCRUB_PATTERNS: tuple[re.Pattern[str], ...] = (
    # user:pass@host  →  host  (strip URL userinfo)
    re.compile(r"//[^/@\s]+@", flags=re.IGNORECASE),
    # Bearer <token>
    re.compile(r"bearer\s+\S+", flags=re.IGNORECASE),
    # key=..., api_key=..., apikey=..., password=..., token=...  query/kv params
    re.compile(r"(?i)(api[-_]?key|key|password|passwd|pwd|token|secret)=([^&\s]+)"),
)


def _scrub(text: str) -> str:
    """Strip credential-shaped substrings from *text* defensively."""
    out = text
    out = _SCRUB_PATTERNS[0].sub("//", out)
    out = _SCRUB_PATTERNS[1].sub("Bearer ***", out)
    out = _SCRUB_PATTERNS[2].sub(r"\1=***", out)
    return out


def _safe_reason(exc: BaseException) -> str:
    """Build a secret-free one-line reason from an exception.

    Connection errors expose only host/port (safe). For other errors we report
    the exception *type* and a scrubbed message, avoiding raw ``str(exc)`` that
    could embed a credentialed URL.
    """
    name = type(exc).__name__
    msg = _scrub(str(exc)).strip()
    # Bound the length so a chatty upstream can't bloat the response.
    msg = msg[:160]
    return f"{name}: {msg}" if msg else name


async def probe_llm(settings: Any) -> dict[str, Any]:
    """Probe the LiteLLM gateway by listing models.

    Issues ``GET {base}/v1/models`` with a bearer header (when a key is set) and
    counts the returned ``data`` array. Never raises; returns ``ok``/``detail``.
    The API key is never placed into ``detail``.
    """
    base = str(settings.litellm_base_url).rstrip("/")
    api_key = ""
    secret = getattr(settings, "litellm_api_key", None)
    if secret is not None:
        # SecretStr — may be empty.
        api_key = secret.get_secret_value()
    headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}
    # Mirror the real LLM connection's TLS policy (agent.models uses the same
    # knob) so the probe reflects actual reachability — homelab gateways use a
    # self-signed cert with litellm_verify_ssl=false.
    verify = bool(getattr(settings, "litellm_verify_ssl", True))
    try:
        async with httpx.AsyncClient(timeout=_PROBE_TIMEOUT_S, verify=verify) as client:
            resp = await client.get(f"{base}/v1/models", headers=headers)
        if resp.status_code != 200:
            # status_code + reason phrase are credential-free.
            reason = resp.reason_phrase or ""
            return {"ok": False, "detail": _scrub(f"HTTP {resp.status_code} {reason}".strip())}
        try:
            data = resp.json()
        except ValueError:
            return {"ok": False, "detail": "200 OK but response was not JSON"}
        models = data.get("data") if isinstance(data, dict) else None
        ids = (
            [m.get("id") for m in models if isinstance(m, dict)] if isinstance(models, list) else []
        )
        count = len(ids)
        # The gateway answering /v1/models doesn't mean ANALYST_MODEL is one of
        # them — a misconfigured value returns 200 here but 400s every actual
        # completion (every hunt silently falls back). Catch that up front.
        analyst = getattr(settings, "analyst_model", None)
        if analyst and analyst not in ids:
            return {
                "ok": False,
                "detail": _scrub(
                    f"gateway reachable ({count} models) but ANALYST_MODEL "
                    f"'{analyst}' is not configured on it — set ANALYST_MODEL to a "
                    f"model the gateway serves"
                ),
            }
        return {"ok": True, "detail": f"200 OK — {count} models (analyst: {analyst})"}
    except Exception as exc:  # a probe failure is a normal ✗ result, never a raise
        return {"ok": False, "detail": _safe_reason(exc)}


async def probe_es(elastic: Any) -> dict[str, Any]:
    """Probe the Elasticsearch cluster via :meth:`ElasticClient.ping`.

    Never raises; returns ``ok``/``detail``. No password ever reaches ``detail``.
    """
    try:
        info = await elastic.ping()
        cluster = str(info.get("cluster", "")) or "(unknown cluster)"
        version = str(info.get("version", "")) or "?"
        return {"ok": True, "detail": _scrub(f"{cluster} — ES {version}")}
    except Exception as exc:  # a probe failure is a normal ✗ result, never a raise
        return {"ok": False, "detail": _safe_reason(exc)}


# The re-creation hint shown when the PCAP path is broken — the publish-blocker
# requirement: tell the operator the sensor user/key/sudo is gone and how to fix.
_PCAP_BROKEN_HINT = (
    "sensor PCAP path is down — the socpcap user, its SSH key, or its NOPASSWD "
    "tcpdump sudo rule is missing/broken. Re-run the sensor setup "
    "(docs/SENSOR_PCAP_SETUP.md)."
)


async def probe_pcap(settings: Any) -> dict[str, Any]:
    """Probe the PCAP fetch path WITHOUT capturing packets.

    SSHes to the sensor as the de-privileged user and runs ``sudo tcpdump
    --version``, which exercises the whole chain — SSH auth (is the user still
    there? is the key valid?) and the NOPASSWD sudo-tcpdump grant — and fails
    loudly with a re-creation hint when the grid operator has nuked the user.
    Never raises; returns ``ok``/``detail``. Secret-free.
    """
    if not getattr(settings, "pcap_enabled", False):
        return {"ok": True, "detail": "PCAP disabled (pcap_enabled=false)"}
    if settings.so_ssh_key is None:
        return {"ok": False, "detail": "no SO_SSH_KEY configured — set it to the sensor pcap key"}

    from soc_ai.tools.get_pcap import _ssh_base_args  # noqa: PLC0415  (avoid import cycle)

    sudo = (getattr(settings, "so_ssh_sudo", "") or "").strip()
    remote = f"{sudo + ' ' if sudo else ''}tcpdump --version"
    args = [*_ssh_base_args(settings), remote]
    timeout = _PROBE_TIMEOUT_S + float(getattr(settings, "so_ssh_timeout_s", 120))
    try:
        proc = await asyncio.create_subprocess_exec(
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        try:
            out_b, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except TimeoutError:
            proc.kill()
            host = getattr(settings, "so_ssh_host", "?")
            return {"ok": False, "detail": f"timed out reaching {host} — sensor unreachable?"}
        text = _scrub((out_b or b"").decode("utf-8", "replace")).strip()
        # Skip the benign ssh "Permanently added ... known hosts" warning
        # (UserKnownHostsFile=/dev/null + accept-new) when choosing the detail.
        lines = [ln for ln in text.splitlines() if "permanently added" not in ln.lower()]
        if proc.returncode == 0 and "tcpdump version" in text.lower():
            ver = next((ln for ln in lines if "tcpdump version" in ln.lower()), "")
            return {"ok": True, "detail": f"sensor reachable — {ver.strip()[:120] or 'tcpdump ok'}"}
        why = (lines[0].strip() if lines else "") or f"exit {proc.returncode}"
        return {"ok": False, "detail": f"{_PCAP_BROKEN_HINT} [{why[:120]}]"}
    except Exception as exc:  # a probe failure is a normal ✗ result, never a raise
        return {"ok": False, "detail": _safe_reason(exc)}

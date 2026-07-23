"""Unit tests for ``soc_ai.cli`` event rendering and HTTP client wiring.

The CLI is mostly a thin SSE-stream printer. We exercise ``_render_event``
directly with representative payloads to catch breakage when SSE event
shapes evolve (e.g. when ``investigation_transcript`` or ``retask`` were
added during the robustness pass).

The auth/TLS tests drive ``_triage``/``_healthz`` through capturing
httpx client subclasses (backed by ``httpx.MockTransport``) to assert the
Authorization header and ``verify=`` wiring without a network.
"""

from __future__ import annotations

import argparse
import asyncio
from typing import Any

import httpx
import pytest
from soc_ai import cli
from soc_ai.cli import _render_event


def _strip_ansi(s: str) -> str:
    """Drop ANSI color escape sequences for stable assertions."""
    import re

    return re.sub(r"\x1b\[[0-9;]*m", "", s)


def test_render_session_start() -> None:
    out = _strip_ansi(_render_event("session_start", {"alert_id": "abc"}))
    assert "session_start" in out
    assert "abc" in out


def test_render_alert_context_summarizes_pivots() -> None:
    payload = {
        "alert": {
            "id": "abc",
            "rule_name": "ET DNS Query for X",
            "severity_label": "high",
            "network_community_id": "1:foo",
        },
        "pivot_summary": {"community_id": 4, "host": 0, "user": 0, "process": 0, "file": 0},
    }
    out = _strip_ansi(_render_event("alert_context", payload))
    assert "alert_context" in out
    assert "high" in out
    assert "ET DNS Query for X" in out
    assert "community_id:4" in out


def test_render_triage_report_with_actions() -> None:
    payload = {
        "verdict": "false_positive",
        "confidence": 0.85,
        "summary": "Internal DNS lookup; benign.",
        "citations": ["alert-001", "event-002"],
        "recommended_actions": [
            {
                "tool_name": "ack_alert",
                "tool_args": {"alert_id": "alert-001"},
                "rationale": "Alert is benign DHCP traffic; can be acknowledged.",
            }
        ],
    }
    out = _strip_ansi(_render_event("triage_report", payload))
    assert "triage_report" in out
    assert "FALSE_POSITIVE" in out
    assert "0.85" in out
    assert "Internal DNS lookup" in out
    assert "alert-001" in out
    assert "ack_alert" in out
    assert "benign DHCP traffic" in out


def test_render_error_includes_hint_when_present() -> None:
    payload = {
        "phase": "investigator",
        "round": 1,
        "type": "OqlValidationError",
        "message": "unknown or forbidden field: 'dest.ip'",
        "hint": "use destination.ip not dest.ip",
    }
    out = _strip_ansi(_render_event("error", payload))
    assert "error" in out
    assert "investigator" in out
    assert "round=1" in out
    assert "OqlValidationError" in out
    assert "dest.ip" in out
    assert "hint:" in out
    assert "destination.ip" in out


def test_render_error_omits_hint_section_when_absent() -> None:
    payload = {
        "phase": "synthesizer",
        "round": 1,
        "type": "RuntimeError",
        "message": "boom",
    }
    out = _strip_ansi(_render_event("error", payload))
    assert "synthesizer" in out
    assert "RuntimeError" in out
    assert "boom" in out
    assert "hint:" not in out


def test_render_retask_event() -> None:
    payload = {
        "reason": "synthesis_below_floor",
        "confidence": 0.3,
        "floor": 0.6,
        "open_questions": ["unenriched IP"],
    }
    out = _strip_ansi(_render_event("retask", payload))
    assert "retask" in out
    assert "synthesis_below_floor" in out
    assert "0.3" in out
    assert "0.6" in out


def test_render_investigation_transcript() -> None:
    payload = {
        "round": 1,
        "evidence": ["a", "b", "c"],
        "open_questions": ["x"],
        "tentative_summary": "DNS-style lookup, no action.",
    }
    out = _strip_ansi(_render_event("investigation_transcript", payload))
    assert "investigation_transcript" in out
    assert "round=1" in out
    assert "evidence=3" in out
    assert "open_questions=1" in out
    assert "DNS-style lookup" in out


def test_render_unknown_kind_falls_back_to_json_dump() -> None:
    out = _strip_ansi(_render_event("future_kind", {"hello": "world"}))
    assert "future_kind" in out
    assert "world" in out


# --- auth token + TLS verify wiring (FR-006 / FR-073) -----------------------


_SSE_BODY = 'event: done\ndata: {"payload": {"recommended_count": 0, "rounds": 1}}\n\n'


def _patch_async_client(
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[dict[str, Any], list[httpx.Request]]:
    """Swap cli's httpx.AsyncClient for one that captures kwargs + requests."""
    captured_kwargs: dict[str, Any] = {}
    captured_requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured_requests.append(request)
        return httpx.Response(200, text=_SSE_BODY, headers={"content-type": "text/event-stream"})

    class _Client(httpx.AsyncClient):
        def __init__(self, **kwargs: Any) -> None:
            captured_kwargs.update(kwargs)
            super().__init__(transport=httpx.MockTransport(handler))

    monkeypatch.setattr(cli.httpx, "AsyncClient", _Client)
    return captured_kwargs, captured_requests


def _patch_sync_client(
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[dict[str, Any], list[httpx.Request]]:
    """Swap cli's httpx.Client for one that captures kwargs + requests."""
    captured_kwargs: dict[str, Any] = {}
    captured_requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured_requests.append(request)
        return httpx.Response(200, json={"status": "ok"})

    class _Client(httpx.Client):
        def __init__(self, **kwargs: Any) -> None:
            captured_kwargs.update(kwargs)
            headers = kwargs.get("headers")
            super().__init__(transport=httpx.MockTransport(handler), headers=headers)

    monkeypatch.setattr(cli.httpx, "Client", _Client)
    return captured_kwargs, captured_requests


def _triage_args(**overrides: Any) -> argparse.Namespace:
    base: dict[str, Any] = {
        "url": "https://127.0.0.1:8443",
        "alert_id": "abc123",
        "token": None,
        "verify": False,
        "cafile": None,
    }
    base.update(overrides)
    return argparse.Namespace(**base)


def _healthz_args(**overrides: Any) -> argparse.Namespace:
    base: dict[str, Any] = {
        "url": "https://127.0.0.1:8443",
        "token": None,
        "verify": False,
        "cafile": None,
    }
    base.update(overrides)
    return argparse.Namespace(**base)


def test_triage_sends_bearer_token_from_flag(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SOC_AI_API_TOKEN", raising=False)
    kwargs, requests = _patch_async_client(monkeypatch)
    rc = cli._triage(_triage_args(token="scai_flagtoken"))
    assert rc == 0
    assert len(requests) == 1
    assert requests[0].headers["authorization"] == "Bearer scai_flagtoken"
    assert requests[0].headers["accept"] == "text/event-stream"
    assert kwargs["verify"] is False


def test_healthz_sends_bearer_token_from_flag(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SOC_AI_API_TOKEN", raising=False)
    kwargs, requests = _patch_sync_client(monkeypatch)
    rc = cli._healthz(_healthz_args(token="scai_flagtoken"))
    assert rc == 0
    assert len(requests) == 1
    assert requests[0].headers["authorization"] == "Bearer scai_flagtoken"
    assert kwargs["verify"] is False


def test_env_token_used_when_no_flag(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SOC_AI_API_TOKEN", "scai_envtoken")
    _, requests = _patch_sync_client(monkeypatch)
    rc = cli._healthz(_healthz_args())
    assert rc == 0
    assert requests[0].headers["authorization"] == "Bearer scai_envtoken"


def test_flag_token_takes_precedence_over_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SOC_AI_API_TOKEN", "scai_envtoken")
    _, requests = _patch_sync_client(monkeypatch)
    rc = cli._healthz(_healthz_args(token="scai_flagtoken"))
    assert rc == 0
    assert requests[0].headers["authorization"] == "Bearer scai_flagtoken"


def test_no_token_sends_no_authorization_header(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SOC_AI_API_TOKEN", raising=False)
    _, sync_requests = _patch_sync_client(monkeypatch)
    assert cli._healthz(_healthz_args()) == 0
    assert "authorization" not in sync_requests[0].headers

    _, async_requests = _patch_async_client(monkeypatch)
    assert cli._triage(_triage_args()) == 0
    assert "authorization" not in async_requests[0].headers


def test_verify_flag_flips_httpx_verify(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SOC_AI_API_TOKEN", raising=False)
    sync_kwargs, _ = _patch_sync_client(monkeypatch)
    assert cli._healthz(_healthz_args(verify=True)) == 0
    assert sync_kwargs["verify"] is True

    async_kwargs, _ = _patch_async_client(monkeypatch)
    assert cli._triage(_triage_args(verify=True)) == 0
    assert async_kwargs["verify"] is True


def test_cafile_pins_verify_to_bundle_path(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SOC_AI_API_TOKEN", raising=False)
    sync_kwargs, _ = _patch_sync_client(monkeypatch)
    assert cli._healthz(_healthz_args(cafile="/etc/pki/lab-ca.pem")) == 0
    assert sync_kwargs["verify"] == "/etc/pki/lab-ca.pem"


def test_verify_defaults_to_false_without_flags(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SOC_AI_API_TOKEN", raising=False)
    async_kwargs, _ = _patch_async_client(monkeypatch)
    assert cli._triage(_triage_args()) == 0
    assert async_kwargs["verify"] is False


def test_triage_warns_on_stderr_when_token_sent_without_tls_verify(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """A Bearer token sent over an unverified TLS connection (the default) must
    print a loud stderr warning (F35) — silent token-over-untrusted-cert lets an
    on-path attacker harvest a fully-privileged API credential unnoticed.
    """
    monkeypatch.delenv("SOC_AI_API_TOKEN", raising=False)
    _patch_async_client(monkeypatch)
    rc = cli._triage(_triage_args(token="scai_flagtoken"))
    assert rc == 0
    err = capsys.readouterr().err
    assert "WARNING" in err
    assert "verify" in err.lower()


def test_healthz_warns_on_stderr_when_token_sent_without_tls_verify(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.delenv("SOC_AI_API_TOKEN", raising=False)
    _patch_sync_client(monkeypatch)
    rc = cli._healthz(_healthz_args(token="scai_flagtoken"))
    assert rc == 0
    err = capsys.readouterr().err
    assert "WARNING" in err


def test_no_insecure_auth_warning_when_verify_enabled(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.delenv("SOC_AI_API_TOKEN", raising=False)
    _patch_sync_client(monkeypatch)
    rc = cli._healthz(_healthz_args(token="scai_flagtoken", verify=True))
    assert rc == 0
    err = capsys.readouterr().err
    assert "WARNING" not in err


def test_no_insecure_auth_warning_when_no_token(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.delenv("SOC_AI_API_TOKEN", raising=False)
    _patch_sync_client(monkeypatch)
    rc = cli._healthz(_healthz_args())
    assert rc == 0
    err = capsys.readouterr().err
    assert "WARNING" not in err


def test_triage_and_healthz_parsers_accept_auth_flags() -> None:
    """The flags are actually registered on both subparsers (wiring check)."""
    # Reuse main()'s parser construction indirectly: build via _add_api_client_args
    # on a fresh parser mirrors the registration; also smoke-parse real argv shapes.
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="cmd")
    t = sub.add_parser("triage")
    t.add_argument("alert_id")
    t.add_argument("--url", default=None)
    cli._add_api_client_args(t)
    h = sub.add_parser("healthz")
    h.add_argument("--url", default=None)
    cli._add_api_client_args(h)

    args = p.parse_args(["triage", "abc", "--token", "scai_x", "--verify"])
    assert args.token == "scai_x"
    assert args.verify is True
    args = p.parse_args(["healthz", "--cafile", "/tmp/ca.pem"])
    assert args.cafile == "/tmp/ca.pem"


def test_stream_investigation_renders_done_event(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """End-to-end through the SSE parse loop with the mocked transport."""
    monkeypatch.delenv("SOC_AI_API_TOKEN", raising=False)
    _patch_async_client(monkeypatch)
    rc = asyncio.run(cli._stream_investigation("https://127.0.0.1:8443", "abc", token="scai_t"))
    assert rc == 0
    out = _strip_ansi(capsys.readouterr().out)
    assert "done" in out
    assert "recommended_count=0" in out


def test_python_dash_m_invocation_runs_main() -> None:
    """``python -m soc_ai.cli …`` must execute main(), not silently import-and-exit-0.

    Live-test regression (2026-07-04): without a ``__main__`` guard the module
    invocation imported cli.py, did nothing, and exited 0 — a triage command
    that "succeeded" without ever contacting the API.
    """
    import subprocess
    import sys

    proc = subprocess.run(
        [sys.executable, "-m", "soc_ai.cli", "healthz", "--url", "https://127.0.0.1:1"],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    # main() running means the unreachable healthz URL fails loudly (non-zero);
    # the silent-import bug exits 0 with no output.
    assert proc.returncode != 0, (
        f"expected a non-zero exit from an unreachable healthz, got 0 "
        f"(stdout={proc.stdout!r}, stderr={proc.stderr!r})"
    )

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
from unittest.mock import AsyncMock, patch

import httpx
import pytest
from pydantic import SecretStr
from soc_ai import cli
from soc_ai.audit.verify import ChainVerifyResult
from soc_ai.cli import _render_event
from soc_ai.config import Settings


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


# The real server shape (soc_ai/api/security.py::require_api_auth, no_session
# arm), wrapped the way FastAPI's default HTTPException handler serializes
# `detail=` — see tests/test_degraded_grid_panels.py for the same `["detail"]`
# unwrapping convention against a real app.
_NO_SESSION_401_BODY = {
    "detail": {
        "reason": "no_session",
        "hint": "Log in at /app/login or send 'Authorization: Bearer scai_…'.",
    }
}


def _patch_async_client(
    monkeypatch: pytest.MonkeyPatch, *, status: int = 200
) -> tuple[dict[str, Any], list[httpx.Request]]:
    """Swap cli's httpx.AsyncClient for one that captures kwargs + requests.

    ``status`` overrides the canned 200 SSE response with the real
    ``no_session`` 401 JSON shape (to simulate an unauthenticated deployment).
    """
    captured_kwargs: dict[str, Any] = {}
    captured_requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured_requests.append(request)
        if status != 200:
            return httpx.Response(status, json=_NO_SESSION_401_BODY)
        return httpx.Response(200, text=_SSE_BODY, headers={"content-type": "text/event-stream"})

    class _Client(httpx.AsyncClient):
        def __init__(self, **kwargs: Any) -> None:
            captured_kwargs.update(kwargs)
            super().__init__(transport=httpx.MockTransport(handler))

    monkeypatch.setattr(cli.httpx, "AsyncClient", _Client)
    return captured_kwargs, captured_requests


def _patch_sync_client(
    monkeypatch: pytest.MonkeyPatch, *, status: int = 200
) -> tuple[dict[str, Any], list[httpx.Request]]:
    """Swap cli's httpx.Client for one that captures kwargs + requests.

    ``status`` overrides the canned 200 response with the real ``no_session``
    401 JSON shape (to simulate an unauthenticated deployment).
    """
    captured_kwargs: dict[str, Any] = {}
    captured_requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured_requests.append(request)
        if status != 200:
            return httpx.Response(status, json=_NO_SESSION_401_BODY)
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


def test_triage_prints_actionable_hint_on_401_with_no_token(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Fresh-VM regression (2026-08-20, F2): ``docker exec soc-ai python -m soc_ai
    triage <id>`` on an ``API_AUTH_REQUIRED=true`` (shipped-default) install dumped
    the raw server JSON with no clue what a CLI caller should actually do about it.
    A 401 sent with no Authorization header now also gets one line naming the fix.
    """
    monkeypatch.delenv("SOC_AI_API_TOKEN", raising=False)
    _patch_async_client(monkeypatch, status=401)
    rc = cli._triage(_triage_args())
    assert rc == 2
    err = capsys.readouterr().err
    assert "SOC_AI_API_TOKEN" in err
    assert "--token" in err
    assert "API tokens" in err


def test_healthz_prints_actionable_hint_on_401_with_no_token(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.delenv("SOC_AI_API_TOKEN", raising=False)
    _patch_sync_client(monkeypatch, status=401)
    rc = cli._healthz(_healthz_args())
    assert rc == 1
    err = capsys.readouterr().err
    assert "SOC_AI_API_TOKEN" in err
    assert "--token" in err
    assert "API tokens" in err


def test_no_401_hint_once_a_token_was_already_sent(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """A 401 that comes back AFTER the CLI attached a token is a bad/expired/
    revoked token (the server's own ``invalid_token`` hint already covers that
    case correctly) — not a missing one, so the "set SOC_AI_API_TOKEN" line
    must not appear; it would be actively wrong when a token was already sent.
    """
    monkeypatch.delenv("SOC_AI_API_TOKEN", raising=False)
    _patch_sync_client(monkeypatch, status=401)
    rc = cli._healthz(_healthz_args(token="scai_badtoken"))
    assert rc == 1
    err = capsys.readouterr().err
    assert "SOC_AI_API_TOKEN" not in err

    _patch_async_client(monkeypatch, status=401)
    rc = cli._triage(_triage_args(token="scai_badtoken"))
    assert rc == 2
    err = capsys.readouterr().err
    assert "SOC_AI_API_TOKEN" not in err


def test_no_401_hint_on_a_healthy_response(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The over-correction control: a 200 must never print the auth hint."""
    monkeypatch.delenv("SOC_AI_API_TOKEN", raising=False)
    _patch_sync_client(monkeypatch)
    rc = cli._healthz(_healthz_args())
    assert rc == 0
    assert "SOC_AI_API_TOKEN" not in capsys.readouterr().err


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


# ── `soc-ai audit verify` — epoch-aware tri-state rendering ────────────────────
#
# `_audit_verify` is not an SSE-stream printer like the rest of this file, but
# it IS a `soc_ai.cli` function with its own capsys-checkable stdout/stderr
# contract, and the epoch partition (soc_ai/audit/verify.py) added a THIRD
# verdict color — amber, for "no tamper found, but not one unbroken chain" —
# beside the existing green/red pair. `verify_audit_chain` is mocked at its
# import site (the same module `_audit_verify` lazily imports from at call
# time), so these tests are purely about the CLI's rendering decision; the ES
# fetch/partition/verify_chain logic behind a real result is already covered
# end-to-end in tests/test_audit_verify.py.


def _cli_settings() -> Settings:
    return Settings(
        so_host="https://so.example.com",
        so_username="analyst",
        so_password=SecretStr("password123"),
        so_verify_ssl=False,
        es_hosts=["https://so.example.com:9200"],
        litellm_base_url="http://localhost:4000",
        api_auth_required=False,
    )


def test_audit_verify_single_epoch_intact_is_green(capsys: pytest.CaptureFixture[str]) -> None:
    """No regression: the ordinary (epochs<=1) intact case keeps its green line."""
    result = ChainVerifyResult(
        ok=True,
        records_verified=5,
        first_broken_seq=None,
        first_seq=0,
        last_seq=4,
        capped=False,
        epochs=1,
        first_broken_epoch_start=None,
        epochs_broken=0,
        newest_broken_epoch_start=None,
        latest_epoch_broken=False,
    )
    with (
        patch("soc_ai.cli.get_settings", return_value=_cli_settings()),
        patch("soc_ai.audit.verify.verify_audit_chain", AsyncMock(return_value=result)),
    ):
        rc = cli._audit_verify(argparse.Namespace(days=None))
    assert rc == 0
    out = _strip_ansi(capsys.readouterr().out)
    assert "audit chain intact" in out
    assert "5 records verified" in out
    assert "epoch" not in out.lower()  # no epoch caveat on the unremarkable case


def test_audit_verify_multi_epoch_intact_is_amber_not_green(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """epochs>1 && ok prints its own amber line — never the green 'chain intact' one.

    House rule: a partial all-clear never wears full success livery. Restart
    boundaries are legitimate (prod carried 134 of them from the chain-head
    recovery bug fixed 2026-08-17), but cross-epoch linkage is unprovable, so
    this is a strictly weaker claim than the single-epoch green line and must
    render as one.
    """
    result = ChainVerifyResult(
        ok=True,
        records_verified=9,
        first_broken_seq=None,
        first_seq=0,
        last_seq=4,
        capped=False,
        epochs=3,
        first_broken_epoch_start=None,
        epochs_broken=0,
        newest_broken_epoch_start=None,
        latest_epoch_broken=False,
    )
    with (
        patch("soc_ai.cli.get_settings", return_value=_cli_settings()),
        patch("soc_ai.audit.verify.verify_audit_chain", AsyncMock(return_value=result)),
    ):
        rc = cli._audit_verify(argparse.Namespace(days=None))
    assert rc == 0
    out = _strip_ansi(capsys.readouterr().out)
    assert "intact within 3 epochs" in out
    assert "9 records verified" in out
    assert "2026-08-17" in out  # names the historical why, not just the count
    # The green line's exact prefix must be absent — this is a different line,
    # not the same one with extra words appended.
    assert "audit chain intact —" not in out


def test_audit_verify_capped_single_epoch_still_uses_the_pre_epoch_warning(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """No regression: a capped-but-single-epoch scan keeps its existing warning.

    Distinct from the multi-epoch amber line above — this is the pre-existing
    "hit the record cap" caveat, unrelated to whether more than one process
    incarnation is in play.
    """
    result = ChainVerifyResult(
        ok=True,
        records_verified=10,
        first_broken_seq=None,
        first_seq=0,
        last_seq=9,
        capped=True,
        epochs=1,
        first_broken_epoch_start=None,
        epochs_broken=0,
        newest_broken_epoch_start=None,
        latest_epoch_broken=False,
    )
    with (
        patch("soc_ai.cli.get_settings", return_value=_cli_settings()),
        patch("soc_ai.audit.verify.verify_audit_chain", AsyncMock(return_value=result)),
    ):
        rc = cli._audit_verify(argparse.Namespace(days=None))
    assert rc == 0
    captured = capsys.readouterr()  # one snapshot — a second call would read empty
    err = _strip_ansi(captured.err)
    out = _strip_ansi(captured.out)
    assert "hit the record cap" in err
    assert "audit chain intact" in out
    assert "epoch" not in out.lower()


def test_audit_verify_tampered_names_the_broken_epoch(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A tamper verdict now locates WHICH epoch broke, not just which local seq.

    ``first_broken_seq`` alone is ambiguous once more than one epoch exists (it
    resets to 0 at every genesis); ``first_broken_epoch_start`` is what actually
    lets an operator find the right restart's trail. This is the "one break,
    clean since" shape — ``latest_epoch_broken=False`` — so the reassurance
    sentence fires.
    """
    result = ChainVerifyResult(
        ok=False,
        records_verified=7,
        first_broken_seq=2,
        first_seq=0,
        last_seq=3,
        capped=False,
        epochs=2,
        first_broken_epoch_start="2026-08-01T00:00:00+00:00",
        epochs_broken=1,
        newest_broken_epoch_start="2026-08-01T00:00:00+00:00",
        latest_epoch_broken=False,
    )
    with (
        patch("soc_ai.cli.get_settings", return_value=_cli_settings()),
        patch("soc_ai.audit.verify.verify_audit_chain", AsyncMock(return_value=result)),
    ):
        rc = cli._audit_verify(argparse.Namespace(days=None))
    assert rc == 1
    err = _strip_ansi(capsys.readouterr().err)
    assert "TAMPER DETECTED" in err
    assert "seq 2" in err
    assert "2026-08-01T00:00:00+00:00" in err
    assert "1 of 2 epochs broken" in err
    assert "Every epoch after 2026-08-01T00:00:00+00:00 verified intact" in err
    assert "the latest epoch is broken" not in err.lower()


def test_audit_verify_tampered_single_epoch_still_names_its_start(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The epoch-location wording also applies to the ordinary single-epoch break —
    it is strictly more information than the old "chain broke at seq S" alone.
    A single-epoch scan's one break is trivially both oldest and latest."""
    result = ChainVerifyResult(
        ok=False,
        records_verified=3,
        first_broken_seq=2,
        first_seq=0,
        last_seq=2,
        capped=False,
        epochs=1,
        first_broken_epoch_start="2026-07-11T00:00:00+00:00",
        epochs_broken=1,
        newest_broken_epoch_start="2026-07-11T00:00:00+00:00",
        latest_epoch_broken=True,
    )
    with (
        patch("soc_ai.cli.get_settings", return_value=_cli_settings()),
        patch("soc_ai.audit.verify.verify_audit_chain", AsyncMock(return_value=result)),
    ):
        rc = cli._audit_verify(argparse.Namespace(days=None))
    assert rc == 1
    err = _strip_ansi(capsys.readouterr().err)
    assert "seq 2" in err
    assert "2026-07-11T00:00:00+00:00" in err
    assert "1 of 1 epochs broken" in err
    assert "The latest epoch is broken." in err


def test_audit_verify_two_epochs_broken_reports_the_tally(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Two broken epochs: the tally names both the oldest AND the newest break.

    This is the shape prod's actual finding takes once every epoch is checked:
    a real duplicate-seq artifact from the historic pre-1.2.8 write-side
    stale-head seq-reuse bug, possibly alongside another scar elsewhere in 134
    epochs of history — an operator needs the COUNT and the newest one's
    location, not just proof that at least one thing broke somewhere.
    """
    result = ChainVerifyResult(
        ok=False,
        records_verified=20,
        first_broken_seq=1,
        first_seq=0,
        last_seq=3,
        capped=False,
        epochs=5,
        first_broken_epoch_start="2026-06-26T21:55:52+00:00",
        epochs_broken=2,
        newest_broken_epoch_start="2026-06-27T02:13:00+00:00",
        latest_epoch_broken=False,
    )
    with (
        patch("soc_ai.cli.get_settings", return_value=_cli_settings()),
        patch("soc_ai.audit.verify.verify_audit_chain", AsyncMock(return_value=result)),
    ):
        rc = cli._audit_verify(argparse.Namespace(days=None))
    assert rc == 1
    err = _strip_ansi(capsys.readouterr().err)
    assert "2 of 5 epochs broken" in err
    assert "oldest break seq 1 (epoch 2026-06-26T21:55:52+00:00)" in err
    assert "newest broken epoch 2026-06-27T02:13:00+00:00" in err
    assert "Every epoch after 2026-06-27T02:13:00+00:00 verified intact" in err


def test_audit_verify_latest_epoch_broken_says_so_loudly(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """When the MOST RECENT epoch is the broken one, no reassurance is offered —
    there is nothing intact "after" it to point to."""
    result = ChainVerifyResult(
        ok=False,
        records_verified=10,
        first_broken_seq=1,
        first_seq=0,
        last_seq=3,
        capped=False,
        epochs=3,
        first_broken_epoch_start="2026-08-19T00:00:00+00:00",
        epochs_broken=1,
        newest_broken_epoch_start="2026-08-19T00:00:00+00:00",
        latest_epoch_broken=True,
    )
    with (
        patch("soc_ai.cli.get_settings", return_value=_cli_settings()),
        patch("soc_ai.audit.verify.verify_audit_chain", AsyncMock(return_value=result)),
    ):
        rc = cli._audit_verify(argparse.Namespace(days=None))
    assert rc == 1
    err = _strip_ansi(capsys.readouterr().err)
    assert "1 of 3 epochs broken" in err
    assert "The latest epoch is broken." in err
    assert "verified intact" not in err


def test_audit_verify_capped_tampered_does_not_claim_everything_after_is_fine(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A capped scan cannot vouch for epochs it never fetched.

    The cap truncates the NEWEST end of the chain (the fetch is oldest-first),
    so a capped scan's last FETCHED epoch is not provably the chain's actual
    latest epoch — there could be more, unseen, beyond the cap. Neither "every
    epoch after X verified intact" nor "the latest epoch is broken" is a claim
    this scan can honestly make, whichever way ``latest_epoch_broken`` happens
    to land for the prefix it did see.
    """
    result = ChainVerifyResult(
        ok=False,
        records_verified=8,
        first_broken_seq=1,
        first_seq=0,
        last_seq=2,
        capped=True,
        epochs=2,
        first_broken_epoch_start="2026-06-26T21:55:52+00:00",
        epochs_broken=1,
        newest_broken_epoch_start="2026-06-26T21:55:52+00:00",
        latest_epoch_broken=False,
    )
    with (
        patch("soc_ai.cli.get_settings", return_value=_cli_settings()),
        patch("soc_ai.audit.verify.verify_audit_chain", AsyncMock(return_value=result)),
    ):
        rc = cli._audit_verify(argparse.Namespace(days=None))
    assert rc == 1
    captured = capsys.readouterr()
    err = _strip_ansi(captured.err)
    assert "1 of 2 epochs broken" in err
    assert "hit the record cap" in err  # the existing standalone capped warning
    assert "verified intact" not in err
    assert "the latest epoch is broken" not in err.lower()

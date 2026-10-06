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
import logging
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


@pytest.fixture(autouse=True)
def _no_recorded_finding_read() -> Any:
    """The CLI reads the newest recorded chain finding after a windowed scan.

    These tests mock the verifier and point at a host that does not exist, so
    that one extra read is stubbed here: no test in this file dials out.
    """
    with patch("soc_ai.audit.verify.recorded_older_duplicate", AsyncMock(return_value=None)):
        yield


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
    # No altered record in this fixture, so the honest headline is the weaker
    # one. Both exit 1; the headline says which of the two to go looking for.
    assert "CHAIN BROKEN" in err
    assert "TAMPER DETECTED" not in err
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
    assert "oldest break is at seq 1 in epoch 2026-06-26T21:55:52+00:00" in err
    assert "newest broken epoch is 2026-06-27T02:13:00+00:00" in err
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


# --------------------------------------------------------------------
# validate-batch --repeats (repeated runs per synth scenario)
# --------------------------------------------------------------------


def test_validate_batch_parser_accepts_repeats(monkeypatch: pytest.MonkeyPatch) -> None:
    """--repeats parses (default 1, explicit N, reject < 1) and reaches the
    validate-batch handler."""
    captured: dict[str, Any] = {}

    def fake_validate_batch(args: argparse.Namespace) -> int:
        captured["args"] = args
        return 0

    monkeypatch.setattr(cli, "_validate_batch", fake_validate_batch)

    monkeypatch.setattr(
        "sys.argv",
        ["soc-ai", "validate-batch", "--oql", "q", "--synth-set", "all", "--repeats", "3"],
    )
    with pytest.raises(SystemExit) as ei:
        cli.main()
    assert ei.value.code == 0
    assert captured["args"].repeats == 3

    monkeypatch.setattr("sys.argv", ["soc-ai", "validate-batch", "--oql", "q"])
    with pytest.raises(SystemExit) as ei:
        cli.main()
    assert ei.value.code == 0
    assert captured["args"].repeats == 1

    # argparse rejects a non-positive count before the handler runs.
    captured.clear()
    monkeypatch.setattr("sys.argv", ["soc-ai", "validate-batch", "--oql", "q", "--repeats", "0"])
    with pytest.raises(SystemExit) as ei:
        cli.main()
    assert ei.value.code == 2
    assert "args" not in captured


def test_validate_batch_wires_repeats_into_batch_config(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Any,
    settings_kratos: Settings,
) -> None:
    """args.repeats lands on BatchConfig.synth_repeats (the one wire the
    parser test can't see)."""
    import soc_ai.eval.batch as batch_mod
    import soc_ai.so_client.elastic as elastic_mod
    from soc_ai.eval.batch import BatchConfig, BatchSummary

    captured: dict[str, Any] = {}

    async def fake_run_batch(cfg: BatchConfig, **_kw: Any) -> BatchSummary:
        captured["cfg"] = cfg
        return BatchSummary(
            batch_dir=tmp_path,
            n_planned=1,
            n_attempted=1,
            n_ok=1,
            n_error=0,
            aborted_reason=None,
            elapsed_s=1,
        )

    class _FakeElastic:
        def __init__(self, _settings: Settings) -> None:
            pass

        async def aclose(self) -> None:
            pass

    monkeypatch.setattr(batch_mod, "run_batch", fake_run_batch)
    monkeypatch.setattr(elastic_mod, "ElasticClient", _FakeElastic)
    monkeypatch.setattr(cli, "get_settings", lambda: settings_kratos)

    args = argparse.Namespace(
        oql="q",
        n=1,
        concurrency=1,
        diversity_keys="rule.name",
        time_range_minutes=60,
        out_dir=str(tmp_path),
        resume=False,
        per_run_timeout_s=10,
        max_consecutive_failures=3,
        synth_set=None,
        repeats=4,
        no_aggregate=True,
        no_meta=True,
    )
    assert cli._validate_batch(args) == 0
    assert captured["cfg"].synth_repeats == 4


@pytest.mark.parametrize("local", [True, False])
def test_validate_batch_local_skips_the_oracle_grade(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Any,
    settings_kratos: Settings,
    local: bool,
) -> None:
    """--local hands run_batch a runner bound to grade=False; without it the
    runner grades. The runner is the only wire that carries the choice."""
    import functools

    import soc_ai.eval.batch as batch_mod
    import soc_ai.so_client.elastic as elastic_mod
    from soc_ai.eval.batch import BatchConfig, BatchSummary

    captured: dict[str, Any] = {}

    async def fake_run_batch(cfg: BatchConfig, **kw: Any) -> BatchSummary:
        captured["runner"] = kw.get("runner")
        return BatchSummary(
            batch_dir=tmp_path,
            n_planned=1,
            n_attempted=1,
            n_ok=1,
            n_error=0,
            aborted_reason=None,
            elapsed_s=1,
        )

    class _FakeElastic:
        def __init__(self, _settings: Settings) -> None:
            pass

        async def aclose(self) -> None:
            pass

    monkeypatch.setattr(batch_mod, "run_batch", fake_run_batch)
    monkeypatch.setattr(elastic_mod, "ElasticClient", _FakeElastic)
    monkeypatch.setattr(cli, "get_settings", lambda: settings_kratos)

    args = argparse.Namespace(
        oql="q",
        n=1,
        concurrency=1,
        diversity_keys="rule.name",
        time_range_minutes=60,
        out_dir=str(tmp_path),
        resume=False,
        per_run_timeout_s=10,
        max_consecutive_failures=3,
        synth_set=None,
        repeats=1,
        no_aggregate=True,
        no_meta=True,
        local=local,
    )
    assert cli._validate_batch(args) == 0
    runner = captured["runner"]
    assert isinstance(runner, functools.partial)
    assert runner.keywords == {"grade": not local}


def test_spec_sweep_runs_the_command_the_console_prints(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`soc-ai spec-sweep --shadow` must run as printed.

    The Operate hub's catalog panel and the config console both tell an
    operator to type exactly that, and `--since` being required meant both
    hints exited 2 on an argparse error. Caught by dogfooding 1.5.1 against
    the range, where the first thing anyone types is the string the UI shows.
    """
    captured: dict[str, Any] = {}

    def fake_spec_sweep(args: argparse.Namespace) -> int:
        captured["args"] = args
        return 0

    monkeypatch.setattr(cli, "_spec_sweep", fake_spec_sweep)
    monkeypatch.setattr("sys.argv", ["soc-ai", "spec-sweep", "--shadow"])
    with pytest.raises(SystemExit) as ei:
        cli.main()
    assert ei.value.code == 0, "the command the console prints did not parse"
    assert captured["args"].since is None, "an unset window must reach the handler as None"
    assert captured["args"].shadow is True


def test_spec_sweep_defaults_its_window_to_the_configured_look_back(
    monkeypatch: pytest.MonkeyPatch, settings_kratos: Settings, caplog: pytest.LogCaptureFixture
) -> None:
    """The default is the scheduler's own window, widened past the interval.

    A window narrower than the interval examines five minutes in every sixty
    and calls the other fifty-five clean, which is the gap the loop already
    clamps. The CLI has to clamp it the same way or the two disagree about
    what one sweep covers: it used to widen without flooring the interval, so
    with interval=0 in the environment it compared a 3-minute window against
    zero, found it wider, and swept three minutes where the loop swept six.
    And it has to SAY so, as the loop does, or only one of the two paths
    tells the operator their settings do not fit together.
    """
    seen: dict[str, Any] = {}

    async def fake_sweep_catalog(_catalog: Any, **kwargs: Any) -> Any:
        seen.update(kwargs)
        from soc_ai.hunting.sweep import SweepResult

        return SweepResult()

    def run(window: int, interval: int) -> str:
        settings = settings_kratos.model_copy(
            update={
                "hunt_spec_sweep_window_minutes": window,
                "hunt_spec_sweep_interval_minutes": interval,
            }
        )
        monkeypatch.setattr(cli, "get_settings", lambda: settings)
        monkeypatch.setattr("soc_ai.hunting.sweep.sweep_catalog", fake_sweep_catalog)
        args = argparse.Namespace(
            since=None, until="now", shadow=True, backfill=False, include_synth=False
        )
        cli._spec_sweep(args)
        return str(seen["since"])

    with caplog.at_level(logging.WARNING):
        assert run(1440, 60) == "now-1440m"
        assert not [r for r in caplog.records if "spec sweep" in r.getMessage()], (
            "nothing to warn about when the window is wider than the interval"
        )
        assert run(5, 60) == "now-61m", "a window narrower than the interval left an unexamined gap"
        assert run(3, 0) == "now-6m", "the interval is floored at 5 before the window is clamped"
    said = [r.getMessage() for r in caplog.records if "spec sweep" in r.getMessage()]
    assert len(said) == 2, "the widening is said once per widened sweep, and not otherwise"
    assert "(5m)" in said[0] and "(60m)" in said[0] and "61m" in said[0]
    assert "(3m)" in said[1] and "(5m)" in said[1] and "6m" in said[1]

    # An explicit window still wins.
    monkeypatch.setattr(cli, "get_settings", lambda: settings_kratos)
    cli._spec_sweep(
        argparse.Namespace(
            since="now-7d", until="now", shadow=True, backfill=False, include_synth=False
        )
    )
    assert seen["since"] == "now-7d"


def test_spec_run_include_synth_parses_and_reaches_run_spec(
    monkeypatch: pytest.MonkeyPatch, settings_kratos: Settings
) -> None:
    """`--include-synth` has to arrive at run_spec, not stop at the handler.

    The four no-alert fixtures exist because the catalog detects attacks that
    never become an alert, and run_spec has taken a SynthScope since the
    catalog landed. Neither shipped command passed it, so documents planted
    into logs-synth-* were invisible to everything an operator can type and a
    spec could not be checked against a live grid. Caught by dogfooding 1.5.1
    against the range. The flag stays off by default: production hunting must
    never see planted evaluation data.
    """
    real_spec_run = cli._spec_run
    captured: dict[str, Any] = {}

    def fake_spec_run(args: argparse.Namespace) -> int:
        captured["args"] = args
        return 0

    monkeypatch.setattr(cli, "_spec_run", fake_spec_run)
    monkeypatch.setattr("sys.argv", ["soc-ai", "spec-run", "--since", "now-1d"])
    with pytest.raises(SystemExit):
        cli.main()
    assert captured["args"].include_synth is False, "the default must be off"

    monkeypatch.setattr(
        "sys.argv", ["soc-ai", "spec-run", "some-spec", "--since", "now-1d", "--include-synth"]
    )
    with pytest.raises(SystemExit):
        cli.main()
    assert captured["args"].include_synth is True
    assert captured["args"].spec_id == "some-spec", "the switch must not eat the spec id"

    # The wire: the handler passes the value on to run_spec.
    seen: list[dict[str, Any]] = []

    async def fake_run_spec(spec: Any, **kwargs: Any) -> Any:
        from soc_ai.hunting.execute import SpecRun

        seen.append(kwargs)
        return SpecRun(
            spec_id=spec.id, since="a", until="b", blind=False, precondition_docs=1, matched_docs=0
        )

    monkeypatch.setattr(cli, "get_settings", lambda: settings_kratos)
    monkeypatch.setattr("soc_ai.hunting.execute.run_spec", fake_run_spec)
    for scope in (True, False):
        args = argparse.Namespace(
            spec_id="identity-4662-dcsync-nonmachine",
            since="now-1d",
            until="now",
            include_synth=scope,
        )
        assert real_spec_run(args) == 0
        assert seen[-1]["include_synth"] is scope, "the flag never reached run_spec"


def test_spec_sweep_include_synth_parses_and_reaches_sweep_catalog(
    monkeypatch: pytest.MonkeyPatch, settings_kratos: Settings
) -> None:
    """Same wire, other command: `--include-synth` must reach sweep_catalog."""
    real_spec_sweep = cli._spec_sweep
    captured: dict[str, Any] = {}

    def fake_spec_sweep(args: argparse.Namespace) -> int:
        captured["args"] = args
        return 0

    monkeypatch.setattr(cli, "_spec_sweep", fake_spec_sweep)
    monkeypatch.setattr("sys.argv", ["soc-ai", "spec-sweep", "--shadow"])
    with pytest.raises(SystemExit):
        cli.main()
    assert captured["args"].include_synth is False, "the default must be off"

    monkeypatch.setattr("sys.argv", ["soc-ai", "spec-sweep", "--shadow", "--include-synth"])
    with pytest.raises(SystemExit):
        cli.main()
    assert captured["args"].include_synth is True

    seen: dict[str, Any] = {}

    async def fake_sweep_catalog(_catalog: Any, **kwargs: Any) -> Any:
        from soc_ai.hunting.sweep import SweepResult

        seen.update(kwargs)
        return SweepResult()

    monkeypatch.setattr(cli, "get_settings", lambda: settings_kratos)
    monkeypatch.setattr("soc_ai.hunting.sweep.sweep_catalog", fake_sweep_catalog)
    for scope in (True, False):
        args = argparse.Namespace(
            since="now-1d", until="now", shadow=True, backfill=False, include_synth=scope
        )
        assert real_spec_sweep(args) == 0
        assert seen["include_synth"] is scope, "the flag never reached sweep_catalog"


def test_audit_verify_tamper_names_what_broke(capsys: pytest.CaptureFixture[str]) -> None:
    """The tamper verdict says which kind of damage, not just that there is some.

    Two writers claiming one position and a record edited after the fact both
    used to print "a record was edited, reordered, inserted, or deleted". On a
    deployment carrying the known concurrency fork, that sentence is also what
    would greet a real alteration.
    """
    result = ChainVerifyResult(
        ok=False,
        records_verified=15122,
        first_broken_seq=109667,
        first_seq=94545,
        last_seq=109667,
        capped=False,
        epochs=1,
        first_broken_epoch_start="2026-09-04T02:32:07Z",
        epochs_broken=1,
        newest_broken_epoch_start="2026-09-04T02:32:07Z",
        latest_epoch_broken=True,
        first_break_kind="duplicate_seq",
        first_break_detail=(
            "2 records claim sequence 109667, and each one still matches its own hash — "
            "the records were not altered; two writers continued the chain from the same point"
        ),
        newest_break_kind="duplicate_seq",
        newest_break_detail=(
            "2 records claim sequence 109667, and each one still matches its own hash — "
            "the records were not altered; two writers continued the chain from the same point"
        ),
    )
    with (
        patch("soc_ai.cli.get_settings", return_value=_cli_settings()),
        patch("soc_ai.audit.verify.verify_audit_chain", AsyncMock(return_value=result)),
    ):
        rc = cli._audit_verify(argparse.Namespace(days=3))
    # Two writers, every copy still hashing true. This printed "TAMPER
    # DETECTED", then "CHAIN BROKEN" with exit 1, while --help says 1 means
    # tamper. Duplicates only is its own condition: exit 3, its own headline.
    assert rc == 3
    err = _strip_ansi(capsys.readouterr().err)
    assert "DUPLICATE SEQUENCE NUMBERS" in err
    assert "duplicate sequence numbers; no record was altered" in err
    assert "CHAIN BROKEN" not in err
    assert "TAMPER DETECTED" not in err
    assert "two writers continued the chain from the same point" in err
    # And the operator is told how to check it themselves, since this shape is
    # the one that is usually NOT an intrusion.
    assert "Compare the timestamps and sessions" in err


def test_audit_verify_tamper_on_an_edit_does_not_offer_the_concurrency_reading(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The negative control for the test above.

    An altered record must not be handed the "this is probably two writers"
    hint — that hint is the one thing that could talk an operator out of
    treating a real edit as an emergency.
    """
    result = ChainVerifyResult(
        ok=False,
        records_verified=42,
        first_broken_seq=17,
        first_seq=0,
        last_seq=41,
        capped=False,
        epochs=1,
        first_broken_epoch_start="2026-09-04T02:32:07Z",
        epochs_broken=1,
        newest_broken_epoch_start="2026-09-04T02:32:07Z",
        latest_epoch_broken=True,
        first_break_kind="content_altered",
        first_break_detail=(
            "the record at sequence 17 no longer matches its own hash — its content was "
            "changed after it was written"
        ),
        newest_break_kind="content_altered",
        newest_break_detail=(
            "the record at sequence 17 no longer matches its own hash — its content was "
            "changed after it was written"
        ),
    )
    with (
        patch("soc_ai.cli.get_settings", return_value=_cli_settings()),
        patch("soc_ai.audit.verify.verify_audit_chain", AsyncMock(return_value=result)),
    ):
        rc = cli._audit_verify(argparse.Namespace(days=None))
    assert rc == 1
    err = _strip_ansi(capsys.readouterr().err)
    assert "content was changed after it was written" in err
    assert "two writers" not in err


def test_audit_verify_says_tamper_when_a_record_no_longer_hashes_true(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The headline that must survive the weaker one being introduced.

    A duplicated position is two writers; a record whose content no longer
    matches its own hash is someone changing the record of a decision. Softening
    the first must not soften the second, so this is the control: altered_records
    non-zero still gets the full word, and still exits 1.
    """
    from soc_ai.audit.verify import ChainVerifyResult

    result = ChainVerifyResult(
        ok=False,
        records_verified=900,
        first_broken_seq=7,
        first_seq=0,
        last_seq=899,
        capped=False,
        epochs=1,
        first_broken_epoch_start="2026-08-01T00:00:00+00:00",
        epochs_broken=1,
        newest_broken_epoch_start="2026-08-01T00:00:00+00:00",
        latest_epoch_broken=True,
        first_break_kind="content_altered",
        first_break_detail="1 record no longer matches its own hash",
        newest_break_kind="content_altered",
        newest_break_detail="1 record no longer matches its own hash",
        altered_records=1,
        break_kinds=("content_altered",),
    )
    with (
        patch("soc_ai.cli.get_settings", return_value=_cli_settings()),
        patch("soc_ai.audit.verify.verify_audit_chain", AsyncMock(return_value=result)),
    ):
        rc = cli._audit_verify(argparse.Namespace(days=None))
    assert rc == 1
    err = _strip_ansi(capsys.readouterr().err)
    assert "TAMPER DETECTED" in err
    assert "CHAIN BROKEN" not in err


# ── soc-ai leads --report ────────────────────────────────────────────────────


def test_leads_report_parses_as_the_docs_print_it(monkeypatch: pytest.MonkeyPatch) -> None:
    """`soc-ai leads --report` must run as written, with the default window."""
    captured: dict[str, Any] = {}

    def fake_leads(args: argparse.Namespace) -> int:
        captured["args"] = args
        return 0

    monkeypatch.setattr(cli, "_leads", fake_leads)
    monkeypatch.setattr("sys.argv", ["soc-ai", "leads", "--report"])
    with pytest.raises(SystemExit) as ei:
        cli.main()
    assert ei.value.code == 0
    assert captured["args"].report is True
    assert captured["args"].weeks == 4


def test_leads_without_a_mode_says_so_and_does_not_read_the_store() -> None:
    """A bare `soc-ai leads` names the mode it needs rather than printing nothing."""
    assert cli._leads(argparse.Namespace(report=False, weeks=4)) == 2


def test_format_lead_quality_prints_the_weeks_the_types_and_the_rule() -> None:
    """The table carries the same numbers, the rule and the noise floor."""
    from soc_ai.api.webui.routes_hunts import (
        LeadQualityOut,
        LeadQualityTypesOut,
        LeadQualityWeekOut,
    )

    report = LeadQualityOut(
        weeks=[
            LeadQualityWeekOut(
                week="2026-W38",
                formed=2,
                hunted=2,
                threat=1,
                promoted=0,
                dismissed={"expected_for_role": 1},
            ),
            LeadQualityWeekOut(week="2026-W37", formed=0),
        ],
        by_types=[
            LeadQualityTypesOut(types="catalog_match+off_hours", formed=2, dismissed=1, threat=1)
        ],
        rule="A lead forms at 0.85 over two or more types.",
        note="A threshold moves only on a week of data.",
    )
    out = _strip_ansi(cli.format_lead_quality(report))
    assert "2026-W38" in out and "2026-W37" in out
    assert "expected_for_role=1" in out
    assert "catalog_match+off_hours" in out
    assert "rule: A lead forms at 0.85 over two or more types." in out
    assert "note: A threshold moves only on a week of data." in out
    # A week with nothing in it prints a dash, not an empty column.
    assert out.splitlines()[2].endswith("-")


def test_format_lead_quality_says_so_when_no_lead_formed() -> None:
    from soc_ai.api.webui.routes_hunts import LeadQualityOut, LeadQualityWeekOut

    out = cli.format_lead_quality(
        LeadQualityOut(
            weeks=[LeadQualityWeekOut(week="2026-W38")],
            by_types=[],
            rule="r",
            note="n",
        )
    )
    assert "No lead formed in this window." in out


def test_format_lead_quality_prints_the_hunt_closures_in_their_own_column() -> None:
    from soc_ai.api.webui.routes_hunts import (
        LeadQualityOut,
        LeadQualityTypesOut,
        LeadQualityWeekOut,
    )

    report = LeadQualityOut(
        weeks=[
            LeadQualityWeekOut(
                week="2026-W39",
                formed=3,
                hunted=3,
                closed_by_hunt=2,
                dismissed={"benign_repeat": 1},
            )
        ],
        by_types=[
            LeadQualityTypesOut(types="novel_served_port", formed=3, dismissed=1, closed_by_hunt=2)
        ],
        rule="r",
        note="n",
    )
    lines = _strip_ansi(cli.format_lead_quality(report)).splitlines()
    assert "closed by hunt" in lines[0]
    assert lines[1].split() == ["2026-W39", "3", "3", "0", "0", "2", "benign_repeat=1"]
    types_row = next(line for line in lines if line.startswith("novel_served_port"))
    assert types_row.split() == ["novel_served_port", "3", "1", "2", "0"]


# ── soc-ai audit verify: window, streaming, exit 3 ───────────────────────────


def _run_verify_against(records: list[dict[str, Any]], args: argparse.Namespace) -> tuple[int, Any]:
    """Run the CLI end to end against a fake grid that holds *records*."""
    from soc_ai.audit import verify as verify_mod

    from tests.test_audit_verify import _FakeES

    fake = _FakeES(records)
    verify_spy = AsyncMock(wraps=verify_mod.verify_audit_chain)
    with (
        patch("soc_ai.cli.get_settings", return_value=_cli_settings()),
        patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=fake),
        patch("soc_ai.audit.verify.verify_audit_chain", verify_spy),
    ):
        rc = cli._audit_verify(args)
    return rc, verify_spy


def test_audit_verify_defaults_to_seven_days_and_all_reads_the_index(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """No flags verifies the newest 7 days; --all verifies the whole index."""
    from datetime import UTC, datetime, timedelta

    from tests.test_audit_verify import _build_chain

    records = _build_chain(5, start_time=datetime.now(UTC) - timedelta(hours=5))
    rc, spy = _run_verify_against(records, argparse.Namespace(days=None, all=False))
    assert rc == 0
    assert spy.call_args.kwargs["days"] == 7
    assert spy.call_args.kwargs["max_records"] is None
    assert "last 7d window" in _strip_ansi(capsys.readouterr().out)

    rc, spy = _run_verify_against(records, argparse.Namespace(days=None, all=True))
    assert rc == 0
    assert spy.call_args.kwargs["days"] is None

    rc, _spy = _run_verify_against(records, argparse.Namespace(days=0, all=False))
    assert rc == 2
    assert "--days must be 1 or more" in _strip_ansi(capsys.readouterr().err)


def test_audit_verify_cli_streams_a_large_index_in_bounded_memory(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """`soc-ai audit verify --all` pages the index and never holds more than one page.

    The CLI used to load the whole index first and a 1 GB container killed it
    (exit 137, no output). With a page of 10 and 45 records, the scan takes
    five pages, and the records alive at each page fit in one page.
    """
    import gc
    import weakref

    from soc_ai.audit import chain as chain_mod
    from soc_ai.audit import verify as verify_mod

    from tests.test_audit_verify import _build_chain, _FakeES

    class _Tracked(dict):  # type: ignore[type-arg]
        __hash__ = object.__hash__

    live: weakref.WeakSet[_Tracked] = weakref.WeakSet()

    class _Watching(_FakeES):
        async def search(self, *, index: str, body: dict[str, Any], **kw: Any) -> dict[str, Any]:
            resp = await super().search(index=index, body=body, **kw)
            for hit in resp["hits"]["hits"]:
                hit["_source"] = _Tracked(hit["_source"])
                live.add(hit["_source"])
            return resp

    held: list[int] = []
    real_feed = chain_mod.EpochStreamChecker.feed_page

    def _spy(self: Any, page: list[dict[str, Any]]) -> None:
        gc.collect()
        held.append(len(live))
        real_feed(self, page)

    monkeypatch.setattr(chain_mod.EpochStreamChecker, "feed_page", _spy)
    monkeypatch.setattr(verify_mod, "_PAGE_SIZE", 10)
    with (
        patch("soc_ai.cli.get_settings", return_value=_cli_settings()),
        patch(
            "soc_ai.so_client.elastic.AsyncElasticsearch", return_value=_Watching(_build_chain(45))
        ),
    ):
        rc = cli._audit_verify(argparse.Namespace(days=None, all=True))

    assert rc == 0
    assert "45 records verified" in _strip_ansi(capsys.readouterr().out)
    assert len(held) >= 5
    # The bound is a page, with one page of slack: under a parallel test run
    # the collector can lag one feed behind. The whole index would be 45.
    assert max(held) <= 20, f"held {max(held)} records at once; a page is 10"


def test_audit_verify_duplicates_only_exits_3_and_says_no_record_was_altered(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Six duplicated positions, nothing altered: exit 3, never "CHAIN BROKEN"/1.

    The negative control edits one record in the same index: that is exit 1 and
    TAMPER DETECTED, so exit 3 cannot swallow an alteration.
    """
    from datetime import UTC, datetime, timedelta

    from soc_ai.audit.chain import compute_hash

    from tests.test_audit_verify import _build_chain

    def _fork(rec: dict[str, Any]) -> dict[str, Any]:
        fork = {k: v for k, v in rec.items() if k != "hash"}
        fork["session_id"] = "second-writer"
        fork["hash"] = compute_hash(fork, fork["prev_hash"])
        return fork

    records = _build_chain(30, start_time=datetime.now(UTC) - timedelta(hours=10))
    forks = [_fork(records[i]) for i in (3, 7, 11, 15, 19, 23)]
    rc, _spy = _run_verify_against([*records, *forks], argparse.Namespace(days=None, all=False))
    err = _strip_ansi(capsys.readouterr().err)
    assert rc == 3, err
    assert "DUPLICATE SEQUENCE NUMBERS" in err
    assert "duplicate sequence numbers; no record was altered" in err
    assert "6 sequence numbers" in err
    assert "CHAIN BROKEN" not in err

    records[9]["payload"] = {"i": "edited"}
    rc, _spy = _run_verify_against([*records, *forks], argparse.Namespace(days=None, all=False))
    err = _strip_ansi(capsys.readouterr().err)
    assert rc == 1
    assert "TAMPER DETECTED" in err
    assert "no record was altered" not in err


def test_audit_verify_help_documents_exit_3(capsys: pytest.CaptureFixture[str]) -> None:
    """`soc-ai audit verify --help` states every exit code, including 3."""
    parser = argparse.ArgumentParser(prog="soc-ai")
    cli._register_audit(parser.add_subparsers(dest="cmd"))
    with pytest.raises(SystemExit):
        parser.parse_args(["audit", "verify", "--help"])
    text = " ".join(capsys.readouterr().out.split())
    assert "0 intact" in text
    assert "1 a record was altered" in text
    assert "2 could not verify" in text
    assert "3 duplicate sequence numbers only" in text
    assert "--all" in text


def test_priors_prints_the_status_and_counts_unmeasurable_as_blind(
    monkeypatch: pytest.MonkeyPatch,
    settings_kratos: Settings,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """``soc-ai priors`` printed a fifth column, ``unmeasurable=2``, where the
    ledger, the store and docs/HUNTING.md count that entity as blind. It also
    printed no status, so a shadow detector and a live analytic read the same.

    The status comes from the effective catalog the sweep ran. A learned
    detector ships in shadow. A profile analytic ships live.
    """
    import soc_ai.config as config_mod
    import soc_ai.hunting.prior_sweep as sweep_mod
    import soc_ai.so_client.elastic as elastic_mod
    from soc_ai.hunting.prior_sweep import PriorSweep
    from soc_ai.hunting.priors import PriorResult

    seen: dict[str, Any] = {}

    def _result(spec: str, key: str, coverage: str, note: str = "") -> PriorResult:
        return PriorResult(
            spec_id=spec, entity_kind="host", entity_key=key, coverage=coverage, note=note
        )

    async def fake_sweep(**kw: Any) -> PriorSweep:
        seen.update(kw)
        return PriorSweep(
            results=(
                _result("model-cross-plane-silence", "192.0.2.1", "measured"),
                _result("model-cross-plane-silence", "192.0.2.2", "unmeasurable", "one plane"),
                _result("profile-connection-rate-spiked", "192.0.2.1", "blind", "no series"),
            ),
            notes=(
                "model-cross-plane-silence: entity states: measured 1, learning 0, blind 0, "
                "unmeasurable 1, stale 0, drifted 0, held 0.",
            ),
        )

    class _FakeElastic:
        def __init__(self, _settings: Settings) -> None:
            pass

        async def aclose(self) -> None:
            pass

    monkeypatch.setattr(sweep_mod, "run_prior_sweep", fake_sweep)
    monkeypatch.setattr(elastic_mod, "ElasticClient", _FakeElastic)
    monkeypatch.setattr(config_mod, "get_settings", lambda: settings_kratos)

    assert cli._priors(argparse.Namespace(recent_hours=24, record=False)) == 0
    out = capsys.readouterr().out

    assert "  coverage: blind=2, measured=1\n" in out
    assert "unmeasurable=" not in out
    # The count of the detector state stays in the per-state note.
    assert "unmeasurable 1, stale 0" in out
    assert f"{'model-cross-plane-silence':48} shadow    blind=1, measured=1" in out
    assert f"{'profile-connection-rate-spiked':48} live      blind=1" in out
    assert "model-cross-plane-silence" in seen["shadow_ids"]
    assert "profile-connection-rate-spiked" not in seen["shadow_ids"]


# ── `soc-ai estate-model show | run` (range dogfood C4) ────────────────────────
#
# No command read the estate fit and none ran it once. The setting toggle and the
# next wake of the loop were the only path, and a second toggle in one day did
# not fit again.


def _estate_settings(tmp_path: Any, **update: Any) -> Settings:
    base = _cli_settings().model_copy(update={"soc_ai_data_dir": tmp_path / "data"})
    return base.model_copy(update=update) if update else base


async def _estate_store(settings: Settings) -> Any:
    from soc_ai.store.db import make_engine, make_sessionmaker, run_migrations

    engine = make_engine(settings)
    await run_migrations(engine)
    return engine, make_sessionmaker(engine)


def _estate_args(cmd: str, **overrides: Any) -> argparse.Namespace:
    base: dict[str, Any] = {"estate_model_cmd": cmd, "json": False}
    base.update(overrides)
    return argparse.Namespace(**base)


def test_estate_model_parser_registers_show_and_run() -> None:
    parser = argparse.ArgumentParser(prog="soc-ai")
    sub = parser.add_subparsers(dest="cmd")
    cli._register_store(sub)
    show = parser.parse_args(["estate-model", "show", "--json"])
    run = parser.parse_args(["estate-model", "run"])
    assert show.func is cli._estate_model_show and show.json is True
    assert run.func is cli._estate_model_run


def test_estate_model_show_with_no_fit(
    tmp_path: Any, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    settings = _estate_settings(tmp_path)
    monkeypatch.setattr(cli, "get_settings", lambda: settings)
    assert cli._estate_model_show(_estate_args("show")) == 0
    out = capsys.readouterr().out
    assert out == ("The setting estate_model_enabled is off.\nNo estate model fit is on record.\n")


def test_estate_model_show_prints_every_field_of_the_newest_fit(
    tmp_path: Any, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    import json as _json
    from datetime import datetime

    from soc_ai.store import estate_model as estate_store

    settings = _estate_settings(tmp_path)

    async def _seed() -> None:
        engine, maker = await _estate_store(settings)
        async with maker() as db:
            await estate_store.record_fit(
                db, fitted_at=datetime(2026, 10, 4, 1, 0), state="learning", hosts=12
            )
            fit_id = await estate_store.record_fit(
                db,
                fitted_at=datetime(2026, 10, 5, 1, 50),
                state="learning",
                reason="Learning, day 6 of 7. The median host has 6 days of profiles.",
                model_sha256="7c2aa66b" + "0" * 56,
                model_file="estate-20261005T015051Z-7c2aa66b001a.json",
                hosts=31,
                features=23,
                groups=3,
                silhouette=0.455,
                support_days=6,
                psi=0.31,
                drifted=[{"feature": "dns.members", "psi": 0.31}],
            )
            await estate_store.update_fit(
                db,
                fit_id,
                outliers=7,
                unexplained=5,
                shared=0,
                no_documents=0,
                observations=0,
                audited=True,
            )
        await engine.dispose()

    asyncio.run(_seed())
    monkeypatch.setattr(cli, "get_settings", lambda: settings)
    assert cli._estate_model_show(_estate_args("show")) == 0
    out = capsys.readouterr().out
    assert out.startswith("The setting estate_model_enabled is off.\nThe newest fit, fit 2:")
    for text in (
        "fitted at     2026-10-05 01:50 UTC",
        "state         learning. Learning, day 6 of 7.",
        "role          challenger until 2026-10-06 01:50 UTC",
        "hosts         31",
        "groups        3, silhouette 0.455",
        "outliers      7 above the threshold, 5 with no stated reason, 0 shared with a "
        "subgroup, 0 with no document",
        "observations  0",
        "model file    estate-20261005T015051Z-7c2aa66b001a.json",
        "sha256        7c2aa66b",
        "drift index   0.31. Drifted: dns.members 0.31",
        "audited       yes",
    ):
        assert text in out, text
    assert "—" not in out and "–" not in out

    assert cli._estate_model_show(_estate_args("show", json=True)) == 0
    body = _json.loads(capsys.readouterr().out)
    assert body["enabled"] is False
    assert body["fit"]["hosts"] == 31 and body["fit"]["fitted_at"] == "2026-10-05T01:50:00"


def test_estate_model_run_with_the_setting_off_fits_once_and_says_so(
    tmp_path: Any, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """A real one-shot fit on an empty store: learning, recorded, with the setting off."""
    pytest.importorskip("sklearn")
    from soc_ai.store import estate_model as estate_store

    settings = _estate_settings(tmp_path)
    assert settings.estate_model_enabled is False
    monkeypatch.setattr(cli, "get_settings", lambda: settings)
    assert cli._estate_model_run(_estate_args("run")) == 0
    out = capsys.readouterr().out
    assert out.startswith(
        "The setting estate_model_enabled is off. This one fit runs because you asked for "
        "it. The daily loop stays off.\n"
    )
    assert "estate model: learning. 0 hosts." in out
    assert "The store recorded fit 1." in out
    assert settings.estate_model_enabled is False  # the one-shot run changed no setting

    async def _latest() -> Any:
        engine, maker = await _estate_store(settings)
        async with maker() as db:
            fit = await estate_store.latest_fit(db)
        await engine.dispose()
        return fit

    fit = asyncio.run(_latest())
    assert fit is not None and fit.state == "learning" and fit.hosts == 0


def test_estate_model_run_with_the_setting_on_in_the_console_prints_no_notice(
    tmp_path: Any, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Negative control: the console override turns the setting on, so no off notice."""
    from soc_ai.hunting.estate_model import job
    from soc_ai.store.config_overrides import set_override

    settings = _estate_settings(tmp_path)

    async def _seed() -> None:
        engine, maker = await _estate_store(settings)
        async with maker() as db:
            await set_override(db, "estate_model_enabled", True, updated_by=None)
        await engine.dispose()

    asyncio.run(_seed())
    seen: list[bool] = []

    async def _fake_run(**kwargs: Any) -> Any:
        seen.append(bool(kwargs["settings"].estate_model_enabled))
        return job.EstateRun(status=job.STATUS_FITTED, state="learning", fit_id=7)

    monkeypatch.setattr(job, "run_estate_model", _fake_run)
    monkeypatch.setattr(cli, "get_settings", lambda: settings)
    assert cli._estate_model_run(_estate_args("run")) == 0
    out = capsys.readouterr().out
    assert "is off" not in out
    assert "The store recorded fit 7." in out
    assert seen == [True]


def test_estate_model_run_refuses_in_a_demo(
    tmp_path: Any, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from soc_ai.hunting.estate_model import job

    called: list[int] = []

    async def _fake_run(**_kw: Any) -> Any:
        called.append(1)
        return job.EstateRun(status=job.STATUS_FITTED)

    monkeypatch.setattr(job, "run_estate_model", _fake_run)
    settings = _estate_settings(tmp_path, soc_ai_demo=True)
    monkeypatch.setattr(cli, "get_settings", lambda: settings)
    assert cli._estate_model_run(_estate_args("run")) == 2
    assert "demo" in _strip_ansi(capsys.readouterr().err)
    assert called == []


def test_estate_model_run_without_the_extra_exits_3(
    tmp_path: Any, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from soc_ai.hunting.estate_model import job

    monkeypatch.setattr(job, "load_ml", lambda: None)
    settings = _estate_settings(tmp_path)
    monkeypatch.setattr(cli, "get_settings", lambda: settings)
    assert cli._estate_model_run(_estate_args("run")) == 3
    err = capsys.readouterr().err
    assert job.UNAVAILABLE_LINE in err
    assert "uv sync --extra ml" in err


# ── The grid TLS warning (range dogfood C9) ────────────────────────────────────
#
# Every CLI command started with the two-line elasticsearch SecurityWarning about
# verify_certs=False, a setting the operator chose. The CLI entry point hides that
# one warning. The library and the server keep it.


def test_the_cli_filter_hides_only_the_grid_tls_warning() -> None:
    import warnings

    from elastic_transport import SecurityWarning
    from elasticsearch import AsyncElasticsearch

    message = (
        "Connecting to 'https://grid.example:9200' using TLS with verify_certs=False is insecure"
    )
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        cli._quiet_grid_tls_warning()
        AsyncElasticsearch("https://127.0.0.1:9200", verify_certs=False)
        # Negative controls. The same class with another message stays. The same
        # message raised outside the elasticsearch package stays.
        warnings.warn_explicit(
            "another security fact", SecurityWarning, "x.py", 1, module="elasticsearch._async"
        )
        warnings.warn_explicit(message, SecurityWarning, "x.py", 2, module="soc_ai.so_client")
        warnings.warn_explicit(message, UserWarning, "x.py", 3, module="elasticsearch._async")
    shown = [(type(w.message).__name__, str(w.message)) for w in caught]
    assert ("SecurityWarning", "another security fact") in shown
    assert ("SecurityWarning", message) in shown
    assert ("UserWarning", message) in shown
    assert not any("127.0.0.1:9200" in text for _, text in shown)


def test_the_library_keeps_the_grid_tls_warning() -> None:
    """Negative control: with no CLI filter the client still warns."""
    import warnings

    from elasticsearch import AsyncElasticsearch

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        AsyncElasticsearch("https://127.0.0.1:9200", verify_certs=False)
    assert any("verify_certs=False is insecure" in str(w.message) for w in caught)


def test_main_sets_the_filter_for_a_cli_command_and_not_for_serve(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import sys

    calls: list[str] = []
    monkeypatch.setattr(cli, "_quiet_grid_tls_warning", lambda: calls.append("quiet"))
    monkeypatch.setattr(cli, "_doctor", lambda _a: 0)
    monkeypatch.setattr(cli, "_serve", lambda _a: 0)

    monkeypatch.setattr(sys, "argv", ["soc-ai", "doctor"])
    with pytest.raises(SystemExit):
        cli.main()
    assert calls == ["quiet"]

    monkeypatch.setattr(sys, "argv", ["soc-ai", "serve"])
    with pytest.raises(SystemExit):
        cli.main()
    assert calls == ["quiet"]

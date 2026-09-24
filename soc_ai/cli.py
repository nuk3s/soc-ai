"""Command-line front-end for soc-ai.

The ``soc-ai`` script in ``pyproject.toml`` dispatches to subcommands:

- ``serve`` (default): boots the FastAPI app under uvicorn (legacy behavior).
- ``triage <alert_id>``: streams an investigation against the local soc-ai
  instance, rendering each SSE event to stdout with colorized output. Useful
  for terminal-first analysts and incident-response work where opening a
  browser is overhead.
- ``healthz``: prints the LIVENESS endpoint's JSON. It probes no dependency —
  ``doctor`` below is the check that answers whether the install works.
- ``doctor``: checks the whole dependency surface (config, local store +
  migration head, DNS/TCP/TLS-layered upstream reachability, Security Onion,
  Elasticsearch — including the audit write grant and index-pattern dataset
  coverage — gateway, analyst-model fitness, egress posture, blocklist
  freshness) and prints a pass/fail table. Exit 0 only when every required
  check passes (warnings don't fail it); ``--json`` emits the results for
  automation.
- ``backup`` / ``restore``: snapshot the live SQLite store (+ app-owned
  sidecar files) into a portable tar.gz, and put one back. Backup is safe
  while the app runs; restore wants the app stopped and gates every
  overwrite behind ``--yes``. Logic lives in ``soc_ai.backup``.

The triage subcommand connects via HTTPS to the configured
``SOC_AI_HOST:SOC_AI_PORT`` and trusts a self-signed cert by default
(matches the lab posture documented in ``docs/DEPLOYMENT.md``); pass
``--verify`` or ``--cafile`` to enable TLS verification. Against a
secured deployment (``api_auth_required=true``, the shipped default),
authenticate with ``--token scai_...`` or the ``SOC_AI_API_TOKEN``
environment variable.

Examples::

    uv run soc-ai serve
    uv run soc-ai triage sB86B54BVBs3R9hX_qZR --token scai_...
    SOC_AI_API_TOKEN=scai_... uv run soc-ai healthz
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import json
import os
import sys
from pathlib import Path
from typing import Any

import httpx

from soc_ai.config import get_settings


# ANSI color helpers — fall back to no-color if stdout isn't a TTY.
def _supports_color() -> bool:
    return sys.stdout.isatty()


_C: dict[str, str] = (
    {
        "reset": "\033[0m",
        "dim": "\033[2m",
        "bold": "\033[1m",
        "red": "\033[31m",
        "green": "\033[32m",
        "yellow": "\033[33m",
        "blue": "\033[34m",
        "magenta": "\033[35m",
        "cyan": "\033[36m",
    }
    if _supports_color()
    else dict.fromkeys(
        ["reset", "dim", "bold", "red", "green", "yellow", "blue", "magenta", "cyan"],
        "",
    )
)

_KIND_COLOR: dict[str, str] = {
    "session_start": _C["dim"],
    "alert_context": _C["cyan"],
    "tool_call": _C["blue"],
    "tool_result": _C["dim"],
    "model_response": _C["magenta"],
    "investigation_transcript": _C["cyan"],
    "usage": _C["dim"],
    "retask": _C["yellow"],
    "triage_report": _C["bold"] + _C["green"],
    "done": _C["dim"] + _C["green"],
    "error": _C["bold"] + _C["red"],
}


def _label(kind: str) -> str:
    color = _KIND_COLOR.get(kind, _C["bold"])
    return f"{color}{kind}{_C['reset']}"


def _short(s: str, n: int = 280) -> str:
    s = s.replace("\n", " ").strip()
    return s if len(s) <= n else s[: n - 1] + "…"


def _render_event(kind: str, payload: dict[str, Any]) -> str:
    """Render a single SSE event as a single line for the CLI."""
    if kind == "session_start":
        return f"{_label(kind)} alert_id={payload.get('alert_id')!r}"
    if kind == "alert_context":
        a = payload.get("alert") or {}
        rule = a.get("rule_name") or "(no rule_name)"
        sev = a.get("severity_label") or "?"
        cid = a.get("network_community_id") or "-"
        ps = payload.get("pivot_summary") or {}
        pivots = ", ".join(f"{k}:{v}" for k, v in ps.items() if v)
        return f"{_label(kind)} {sev} {rule!r} community_id={cid} pivots=[{pivots}]"
    if kind == "tool_call":
        args = payload.get("args")
        if not isinstance(args, str):
            args = json.dumps(args)
        return f"{_label(kind)} {payload.get('tool_name')}({_short(args, 160)})"
    if kind == "tool_result":
        result = payload.get("result")
        body = json.dumps(result) if not isinstance(result, str) else result
        return f"{_label(kind)} {payload.get('tool_name')} → {_short(body, 160)}"
    if kind == "model_response":
        line = f"{_label(kind)} {_short(payload.get('content', ''), 220)}"
        trace = payload.get("reasoning_trace")
        if trace:
            line += f"\n   {_C['dim']}<think>{_short(trace, 200)}{_C['reset']}"
        return line
    if kind == "investigation_transcript":
        rnd = payload.get("round")
        ev_count = len(payload.get("evidence") or [])
        oq_count = len(payload.get("open_questions") or [])
        return (
            f"{_label(kind)} round={rnd} evidence={ev_count} "
            f"open_questions={oq_count}\n   "
            f"{_C['dim']}{_short(payload.get('tentative_summary', ''), 180)}{_C['reset']}"
        )
    if kind == "usage":
        return (
            f"{_label(kind)} phase={payload.get('phase')} "
            f"round={payload.get('round')} tools={payload.get('tool_calls')} "
            f"reqs={payload.get('requests')} tokens="
            f"{payload.get('input_tokens')}/{payload.get('output_tokens')}"
        )
    if kind == "retask":
        return (
            f"{_label(kind)} reason={payload.get('reason')} "
            f"confidence={payload.get('confidence')} floor={payload.get('floor')}"
        )
    if kind == "triage_report":
        verdict = payload.get("verdict") or "?"
        conf = payload.get("confidence")
        summary = _short(payload.get("summary") or "", 320)
        cites = ", ".join((payload.get("citations") or [])[:6])
        out = [
            f"{_label(kind)} {verdict.upper()}  confidence={conf}",
            f"   {summary}",
            f"   {_C['dim']}citations: {cites or '(none)'}{_C['reset']}",
        ]
        actions = payload.get("recommended_actions") or []
        for a in actions:
            rendered_rationale = _short(a.get("rationale", ""), 200)
            out.append(
                f"   {_C['yellow']}→ {a.get('tool_name')} ({rendered_rationale}){_C['reset']}"
            )
        return "\n".join(out)
    if kind == "done":
        return (
            f"{_label(kind)} recommended_count={payload.get('recommended_count')} "
            f"rounds={payload.get('rounds')}"
        )
    if kind == "error":
        line = (
            f"{_label(kind)} phase={payload.get('phase')} "
            f"round={payload.get('round')} type={payload.get('type')}"
        )
        line += f"\n   {payload.get('message', '')}"
        if payload.get("hint"):
            line += f"\n   {_C['yellow']}hint: {payload['hint']}{_C['reset']}"
        return line
    # Fallback for unknown kinds — dump the payload.
    return f"{_label(kind)} {_short(json.dumps(payload), 160)}"


async def _stream_investigation(
    base_url: str,
    alert_id: str,
    *,
    token: str | None = None,
    verify: bool | str = False,
) -> int:
    """Connect, stream the SSE events, render each. Returns process exit code."""
    url = base_url.rstrip("/") + "/investigate"
    print(
        f"{_C['dim']}POST {url}  alert_id={alert_id!r}{_C['reset']}",
        file=sys.stderr,
    )
    saw_error = False
    saw_triage = False
    # verify defaults to False (lab self-signed posture; --verify/--cafile
    # enable TLS verification); SSE stream needs no client-side timeout
    # because investigations can legitimately take many minutes.
    async with (
        httpx.AsyncClient(verify=verify, timeout=None) as client,  # noqa: S113
        client.stream(
            "POST",
            url,
            json={"alert_id": alert_id},
            headers={"Accept": "text/event-stream", **_auth_headers(token)},
        ) as resp,
    ):
        if resp.status_code != 200:
            print(
                f"{_C['red']}HTTP {resp.status_code}{_C['reset']}: {await resp.aread()!r}",
                file=sys.stderr,
            )
            _print_401_hint_if_no_token(resp.status_code, token)
            return 2
        kind: str | None = None
        buf = ""
        async for chunk in resp.aiter_text():
            buf += chunk
            while "\n" in buf:
                line, buf = buf.split("\n", 1)
                line = line.rstrip("\r")
                if line.startswith("event:"):
                    kind = line[len("event:") :].strip()
                elif line.startswith("data:"):
                    data = line[len("data:") :].strip()
                    try:
                        parsed = json.loads(data)
                    except json.JSONDecodeError:
                        print(f"{_C['red']}parse error{_C['reset']}: {data}")
                        continue
                    payload = parsed.get("payload", parsed)
                    rendered = _render_event(kind or "message", payload)
                    print(rendered, flush=True)
                    if kind == "error":
                        saw_error = True
                    if kind == "triage_report":
                        saw_triage = True
                    kind = None
    if saw_error and not saw_triage:
        return 1
    return 0


def _serve(_args: argparse.Namespace) -> int:
    """Boot the FastAPI app under uvicorn (existing v1 behavior)."""
    import uvicorn  # noqa: PLC0415 - lazy import; only the serve subcommand needs it

    settings = get_settings()
    uvicorn.run(
        "soc_ai.main:app",
        host=settings.soc_ai_host,
        port=settings.soc_ai_port,
        log_level=settings.log_level.lower(),
        ssl_certfile=str(settings.soc_ai_tls_cert) if settings.soc_ai_tls_cert else None,
        ssl_keyfile=str(settings.soc_ai_tls_key) if settings.soc_ai_tls_key else None,
        # AEAD ciphers only — no CBC/SHA-1. OpenSSL 3.x already floors at TLS 1.2.
        ssl_ciphers="ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM",
    )
    return 0


def _resolve_base_url(url_arg: str | None) -> str:
    """Pick a base URL. Prefer ``--url``; otherwise fall back to the .env settings.

    The triage/healthz subcommands only need a reachable HTTP endpoint, so
    we tolerate get_settings() failing (e.g. no .env on the caller's host)
    and print a helpful error in that case.
    """
    if url_arg:
        return url_arg
    try:
        settings = get_settings()
    except Exception as e:
        print(
            f"{_C['red']}Could not load settings to resolve a default URL: "
            f"{e}{_C['reset']}\n"
            f"Pass --url https://host:port explicitly, or run from a "
            f"directory with a populated .env.",
            file=sys.stderr,
        )
        raise SystemExit(2) from e
    host = settings.soc_ai_host
    # 0.0.0.0 / :: on the bind side means "any interface"; for the client
    # we need a real host. Fall back to localhost when the bind is wildcard.
    if host in ("0.0.0.0", "::"):  # noqa: S104 - matching server bind config, not literal binding
        host = "127.0.0.1"
    scheme = "https" if settings.soc_ai_tls_cert else "http"
    return f"{scheme}://{host}:{settings.soc_ai_port}"


def _resolve_token(args: argparse.Namespace) -> str | None:
    """API bearer token: explicit ``--token`` wins, then ``SOC_AI_API_TOKEN``.

    Returns None when neither is set (unauthenticated request — only works
    against a deployment with ``api_auth_required`` turned off).
    """
    token = getattr(args, "token", None)
    if token:
        return str(token)
    return os.environ.get("SOC_AI_API_TOKEN") or None


def _resolve_verify(args: argparse.Namespace) -> bool | str:
    """TLS verification for CLI HTTP calls: ``--cafile`` > ``--verify`` > off.

    Defaults to False (the lab self-signed posture) for backward
    compatibility; a CA bundle path pins verification to that bundle.
    """
    cafile = getattr(args, "cafile", None)
    if cafile:
        return str(cafile)
    return bool(getattr(args, "verify", False))


def _auth_headers(token: str | None) -> dict[str, str]:
    """Authorization header for the API token, or empty when unauthenticated."""
    return {"Authorization": f"Bearer {token}"} if token else {}


def _warn_insecure_auth(token: str | None, verify: bool | str) -> None:
    """Loud stderr warning when a Bearer token rides over unverified TLS.

    Mirrors the ``API_AUTH_REQUIRED=false`` warning main.py emits at startup:
    a real risk (on-path attacker captures a fully-privileged API token) gets
    a visible flag instead of silent acceptance, without changing the default
    lab self-signed posture.
    """
    if token and verify is False:
        print(
            f"{_C['yellow']}WARNING{_C['reset']}: soc-ai sends a Bearer token with "
            "TLS certificate verification disabled. This is the default. An on-path "
            "attacker could capture the token. Pass --verify or --cafile to verify "
            "the server's certificate.",
            file=sys.stderr,
        )


def _print_401_hint_if_no_token(status_code: int, token: str | None) -> None:
    """One actionable line when the API answers 401 and the CLI sent no token.

    Live-VM regression (2026-08-20): ``docker exec soc-ai python -m soc_ai
    triage <id>`` on an ``API_AUTH_REQUIRED=true`` (the shipped default) install
    prints the raw server JSON — ``{"reason":"no_session","hint":"Log in at
    /app/login or send 'Authorization: Bearer scai_…'."}`` — which is correct but
    doesn't say *how* the CLI itself takes a token. This adds that, and only
    that: gated on ``not token`` so a 401 the CLI got back AFTER attaching a
    token (a bad/expired/revoked one — the server's own ``invalid_token`` hint
    already covers that case correctly) never sees this "set a token" line,
    which would be actively misleading there.
    """
    if status_code == 401 and not token:
        print(
            f"{_C['yellow']}hint{_C['reset']}: this deployment requires authentication. "
            "Set SOC_AI_API_TOKEN, or pass --token scai_... . Mint a token in the web "
            "UI under Config → API tokens.",
            file=sys.stderr,
        )


def _triage(args: argparse.Namespace) -> int:
    base_url = _resolve_base_url(args.url)
    token = _resolve_token(args)
    verify = _resolve_verify(args)
    _warn_insecure_auth(token, verify)
    return asyncio.run(
        _stream_investigation(
            base_url,
            args.alert_id,
            token=token,
            verify=verify,
        )
    )


def _healthz(args: argparse.Namespace) -> int:
    base_url = _resolve_base_url(args.url)
    url = base_url.rstrip("/") + "/healthz"
    token = _resolve_token(args)
    verify = _resolve_verify(args)
    _warn_insecure_auth(token, verify)
    # verify defaults to False (lab self-signed); --verify/--cafile enable it.
    with httpx.Client(
        verify=verify,
        timeout=10.0,
        headers=_auth_headers(token),
    ) as client:
        resp = client.get(url)
    try:
        print(json.dumps(resp.json(), indent=2))
    except ValueError:
        # A non-JSON body (a proxy 502 page, an auth redirect, a plain-text
        # error) must not crash healthz with a raw traceback — show the status
        # and a snippet so the operator can see what answered.
        print(f"HTTP {resp.status_code} (non-JSON body): {resp.text[:200]}")
    _print_401_hint_if_no_token(resp.status_code, token)
    return 0 if resp.status_code == 200 else 1


def _doctor(args: argparse.Namespace) -> int:
    """Run the dependency-surface health checks and print a pass/fail table.

    Exit codes:
      0   every required check passed (WARN/INFO lines don't fail the doctor)
      1   at least one required check FAILed, or --strict and something WARNed

    The default stays lenient on purpose. A monitor keyed on this exit status has
    read 0-with-warnings as success for the life of the tool, and silently
    starting to page it would be a worse defect than the one it fixes — but a
    WARN nobody's automation can see is how the band becomes decorative, so
    --strict makes the other answer available without changing anyone's.
    """
    from soc_ai.doctor import CheckResult, exit_code, run_doctor  # noqa: PLC0415 - lazy

    results = asyncio.run(run_doctor())
    rc = exit_code(results, strict=bool(getattr(args, "strict", False)))

    if args.json:
        print(
            json.dumps(
                {"ok": rc == 0, "results": [r.as_dict() for r in results]},
                indent=2,
            )
        )
        return rc

    status_color = {
        "PASS": _C["green"],
        "WARN": _C["yellow"],
        "FAIL": _C["bold"] + _C["red"],
        "INFO": _C["dim"],
    }
    name_w = max(len(r.name) for r in results)

    def _line(r: CheckResult) -> str:
        color = status_color.get(r.status, "")
        out = f"{color}{r.status:<4}{_C['reset']}  {r.name:<{name_w}}  {r.detail}"
        if r.hint:
            # Hint on its own indented line, aligned under the detail column.
            out += f"\n{' ' * (6 + name_w + 2)}{_C['yellow']}fix: {r.hint}{_C['reset']}"
        return out

    for r in results:
        print(_line(r))
    n_pass = sum(1 for r in results if r.status == "PASS")
    n_warn = sum(1 for r in results if r.status == "WARN")
    n_fail = sum(1 for r in results if r.status == "FAIL")
    summary_color = _C["red"] if n_fail else _C["green"]
    print(
        f"\n{summary_color}{n_pass} passed, {n_warn} warning(s), {n_fail} failure(s){_C['reset']}"
    )
    return rc


def _validate(args: argparse.Namespace) -> int:
    """Run the offline eval harness against a real alert.

    Streams a colorless progress trail to stderr while the
    investigation runs (so the operator knows it didn't hang on a
    long synthesis call), then prints the oracle's de-sanitized critique
    to stdout and the bundle path to stderr.

    Exit codes:
      0   ok
      2   alert not found (prefetch failed)
      3   sanitization residue refused to send (see refused/ subdir)
      4   LiteLLM/oracle call failed
      5   unexpected internal error
    """
    from pathlib import Path  # noqa: PLC0415 - lazy

    from soc_ai.eval import run as run_eval  # noqa: PLC0415 - lazy

    out_dir = Path(args.out_dir) if args.out_dir else Path("evals")

    print(
        f"{_C['dim']}eval harness · alert={args.alert_id!r} · "
        f"investigating + sanitizing + asking the oracle…{_C['reset']}",
        file=sys.stderr,
        flush=True,
    )
    try:
        result = asyncio.run(run_eval(args.alert_id, out_dir=out_dir))
    except RuntimeError as e:
        msg = str(e)
        if "alert not found" in msg.lower() or "prefetch" in msg.lower():
            print(f"{_C['red']}prefetch failed{_C['reset']}: {msg}", file=sys.stderr)
            return 2
        if "residue" in msg.lower():
            print(f"{_C['red']}sanitization refused{_C['reset']}: {msg}", file=sys.stderr)
            return 3
        if "litellm" in msg.lower() or "oracle" in msg.lower():
            print(f"{_C['red']}oracle call failed{_C['reset']}: {msg}", file=sys.stderr)
            return 4
        print(f"{_C['red']}eval failed{_C['reset']}: {msg}", file=sys.stderr)
        return 5

    # Stdout: the oracle's response, de-sanitized.
    print(result.response_md)

    # Stderr: meta line.
    usage = result.oracle_response.usage
    print(
        f"\n{_C['dim']}bundle: {result.bundle_dir} · "
        f"investigation: {result.investigation_elapsed_ms / 1000:.1f}s · "
        f"oracle: {result.oracle_response.elapsed_ms / 1000:.1f}s · "
        f"tokens in/out/cached: "
        f"{usage.get('input_tokens', 0)}/"
        f"{usage.get('output_tokens', 0)}/"
        f"{usage.get('cache_read_input_tokens', 0)}{_C['reset']}",
        file=sys.stderr,
    )
    return 0


def _positive_int(value: str) -> int:
    """argparse type for counts that must be >= 1 (e.g. --repeats)."""
    n = int(value)
    if n < 1:
        raise argparse.ArgumentTypeError(f"must be >= 1, got {n}")
    return n


def _validate_batch(args: argparse.Namespace) -> int:
    """Run the eval harness over a batch of alerts and write index.jsonl.

    Exit codes:
      0   ok (or partial: ran what we got, wrote what we have)
      2   sampler returned no eligible alerts
      4   batch aborted by failure-budget (LiteLLM down, etc.)
      5   unexpected internal error
    """
    from pathlib import Path  # noqa: PLC0415 - lazy

    from soc_ai.eval.batch import BatchConfig, run_batch  # noqa: PLC0415 - lazy
    from soc_ai.so_client.elastic import ElasticClient  # noqa: PLC0415 - lazy

    settings = get_settings()
    diversity_keys = tuple(k.strip() for k in args.diversity_keys.split(",") if k.strip())

    synth_scenarios: tuple[Any, ...] | None = None
    if getattr(args, "synth_set", None):
        from soc_ai.eval.synth_loader import (  # noqa: PLC0415 - lazy
            load_all_scenarios,
            select_scenarios,
        )

        scenarios_dir = Path(__file__).parent / "eval" / "synth_scenarios"
        try:
            catalogue = load_all_scenarios(scenarios_dir)
            picked = select_scenarios(catalogue, selector=args.synth_set)
            # `select_scenarios` already excludes the declarative population
            # from the tier and `all` selectors, but an EXPLICIT id still
            # resolves either — deliberately, since an explicit request is
            # explicit. This is the triage harness though, and a scenario with
            # no alert has nothing for it to sample: it would plant its
            # documents and then raise from the ingester, leaving litter behind
            # and reporting nothing useful. Reject before any side effect.
            not_triageable = [s.id for s in picked if s.spec_journey is not None]
            if not_triageable:
                print(
                    f"{_C['red']}--synth-set names scenarios that cannot be "
                    f"triaged{_C['reset']}: {', '.join(not_triageable)}\n"
                    "  These declare a spec_journey and belong to the declarative "
                    "population. They carry no alert by design.\n"
                    "  Score them with `soc-ai spec-run` or the spec_journey "
                    "coverage gate.",
                    file=sys.stderr,
                )
                return 5
            synth_scenarios = tuple(picked)
        except Exception as e:
            print(
                f"{_C['red']}--synth-set load failed{_C['reset']}: {type(e).__name__}: {e}",
                file=sys.stderr,
            )
            return 5
        repeats_note = f" x {args.repeats} repeats" if getattr(args, "repeats", 1) > 1 else ""
        print(
            f"{_C['dim']}synth-set: {args.synth_set} → "
            f"{len(synth_scenarios)} scenarios{repeats_note} "
            f"({','.join(s.id for s in synth_scenarios)}){_C['reset']}",
            file=sys.stderr,
            flush=True,
        )

    cfg = BatchConfig(
        oql=args.oql,
        n=args.n,
        concurrency=args.concurrency,
        diversity_keys=diversity_keys,
        time_range_minutes=args.time_range_minutes,
        out_dir=Path(args.out_dir),
        resume=args.resume,
        per_run_timeout_s=args.per_run_timeout_s,
        max_consecutive_failures=args.max_consecutive_failures,
        synth_scenarios=synth_scenarios,
        synth_repeats=getattr(args, "repeats", 1),
    )

    print(
        f"{_C['dim']}validate-batch · n={cfg.n} concurrency={cfg.concurrency} "
        f"diversity={','.join(cfg.diversity_keys)} window={cfg.time_range_minutes}m"
        f"{_C['reset']}",
        file=sys.stderr,
        flush=True,
    )

    def _emit(line: str) -> None:
        print(f"{_C['dim']}{line}{_C['reset']}", file=sys.stderr, flush=True)

    async def _go() -> int:
        elastic = ElasticClient(settings)
        try:
            try:
                summary = await run_batch(cfg, settings=settings, elastic=elastic, progress=_emit)
            except RuntimeError as e:
                print(
                    f"{_C['red']}batch failed{_C['reset']}: {e}",
                    file=sys.stderr,
                )
                return 5
            except Exception as e:
                print(
                    f"{_C['red']}batch failed (transport){_C['reset']}: {type(e).__name__}: {e}",
                    file=sys.stderr,
                )
                return 5
        finally:
            with contextlib.suppress(Exception):
                await elastic.aclose()

        if summary.aborted_reason:
            print(
                f"{_C['red']}{summary.aborted_reason}{_C['reset']}",
                file=sys.stderr,
            )
        print(
            f"\n{_C['dim']}batch: {summary.batch_dir} · "
            f"planned={summary.n_planned} ok={summary.n_ok} err={summary.n_error} · "
            f"elapsed={summary.elapsed_s // 60}m{summary.elapsed_s % 60}s"
            f"{_C['reset']}",
            file=sys.stderr,
        )
        if summary.n_planned == 0:
            return 2
        if summary.aborted_reason:
            return 4
        return 0

    rc = asyncio.run(_go())
    if rc == 0 and not getattr(args, "no_aggregate", False):
        _auto_aggregate_after_batch(args)
    return rc


async def _fire_quality_alarm(
    settings: Any,
    *,
    elastic: Any,
    mode: str,
    reasons: list[str],
    metrics: Any,
    audit: Any = None,
) -> None:
    """Best-effort alarm side effects for a nightly quality regression.

    Two channels, both fail-soft: an audit event (kind ``quality_regression``,
    so the degradation is provable from the trail even after the snapshot
    table prunes) and the opt-in notification webhook (a hard no-op unless
    notifications are enabled + configured — the nightly must never grow an
    egress path the operator didn't turn on). The committed snapshot row is
    the durable record; neither channel failing can lose the alarm itself.

    ``audit`` is the caller's logger. The in-app nightly passes the server's
    own, because a second :class:`~soc_ai.audit.logger.AuditLogger` in one
    process is a second chain head with its own lock, and the two heads then
    hand the same position to two records. That is now caught by the grid
    rather than written (see :mod:`soc_ai.audit.logger`), but caught means a
    conflict and a retry inside the write budget — cheaper not to create the
    collision. The CLI has no server logger to borrow and builds one.
    """
    from soc_ai import notify  # noqa: PLC0415 - lazy
    from soc_ai.audit.logger import AuditLogger  # noqa: PLC0415 - lazy

    try:
        if audit is None:
            audit = AuditLogger(settings, elastic)
        await audit.log_kind(
            session_id="quality-nightly",
            kind="quality_regression",
            payload={
                "mode": mode,
                "reasons": reasons,
                "n_ok": metrics.n_ok,
                "n_error": metrics.n_error,
                "agreement_rate": metrics.agreement_rate,
                "fallback_rate": metrics.fallback_rate,
                "error_rate": metrics.error_rate,
            },
        )
    except Exception as e:  # audit is best-effort — never break the alarm on it
        print(
            f"{_C['dim']}quality_regression audit write failed (continuing): "
            f"{type(e).__name__}{_C['reset']}",
            file=sys.stderr,
        )

    event = notify.event_for_quality_regression(mode=mode, reasons=reasons, settings=settings)
    if event is not None:
        # fire_safe respects the master toggle + webhook config and never raises.
        await notify.fire_safe(event, settings, audit)


def _eval_nightly(args: argparse.Namespace) -> int:
    """Nightly quality micro-eval: a tiny real-alert batch, trended locally.

    Thin orchestration over the existing batch machinery (`validate-batch`'s
    engine room): investigate ``quality_nightly_n`` real alerts at
    concurrency 1, aggregate, land ONE row in the ``quality_snapshots``
    table (pruned to the newest 90), and alarm — audit event + opt-in
    webhook — when the new point regresses against its own trailing
    same-mode history. Converts "the verdicts were validated once" into
    "the verdicts are measured every night".

    Two measurement modes (never blended in the trend):

    * ``graded``  — the cloud oracle critiques every run; ``agreement_rate``
      joins the trend. One cloud call per alert.
    * ``local``   — ZERO egress: no oracle at all; the trend carries the
      local proxies (fallback rate, error rate, verdict distribution,
      latency p50).

    Default mode follows the install's posture: ``oracle_enabled`` is the
    operator's standing declaration that cloud-oracle egress is acceptable,
    so it gates the nightly grader too; ``--graded`` / ``--local`` override.
    NO synth scenarios and NO meta-analysis — the nightly is a cheap smoke-
    trend over real traffic, not a benchmark.

    Scheduling: either the in-app scheduler (Config → Quality →
    ``eval_nightly_enabled``, runs daily at ``eval_nightly_hour_utc``) or
    host cron → ``docker exec`` (see docs/DOCKER.md). Both call the same
    :func:`soc_ai.eval.nightly.run_eval_nightly` core.

    Exit codes:
      0   ok — snapshot written (a fired alarm still exits 0: the run worked)
      2   sampler returned no eligible alerts (no snapshot)
      4   batch aborted by failure budget (snapshot IS still written — a
          fully-broken engine is exactly what the trend must record)
      5   unexpected internal error
    """
    from soc_ai.eval.nightly import run_eval_nightly  # noqa: PLC0415 - lazy

    settings = get_settings()

    # Mode: explicit flag wins (argparse enforces mutual exclusion); otherwise
    # follow the oracle posture — a zero-egress install trends locally without
    # any flag juggling in its crontab.
    if args.graded:
        mode = "graded"
    elif args.local:
        mode = "local"
    else:
        mode = "graded" if settings.oracle_enabled else "local"

    def _emit(line: str) -> None:
        print(f"{_C['dim']}{line}{_C['reset']}", file=sys.stderr, flush=True)

    result = asyncio.run(
        run_eval_nightly(
            settings,
            mode=mode,
            oql=args.oql,
            out_dir=args.out_dir,
            per_run_timeout_s=args.per_run_timeout_s,
            emit=_emit,
            # Module-global reference resolved here at call time, so tests
            # patching `cli._fire_quality_alarm` keep intercepting the alarm.
            fire_alarm=_fire_quality_alarm,
        )
    )
    rc = result.exit_code

    if rc == 5:
        print(f"{_C['red']}{result.detail}{_C['reset']}", file=sys.stderr)
    elif rc == 2:
        print(f"{_C['yellow']}{result.detail}{_C['reset']}", file=sys.stderr)
    elif result.metrics is not None:
        metrics = result.metrics

        def _pct(v: float | None) -> str:
            return "—" if v is None else f"{v * 100:.0f}%"

        print(
            f"{_C['bold']}quality snapshot{_C['reset']} ({result.mode}) — "
            f"ok={metrics.n_ok} err={metrics.n_error} · "
            f"agreement={_pct(metrics.agreement_rate)} · "
            f"fallback={_pct(metrics.fallback_rate)} · "
            f"error={_pct(metrics.error_rate)} · "
            f"p50={metrics.latency_p50_ms or '—'}ms\n"
            f"{_C['dim']}batch: {result.batch_dir}{_C['reset']}",
            file=sys.stderr,
        )
        if result.alarm_reasons:
            print(f"{_C['bold']}{_C['red']}QUALITY REGRESSION{_C['reset']}", file=sys.stderr)
            for r in result.alarm_reasons:
                print(f"  {_C['yellow']}- {r}{_C['reset']}", file=sys.stderr)
    if rc == 0:
        # The nightly only trends if something schedules it — hand the operator
        # the exact host-cron line (docs/DOCKER.md carries the same one).
        print(
            f"\n{_C['dim']}schedule it with host cron. See docs/DOCKER.md.{_C['reset']}\n"
            "  17 2 * * *  root  docker compose -f /opt/soc-ai/docker-compose.yml "
            "exec -T soc-ai python -m soc_ai eval-nightly",
            file=sys.stderr,
        )
    return rc


def _auto_aggregate_after_batch(args: argparse.Namespace) -> None:
    """Best-effort eval-report after a successful validate-batch.

    Failures here don't propagate — the batch itself is intact, and
    the operator can re-run ``soc-ai eval-report <batch-dir>`` by
    hand. Honors ``--no-meta`` from validate-batch by forwarding it
    through to the eval-report dispatch.
    """
    from pathlib import Path  # noqa: PLC0415 - lazy

    out_dir = Path(args.out_dir)
    if args.resume:
        target = out_dir
    else:
        candidates = sorted(
            (p for p in out_dir.iterdir() if p.is_dir() and p.name.startswith("batch-")),
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        )
        if not candidates:
            print(
                f"{_C['yellow']}skipping eval-report: no batch-* dir under {out_dir}{_C['reset']}",
                file=sys.stderr,
            )
            return
        target = candidates[0]

    forwarded = argparse.Namespace(
        batch_dir=str(target),
        no_meta=getattr(args, "no_meta", False),
        rerun_meta=False,
    )
    try:
        _eval_report(forwarded)
    except Exception as e:
        print(
            f"{_C['yellow']}eval-report failed. The batch is intact. Run "
            f"`soc-ai eval-report {target}` by hand. "
            f"{type(e).__name__}: {e}{_C['reset']}",
            file=sys.stderr,
        )


def _eval_report(args: argparse.Namespace) -> int:
    """Aggregate a batch's index.jsonl into aggregates.json + report.md.

    Runs the oracle meta-analysis by default (over the per-alert
    `## 3. Architecture` sections); pass ``--no-meta`` to skip it.
    Idempotent: re-running only re-runs meta-analysis if
    ``meta_analysis.md`` is missing or ``--rerun-meta`` is set.

    Exit codes:
      0   ok (aggregates always; meta best-effort)
      2   batch dir missing or has no index.jsonl
      5   unexpected internal error in the aggregator
    """
    from pathlib import Path  # noqa: PLC0415 - lazy

    from soc_ai.eval.report import (  # noqa: PLC0415 - lazy
        aggregates_to_json,
        build_report,
        load_index,
        write_report_markdown,
    )

    batch_dir = Path(args.batch_dir)
    if not batch_dir.exists() or not batch_dir.is_dir():
        print(f"{_C['red']}no such batch dir{_C['reset']}: {batch_dir}", file=sys.stderr)
        return 2

    try:
        json_path, md_path, agg = build_report(batch_dir)
    except FileNotFoundError as e:
        print(f"{_C['red']}{e}{_C['reset']}", file=sys.stderr)
        return 2
    except Exception as e:
        print(
            f"{_C['red']}eval-report failed{_C['reset']}: {type(e).__name__}: {e}",
            file=sys.stderr,
        )
        return 5

    print(
        f"{_C['dim']}aggregated {agg.n_total} rows "
        f"(ok={agg.n_ok} err={agg.n_error})\n"
        f"aggregates: {json_path}\nreport:     {md_path}{_C['reset']}",
        file=sys.stderr,
    )

    # Meta-analysis: opt-out via --no-meta. Skip if already done unless
    # --rerun-meta. The aggregate report has already been written; if
    # meta succeeds we re-render report.md so the meta pointer flips
    # from "run --rerun-meta" to "see meta_analysis.md".
    if args.no_meta:
        return 0
    meta_md = batch_dir / "meta_analysis.md"
    if meta_md.exists() and not args.rerun_meta:
        print(
            f"{_C['dim']}meta-analysis already exists at {meta_md}. "
            f"Pass --rerun-meta to build it again.{_C['reset']}",
            file=sys.stderr,
        )
        return 0

    settings = get_settings()
    rows = load_index(batch_dir)
    aggregates_dict = aggregates_to_json(agg)

    print(
        f"{_C['dim']}running meta-analysis (model={settings.claude_oracle_model})…{_C['reset']}",
        file=sys.stderr,
        flush=True,
    )

    from soc_ai.eval.meta_analysis import run_meta_analysis  # noqa: PLC0415 - lazy

    try:
        meta = asyncio.run(
            run_meta_analysis(
                rows=rows,
                batch_dir=batch_dir,
                aggregates=aggregates_dict,
                settings=settings,
            )
        )
    except RuntimeError as e:
        print(
            f"{_C['yellow']}meta-analysis skipped: {e}{_C['reset']}",
            file=sys.stderr,
        )
        return 0
    except Exception as e:
        print(
            f"{_C['yellow']}meta-analysis failed. The aggregates are intact. "
            f"{type(e).__name__}: {e}{_C['reset']}",
            file=sys.stderr,
        )
        return 0

    # Re-render report.md so the meta pointer reflects the new file.
    write_report_markdown(batch_dir, rows, agg)

    print(
        f"{_C['dim']}meta:       {meta.md_path}\n"
        f"meta json:  {meta.json_path}\n"
        f"({meta.n_runs_in_meta} runs · {meta.n_chunks} chunks · "
        f"{meta.n_themes_total} themes · {len(meta.changes)} changes)"
        f"{_C['reset']}",
        file=sys.stderr,
    )
    return 0


def _synth_clean(args: argparse.Namespace) -> int:
    """Delete synthetic-eval docs from ``logs-synth-*`` (TTL / cleanup)."""
    from datetime import UTC, datetime, timedelta  # noqa: PLC0415 - lazy

    from soc_ai.eval.synth_ingest import cleanup_synth_docs  # noqa: PLC0415 - lazy
    from soc_ai.so_client.elastic import ElasticClient  # noqa: PLC0415 - lazy

    settings = get_settings()
    older_than: datetime | None = None
    if args.older_than_days is not None:
        older_than = datetime.now(UTC) - timedelta(days=args.older_than_days)

    async def _go() -> int:
        elastic = ElasticClient(settings)
        try:
            return await cleanup_synth_docs(elastic, older_than=older_than)
        finally:
            await elastic.aclose()

    try:
        deleted = asyncio.run(_go())
    except Exception as e:
        print(
            f"{_C['red']}synth-clean failed{_C['reset']}: {type(e).__name__}: {e}",
            file=sys.stderr,
        )
        return 1
    scope = f" older than {args.older_than_days}d" if args.older_than_days is not None else ""
    print(f"{_C['dim']}deleted {deleted} synth docs from logs-synth-*{scope}{_C['reset']}")
    return 0


def _eval_journey(args: argparse.Namespace) -> int:
    """argparse handler for ``soc-ai eval-journey``.

    Runs ONE synthetic scenario's flagship journey end to end against the live
    grid — ingest the scenario (containment pre-check first), hunt its
    ``hunt_journey.objective`` under the synth opt-in, promote the
    best-matching finding through the real promotion chain, wait for the
    promoted investigation's verdict — then scores it stage by stage with
    :func:`soc_ai.eval.journey.score_journey` and prints the attributed result.

    Grid hygiene is deliberately the CALLER's job: run ``soc-ai synth-clean``
    BEFORE (a stale fixture must not score this run) and AFTER (no planted doc
    may outlive the eval) — this command never deletes anything itself.

    Exit codes:
      0   the journey reached COMPLETE
      1   the journey fell short (the printed stage/detail says where) — a
          legitimate measurement, and the CI-gateable signal
      2   unknown scenario id, or the scenario declares no hunt_journey
      5   the run itself failed (ingest refusal, scorer refusal, transport)
    """
    from pathlib import Path  # noqa: PLC0415 - lazy

    from soc_ai.eval.journey_runner import (  # noqa: PLC0415 - lazy
        EXIT_ERROR,
        EXIT_NO_JOURNEY,
        run_journey,
    )
    from soc_ai.eval.synth_loader import load_all_scenarios  # noqa: PLC0415 - lazy
    from soc_ai.so_client.elastic import ElasticClient  # noqa: PLC0415 - lazy

    settings = get_settings()
    scenarios_dir = Path(__file__).parent / "eval" / "synth_scenarios"
    try:
        catalogue = load_all_scenarios(scenarios_dir)
    except Exception as e:
        print(
            f"{_C['red']}scenario catalogue failed to load{_C['reset']}: {type(e).__name__}: {e}",
            file=sys.stderr,
        )
        return EXIT_ERROR
    scenario = next((s for s in catalogue if s.id == args.scenario_id), None)
    with_journeys = ", ".join(s.id for s in catalogue if s.hunt_journey is not None) or "(none)"
    if scenario is None:
        print(
            f"{_C['red']}unknown scenario id{_C['reset']}: {args.scenario_id!r}. "
            f"Scenarios with a hunt_journey: {with_journeys}",
            file=sys.stderr,
        )
        return EXIT_NO_JOURNEY
    if scenario.hunt_journey is None:
        print(
            f"{_C['red']}scenario {scenario.id!r} declares no hunt_journey{_C['reset']}. "
            f"Nothing can run. Scenarios with one: {with_journeys}",
            file=sys.stderr,
        )
        return EXIT_NO_JOURNEY

    def _emit(line: str) -> None:
        print(f"{_C['dim']}{line}{_C['reset']}", file=sys.stderr, flush=True)

    _emit(
        "eval-journey never cleans the grid. Bracket it with `soc-ai synth-clean` before and after."
    )

    async def _go() -> Any:
        elastic = ElasticClient(settings)
        try:
            return await run_journey(settings, scenario, elastic=elastic, emit=_emit)
        finally:
            with contextlib.suppress(Exception):
                await elastic.aclose()

    try:
        outcome = asyncio.run(_go())
    except Exception as e:
        print(
            f"{_C['red']}eval-journey failed{_C['reset']}: {type(e).__name__}: {e}",
            file=sys.stderr,
        )
        return EXIT_ERROR

    if outcome.result is None:
        print(f"{_C['red']}{outcome.detail}{_C['reset']}", file=sys.stderr)
        return int(outcome.exit_code)
    _print_journey_result(scenario, outcome)
    return int(outcome.exit_code)


def _print_journey_result(scenario: Any, outcome: Any) -> None:
    """Render a JourneyRunOutcome legibly: stage, verdicts, citations, detail."""
    from soc_ai.eval.journey import JourneyStage  # noqa: PLC0415 - lazy

    result = outcome.result
    complete = result.reached is JourneyStage.COMPLETE
    headline_color = _C["green"] if complete else _C["red"]
    stage = str(result.reached).upper()
    print(
        f"{_C['bold']}journey {result.scenario_id}{_C['reset']} — "
        f"{headline_color}{stage}{_C['reset']}"
    )
    actual = result.actual_verdict if result.actual_verdict is not None else "(none)"
    print(f"  verdict:  expected {result.expected_verdict} · actual {actual}")
    expected_events = list(scenario.hunt_journey.expected_cited_event_ids)
    cited = ", ".join(result.cited_expected_events) or "(none)"
    print(
        f"  cited:    {len(result.cited_expected_events)}/{len(expected_events)} "
        f"expected event(s): {cited}"
    )
    print(
        f"  rows:     hunt {outcome.hunt_id or '—'} · "
        f"investigation {outcome.investigation_id or '—'}"
    )
    print(f"  detail:   {result.detail}")


def _register_eval_journey(sub: Any) -> None:
    """Register the ``eval-journey`` subparser (split out of :func:`main` for size)."""
    p_ej = sub.add_parser(
        "eval-journey",
        help="Run ONE synth scenario's hunt journey against the live grid and "
        "score it stage by stage. The journey is ingest, hunt, promote, verdict. "
        "Exit 0 only when the journey reaches COMPLETE. Bracket it with "
        "`soc-ai synth-clean` before and after. This command never wipes the grid",
    )
    p_ej.add_argument(
        "scenario_id",
        help="Scenario id from soc_ai/eval/synth_scenarios/ that declares a "
        "hunt_journey (e.g. m1-cobalt-strike-beacon)",
    )
    p_ej.set_defaults(func=_eval_journey)


def _discover_internal_identifiers(_args: argparse.Namespace) -> int:
    """argparse handler for ``soc-ai discover-internal-identifiers``.

    Learns internal domain suffixes + bare internal hostnames from Security
    Onion data and upserts them into the managed ``internal_identifier`` table
    as ``detected`` rows (the Oracle egress sanitizer consumes the effective
    merged set). Skips entirely when ``discovery_enabled`` is off.

    Exit codes:
      0   ok (including a zero-yield scan, or discovery disabled)
      1   hard failure (ES client / migration could not be built)
    """
    from soc_ai.enrichment.discovery import run_discovery  # noqa: PLC0415 - lazy
    from soc_ai.so_client.elastic import ElasticClient  # noqa: PLC0415 - lazy
    from soc_ai.store.db import (  # noqa: PLC0415 - lazy
        make_engine,
        make_sessionmaker,
        run_migrations,
    )

    settings = get_settings()
    if not settings.discovery_enabled:
        print(
            f"{_C['dim']}internal-identifier discovery is off. Set "
            f"DISCOVERY_ENABLED=true to turn it on.{_C['reset']}"
        )
        return 0

    async def _go() -> int:
        engine = make_engine(settings)
        elastic = ElasticClient(settings)
        try:
            # Ensure the internal_identifier table exists (the timer/CLI may run
            # before the server has ever started against this DB).
            await run_migrations(engine)
            sessionmaker = make_sessionmaker(engine)
            summary = await run_discovery(elastic, sessionmaker, settings)
        finally:
            with contextlib.suppress(Exception):
                await elastic.aclose()
            with contextlib.suppress(Exception):
                await engine.dispose()

        print(
            f"{_C['bold']}internal-identifier discovery{_C['reset']} — "
            f"scanned≈{summary.scanned_events} events, "
            f"internal_hosts_seen={summary.internal_hosts_seen}"
        )
        print(
            f"  suffixes: {summary.suffixes_found} found "
            f"({_C['green']}{summary.suffixes_active} active{_C['reset']}, "
            f"{summary.suffixes_muted} muted)"
        )
        print(f"  hosts:    {summary.hosts_found} found")
        print(
            f"  cidrs:    {summary.cidrs_found} found "
            f"({summary.cidrs_suggested} suggested, "
            f"{_C['dim']}always muted, un-mute to apply{_C['reset']})"
        )
        if summary.errors:
            n_err = len(summary.errors)
            print(f"{_C['yellow']}  degraded ({n_err} sub-query error(s)):{_C['reset']}")
            for err in summary.errors:
                print(f"    - {err}")
        return 0

    try:
        return asyncio.run(_go())
    except Exception as e:
        print(
            f"{_C['red']}discover-internal-identifiers failed{_C['reset']}: "
            f"{type(e).__name__}: {e}",
            file=sys.stderr,
        )
        return 1


def _audit_verify(args: argparse.Namespace) -> int:
    """argparse handler for ``soc-ai audit verify``.

    Pulls every record from the audit index (``{audit_index_alias}-*``), sorted
    ascending by timestamp, partitions it into epochs at each restart boundary,
    and runs the tamper-evident hash chain over EVERY epoch — never stopping at
    the first broken one (:func:`soc_ai.audit.verify.verify_audit_chain`). This
    is the operator's way to actually exercise the tamper-evidence: every epoch
    intact proves no audit record was edited, reordered, inserted, or deleted
    since it was written, within any process incarnation's own trail.

    A chain that spans more than one epoch is NOT itself a problem — a process
    restart is a legitimate boundary (prod carried 134 of them, 2026-06-24 →
    2026-08-16, from a chain-head recovery bug fixed 2026-08-17; see
    :mod:`soc_ai.audit.verify`'s module docstring) — but it is a genuinely
    weaker claim than one unbroken chain, since cross-epoch linkage can never be
    checked (a genesis record's ``prev_hash`` is the all-zero hash by
    construction). So a multi-epoch all-clear prints amber, not green: a
    partial all-clear must never wear full success livery.

    A TAMPER verdict now reports its blast radius, not just its existence: live
    prod (2026-08-21) found a REAL duplicate-seq artifact from the historic
    pre-1.2.8 write-side stale-head seq-reuse bug, mid-epoch, on top of the
    already-known genesis-reset fragmentation — and stopping at the first break
    (the old behavior) could not answer "is anything MORE recent also broken".
    Every epoch is checked regardless of earlier breaks; the tally names how
    many broke, the oldest (compat) and newest broken epoch, and either
    reassures ("every epoch after the newest break verified intact") or, if the
    break reaches the current epoch, says so plainly ("the latest epoch is
    broken") — see :mod:`soc_ai.audit.verify`'s module docstring for the finding
    that made this a real requirement.

    Exit codes:
      0   every epoch intact (including an empty index — nothing to tamper
          with), whether that is one epoch or many
      1   the chain does not verify — at least one epoch broke. The headline
          distinguishes the two reasons: TAMPER DETECTED when a record no
          longer matches its own hash, CHAIN BROKEN when every copy still
          hashes true and the damage is duplicated or absent positions (two
          writers, not an intruder). Both exit 1.
      2   could not run (ES unreachable / settings didn't load)
    """
    from soc_ai.audit.verify import (  # noqa: PLC0415 - lazy
        ChainVerifyResult,
        verify_audit_chain,
    )
    from soc_ai.so_client.elastic import ElasticClient  # noqa: PLC0415 - lazy

    try:
        settings = get_settings()
    except Exception as e:
        print(
            f"{_C['red']}audit verify could not run{_C['reset']}: settings did not load "
            f"({type(e).__name__}: {e}). Run from a directory with a populated .env.",
            file=sys.stderr,
        )
        return 2

    days: int | None = getattr(args, "days", None)

    async def _go() -> ChainVerifyResult:
        elastic = ElasticClient(settings)
        try:
            return await verify_audit_chain(elastic, settings.audit_index_alias, days=days)
        finally:
            with contextlib.suppress(Exception):
                await elastic.aclose()

    try:
        result = asyncio.run(_go())
    except Exception as e:
        # A verification against an unreachable index is "could not run", NOT
        # "intact" — never let an ES/transport error read as a clean chain.
        print(
            f"{_C['red']}audit verify could not run{_C['reset']}: "
            f"{type(e).__name__}: {e} "
            f"{_C['dim']}(is the ES/audit index reachable?){_C['reset']}",
            file=sys.stderr,
        )
        return 2

    scope = f" (last {days}d window)" if days is not None else ""
    if result.capped:
        print(
            f"{_C['yellow']}warning: the scan hit the record cap. It verified only "
            f"a prefix of the chain. Bound the scan with --days to check a smaller "
            f"window.{_C['reset']}",
            file=sys.stderr,
        )

    if not result.ok:
        # The tally: how many epochs broke, and where the oldest and newest
        # breaks are. `epochs_broken == 1` gets the tighter singular phrasing
        # (naming "oldest" and "newest" for the same one epoch twice would be
        # true but redundant) — both name the seq LOCAL to that epoch, since
        # seq resets to 0 at every genesis.
        if result.epochs_broken == 1:
            tally = (
                f"1 of {result.epochs} epochs broken. The break is at seq "
                f"{result.first_broken_seq} in epoch {result.first_broken_epoch_start}"
            )
        else:
            tally = (
                f"{result.epochs_broken} of {result.epochs} epochs broken. The oldest "
                f"break is at seq {result.first_broken_seq} in epoch "
                f"{result.first_broken_epoch_start}. The newest broken epoch is "
                f"{result.newest_broken_epoch_start}"
            )
        # A capped scan cannot vouch for anything beyond its own prefix — the
        # cap always truncates the NEWEST end of the chain (the fetch is
        # oldest-first) — so neither claim below is honest under `capped`,
        # regardless of which way `latest_epoch_broken` happens to land for
        # the prefix actually scanned. The standalone capped warning above
        # already carries the "this is not the full picture" signal.
        if result.capped:
            trailing = ""
        elif result.latest_epoch_broken:
            trailing = " The latest epoch is broken."
        else:
            trailing = f" Every epoch after {result.newest_broken_epoch_start} verified intact."
        # The headline has to match the evidence underneath it. This printed
        # "TAMPER DETECTED" unconditionally, and the very next line said "the
        # records were not altered; two writers continued the chain from the
        # same point" — a headline contradicted by its own body, on a finding
        # that is soc-ai's own concurrency and not an intruder.
        #
        # `altered_records` is the discriminator and it is exact: a record that
        # no longer matches its own hash is someone changing the record of a
        # decision. A position claimed twice, with every copy still hashing
        # true, is two writers. Both mean the chain does not verify, so both
        # still exit 1 and both still print red — what changes is which of the
        # two an operator is being told to go and look for.
        headline = "TAMPER DETECTED" if result.altered_records else "CHAIN BROKEN"
        print(
            f"{_C['red']}{_C['bold']}{headline}{_C['reset']}{_C['red']}: "
            f"{tally}.{trailing}{_C['reset']}{scope}",
            file=sys.stderr,
        )
        # WHAT broke, not just that something did. A position claimed twice by
        # two writers and a record whose content was edited after the fact are
        # different events with different responses, and one sentence covering
        # both ("a record was edited, reordered, inserted, or deleted") left an
        # operator unable to tell a known concurrency defect from an intrusion.
        detail = result.newest_break_detail or result.first_break_detail
        print(
            f"{_C['dim']}{result.records_verified} record(s) scanned. "
            f"{detail or 'A record was edited, reordered, inserted, or deleted.'}"
            f"{_C['reset']}",
            file=sys.stderr,
        )
        # How widespread, in the same words the scheduled alarm and the webhook
        # use. Naming one sequence number leaves a single collision and a
        # forked afternoon reading identically.
        from soc_ai.audit.verify import describe_blast_radius  # noqa: PLC0415

        blast_radius = describe_blast_radius(result)
        if blast_radius:
            print(f"{_C['dim']}{blast_radius}{_C['reset']}", file=sys.stderr)
        if result.newest_break_kind == "duplicate_seq":
            print(
                f"{_C['dim']}A duplicated position is the signature of two writers "
                f"that append at once. An edit leaves a different signature. Compare "
                f"the timestamps and sessions of the records at that sequence. "
                f"Two different sessions minutes apart means concurrency. One record "
                f"rewritten in place means an edit.{_C['reset']}",
                file=sys.stderr,
            )
        return 1

    if result.records_verified == 0:
        print(f"{_C['green']}audit chain intact{_C['reset']}: 0 records{scope}")
        return 0

    # epochs > 1: every epoch checked out, but that is "no tamper found within
    # any restart's own trail" — never "one unbroken chain". No green, no
    # checkmark-shaped wording; amber, same livery `capped` already uses above,
    # because this is the same species of caveat (an honest all-clear that
    # falls short of the full claim).
    if result.epochs > 1:
        print(
            f"{_C['yellow']}chain intact within {result.epochs} epochs{_C['reset']}: "
            f"{result.records_verified} records verified{scope}. Epoch boundaries are "
            f"process restarts. A chain-head recovery bug was fixed on 2026-08-17. "
            f"Cross-epoch linkage is not provable."
        )
        return 0

    span = f"seq {result.first_seq}..{result.last_seq}"
    print(
        f"{_C['green']}audit chain intact{_C['reset']}: "
        f"{result.records_verified} records verified ({span}){scope}"
    )
    return 0


def _register_audit(sub: Any) -> None:
    """Register the ``audit`` command group (currently just ``audit verify``)."""
    p_audit = sub.add_parser(
        "audit",
        help="Audit-trail tooling. Subcommand: `verify` checks the tamper-evident "
        "hash chain over the live audit index",
    )
    audit_sub = p_audit.add_subparsers(dest="audit_cmd")
    p_ver = audit_sub.add_parser(
        "verify",
        help="Verify the tamper-evident audit hash chain against the live ES "
        "audit index. Exit 0 = intact, 1 = tamper detected, 2 = could not run",
    )
    p_ver.add_argument(
        "--days",
        type=int,
        default=None,
        metavar="N",
        help="Bound the scan to audit records from the last N days, by timestamp. "
        "The default is the whole index. A windowed scan verifies contiguity "
        "WITHIN the window. It cannot verify linkage across the window boundary, "
        "because it does not fetch the record before the window.",
    )
    p_ver.set_defaults(func=_audit_verify)
    # `soc-ai audit` with no subcommand: print the group help instead of serving.
    p_audit.set_defaults(func=lambda _a: (p_audit.print_help(), 2)[1])


def _resolve_data_dir(args: argparse.Namespace) -> Path | None:
    """Data directory for backup/restore: ``--data-dir`` wins, then settings.

    Returns None (the caller prints the error) when neither resolves — e.g.
    no .env on this host and no explicit flag.
    """
    override = getattr(args, "data_dir", None)
    if override:
        return Path(override)
    try:
        return get_settings().soc_ai_data_dir
    except Exception:
        return None


def _resolve_cache_dirs() -> dict[str, Path] | None:
    """The enrichment-cache directories from settings, or None if no settings."""
    try:
        settings = get_settings()
    except Exception:
        return None
    return {
        "blocklists": settings.blocklist_data_dir,
        "maxmind": settings.maxmind_data_dir,
        "cloud_prefixes": settings.cloud_prefix_data_dir,
    }


def _backup(args: argparse.Namespace) -> int:
    """Snapshot the store into a tar.gz (safe while the app is running).

    Exit codes:
      0   archive written
      1   backup failed (no store, unreadable data dir, I/O error)
      2   cannot resolve the data dir / cache dirs (pass --data-dir or fix .env)
    """
    from soc_ai.backup import (  # noqa: PLC0415 - lazy
        BackupError,
        create_backup,
        default_backup_name,
    )

    data_dir = _resolve_data_dir(args)
    if data_dir is None:
        print(
            f"{_C['red']}could not resolve the data directory{_C['reset']}: settings "
            "did not load and no --data-dir was given. Pass --data-dir PATH, or run "
            "from a directory with a populated .env.",
            file=sys.stderr,
        )
        return 2
    cache_dirs = _resolve_cache_dirs()
    if args.full and cache_dirs is None:
        print(
            f"{_C['red']}--full needs the cache directories from settings{_C['reset']}. "
            "The settings did not load. Run from a directory with a populated .env. "
            "You can also drop --full. `soc-ai blocklists refresh` downloads the "
            "caches again.",
            file=sys.stderr,
        )
        return 2

    out = Path(args.out) if args.out else Path.cwd() / default_backup_name()
    try:
        result = create_backup(data_dir, out, full=args.full, cache_dirs=cache_dirs)
    except BackupError as e:
        print(f"{_C['red']}backup failed{_C['reset']}: {e}", file=sys.stderr)
        return 1

    m = result.manifest
    head = m.alembic_head or "(fresh, no migrations applied)"
    print(
        f"backed up {data_dir / 'soc-ai.db'} "
        f"({result.db_bytes / 1_048_576:.1f} MiB, migration head {head})"
    )
    print(f"  sidecars: {', '.join(m.sidecars) or '(none)'}")
    if m.full:
        print(f"  caches:   {', '.join(m.caches) or '(none found)'}")
    else:
        print(
            f"  caches:   excluded {_C['dim']}(`soc-ai blocklists refresh` re-seeds "
            f"them. --full includes them.){_C['reset']}"
        )
    print(f"{_C['bold']}archive: {result.archive}{_C['reset']}")
    return 0


def _restore(args: argparse.Namespace) -> int:
    """Restore a backup archive into the data directory.

    Exit codes:
      0   restored
      1   bad archive / I/O failure
      2   refused (existing store or live WAL without --yes; archive from a
          NEWER soc-ai = unsupported downgrade) or unresolvable data dir
    """
    from soc_ai.backup import BackupError, RestoreRefused, restore_backup  # noqa: PLC0415 - lazy

    data_dir = _resolve_data_dir(args)
    if data_dir is None:
        print(
            f"{_C['red']}could not resolve the data directory{_C['reset']}: settings "
            "did not load and no --data-dir was given. Pass --data-dir PATH, or run "
            "from a directory with a populated .env.",
            file=sys.stderr,
        )
        return 2

    try:
        result = restore_backup(
            Path(args.archive),
            data_dir,
            assume_yes=args.yes,
            cache_dirs=_resolve_cache_dirs(),
        )
    except RestoreRefused as e:
        print(f"{_C['red']}restore refused{_C['reset']}: {e}", file=sys.stderr)
        return 2
    except BackupError as e:
        print(f"{_C['red']}restore failed{_C['reset']}: {e}", file=sys.stderr)
        return 1

    for w in result.warnings:
        print(f"{_C['yellow']}warning: {w}{_C['reset']}", file=sys.stderr)
    head = result.archive_head or "(fresh, no migrations applied)"
    print(f"restored store → {result.db_path} (migration head {head})")
    if result.archive_head and result.code_head and result.archive_head != result.code_head:
        print(
            f"  archive head {result.archive_head} is older than code head "
            f"{result.code_head}. The app migrates it to head at the next startup."
        )
    print(f"  sidecars: {', '.join(result.sidecars) or '(none)'}")
    if result.caches:
        print(f"  caches:   {', '.join(result.caches)}")
    print(
        f"{_C['bold']}restart the app to pick up the restored store{_C['reset']} "
        f"{_C['dim']}(docker compose up -d soc-ai / systemctl restart soc-ai){_C['reset']}"
    )
    return 0


def _register_backup(sub: Any) -> None:
    """Register the ``backup`` + ``restore`` subparsers (split out for size)."""
    p_bak = sub.add_parser(
        "backup",
        help="Snapshot the live SQLite store + app-owned sidecar files into a "
        "portable tar.gz (uses the SQLite backup API — safe while the app runs)",
    )
    p_bak.add_argument(
        "--out",
        default=None,
        metavar="PATH",
        help="Archive path to write (default: ./soc-ai-backup-<UTC-stamp>.tar.gz)",
    )
    p_bak.add_argument(
        "--full",
        action="store_true",
        help="Also include the enrichment caches: blocklists, MaxMind and cloud "
        "prefixes. soc-ai excludes them by default. `soc-ai blocklists refresh` "
        "downloads them again. They are much larger than the DB",
    )
    p_bak.add_argument(
        "--data-dir",
        default=None,
        metavar="PATH",
        help="Override the data directory (default: SOC_AI_DATA_DIR from env/.env)",
    )
    p_bak.set_defaults(func=_backup)

    p_res = sub.add_parser(
        "restore",
        help="Restore a `soc-ai backup` archive into the data directory. Without "
        "--yes it refuses to overwrite an existing store. Without --yes it also "
        "refuses to restore under an app that looks live. It refuses an archive "
        "from a newer soc-ai. Stop the app first",
    )
    p_res.add_argument("archive", help="Path to the soc-ai-backup-*.tar.gz to restore")
    p_res.add_argument(
        "--yes",
        action="store_true",
        help="Overwrite existing state. Proceed even when the store looks live "
        "with recent WAL activity. The restore prints what it overwrites",
    )
    p_res.add_argument(
        "--data-dir",
        default=None,
        metavar="PATH",
        help="Override the data directory (default: SOC_AI_DATA_DIR from env/.env)",
    )
    p_res.set_defaults(func=_restore)


def _spec_run(args: argparse.Namespace) -> int:
    """Run one hunt spec, or the whole catalog, and print candidates as JSON.

    Exit codes:
      0   ran; nothing found, or candidates printed
      2   no such spec id
      3   at least one spec was BLIND (its precondition matched nothing)
      5   at least one spec errored against the grid

    Blind gets its own exit code on purpose. "The DCSync spec found nothing"
    and "the DCSync spec cannot see, because Directory Service Access auditing
    is off" are opposite facts, and a script that treats both as success is
    exactly the false all-clear this tool exists to prevent.
    """
    import asyncio  # noqa: PLC0415 - lazy
    import json  # noqa: PLC0415 - lazy
    from dataclasses import asdict  # noqa: PLC0415 - lazy
    from pathlib import Path  # noqa: PLC0415 - lazy

    from soc_ai.hunting.execute import run_spec  # noqa: PLC0415 - lazy
    from soc_ai.hunting.spec import load_catalog  # noqa: PLC0415 - lazy
    from soc_ai.so_client.elastic import ElasticClient  # noqa: PLC0415 - lazy

    settings = get_settings()
    catalog = load_catalog(Path(__file__).parent / "hunting" / "catalog")

    if args.spec_id and args.spec_id not in catalog:
        print(f"no such spec: {args.spec_id}", file=sys.stderr)
        print(f"available: {', '.join(sorted(catalog))}", file=sys.stderr)
        return 2
    specs = [catalog[args.spec_id]] if args.spec_id else list(catalog.values())

    async def _go() -> list[Any]:
        elastic = ElasticClient(settings)
        try:
            return [
                await run_spec(
                    spec,
                    elastic=elastic,
                    settings=settings,
                    since=args.since,
                    until=args.until,
                    include_synth=args.include_synth,
                )
                for spec in specs
            ]
        finally:
            await elastic.aclose()

    runs = asyncio.run(_go())

    blind = any(r.blind for r in runs)
    errored = any(r.error for r in runs)
    for run in runs:
        payload = {
            **{k: v for k, v in asdict(run).items() if k != "candidates"},
            "clean": run.clean,
            "candidates": [asdict(c) for c in run.candidates],
        }
        print(json.dumps(payload, default=str))

    if errored:
        return 5
    return 3 if blind else 0


def _register_spec_run(sub: Any) -> None:
    """Register the ``spec-run`` subparser."""
    p_sr = sub.add_parser(
        "spec-run",
        help="Run a declarative hunt spec (or the whole catalog) against the grid "
        "and print candidates as JSON. No model is called.",
    )
    p_sr.add_argument(
        "spec_id",
        nargs="?",
        default=None,
        help="Spec id to run; omit to run the whole catalog",
    )
    p_sr.add_argument(
        "--since",
        required=True,
        help="Window start, ES date math or ISO-8601 (e.g. now-7d, 2026-09-03T00:00:00Z)",
    )
    p_sr.add_argument(
        "--until",
        default="now",
        help="Window end, ES date math or ISO-8601 (default: now)",
    )
    p_sr.add_argument(
        "--include-synth",
        action="store_true",
        help="Also read planted evaluation documents in logs-synth-*. A spec can "
        "then run against a synthetic scenario planted on a live grid. Do not use "
        "this for production hunting. It is off by default. Every other query "
        "excludes those documents.",
    )
    p_sr.set_defaults(func=_spec_run)


def _spec_sweep(args: argparse.Namespace) -> int:
    """Sweep the hunt catalog, gate the results, and record triggered hunts.

    Exit codes:
      0   swept; hunts recorded or nothing to report
      3   at least one spec was BLIND
      5   at least one spec errored against the grid

    Two modes worth knowing:

    ``--shadow`` runs everything and records NO hunt, while still reporting what
    each spec would have surfaced. It seeds the fire-once state rather than
    spending it, so a week of shadow does not leave the spec silent on the day
    it goes live.

    ``--backfill`` sweeps history to seed state and produce one digest, rather
    than firing a finding per historical occurrence at somebody who was not
    watching when they happened.
    """
    import asyncio  # noqa: PLC0415 - lazy
    import json  # noqa: PLC0415 - lazy
    from datetime import UTC, datetime  # noqa: PLC0415 - lazy

    from soc_ai.hunting.catalog_tiers import effective_catalog  # noqa: PLC0415 - lazy
    from soc_ai.hunting.sweep import sweep_catalog  # noqa: PLC0415 - lazy
    from soc_ai.so_client.elastic import ElasticClient  # noqa: PLC0415 - lazy
    from soc_ai.store.db import (  # noqa: PLC0415 - lazy
        make_engine,
        make_sessionmaker,
        run_migrations,
    )

    settings = get_settings()
    # An operator following the console's hint types `spec-sweep --shadow` with
    # no window and got an argparse error. The scheduler already knows the
    # answer, so the CLI uses the same one rather than making the operator
    # supply it: the same helper the loop calls, floor and clamp included, so
    # a hand-run sweep covers exactly what the loop's would. The widening is
    # said the way the loop says it; with no logging configured this lands on
    # stderr, and the JSON on stdout stays parseable.
    since = args.since
    if since is None:
        import logging  # noqa: PLC0415 - lazy

        from soc_ai.hunting.window import sweep_window  # noqa: PLC0415 - lazy

        window = sweep_window(settings)
        window.say_if_widened(logging.getLogger(__name__))
        since = window.since

    async def _go() -> Any:
        engine = make_engine(settings)
        # The sweep WRITES, so the schema has to exist. `serve` migrates at
        # startup; a CLI invocation against a fresh database would otherwise
        # fail on a missing table halfway through the catalog, after some
        # specs had already queried the grid.
        await run_migrations(engine)
        elastic = ElasticClient(settings)
        try:
            async with make_sessionmaker(engine)() as session:
                # The effective catalog, not the files alone: a retired
                # analytic must stop running and a local one in shadow must
                # start, and both facts live in the database.
                tiers = await effective_catalog(session)
                result = await sweep_catalog(
                    tiers.specs,
                    session=session,
                    elastic=elastic,
                    settings=settings,
                    since=since,
                    until=args.until,
                    now=datetime.now(UTC).replace(tzinfo=None),
                    backfill=args.backfill,
                    include_synth=args.include_synth,
                    record=not args.shadow,
                    shadow_ids=tiers.shadow_ids,
                )
                await session.commit()
                return result
        finally:
            await elastic.aclose()
            await engine.dispose()

    result = asyncio.run(_go())
    print(json.dumps(result.to_dict(), indent=2))
    if result.errored:
        return 5
    return 3 if result.blind else 0


def _priors(args: argparse.Namespace) -> int:
    """Run every role prior against every profiled entity and print what fired.

    Exit codes:
      0   swept; findings printed (or none, with the coverage breakdown)
      5   the sweep could not complete against the grid

    A zero-finding sweep prints its coverage counts either way. "Nothing
    departed" and "nothing could be measured" are the same empty list, and an
    analyst who cannot tell them apart has been handed an all-clear that was
    never earned.
    """
    import asyncio  # noqa: PLC0415 - lazy

    from soc_ai.config import get_settings  # noqa: PLC0415 - lazy
    from soc_ai.hunting.prior_sweep import (  # noqa: PLC0415 - lazy
        format_sweep,
        run_prior_sweep,
    )
    from soc_ai.so_client.elastic import ElasticClient  # noqa: PLC0415 - lazy
    from soc_ai.store.db import (  # noqa: PLC0415 - lazy
        make_engine,
        make_sessionmaker,
        run_migrations,
    )

    settings = get_settings()

    async def _go() -> int:
        engine = make_engine(settings)
        await run_migrations(engine)
        elastic = ElasticClient(settings)
        try:
            async with make_sessionmaker(engine)() as session:
                # The estate's own address space, so the sweep does not record
                # observations about the internet and form leads out of them.
                from soc_ai.oracle.identifiers import (  # noqa: PLC0415 - lazy
                    effective_internal_identifiers,
                )

                cidrs = (await effective_internal_identifiers(session, settings)).cidrs
                # The effective catalog, for the same reason the spec sweep
                # reads it: a retired prior must stop running and a local one
                # in shadow must start.
                from soc_ai.hunting.catalog_tiers import (  # noqa: PLC0415 - lazy
                    effective_catalog,
                )

                tiers = await effective_catalog(session)
                sweep = await run_prior_sweep(
                    elastic=elastic,
                    settings=settings,
                    db=session,
                    recent_hours=int(args.recent_hours),
                    record=bool(args.record),
                    cidrs=cidrs,
                    catalog=tiers.specs,
                    shadow_ids=tiers.shadow_ids,
                )
            print(format_sweep(sweep))
            return 5 if sweep.errors else 0
        finally:
            # aclose, named directly. `getattr(elastic, "close", None)` was the
            # first cut and it silently did nothing -- the method is aclose --
            # leaking an aiohttp session on every run. Same shape as the
            # operator_value bug in prior_sweep: a getattr default turns a
            # wrong name into a no-op instead of an error.
            await elastic.aclose()
            await engine.dispose()

    return asyncio.run(_go())


def _register_priors(sub: Any) -> None:
    """Register the ``priors`` subparser."""
    p_pr = sub.add_parser(
        "priors",
        help="Run the role priors against every entity that has a behavioural "
        "profile, and print what departed. No model is called.",
    )
    p_pr.add_argument(
        "--recent-hours",
        type=int,
        default=24,
        help="How far back 'lately' reaches. The default is 24. This window is "
        "much shorter than the 30-day baseline. Over one window, every "
        "observation is already in the baseline built from it. The sweep is then "
        "clean whatever happened.",
    )
    p_pr.add_argument(
        "--record",
        action="store_true",
        help="Write each departure as an observation, and form leads from what "
        "accumulates. This is OFF by default, because a read of the coverage must "
        "have no side effect. An operator who reads the sweep must not change what "
        "the next run concludes. soc-ai records leads in shadow either way.",
    )
    p_pr.set_defaults(func=_priors)


def format_lead_quality(report: Any) -> str:
    """The lead quality block as a table.

    The same numbers the Analytics tab shows, so an operator on a terminal and
    an analyst on the page read one report. The rule and the noise-floor note
    sit under the table, because a number with no rule beside it invites a
    change to the rule.
    """
    lines: list[str] = ["week      formed  hunted  threat  promoted  dismissed"]
    for week in report.weeks:
        dismissed = ", ".join(f"{k}={v}" for k, v in week.dismissed.items()) or "-"
        lines.append(
            f"{week.week:<9} {week.formed:>6}  {week.hunted:>6}  {week.threat:>6}  "
            f"{week.promoted:>8}  {dismissed}"
        )
    if report.by_types:
        width = max(len(t.types) for t in report.by_types)
        width = max(width, len("types"))
        lines.append("")
        lines.append(f"{'types':<{width}}  formed  dismissed  threat")
        for row in report.by_types:
            lines.append(
                f"{row.types:<{width}}  {row.formed:>6}  {row.dismissed:>9}  {row.threat:>6}"
            )
    else:
        lines.append("")
        lines.append("No lead formed in this window.")
    lines.append("")
    lines.append(f"rule: {report.rule}")
    lines.append(f"note: {report.note}")
    return "\n".join(lines)


def _leads(args: argparse.Namespace) -> int:
    """Print what the lead rule produced over the last few weeks.

    Exit codes:
      0   the report printed
      2   no mode was asked for

    Reads the local store only. No model and no grid.
    """
    import asyncio  # noqa: PLC0415 - lazy

    if not getattr(args, "report", False):
        print("soc-ai leads needs a mode. Use --report.")
        return 2

    from soc_ai.config import get_settings  # noqa: PLC0415 - lazy
    from soc_ai.store.db import (  # noqa: PLC0415 - lazy
        make_engine,
        make_sessionmaker,
        run_migrations,
    )

    settings = get_settings()

    async def _go() -> int:
        # The route owns the counting, so the table and the Analytics tab can
        # never report different numbers for one week.
        from soc_ai.api.webui.routes_hunts import lead_quality  # noqa: PLC0415 - lazy

        engine = make_engine(settings)
        await run_migrations(engine)
        try:
            async with make_sessionmaker(engine)() as session:
                report = await lead_quality(session, weeks=int(args.weeks))
            print(format_lead_quality(report))
            return 0
        finally:
            await engine.dispose()

    return asyncio.run(_go())


def _register_leads(sub: Any) -> None:
    """Register the ``leads`` subparser."""
    p_le = sub.add_parser(
        "leads",
        help="Print what the lead rule produced: leads formed, hunted, with a "
        "threat finding, dismissed by reason and promoted, per week and per "
        "observation-type pair. No model is called.",
    )
    p_le.add_argument(
        "--report",
        action="store_true",
        help="Print the lead quality table. This is the only mode today.",
    )
    p_le.add_argument(
        "--weeks",
        type=int,
        default=4,
        help="How many ISO weeks to report, newest first. The default is 4. A "
        "threshold moves on a week of data, never on a day.",
    )
    p_le.set_defaults(func=_leads)


def _register_spec_sweep(sub: Any) -> None:
    """Register the ``spec-sweep`` subparser."""
    p_ss = sub.add_parser(
        "spec-sweep",
        help="Sweep the declarative hunt catalog and record triggered hunts for "
        "anything not already handled. No model is called.",
    )
    p_ss.add_argument(
        "--since",
        default=None,
        help="Window start (ES date math or ISO-8601). Defaults to the configured "
        "look-back window, so the command the console prints runs as printed.",
    )
    p_ss.add_argument("--until", default="now", help="Window end (default: now)")
    p_ss.add_argument(
        "--shadow",
        action="store_true",
        help="Report what each spec WOULD find. Record no hunt. This seeds the "
        "fire-once state and does not spend it. The spec is then not silent when "
        "it goes live.",
    )
    p_ss.add_argument(
        "--backfill",
        action="store_true",
        help="Seed state from history without firing a finding per historical "
        "occurrence. Use once when adding a spec.",
    )
    p_ss.add_argument(
        "--include-synth",
        action="store_true",
        help="Also read planted evaluation documents in logs-synth-*. The sweep can "
        "then run against a synthetic scenario planted on a live grid. Do not use "
        "this for production hunting. It is off by default. soc-ai marks a hunt "
        "recorded under it as a synthetic-evaluation run.",
    )
    p_ss.set_defaults(func=_spec_sweep)


def _register_synth_clean(sub: Any) -> None:
    """Register the ``synth-clean`` subparser (split out of :func:`main` for size)."""
    p_sc = sub.add_parser(
        "synth-clean",
        help="Delete synthetic-eval docs (synth.scenario_id) from logs-synth-*. "
        "The fixtures then do not accumulate",
    )
    p_sc.add_argument(
        "--older-than-days",
        type=int,
        default=None,
        help="Only delete synth docs older than N days (default: delete all)",
    )
    p_sc.set_defaults(func=_synth_clean)
    # Registered here rather than in main(): eval-journey is synth-clean's
    # sibling (synth-clean is the mandatory hygiene bracket around every
    # journey run), and main() is at its statement budget (the model-probe
    # precedent in _register_doctor).
    _register_eval_journey(sub)


def _register_eval_nightly(sub: Any) -> None:
    """Register the ``eval-nightly`` subparser (split out of :func:`main` for size)."""
    p_en = sub.add_parser(
        "eval-nightly",
        help="Nightly quality micro-eval. It investigates a few real alerts, lands "
        "one row in the local quality trend, and alarms on a regression. Schedule "
        "it from host cron. See docs/DOCKER.md. The mode defaults to oracle-graded "
        "if oracle_enabled is on. Otherwise the mode is zero-egress local",
    )
    p_en.add_argument(
        "--oql",
        default=None,
        help="OQL selecting candidate alerts (default: the web-UI alerts feed "
        "query, webui_alerts_query — the same population the dashboard shows)",
    )
    nightly_mode = p_en.add_mutually_exclusive_group()
    nightly_mode.add_argument(
        "--graded",
        action="store_true",
        help="Force oracle grading (one cloud call per alert; agreement_rate joins the trend)",
    )
    nightly_mode.add_argument(
        "--local",
        action="store_true",
        help="Force zero-egress local mode (no oracle; trends fallback/error "
        "rates, verdict distribution and latency only)",
    )
    p_en.add_argument(
        "--out-dir",
        # None (not "evals") so the default is resolved against the install's
        # data dir — in a container the WORKDIR is not a volume, so a relative
        # default silently discards every bundle on the next recreate, taking
        # the oracle critiques behind each alarm with it.
        default=None,
        help="Parent directory for the batch-<ts>/ artifact subdir "
        "(default: alongside the data dir, e.g. /var/lib/soc-ai/evals; ./evals "
        "on a host install)",
    )
    p_en.add_argument(
        "--per-run-timeout-s",
        type=int,
        default=1800,
        help="Per-alert harness wall-clock cap in seconds (default: 1800 = 30min)",
    )
    p_en.set_defaults(func=_eval_nightly)


def _register_doctor(sub: Any) -> None:
    """Register the ``doctor`` subparser (split out of :func:`main` for size)."""
    p_doc = sub.add_parser(
        "doctor",
        help="Check the whole dependency surface and print a pass/fail table. The "
        "checks cover config, store, DNS, TCP and TLS reachability, SO and ES, the "
        "audit write grant, index-pattern coverage, the gateway and model fitness. "
        "Exit 0 only if every required check passes",
    )
    p_doc.add_argument(
        "--json",
        action="store_true",
        help="Emit the check results as JSON instead of the table (for automation)",
    )
    p_doc.add_argument(
        "--strict",
        action="store_true",
        help="Exit non-zero on WARN and on FAIL. This is opt-in. An existing "
        "monitor keyed on this exit status keeps seeing what it always saw",
    )
    p_doc.set_defaults(func=_doctor)
    # Registered here rather than in main(): model-probe is doctor's sibling
    # diagnostic, and main() is at its statement budget.
    _add_model_probe_parser(sub)


def _model_probe(args: argparse.Namespace) -> int:
    """argparse handler for ``soc-ai model-probe``.

    Probes a candidate analyst backend with the REAL synthesizer contract —
    run this before pointing prod at a new model, once per candidate setting
    (``--output-mode``, ``--tool-choice``). ``--min-ok`` makes it CI-gateable:
    exit 1 when fewer than that many attempts produced a valid TriageReport.
    """
    import asyncio as _asyncio  # noqa: PLC0415

    from soc_ai.model_probe import format_probe_report, probe_model  # noqa: PLC0415

    settings = get_settings()
    overrides: dict[str, Any] = {}
    if args.model:
        overrides["analyst_model"] = args.model
    if args.tool_choice == "required":
        overrides["analyst_tool_choice_required"] = True
    if overrides:
        settings = settings.model_copy(update=overrides)

    rep = _asyncio.run(probe_model(settings, n=args.n, output_mode=args.output_mode))
    if args.json:
        print(json.dumps(rep, indent=2))
    else:
        print(format_probe_report(rep))
    if args.min_ok and rep["ok"] < args.min_ok:
        print(f"FAIL: {rep['ok']} usable < --min-ok {args.min_ok}", file=sys.stderr)
        return 1
    return 0


def _add_model_probe_parser(sub: Any) -> None:
    p_probe = sub.add_parser(
        "model-probe",
        help="Probe a candidate analyst model against the real triage contract",
        description=(
            "Run the synthesizer agent (same builders and prompt prod uses) N times "
            "against a canned scenario and tally the outcomes into failure classes. "
            "The first command to run when evaluating a new/lesser analyst backend."
        ),
    )
    p_probe.add_argument(
        "--model",
        default=None,
        help="LiteLLM route to probe (default: the configured analyst model)",
    )
    p_probe.add_argument("-n", type=int, default=6, help="Number of attempts (default 6)")
    p_probe.add_argument(
        "--output-mode",
        choices=["tool", "native", "prompted"],
        default="tool",
        help="Structured-output mode to probe (see synthesizer_output_mode)",
    )
    p_probe.add_argument(
        "--tool-choice",
        choices=["auto", "required"],
        default="auto",
        help="Probe with tool_choice forced (see analyst_tool_choice_required)",
    )
    p_probe.add_argument(
        "--min-ok",
        type=int,
        default=0,
        help="Exit 1 if fewer than this many attempts were usable (CI gate)",
    )
    p_probe.add_argument("--json", action="store_true", help="Emit the report as JSON")
    p_probe.set_defaults(func=_model_probe)


def _add_api_client_args(p: argparse.ArgumentParser) -> None:
    """Shared flags for subcommands that call the running soc-ai HTTP API."""
    p.add_argument(
        "--token",
        default=None,
        help="API bearer token (scai_...) for a secured deployment. "
        "api_auth_required=true is the shipped default. The CLI falls back to the "
        "SOC_AI_API_TOKEN environment variable. Omit both only if the server "
        "allows unauthenticated access.",
    )
    p.add_argument(
        "--verify",
        action="store_true",
        help="Verify the server's TLS certificate against the system CA store. "
        "The default is no verification. That matches the lab self-signed posture",
    )
    p.add_argument(
        "--cafile",
        default=None,
        metavar="PATH",
        help="CA bundle used to verify the server's TLS certificate "
        "(implies verification; takes precedence over --verify)",
    )


def main() -> None:  # noqa: PLR0915 - linear subparser registration, one statement per flag
    """CLI entry point bound by ``[project.scripts]``."""
    parser = argparse.ArgumentParser(prog="soc-ai", description=__doc__)
    sub = parser.add_subparsers(dest="cmd")

    p_serve = sub.add_parser("serve", help="Boot the FastAPI app (default)")
    p_serve.set_defaults(func=_serve)

    p_triage = sub.add_parser("triage", help="Stream an investigation for an alert id to stdout")
    p_triage.add_argument("alert_id", help="Elasticsearch _id of the alert under triage")
    p_triage.add_argument(
        "--url",
        default=None,
        help="Override base URL of the soc-ai instance (default: from SOC_AI_HOST/PORT)",
    )
    _add_api_client_args(p_triage)
    p_triage.set_defaults(func=_triage)

    p_health = sub.add_parser(
        "healthz",
        help="Print the soc-ai /healthz liveness JSON (probes nothing — see `doctor`)",
    )
    p_health.add_argument(
        "--url",
        default=None,
        help="Override base URL (default: from SOC_AI_HOST/PORT)",
    )
    _add_api_client_args(p_health)
    p_health.set_defaults(func=_healthz)

    _register_doctor(sub)
    _register_backup(sub)
    _register_audit(sub)

    p_val = sub.add_parser(
        "validate",
        help="Eval an alert: run pipeline → sanitize → ask the oracle (Opus 1M) for critique",
    )
    p_val.add_argument("alert_id", help="Elasticsearch _id of the alert to evaluate")
    p_val.add_argument(
        "--out-dir",
        default=None,
        help="Parent directory for the evals/<ts>-<alert_id>/ bundle (default: ./evals)",
    )
    p_val.set_defaults(func=_validate)

    p_vb = sub.add_parser(
        "validate-batch",
        help="Eval a batch of alerts via OQL; write evals/batch-<ts>/{bundles,index.jsonl}",
    )
    p_vb.add_argument(
        "--oql",
        required=True,
        help="OQL query selecting candidate alerts. The runner samples diverse "
        "alerts from the result stream.",
    )
    p_vb.add_argument(
        "--n", type=int, default=1000, help="Target number of diverse alerts (default: 1000)"
    )
    p_vb.add_argument(
        "--concurrency",
        type=int,
        default=5,
        help="Parallel runs after cache warmup (default: 5)",
    )
    p_vb.add_argument(
        "--diversity-keys",
        default="rule.name,host.name",
        help="Comma-separated dotted fields used to dedupe sampled alerts "
        "(default: rule.name,host.name)",
    )
    p_vb.add_argument(
        "--time-range-minutes",
        type=int,
        default=10_080,
        help="OQL @timestamp window in minutes (default: 10080 = 7 days)",
    )
    p_vb.add_argument(
        "--out-dir",
        default="evals",
        help="Parent directory for the batch-<ts>/ subdir (default: ./evals)",
    )
    p_vb.add_argument(
        "--resume",
        action="store_true",
        help="Reuse --out-dir as-is (don't mint a new batch-<ts>) and skip alert "
        "IDs already in index.jsonl",
    )
    p_vb.add_argument(
        "--per-run-timeout-s",
        type=int,
        default=1800,
        help="Per-alert harness wall-clock cap in seconds (default: 1800 = 30min)",
    )
    p_vb.add_argument(
        "--max-consecutive-failures",
        type=int,
        default=10,
        help="Abort the batch if this many runs fail in a row (default: 10)",
    )
    p_vb.add_argument(
        "--no-aggregate",
        action="store_true",
        help="Skip running eval-report after the batch finishes",
    )
    p_vb.add_argument(
        "--no-meta",
        action="store_true",
        help="Skip the oracle meta-analysis step of the auto eval-report",
    )
    p_vb.add_argument(
        "--synth-set",
        default=None,
        help=(
            "Inject synth-TP scenarios from soc_ai/eval/synth_scenarios/. "
            "Accepts: 'easy', 'medium', 'hard', 'all', or a comma-separated "
            "list of scenario ids (e.g. 'e1-emotet-feodo-c2,h1-kerberoasting'). "
            "Each injected scenario's triage-target alert is added to the "
            "batch alongside the OQL-sampled real alerts; aggregates.json "
            "carries a separate synth_stratum block with escalation P/R + "
            "Wilson 95%% CI."
        ),
    )
    p_vb.add_argument(
        "--repeats",
        type=_positive_int,
        default=1,
        help=(
            "Plant + run each --synth-set scenario this many times (default: 1). "
            "Each repeat is an isolated plant with its own scope key, so repeats "
            "never see each other's documents; the report then adds per-scenario "
            "pass-rate/stability and a batch flip-rate, so scenario-level variance "
            "is measured instead of masquerading as signal. Real-alert sampling "
            "(--n) is unaffected; without --synth-set this flag is a no-op."
        ),
    )
    p_vb.set_defaults(func=_validate_batch)

    _register_eval_nightly(sub)
    _register_spec_run(sub)
    _register_spec_sweep(sub)
    _register_priors(sub)
    _register_leads(sub)

    p_er = sub.add_parser(
        "eval-report",
        help="Aggregate a batch's index.jsonl into aggregates.json + report.md",
    )
    p_er.add_argument("batch_dir", help="Path to the batch directory written by validate-batch")
    p_er.add_argument(
        "--no-meta",
        action="store_true",
        help="Skip oracle meta-analysis (just (re)build aggregates.json + report.md)",
    )
    p_er.add_argument(
        "--rerun-meta",
        action="store_true",
        help="Force re-running meta-analysis even if meta_analysis.md exists",
    )
    p_er.set_defaults(func=_eval_report)

    _register_synth_clean(sub)

    # Blocklist + cloud-prefix refresh (`soc-ai blocklists refresh`).
    # The blocklist_refresh module owns the abuse.ch Auth-Key handling, atomic
    # writes, and --source filtering; its CLI handler delegates the cloud-prefix
    # half to soc_ai.enrichment.refresh.
    from soc_ai.enrichment.blocklist_refresh import (  # noqa: PLC0415
        register_subparser as _register_blocklists,
    )

    _register_blocklists(sub)

    p_disc = sub.add_parser(
        "discover-internal-identifiers",
        help="Learn internal domain suffixes + bare hostnames from ES and "
        "upsert them as detected internal_identifier rows",
    )
    p_disc.set_defaults(func=_discover_internal_identifiers)

    args = parser.parse_args()
    # Default to serve if no subcommand given (backward compat with v1).
    if not getattr(args, "func", None):
        args = parser.parse_args(["serve"])
    raise SystemExit(args.func(args))


if __name__ == "__main__":  # pragma: no cover - exercised via a subprocess test
    main()

"""Command-line front-end for soc-ai.

The ``soc-ai`` script in ``pyproject.toml`` dispatches to subcommands:

- ``serve`` (default): boots the FastAPI app under uvicorn (legacy behavior).
- ``triage <alert_id>``: streams an investigation against the local soc-ai
  instance, rendering each SSE event to stdout with colorized output. Useful
  for terminal-first analysts and incident-response work where opening a
  browser is overhead.
- ``healthz``: prints the health endpoint's JSON.
- ``doctor``: checks the whole dependency surface (config, local store +
  migration head, Security Onion, Elasticsearch, gateway, analyst-model
  fitness, egress posture, blocklist freshness) and prints a pass/fail
  table. Exit 0 only when every required check passes (warnings don't
  fail it); ``--json`` emits the results for automation.
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


def _triage(args: argparse.Namespace) -> int:
    base_url = _resolve_base_url(args.url)
    return asyncio.run(
        _stream_investigation(
            base_url,
            args.alert_id,
            token=_resolve_token(args),
            verify=_resolve_verify(args),
        )
    )


def _healthz(args: argparse.Namespace) -> int:
    base_url = _resolve_base_url(args.url)
    url = base_url.rstrip("/") + "/healthz"
    # verify defaults to False (lab self-signed); --verify/--cafile enable it.
    with httpx.Client(
        verify=_resolve_verify(args),
        timeout=10.0,
        headers=_auth_headers(_resolve_token(args)),
    ) as client:
        resp = client.get(url)
    try:
        print(json.dumps(resp.json(), indent=2))
    except ValueError:
        # A non-JSON body (a proxy 502 page, an auth redirect, a plain-text
        # error) must not crash healthz with a raw traceback — show the status
        # and a snippet so the operator can see what answered.
        print(f"HTTP {resp.status_code} (non-JSON body): {resp.text[:200]}")
    return 0 if resp.status_code == 200 else 1


def _doctor(args: argparse.Namespace) -> int:
    """Run the dependency-surface health checks and print a pass/fail table.

    Exit codes:
      0   every required check passed (WARN/INFO lines don't fail the doctor)
      1   at least one required check FAILed
    """
    from soc_ai.doctor import CheckResult, exit_code, run_doctor  # noqa: PLC0415 - lazy

    results = asyncio.run(run_doctor())
    rc = exit_code(results)

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
            synth_scenarios = tuple(picked)
        except Exception as e:
            print(
                f"{_C['red']}--synth-set load failed{_C['reset']}: {type(e).__name__}: {e}",
                file=sys.stderr,
            )
            return 5
        print(
            f"{_C['dim']}synth-set: {args.synth_set} → "
            f"{len(synth_scenarios)} scenarios "
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
) -> None:
    """Best-effort alarm side effects for a nightly quality regression.

    Two channels, both fail-soft: an audit event (kind ``quality_regression``,
    so the degradation is provable from the trail even after the snapshot
    table prunes) and the opt-in notification webhook (a hard no-op unless
    notifications are enabled + configured — the nightly must never grow an
    egress path the operator didn't turn on). The committed snapshot row is
    the durable record; neither channel failing can lose the alarm itself.
    """
    from soc_ai import notify  # noqa: PLC0415 - lazy
    from soc_ai.audit.logger import AuditLogger  # noqa: PLC0415 - lazy

    audit = None
    try:
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


def _eval_nightly(args: argparse.Namespace) -> int:  # noqa: PLR0915 - one place that wires the whole nightly
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

    Scheduling is the HOST's job (cron → ``docker exec``, see
    docs/DOCKER.md); soc-ai deliberately ships no in-app scheduler for this.

    Exit codes:
      0   ok — snapshot written (a fired alarm still exits 0: the run worked)
      2   sampler returned no eligible alerts (no snapshot)
      4   batch aborted by failure budget (snapshot IS still written — a
          fully-broken engine is exactly what the trend must record)
      5   unexpected internal error
    """
    from pathlib import Path  # noqa: PLC0415 - lazy

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

    # Clamp to the documented bounds even for env-sourced values: the config
    # console enforces [1,10] / [0.05,0.5], but a stray .env must not turn the
    # unattended nightly into an hour-long batch or a hair-trigger pager.
    n = max(1, min(10, settings.quality_nightly_n))
    alarm_drop = max(0.05, min(0.5, settings.quality_alarm_drop))
    oql = args.oql or settings.webui_alerts_query

    print(
        f"{_C['dim']}eval-nightly · mode={mode} n={n} oql={oql!r}{_C['reset']}",
        file=sys.stderr,
        flush=True,
    )

    def _emit(line: str) -> None:
        print(f"{_C['dim']}{line}{_C['reset']}", file=sys.stderr, flush=True)

    async def _go() -> int:
        import functools  # noqa: PLC0415 - lazy

        from soc_ai.eval.batch import BatchConfig, run_batch  # noqa: PLC0415 - lazy
        from soc_ai.eval.harness import run as harness_run  # noqa: PLC0415 - lazy
        from soc_ai.eval.quality import (  # noqa: PLC0415 - lazy
            TrendPoint,
            compute_snapshot_metrics,
            detect_regression,
        )
        from soc_ai.eval.report import build_report, load_index  # noqa: PLC0415 - lazy
        from soc_ai.so_client.elastic import ElasticClient  # noqa: PLC0415 - lazy
        from soc_ai.store import quality as quality_store  # noqa: PLC0415 - lazy
        from soc_ai.store.db import (  # noqa: PLC0415 - lazy
            make_engine,
            make_sessionmaker,
            run_migrations,
        )

        cfg = BatchConfig(
            oql=oql,
            n=n,
            # Concurrency 1: the nightly runs unattended on possibly-shared
            # inference infra — it must never contend with live triage.
            concurrency=1,
            out_dir=Path(args.out_dir),
            per_run_timeout_s=args.per_run_timeout_s,
        )

        elastic = ElasticClient(settings)
        try:
            try:
                summary = await run_batch(
                    cfg,
                    settings=settings,
                    elastic=elastic,
                    # grade=False keeps the per-alert oracle call OUT of local
                    # mode — the whole zero-egress contract hangs on this kwarg.
                    runner=functools.partial(harness_run, grade=(mode == "graded")),
                    progress=_emit,
                )
            except RuntimeError as e:
                print(f"{_C['red']}eval-nightly failed{_C['reset']}: {e}", file=sys.stderr)
                return 5
            except Exception as e:
                print(
                    f"{_C['red']}eval-nightly failed (transport){_C['reset']}: "
                    f"{type(e).__name__}: {e}",
                    file=sys.stderr,
                )
                return 5

            if summary.n_planned == 0:
                print(
                    f"{_C['yellow']}no eligible alerts for {oql!r} — "
                    f"no snapshot written{_C['reset']}",
                    file=sys.stderr,
                )
                return 2
            if summary.aborted_reason:
                # Still record the point below: a fully-broken engine (every
                # run failing) is precisely the regression the trend exists
                # to catch — swallowing it would blind the alarm.
                print(f"{_C['red']}{summary.aborted_reason}{_C['reset']}", file=sys.stderr)

            # Aggregate (pure; no oracle, no meta-analysis) + reduce to a point.
            _json_path, _md_path, agg = build_report(summary.batch_dir)
            rows = load_index(summary.batch_dir)
            metrics = compute_snapshot_metrics(rows, agg, mode=mode)

            # Trend: read same-mode history, detect, insert + prune in one txn.
            engine = make_engine(settings)
            try:
                # The CLI may run before the app ever booted against this
                # store (fresh install, cron-first) — same idiom as
                # discover-internal-identifiers.
                await run_migrations(engine)
                maker = make_sessionmaker(engine)
                async with maker() as db:
                    history = await quality_store.recent_snapshots(db, limit=7, mode=mode)
                    reasons = detect_regression(
                        metrics,
                        [
                            TrendPoint(
                                agreement_rate=h.agreement_rate,
                                fallback_rate=h.fallback_rate,
                            )
                            for h in history
                        ],
                        alarm_drop=alarm_drop,
                    )
                    await quality_store.insert_snapshot(
                        db,
                        mode=mode,
                        n_ok=metrics.n_ok,
                        n_error=metrics.n_error,
                        agreement_rate=metrics.agreement_rate,
                        fallback_rate=metrics.fallback_rate,
                        error_rate=metrics.error_rate,
                        verdict_counts=metrics.verdict_counts,
                        latency_p50_ms=metrics.latency_p50_ms,
                        batch_dir=str(summary.batch_dir),
                        alarmed=bool(reasons),
                        alarm_reasons=reasons or None,
                    )
            finally:
                with contextlib.suppress(Exception):
                    await engine.dispose()

            def _pct(v: float | None) -> str:
                return "—" if v is None else f"{v * 100:.0f}%"

            print(
                f"{_C['bold']}quality snapshot{_C['reset']} ({mode}) — "
                f"ok={metrics.n_ok} err={metrics.n_error} · "
                f"agreement={_pct(metrics.agreement_rate)} · "
                f"fallback={_pct(metrics.fallback_rate)} · "
                f"error={_pct(metrics.error_rate)} · "
                f"p50={metrics.latency_p50_ms or '—'}ms\n"
                f"{_C['dim']}batch: {summary.batch_dir}{_C['reset']}",
                file=sys.stderr,
            )

            if reasons:
                print(f"{_C['bold']}{_C['red']}QUALITY REGRESSION{_C['reset']}", file=sys.stderr)
                for r in reasons:
                    print(f"  {_C['yellow']}- {r}{_C['reset']}", file=sys.stderr)
                await _fire_quality_alarm(
                    settings, elastic=elastic, mode=mode, reasons=reasons, metrics=metrics
                )

            return 4 if summary.aborted_reason else 0
        finally:
            with contextlib.suppress(Exception):
                await elastic.aclose()

    rc = asyncio.run(_go())
    if rc == 0:
        # The nightly only trends if something schedules it — hand the operator
        # the exact host-cron line (docs/DOCKER.md carries the same one).
        print(
            f"\n{_C['dim']}schedule it (host cron — see docs/DOCKER.md):{_C['reset']}\n"
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
            f"{_C['yellow']}eval-report failed (batch is intact, run "
            f"`soc-ai eval-report {target}` manually): "
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
            f"{_C['dim']}meta-analysis already exists at {meta_md}; "
            f"pass --rerun-meta to regenerate{_C['reset']}",
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
            f"{_C['yellow']}meta-analysis failed (aggregates intact): "
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
            f"{_C['dim']}internal-identifier discovery is disabled "
            f"(set DISCOVERY_ENABLED=true to enable){_C['reset']}"
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
            f"{_C['dim']}always muted — un-mute to apply{_C['reset']})"
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
    ascending by ``seq``, and runs the tamper-evident hash chain over them
    (:func:`soc_ai.audit.verify.verify_audit_chain`). This is the operator's way
    to actually exercise the tamper-evidence: an intact chain proves no audit
    record was edited, reordered, inserted, or deleted since it was written.

    Exit codes:
      0   chain intact (including an empty index — nothing to tamper with)
      1   TAMPER DETECTED — the chain broke at some seq
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
            f"{_C['yellow']}warning: scan hit the record cap — only a prefix of the "
            f"chain was verified; bound the scan with --days to check a smaller "
            f"window{_C['reset']}",
            file=sys.stderr,
        )

    if not result.ok:
        broken = result.first_broken_seq
        print(
            f"{_C['red']}{_C['bold']}TAMPER DETECTED{_C['reset']}{_C['red']} — "
            f"chain broke at seq {broken}{_C['reset']}{scope}",
            file=sys.stderr,
        )
        print(
            f"{_C['dim']}{result.records_verified} record(s) scanned before the break. "
            f"A record was edited, reordered, inserted, or deleted.{_C['reset']}",
            file=sys.stderr,
        )
        return 1

    if result.records_verified == 0:
        print(f"{_C['green']}audit chain intact{_C['reset']} — 0 records{scope}")
        return 0

    span = f"seq {result.first_seq}..{result.last_seq}"
    print(
        f"{_C['green']}audit chain intact{_C['reset']} — "
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
        help="Bound the scan to audit records from the last N days (by timestamp). "
        "Default: the whole index. NOTE: a windowed scan verifies contiguity "
        "WITHIN the window but cannot verify linkage across the window boundary "
        "(the record before the window isn't fetched).",
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
            f"{_C['red']}--full needs the cache directories from settings{_C['reset']}, "
            "which did not load. Run from a directory with a populated .env (or drop "
            "--full — the caches are re-downloadable via `soc-ai blocklists refresh`).",
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
    head = m.alembic_head or "(fresh — no migrations applied)"
    print(
        f"backed up {data_dir / 'soc-ai.db'} "
        f"({result.db_bytes / 1_048_576:.1f} MiB, migration head {head})"
    )
    print(f"  sidecars: {', '.join(m.sidecars) or '(none)'}")
    if m.full:
        print(f"  caches:   {', '.join(m.caches) or '(none found)'}")
    else:
        print(
            f"  caches:   excluded {_C['dim']}(re-downloadable — `soc-ai blocklists "
            f"refresh` re-seeds them; --full includes them){_C['reset']}"
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
    head = result.archive_head or "(fresh — no migrations applied)"
    print(f"restored store → {result.db_path} (migration head {head})")
    if result.archive_head and result.code_head and result.archive_head != result.code_head:
        print(
            f"  archive head {result.archive_head} is older than code head "
            f"{result.code_head} — the app migrates it to head at next startup"
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
        help="Also include the enrichment caches (blocklists, MaxMind, cloud "
        "prefixes). Excluded by default: they are re-downloadable via "
        "`soc-ai blocklists refresh` and dwarf the DB",
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
        help="Restore a `soc-ai backup` archive into the data directory. Refuses "
        "to overwrite an existing store (or restore under a live-looking app) "
        "without --yes; refuses archives from a newer soc-ai (downgrade). "
        "Stop the app first",
    )
    p_res.add_argument("archive", help="Path to the soc-ai-backup-*.tar.gz to restore")
    p_res.add_argument(
        "--yes",
        action="store_true",
        help="Overwrite existing state, and proceed even when the store looks "
        "live (recent WAL activity) — the restore prints what it overwrites",
    )
    p_res.add_argument(
        "--data-dir",
        default=None,
        metavar="PATH",
        help="Override the data directory (default: SOC_AI_DATA_DIR from env/.env)",
    )
    p_res.set_defaults(func=_restore)


def _register_synth_clean(sub: Any) -> None:
    """Register the ``synth-clean`` subparser (split out of :func:`main` for size)."""
    p_sc = sub.add_parser(
        "synth-clean",
        help="Delete synthetic-eval docs (synth.scenario_id) from logs-synth-* "
        "so fixtures don't accumulate forever",
    )
    p_sc.add_argument(
        "--older-than-days",
        type=int,
        default=None,
        help="Only delete synth docs older than N days (default: delete all)",
    )
    p_sc.set_defaults(func=_synth_clean)


def _register_eval_nightly(sub: Any) -> None:
    """Register the ``eval-nightly`` subparser (split out of :func:`main` for size)."""
    p_en = sub.add_parser(
        "eval-nightly",
        help="Nightly quality micro-eval: investigate a few real alerts, land one "
        "row in the local quality trend, and alarm on regression. Schedule it "
        "from host cron (see docs/DOCKER.md); the mode defaults to oracle-graded "
        "iff oracle_enabled, else zero-egress local",
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
        default="evals",
        help="Parent directory for the batch-<ts>/ artifact subdir (default: ./evals)",
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
        help="Check the whole dependency surface (config, store, SO/ES, gateway, "
        "model fitness) and print a pass/fail table; exit 0 iff all required "
        "checks pass",
    )
    p_doc.add_argument(
        "--json",
        action="store_true",
        help="Emit the check results as JSON instead of the table (for automation)",
    )
    p_doc.set_defaults(func=_doctor)


def _add_api_client_args(p: argparse.ArgumentParser) -> None:
    """Shared flags for subcommands that call the running soc-ai HTTP API."""
    p.add_argument(
        "--token",
        default=None,
        help="API bearer token (scai_...) for a secured deployment "
        "(api_auth_required=true, the shipped default). Falls back to the "
        "SOC_AI_API_TOKEN environment variable; omit both only if the "
        "server allows unauthenticated access.",
    )
    p.add_argument(
        "--verify",
        action="store_true",
        help="Verify the server's TLS certificate against the system CA store "
        "(default: no verification, matching the lab self-signed posture)",
    )
    p.add_argument(
        "--cafile",
        default=None,
        metavar="PATH",
        help="CA bundle used to verify the server's TLS certificate "
        "(implies verification; takes precedence over --verify)",
    )


def main() -> None:
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

    p_health = sub.add_parser("healthz", help="Print the soc-ai /healthz JSON")
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
    p_vb.set_defaults(func=_validate_batch)

    _register_eval_nightly(sub)

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

"""Command-line front-end for soc-ai.

The ``soc-ai`` script in ``pyproject.toml`` dispatches to subcommands:

- ``serve`` (default): boots the FastAPI app under uvicorn (legacy behavior).
- ``triage <alert_id>``: streams an investigation against the local soc-ai
  instance, rendering each SSE event to stdout with colorized output. Useful
  for terminal-first analysts and incident-response work where opening a
  browser is overhead.
- ``healthz``: prints the health endpoint's JSON.

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
    "approval_required": _C["yellow"],
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
    if kind == "approval_required":
        return (
            f"{_label(kind)} {payload.get('tool_name')} "
            f"token={payload.get('token')!r}\n   "
            f"{_C['yellow']}→ {_short(payload.get('rationale', ''), 200)}{_C['reset']}"
        )
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

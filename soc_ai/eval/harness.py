"""End-to-end eval harness.

Run an investigation in-process, capture every SSE event, sanitize
the trail, ship it to the cloud oracle via the LiteLLM gateway (which
forwards to the cloud model), save a bundle. The CLI's ``validate``
subcommand is the only intended caller.
"""

from __future__ import annotations

import contextlib
import json
import logging
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from soc_ai.agent.orchestrator import (
    InvestigationContext,
    StepEvent,
    build_local_enrichment_context,
    investigate,
)
from soc_ai.config import Settings, get_settings
from soc_ai.eval import sanitize as san
from soc_ai.eval.oracle_client import OracleError, OracleResponse, call_oracle
from soc_ai.eval.prompt import SYSTEM_PROMPT, architecture_block, build_user_message
from soc_ai.so_client.auth import make_auth
from soc_ai.so_client.elastic import ElasticClient
from soc_ai.tools.enrichment import MispClient

_LOGGER = logging.getLogger(__name__)


@dataclass
class EvalResult:
    """Returned to the CLI after a successful run.

    On failure, the harness raises (the CLI maps to exit codes); on
    success this carries everything needed to print + reference.
    """

    bundle_dir: Path
    response_md: str
    sanitized_events: list[dict[str, Any]]
    sanitized_report: dict[str, Any] | None
    mapping: san.Mapping
    oracle_response: OracleResponse
    investigation_elapsed_ms: int


# Type alias for an oracle-call function so tests can substitute a
# stub without monkey-patching the module. Keep the kwarg shape in
# sync with `oracle_client.call_oracle`.
OracleCaller = Callable[..., OracleResponse]


async def run(
    alert_id: str,
    *,
    settings: Settings | None = None,
    out_dir: Path | None = None,
    oracle_caller: OracleCaller = call_oracle,
    include_synth: bool = False,
    expected_verdict: str | None = None,
) -> EvalResult:
    """Run the eval pipeline end-to-end.

    Args:
        alert_id: ES `_id` of the alert to evaluate.
        settings: optional pre-built Settings (tests override).
        out_dir: parent dir for the bundle (default: ``./evals``).
        oracle_caller: pluggable LiteLLM-call function so tests can
            stub without hitting the network.
        include_synth: if True, the prefetch includes synth docs; set
            for synthetic-scenario evaluation runs.
        expected_verdict: for synthetic scenarios only — the planted,
            known-correct verdict from ``Scenario.ground_truth.verdict``.
            When set, the oracle prompt gains a ground-truth block so
            grading is factual rather than subjective.
    """
    settings = settings or get_settings()
    out_dir = out_dir or Path("evals")

    if not settings.litellm_api_key:
        raise RuntimeError(
            "LITELLM_API_KEY not set; LiteLLM gateway will reject the "
            "oracle call. Add it to /opt/soc-ai/.env."
        )

    _LOGGER.info(
        "eval harness starting alert=%s model=%s litellm=%s",
        alert_id,
        settings.claude_oracle_model,
        settings.litellm_base_url,
    )

    # ----- Run the investigation in-process -----
    # `include_synth` lets the prefetch see this synth alert's own supporting
    # docs; real alerts leave it False so synth fixtures stay invisible.
    ctx = _build_context(settings, include_synth=include_synth)

    started = time.monotonic()
    events: list[StepEvent] = []
    final_report: dict[str, Any] | None = None
    try:
        async for ev in investigate(alert_id, ctx=ctx):
            events.append(ev)
            if ev.kind == "triage_report":
                final_report = ev.payload
    finally:
        # ElasticClient holds aiohttp connections; release them. Errors
        # during teardown shouldn't mask whatever the run produced.
        with contextlib.suppress(Exception):
            await ctx.elastic.aclose()
        with contextlib.suppress(Exception):
            await ctx.auth.aclose()
    investigation_elapsed_ms = int((time.monotonic() - started) * 1000)

    # ----- Sanitize -----
    mapping = san.Mapping()
    sanitized_events = [
        _sanitize_event_payload(ev.kind, ev.sequence, ev.payload, mapping) for ev in events
    ]
    sanitized_report = _sanitize_dict(final_report, mapping) if final_report else None

    # Build a single string of everything we'll send for the residue check.
    # Cheaper than walking the dicts again — `unsafe_residue` uses the
    # same regexes as `sanitize` so this catches drift either way.
    bundle_text = json.dumps(sanitized_events, default=str)
    if sanitized_report is not None:
        bundle_text += "\n" + json.dumps(sanitized_report, default=str)
    issues = san.unsafe_residue(bundle_text)
    if issues:
        # Save a debug bundle even on refusal so the operator can see
        # what slipped through and extend the redactor.
        debug_dir = _new_bundle_dir(out_dir, alert_id) / "refused"
        debug_dir.mkdir(parents=True, exist_ok=True)
        (debug_dir / "events.jsonl").write_text(
            "\n".join(json.dumps(e, default=str) for e in sanitized_events),
            encoding="utf-8",
        )
        (debug_dir / "issues.txt").write_text("\n".join(issues), encoding="utf-8")
        raise RuntimeError(
            f"sanitization residue check refused to send "
            f"({len(issues)} issues). See {debug_dir} for the offending tokens."
        )

    # ----- Build the user message + ask the oracle (via LiteLLM) -----
    alert_id_label = mapping.forward.get(alert_id, alert_id)
    user_message = build_user_message(
        alert_id_label=alert_id_label,
        sanitized_events=sanitized_events,
        sanitized_report=sanitized_report,
        expected_verdict=expected_verdict,
    )
    arch = architecture_block()

    try:
        response = oracle_caller(
            base_url=str(settings.litellm_base_url),
            api_key=settings.litellm_api_key.get_secret_value()
            if hasattr(settings.litellm_api_key, "get_secret_value")
            else settings.litellm_api_key,
            verify_ssl=settings.litellm_verify_ssl,
            model=settings.claude_oracle_model,
            max_tokens=settings.claude_oracle_max_tokens,
            system_prompt=SYSTEM_PROMPT,
            arch_context=arch,
            user_message=user_message,
        )
    except OracleError as e:
        raise RuntimeError(f"LiteLLM/oracle call failed: {e}") from e

    # ----- De-sanitize the response for local display -----
    response_md = san.desanitize(response.text, mapping)

    # ----- Save the artifact bundle -----
    bundle_dir = _new_bundle_dir(out_dir, alert_id)
    _save_bundle(
        bundle_dir,
        alert_id=alert_id,
        events=sanitized_events,
        report=sanitized_report,
        mapping=mapping,
        user_message=user_message,
        arch_context=arch,
        system_prompt=SYSTEM_PROMPT,
        response=response,
        response_md=response_md,
        investigation_elapsed_ms=investigation_elapsed_ms,
    )

    return EvalResult(
        bundle_dir=bundle_dir,
        response_md=response_md,
        sanitized_events=sanitized_events,
        sanitized_report=sanitized_report,
        mapping=mapping,
        oracle_response=response,
        investigation_elapsed_ms=investigation_elapsed_ms,
    )


# --------------------------------------------------------------------
# Internals
# --------------------------------------------------------------------


def _build_context(settings: Settings, *, include_synth: bool = False) -> InvestigationContext:
    """Build an InvestigationContext from settings, no audit logger.

    The eval harness deliberately skips the audit logger — every event
    is captured locally and saved to the bundle, so duplicating into
    the audit ES index would double-cost the storage for no value.
    """
    auth = make_auth(settings)
    elastic = ElasticClient(settings)
    misp = MispClient(settings) if settings.misp_url else None
    enrichment = build_local_enrichment_context(settings)
    return InvestigationContext(
        settings=settings,
        auth=auth,
        elastic=elastic,
        misp=misp,
        audit=None,
        blocklist=enrichment.blocklist,
        maxmind=enrichment.maxmind,
        cloud=enrichment.cloud,
        include_synth=include_synth,
    )


def _sanitize_event_payload(
    kind: str,
    sequence: int,
    payload: dict[str, Any],
    mapping: san.Mapping,
) -> dict[str, Any]:
    """Return a sanitized copy of one SSE event payload."""
    return {
        "kind": kind,
        "sequence": sequence,
        "payload": _sanitize_dict(payload, mapping),
    }


def _sanitize_dict(value: Any, mapping: san.Mapping) -> Any:
    """Walk a dict/list/scalar tree, sanitize every string in place.

    Non-string scalars (int, bool, None) pass through unchanged.

    Both keys and values are sanitized when they are strings — the
    synth-first redesign's `enrichments: dict[str, IndicatorEnrichment]`
    keys IPs/domains by raw indicator string, which would otherwise
    leak through.
    """
    if isinstance(value, str):
        sanitized, _ = san.sanitize(value, mapping=mapping)
        return sanitized
    if isinstance(value, dict):
        return {
            (san.sanitize(k, mapping=mapping)[0] if isinstance(k, str) else k): _sanitize_dict(
                v, mapping
            )
            for k, v in value.items()
        }
    if isinstance(value, list):
        return [_sanitize_dict(v, mapping) for v in value]
    return value


def _new_bundle_dir(parent: Path, alert_id: str) -> Path:
    """Build a fresh `evals/<ts>-<alert_id>` directory."""
    ts = datetime.now(UTC).strftime("%Y-%m-%dT%H%M%SZ")
    safe_alert = "".join(c if c.isalnum() or c in "-_" else "_" for c in alert_id)
    out = parent / f"{ts}-{safe_alert}"
    out.mkdir(parents=True, exist_ok=True)
    return out


def _save_bundle(
    bundle_dir: Path,
    *,
    alert_id: str,
    events: list[dict[str, Any]],
    report: dict[str, Any] | None,
    mapping: san.Mapping,
    user_message: str,
    arch_context: str,
    system_prompt: str,
    response: OracleResponse,
    response_md: str,
    investigation_elapsed_ms: int,
) -> None:
    """Persist the full artifact bundle.

    Layout:
        bundle_dir/
            response.md       the oracle's de-sanitized critique
            request.json      what was sent (sanitized)
            events.jsonl      one event per line (sanitized)
            mapping.json      {label: original}
            meta.json         alert_id, ts, model, tokens, status, elapsed
    """
    (bundle_dir / "response.md").write_text(response_md, encoding="utf-8")
    (bundle_dir / "events.jsonl").write_text(
        "\n".join(json.dumps(e, default=str) for e in events) + "\n",
        encoding="utf-8",
    )
    (bundle_dir / "request.json").write_text(
        json.dumps(
            {
                "system_prompt": system_prompt,
                "arch_context": arch_context,
                "user_message": user_message,
            },
            indent=2,
            default=str,
        ),
        encoding="utf-8",
    )
    (bundle_dir / "mapping.json").write_text(
        json.dumps(
            {
                "forward": mapping.forward,
                "reverse": mapping.reverse,
                "summary": mapping.summary(),
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    (bundle_dir / "meta.json").write_text(
        json.dumps(
            {
                "alert_id": alert_id,
                "alert_id_label": mapping.forward.get(alert_id, alert_id),
                "timestamp_utc": datetime.now(UTC).isoformat(),
                "model": response.model,
                "usage": response.usage,
                "investigation_elapsed_ms": investigation_elapsed_ms,
                "claude_elapsed_ms": response.elapsed_ms,
                "verdict": (report or {}).get("verdict"),
                "confidence": (report or {}).get("confidence"),
                "redaction_summary": mapping.summary(),
                "events_count": len(events),
            },
            indent=2,
            default=str,
        ),
        encoding="utf-8",
    )

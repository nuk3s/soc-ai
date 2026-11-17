"""End-to-end eval harness.

Run an investigation in-process, capture every SSE event, sanitize
the trail, ship it to the cloud oracle via the LiteLLM gateway (which
forwards to the cloud model), save a bundle. The CLI's ``validate``
subcommand is the only intended caller.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any
from urllib.parse import urlsplit

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
from soc_ai.store.db import is_postgres_url, make_engine, make_sessionmaker, store_url
from soc_ai.tools.enrichment import MispClient

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

_LOGGER = logging.getLogger(__name__)


# Why a grade request failed. The three want different responses from an
# operator: a used-up quota clears by itself, a gateway fault is an outage, and
# a sanitizer refusal is a gap in the redactor.
GRADER_QUOTA = "quota"
GRADER_GATEWAY = "gateway"
GRADER_REFUSAL = "refusal"

# The gateway status for a rate limit. The provider names its quota in the body
# of the same answer ("Claude Max rate limit reached").
_HTTP_TOO_MANY_REQUESTS = 429


class GraderError(RuntimeError):
    """The GRADING half of a run failed. The investigation itself completed.

    A ``RuntimeError`` on purpose: ``soc-ai validate`` and ``validate-batch``
    asked for a grade and map a ``RuntimeError`` to their failure exit, and
    that must not change. The subclass is what lets the nightly tell a lost
    grade from a failed investigation. On production the two were one error
    string, so three nights that lost every grade to the Oracle quota were
    recorded as ``error_rate 1.00``: a triage failure that never happened.
    """

    def __init__(self, message: str, *, kind: str) -> None:
        super().__init__(message)
        self.kind = kind


def _grader_kind(error: BaseException) -> str:
    """Quota or gateway, read from the status first and the text second.

    The text check exists for an ``oracle_caller`` that raises a plain
    ``OracleError`` with no status, which every older double does.
    """
    text = str(error).lower()
    if getattr(error, "status_code", None) == _HTTP_TOO_MANY_REQUESTS or any(
        marker in text for marker in ("rate limit", "rate_limit", "ratelimit")
    ):
        return GRADER_QUOTA
    return GRADER_GATEWAY


def _backend_of(api_base: Any) -> str | None:
    """``host:port`` of a gateway ``api_base``, or None.

    Only the host and the port. A backend address can carry credentials in its
    userinfo, and those have no business in a quality record.
    """
    if not isinstance(api_base, str) or not api_base.strip():
        return None
    raw = api_base.strip()
    try:
        parts = urlsplit(raw if "://" in raw else f"//{raw}")
        host, port = parts.hostname, parts.port
    except ValueError:
        return None
    if not host:
        return None
    return f"{host}:{port}" if port else host


def _names(value: Any) -> list[str]:
    """The non-empty strings in ``value``: one string, or a list of them."""
    values = value if isinstance(value, list) else [value]
    return [v.strip() for v in values if isinstance(v, str) and v.strip()]


def _served_models_of(payload: dict[str, Any]) -> list[str]:
    """The models one event names as served. Empty when it names none.

    A ``served_model`` field on the event wins, read by name and by shape: a
    string, or a mapping that holds the names. The mapping form is the per-run
    record (``{"configured": ..., "model_groups": [...], "fallback": ...}``);
    its ``configured`` key is NOT read, because a configured name is not a
    served one. Otherwise the route the gateway attributed the call to
    (``served_backend.model_group``), which is what every run records today.
    """
    own = payload.get("served_model")
    if isinstance(own, dict):
        for key in ("model_groups", "model_group", "model", "name"):
            if names := _names(own.get(key)):
                return names
    elif names := _names(own):
        return names
    backend = payload.get("served_backend")
    if isinstance(backend, dict):
        return _names(backend.get("model_group"))
    return []


def served_models_from_events(payloads: Iterable[Any]) -> list[dict[str, str]]:
    """The distinct (model, backend) pairs that served one run, in first-seen order.

    Empty when the run recorded nothing. This function never falls back to the
    configured model: the caller marks that case, because a configured name
    presented as a served name is the defect this record exists to end. On
    production the route ``deepseek-v4-flash`` moved from one engine to another
    on 2026-11-02 and a fallback route served 54 runs, and every snapshot of
    those days carried the one configured name.

    Each entry is ``{"model": ...}`` with a ``"backend"`` key when the gateway
    named the engine address. The route name alone could not show the move
    above: the name stayed and the address changed. A model that one event
    names with its address and another event names without it is listed once,
    with the address.
    """
    seen: list[dict[str, str]] = []
    for payload in payloads:
        if not isinstance(payload, dict):
            continue
        backend = payload.get("served_backend")
        address = _backend_of(backend.get("api_base")) if isinstance(backend, dict) else None
        for model in _served_models_of(payload):
            entry = {"model": model}
            if address is not None:
                entry["backend"] = address
            if entry not in seen:
                seen.append(entry)
    with_address = {entry["model"] for entry in seen if "backend" in entry}
    return [entry for entry in seen if "backend" in entry or entry["model"] not in with_address]


def run_error_from_events(events: Iterable[Any]) -> tuple[str | None, str | None]:
    """``(type, text)`` of the last ``error`` event of a run, or ``(None, None)``.

    Takes ``(kind, payload)`` pairs. The orchestrator writes the exception class
    under ``type`` and its text under ``message``. This is what the run itself
    recorded about its end, and the nightly reads it to state why a run that
    left no report died: a gateway fault, a token limit or a time limit.
    """
    found: tuple[str | None, str | None] = (None, None)
    for kind, payload in events:
        if kind != "error" or not isinstance(payload, dict):
            continue
        error_type = payload.get("type")
        message = payload.get("message")
        found = (
            str(error_type) if isinstance(error_type, str) and error_type else None,
            str(message)[:300] if isinstance(message, str) and message else None,
        )
    return found


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
    # Set only under ``tolerate_grader_failure``: the investigation completed
    # and the grade request failed. ``grader_error_kind`` is one of the
    # GRADER_* constants. Both stay None on a graded or an ungraded run.
    grader_error: str | None = None
    grader_error_kind: str | None = None
    # Which model served this run, from the RAW events. See
    # :func:`served_models_from_events`.
    served: list[dict[str, str]] = field(default_factory=list)
    # The run's own failure, from its last ``error`` event: the exception class
    # and its message. None on a run that raised no error. A run can record an
    # error and still end with a report, so this says why a run died only when
    # the run has no verdict. See :func:`run_error_from_events`.
    run_error_type: str | None = None
    run_error: str | None = None


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
    include_synth: bool | str = False,
    expected_verdict: str | None = None,
    grade: bool = True,
    tolerate_grader_failure: bool = False,
) -> EvalResult:
    """Run the eval pipeline end-to-end.

    Args:
        alert_id: ES `_id` of the alert to evaluate.
        settings: optional pre-built Settings (tests override).
        out_dir: parent dir for the bundle (default: ``./evals``).
        oracle_caller: pluggable LiteLLM-call function so tests can
            stub without hitting the network.
        include_synth: synth-doc visibility for the run's tools. The batch
            runner passes the SCENARIO ID under triage so the investigation
            sees that scenario's own planted docs and nothing planted by its
            sibling scenarios; False (real alerts) keeps every synth doc
            invisible. True (all synth visible) is reserved for the
            hunt-journey runner.
        expected_verdict: for synthetic scenarios only — the planted,
            known-correct verdict from ``Scenario.ground_truth.verdict``.
            When set, the oracle prompt gains a ground-truth block so
            grading is factual rather than subjective.
        grade: when False (the ``soc-ai eval-nightly`` local mode), the
            investigation runs and the bundle is saved but the ORACLE IS
            NEVER CALLED — zero cloud egress. ``response.md`` is empty,
            ``oracle_response`` is a zero-usage stub, and the residue
            refusal gate is skipped (it exists to protect an egress that
            isn't happening). The local trend signals (verdict, fallback,
            latency) are all still real.
        tolerate_grader_failure: when True (the nightly), a failed grade
            request does not raise. The bundle is saved with an empty
            critique and the result carries ``grader_error`` and
            ``grader_error_kind``, so the caller keeps the verdict, the
            latency and the served model of an investigation that completed.
            False (the default) keeps the raise: ``validate`` and
            ``validate-batch`` asked for the grade.
    """
    settings = settings or get_settings()
    out_dir = out_dir or Path("evals")

    # The key gates the ANALYST model calls too (the whole pipeline runs
    # through the LiteLLM gateway), so ungraded runs still require it.
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
    engine, db_sessionmaker = _store_sessionmaker(settings)
    ctx = _build_context(settings, include_synth=include_synth, db_sessionmaker=db_sessionmaker)

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
        if engine is not None:
            with contextlib.suppress(Exception):
                await engine.dispose()
    investigation_elapsed_ms = int((time.monotonic() - started) * 1000)
    # Read from the RAW events, before the sanitizer runs: it rewrites host
    # names, and this record never leaves the install.
    served, (run_error_type, run_error) = (
        served_models_from_events(ev.payload for ev in events),
        run_error_from_events((ev.kind, ev.payload) for ev in events),
    )

    # ----- Sanitize -----
    # Thread the operator's ORACLE_EXTRA_HOSTS / ORACLE_INTERNAL_SUFFIXES into
    # every sanitize() call so bare internal hostnames the operator configured
    # (shape-indistinguishable from public infra) are redacted before egress —
    # matching the production Oracle client. The same tuples feed the residue
    # gate in _grade_with_oracle so the detector can verify the replacer.
    resolved_hosts = tuple(settings.oracle_extra_hosts)
    resolved_suffixes = tuple(settings.oracle_internal_suffixes)
    mapping = san.Mapping()
    sanitized_events = [
        _sanitize_event_payload(
            ev.kind,
            ev.sequence,
            ev.payload,
            mapping,
            extra_hosts=resolved_hosts,
            extra_suffixes=resolved_suffixes,
        )
        for ev in events
    ]
    sanitized_report = (
        _sanitize_dict(
            final_report,
            mapping,
            extra_hosts=resolved_hosts,
            extra_suffixes=resolved_suffixes,
        )
        if final_report
        else None
    )

    grader_error: GraderError | None = None
    if grade:
        try:
            response, response_md, user_message, arch = await _grade_with_oracle(
                alert_id=alert_id,
                settings=settings,
                out_dir=out_dir,
                oracle_caller=oracle_caller,
                expected_verdict=expected_verdict,
                sanitized_events=sanitized_events,
                sanitized_report=sanitized_report,
                mapping=mapping,
            )
        except GraderError as e:
            if not tolerate_grader_failure:
                raise
            # The investigation is complete and is worth keeping: its verdict,
            # its latency and its served model are all real. Only the critique
            # is missing, so the bundle takes the ungraded shape below.
            grader_error = e
            user_message = ""
            arch = ""
            response = OracleResponse(text="", model="(not graded)", usage={}, elapsed_ms=0)
            response_md = ""
    else:
        # Ungraded (local) mode: NO oracle, NO egress of any kind. The bundle
        # keeps its normal shape (an empty response.md, a zero-usage stub
        # OracleResponse) so downstream readers — the batch runner reads
        # response.md unconditionally — never need a special case. The
        # residue gate is skipped on purpose: it guards an egress that this
        # mode never performs, and refusing a purely-local run over a
        # sanitizer gap would fail nightlies for no protective benefit.
        user_message = ""
        arch = ""
        response = OracleResponse(text="", model="(ungraded)", usage={}, elapsed_ms=0)
        response_md = ""

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
        grader_error=str(grader_error) if grader_error is not None else None,
        grader_error_kind=grader_error.kind if grader_error is not None else None,
    )

    return EvalResult(
        bundle_dir=bundle_dir,
        response_md=response_md,
        sanitized_events=sanitized_events,
        sanitized_report=sanitized_report,
        mapping=mapping,
        oracle_response=response,
        investigation_elapsed_ms=investigation_elapsed_ms,
        grader_error=str(grader_error) if grader_error is not None else None,
        grader_error_kind=grader_error.kind if grader_error is not None else None,
        served=served,
        run_error_type=run_error_type,
        run_error=run_error,
    )


# --------------------------------------------------------------------
# Internals
# --------------------------------------------------------------------


async def _grade_with_oracle(
    *,
    alert_id: str,
    settings: Settings,
    out_dir: Path,
    oracle_caller: OracleCaller,
    expected_verdict: str | None,
    sanitized_events: list[dict[str, Any]],
    sanitized_report: dict[str, Any] | None,
    mapping: san.Mapping,
) -> tuple[OracleResponse, str, str, str]:
    """The graded half of :func:`run`: residue-gate, prompt, oracle, de-sanitize.

    This is the ONLY egress in the harness, so the whole chain lives together:
    the residue check that must pass before anything leaves, the prompt build,
    the LiteLLM/oracle call, and the de-sanitization of the critique for local
    display. Returns ``(response, response_md, user_message, arch_context)``.

    ``async`` because ``oracle_caller`` is a blocking ``httpx.Client`` POST with
    a timeout up to 300s: run inline it would freeze the single-worker event loop
    for the whole critique (the notifications poll, /health, SSE streams and every
    scheduler wake stall). It is offloaded with :func:`asyncio.to_thread`, the
    same precedent :mod:`soc_ai.eval.meta_analysis` uses for the identical call.
    """
    # Sanitize the alert id itself. A bare ``mapping.forward.get(alert_id, ...)``
    # only redacts the id when that exact string coincidentally appeared (and
    # matched a pattern) elsewhere in the payload; run it through sanitize() so
    # an internal identifier embedded in the ES ``_id`` (some deployments do
    # this) is redacted regardless. Fold the resulting label into ``bundle_text``
    # so the pre-send residue gate actually covers the id.
    alert_id_label, _ = san.sanitize(
        alert_id,
        mapping=mapping,
        extra_hosts=tuple(settings.oracle_extra_hosts),
        extra_suffixes=tuple(settings.oracle_internal_suffixes),
    )

    # Build a single string of everything we'll send for the residue check.
    # Cheaper than walking the dicts again — `unsafe_residue` uses the
    # same regexes as `sanitize` so this catches drift either way.
    bundle_text = json.dumps(sanitized_events, default=str)
    if sanitized_report is not None:
        bundle_text += "\n" + json.dumps(sanitized_report, default=str)
    bundle_text += "\n" + alert_id_label
    issues = san.unsafe_residue(
        bundle_text,
        extra_hosts=tuple(settings.oracle_extra_hosts),
        extra_suffixes=tuple(settings.oracle_internal_suffixes),
    )
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
        raise GraderError(
            f"sanitization residue check refused to send "
            f"({len(issues)} issues). See {debug_dir} for the offending tokens.",
            kind=GRADER_REFUSAL,
        )

    # ----- Build the user message + ask the oracle (via LiteLLM) -----
    user_message = build_user_message(
        alert_id_label=alert_id_label,
        sanitized_events=sanitized_events,
        sanitized_report=sanitized_report,
        expected_verdict=expected_verdict,
    )
    arch = architecture_block()

    # run() already refused a missing key before doing any work; this re-check
    # exists for the type narrowing (SecretStr | None) now that the oracle call
    # lives in its own function.
    api_key = settings.litellm_api_key
    if api_key is None:  # pragma: no cover - unreachable via run()
        raise RuntimeError("LITELLM_API_KEY not set")

    try:
        response = await asyncio.to_thread(
            oracle_caller,
            base_url=str(settings.litellm_base_url),
            api_key=api_key.get_secret_value() if hasattr(api_key, "get_secret_value") else api_key,
            verify_ssl=settings.litellm_verify_ssl,
            model=settings.claude_oracle_model,
            max_tokens=settings.claude_oracle_max_tokens,
            system_prompt=SYSTEM_PROMPT,
            arch_context=arch,
            user_message=user_message,
        )
    except OracleError as e:
        raise GraderError(f"LiteLLM/oracle call failed: {e}", kind=_grader_kind(e)) from e

    # ----- De-sanitize the response for local display -----
    response_md = san.desanitize(response.text, mapping)
    return response, response_md, user_message, arch


def _store_sessionmaker(
    settings: Settings,
) -> tuple[AsyncEngine | None, async_sessionmaker[AsyncSession] | None]:
    """Wire the app's local SQLite store into the eval context (fail-soft).

    The production API passes ``app.state.db_sessionmaker`` into every
    :class:`InvestigationContext`, so the investigator's ``t_lookup_runbook``
    tool can search operator runbooks. The eval harness historically passed
    nothing, which silently pinned ``lookup_runbook`` to ``[]`` on every eval
    run (E4.1 reachability finding, 2026-07-08: 6/32 investigations called it,
    all got ``[]`` regardless of the runbook table). Wire the same store here
    WHEN it already exists (``settings.soc_ai_data_dir / soc-ai.db``); the
    harness never creates or migrates the DB (that's the app's — or the eval
    driver script's — job), and a missing/unopenable store degrades to the old
    no-DB behavior, never an error. The caller owns disposal of the returned
    engine.
    """
    try:
        # A PostgreSQL store has no file to look for; the app created it.
        db_path = settings.soc_ai_data_dir / "soc-ai.db"
        if not is_postgres_url(store_url(settings)) and not db_path.is_file():
            return None, None
        engine = make_engine(settings)
        return engine, make_sessionmaker(engine)
    except Exception as e:  # fail-soft by design (eval must run DB-less)
        _LOGGER.warning("eval store wiring failed; lookup_runbook sees no DB: %s", e)
        return None, None


def _build_context(
    settings: Settings,
    *,
    include_synth: bool | str = False,
    db_sessionmaker: async_sessionmaker[AsyncSession] | None = None,
) -> InvestigationContext:
    """Build an InvestigationContext from settings, no audit logger.

    The eval harness deliberately skips the audit logger — every event
    is captured locally and saved to the bundle, so duplicating into
    the audit ES index would double-cost the storage for no value.

    ``db_sessionmaker`` (from :func:`_store_sessionmaker`) mirrors the API
    layer's store injection so ``t_lookup_runbook`` — and any future
    store-backed read tool — behaves in evals as it does in production.
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
        db_sessionmaker=db_sessionmaker,
    )


def _sanitize_event_payload(
    kind: str,
    sequence: int,
    payload: dict[str, Any],
    mapping: san.Mapping,
    *,
    extra_hosts: tuple[str, ...] = (),
    extra_suffixes: tuple[str, ...] = (),
) -> dict[str, Any]:
    """Return a sanitized copy of one SSE event payload."""
    return {
        "kind": kind,
        "sequence": sequence,
        "payload": _sanitize_dict(
            payload, mapping, extra_hosts=extra_hosts, extra_suffixes=extra_suffixes
        ),
    }


def _sanitize_dict(
    value: Any,
    mapping: san.Mapping,
    *,
    extra_hosts: tuple[str, ...] = (),
    extra_suffixes: tuple[str, ...] = (),
) -> Any:
    """Walk a dict/list/scalar tree, sanitize every string in place.

    Non-string scalars (int, bool, None) pass through unchanged.

    Both keys and values are sanitized when they are strings — the
    synth-first redesign's `enrichments: dict[str, IndicatorEnrichment]`
    keys IPs/domains by raw indicator string, which would otherwise
    leak through.

    ``extra_hosts`` / ``extra_suffixes`` (the operator's ORACLE_EXTRA_HOSTS /
    ORACLE_INTERNAL_SUFFIXES) are threaded into every sanitize() call so
    deployment-specific bare hostnames and custom internal suffixes are
    redacted here too, not just by the defaults.
    """
    if isinstance(value, str):
        sanitized, _ = san.sanitize(
            value, mapping=mapping, extra_hosts=extra_hosts, extra_suffixes=extra_suffixes
        )
        return sanitized
    if isinstance(value, dict):
        return {
            (
                san.sanitize(
                    k, mapping=mapping, extra_hosts=extra_hosts, extra_suffixes=extra_suffixes
                )[0]
                if isinstance(k, str)
                else k
            ): _sanitize_dict(v, mapping, extra_hosts=extra_hosts, extra_suffixes=extra_suffixes)
            for k, v in value.items()
        }
    if isinstance(value, list):
        return [
            _sanitize_dict(v, mapping, extra_hosts=extra_hosts, extra_suffixes=extra_suffixes)
            for v in value
        ]
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
    grader_error: str | None = None,
    grader_error_kind: str | None = None,
) -> None:
    """Persist the full artifact bundle.

    Layout:
        bundle_dir/
            response.md            the oracle's de-sanitized critique
            response.sanitized.md  the oracle's RAW critique (labels intact)
            request.json           what was sent (sanitized)
            events.jsonl           one event per line (sanitized)
            mapping.json           {label: original}
            meta.json              alert_id, ts, model, tokens, status, elapsed

    ``response.md`` is de-sanitized for the operator to read; ``response.sanitized.md``
    keeps the label-only text the oracle actually returned. The meta-analysis
    re-sends critique sections to the cloud, so it MUST read the sanitized copy
    (never the rehydrated one) to avoid shipping real internal identifiers twice.
    """
    (bundle_dir / "response.md").write_text(response_md, encoding="utf-8")
    (bundle_dir / "response.sanitized.md").write_text(response.text, encoding="utf-8")
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
                # None on a graded and on an ungraded run. Set when the grade
                # request failed and the caller chose to keep the investigation.
                "grader_error": grader_error,
                "grader_error_kind": grader_error_kind,
            },
            indent=2,
            default=str,
        ),
        encoding="utf-8",
    )

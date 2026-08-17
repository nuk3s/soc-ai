"""Admin config console: settings, danger zone, API keys, agent tools, connection tests."""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from fastapi import Depends, HTTPException, Request
from pydantic import BaseModel, SecretStr, ValidationError
from sqlalchemy import select

from soc_ai.api import agent_tools as agent_tools_svc
from soc_ai.api.deps import get_settings_dep
from soc_ai.api.webui._shared import (
    _ago,
    require_admin_api,
    router,
)
from soc_ai.config import Settings
from soc_ai.store import config_overrides as cfg_svc
from soc_ai.store.models import ApiToken, ConfigOverride
from soc_ai.webui import (
    probes,
)
from soc_ai.webui.deps import current_user

_LOGGER = logging.getLogger(__name__)

# ── Config (admin) ─────────────────────────────────────────────────────────

_SETTING_TYPE = {
    "bool": "toggle",
    "int": "number",
    "float": "number",
    "str": "text",
    "csv": "text",
    "select": "select",
}


class SettingOut(BaseModel):
    key: str
    # Human label (what the console shows as the field title); the raw key is kept
    # as a secondary mono hint. Without this the UI fell back to the snake_case key.
    label: str
    help: str
    source: str
    apply: str
    type: str
    value: bool | float | str
    bounds: str | None = None
    options: list[str] | None = None


class SettingGroupOut(BaseModel):
    title: str
    # Top-level Config-page header this group nests under (SECTION_PARENTS —
    # server-owned so the frontend nav never hardcodes a divergent grouping).
    parent: str
    items: list[SettingOut]


class ApiTokenOut(BaseModel):
    id: int
    name: str
    prefix: str
    created: str
    used: str


class ConfigOut(BaseModel):
    groups: list[SettingGroupOut]
    tokens: list[ApiTokenOut]
    dangerHost: str


# ── Danger-zone models ────────────────────────────────────────────────────────


class DangerSettingOut(BaseModel):
    key: str
    label: str
    type: str  # "secret" | "text" | "bool" | "csv"
    isSet: bool  # whether a non-empty value is configured
    source: str  # "env" | "db" | "unset"
    hot: bool  # True = hot-apply, False = restart-required


class SaveDangerIn(BaseModel):
    key: str
    value: str
    confirm: str  # must equal key (typed confirmation)


class ConnTestOut(BaseModel):
    ok: bool
    detail: str


def _setting_value(spec: cfg_svc.SettingSpec, settings: Settings) -> bool | float | str:
    val = getattr(settings, spec.attr, None)
    if spec.type == "csv":
        return ", ".join(str(x) for x in (val or []))
    if spec.type == "bool":
        return bool(val)
    if spec.type in ("int", "float"):
        return val if val is not None else 0
    return "" if val is None else str(val)


def _override_display(spec: cfg_svc.SettingSpec, raw: Any) -> bool | float | str:
    """Format a stored (non-secret) override value the same way _setting_value
    formats a live one. Used for a hot=False setting whose DB override is not
    applied to the live Settings until restart — rendering the live attribute
    there would show the OLD value while the source badge already reads "db", so
    a just-saved value appears to vanish. Rendering the staged override keeps the
    field consistent with its source badge.
    """
    if spec.type == "csv":
        return ", ".join(str(x) for x in (raw or []))
    if spec.type == "bool":
        return bool(raw)
    if spec.type in ("int", "float"):
        return raw if raw is not None else 0
    return "" if raw is None else str(raw)


def _bounds(spec: cfg_svc.SettingSpec) -> str | None:
    lo, hi = spec.min_value, spec.max_value
    if lo is None and hi is None:
        return None

    def fmt(x: float | None) -> str:
        if x is None:
            return "∞"
        return str(int(x)) if spec.type == "int" and x == int(x) else str(x)

    return f"{fmt(lo)} to {fmt(hi)}"


@router.get("/config", response_model=ConfigOut, dependencies=[Depends(require_admin_api)])
async def get_config(
    request: Request,
    settings: Settings = Depends(get_settings_dep),
) -> ConfigOut:
    async with request.app.state.db_sessionmaker() as db:
        overrides = await cfg_svc.load_overrides(db)
        tokens = (
            (await db.execute(select(ApiToken).order_by(ApiToken.created_at.desc())))
            .scalars()
            .all()
        )

    groups: list[SettingGroupOut] = []
    for section in cfg_svc.SECTION_ORDER:
        items = [
            SettingOut(
                key=spec.key,
                label=spec.label,
                help=spec.help,
                source="db" if spec.key in overrides else "env",
                apply="hot-apply" if spec.hot else "restart",
                type=_SETTING_TYPE.get(spec.type, "text"),
                # Fixed-choice settings: the frontend's select branch keys on
                # type=='select' + options (that branch predates any server
                # emitting it — notify_format was special-cased by key instead).
                options=list(spec.options) if spec.options else None,
                # For a hot=False setting the DB override is not applied to the
                # live Settings until restart, so the live attribute still holds
                # the OLD value. Render the staged override instead so the field
                # matches its "db" source badge rather than silently reverting.
                value=(
                    _override_display(spec, overrides[spec.key])
                    if not spec.hot and spec.key in overrides
                    else _setting_value(spec, settings)
                ),
                bounds=_bounds(spec),
            )
            for spec in cfg_svc.WHITELIST
            if spec.section == section and not spec.danger and not spec.secret
        ]
        if items:
            groups.append(
                SettingGroupOut(
                    title=section,
                    # Fail-soft: an unmapped section becomes its own top-level
                    # bucket rather than 500ing the whole config page.
                    parent=cfg_svc.SECTION_PARENTS.get(section, section),
                    items=items,
                )
            )

    token_views = [
        ApiTokenOut(
            id=t.id,
            name=t.name,
            prefix="scai_••••",
            created=_ago(t.created_at.isoformat()),
            used=_ago(t.last_used_at.isoformat()) if t.last_used_at else "never",
        )
        for t in tokens
        if not t.revoked
    ]
    return ConfigOut(
        groups=groups, tokens=token_views, dangerHost=str(settings.so_host or "soc-ai")
    )


class GatewayModelsOut(BaseModel):
    ok: bool
    models: list[str] = []
    detail: str | None = None


@router.get(
    "/config/models",
    response_model=GatewayModelsOut,
    dependencies=[Depends(require_admin_api)],
)
async def api_gateway_models(
    settings: Settings = Depends(get_settings_dep),
) -> GatewayModelsOut:
    """Model ids the LiteLLM gateway serves.

    Feeds the analyst-model dropdown in the config console (fetched separately
    from GET /config so a slow/down gateway never delays the page — the UI
    falls back to a free-text field when this returns ok=false)."""
    ids, err = await probes.list_gateway_models(settings)
    return GatewayModelsOut(ok=err is None, models=ids, detail=err)


class ModelFitnessLegOut(BaseModel):
    name: str
    ok: bool
    grade: str  # "pass" | "degraded" | "fail"
    detail: str
    # How slow, and on which backend (2026-08-07). Every recorded FAIL in the
    # first 50 checks was a timeout reported as an unfalsifiable "timed out";
    # these two make the same event arguable. Null on a leg that never ran far
    # enough to measure, and on results cached before this shipped.
    elapsed_s: float | None = None
    backend: str | None = None


class ModelFitnessOut(BaseModel):
    grade: str  # "pass" | "degraded" | "fail" | "unknown"
    model: str
    legs: list[ModelFitnessLegOut] = []
    detail: str
    # Cache metadata (migration 0023): the Config page auto-runs this check on
    # every load, and a fitness verdict only changes when the backend behind the
    # route does — so within the TTL the route answers from the stored result.
    cached: bool = False
    checked_at: str | None = None
    # Which gateway backend served the probe (LiteLLM attribution headers). An
    # alias can be re-routed without the client seeing it, so "model X is unfit"
    # otherwise names what we asked for, not what ran.
    served_backend: dict[str, str] | None = None
    # Was a measurement actually taken for this response? False when the
    # self-load guard declined to probe (see ``_self_load_reason``), in which
    # case ``note`` says why and the verdict is the cached one (or "unknown").
    measured: bool = True
    note: str | None = None
    # n-of-m history from the audit store. ``alarm`` is the ONE boolean the chip
    # should key its red state on; the rest is the sentence under it ("unfit —
    # 2 of last 5 checks failed, last pass 3h ago"). All null when the audit
    # store could not be read, where ``alarm`` degrades to the single sample.
    alarm: bool = False
    recent_checks: int | None = None
    recent_fails: int | None = None
    consecutive_fails: int | None = None
    last_pass_at: str | None = None


# One day: the operator's "maybe once a day" (dogfood 2026-08-05). The manual
# "Check fitness" button always bypasses via ?force=true.
_FITNESS_CACHE_TTL_S = 24 * 3600

# How many checks the n-of-m window holds, and how many consecutive fails it
# takes to call the model unfit. WHY 2: of the 50 recorded checks for the live
# analyst model, 25 graded FAIL and every one was a timeout — several of them
# while soc-ai's own eval was saturating the same gateway. One adverse sample is
# a measurement; two in a row is a verdict.
_FITNESS_HISTORY_N = 5
_FITNESS_ALARM_CONSECUTIVE = 2
# How many docs to pull per window slot, since the model match is applied after
# the fetch (see _recent_fitness_checks). Covers an operator A/B-ing two models
# without a second round trip.
_HISTORY_OVERFETCH = 4


def _self_load_reason(state: Any) -> str | None:
    """Name the soc-ai batch currently saturating the gateway, or None.

    A fitness probe measures the model AND everything queued in front of it. At
    22:37:10 on 2026-08-06 the probe graded deepseek-v4-flash UNFIT while a
    graded eval was in flight against the same gateway — and that eval landed
    nine minutes later with agreement 1.0 over n_ok=5. The model "unable to
    produce a TriageReport" produced five, correctly, concurrently.

    Reads each batch through its OWNER's accessor rather than poking app.state
    attribute names, so a renamed status slot fails in CI (the tests import the
    same accessors) instead of quietly disabling the guard. At runtime it is
    fail-soft: the guard is a refinement of a read-only diagnostic and must never
    be the reason the Config page 500s.
    """
    try:
        from soc_ai.api.webui.routes_quality import _get_quality_eval_status  # noqa: PLC0415
        from soc_ai.webui import autotriage as at  # noqa: PLC0415

        if _get_quality_eval_status(state).running:
            return "quality-eval batch in flight"
        if at.get_status(state).active:
            return "auto-triage batch in flight"
        if _battery_status(state).running:
            return "model battery in flight"
    except Exception:
        _LOGGER.warning("model_fitness self-load check failed (probing anyway)", exc_info=True)
    return None


def _fitness_history_summary(window: list[dict[str, str]]) -> dict[str, Any]:
    """Fold the last-N checks (newest first) into the chip's n-of-m summary.

    ``window`` entries are ``{"grade": ..., "at": <iso>}``. ``alarm`` is True
    only on :data:`_FITNESS_ALARM_CONSECUTIVE` consecutive fails ending at the
    newest check, so a single slow measurement reports honestly without
    condemning the model.
    """
    consecutive = 0
    for entry in window:
        if entry["grade"] != "fail":
            break
        consecutive += 1
    return {
        "alarm": consecutive >= _FITNESS_ALARM_CONSECUTIVE,
        "recent_checks": len(window),
        "recent_fails": sum(1 for e in window if e["grade"] == "fail"),
        "consecutive_fails": consecutive,
        "last_pass_at": next((e["at"] for e in window if e["grade"] == "pass"), None),
    }


async def _recent_fitness_checks(
    request: Request, settings: Settings, *, model: str, limit: int
) -> list[dict[str, str]] | None:
    """The last *limit* stored ``model_fitness`` checks for *model*, newest first.

    The audit index already holds every check ever run — the history the chip
    needs exists without a schema change. Returns None (NOT an empty list) when
    the audit store can't be read, so the caller degrades to single-sample
    behaviour instead of claiming a clean history off a failed query. Never
    raises: an unreadable audit index must not break the Config page.

    Only ``kind`` is filtered server-side; the model match happens here, on the
    returned payloads. ``payload`` is mapped ``flattened`` only on indices created
    after that template landed, so a term query on ``payload.model`` would match
    NOTHING on an older daily index — and a silently empty history means the
    alarm can never fire again. Over-fetching a handful of docs is the cheaper
    failure mode.
    """
    elastic = getattr(request.app.state, "elastic", None)
    if elastic is None:
        return None
    query = {"bool": {"filter": [{"term": {"kind": "model_fitness"}}]}}
    try:
        # Same bound as the egress counts below: a silent grid must cost the chip
        # its history, not cost the operator ninety seconds of frozen Config page.
        async with asyncio.timeout(settings.webui_grid_timeout_s):
            result = await elastic.search(
                f"{settings.audit_index_alias}-*",
                query,
                size=limit * _HISTORY_OVERFETCH,
                sort=[{"timestamp": {"order": "desc"}}],
            )
        hits = result.hits
    except Exception:
        _LOGGER.info("model_fitness history unavailable (chip falls back to one sample)")
        return None
    if not isinstance(hits, list):
        return None
    checks: list[dict[str, str]] = []
    for hit in hits:
        src = hit.get("_source") if isinstance(hit, dict) else None
        if not isinstance(src, dict):
            continue
        payload = src.get("payload")
        if not isinstance(payload, dict) or str(payload.get("model", "")) != model:
            continue  # another model's checks must not colour this one's history
        grade = str(payload.get("grade", ""))
        at = str(src.get("timestamp", ""))
        if grade and at:
            checks.append({"grade": grade, "at": at})
        if len(checks) >= limit:
            break
    return checks


async def _fitness_out(
    request: Request,
    settings: Settings,
    *,
    result: dict[str, Any],
    model_id: str,
    cached: bool = False,
    checked_at: str | None = None,
    measured: bool = True,
    note: str | None = None,
) -> ModelFitnessOut:
    """Compose the chip payload: this verdict plus its n-of-m history.

    Every return path goes through here so the cached verdict — which is what
    the Config page actually renders most of the time — carries the same
    history summary as a fresh measurement.

    A freshly measured verdict is not in the audit index yet, so it is prepended
    to the window; a cached or not-measured one already is, so the window is the
    stored history alone (prepending would double-count it).
    """
    history = await _recent_fitness_checks(
        request, settings, model=model_id, limit=_FITNESS_HISTORY_N
    )
    grade = str(result.get("grade", "unknown"))
    if measured and not cached:
        window = [{"grade": grade, "at": checked_at or ""}, *(history or [])][:_FITNESS_HISTORY_N]
    else:
        window = list(history or [])[:_FITNESS_HISTORY_N]

    if history is None or not window:
        # No readable history: keep today's behaviour (one sample decides) rather
        # than claim a clean record we never read.
        summary: dict[str, Any] = {
            "alarm": grade == "fail",
            "recent_checks": None,
            "recent_fails": None,
            "consecutive_fails": None,
            "last_pass_at": None,
        }
    else:
        summary = _fitness_history_summary(window)

    return ModelFitnessOut(
        grade=grade,
        model=str(result.get("model", model_id)),
        legs=[ModelFitnessLegOut(**leg) for leg in result.get("legs", [])],
        detail=str(result.get("detail", "")),
        cached=cached,
        checked_at=checked_at,
        served_backend=result.get("served_backend"),
        measured=measured,
        note=note,
        **summary,
    )


@router.get(
    "/config/model-fitness",
    response_model=ModelFitnessOut,
    dependencies=[Depends(require_admin_api)],
)
async def api_model_fitness(
    request: Request,
    force: bool = False,
    settings: Settings = Depends(get_settings_dep),
) -> ModelFitnessOut:
    """Grade whether ``analyst_model`` can actually do the pipeline's job.

    Runs the three-leg fitness probe (structured output, tool loop, reasoning
    budget) against the real gateway and returns the grade. Feeds the
    "Check fitness" chip next to the analyst-model dropdown in the config console
    — a model that lists on /config/models can still be UNFIT (all-fallback
    verdicts), which this catches. Bounded + fail-soft in probes.py; never issues
    a Security-Onion write.

    Emits a ``model_fitness`` audit event with the grade so an operator switching
    to an unfit model leaves a trail of the warning that was shown. The audit
    write is best-effort: config routes are otherwise audit-free, and a failed
    audit index must never turn a read-only diagnostic into a 500 — so it is
    wrapped and logged, never raised.

    Two guards on the AUTO path (``force=false``), both from the 2026-08-07 audit
    of all 50 stored checks. First, the probe does not run while soc-ai's own
    eval/auto-triage/battery is saturating the gateway — that measures the queue,
    not the model. Second, the red state is n-of-m: the response carries the last
    checks read back out of the audit index, and ``alarm`` needs two consecutive
    fails. ``?force=true`` (the operator's "Check fitness") bypasses the first.
    """
    from soc_ai.store import model_battery as mb_svc  # noqa: PLC0415

    model_id = str(settings.analyst_model or "")
    cached: dict[str, Any] | None = None
    if not force:
        # Serve the cached verdict inside the TTL — page loads must not cost a
        # gateway probe (dogfood 2026-08-05: "Checking fitness…" every visit).
        async with request.app.state.db_sessionmaker() as db:
            cached = await mb_svc.get_fitness(db, model=model_id)
        if cached is not None:
            try:
                checked = datetime.fromisoformat(cached["checked_at"])
                age_s = (datetime.now(UTC).replace(tzinfo=None) - checked).total_seconds()
            except ValueError:
                age_s = _FITNESS_CACHE_TTL_S + 1
            if age_s < _FITNESS_CACHE_TTL_S:
                return await _fitness_out(
                    request,
                    settings,
                    result=cached["result"],
                    model_id=model_id,
                    cached=True,
                    checked_at=cached["checked_at"],
                )

        # Stale (or absent) cache AND soc-ai is hammering its own gateway: keep
        # the old verdict rather than manufacture a new one from queue latency.
        load = _self_load_reason(request.app.state)
        if load is not None:
            note = f"not measured: {load}"
            if cached is not None:
                return await _fitness_out(
                    request,
                    settings,
                    result=cached["result"],
                    model_id=model_id,
                    cached=True,
                    checked_at=cached["checked_at"],
                    measured=False,
                    note=note,
                )
            return await _fitness_out(
                request,
                settings,
                result={"grade": "unknown", "model": model_id, "legs": [], "detail": note},
                model_id=model_id,
                measured=False,
                note=note,
            )

    result = await probes.probe_model_fitness(settings)
    checked_at_now = datetime.now(UTC).replace(tzinfo=None).isoformat()
    try:
        async with request.app.state.db_sessionmaker() as db:
            await mb_svc.upsert_fitness(db, model=model_id, result=result)
    except Exception:  # cache write is best-effort — never fail the diagnostic
        _LOGGER.warning("model_fitness cache write failed (continuing)", exc_info=True)

    # Compose (and read the history) BEFORE the audit write: this run's own
    # record must not land in its own n-of-m window.
    out = await _fitness_out(
        request, settings, result=result, model_id=model_id, checked_at=checked_at_now
    )

    # Best-effort audit. request.app.state.audit is the shared AuditLogger; its
    # own log() swallows ES write errors for non-mutating events, but we still
    # guard defensively (a missing/None audit on a test double, etc.) so the
    # diagnostic itself can never fail on the audit side.
    try:
        user = await current_user(request)
        audit = getattr(request.app.state, "audit", None)
        if audit is not None:
            await audit.log_kind(
                session_id=f"model-fitness:{result.get('model', '')}",
                kind="model_fitness",
                payload={
                    "model": result.get("model", ""),
                    "grade": result.get("grade", ""),
                    "detail": result.get("detail", ""),
                    "legs": result.get("legs", []),
                },
                user=user.username if user else "unknown",
            )
    except Exception:  # audit is best-effort — a diagnostic must never 500 on it
        _LOGGER.warning("model_fitness audit write failed (continuing)", exc_info=True)

    # E2.4 notification trigger — a FAIL grade pings on-call (an unfit analyst
    # model silently ruins triage). THIN + fail-soft: build the event iff the probe
    # graded FAIL + notify_on_model_fitness_fail is on, and fire it (a hard no-op
    # unless notifications are enabled + a webhook is configured). Wrapped so a
    # webhook can never turn this read-only diagnostic into a 500.
    #
    # Gated on the SAME n-of-m alarm as the chip: paging on every transient
    # measurement is what taught on-call to ignore the unfit-model alert (25 of
    # the first 50 checks graded FAIL, all of them timeouts).
    try:
        if out.alarm:
            from soc_ai import notify  # noqa: PLC0415

            event = notify.event_for_model_fitness(result=result, settings=settings)
            if event is not None:
                await notify.fire_safe(event, settings, getattr(request.app.state, "audit", None))
    except Exception:  # a notification must never break the diagnostic
        _LOGGER.warning("model_fitness notify trigger failed (continuing)", exc_info=True)

    return out


# ── Audit chain verification (admin) ───────────────────────────────────────
# The audit trail carries a tamper-evident hash chain (soc_ai.audit.chain). This
# endpoint lets an operator actually RUN that verification against the live audit
# index — the whole point of tamper-evidence is being able to check it. Shares the
# ES-fetch + verify_chain path with the `soc-ai audit verify` CLI
# (soc_ai.audit.verify.verify_audit_chain).


class AuditChainVerifyOut(BaseModel):
    ok: bool  # True iff the chain (over the scanned records) is intact
    records_verified: int  # number of chained records checked
    first_broken_seq: int | None = None  # seq of the first break, else null
    first_seq: int | None = None  # seq span actually covered (null on empty)
    last_seq: int | None = None
    capped: bool = False  # True iff the scan hit the record cap (prefix only)
    checked_at: str  # ISO-8601 UTC timestamp of this verification


@router.get(
    "/config/audit/verify-chain",
    response_model=AuditChainVerifyOut,
    dependencies=[Depends(require_admin_api)],
    tags=["config"],
)
async def api_audit_verify_chain(
    request: Request,
    days: int | None = None,
    settings: Settings = Depends(get_settings_dep),
) -> AuditChainVerifyOut:
    """Verify the tamper-evident audit hash chain against the live ES audit index.

    Pulls every audit record (optionally the last ``?days=N`` days) sorted by
    ``seq`` and recomputes the chain (see :mod:`soc_ai.audit.chain`). ``ok`` is
    True iff no record was edited, reordered, inserted, or deleted since it was
    written; ``first_broken_seq`` names the first break otherwise. An empty index
    is intact by definition.

    Unlike the other config diagnostics this is NOT fail-soft: a verification
    against an unreachable audit index is "could not run", never a clean chain —
    so an ES error propagates to a 5xx rather than being reported as ``ok``. A
    windowed (``days``) scan verifies contiguity within the window but cannot
    verify linkage across the window boundary.
    """
    from datetime import UTC, datetime  # noqa: PLC0415

    from soc_ai.audit.verify import verify_audit_chain  # noqa: PLC0415
    from soc_ai.so_client.elastic import GridPartialResultsError  # noqa: PLC0415

    elastic = getattr(request.app.state, "elastic", None)
    if elastic is None:
        raise HTTPException(
            status_code=503,
            detail={"reason": "audit_verify_unavailable", "message": "no ES client"},
        )

    try:
        result = await verify_audit_chain(elastic, settings.audit_index_alias, days=days)
    except GridPartialResultsError as exc:
        # ES answered 200 but read only part of the audit index. The same refusal
        # as any other read failure — unverifiable, never a verdict either way —
        # but with the full shard story in the message: the operator must be able
        # to tell "could not read the whole index" apart from "the chain broke",
        # and the generic arm below deliberately reports only an exception type.
        _LOGGER.warning("audit chain verification read only part of the index: %s", exc)
        raise HTTPException(
            status_code=502,
            detail={"reason": "audit_verify_failed", "message": str(exc)},
        ) from exc
    except Exception as exc:
        # A verification is meaningless if we couldn't read the records — surface
        # it as "could not run", never as an intact chain.
        _LOGGER.warning("audit chain verification failed to run", exc_info=True)
        raise HTTPException(
            status_code=502,
            detail={"reason": "audit_verify_failed", "message": f"{type(exc).__name__}"},
        ) from exc

    return AuditChainVerifyOut(
        ok=result.ok,
        records_verified=result.records_verified,
        first_broken_seq=result.first_broken_seq,
        first_seq=result.first_seq,
        last_seq=result.last_seq,
        capped=result.capped,
        checked_at=datetime.now(UTC).isoformat(),
    )


# ── Egress policy (admin, read-model) — E5.3 ───────────────────────────────
# ONE page listing every possible egress destination, its enable state, its
# redaction posture, and a best-effort 7-day audit count — so "zero egress" is
# INSPECTABLE, not asserted. Pure read over Settings (+ the audit index for the
# counters); no writes, no new audit kind, no migration. The counters are
# best-effort: a down/unreachable audit index yields null counts and the policy
# table still renders (the table — enable state + posture — is the deliverable).


class EgressDestinationOut(BaseModel):
    id: str
    label: str
    enabled: bool
    redaction: str  # short posture string
    detail: str  # one-line human description
    count_7d: int | None = None  # best-effort 7-day audit count; null = unknown


class EgressPolicyOut(BaseModel):
    destinations: list[EgressDestinationOut]
    zero_egress: bool  # True iff EVERY destination is disabled


def _secret_is_set(value: object) -> bool:
    """True when a (possibly SecretStr) value holds a non-empty string."""
    if value is None:
        return False
    raw = value.get_secret_value() if isinstance(value, SecretStr) else str(value)
    return bool(raw.strip())


# Egress destination → the audit kind(s) whose 7-day count reflects "this
# destination actually fired". Web search / page fetch have no dedicated kind
# (they're generic ``tool_call``s, indistinguishable at the index level without
# a payload filter), so they map to no kind → count stays null (honest "unknown",
# not a misleading 0). Oracle counts both the escalation and the adjudication.
_EGRESS_AUDIT_KINDS: dict[str, list[str]] = {
    "oracle": ["oracle_escalation", "oracle_adjudication"],
    "web_search": [],
    "crawl": [],
    "online_enrichment": [],
    "analyst_cloud": [],
    "notifications": ["notification"],
    "rag_gateway": [],
}


def _egress_destinations(settings: Settings) -> list[dict[str, Any]]:
    """Build the egress destination rows from live Settings (no counts yet).

    "enabled" is derived TRUTHFULLY per destination: a toggle alone for Oracle /
    online enrichment / analyst redaction; a toggle AND a reachable URL for web
    search / page fetch; a toggle AND a configured webhook for notifications.

    "redaction" is HONEST about posture. In particular, the analyst-model
    destination reads ``analyst_cloud_redaction``: with it OFF, the analyst model
    egresses with NO redaction — so the posture says exactly that (and names the
    fail-closed upgrade when redaction IS on).
    """
    # Analyst redaction posture: off = no redaction; on = best-effort, unless
    # fail-closed is also on (independent residue sweep, E5.1).
    if not settings.analyst_cloud_redaction:
        analyst_redaction = (
            "none — pointed at your gateway; enable analyst_cloud_redaction "
            "if that gateway routes to a cloud model"
        )
    elif settings.analyst_redaction_fail_closed:
        analyst_redaction = "sanitized + fail-closed"
    else:
        analyst_redaction = "sanitized (best-effort)"

    return [
        {
            "id": "oracle",
            "label": "Oracle (cloud second opinion)",
            "enabled": bool(settings.oracle_enabled),
            "redaction": "sanitized + fail-closed residue gate",
            "detail": (
                f"Frontier adjudicator ({settings.oracle_model}) via the gateway; "
                "internal identifiers pseudonymized before egress, residue-gated."
            ),
        },
        {
            "id": "web_search",
            "label": "Web search (SearXNG)",
            # A toggle alone isn't reachable — the tool also needs a SearXNG URL.
            "enabled": bool(settings.web_search_enabled) and bool(settings.searxng_url.strip()),
            "redaction": "refuses internal identifiers",
            "detail": "Investigator web search; the query refuses internal identifiers.",
        },
        {
            "id": "crawl",
            "label": "Page fetch (crawl4ai)",
            "enabled": bool(settings.crawl4ai_enabled) and bool(settings.crawl4ai_url.strip()),
            "redaction": "refuses internal URLs",
            "detail": "Deep page read of a URL; refuses internal/private URLs.",
        },
        {
            "id": "online_enrichment",
            "label": "Online enrichment (Shodan / GreyNoise / CVE)",
            "enabled": bool(settings.allow_online_enrichment),
            "redaction": "external indicators only",
            "detail": "Third-party reputation/asset lookups; sends external indicators only.",
        },
        {
            "id": "analyst_cloud",
            "label": "Analyst model",
            # The analyst model ALWAYS receives payloads — this "destination" is a
            # real egress iff the model is pointed off-box. We can't know the
            # gateway's downstream from here, so "enabled" tracks whether the
            # redaction guard is engaged; the posture string carries the honesty.
            "enabled": bool(settings.analyst_cloud_redaction),
            "redaction": analyst_redaction,
            "detail": (
                f"The analyst model ({settings.analyst_model}) itself; "
                "a real egress only if your gateway routes it to a cloud provider."
            ),
        },
        {
            "id": "notifications",
            "label": "Notifications (webhook)",
            # Needs BOTH the master toggle AND a configured webhook URL.
            "enabled": bool(settings.notify_enabled)
            and _secret_is_set(settings.notify_webhook_url),
            "redaction": "synthetic, no internal data",
            "detail": "Outbound alert/hunt webhook; synthetic bodies, no internal identifiers.",
        },
        {
            "id": "rag_gateway",
            "label": "Runbook retrieval (embeddings / rerank)",
            # Either model id makes retrieval call the gateway. Same host as the
            # analyst model (litellm_base_url) — like analyst_cloud, a REAL
            # egress only if that gateway routes off-box; the posture is honest
            # about what leaves the process either way.
            "enabled": bool(settings.rag_embed_model.strip())
            or bool(settings.rag_rerank_model.strip()),
            "redaction": "none — sends runbook text + agent search queries",
            "detail": (
                "Opt-in semantic tier for lookup_runbook: runbooks + search "
                "queries go to your gateway's embeddings/rerank models "
                f"({settings.rag_embed_model or 'unset'} / "
                f"{settings.rag_rerank_model or 'unset'}). Off = pure-local FTS5."
            ),
        },
    ]


@router.get(
    "/config/egress-policy",
    response_model=EgressPolicyOut,
    dependencies=[Depends(require_admin_api)],
    tags=["config"],
)
async def api_egress_policy(
    request: Request,
    settings: Settings = Depends(get_settings_dep),
) -> EgressPolicyOut:
    """One page: every egress destination, its enable state, redaction posture,
    and a best-effort 7-day audit count. Makes "zero egress" inspectable.

    Pure read-model. ``zero_egress`` is True iff EVERY destination is disabled.
    The counters are BEST-EFFORT: the 7-day audit aggregation is wrapped so ANY
    ES error yields null counts and the table still renders — a down audit index
    must never break the page. Destinations with no dedicated audit kind (web
    search, page fetch, online enrichment, analyst model — generic ``tool_call``s
    at the index level) return null counts by design (honest "unknown", not 0).
    """
    from soc_ai.audit.counts import audit_counts_by_kind  # noqa: PLC0415

    rows = _egress_destinations(settings)
    zero_egress = not any(row["enabled"] for row in rows)

    # Best-effort counts. Aggregate ONCE over the union of mapped kinds, then fan
    # the results back to each destination. Wrapped defensively so even an
    # unexpected failure in the helper (which is itself fail-soft) can never turn
    # this read-only diagnostic into a 500 — null counts, table still returned.
    all_kinds = sorted({k for kinds in _EGRESS_AUDIT_KINDS.values() for k in kinds})
    counts_by_kind: dict[str, int | None] = {}
    if all_kinds:
        try:
            elastic = getattr(request.app.state, "elastic", None)
            # Bounded at the console's grid budget rather than the ES client's
            # retry budget (~90 s at shipped defaults). A grid that accepts the
            # connection and never answers raises nothing, so the fail-soft
            # handler below never ran and the page simply hung — and the one page
            # an operator opens to check "is anything leaving this box" is the
            # worst place in the product to look frozen. A timeout lands in that
            # handler like any other failure: unknown counts, table still drawn.
            async with asyncio.timeout(settings.webui_grid_timeout_s):
                counts_by_kind = await audit_counts_by_kind(
                    elastic, settings.audit_index_alias, all_kinds, days=7
                )
        except Exception:  # the helper is fail-soft, but never trust it to a 500
            _LOGGER.warning("egress-policy audit counts failed (continuing null)", exc_info=True)
            counts_by_kind = {}

    destinations: list[EgressDestinationOut] = []
    for row in rows:
        kinds = _EGRESS_AUDIT_KINDS.get(row["id"], [])
        # Sum the per-kind counts for this destination. Null when the destination
        # has no mapped kind, OR when any of its kinds' counts is unknown (a
        # partial sum would understate — better an honest null).
        count_7d: int | None
        if not kinds:
            count_7d = None
        else:
            per = [counts_by_kind.get(k) for k in kinds]
            count_7d = None if any(c is None for c in per) else sum(c or 0 for c in per)
        destinations.append(
            EgressDestinationOut(
                id=row["id"],
                label=row["label"],
                enabled=row["enabled"],
                redaction=row["redaction"],
                detail=row["detail"],
                count_7d=count_7d,
            )
        )

    return EgressPolicyOut(destinations=destinations, zero_egress=zero_egress)


# ── Runbook retrieval (RAG) admin: re-embed (E4.1) ─────────────────────────
# The semantic tier embeds runbooks at write time (fail-soft), so vectors go
# MISSING when the gateway was down during a save, and STALE when the operator
# switches rag_embed_model. This endpoint is the catch-up: one pass embedding
# every missing/stale runbook, returning honest counts (a gateway failure is
# counted, never raised — the button shows "N failed", not a 500).


class RagReembedOut(BaseModel):
    ok: bool  # True iff nothing failed
    total: int  # runbooks in the store
    embedded: int  # vectors written this pass
    skipped: int  # already embedded by the current model
    failed: int  # gateway failures (vectors NOT written)


@router.post(
    "/config/rag/reembed",
    response_model=RagReembedOut,
    dependencies=[Depends(require_admin_api)],
    tags=["config"],
)
async def api_rag_reembed(
    request: Request,
    settings: Settings = Depends(get_settings_dep),
) -> RagReembedOut:
    """Embed every runbook whose vector is missing or stale (wrong model).

    Requires ``rag_embed_model`` to be configured (400 otherwise — the button
    is pointless with the tier off). Purely local except the one batched
    gateway embeddings call; never writes to Security Onion.
    """
    if not settings.rag_embed_model.strip():
        raise HTTPException(
            status_code=400,
            detail={
                "reason": "rag_disabled",
                "hint": "set rag_embed_model (Retrieval settings) before re-embedding",
            },
        )
    from soc_ai.rag import runbook_embeddings as rag_svc  # noqa: PLC0415

    async with request.app.state.db_sessionmaker() as db:
        counts = await rag_svc.reembed_missing(db, settings=settings)
    return RagReembedOut(ok=counts["failed"] == 0, **counts)


# ── Config mutations (admin) ───────────────────────────────────────────────


class SettingIn(BaseModel):
    key: str
    value: str  # stringified; coerced to the spec's declared type server-side


@router.post("/config/setting", dependencies=[Depends(require_admin_api)])
async def set_setting(request: Request, body: SettingIn) -> dict[str, Any]:
    """Persist + (if hot) hot-apply one whitelisted, non-Danger setting.

    Danger-Zone (connection/secret) settings are deliberately NOT editable here —
    they use the typed-confirm + Fernet path on POST /api/v1/config/danger/setting.
    """
    settings = request.app.state.settings
    if not cfg_svc.is_editable(body.key):
        raise HTTPException(status_code=400, detail={"reason": "unknown_setting"})
    spec = cfg_svc.WHITELIST_BY_KEY[body.key]
    if spec.danger:
        raise HTTPException(
            status_code=400,
            detail={"reason": "danger_zone", "hint": "use POST /api/v1/config/danger/setting"},
        )
    if spec.secret:
        # Secrets never go through the plaintext (secret_box=None) path — that
        # would raise deep in set_override (500). Route them to the dedicated
        # write-only endpoint instead.
        raise HTTPException(
            status_code=400,
            detail={"reason": "secret_setting", "hint": "use POST /api/v1/config/api-keys"},
        )
    try:
        typed = cfg_svc.coerce(body.key, body.value)
    except ValueError as exc:
        raise HTTPException(
            status_code=400, detail={"reason": "invalid_value", "hint": str(exc)}
        ) from exc
    user = await current_user(request)
    # Validate the live assignment BEFORE persisting: coerce() accepts a
    # type-correct value that a Settings field validator / cross-field constraint
    # can still reject at assignment time. Dry-run it against a COPY of the live
    # settings so a rejected value is refused up front — rather than being
    # committed over the operator's previously-saved override and then "rolled
    # back" by DELETING the row, which would discard that prior value and silently
    # revert the setting to its env/default on the next restart.
    if spec.hot:
        try:
            setattr(settings.model_copy(), spec.attr, typed)
        except (ValueError, TypeError, ValidationError) as exc:
            raise HTTPException(
                status_code=400,
                detail={
                    "reason": "invalid_value",
                    "hint": f"{body.key} failed validation on apply and was not saved",
                },
            ) from exc
    async with request.app.state.db_sessionmaker() as db:
        await cfg_svc.set_override(
            db, body.key, typed, updated_by=user.id if user else None, secret_box=None
        )
        if spec.hot:
            # The dry-run above proved this assignment succeeds, so it applies now.
            cfg_svc.apply_to_settings(settings, {body.key: typed}, secret_box=None)
    return {"ok": True, "restart_required": not spec.hot}


@router.get(
    "/config/danger",
    response_model=list[DangerSettingOut],
    dependencies=[Depends(require_admin_api)],
    tags=["config"],
)
async def api_get_danger_settings(
    request: Request,
    settings: Settings = Depends(get_settings_dep),
) -> list[DangerSettingOut]:
    """List all danger-zone settings. Secret values are NEVER returned — only isSet status."""
    # Fetch all DB override keys in one query to avoid N+1.
    async with request.app.state.db_sessionmaker() as db:
        db_row_keys: set[str] = set(
            (
                await db.scalars(
                    select(ConfigOverride.key).where(
                        ConfigOverride.key.in_(
                            [spec.key for spec in cfg_svc.WHITELIST_BY_KEY.values() if spec.danger]
                        )
                    )
                )
            ).all()
        )

    rows: list[DangerSettingOut] = []
    for spec in cfg_svc.WHITELIST_BY_KEY.values():
        if not spec.danger:
            continue

        # Determine source and isSet: DB takes precedence over env.
        if spec.key in db_row_keys:
            source = "db"
            is_set = True
        else:
            # Check the live Settings attribute (populated from env / .env at startup).
            attr_val = getattr(settings, spec.attr, None)
            is_set = _secret_is_set(attr_val)
            source = "env" if is_set else "unset"

        # Map internal SettingType to the frontend type label.
        if spec.secret:
            field_type = "secret"
        elif spec.type == "bool":
            field_type = "bool"
        elif spec.type == "csv":
            field_type = "csv"
        else:
            field_type = "text"

        rows.append(
            DangerSettingOut(
                key=spec.key,
                label=spec.label,
                type=field_type,
                isSet=is_set,
                source=source,
                hot=spec.hot,
            )
        )
    return rows


@router.post(
    "/config/danger/setting",
    dependencies=[Depends(require_admin_api)],
    tags=["config"],
)
async def api_save_danger_setting(
    body: SaveDangerIn,
    request: Request,
    settings: Settings = Depends(get_settings_dep),
) -> dict[str, object]:
    """Save a danger-zone setting. Requires typed confirmation (confirm must equal key).

    Secret-typed settings are Fernet-encrypted before DB storage.
    Never returns the plaintext value. A hot=True danger spec (PCAP SSH, the
    crawl4ai token, internal_cidrs — all read fresh per tool-call) is applied
    live; the SO/ES/LiteLLM connection settings feed startup clients and still
    need a restart.
    """
    # 1. Typed confirmation guard
    if body.confirm.strip() != body.key:
        raise HTTPException(
            status_code=400,
            detail={"reason": "confirm_mismatch", "hint": "confirm must equal the setting key"},
        )

    # 2. Validate key is a known danger spec
    spec = cfg_svc.WHITELIST_BY_KEY.get(body.key)
    if spec is None or not spec.danger:
        raise HTTPException(
            status_code=400,
            detail={"reason": "unknown_danger_key", "hint": "key is not a known danger setting"},
        )

    # 3. Coerce the string value to the spec's declared type
    try:
        typed = cfg_svc.coerce(body.key, body.value)
    except ValueError as exc:
        raise HTTPException(
            status_code=400, detail={"reason": "invalid_value", "hint": str(exc)}
        ) from exc

    # 4. Determine actor for audit trail (id is int | None)
    user = await current_user(request)
    updated_by: int | None = user.id if user else None

    # 5. Persist — set_override Fernet-encrypts secret-typed values when secret_box is set.
    #    A secret-typed key with no CONFIG_SECRET_KEY makes set_override raise
    #    ValueError; surface that as a 400 (operator must set the key) rather than
    #    an uncaught 500. No plaintext is written on this path.
    secret_box = request.app.state.secret_box

    # Validate the live assignment BEFORE persisting for hot specs: a value that
    # fails live validation (a field or cross-field constraint, e.g. PCAP_ENABLED
    # requiring a non-empty SO_SSH_HOST, or a malformed internal_cidrs entry) must
    # be refused up front rather than committed over the operator's prior override
    # and then "rolled back" by DELETING the row — which would discard that prior
    # value and revert to the env value on the next restart. Dry-run against a
    # COPY of the live settings (the hot danger specs are all non-secret plaintext).
    if spec.hot:
        try:
            setattr(settings.model_copy(), spec.attr, typed)
        except (ValueError, TypeError, ValidationError) as exc:
            raise HTTPException(
                status_code=400,
                detail={
                    "reason": "invalid_value",
                    "hint": f"{body.key} failed validation on apply and was not saved",
                },
            ) from exc

    try:
        async with request.app.state.db_sessionmaker() as db:
            await cfg_svc.set_override(
                db,
                body.key,
                typed,
                updated_by=updated_by,
                secret_box=secret_box if spec.secret else None,
            )
    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail={
                "reason": "no_config_secret_key",
                "hint": "Set CONFIG_SECRET_KEY to edit secret values via the UI.",
            },
        ) from exc

    # Hot specs are read fresh per tool-call → apply live via setattr on the
    # Settings singleton (validate_assignment coerces str→SecretStr, csv→typed).
    # The dry-run above proved this assignment succeeds, so it applies now.
    if spec.hot:
        setattr(settings, spec.attr, typed)
        restart_required = False
    else:
        restart_required = True

    return {"ok": True, "restart_required": restart_required}


# ── API keys (hot, write-only enrichment provider secrets) ────────────────────
# Distinct from the Danger-Zone secrets (SO/ES/LiteLLM, restart-required): these
# enrichment keys are read per tool-call, so a save hot-applies live (no restart)
# and no typed confirm is required. Values are Fernet-encrypted at rest and never
# returned to the client.


class ApiKeyOut(BaseModel):
    key: str
    label: str
    help: str
    isSet: bool
    source: str  # "db" | "env" | "unset"


class SaveApiKeyIn(BaseModel):
    key: str
    value: str


@router.get(
    "/config/api-keys",
    response_model=list[ApiKeyOut],
    dependencies=[Depends(require_admin_api)],
    tags=["config"],
)
async def api_get_api_keys(
    request: Request,
    settings: Settings = Depends(get_settings_dep),
) -> list[ApiKeyOut]:
    """List the enrichment API-key fields. Values are NEVER returned — only isSet."""
    specs = cfg_svc.api_key_specs()
    async with request.app.state.db_sessionmaker() as db:
        db_keys: set[str] = set(
            (
                await db.scalars(
                    select(ConfigOverride.key).where(ConfigOverride.key.in_([s.key for s in specs]))
                )
            ).all()
        )
    out: list[ApiKeyOut] = []
    for spec in specs:
        if spec.key in db_keys:
            source, is_set = "db", True
        else:
            attr_val = getattr(settings, spec.attr, None)
            is_set = _secret_is_set(attr_val)
            source = "env" if is_set else "unset"
        out.append(
            ApiKeyOut(key=spec.key, label=spec.label, help=spec.help, isSet=is_set, source=source)
        )
    return out


@router.post(
    "/config/api-keys",
    dependencies=[Depends(require_admin_api)],
    tags=["config"],
)
async def api_save_api_key(
    body: SaveApiKeyIn,
    request: Request,
    settings: Settings = Depends(get_settings_dep),
) -> dict[str, object]:
    """Save an enrichment API key (Fernet-encrypted, write-only) and hot-apply it."""
    spec = cfg_svc.WHITELIST_BY_KEY.get(body.key)
    if spec is None or not spec.secret or spec.danger:
        raise HTTPException(
            status_code=400,
            detail={"reason": "unknown_api_key", "hint": "key is not a known API-key setting"},
        )
    value = body.value.strip()
    if not value:
        raise HTTPException(
            status_code=400,
            detail={"reason": "empty_value", "hint": "send a non-empty value, or DELETE to clear"},
        )
    user = await current_user(request)
    updated_by: int | None = user.id if user else None
    secret_box = request.app.state.secret_box
    try:
        async with request.app.state.db_sessionmaker() as db:
            await cfg_svc.set_override(
                db, body.key, value, updated_by=updated_by, secret_box=secret_box
            )
    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail={
                "reason": "no_config_secret_key",
                "hint": "Set CONFIG_SECRET_KEY to store API keys via the UI.",
            },
        ) from exc
    # Persist the plaintext onto the live Settings singleton (validate_assignment
    # coerces str → SecretStr). NOT apply_to_settings — that decrypts a stored
    # token. Most enrichment keys are read fresh per tool-call so this applies
    # live; the one exception is misp_api_key (hot=False), which is baked into the
    # MISP client built at startup and only takes effect on restart — the field's
    # help text (surfaced by GET /config/api-keys) carries that restart warning.
    setattr(settings, spec.attr, value)
    return {"ok": True, "isSet": True}


@router.delete(
    "/config/api-keys/{key}",
    dependencies=[Depends(require_admin_api)],
    tags=["config"],
)
async def api_clear_api_key(
    key: str,
    request: Request,
    settings: Settings = Depends(get_settings_dep),
) -> dict[str, object]:
    """Clear an enrichment API key: drop the DB override and unset the live value."""
    spec = cfg_svc.WHITELIST_BY_KEY.get(key)
    if spec is None or not spec.secret or spec.danger:
        raise HTTPException(
            status_code=400,
            detail={"reason": "unknown_api_key", "hint": "key is not a known API-key setting"},
        )
    async with request.app.state.db_sessionmaker() as db:
        await cfg_svc.delete_override(db, key)
    # Hot-clear the live value (reverts to None until a restart re-applies env).
    setattr(settings, spec.attr, None)
    return {"ok": True, "isSet": False}


class AgentToolsOut(BaseModel):
    tools: list[agent_tools_svc.AgentToolOut]


@router.get(
    "/config/agent-tools",
    response_model=AgentToolsOut,
    dependencies=[Depends(require_admin_api)],
    tags=["config"],
)
async def api_get_agent_tools(
    settings: Settings = Depends(get_settings_dep),
) -> AgentToolsOut:
    """List every tool available to the agent, with its description + dependencies."""
    return AgentToolsOut(tools=agent_tools_svc.collect_agent_tools(settings))


# ── Notifications (E2.4): the webhook secret + a "Send test" validation ────────
# The master toggle / per-trigger toggles / format / threshold are ordinary
# non-secret settings in the "Notifications" group (rendered by GET /config like
# any other section). The webhook URL is a secret handled here on its OWN
# endpoints (Fernet-encrypted, write-only) so it stays in the Notifications
# section rather than the shared API-keys panel. The Test button posts a canned,
# synthetic event — it requires a configured webhook URL but NOT the master
# toggle, so an operator can validate the destination BEFORE enabling routing.


class NotifyWebhookOut(BaseModel):
    isSet: bool
    source: str  # "db" | "env" | "unset"


class SaveNotifyWebhookIn(BaseModel):
    value: str


@router.get(
    "/config/notify/webhook",
    response_model=NotifyWebhookOut,
    dependencies=[Depends(require_admin_api)],
    tags=["config"],
)
async def api_get_notify_webhook(
    request: Request,
    settings: Settings = Depends(get_settings_dep),
) -> NotifyWebhookOut:
    """Report whether the notification webhook URL is set (never returns the value)."""
    spec = cfg_svc.notify_webhook_spec()
    async with request.app.state.db_sessionmaker() as db:
        in_db = (
            await db.scalars(select(ConfigOverride.key).where(ConfigOverride.key == spec.key))
        ).first() is not None
    if in_db:
        return NotifyWebhookOut(isSet=True, source="db")
    attr_val = getattr(settings, spec.attr, None)
    is_set = _secret_is_set(attr_val)
    return NotifyWebhookOut(isSet=is_set, source="env" if is_set else "unset")


@router.post(
    "/config/notify/webhook",
    dependencies=[Depends(require_admin_api)],
    tags=["config"],
)
async def api_save_notify_webhook(
    body: SaveNotifyWebhookIn,
    request: Request,
    settings: Settings = Depends(get_settings_dep),
) -> dict[str, object]:
    """Save the webhook URL (Fernet-encrypted, write-only) and hot-apply it.

    Mirrors the API-key save path: an http(s) URL is required; it is encrypted at
    rest and never returned. Requires CONFIG_SECRET_KEY (else a 400 telling the
    operator to set it, not a 500).
    """
    spec = cfg_svc.notify_webhook_spec()
    value = body.value.strip()
    if not value:
        raise HTTPException(
            status_code=400,
            detail={"reason": "empty_value", "hint": "send a non-empty URL, or DELETE to clear"},
        )
    # Reject a non-http(s) scheme up front (SSRF hygiene, same as the URL settings).
    from urllib.parse import urlparse  # noqa: PLC0415

    scheme = urlparse(value).scheme.lower()
    if scheme not in ("http", "https"):
        raise HTTPException(
            status_code=400,
            detail={"reason": "invalid_value", "hint": "webhook URL must be http(s)"},
        )
    user = await current_user(request)
    updated_by: int | None = user.id if user else None
    secret_box = request.app.state.secret_box
    try:
        async with request.app.state.db_sessionmaker() as db:
            await cfg_svc.set_override(
                db, spec.key, value, updated_by=updated_by, secret_box=secret_box
            )
    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail={
                "reason": "no_config_secret_key",
                "hint": "Set CONFIG_SECRET_KEY to store the webhook URL via the UI.",
            },
        ) from exc
    # Hot-apply: notify.fire reads the URL fresh per send. setattr the plaintext
    # onto the live Settings singleton (validate_assignment coerces str→SecretStr).
    setattr(settings, spec.attr, value)
    return {"ok": True, "isSet": True}


@router.delete(
    "/config/notify/webhook",
    dependencies=[Depends(require_admin_api)],
    tags=["config"],
)
async def api_clear_notify_webhook(
    request: Request,
    settings: Settings = Depends(get_settings_dep),
) -> dict[str, object]:
    """Clear the webhook URL: drop the DB override and unset the live value."""
    spec = cfg_svc.notify_webhook_spec()
    async with request.app.state.db_sessionmaker() as db:
        await cfg_svc.delete_override(db, spec.key)
    setattr(settings, spec.attr, None)
    return {"ok": True, "isSet": False}


@router.post(
    "/config/notify/test",
    response_model=ConnTestOut,
    dependencies=[Depends(require_admin_api)],
    tags=["config"],
)
async def api_notify_test(
    request: Request,
    settings: Settings = Depends(get_settings_dep),
) -> ConnTestOut:
    """Send a canned, synthetic test notification to the configured webhook.

    Requires a webhook URL to be configured; does NOT require ``notify_enabled``
    (this is an explicit operator validation — send the test, THEN enable routing).
    The canned event contains NO internal identifier (a fixed "soc-ai notification
    test" body), so validating the destination never leaks a real alert/hunt/host.
    Returns ``{ok, detail}`` (scrubbed — never the webhook URL).
    """
    from soc_ai import notify  # noqa: PLC0415

    if not notify.webhook_configured(settings):
        return ConnTestOut(
            ok=False,
            detail="No webhook URL configured — set the Notifications webhook URL first.",
        )

    audit = getattr(request.app.state, "audit", None)
    ok, detail = await notify.send_test(settings, audit)
    return ConnTestOut(ok=ok, detail=detail)


_DANGER_TEST_TARGETS: frozenset[str] = frozenset({"es", "llm"})


@router.post(
    "/config/danger/test/{target}",
    response_model=ConnTestOut,
    dependencies=[Depends(require_admin_api)],
    tags=["config"],
)
async def api_danger_test_connection(
    target: str,
    request: Request,
    settings: Settings = Depends(get_settings_dep),
) -> ConnTestOut:
    """Run a connectivity probe for target ∈ {es, llm}.
    Returns {ok, detail}. Detail is secret-free — probes.py scrubs credentials internally.

    The ES leg is bounded by ``webui_grid_timeout_s``. ``probe_es`` never raises,
    so against a grid that accepts the connection and never answers it simply did
    not come back: the probe sat on the ES client's retry budget (~90 s at shipped
    defaults) and the BROWSER produced the verdict when it gave up at 20 s. The one
    control on this page whose entire job is diagnosing the grid was the one control
    that could not state a diagnosis. On expiry it states one — definitive, from the
    server, naming the budget it waited out. The LLM leg needs no wrapper: it is an
    HTTP call to the gateway under its own per-request timeout, not an ES read.
    """
    if target not in _DANGER_TEST_TARGETS:
        valid = sorted(_DANGER_TEST_TARGETS)
        raise HTTPException(
            status_code=400,
            detail={"reason": "unknown_target", "hint": f"target must be one of {valid}"},
        )

    if target == "es":
        budget = settings.webui_grid_timeout_s
        try:
            async with asyncio.timeout(budget):
                result = await probes.probe_es(request.app.state.elastic)
        except TimeoutError:
            return ConnTestOut(
                ok=False,
                detail=(
                    f"Security Onion did not answer within {budget}s — treating the grid "
                    "as down. Check Elasticsearch load and shard health."
                ),
            )
    else:
        result = await probes.probe_llm(settings)

    return ConnTestOut(ok=result["ok"], detail=result["detail"])


# ── Model fitness battery (design spec 2026-08-05) ───────────────────────────
#
# The on-demand second tier of the fitness feature: probe the analyst model
# under every structured-output configuration and recommend the winner. Slow
# (minutes on a CPU tier), so it runs as a background task with a polling GET —
# the auto-triage status pattern — never as a long HTTP request.


@dataclass
class _BatteryStatus:
    """Single-flight battery state on ``app.state`` (mirrors AutoTriageStatus)."""

    running: bool = False
    model: str = ""
    current_config: str | None = None
    completed: int = 0
    total: int = 4
    error: str | None = None
    _task: Any = None


def _battery_status(state: Any) -> _BatteryStatus:
    status = getattr(state, "model_battery_status", None)
    if status is None:
        status = _BatteryStatus()
        state.model_battery_status = status
    return status


class BatteryStartIn(BaseModel):
    # The LiteLLM route to probe; empty/absent = the configured analyst model.
    # Probing the STAGED dropdown selection before save is the point.
    model: str = ""


async def _run_battery_task(
    state: Any, settings: Settings, model: str, status: _BatteryStatus
) -> None:
    """Background battery run: probe → persist → audit. Never raises."""
    from soc_ai import model_probe  # noqa: PLC0415 - patch point for tests
    from soc_ai.store import model_battery as mb_svc  # noqa: PLC0415

    def _progress(label: str, i: int, total: int) -> None:
        status.current_config = label
        status.completed = i - 1
        status.total = total

    try:
        result = await model_probe.run_battery(settings, model=model or None, on_progress=_progress)
        async with state.db_sessionmaker() as db:
            await mb_svc.upsert(db, model=result["model"], result=result)
        status.completed = status.total
        # Audit the measurement like model_fitness does — best-effort: a failed
        # audit index must never fail the battery that already completed.
        try:
            audit = getattr(state, "audit", None)
            if audit is not None:
                rec = result.get("recommendation")
                await audit.log_kind(
                    session_id=f"model-battery:{result['model']}",
                    kind="model_battery",
                    payload={
                        "model": result["model"],
                        "recommendation": rec,
                        "configs": [
                            {
                                "output_mode": c.get("output_mode"),
                                "tool_choice_required": c.get("tool_choice_required"),
                                "ok": c.get("ok"),
                                "n": c.get("n"),
                                "elapsed_s": c.get("elapsed_s"),
                            }
                            for c in result.get("configs", [])
                        ],
                    },
                )
        except Exception:
            _LOGGER.exception("model-battery audit write failed (result persisted)")
    except Exception as exc:
        _LOGGER.exception("model battery failed for model=%s", model)
        status.error = " ".join(str(exc).split())[:300]
    finally:
        status.running = False
        status.current_config = None


@router.post(
    "/config/model-battery",
    status_code=202,
    dependencies=[Depends(require_admin_api)],
)
async def api_start_model_battery(
    body: BatteryStartIn,
    request: Request,
    settings: Settings = Depends(get_settings_dep),
) -> dict[str, Any]:
    """Start a fitness battery in the background (409 if one is running).

    Single-flight across models on purpose: probes run sequentially so timing
    stays attributable, and two concurrent batteries against one gateway would
    queue against each other and corrupt both measurements.
    """
    status = _battery_status(request.app.state)
    if status.running:
        raise HTTPException(status_code=409, detail="a model battery is already running")
    status.running = True
    status.model = body.model or settings.analyst_model
    status.completed = 0
    status.error = None
    status._task = asyncio.create_task(
        _run_battery_task(request.app.state, settings, body.model, status)
    )
    return {"started": True, "model": status.model}


@router.get(
    "/config/model-battery",
    dependencies=[Depends(require_admin_api)],
)
async def api_model_battery_status(
    request: Request,
    model: str = "",
    settings: Settings = Depends(get_settings_dep),
) -> dict[str, Any]:
    """Live battery progress, or the persisted last result for *model*.

    While a battery runs, every poll returns its progress (regardless of the
    ``model`` param — single-flight means there is exactly one to report).
    Idle, the stored result for the requested model is served with its
    timestamp so the UI can render measurement age.
    """
    status = _battery_status(request.app.state)
    if status.running:
        return {
            "running": True,
            "model": status.model,
            "current_config": status.current_config,
            "completed": status.completed,
            "total": status.total,
            "result": None,
            "stored_at": None,
        }
    from soc_ai.store import model_battery as mb_svc  # noqa: PLC0415

    target = model or settings.analyst_model
    async with request.app.state.db_sessionmaker() as db:
        stored = await mb_svc.get(db, model=target)
    # A fitness-only row carries an empty-dict result marker: a quick fitness
    # check ran (the one that fires on Config mount) but no full battery. A real
    # battery report always has a ``configs`` key; the marker has none. Serve the
    # marker as absent — a truthy ``{}`` on the wire has no configs array, and the
    # UI's table render did ``result.configs.map`` on it, taking down the whole
    # Config page (P0). Null in, honest wire shape out.
    result = stored["result"] if stored else None
    has_battery = isinstance(result, dict) and "configs" in result
    return {
        "running": False,
        "model": target,
        "current_config": None,
        "completed": 0,
        "total": 4,
        "error": status.error,
        "result": result if has_battery else None,
        "stored_at": stored["created_at"] if (stored and has_battery) else None,
    }

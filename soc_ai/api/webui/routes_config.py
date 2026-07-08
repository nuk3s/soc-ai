"""Admin config console: settings, danger zone, API keys, agent tools, connection tests."""

from __future__ import annotations

import logging
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

_SETTING_TYPE = {"bool": "toggle", "int": "number", "float": "number", "str": "text", "csv": "text"}


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
                value=_setting_value(spec, settings),
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


class ModelFitnessOut(BaseModel):
    grade: str  # "pass" | "degraded" | "fail"
    model: str
    legs: list[ModelFitnessLegOut] = []
    detail: str


@router.get(
    "/config/model-fitness",
    response_model=ModelFitnessOut,
    dependencies=[Depends(require_admin_api)],
)
async def api_model_fitness(
    request: Request,
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
    """
    result = await probes.probe_model_fitness(settings)

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
    try:
        from soc_ai import notify  # noqa: PLC0415

        event = notify.event_for_model_fitness(result=result, settings=settings)
        if event is not None:
            await notify.fire_safe(event, settings, getattr(request.app.state, "audit", None))
    except Exception:  # a notification must never break the diagnostic
        _LOGGER.warning("model_fitness notify trigger failed (continuing)", exc_info=True)

    return ModelFitnessOut(
        grade=result["grade"],
        model=result["model"],
        legs=[ModelFitnessLegOut(**leg) for leg in result.get("legs", [])],
        detail=result["detail"],
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
    async with request.app.state.db_sessionmaker() as db:
        await cfg_svc.set_override(
            db, body.key, typed, updated_by=user.id if user else None, secret_box=None
        )
        restart_required = not spec.hot
        if spec.hot:
            applied = cfg_svc.apply_to_settings(settings, {body.key: typed}, secret_box=None)
            if body.key not in applied:
                # coerce() accepted the value but the live Settings model rejected
                # the assignment (a field validator / cross-field constraint).
                # apply_to_settings skips it silently, so without this the DB would
                # keep a poisoned override that never applies and re-skips every
                # restart while the UI reported success. Roll back + report honestly.
                await cfg_svc.delete_override(db, body.key)
                raise HTTPException(
                    status_code=400,
                    detail={
                        "reason": "invalid_value",
                        "hint": f"{body.key} failed validation on apply and was not saved",
                    },
                )
    return {"ok": True, "restart_required": restart_required}


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
            if attr_val is None:
                source = "unset"
                is_set = False
            else:
                # SecretStr fields must be unwrapped to check for emptiness.
                raw = (
                    attr_val.get_secret_value()
                    if isinstance(attr_val, SecretStr)
                    else str(attr_val)
                )
                if raw.strip():
                    source = "env"
                    is_set = True
                else:
                    source = "unset"
                    is_set = False

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
    # restart_required reflects whether it actually applied (a non-hot spec, or a
    # value that fails live validation, still persists and applies on restart).
    applied_live = False
    if spec.hot:
        try:
            setattr(settings, spec.attr, typed)
            applied_live = True
        except (ValueError, TypeError, ValidationError):
            applied_live = False

    return {"ok": True, "restart_required": not applied_live}


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
            raw = (
                attr_val.get_secret_value()
                if isinstance(attr_val, SecretStr)
                else ("" if attr_val is None else str(attr_val))
            )
            source, is_set = ("env", True) if raw.strip() else ("unset", False)
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
    # Hot-apply: enrichment keys are read fresh per tool-call. setattr the
    # plaintext onto the live Settings singleton (validate_assignment coerces
    # str → SecretStr). NOT apply_to_settings — that decrypts a stored token.
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
    raw = (
        attr_val.get_secret_value()
        if isinstance(attr_val, SecretStr)
        else ("" if attr_val is None else str(attr_val))
    )
    return NotifyWebhookOut(isSet=bool(raw.strip()), source="env" if raw.strip() else "unset")


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
    """
    if target not in _DANGER_TEST_TARGETS:
        valid = sorted(_DANGER_TEST_TARGETS)
        raise HTTPException(
            status_code=400,
            detail={"reason": "unknown_target", "hint": f"target must be one of {valid}"},
        )

    if target == "es":
        result = await probes.probe_es(request.app.state.elastic)
    else:
        result = await probes.probe_llm(settings)

    return ConnTestOut(ok=result["ok"], detail=result["detail"])

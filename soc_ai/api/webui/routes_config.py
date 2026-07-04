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
            groups.append(SettingGroupOut(title=section, items=items))

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

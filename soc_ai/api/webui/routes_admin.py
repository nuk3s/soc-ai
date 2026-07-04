"""Admin: API tokens and user management."""

from __future__ import annotations

import logging
import secrets

from fastapi import Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy.exc import IntegrityError

from soc_ai.api.webui._shared import (
    require_admin_api,
    router,
)
from soc_ai.store import auth as auth_svc
from soc_ai.webui.deps import current_user

_LOGGER = logging.getLogger(__name__)


class TokenCreateIn(BaseModel):
    # Charset-restricted: the token name surfaces in the alerts-grid owner field
    # (owner = "token:<name>"), so keep it to a safe, non-injectable set.
    name: str = Field(min_length=1, max_length=64, pattern=r"^[\w .\-]+$")


@router.post("/config/tokens", dependencies=[Depends(require_admin_api)])
async def create_token(request: Request, body: TokenCreateIn) -> dict[str, str]:
    """Mint an API token — the raw ``scai_…`` value is returned ONCE.

    Requires a real authenticated session user as the creator. ``created_by`` is
    a non-null FK to ``users.id``; we refuse rather than persist a token attributed
    to user 0 / null (which would happen for a bearer-token caller or a dev session
    that passed the auth gate without a resolvable session user).
    """
    name = body.name.strip() or "token"
    user = await current_user(request)
    if user is None:
        raise HTTPException(
            status_code=403,
            detail={
                "reason": "no_session_user",
                "hint": (
                    "Minting an API token requires an authenticated admin session; "
                    "log in at /app/login (bearer-token callers cannot mint tokens)."
                ),
            },
        )
    async with request.app.state.db_sessionmaker() as db:
        raw = await auth_svc.create_api_token(db, name, user.id)
    return {"token": raw}


@router.post("/config/tokens/{token_id}/revoke", dependencies=[Depends(require_admin_api)])
async def revoke_token(request: Request, token_id: int) -> dict[str, bool]:
    async with request.app.state.db_sessionmaker() as db:
        await auth_svc.revoke_api_token(db, token_id)
    return {"ok": True}


# ── User management (admin) ────────────────────────────────────────────────


class UserOut(BaseModel):
    id: int
    username: str
    role: str
    disabled: bool
    status: str
    lastLoginAt: str | None


class UsersListOut(BaseModel):
    users: list[UserOut]


class CreateUserIn(BaseModel):
    username: str = Field(min_length=1, max_length=64, pattern=r"^[\w.\-@]+$")
    password: str = Field(min_length=1, max_length=1024)
    role: str


class SetRoleIn(BaseModel):
    role: str


@router.get("/config/users", response_model=UsersListOut, dependencies=[Depends(require_admin_api)])
async def list_users_endpoint(request: Request) -> UsersListOut:
    async with request.app.state.db_sessionmaker() as db:
        users = await auth_svc.list_users(db)
    return UsersListOut(
        users=[
            UserOut(
                id=u.id,
                username=u.username,
                role=u.role,
                disabled=u.disabled,
                status=u.status,
                lastLoginAt=u.last_login_at.isoformat() if u.last_login_at is not None else None,
            )
            for u in users
        ]
    )


@router.post("/config/users", dependencies=[Depends(require_admin_api)])
async def create_user_endpoint(request: Request, body: CreateUserIn) -> dict[str, bool]:
    username = body.username.strip()
    if not username:
        raise HTTPException(
            status_code=400,
            detail={"reason": "username_required", "hint": "Username must not be empty."},
        )
    if len(body.password) < 8:
        raise HTTPException(
            status_code=400,
            detail={
                "reason": "password_too_short",
                "hint": "Password must be at least 8 characters.",
            },
        )
    if body.role not in auth_svc.VALID_ROLES:
        raise HTTPException(
            status_code=400,
            detail={"reason": "invalid_role", "hint": "Role must be admin or analyst."},
        )
    async with request.app.state.db_sessionmaker() as db:
        existing = await auth_svc.list_users(db)
        if any(u.username == username for u in existing):
            raise HTTPException(
                status_code=400,
                detail={
                    "reason": "username_taken",
                    "hint": f"Username {username!r} is already taken.",
                },
            )
        try:
            await auth_svc.create_user(db, username, body.password, role=body.role)
        except IntegrityError as exc:
            raise HTTPException(
                status_code=400,
                detail={
                    "reason": "username_taken",
                    "hint": f"Username {username!r} is already taken.",
                },
            ) from exc
    return {"ok": True}


@router.post(
    "/config/users/{user_id}/toggle-disabled",
    dependencies=[Depends(require_admin_api)],
)
async def toggle_user_disabled(request: Request, user_id: int) -> dict[str, bool | int]:
    # Resolve caller for self-disable guard: session user OR API-token bearer
    caller = await current_user(request)
    if caller is None and request.app.state.settings.api_auth_required:
        # Bearer-token caller: resolve user from token so self-disable is blocked
        authz = request.headers.get("authorization", "")
        if authz.lower().startswith("bearer "):
            raw_token = authz[7:].strip()
            async with request.app.state.db_sessionmaker() as _db:
                api_tok = await auth_svc.check_api_token(_db, raw_token)
            if api_tok is not None:
                async with request.app.state.db_sessionmaker() as _db:
                    caller = await auth_svc.get_user_by_id(_db, api_tok.created_by)
    if caller is not None and caller.id == user_id:
        raise HTTPException(
            status_code=400,
            detail={
                "reason": "cannot_disable_self",
                "hint": "You cannot disable your own account.",
            },
        )
    async with request.app.state.db_sessionmaker() as db:
        target = await auth_svc.get_user_by_id(db, user_id)
        if target is None:
            raise HTTPException(
                status_code=400,
                detail={"reason": "user_not_found", "hint": f"No user with id {user_id}."},
            )
        will_disable = not target.disabled
        if will_disable and target.role == "admin":
            count = await auth_svc.count_enabled_admins(db)
            if count <= 1:
                raise HTTPException(
                    status_code=400,
                    detail={
                        "reason": "last_admin",
                        "hint": "Cannot disable the last enabled admin.",
                    },
                )
        await auth_svc.set_user_disabled(db, user_id, will_disable)
    return {"ok": True, "disabled": will_disable}


@router.post(
    "/config/users/{user_id}/reset-password",
    dependencies=[Depends(require_admin_api)],
)
async def reset_user_password_endpoint(request: Request, user_id: int) -> dict[str, str | bool]:
    async with request.app.state.db_sessionmaker() as db:
        target = await auth_svc.get_user_by_id(db, user_id)
        if target is None:
            raise HTTPException(
                status_code=400,
                detail={"reason": "user_not_found", "hint": f"No user with id {user_id}."},
            )
        new_pw = secrets.token_urlsafe(12)
        await auth_svc.reset_user_password(db, user_id, new_pw)
    return {"ok": True, "password": new_pw}


@router.post(
    "/config/users/{user_id}/set-role",
    dependencies=[Depends(require_admin_api)],
)
async def set_user_role_endpoint(
    request: Request, user_id: int, body: SetRoleIn
) -> dict[str, bool]:
    if body.role not in auth_svc.VALID_ROLES:
        raise HTTPException(
            status_code=400,
            detail={"reason": "invalid_role", "hint": "Role must be admin or analyst."},
        )
    async with request.app.state.db_sessionmaker() as db:
        target = await auth_svc.get_user_by_id(db, user_id)
        if target is None:
            raise HTTPException(
                status_code=400,
                detail={"reason": "user_not_found", "hint": f"No user with id {user_id}."},
            )
        if target.role == "admin" and body.role != "admin" and not target.disabled:
            count = await auth_svc.count_enabled_admins(db)
            if count <= 1:
                raise HTTPException(
                    status_code=400,
                    detail={"reason": "last_admin", "hint": "Cannot demote the last admin."},
                )
        await auth_svc.set_user_role(db, user_id, body.role)
    return {"ok": True}

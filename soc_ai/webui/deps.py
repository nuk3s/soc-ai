"""FastAPI dependency for resolving the current user from the session cookie.

Shared by the JSON API auth layer (``soc_ai.api.security`` /
``soc_ai.api.webui_api``). The React SPA authenticates via ``POST /api/v1/login``,
which sets the session cookie this module reads.
"""

from __future__ import annotations

from fastapi import Request
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from soc_ai.store import auth as auth_svc
from soc_ai.store.models import User


def db_sessionmaker(request: Request) -> async_sessionmaker[AsyncSession]:
    maker: async_sessionmaker[AsyncSession] = request.app.state.db_sessionmaker
    return maker


async def current_user(request: Request) -> User | None:
    raw = request.cookies.get(auth_svc.SESSION_COOKIE)
    if raw is None:
        return None
    async with db_sessionmaker(request)() as db:
        return await auth_svc.get_session_user(db, raw)

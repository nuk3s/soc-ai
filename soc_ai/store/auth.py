"""Password hashing and session/API-token lifecycle for the web UI.

Passwords use bcrypt (CPU-bound, run in a thread). Session and API tokens
are high-entropy random strings; only their SHA-256 is stored.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import secrets
import time
from datetime import UTC, datetime, timedelta
from typing import Any

import bcrypt
from pydantic import SecretStr
from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from soc_ai.store.models import ApiToken, User, UserSession

_LOGGER = logging.getLogger(__name__)

SESSION_COOKIE = "soc_ai_session"
_BCRYPT_MAX_BYTES = 72
TOKEN_PREFIX = "scai_"  # noqa: S105
VALID_ROLES = ("admin", "analyst")


# ---------------------------------------------------------------------------
# Login brute-force throttle (in-memory, no external dependency)
# ---------------------------------------------------------------------------


class LoginThrottle:
    """Sliding-window failed-login throttle keyed by (client IP, username).

    After ``max_failures`` failures inside ``window_s``, the key is locked for
    ``cooldown_s``. A successful login clears the key. State is in-memory and
    bounded (``max_keys``); oldest-touched entries are evicted when full, so a
    flood of distinct keys cannot grow the dict without limit. Per-process only
    — adequate for the single-process deployment; not shared across workers.
    """

    __slots__ = ("_fails", "_locked", "cooldown_s", "max_failures", "max_keys", "window_s")

    def __init__(
        self,
        *,
        max_failures: int = 5,
        window_s: float = 15 * 60,
        cooldown_s: float = 5 * 60,
        max_keys: int = 4096,
    ) -> None:
        self.max_failures = max_failures
        self.window_s = window_s
        self.cooldown_s = cooldown_s
        self.max_keys = max_keys
        # key -> list of failure timestamps (monotonic seconds), pruned to window.
        self._fails: dict[tuple[str, str], list[float]] = {}
        # key -> unlock-at timestamp (monotonic seconds).
        self._locked: dict[tuple[str, str], float] = {}

    @staticmethod
    def _key(ip: str, username: str) -> tuple[str, str]:
        return (ip or "?", (username or "").lower())

    def _evict_if_full(self) -> None:
        # Cheap bound: when over capacity, drop ~one entry. Locked keys are kept
        # preferentially (they're the security-relevant ones).
        while len(self._fails) >= self.max_keys:
            oldest_key = min(
                self._fails, key=lambda k: self._fails[k][-1] if self._fails[k] else 0.0
            )
            self._fails.pop(oldest_key, None)

    def is_locked(self, ip: str, username: str) -> bool:
        """True iff this (ip, username) is currently in cooldown."""
        key = self._key(ip, username)
        until = self._locked.get(key)
        if until is None:
            return False
        if time.monotonic() >= until:
            # Cooldown elapsed — clear the lock and the failure history.
            self._locked.pop(key, None)
            self._fails.pop(key, None)
            return False
        return True

    def record_failure(self, ip: str, username: str) -> bool:
        """Record a failed attempt. Returns True if the key is now locked."""
        key = self._key(ip, username)
        now = time.monotonic()
        window_start = now - self.window_s
        hits = [t for t in self._fails.get(key, ()) if t >= window_start]
        hits.append(now)
        self._evict_if_full()
        self._fails[key] = hits
        if len(hits) >= self.max_failures:
            self._locked[key] = now + self.cooldown_s
            return True
        return False

    def clear(self, ip: str, username: str) -> None:
        """Clear all failure state for a key (call on a successful login)."""
        key = self._key(ip, username)
        self._fails.pop(key, None)
        self._locked.pop(key, None)

    def reset(self) -> None:
        """Drop all state (test helper)."""
        self._fails.clear()
        self._locked.clear()


# Module-level singleton used by the login endpoint. A single process serves the
# app, so a per-process throttle is sufficient; reset() in tests.
login_throttle = LoginThrottle()

# Second throttle keyed per-IP across ALL usernames (uses the "" username bucket),
# so a password-spray that rotates usernames to stay under the per-(IP,username)
# limit still trips a coarser per-IP lockout. Higher threshold for shared/NAT IPs.
login_ip_throttle = LoginThrottle(max_failures=20, window_s=15 * 60, cooldown_s=15 * 60)

# Precomputed bcrypt hash for authenticate()'s constant-time path: verified
# against when the account is missing/disabled so login timing is uniform.
_DUMMY_PASSWORD_HASH = bcrypt.hashpw(b"soc-ai-constant-time", bcrypt.gensalt()).decode()


def utcnow() -> datetime:
    """Naive UTC now — the single producer for store timestamp comparisons."""
    return datetime.now(UTC).replace(tzinfo=None)


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def csrf_token_for(raw_session_token: str) -> str:
    """Stateless CSRF token derived from the (HttpOnly) session cookie."""
    return _sha256("csrf:" + raw_session_token)


async def hash_password(password: str) -> str:
    def _hash() -> str:
        return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

    return await asyncio.to_thread(_hash)


async def verify_password(password: str, password_hash: str) -> bool:
    def _verify() -> bool:
        return bool(bcrypt.checkpw(password.encode(), password_hash.encode()))

    return await asyncio.to_thread(_verify)


async def create_user(
    db: AsyncSession, username: str, password: str, role: str = "analyst"
) -> User:
    user = User(username=username, password_hash=await hash_password(password), role=role)
    db.add(user)
    await db.commit()
    await db.refresh(user)
    return user


async def authenticate(db: AsyncSession, username: str, password: str) -> User | None:
    if len(password.encode()) > _BCRYPT_MAX_BYTES:
        return None
    user = await db.scalar(select(User).where(User.username == username))
    if user is None or user.disabled:
        # Constant-time: run a bcrypt comparison against a fixed dummy hash so the
        # response time doesn't reveal whether the account exists / is enabled
        # (closes the login user-enumeration timing oracle).
        await verify_password(password, _DUMMY_PASSWORD_HASH)
        return None
    if not await verify_password(password, user.password_hash):
        return None
    user.last_login_at = utcnow()
    await db.commit()
    return user


async def create_session(db: AsyncSession, user: User, ttl_hours: int) -> str:
    raw = secrets.token_urlsafe(32)
    db.add(
        UserSession(
            token_hash=_sha256(raw),
            user_id=user.id,
            expires_at=utcnow() + timedelta(hours=ttl_hours),
        )
    )
    await db.commit()
    return raw


async def get_session_user(db: AsyncSession, raw_token: str) -> User | None:
    session = await db.scalar(
        select(UserSession).where(UserSession.token_hash == _sha256(raw_token))
    )
    if session is None or session.expires_at < utcnow():
        return None
    user = await db.get(User, session.user_id)
    if user is None or user.disabled:
        return None
    return user


async def delete_session(db: AsyncSession, raw_token: str) -> None:
    session = await db.scalar(
        select(UserSession).where(UserSession.token_hash == _sha256(raw_token))
    )
    if session is not None:
        await db.delete(session)
        await db.commit()


async def create_api_token(db: AsyncSession, name: str, created_by: int) -> str:
    raw = TOKEN_PREFIX + secrets.token_urlsafe(32)
    db.add(ApiToken(token_hash=_sha256(raw), name=name, created_by=created_by))
    await db.commit()
    return raw


async def check_api_token(db: AsyncSession, raw_token: str) -> ApiToken | None:
    token = await db.scalar(select(ApiToken).where(ApiToken.token_hash == _sha256(raw_token)))
    if token is None or token.revoked:
        return None
    token.last_used_at = utcnow()
    await db.commit()
    return token


# ---------------------------------------------------------------------------
# Admin management helpers (increment 2 — users + API tokens)
# ---------------------------------------------------------------------------


async def list_users(db: AsyncSession) -> list[User]:
    """All users, ordered by username (for the admin Users table)."""
    return list((await db.scalars(select(User).order_by(User.username))).all())


async def get_user_by_id(db: AsyncSession, user_id: int) -> User | None:
    """Fetch a single user by primary key, or ``None`` if absent."""
    return await db.get(User, user_id)


async def set_user_disabled(db: AsyncSession, user_id: int, disabled: bool) -> None:
    """Enable/disable a user account."""
    user = await db.get(User, user_id)
    if user is None:
        return
    user.disabled = disabled
    await db.commit()


async def reset_user_password(db: AsyncSession, user_id: int, new_password: str) -> None:
    """Set a new password hash and invalidate the user's existing sessions.

    Deleting the sessions forces a fresh login with the new credential, so a
    reset immediately revokes any active cookie for that account.
    """
    user = await db.get(User, user_id)
    if user is None:
        return
    user.password_hash = await hash_password(new_password)
    await db.execute(delete(UserSession).where(UserSession.user_id == user_id))
    await db.commit()


async def set_user_role(db: AsyncSession, user_id: int, role: str) -> None:
    """Set a user's role. Only ``admin``/``analyst`` are accepted."""
    if role not in VALID_ROLES:
        raise ValueError(f"invalid role: {role!r}")
    user = await db.get(User, user_id)
    if user is None:
        return
    user.role = role
    await db.commit()


async def set_user_status(db: AsyncSession, user_id: int, status: str) -> None:
    """Set a user's free-text status string (trimmed, capped at 64 chars)."""
    user = await db.get(User, user_id)
    if user is None:
        return
    user.status = status[:64]
    await db.commit()


async def count_enabled_admins(db: AsyncSession) -> int:
    """Number of enabled users with the ``admin`` role (last-admin guard)."""
    count: Any = await db.scalar(
        select(func.count()).select_from(User).where(User.role == "admin", User.disabled.is_(False))
    )
    return int(count or 0)


async def list_api_tokens(db: AsyncSession) -> list[ApiToken]:
    """All API tokens, newest first."""
    return list((await db.scalars(select(ApiToken).order_by(ApiToken.created_at.desc()))).all())


async def revoke_api_token(db: AsyncSession, token_id: int) -> None:
    """Mark an API token revoked (``check_api_token`` then rejects it)."""
    token = await db.get(ApiToken, token_id)
    if token is None:
        return
    token.revoked = True
    await db.commit()


async def bootstrap_admin(db: AsyncSession, fixed_password: SecretStr | None) -> str | None:
    """Create the initial admin if the users table is empty.

    Returns the generated password when one was invented (caller logs it);
    returns None when the table was non-empty or the operator supplied the
    password via settings (no reason to write a known secret to the journal).
    """
    count: Any = await db.scalar(select(func.count()).select_from(User))
    if count:
        return None
    if fixed_password is not None:
        await create_user(db, "admin", fixed_password.get_secret_value(), role="admin")
        return None
    password = secrets.token_urlsafe(12)
    await create_user(db, "admin", password, role="admin")
    return password

"""Location and lifecycle of the one-shot bootstrap-admin password sidecar.

Two places need the SAME path: startup writes it when it invents the initial
admin password (:func:`soc_ai.main._persist_bootstrap_credential`) and the
self-service password change retires it (``POST /api/v1/me/password``). A route
module cannot import ``soc_ai.main`` — ``main`` imports the routers — and a
second copy of the filename in the route would drift silently the day the
sidecar moves, so the path logic lives here and both sides call it.
"""

from __future__ import annotations

import hashlib
import logging
from pathlib import Path
from typing import Any

_LOGGER = logging.getLogger(__name__)

#: The account :func:`soc_ai.store.auth.bootstrap_admin` creates on a fresh DB.
BOOTSTRAP_ADMIN_USERNAME = "admin"

_FILENAME = "bootstrap-admin-password.txt"


def bootstrap_credential_path(settings: Any) -> Path:
    """Where the generated bootstrap password is parked (mode 0600)."""
    return Path(settings.soc_ai_data_dir) / _FILENAME


def clear_bootstrap_credential(settings: Any, username: str) -> bool:
    """Retire the sidecar once the bootstrap admin has set its own password.

    Returns True only when a file was actually removed. Callers use this
    strictly as a post-success cleanup, so every failure mode is non-fatal:

    - a different account changed its password → not ours to delete;
    - the file was never written (the operator supplied
      ``BOOTSTRAP_ADMIN_PASSWORD``) or was already deleted by hand → nothing
      to do, and emphatically not an error the analyst should see;
    - the data dir is read-only → log it, but the password change itself
      already succeeded and must still report success.
    """
    if username != BOOTSTRAP_ADMIN_USERNAME:
        return False
    path = bootstrap_credential_path(settings)
    try:
        path.unlink()
    except FileNotFoundError:
        return False
    except OSError:
        _LOGGER.warning(
            "could not remove the bootstrap credential sidecar at %s after the "
            "admin password change — delete it by hand",
            path,
        )
        return False
    _LOGGER.info("removed the bootstrap credential sidecar at %s (password changed)", path)
    return True


# bcrypt reads at most 72 bytes; a longer value can never be the stored password.
_BCRYPT_MAX_BYTES = 72

# (stored hash, digest of the candidate) -> did the candidate verify. A bcrypt
# check costs a quarter second, and ``GET /me`` asks on every page load. The
# stored hash changes with the password, so a cached answer can never outlive
# the password it describes.
_GENERATED_CACHE: dict[tuple[str, str], bool] = {}
_GENERATED_CACHE_MAX = 64


#: Where a generated password can sit. The values are the doctor's words.
SOURCE_SIDECAR = "sidecar"
SOURCE_ENV = "env"


def _generated_candidates(settings: Any) -> list[tuple[str, str]]:
    """The passwords soc-ai generated for the bootstrap admin, if any remain.

    Two sources: the sidecar the first start writes, and the
    ``BOOTSTRAP_ADMIN_PASSWORD`` that ``setup.sh`` generates into ``.env``. Both
    sit in a plaintext file, so an admin still on either one has a password a
    reader of that file knows.
    """
    out: list[tuple[str, str]] = []
    try:
        text = bootstrap_credential_path(settings).read_text(encoding="utf-8").strip()
    except (OSError, UnicodeDecodeError):
        text = ""
    if text:
        out.append((SOURCE_SIDECAR, text))
    fixed = getattr(settings, "bootstrap_admin_password", None)
    if fixed is not None:
        value = str(fixed.get_secret_value())
        if value and value != text:
            out.append((SOURCE_ENV, value))
    return [(src, c) for src, c in out if len(c.encode()) <= _BCRYPT_MAX_BYTES]


async def generated_password_source(settings: Any, username: str, password_hash: str) -> str | None:
    """Where the bootstrap admin's live generated password sits, or None.

    Only the bootstrap account can hold one. Another account whose password
    happens to equal it is not flagged: nothing told that user the value.
    """
    if username != BOOTSTRAP_ADMIN_USERNAME or not password_hash:
        return None
    from soc_ai.store.auth import verify_password  # noqa: PLC0415 - keep this module light

    for source, candidate in _generated_candidates(settings):
        key = (password_hash, hashlib.sha256(candidate.encode()).hexdigest())
        hit = _GENERATED_CACHE.get(key)
        if hit is None:
            try:
                hit = await verify_password(candidate, password_hash)
            except ValueError:
                hit = False
            if len(_GENERATED_CACHE) >= _GENERATED_CACHE_MAX:
                _GENERATED_CACHE.clear()
            _GENERATED_CACHE[key] = hit
        if hit:
            return source
    return None


async def uses_generated_password(settings: Any, username: str, password_hash: str) -> bool:
    """True when the bootstrap admin still signs in with a generated password."""
    return await generated_password_source(settings, username, password_hash) is not None

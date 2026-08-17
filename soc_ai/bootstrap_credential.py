"""Location and lifecycle of the one-shot bootstrap-admin password sidecar.

Two places need the SAME path: startup writes it when it invents the initial
admin password (:func:`soc_ai.main._persist_bootstrap_credential`) and the
self-service password change retires it (``POST /api/v1/me/password``). A route
module cannot import ``soc_ai.main`` — ``main`` imports the routers — and a
second copy of the filename in the route would drift silently the day the
sidecar moves, so the path logic lives here and both sides call it.
"""

from __future__ import annotations

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

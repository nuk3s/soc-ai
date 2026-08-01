"""About metadata + the opt-in GitHub release check.

The update check is the About page's only outbound call, so it follows the same
discipline as the rest of soc-ai's egress: off by default, fail closed, never
raise, never leak. When enabled it fetches the latest GitHub release tag and
compares it to the running version LOCALLY — nothing about the deployment is
sent, and the shared :func:`online_client` already uses a version-free
User-Agent. The failure ``detail`` is built only from the exception *type* name,
so no host, URL, or message can leak into the response.
"""

from __future__ import annotations

import logging
from typing import Any

from packaging.version import InvalidVersion, Version

from soc_ai import __version__
from soc_ai.demo.guard import is_demo
from soc_ai.tools.online import online_client

_LOGGER = logging.getLogger(__name__)

REPO_URL = "https://github.com/nuk3s/soc-ai"
LICENSE = "Apache-2.0"
_RELEASES_URL = "https://api.github.com/repos/nuk3s/soc-ai/releases/latest"


def _is_newer(latest: str, current: str) -> bool:
    """True if release ``latest`` is a newer version than ``current`` (semver-aware).

    Raises :class:`InvalidVersion` if ``latest`` is not a PEP 440 / semver tag, so
    the caller can report an inconclusive result rather than a false "up to date".
    """
    return Version(latest) > Version(current)


async def check_for_update(settings: Any) -> dict[str, Any]:
    """Compare the running version against the latest GitHub release.

    Never raises. Off by default (no network I/O). In demo mode returns a clean
    no-egress answer. On any network/parse failure returns a secret-free
    ``ok=False`` result rather than propagating.
    """
    current = __version__
    if not settings.update_check_enabled:
        return {
            "enabled": False,
            "current_version": current,
            "update_available": False,
            "detail": "update check is off (no outbound calls)",
        }
    # Enabled but replaying fixtures: report a clean, no-egress answer rather than
    # letting the demo guard turn a working demo into a "could not reach GitHub".
    if is_demo(settings):
        return {
            "enabled": True,
            "ok": True,
            "current_version": current,
            "latest_version": current,
            "update_available": False,
            "detail": "demo mode — the live deployment checks GitHub for releases",
        }
    try:
        async with online_client(settings) as client:
            resp = await client.get(
                _RELEASES_URL, headers={"Accept": "application/vnd.github+json"}
            )
        resp.raise_for_status()
        tag = str(resp.json().get("tag_name") or "").strip()
        latest = tag[1:] if tag.startswith("v") else tag
        if not latest:
            return {
                "enabled": True,
                "ok": False,
                "current_version": current,
                "update_available": False,
                "detail": "GitHub returned no release tag",
            }
        try:
            available = _is_newer(latest, current)
        except InvalidVersion:
            # A non-semver tag (e.g. 'nightly') can't be compared; report it as
            # inconclusive rather than falsely claiming "up to date".
            return {
                "enabled": True,
                "ok": False,
                "current_version": current,
                "latest_version": latest,
                "update_available": False,
                "detail": f"unrecognized release tag '{latest}'",
            }
        return {
            "enabled": True,
            "ok": True,
            "current_version": current,
            "latest_version": latest,
            "update_available": available,
            "detail": f"update available: {latest}" if available else "up to date",
        }
    except Exception as exc:  # never raise into the caller; never echo the URL/host
        _LOGGER.info("update check failed: %s", type(exc).__name__)
        return {
            "enabled": True,
            "ok": False,
            "current_version": current,
            "update_available": False,
            "detail": f"could not reach GitHub ({type(exc).__name__})",
        }

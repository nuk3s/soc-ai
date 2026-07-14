"""Demo-mode egress refusal. Every outbound-client constructor calls
``assert_egress_allowed`` first, so zero egress holds by construction —
per docs/dev/superpowers/specs/2026-07-12-demo-site-design.md."""

from __future__ import annotations

import ipaddress
import os
from typing import Any
from urllib.parse import urlsplit

_LOOPBACK = {"127.0.0.1", "localhost", "::1"}

# Truthy env spellings for the ambient fallback (mirrors pydantic's bool coercion).
_TRUTHY = {"1", "true", "yes", "on", "t", "y"}


def _demo_on(settings: Any) -> bool:
    """Whether *settings* carries a genuine demo flag.

    Strict ``is True`` on purpose: many call sites accept duck-typed settings
    (``SimpleNamespace``, test Mocks). A ``MagicMock`` auto-creates truthy
    attributes, which must never flip the guard on; the real ``Settings``
    field is a genuine bool (env-only), so ``is True`` is exact for it.
    """
    return getattr(settings, "soc_ai_demo", False) is True


class DemoEgressBlocked(RuntimeError):
    """Demo mode refused to construct an outbound network client."""

    def __init__(self, what: str) -> None:
        super().__init__(f"demo mode: outbound {what} is disabled")


def assert_egress_allowed(settings: Any, what: str) -> None:
    """Raise :class:`DemoEgressBlocked` when the demo flag is set."""
    if _demo_on(settings):
        raise DemoEgressBlocked(what)


def _bare_hostname(host: str) -> str:
    """Extract the bare hostname from a URL, ``host:port``, or bare host.

    Fail-closed: an unparseable value is returned as-is, which won't match the
    loopback set — in demo mode that means BLOCKED, never accidentally allowed.
    """
    value = str(host).strip()
    if not value:
        return value
    # A bare IP literal (incl. IPv6 like ``::1``) must not be split on colons.
    try:
        ipaddress.ip_address(value)
    except ValueError:
        pass
    else:
        return value
    if "://" not in value:
        # Force netloc parsing so ``host:port`` / ``[::1]:9200`` resolve.
        value = "//" + value
    try:
        return urlsplit(value).hostname or str(host)
    except ValueError:
        return str(host)


def assert_loopback_only(settings: Any, host: str, what: str) -> None:
    """Demo mode allows this client only against loopback (the bundled mock)."""
    if not _demo_on(settings):
        return
    bare = _bare_hostname(host)
    try:
        is_loopback_ip = ipaddress.ip_address(bare).is_loopback
    except ValueError:
        is_loopback_ip = False
    if bare not in _LOOPBACK and not is_loopback_ip:
        raise DemoEgressBlocked(f"{what} (non-loopback host {host!r})")


def assert_ambient_egress_allowed(what: str) -> None:
    """:func:`assert_egress_allowed` for call paths with no ``Settings`` in scope.

    Resolves the flag from the cached application settings; when settings are
    not constructible (bare environments, e.g. unit tests driving a refresh
    helper directly), falls back to the raw ``SOC_AI_DEMO`` env var — the flag
    is env-only, so the variable is authoritative either way.
    """
    try:
        from soc_ai.config import get_settings  # noqa: PLC0415 — lazy: config is heavy

        demo = _demo_on(get_settings())
    except Exception:
        demo = os.environ.get("SOC_AI_DEMO", "").strip().lower() in _TRUTHY
    if demo:
        raise DemoEgressBlocked(what)

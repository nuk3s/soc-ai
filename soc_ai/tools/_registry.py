"""Tool registry.

Every tool function in :mod:`soc_ai.tools` is decorated with :func:`tool` to
register metadata (name, read/write classification, description). The agent
orchestrator reads the registry to know which tools to expose to the LLM.

Read tools (``read_only=True``) auto-execute - they're considered safe enough
to invoke without a human in the loop. Write tools (``read_only=False``) only
run through :func:`soc_ai.tools.write_exec.execute_write_tool` — the pipeline
recommends them in the report and the analyst executes them on demand via the
actions API.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any, TypeVar

_F = TypeVar("_F", bound=Callable[..., Awaitable[Any]])


@dataclass(frozen=True)
class ToolSpec:
    """Registered metadata for one tool."""

    name: str
    read_only: bool
    description: str
    func: Callable[..., Awaitable[Any]]


_REGISTRY: dict[str, ToolSpec] = {}


def tool(
    *,
    read_only: bool,
    description: str = "",
) -> Callable[[_F], _F]:
    """Decorator that registers ``func`` in the global tool registry.

    Returns the wrapped function with its original type signature preserved
    so callers (and mypy) keep the function's typed return value.
    """

    def decorator(func: _F) -> _F:
        desc = description or _first_doc_line(func)
        _REGISTRY[func.__name__] = ToolSpec(
            name=func.__name__,
            read_only=read_only,
            description=desc,
            func=func,
        )
        return func

    return decorator


def _first_doc_line(func: Callable[..., Any]) -> str:
    doc = (func.__doc__ or "").strip()
    return doc.splitlines()[0] if doc else ""


def get_tool(name: str) -> ToolSpec:
    """Return the :class:`ToolSpec` for ``name``. Raises ``KeyError`` if missing."""
    if name not in _REGISTRY:
        raise KeyError(f"tool not registered: {name}")
    return _REGISTRY[name]


def list_tools(*, only_read_only: bool = False) -> list[ToolSpec]:
    """Return all registered tools, optionally restricted to read-only ones."""
    return [s for s in _REGISTRY.values() if not only_read_only or s.read_only]


def clear_registry_for_tests() -> None:
    """Test-only: wipe the registry so tests don't leak state between modules."""
    _REGISTRY.clear()

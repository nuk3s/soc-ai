"""Tool registry and approval-gate state.

Every tool function in :mod:`soc_ai.tools` is decorated with :func:`tool` to
register metadata (name, read/write classification, description). The agent
orchestrator (step 6) reads the registry to know which tools to expose to the
LLM, and uses :class:`ApprovalGate` to gate write tools behind explicit user
approval surfaced via SSE.

Read tools (``read_only=True``) auto-approve - they're considered safe enough
to invoke without a human in the loop. Write tools (``read_only=False``) MUST
go through :class:`ApprovalGate` before the underlying function is invoked.
"""

from __future__ import annotations

import asyncio
import secrets
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any, TypeVar

from soc_ai.errors import ApprovalRejected, ApprovalRequired

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


# =====================================================================
# ApprovalGate
# =====================================================================


_PENDING = "pending"
_APPROVED = "approved"
_REJECTED = "rejected"
_CONSUMED = "consumed"


@dataclass
class PendingApproval:
    """One pending write-tool call awaiting (or already past) user decision."""

    tool_name: str
    tool_args: dict[str, Any]
    token: str
    state: str = _PENDING
    reason: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


class ApprovalGate:
    """In-memory tracking of pending/approved/rejected write-tool calls.

    Lifecycle:

    1. The orchestrator calls :meth:`request` to mint a token for a pending
       write-tool invocation; surfaces the token over SSE; raises
       :class:`ApprovalRequired`.
    2. The user POSTs ``/approve {token, decision}``; the route handler calls
       :meth:`decide`.
    3. The orchestrator resumes by calling :meth:`consume` which atomically
       transitions the request to ``consumed`` (single-execution guarantee
       even on duplicate ``/approve`` retries) and returns the
       :class:`PendingApproval` so the caller can execute the tool function.

    Thread-safe via an :class:`asyncio.Lock`.
    """

    def __init__(self) -> None:
        self._items: dict[str, PendingApproval] = {}
        self._lock = asyncio.Lock()

    async def request(
        self,
        tool_name: str,
        tool_args: dict[str, Any],
        *,
        metadata: dict[str, Any] | None = None,
    ) -> str:
        """Register a pending approval and return its token."""
        async with self._lock:
            token = secrets.token_urlsafe(16)
            self._items[token] = PendingApproval(
                tool_name=tool_name,
                tool_args=dict(tool_args),
                token=token,
                metadata=dict(metadata or {}),
            )
            return token

    async def decide(
        self,
        token: str,
        approved: bool,
        *,
        reason: str | None = None,
    ) -> None:
        """Record the user's approval decision. Idempotent on repeat calls."""
        async with self._lock:
            req = self._items.get(token)
            if req is None:
                raise KeyError(f"unknown approval token: {token}")
            if req.state in (_APPROVED, _REJECTED, _CONSUMED):
                # Idempotent: ignore repeated decisions
                return
            req.state = _APPROVED if approved else _REJECTED
            req.reason = reason

    async def consume(self, token: str) -> PendingApproval:
        """Mark the request consumed and return it for execution.

        Raises :class:`ApprovalRequired` if still pending,
        :class:`ApprovalRejected` if rejected or already consumed.
        """
        async with self._lock:
            req = self._items.get(token)
            if req is None:
                raise KeyError(f"unknown approval token: {token}")
            if req.state == _CONSUMED:
                raise ApprovalRejected(req.tool_name, reason="approval already executed")
            if req.state == _REJECTED:
                raise ApprovalRejected(req.tool_name, reason=req.reason)
            if req.state != _APPROVED:
                raise ApprovalRequired(req.tool_name, req.tool_args, token)
            req.state = _CONSUMED
            return req

    async def get(self, token: str) -> PendingApproval | None:
        return self._items.get(token)

    async def pending(self) -> list[PendingApproval]:
        """Return a snapshot of all approvals still awaiting a decision."""
        return [r for r in self._items.values() if r.state == _PENDING]

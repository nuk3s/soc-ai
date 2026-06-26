"""soc-ai error hierarchy.

The API layer in :mod:`soc_ai.api` maps these to HTTP responses; tools and the
agent loop raise them at the boundaries of the trust model.
"""

from __future__ import annotations

from typing import Any


class SocAiError(Exception):
    """Root of the soc-ai error hierarchy."""


class SoApiError(SocAiError):
    """An error returned by the Security Onion HTTP API."""

    def __init__(
        self,
        message: str,
        *,
        status_code: int | None = None,
        url: str | None = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.url = url


class SoAuthError(SoApiError):
    """Authentication to the SO grid failed (bad credentials, expired session)."""


class SoNotFoundError(SoApiError):
    """A requested SO resource (alert, case, detection) does not exist."""


class OqlValidationError(SocAiError):
    """The OQL parser/validator rejected a query before it reached Elasticsearch.

    Carries the offending fragment and a human-readable reason so the agent can
    self-correct in the next turn.
    """

    def __init__(self, message: str, *, fragment: str | None = None) -> None:
        super().__init__(message)
        self.fragment = fragment


class ApprovalRequired(SocAiError):
    """A write tool was called without a matching approval token.

    This is a control-flow signal, not a fault: the orchestrator catches it,
    emits an SSE ``approval_required`` event, and resumes after the user
    POSTs to ``/approve``.
    """

    def __init__(
        self,
        tool_name: str,
        tool_args: dict[str, Any],
        token: str,
    ) -> None:
        super().__init__(f"approval required for {tool_name}")
        self.tool_name = tool_name
        self.tool_args = tool_args
        self.token = token


class ApprovalRejected(SocAiError):
    """The user explicitly rejected a write-tool approval request."""

    def __init__(self, tool_name: str, *, reason: str | None = None) -> None:
        super().__init__(f"user rejected {tool_name}" + (f": {reason}" if reason else ""))
        self.tool_name = tool_name
        self.reason = reason


class ModelError(SocAiError):
    """The LiteLLM gateway / underlying model returned an error or malformed output."""

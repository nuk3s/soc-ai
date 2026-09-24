"""soc-ai error hierarchy.

The API layer in :mod:`soc_ai.api` maps these to HTTP responses; tools and the
agent loop raise them at the boundaries of the trust model.
"""

from __future__ import annotations


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


class ModelError(SocAiError):
    """The LiteLLM gateway / underlying model returned an error or malformed output."""


class SyntheticAnchorError(SocAiError):
    """The alert a run is anchored to is a plant the run's own scope hides.

    Raised at the anchor fetch, before any pivot runs, because everything the
    run would gather about that alert is already excluded by the same guard.
    Continuing does not produce a weakly-evidenced answer; it produces a
    confident one built out of zeros the guard created. Measured on the range:
    fifteen tool calls, no results from any of them, an explicit statement that
    the account's purpose could not be independently verified, and a verdict of
    false positive at 0.60 on a critical detection whose group also held three
    genuine events.

    Deliberately not a :class:`SoNotFoundError`. The document exists and the
    grid can read it; this run cannot, and those are different sentences to
    whoever reads the run afterwards.
    """

    def __init__(self, message: str, *, alert_id: str, scenario_id: str) -> None:
        super().__init__(message)
        self.alert_id = alert_id
        self.scenario_id = scenario_id

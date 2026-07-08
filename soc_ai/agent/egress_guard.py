"""General cloud-egress guard for the ANALYST model path.

When the operator points ``settings.analyst_model`` at a cloud provider, every
payload the triage/hunt/chat agents send to that model — enriched alert
context, composed prompts, and tool results — is a privacy leak unless the
internal identifiers in it are redacted first.  The Oracle second-opinion path
already solved this with a reversible redaction tunnel
(:mod:`soc_ai.oracle.sanitize` / :mod:`soc_ai.oracle.redact`); this module
generalises the same primitives into a guard object the entrypoints can hang
on the :class:`~soc_ai.agent.context.InvestigationContext`.

One :class:`EgressGuard` instance holds ONE
:class:`~soc_ai.oracle.sanitize.Mapping` for its whole lifetime (one
investigation / hunt / chat-turn set), so the same real value always maps to
the same opaque label (``IP_01``, ``HOST_02``, …) across every payload of that
run — the model's cross-references between prompt, tool results, and its own
output stay consistent, and every label in the model's output can be restored
to the real value before storage/display.

Scope boundary (deliberate): the Oracle path keeps its OWN independent
sanitize/residue/desanitize pipeline in :mod:`soc_ai.oracle.client` — do NOT
refactor the oracle code onto this guard.  The Oracle pipeline is
adjudication-shaped (single payload, fail-closed residue sweep, refuse on
leak); this guard is loop-shaped (many payloads, stable labels, reversible at
the tool boundary so the agent loop still works against real Elasticsearch).
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from soc_ai.oracle.identifiers import effective_internal_identifiers
from soc_ai.oracle.sanitize import (
    Mapping,
    Replacement,
    desanitize,
    redaction_replacements,
    redaction_summary,
    sanitize,
    unsafe_residue,
)

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

    from soc_ai.config import Settings

_LOGGER = logging.getLogger(__name__)


class EgressResidueError(Exception):
    """A composed outbound payload still carried internal identifiers.

    Raised by :meth:`EgressGuard.check_or_raise` when fail-closed mode is on and
    the INDEPENDENT :func:`~soc_ai.oracle.sanitize.unsafe_residue` sweep found
    identifiers that survived sanitization on the final outbound string.  The
    orchestrator catches it, refuses to call the analyst model, and lands a
    pipeline-error verdict.

    ``leaked`` holds the human-readable leak descriptions from
    :func:`~soc_ai.oracle.sanitize.unsafe_residue` — used ONLY for the count and
    for local diagnostics.  It MUST NOT be echoed into the persisted report or
    the audit payload (that would leak the very values the block exists to
    protect); callers surface ``len(leaked)`` and the leaked CLASS, never the
    values.
    """

    def __init__(self, leaked: list[str]) -> None:
        self.leaked = leaked
        # The message names only the COUNT — never the values — so an exception
        # string that lands in a log/summary cannot itself become the leak.
        super().__init__(
            f"{len(leaked)} internal identifier(s) survived sanitization on an "
            "analyst-egress payload"
        )


class EgressGuard:
    """Reversible redaction tunnel for one investigation / hunt / chat run.

    Construct once per run (via :meth:`for_settings` in the entrypoints) and
    attach to ``ctx.egress_guard``; every sanitize/desanitize call then shares
    the same :class:`~soc_ai.oracle.sanitize.Mapping`, keeping labels stable
    across the run's payloads.
    """

    def __init__(
        self,
        *,
        extra_hosts: tuple[str, ...],
        extra_suffixes: tuple[str, ...],
        allowlist: tuple[str, ...] = (),
    ) -> None:
        """Args mirror the oracle sanitizer's kwargs (they are threaded verbatim).

        Args:
            extra_hosts: Bare internal hostnames to redact beyond the
                shape/suffix rules (typically the *effective* set — env config
                unioned with DB-discovered identifiers).
            extra_suffixes: Internal DNS suffixes beyond the settings default.
            allowlist: Tokens that must pass through verbatim even if they
                would otherwise be redacted.
        """
        # ONE mapping for the guard's lifetime — label stability across every
        # sanitize/desanitize call of this run is the core invariant.
        self._mapping = Mapping()
        self._extra_hosts = extra_hosts
        self._extra_suffixes = extra_suffixes
        self._allowlist = allowlist

    def sanitize_obj(self, obj: Any) -> Any:
        """Recursively redact internal identifiers in *obj* (str/dict/list/tuple)."""
        return sanitize(
            obj,
            self._mapping,
            allowlist=self._allowlist,
            extra_hosts=self._extra_hosts,
            extra_suffixes=self._extra_suffixes,
        )

    def sanitize_text(self, text: str) -> str:
        """Redact internal identifiers in a single string (prompt/JSON blob)."""
        # sanitize() returns the same type it was given for a str input; the
        # str() is a type-narrowing no-op that keeps the signature honest.
        return str(self.sanitize_obj(text))

    def residue(self, text: str) -> list[str]:
        """Independent leak sweep over a FINAL composed outbound string.

        Delegates to :func:`~soc_ai.oracle.sanitize.unsafe_residue`, which
        re-implements identifier detection from scratch (it does NOT share code
        with :meth:`sanitize_text`) so a bug in the sanitize path cannot blind
        this safety net.  Threads the guard's own host/suffix/allowlist config
        plus the real values learned so far this run.

        Returns the human-readable leak descriptions from ``unsafe_residue`` —
        an EMPTY list means the string is clean.  Callers MUST refuse to
        transmit *text* when the result is non-empty (see
        :meth:`check_or_raise`).
        """
        # ``mapping.reverse`` maps opaque label -> real value, so its VALUES are
        # the real identifiers learned this run; any that still appear verbatim
        # in the composed string are residue (a sanitize miss).
        return unsafe_residue(
            text,
            allowlist=self._allowlist,
            extra_hosts=self._extra_hosts,
            extra_suffixes=self._extra_suffixes,
            known_values=tuple(self._mapping.reverse.values()),
        )

    def check_or_raise(self, text: str, *, fail_closed: bool) -> None:
        """Fail closed on residual identifiers in a composed outbound string.

        When *fail_closed* is False this is a no-op (the current best-effort
        behavior — a sanitize miss still egresses).  When True, run
        :meth:`residue` and raise :class:`EgressResidueError` if it is
        non-empty, carrying the leak list so the caller can block the model call
        and land a pipeline error citing the COUNT (never the values).
        """
        if not fail_closed:
            return
        leaked = self.residue(text)
        if leaked:
            raise EgressResidueError(leaked)

    def desanitize_obj(self, obj: Any) -> Any:
        """Recursively restore opaque labels in *obj* to their real values."""
        return desanitize(obj, self._mapping)

    def redaction_summary(self) -> dict[str, int]:
        """Per-category redaction counts for this guard's lifetime mapping.

        Delegates to :func:`~soc_ai.oracle.sanitize.redaction_summary` — the
        same ``{"IP": 3, "HOST": 1, …}`` shape the Oracle preview reports, and
        equally safe to log/display: counts only, never the redacted values.
        Used by the E5.2 analyst-path redaction preview so its summary chips
        render identically to the Oracle preview's.
        """
        return redaction_summary(self._mapping)

    def redaction_replacements(self) -> list[Replacement]:
        """Every (label ↔ value ↔ category) pair this guard has allocated.

        Read-only view of the lifetime mapping, via
        :func:`~soc_ai.oracle.sanitize.redaction_replacements`.  It DOES carry
        the real values — for the admin-gated redaction previews only (which
        already return the raw original to the same caller); never log it and
        never let it ride an egress payload.
        """
        return redaction_replacements(self._mapping)

    @classmethod
    async def for_settings(
        cls,
        settings: Settings,
        db_sessionmaker: async_sessionmaker[AsyncSession] | None = None,
    ) -> EgressGuard:
        """Build a guard with the deployment's effective internal identifiers.

        Mirrors how the Oracle client threads ``extra_hosts``/``extra_suffixes``:
        when a DB session factory is available, resolve the *effective* set
        (env config unioned with active detected/manual identifiers from the
        ``internal_identifier`` table, minus muted) via
        :func:`~soc_ai.oracle.identifiers.effective_internal_identifiers`.
        Best-effort: on any DB error — or with no session factory at all —
        fall back to the raw ``settings.oracle_extra_hosts`` /
        ``settings.oracle_internal_suffixes`` tuples, so a db-less caller
        (CLI / eval / tests) still gets the env-configured redaction floor.
        """
        hosts: tuple[str, ...] = tuple(settings.oracle_extra_hosts)
        suffixes: tuple[str, ...] = tuple(settings.oracle_internal_suffixes)
        if db_sessionmaker is not None:
            try:
                async with db_sessionmaker() as db:
                    effective = await effective_internal_identifiers(db, settings)
                hosts, suffixes = effective.hosts, effective.suffixes
            except Exception:
                # Never block an investigation on a DB hiccup — the env-config
                # floor still applies (the sanitizer re-adds the reserved
                # suffixes regardless), we just lose the DB-discovered names.
                _LOGGER.warning(
                    "egress_guard: failed to resolve effective internal identifiers; "
                    "falling back to env-config oracle_extra_hosts/oracle_internal_suffixes",
                    exc_info=True,
                )
        return cls(extra_hosts=hosts, extra_suffixes=suffixes)


__all__ = ["EgressGuard", "EgressResidueError"]

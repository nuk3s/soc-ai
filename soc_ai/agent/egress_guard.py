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
from soc_ai.oracle.sanitize import Mapping, desanitize, sanitize

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

    from soc_ai.config import Settings

_LOGGER = logging.getLogger(__name__)


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

    def desanitize_obj(self, obj: Any) -> Any:
        """Recursively restore opaque labels in *obj* to their real values."""
        return desanitize(obj, self._mapping)

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


__all__ = ["EgressGuard"]

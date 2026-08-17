"""Host dossier: durable, system-inferred asset context for the network.

A deterministic, rule-based builder aggregates Elasticsearch per internal host
and writes an *inference lane*; an operator overlay writes a physically separate
*operator lane*. There is no stored "current value" — the resolver computes the
effective value at read time, so an operator override cannot be clobbered by a
rebuild, and the builder keeps observing an overridden field forever (which is
what lets persistent disagreement accumulate and eventually prod the operator).

The package is I/O-free except for :mod:`soc_ai.dossier.observe`:

* :mod:`soc_ai.dossier.types` — the shared dataclasses and field vocabulary
* :mod:`soc_ai.dossier.observe` — the Elasticsearch collector
* :mod:`soc_ai.dossier.infer` — the pure classifier
* :mod:`soc_ai.dossier.resolve` — the pure resolver, the ONLY path to an
  effective value
* :mod:`soc_ai.dossier.prompt` — the investigation-prompt block

Persistence lives in :mod:`soc_ai.store.host_dossier`, the refresh job in
:mod:`soc_ai.enrichment.host_dossier`.
"""

from __future__ import annotations

from soc_ai.dossier.types import (
    DOSSIER_FIELDS,
    PROVENANCE_LADDER,
    STRENGTH_CONFIDENCE,
    DossierField,
    Fact,
    HostObservations,
    ProvenanceSource,
    Strength,
    provenance_rank,
)

__all__ = [
    "DOSSIER_FIELDS",
    "PROVENANCE_LADDER",
    "STRENGTH_CONFIDENCE",
    "DossierField",
    "Fact",
    "HostObservations",
    "ProvenanceSource",
    "Strength",
    "provenance_rank",
]

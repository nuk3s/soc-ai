"""The dossier's read/prod policy defaults — the ONE place each is spelled.

Four numbers govern how a stored dossier field is read and when a standing
disagreement is worth prodding an operator about:

* :data:`DEFAULT_MIN_CONFIDENCE` — the render floor. An inferred value below it
  resolves to "unknown" rather than being asserted (``resolve.below_confidence_floor``).
* :data:`DEFAULT_STALENESS_HOURS` — past this age an inferred value is treated
  as unknown rather than reasserted.
* :data:`DEFAULT_CONFLICT_MIN_OBSERVATIONS` — consecutive disagreeing builds
  before the conflict machine prods.
* :data:`DEFAULT_CONFLICT_PROMPT_INTERVAL_HOURS` — minimum gap between prods
  about one field.

They previously lived as bare literals in three places at once — the resolver,
the store, and the ``Settings`` field defaults — with no import linking them.
That is the ``dossier-policy-triplet`` drift class: a release that tuned the
``Settings`` default left the two mirrored literals behind, so the host page,
``t_host_dossier`` and the summary counts could quietly apply different floors
than the sweep. Spelling each once here and having every consumer read it is the
constant-level version of the fix ``below_confidence_floor`` already made for the
predicate.

Deliberately dependency-free (only the ``__future__`` import): this module sits
below :mod:`soc_ai.config`, :mod:`soc_ai.dossier.resolve` and
:mod:`soc_ai.store.host_dossier`, so all three can read it without a cycle. It
holds values, not behaviour — the render predicate stays in ``resolve``.
"""

from __future__ import annotations

# Floor (0-1) an inferred value must clear to be asserted. The classifier emits
# 0.9 (strong) / 0.5 (weak) / 0.0 (none), so 0.6 admits strong evidence only.
DEFAULT_MIN_CONFIDENCE = 0.6

# Age (hours) past which an inferred value is unknown rather than reasserted.
# Three days = three missed daily sweeps, so one failed run does not blank the
# network but a builder switched off for a week stops feeding week-old facts.
DEFAULT_STALENESS_HOURS = 72

# Consecutive DISAGREEING builds before the system prods the operator that its
# inference still disagrees with their override. One is noise; three is a
# standing signal. The counter resets to zero the moment a build agrees again.
DEFAULT_CONFLICT_MIN_OBSERVATIONS = 3

# Minimum hours between prods about the same field. 336 = 14 days. 0 disables
# prodding entirely; a "keep mine" snooze doubles from here per prompt sent.
DEFAULT_CONFLICT_PROMPT_INTERVAL_HOURS = 336

__all__ = [
    "DEFAULT_CONFLICT_MIN_OBSERVATIONS",
    "DEFAULT_CONFLICT_PROMPT_INTERVAL_HOURS",
    "DEFAULT_MIN_CONFIDENCE",
    "DEFAULT_STALENESS_HOURS",
]

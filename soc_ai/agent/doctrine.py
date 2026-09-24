"""What the hunt catalog knows that a triage run otherwise cannot reach.

The catalog is where per-detection doctrine lives: a spec states, beside its
predicate, whether the thing it detects has a benign population at all. Until
now nothing on the triage path could read that. The decoy gate hard-coded the
one case (``_alert_signals_decoy``); DCSync and AS-REP roasting share the
property and had no gate, and on the range the same real DCSync alert triaged
false_positive one day and true_positive the next, both runs grounded, the
verdict depending on which way the model leaned.

This module is the bridge. It loads the flagged specs once and asks, for a raw
alert document, whether any of them claims it — using the same in-memory
evaluator the coverage gate uses (:mod:`soc_ai.hunting.match`), so the question
"does this alert fall under that spec" has one answer in the whole codebase.

Two shapes of document. Security Onion's Sigma pipeline nests the original
event under an ``event_data`` envelope, and every reader that looked only at
the top level arrived with nothing (the alert queue learned this first). So the
document is tried as-is and then one level down.

Fails open everywhere: an unreadable document, an unloadable catalog, a spec
whose predicate raises on an odd value — all of them answer "no spec claims
this", because a gate that raises takes the investigation down with it.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping
from functools import lru_cache
from typing import Any

from soc_ai.hunting.match import detection_matches
from soc_ai.hunting.spec import CATALOG_DIR, HuntSpec, load_catalog

_LOGGER = logging.getLogger(__name__)

# Where Security Onion's Sigma pipeline puts the original event.
_ENVELOPE_KEY = "event_data"


@lru_cache(maxsize=1)
def no_baseline_specs() -> tuple[HuntSpec, ...]:
    """Every shipped spec that declares ``no_benign_baseline``, loaded once.

    Cached because a triage run consults this on every verdict and the catalog
    is four files that change only with a deploy. ``cache_clear()`` exists for
    tests that patch the loader.
    """
    return tuple(s for s in load_catalog(CATALOG_DIR).values() if s.no_benign_baseline)


def spec_declaring_no_baseline_for(raw: Any) -> HuntSpec | None:
    """The flagged spec whose predicate ``raw`` satisfies, or None.

    ``raw`` is the alert's own ``_source`` (``SoAlert.raw``). The first spec
    to match wins; the catalog has no two flagged specs on the same event code,
    and if it ever does the sweep would surface both, so first-match here is
    consistent with what an operator would already be seeing.
    """
    if not isinstance(raw, Mapping) or not raw:
        return None
    try:
        specs = no_baseline_specs()
    except Exception:
        return None
    candidates: list[Mapping[str, Any]] = [raw]
    envelope = raw.get(_ENVELOPE_KEY)
    if isinstance(envelope, Mapping) and envelope:
        candidates.append(envelope)
    for spec in specs:
        if spec.detection is None:
            # A ``profile`` spec has no document pattern — it reads an entity's
            # baseline, not the alert in hand. It can still be flagged
            # no_benign_baseline, but this gate is about matching the raw
            # document, and there is nothing here to match it against.
            continue
        for doc in candidates:
            try:
                if detection_matches(spec.detection, doc):
                    return spec
            except Exception:
                # A predicate that cannot evaluate this document is not a claim
                # on it. Logged at debug: it is a spec or a document oddity, and
                # a verdict must never be lost to either.
                _LOGGER.debug(
                    "doctrine: %s could not evaluate the document", spec.id, exc_info=True
                )
                continue
    return None


__all__ = ["no_baseline_specs", "spec_declaring_no_baseline_for"]

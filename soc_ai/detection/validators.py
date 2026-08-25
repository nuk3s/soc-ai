"""Deterministic validators for the detection bridge (Task 3).

Two gates that annotate a drafter-produced :class:`SigmaDraft` before an
analyst ever sees it, mirroring
:func:`soc_ai.agent.hunt_gates._validate_hunt_findings`'s never-raise,
``model_copy(update=...)`` convention:

* :func:`validate_sigma_yaml` — parses ``draft.sigma_yaml`` with PyYAML and
  checks the Sigma schema: ``title``/``logsource``/``detection`` with a
  ``condition``, every field named in the detection selections passing the
  SAME OQL field whitelist :func:`soc_ai.so_client.oql.validate_oql` enforces,
  and a ``condition`` that references at least one defined selection. Pure,
  synchronous, never touches the grid.
* :func:`dry_run_detection` — runs ``draft.oql`` as a single would-have-fired
  ``| head 5`` query against the SO grid via
  :func:`soc_ai.tools.query_events.query_events_oql` (the same
  whitelist-validated, injection-proof path every read tool uses), reading
  the hit count, its lower-bound flag, and the sample evidence ids from that
  one response. A rule whose filter matches ALL events is refused before any
  grid call. Fail-soft: a rejected or malformed OQL, or a grid outage, both
  land as ``DryRunResult(ran=False, error=...)`` rather than raising past
  this function.
"""

from __future__ import annotations

import re
from datetime import datetime
from fnmatch import fnmatch
from typing import Any

import yaml

from soc_ai.config import Settings
from soc_ai.detection.models import DryRunResult, SigmaDraft
from soc_ai.so_client.elastic import ElasticClient
from soc_ai.so_client.oql import (
    MatchAll,
    _split_pipe,
    collect_filter_fields,
    get_whitelist,
    parse_oql,
)
from soc_ai.tools.query_events import query_events_oql

_REQUIRED_SIGMA_KEYS = ("title", "logsource", "detection")

# ``detection`` keys that are Sigma directives, not named selections.
_NON_SELECTION_KEYS = frozenset({"condition", "timeframe"})

# Sigma condition grammar words that are never selection names.
_CONDITION_KEYWORDS = frozenset({"and", "or", "not", "of", "all", "any"})

# Would-have-fired window ceiling. query_events_oql's own hard cap is
# _MAX_TIME_RANGE_MINUTES = 43_200 (30 days) — 30 * 1440 lands EXACTLY on
# that ceiling, so 30 is the largest window_days a caller can request without
# the underlying tool call raising. We clamp up front (rather than letting an
# over-cap window_days fall through to query_events_oql's own ValueError and
# get caught by the fail-soft except below) so a slightly-too-large request
# still gets an honest would-have-fired answer over the widest legal window,
# instead of a hard "couldn't run" error that a raw pass-through would give.
_MAX_DRY_RUN_WINDOW_DAYS = 30

# Match-all floor: a drafted rule whose filter matches EVERY event is not a
# detection — refusing to dry-run it saves a pointless full-window grid scan
# and tells the analyst plainly why there is no would-have-fired number.
_MATCH_ALL_ERROR = "rule matches all events — not specific enough to dry-run"

# Model-supplied result-shaping stages the dry run strips before appending its
# own ``| head 5`` (mirrors ``_HEAD_RE`` in soc_ai.so_client.oql).
_HEAD_STAGE_RE = re.compile(r"^(?:head|limit)\s+\d+$", re.IGNORECASE)


def _sigma_selection_fields(selections: dict[str, Any]) -> set[str]:
    """Every field name referenced by the Sigma detection selections.

    A selection value is a mapping of ``field: value`` (or a list of such
    mappings); a list of bare strings is a field-less keyword list and
    contributes nothing. Sigma value modifiers (``field|contains`` etc.) are
    stripped down to the bare field name before whitelist checking.
    """
    fields: set[str] = set()
    for value in selections.values():
        items = value if isinstance(value, list) else [value]
        for item in items:
            if isinstance(item, dict):
                for raw_field in item:
                    fields.add(str(raw_field).split("|", 1)[0])
    return fields


def _condition_references_selection(condition: str, selection_keys: set[str]) -> bool:
    """True iff the Sigma condition names at least one defined selection.

    Understands the common condition grammar: bare selection names joined with
    and/or/not, ``N of <pattern>`` / ``all of <pattern>`` with a trailing-``*``
    glob, and ``... of them`` (which covers every defined selection). The token
    class includes ``-``: a hyphenated selection name (``selection-dns``) is
    legal Sigma and must parse as ONE token, not two.
    """
    for token in re.findall(r"[\w*-]+", condition):
        lowered = token.lower()
        if lowered in _CONDITION_KEYWORDS or token.isdigit():
            continue
        if lowered == "them":
            if selection_keys:
                return True
            continue
        if "*" in token:
            if any(fnmatch(key, token) for key in selection_keys):
                return True
        elif token in selection_keys:
            return True
    return False


def validate_sigma_yaml(draft: SigmaDraft) -> SigmaDraft:
    """Parse the Sigma YAML and check the schema.

    Sets ``schema_ok`` (and, on failure, ``validator_note``). Beyond the
    minimal shape (``title``/``logsource``/``detection`` with a
    ``condition``), every field named in the detection selections must pass
    the same OQL field whitelist :func:`soc_ai.so_client.oql.validate_oql`
    enforces — a rule that queries fields this deployment cannot search would
    never fire — and the ``condition`` must reference at least one selection
    the rule actually defines. Never raises: every failure resolves to
    ``schema_ok=False`` with a human-readable note, leaving the rest of
    ``draft`` intact.
    """
    try:
        doc = yaml.safe_load(draft.sigma_yaml)
    except yaml.YAMLError as e:
        return draft.model_copy(
            update={"schema_ok": False, "validator_note": f"Sigma YAML did not parse: {e}"}
        )

    if not isinstance(doc, dict) or any(key not in doc for key in _REQUIRED_SIGMA_KEYS):
        return draft.model_copy(
            update={
                "schema_ok": False,
                "validator_note": ("Sigma rule missing required keys (title/logsource/detection)."),
            }
        )

    detection = doc.get("detection")
    condition = detection.get("condition") if isinstance(detection, dict) else None
    if not condition or not isinstance(detection, dict):
        return draft.model_copy(
            update={"schema_ok": False, "validator_note": "Sigma detection has no condition."}
        )

    selections = {
        str(key): value for key, value in detection.items() if str(key) not in _NON_SELECTION_KEYS
    }

    whitelist = get_whitelist()
    unknown_fields = sorted(
        field for field in _sigma_selection_fields(selections) if not whitelist.is_allowed(field)
    )
    if unknown_fields:
        return draft.model_copy(
            update={
                "schema_ok": False,
                "validator_note": (
                    "Sigma rule uses fields that are not searchable on this "
                    f"deployment: {', '.join(unknown_fields)}."
                ),
            }
        )

    if not _condition_references_selection(str(condition), set(selections)):
        return draft.model_copy(
            update={
                "schema_ok": False,
                "validator_note": (
                    "Sigma condition does not match any selection defined in the rule."
                ),
            }
        )

    return draft.model_copy(update={"schema_ok": True})


def _strip_result_stages(oql: str) -> str:
    """Drop model-supplied ``count``/``head`` pipe stages from a drafted OQL.

    The dry run appends its own ``| head 5``; a drafter-emitted ``| count``
    (despite the schema telling it not to) or ``| head N`` would otherwise
    turn the single sample query into a zero-hit count or a repeated-stage
    validation reject. Splits on top-level pipes only (a ``|`` inside a
    quoted value is preserved), so quoted values survive intact.
    """
    parts = _split_pipe(oql)
    kept = [parts[0].strip()]
    for stage in parts[1:]:
        stripped = stage.strip()
        if stripped.lower() == "count" or _HEAD_STAGE_RE.match(stripped):
            continue
        kept.append(stripped)
    return " | ".join(part for part in kept if part)


async def dry_run_detection(
    draft: SigmaDraft,
    *,
    elastic: ElasticClient,
    settings: Settings,
    window_days: int = 30,
    time_anchor: datetime | None = None,
) -> SigmaDraft:
    """Run ``draft.oql`` as a single would-have-fired query over the grid.

    One ``{oql} | head 5`` query answers everything at once: ``hit_count``
    comes from the response's ``total`` (exact up to Elasticsearch's 10 000
    track-total-hits ceiling, the same ceiling the OQL ``| count`` stage
    pins explicitly), ``total_is_lower_bound`` from its ``gte`` relation, and
    ``sample_ids`` from the returned hits — no second serial round trip. Any
    model-supplied ``| count`` / ``| head`` stage is stripped first.

    Reuses :func:`query_events_oql` — the same whitelist-validated,
    injection-proof path every other read tool uses — so a drafted OQL
    referencing a forbidden/unwhitelisted field fails the SAME way an agent's
    live query would; the OQL field whitelist is the injection boundary and
    this function never bypasses it.

    A rule whose filter parses to match-all (or contains no field term at
    all) is refused WITHOUT querying: it would "fire" on every event in the
    window, which is a specificity problem, not a would-have-fired answer.

    Fail-soft: any exception while resolving the query (bad OQL, whitelist
    rejection, grid outage) is caught and reported as
    ``DryRunResult(ran=False, error=...)`` rather than propagating.

    ``window_days`` is clamped to ``[1, _MAX_DRY_RUN_WINDOW_DAYS]`` up front
    (see the module docstring) — a caller-supplied window over 30 days
    silently runs at 30 rather than erroring.
    """
    window_days = max(1, min(window_days, _MAX_DRY_RUN_WINDOW_DAYS))

    def _not_run(error: str) -> SigmaDraft:
        return draft.model_copy(
            update={"dry_run": DryRunResult(ran=False, window_days=window_days, error=error[:200])}
        )

    oql = _strip_result_stages(draft.oql.strip())
    if not oql:
        return _not_run(_MATCH_ALL_ERROR)

    try:
        ast = parse_oql(oql)
    except Exception as e:
        return _not_run(str(e))
    if isinstance(ast.filter_, MatchAll) or not collect_filter_fields(ast.filter_):
        return _not_run(_MATCH_ALL_ERROR)

    try:
        res = await query_events_oql(
            f"{oql} | head 5",
            elastic=elastic,
            settings=settings,
            time_range_minutes=window_days * 1440,
            time_anchor=time_anchor,
        )
    except Exception as e:
        return _not_run(str(e))

    sample_ids = [str(hit["_id"]) for hit in res.hits[:5] if isinstance(hit, dict) and "_id" in hit]
    return draft.model_copy(
        update={
            "dry_run": DryRunResult(
                ran=True,
                hit_count=res.total,
                total_is_lower_bound=res.total_is_lower_bound,
                sample_ids=sample_ids,
                window_days=window_days,
            )
        }
    )

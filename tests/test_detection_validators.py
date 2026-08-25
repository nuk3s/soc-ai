"""Tests for the deterministic detection-bridge validators
(:mod:`soc_ai.detection.validators`).

Two gates under test, mirroring ``tests/test_hunt_gates.py``'s
never-raise/``model_copy`` conventions:

* :func:`validate_sigma_yaml` — pure, synchronous, no ES. Malformed YAML,
  missing required Sigma keys, a missing ``condition``, a selection field
  outside the OQL field whitelist, and a condition naming an undefined
  selection all resolve to ``schema_ok=False`` + a note rather than raising.
* :func:`dry_run_detection` — the single would-have-fired ``| head 5`` query
  (count + lower-bound flag + sample ids from ONE response), built on the
  SAME :func:`soc_ai.tools.query_events.query_events_oql` path every read
  tool uses. Most cases patch ``query_events_oql`` directly (typed
  ``EsSearchResult`` in, no real ES); the whitelist-rejection case
  (``test_dry_run_detection_whitelist_rejected_oql_fails_soft``) deliberately
  does NOT patch it, instead driving the REAL ``query_events_oql`` — and
  therefore the real ``validate_oql`` — against a mocked
  :class:`~soc_ai.so_client.elastic.ElasticClient` (patched at the raw
  ``AsyncElasticsearch`` level, ``test_tools_read.py``'s convention), so the
  injection boundary is proven to hold for a MODEL-drafted OQL, not just
  asserted. The match-all floor is proven to refuse over-broad rules BEFORE
  any grid call.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest
from soc_ai.config import Settings
from soc_ai.detection.models import SigmaDraft
from soc_ai.detection.validators import dry_run_detection, validate_sigma_yaml
from soc_ai.so_client.elastic import ElasticClient, EsSearchResult

_QUERY_EVENTS_OQL = "soc_ai.detection.validators.query_events_oql"


def _draft(**overrides: object) -> SigmaDraft:
    fields: dict[str, object] = {
        "title": "Zerologon NetrServerAuthenticate3 anomaly",
        "sigma_yaml": (
            "title: Zerologon NetrServerAuthenticate3 anomaly\n"
            "logsource:\n"
            "  category: dce_rpc\n"
            "detection:\n"
            "  selection:\n"
            "    zeek.dce_rpc.operation: NetrServerAuthenticate3\n"
            "  condition: selection\n"
        ),
        "oql": "event.dataset:zeek.dce_rpc AND zeek.dce_rpc.operation:NetrServerAuthenticate3",
        "rationale": (
            "The finding's citations show repeated NetrServerAuthenticate3 calls from "
            "a single source host, the Zerologon authentication-bypass pattern."
        ),
    }
    fields.update(overrides)
    return SigmaDraft(**fields)  # type: ignore[arg-type]


def _es_result(
    total: int,
    hits: list[dict[str, object]] | None = None,
    *,
    total_is_lower_bound: bool = False,
) -> EsSearchResult:
    return EsSearchResult(
        total=total,
        took_ms=3,
        hits=hits or [],
        total_is_lower_bound=total_is_lower_bound,
    )


def _make_elastic(settings: Settings) -> tuple[ElasticClient, AsyncMock]:
    """A real :class:`ElasticClient` backed by a mocked ``AsyncElasticsearch``.

    Unlike the other tests here (which patch ``query_events_oql`` directly),
    this builds a real client so the real ``query_events_oql`` — and its
    ``validate_oql`` whitelist check — actually runs. Mirrors
    ``test_tools_read.py``'s ``_make_elastic``.
    """
    fake_es = AsyncMock()
    with patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=fake_es):
        client = ElasticClient(settings)
    return client, fake_es


# ── validate_sigma_yaml: pure, no ES ────────────────────────────────────────


def test_validate_sigma_yaml_valid_sets_schema_ok_true() -> None:
    draft = _draft()
    validated = validate_sigma_yaml(draft)
    assert validated.schema_ok is True
    assert validated.validator_note is None
    # The rest of the draft is untouched.
    assert validated.title == draft.title
    assert validated.oql == draft.oql


def test_validate_sigma_yaml_malformed_yaml_sets_schema_ok_false() -> None:
    draft = _draft(sigma_yaml="title: [unclosed")
    validated = validate_sigma_yaml(draft)
    assert validated.schema_ok is False
    assert validated.validator_note is not None
    assert "parse" in validated.validator_note.lower()


def test_validate_sigma_yaml_missing_logsource_sets_schema_ok_false() -> None:
    draft = _draft(
        sigma_yaml=("title: foo\ndetection:\n  selection:\n    x: y\n  condition: selection\n")
    )
    validated = validate_sigma_yaml(draft)
    assert validated.schema_ok is False
    assert validated.validator_note is not None
    assert "required keys" in validated.validator_note.lower()


def test_validate_sigma_yaml_detection_without_condition_sets_schema_ok_false() -> None:
    draft = _draft(
        sigma_yaml=(
            "title: foo\nlogsource:\n  category: dce_rpc\ndetection:\n  selection:\n    x: y\n"
        )
    )
    validated = validate_sigma_yaml(draft)
    assert validated.schema_ok is False
    assert validated.validator_note is not None
    assert "condition" in validated.validator_note.lower()


def test_validate_sigma_yaml_non_mapping_document_sets_schema_ok_false() -> None:
    """A YAML doc that parses but isn't a mapping (e.g. a bare list/scalar)
    hits the same 'missing required keys' branch as a dict lacking them."""
    draft = _draft(sigma_yaml="- just\n- a\n- list\n")
    validated = validate_sigma_yaml(draft)
    assert validated.schema_ok is False
    assert validated.validator_note is not None


def test_validate_sigma_yaml_non_whitelisted_field_sets_schema_ok_false() -> None:
    """A selection field outside the OQL field whitelist fails schema
    validation — the drafted rule could never fire on this deployment."""
    draft = _draft(
        sigma_yaml=(
            "title: Raw-source probe\n"
            "logsource:\n"
            "  category: dce_rpc\n"
            "detection:\n"
            "  selection:\n"
            "    dce_rpc.operation: NetrServerAuthenticate3\n"
            "  condition: selection\n"
        )
    )
    validated = validate_sigma_yaml(draft)
    assert validated.schema_ok is False
    assert validated.validator_note is not None
    assert "dce_rpc.operation" in validated.validator_note
    assert "not searchable" in validated.validator_note


def test_validate_sigma_yaml_field_modifier_is_stripped_before_whitelist() -> None:
    """A Sigma value modifier (``field|contains``) checks the BARE field name
    against the whitelist, so a legitimate field with a modifier passes."""
    draft = _draft(
        sigma_yaml=(
            "title: foo\n"
            "logsource:\n"
            "  category: dce_rpc\n"
            "detection:\n"
            "  selection:\n"
            "    zeek.dce_rpc.operation|contains: NetrServer\n"
            "  condition: selection\n"
        )
    )
    validated = validate_sigma_yaml(draft)
    assert validated.schema_ok is True


def test_validate_sigma_yaml_condition_naming_missing_selection_fails() -> None:
    """A condition that references a selection the rule never defines is a
    broken rule — schema_ok False with an analyst-readable note."""
    draft = _draft(
        sigma_yaml=(
            "title: foo\n"
            "logsource:\n"
            "  category: dce_rpc\n"
            "detection:\n"
            "  selection:\n"
            "    zeek.dce_rpc.operation: NetrServerAuthenticate3\n"
            "  condition: selection_typo\n"
        )
    )
    validated = validate_sigma_yaml(draft)
    assert validated.schema_ok is False
    assert validated.validator_note is not None
    assert "condition" in validated.validator_note.lower()


def test_validate_sigma_yaml_condition_glob_and_of_forms_pass() -> None:
    """``1 of selection*`` matches the defined ``selection_auth`` key — the
    common Sigma condition grammar is understood, not just bare names."""
    draft = _draft(
        sigma_yaml=(
            "title: foo\n"
            "logsource:\n"
            "  category: dce_rpc\n"
            "detection:\n"
            "  selection_auth:\n"
            "    zeek.dce_rpc.operation: NetrServerAuthenticate3\n"
            "  condition: 1 of selection*\n"
        )
    )
    validated = validate_sigma_yaml(draft)
    assert validated.schema_ok is True


def test_validate_sigma_yaml_hyphenated_selection_name_passes() -> None:
    """A legal hyphenated selection name (``selection-dns``) must parse as ONE
    condition token — the old ``[\\w*]+`` token class split it in two and
    false-failed the condition check."""
    draft = _draft(
        sigma_yaml=(
            "title: foo\n"
            "logsource:\n"
            "  category: dce_rpc\n"
            "detection:\n"
            "  selection-dns:\n"
            "    zeek.dce_rpc.operation: NetrServerAuthenticate3\n"
            "  condition: selection-dns\n"
        )
    )
    validated = validate_sigma_yaml(draft)
    assert validated.schema_ok is True
    assert validated.validator_note is None


def test_validate_sigma_yaml_never_raises_on_weird_detection_shapes() -> None:
    """Scalar selections, keyword lists, and non-string keys must not raise —
    the gate is fail-closed on schema_ok, never an exception."""
    draft = _draft(
        sigma_yaml=(
            "title: foo\n"
            "logsource:\n"
            "  category: dce_rpc\n"
            "detection:\n"
            "  keywords:\n"
            "    - some-bare-keyword\n"
            "  selection: 42\n"
            "  condition: keywords\n"
        )
    )
    validated = validate_sigma_yaml(draft)
    assert validated.schema_ok in (True, False)


# ── dry_run_detection: single would-have-fired query ────────────────────────


async def test_dry_run_detection_single_query_counts_and_samples(
    settings_kratos: Settings,
) -> None:
    elastic = AsyncMock(spec=ElasticClient)
    head_hits = [{"_id": f"e{i}", "_source": {}} for i in range(3)]
    mock_query = AsyncMock(return_value=_es_result(4, hits=head_hits, total_is_lower_bound=True))

    with patch(_QUERY_EVENTS_OQL, mock_query):
        draft = _draft(oql="event.dataset:zeek.dce_rpc")
        result = await dry_run_detection(draft, elastic=elastic, settings=settings_kratos)

    assert result.dry_run is not None
    assert result.dry_run.ran is True
    assert result.dry_run.hit_count == 4
    assert result.dry_run.total_is_lower_bound is True
    assert result.dry_run.sample_ids == ["e0", "e1", "e2"]
    assert result.dry_run.window_days == 30
    assert result.dry_run.error is None
    # Rest of the draft untouched.
    assert result.title == draft.title

    # ONE query — count, lower-bound flag, and sample ids all come from the
    # single `| head 5` response; no serial second round trip.
    assert mock_query.await_count == 1
    assert mock_query.call_args.args[0] == "event.dataset:zeek.dce_rpc | head 5"


async def test_dry_run_detection_model_supplied_count_is_stripped(
    settings_kratos: Settings,
) -> None:
    elastic = AsyncMock(spec=ElasticClient)
    mock_query = AsyncMock(return_value=_es_result(1))

    with patch(_QUERY_EVENTS_OQL, mock_query):
        draft = _draft(oql="event.dataset:zeek.dce_rpc | count")
        result = await dry_run_detection(draft, elastic=elastic, settings=settings_kratos)

    assert result.dry_run is not None
    assert result.dry_run.ran is True
    assert mock_query.await_count == 1
    query = mock_query.call_args.args[0]
    assert query == "event.dataset:zeek.dce_rpc | head 5"
    assert "count" not in query


async def test_dry_run_detection_model_supplied_head_is_replaced(
    settings_kratos: Settings,
) -> None:
    """A drafter-emitted `| head N` is stripped so the appended `| head 5`
    doesn't trip the repeated-stage validator."""
    elastic = AsyncMock(spec=ElasticClient)
    mock_query = AsyncMock(return_value=_es_result(1))

    with patch(_QUERY_EVENTS_OQL, mock_query):
        draft = _draft(oql="event.dataset:zeek.dce_rpc | head 50")
        result = await dry_run_detection(draft, elastic=elastic, settings=settings_kratos)

    assert result.dry_run is not None
    assert result.dry_run.ran is True
    assert mock_query.call_args.args[0] == "event.dataset:zeek.dce_rpc | head 5"


async def test_dry_run_detection_sample_ids_capped_at_five(settings_kratos: Settings) -> None:
    elastic = AsyncMock(spec=ElasticClient)
    head_hits = [{"_id": f"e{i}", "_source": {}} for i in range(8)]
    mock_query = AsyncMock(return_value=_es_result(8, hits=head_hits))

    with patch(_QUERY_EVENTS_OQL, mock_query):
        draft = _draft()
        result = await dry_run_detection(draft, elastic=elastic, settings=settings_kratos)

    assert result.dry_run is not None
    assert len(result.dry_run.sample_ids) == 5


@pytest.mark.parametrize("oql", ["", "*", "* | count", "| count"])
async def test_dry_run_detection_match_all_oql_refused_without_querying(
    settings_kratos: Settings, oql: str
) -> None:
    """A rule whose filter matches EVERY event gets no would-have-fired
    number — it is refused up front, before any grid call."""
    elastic = AsyncMock(spec=ElasticClient)
    mock_query = AsyncMock()

    with patch(_QUERY_EVENTS_OQL, mock_query):
        draft = _draft(oql=oql)
        result = await dry_run_detection(draft, elastic=elastic, settings=settings_kratos)

    assert result.dry_run is not None
    assert result.dry_run.ran is False
    assert result.dry_run.error is not None
    assert "matches all events" in result.dry_run.error
    mock_query.assert_not_awaited()


async def test_dry_run_detection_whitelist_rejected_oql_fails_soft(
    settings_kratos: Settings,
) -> None:
    """A forbidden field in the drafted OQL is rejected by the REAL
    validate_oql (inside the REAL query_events_oql, not a mock) — the
    injection boundary holds for a model-drafted rule too."""
    elastic, fake_es = _make_elastic(settings_kratos)
    draft = _draft(oql="_source:foo")

    result = await dry_run_detection(draft, elastic=elastic, settings=settings_kratos)

    assert result.dry_run is not None
    assert result.dry_run.ran is False
    assert result.dry_run.error is not None
    assert "forbidden" in result.dry_run.error.lower()
    # Never reached ES — validate_oql raises before dispatch.
    fake_es.search.assert_not_called()


async def test_dry_run_detection_grid_exception_fails_soft(settings_kratos: Settings) -> None:
    elastic = AsyncMock(spec=ElasticClient)
    mock_query = AsyncMock(side_effect=RuntimeError("es unreachable"))

    with patch(_QUERY_EVENTS_OQL, mock_query):
        draft = _draft()
        result = await dry_run_detection(draft, elastic=elastic, settings=settings_kratos)

    assert result.dry_run is not None
    assert result.dry_run.ran is False
    assert result.dry_run.error is not None
    assert "es unreachable" in result.dry_run.error
    assert result.dry_run.hit_count == 0


async def test_dry_run_detection_window_days_over_thirty_is_clamped(
    settings_kratos: Settings,
) -> None:
    """window_days > 30 is clamped to the tool's own 30-day ceiling
    (_MAX_TIME_RANGE_MINUTES = 43_200 = 30 * 1440) rather than raising."""
    elastic = AsyncMock(spec=ElasticClient)
    mock_query = AsyncMock(return_value=_es_result(2))

    with patch(_QUERY_EVENTS_OQL, mock_query):
        draft = _draft()
        result = await dry_run_detection(
            draft, elastic=elastic, settings=settings_kratos, window_days=90
        )

    assert result.dry_run is not None
    assert result.dry_run.ran is True
    assert result.dry_run.window_days == 30
    called_kwargs = mock_query.call_args.kwargs
    assert called_kwargs["time_range_minutes"] == 30 * 1440

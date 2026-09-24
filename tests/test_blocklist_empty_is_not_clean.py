"""An empty feed read as a clean answer, everywhere it was rendered.

The blocklist feeds have never been refreshed on either deployment and the data
directory does not exist. ``BlocklistDB.from_dir`` loads nothing, every
``lookup_ip`` returns an empty list, and the one signal that anything is wrong is
a warning in the process log. The enrichment result carried no field saying so,
so "we checked and found nothing" and "we could not check" were the same object.
The timeline rendered that object as "no blocklist/MISP match" and three triages
leaned on the phrasing to support a false positive.

The distinction now travels on the result itself. ``blocklist_sources`` names the
feeds that answered a lookup, and ``blocklist_checked`` reads it back as three
states rather than two, because there are three:

    None   the result does not say. Records written before the field existed,
           and hand-built contexts. Nothing may be concluded either way.
    False  a lookup ran against a database with nothing loaded. An empty hit
           list is an absence of data.
    True   these feeds answered. An empty hit list is a clean result, as far as
           they reach.

Collapsing the first two would have relabelled every archived enrichment as
unchecked, which is its own false statement.
"""

from __future__ import annotations

from typing import Any

import pytest
from soc_ai.api.webui._timeline import _tool_outcome
from soc_ai.config import Settings
from soc_ai.enrichment.blocklists import BlocklistDB, BlocklistHit
from soc_ai.tools.enrichment import enrich_domain, enrich_hash, enrich_ip

EXTERNAL = "203.0.113.10"


def _empty_db() -> BlocklistDB:
    """What a deployment that never ran `soc-ai blocklists refresh` has."""
    return BlocklistDB()


def _loaded_db(*, hit: bool = False) -> BlocklistDB:
    db = BlocklistDB(loaded_sources=["urlhaus", "tor"])
    if hit:
        db.ips[EXTERNAL] = [
            BlocklistHit(
                indicator=EXTERNAL,
                indicator_type="ip",
                source="abuse.ch URLhaus",
                tags=("malware",),
            )
        ]
    return db


# ---------------------------------------------------------------------------
# The result carries the distinction
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_an_unloaded_feed_is_not_a_clean_lookup(settings_kratos: Settings) -> None:
    e = await enrich_ip(EXTERNAL, settings=settings_kratos, blocklist=_empty_db())
    assert e.blocklist_hits == []
    assert e.blocklist_sources == []
    assert e.blocklist_checked is False
    assert any("blocklist" in err and "no sources loaded" in err for err in e.errors), e.errors


@pytest.mark.asyncio
async def test_a_loaded_feed_with_no_hit_is_a_clean_lookup(settings_kratos: Settings) -> None:
    """Negative control. The marker must mean "not checked", not "no hits".

    Without this the fix could pass by marking every miss as unchecked, which
    destroys the signal it was built to preserve.
    """
    e = await enrich_ip(EXTERNAL, settings=settings_kratos, blocklist=_loaded_db())
    assert e.blocklist_hits == []
    assert e.blocklist_sources == ["urlhaus", "tor"]
    assert e.blocklist_checked is True
    assert not any("no sources loaded" in err for err in e.errors)


@pytest.mark.asyncio
async def test_a_hit_still_comes_back_as_a_hit(settings_kratos: Settings) -> None:
    e = await enrich_ip(EXTERNAL, settings=settings_kratos, blocklist=_loaded_db(hit=True))
    assert [h.source for h in e.blocklist_hits] == ["abuse.ch URLhaus"]
    assert e.blocklist_checked is True


@pytest.mark.asyncio
async def test_no_blocklist_at_all_is_also_unchecked(settings_kratos: Settings) -> None:
    """A caller that passed no database checked nothing either."""
    e = await enrich_ip(EXTERNAL, settings=settings_kratos, blocklist=None)
    assert e.blocklist_checked is False


@pytest.mark.asyncio
async def test_the_domain_lookup_carries_it_too(settings_kratos: Settings) -> None:
    unchecked = await enrich_domain("example.test", settings=settings_kratos, blocklist=_empty_db())
    checked = await enrich_domain("example.test", settings=settings_kratos, blocklist=_loaded_db())
    assert unchecked.blocklist_checked is False
    assert checked.blocklist_checked is True


@pytest.mark.asyncio
async def test_the_hash_lookup_carries_it_too(settings_kratos: Settings) -> None:
    digest = "a" * 64
    unchecked = await enrich_hash(digest, "sha256", settings=settings_kratos, blocklist=_empty_db())
    checked = await enrich_hash(digest, "sha256", settings=settings_kratos, blocklist=_loaded_db())
    assert unchecked.blocklist_checked is False
    assert checked.blocklist_checked is True


def test_a_context_nobody_recorded_says_nothing_either_way() -> None:
    """The third state. A hand-built or archived enrichment made no claim, and
    the fix must not put one in its mouth."""
    from soc_ai.tools.enrichment import IndicatorEnrichment

    e = IndicatorEnrichment(indicator=EXTERNAL, indicator_type="ip")
    assert e.blocklist_sources is None
    assert e.blocklist_checked is None


@pytest.mark.asyncio
async def test_the_marker_survives_the_dump_the_model_reads(settings_kratos: Settings) -> None:
    """The model sees the tool result as JSON, so the distinction has to serialise."""
    e = await enrich_ip(EXTERNAL, settings=settings_kratos, blocklist=_empty_db())
    dumped = e.model_dump(mode="json")
    assert dumped["blocklist_checked"] is False
    assert dumped["blocklist_sources"] == []


# ---------------------------------------------------------------------------
# The renderers
# ---------------------------------------------------------------------------


def _enrich_result(**over: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "indicator": EXTERNAL,
        "indicator_type": "ip",
        "internal": False,
        "blocklist_hits": [],
        "misp_hits": [],
        "blocklist_sources": ["urlhaus"],
        "blocklist_checked": True,
    }
    base.update(over)
    return base


def test_the_timeline_does_not_call_an_unchecked_indicator_a_miss() -> None:
    label = _tool_outcome(_enrich_result(blocklist_sources=[], blocklist_checked=False))
    assert "no blocklist/MISP match" not in label
    assert "no blocklist loaded" in label


def test_the_timeline_still_reports_a_real_miss_as_a_miss() -> None:
    """Negative control on the label."""
    assert _tool_outcome(_enrich_result()) == "no blocklist/MISP match"


def test_the_timeline_still_reports_a_hit() -> None:
    label = _tool_outcome(
        _enrich_result(blocklist_hits=[{"source": "abuse.ch URLhaus"}]),
    )
    assert label.startswith("flagged malicious")


def test_an_internal_address_says_the_feed_state_too() -> None:
    """The curated internal-seed feed is the one that names known-bad internal
    hosts, so "internal" does not excuse an unloaded blocklist."""
    label = _tool_outcome(
        _enrich_result(internal=True, blocklist_sources=[], blocklist_checked=False)
    )
    assert "internal address" in label
    assert "no blocklist loaded" in label


def test_an_internal_address_with_loaded_feeds_is_unchanged() -> None:
    assert _tool_outcome(_enrich_result(internal=True)) == "internal address"


def test_a_result_from_before_the_marker_existed_is_rendered_as_it_was() -> None:
    """Stored investigations predate the field. Absent means "we do not know",
    and re-labelling every archived enrichment as unchecked would be its own
    false statement."""
    old = _enrich_result()
    del old["blocklist_sources"]
    del old["blocklist_checked"]
    assert _tool_outcome(old) == "no blocklist/MISP match"


def test_the_entity_graph_says_its_nodes_were_never_checked() -> None:
    """An unflagged node is not a cleared node. The node shapes carry no third
    state, so the graph note has to carry it."""
    from types import SimpleNamespace

    from soc_ai.api.webui._timeline import _entity_graph

    alert = {"source_ip": "10.0.0.1", "destination_ip": EXTERNAL, "host_name": "ws01"}
    enrichments = {EXTERNAL: _enrich_result(blocklist_sources=[], blocklist_checked=False)}
    inv = SimpleNamespace(src_ip="10.0.0.1", dest_ip=EXTERNAL, verdict="false_positive")
    _, _, note = _entity_graph(alert, enrichments, inv)
    assert note is not None
    assert "checked none of them" in note


def test_the_entity_graph_note_is_unchanged_with_loaded_feeds() -> None:
    """Negative control."""
    from types import SimpleNamespace

    from soc_ai.api.webui._timeline import _entity_graph

    alert = {"source_ip": "10.0.0.1", "destination_ip": EXTERNAL, "host_name": "ws01"}
    inv = SimpleNamespace(src_ip="10.0.0.1", dest_ip=EXTERNAL, verdict="false_positive")
    _, _, note = _entity_graph(alert, {EXTERNAL: _enrich_result()}, inv)
    assert note is not None
    assert "blocklist" not in note


def test_the_prefetch_line_does_not_imply_a_reputation_check() -> None:
    from soc_ai.api.webui._timeline import _detail_for

    payload = {
        "enrichments": {EXTERNAL: _enrich_result(blocklist_sources=[], blocklist_checked=False)},
        "host_alert_profile": {},
    }
    assert "checked no indicator against threat intel" in _detail_for(
        "enriched_alert_context", payload
    )


def test_the_prefetch_line_is_unchanged_with_loaded_feeds() -> None:
    """Negative control."""
    from soc_ai.api.webui._timeline import _detail_for

    payload = {"enrichments": {EXTERNAL: _enrich_result()}, "host_alert_profile": {}}
    assert "checked against threat intel" not in _detail_for("enriched_alert_context", payload)


def test_a_partial_enrichment_of_the_wrong_shape_does_not_break_the_row() -> None:
    """A stored payload can leave a list where the indicator map belongs. A
    timeline row must render, not 500."""
    from soc_ai.api.webui._timeline import _detail_for

    payload = {"enrichments": ["not a map"], "host_alert_profile": "also not a map"}
    assert "loaded the alert" in _detail_for("enriched_alert_context", payload)


# ---------------------------------------------------------------------------
# The decision templates
# ---------------------------------------------------------------------------


def _internal_pair(*, sources: list[str] | None) -> dict[str, Any]:
    from soc_ai.tools.enrichment import IndicatorEnrichment

    return {
        ip: IndicatorEnrichment(
            indicator=ip, indicator_type="ip", internal=True, blocklist_sources=sources
        )
        for ip in ("10.0.0.1", "10.0.0.2")
    }


def _clean_internal_alert() -> Any:
    from soc_ai.so_client.models import SoAlert

    return SoAlert(
        id="a1",
        rule_name="ET INFO Internal Doh",
        severity_label="low",
        source_ip="10.0.0.1",
        destination_ip="10.0.0.2",
        alert_action="allowed",
    )


def _enriched_ctx(alert: Any, enrichments: dict[str, Any]) -> Any:
    from soc_ai.enrichment.zeek_parser import TypedZeekFields
    from soc_ai.tools.get_alert_context import EnrichedAlertContext

    return EnrichedAlertContext(
        alert=alert,
        community_id_events=[],
        host_events=[],
        user_events=[],
        process_events=[],
        file_events=[],
        pivot_summary={},
        host_alert_profile={},
        prefetch_gaps={},
        typed_zeek=TypedZeekFields(),
        enrichments=enrichments,
    )


def test_the_internal_template_does_not_claim_a_check_that_did_not_run() -> None:
    """The template's locality grounds survive an unloaded feed. Its third
    ground does not, and that is the line three triages leaned on."""
    from soc_ai.agent.decision_templates import match_decision_template

    cv = match_decision_template(_enriched_ctx(_clean_internal_alert(), _internal_pair(sources=[])))
    assert cv is not None
    assert cv.template_id == "clean_internal_traffic"
    assert not any("no blocklist hits" in line for line in cv.cited_evidence)
    assert any("not loaded" in line for line in cv.cited_evidence)
    assert "no blocklist hits" not in cv.rationale


def test_the_internal_template_still_cites_a_real_check() -> None:
    """Negative control."""
    from soc_ai.agent.decision_templates import match_decision_template

    cv = match_decision_template(
        _enriched_ctx(_clean_internal_alert(), _internal_pair(sources=["urlhaus"]))
    )
    assert cv is not None
    assert any("no blocklist hits" in line for line in cv.cited_evidence)


def _informational_external_ctx(sources: list[str] | None) -> Any:
    from soc_ai.so_client.models import RuleMetadata, SoAlert
    from soc_ai.tools.enrichment import IndicatorEnrichment

    alert = SoAlert(
        id="a2",
        rule_name="ET INFO Observed DNS Query",
        severity_label="low",
        source_ip="10.0.0.1",
        destination_ip=EXTERNAL,
        alert_action="allowed",
        rule_metadata=RuleMetadata(signature_severity="Informational"),
    )
    enrich = {
        "10.0.0.1": IndicatorEnrichment(
            indicator="10.0.0.1", indicator_type="ip", internal=True, blocklist_sources=sources
        ),
        EXTERNAL: IndicatorEnrichment(
            indicator=EXTERNAL, indicator_type="ip", blocklist_sources=sources
        ),
    }
    return _enriched_ctx(alert, enrich)


def test_the_unknown_asn_template_stands_down_with_no_feed() -> None:
    """Its only reputation ground is a clean external endpoint. Without a feed
    it has none, so the alert goes to investigation rather than to a 0.7 false
    positive built on a lookup that did not happen."""
    from soc_ai.agent.decision_templates import match_decision_template

    cv = match_decision_template(_informational_external_ctx([]))
    assert cv is None or cv.template_id != "informational_external_unknown_asn"


def test_the_unknown_asn_template_still_fires_on_a_real_check() -> None:
    """Negative control."""
    from soc_ai.agent.decision_templates import match_decision_template

    cv = match_decision_template(_informational_external_ctx(["urlhaus"]))
    assert cv is not None
    assert cv.template_id == "informational_external_unknown_asn"


def test_an_unrecorded_context_leaves_the_templates_where_they_were() -> None:
    """Negative control for the third state: no claim recorded, no change."""
    from soc_ai.agent.decision_templates import match_decision_template

    cv = match_decision_template(_informational_external_ctx(None))
    assert cv is not None
    assert cv.template_id == "informational_external_unknown_asn"


# ---------------------------------------------------------------------------
# The evidence the synthesizer reads
# ---------------------------------------------------------------------------


def test_the_coverage_gap_is_a_citable_bullet() -> None:
    """Same shape as the endpoint-coverage gap: a fact the synthesizer can cite,
    rather than a silence it has to interpret."""
    from soc_ai.agent.evidence import _materialize_prefetch_evidence

    bullets = _materialize_prefetch_evidence(
        _enriched_ctx(_clean_internal_alert(), _internal_pair(sources=[]))
    )
    gap = [b for b in bullets if "blocklist" in b]
    assert len(gap) == 1
    assert "not exoneration" in gap[0]
    assert "blocklist_sources" in gap[0]


def test_no_coverage_bullet_when_the_feeds_answered() -> None:
    """Negative control."""
    from soc_ai.agent.evidence import _materialize_prefetch_evidence

    bullets = _materialize_prefetch_evidence(
        _enriched_ctx(_clean_internal_alert(), _internal_pair(sources=["urlhaus"]))
    )
    assert not [b for b in bullets if "blocklist" in b]


def test_no_coverage_bullet_when_nothing_was_recorded() -> None:
    from soc_ai.agent.evidence import _materialize_prefetch_evidence

    bullets = _materialize_prefetch_evidence(
        _enriched_ctx(_clean_internal_alert(), _internal_pair(sources=None))
    )
    assert not [b for b in bullets if "blocklist" in b]

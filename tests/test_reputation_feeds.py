"""A miss is evidence only for a feed that is loaded and holds the indicator type.

Measured defect (production review 2026-11-12, ops finding 6, hunts finding 7).
A production host loaded one feed: the Tor exit list. Each lookup returned
``blocklist_checked: true`` and ``blocklist_sources: ["tor"]``. The prompt
counted a miss with ``blocklist_checked: true`` as positive evidence, so the
model called an address clean when no malware feed had answered. Eight of
seventeen hunt reports cited that clean result. Two hunts read
``blocklist_sources: ["tor"]`` with no hit as a Tor hit, and one wrote three
threat findings about "TOR-listed" addresses that are public time servers.

The result now holds a status and three feed lists. The names of the lists
say what each list holds.
"""

from __future__ import annotations

from typing import Any

import pytest
from soc_ai.agent.decision_templates import _blocklist_feeds_missing
from soc_ai.agent.evidence import _materialize_prefetch_evidence
from soc_ai.agent.prompts import build_synth_first_system_prompt
from soc_ai.api.webui._timeline import _blocklist_unchecked, _tool_outcome
from soc_ai.config import Settings
from soc_ai.enrichment.blocklists import FEED_PROFILES, BlocklistDB, BlocklistHit, feed_of_hit
from soc_ai.enrichment.zeek_parser import TypedZeekFields
from soc_ai.so_client.fields import get_dotted
from soc_ai.so_client.models import SoAlert
from soc_ai.tools.enrichment import IndicatorEnrichment, enrich_domain, enrich_hash, enrich_ip
from soc_ai.tools.get_alert_context import EnrichedAlertContext

TIME_SERVER = "198.51.100.28"
TOR_EXIT = "203.0.113.77"
SHA256 = "ab" * 32


def _tor_hit() -> BlocklistHit:
    return BlocklistHit(
        indicator=TOR_EXIT, indicator_type="ip", source="Tor Project exit list", tags=("tor",)
    )


def _production_db() -> BlocklistDB:
    """The measured host: the Tor exit list loaded, three abuse.ch feeds never fetched."""
    db = BlocklistDB(loaded_sources=["tor"], missing_sources=["urlhaus", "threatfox", "feodo"])
    db.ips[TOR_EXIT] = [_tor_hit()]
    return db


def _malware_db(*feeds: str) -> BlocklistDB:
    return BlocklistDB(loaded_sources=list(feeds))


# ---------------------------------------------------------------------------
# The measured case: the Tor exit list alone
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_a_miss_with_only_the_tor_list_is_not_checked(settings_kratos: Settings) -> None:
    e = await enrich_ip(TIME_SERVER, settings=settings_kratos, blocklist=_production_db())
    assert e.blocklist_hits == []
    assert e.reputation_status == "not_checked"
    assert e.feeds_matched == []
    assert e.feeds_checked == ["tor"]
    assert e.feeds_not_loaded == ["urlhaus", "threatfox", "feodo"]
    # The gates and the templates read this property. It was True on the host.
    assert e.blocklist_checked is False


@pytest.mark.asyncio
async def test_the_note_states_what_the_tor_miss_supports(settings_kratos: Settings) -> None:
    e = await enrich_ip(TIME_SERVER, settings=settings_kratos, blocklist=_production_db())
    note = e.reputation_note or ""
    assert "No malware feed that holds addresses is loaded." in note
    assert "The reputation of this indicator is not checked." in note
    assert "The feed `tor` does not list it." in note
    assert "The feeds `urlhaus`, `threatfox` and `feodo` are configured and not loaded." in note


@pytest.mark.asyncio
async def test_the_dump_holds_no_field_name_that_reads_as_a_hit(
    settings_kratos: Settings,
) -> None:
    """The model reads the dump. The older names are not in it."""
    e = await enrich_ip(TIME_SERVER, settings=settings_kratos, blocklist=_production_db())
    dumped = e.model_dump(mode="json")
    assert "blocklist_sources" not in dumped
    assert "blocklist_checked" not in dumped
    assert dumped["reputation_status"] == "not_checked"
    assert dumped["feeds_matched"] == []
    assert dumped["feeds_checked"] == ["tor"]
    assert dumped["feeds_not_loaded"] == ["urlhaus", "threatfox", "feodo"]
    assert dumped["reputation_note"]


@pytest.mark.asyncio
async def test_a_real_tor_exit_is_still_listed(settings_kratos: Settings) -> None:
    """Negative control: the new shape must not hide a real match."""
    e = await enrich_ip(TOR_EXIT, settings=settings_kratos, blocklist=_production_db())
    assert e.reputation_status == "listed"
    assert e.feeds_matched == ["tor"]
    assert [feed_of_hit(hit) for hit in e.blocklist_hits] == ["tor"]
    assert e.blocklist_checked is True
    assert "The feed `tor` lists this indicator." in (e.reputation_note or "")


# ---------------------------------------------------------------------------
# A loaded malware feed
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_a_miss_on_a_loaded_malware_feed_is_evidence(settings_kratos: Settings) -> None:
    """Negative control: the fix must not turn every miss into "not checked"."""
    e = await enrich_ip(
        TIME_SERVER, settings=settings_kratos, blocklist=_malware_db("urlhaus", "feodo", "tor")
    )
    assert e.reputation_status == "not_listed"
    assert e.feeds_checked == ["urlhaus", "feodo", "tor"]
    assert e.feeds_not_loaded == []
    assert e.blocklist_checked is True
    note = e.reputation_note or ""
    assert "The feeds `urlhaus`, `feodo` and `tor` do not list this indicator." in note
    assert "The miss is evidence for the checked feeds only." in note


@pytest.mark.asyncio
async def test_a_feed_is_checked_only_for_an_indicator_type_that_it_holds(
    settings_kratos: Settings,
) -> None:
    """The Tor list and Feodo hold addresses. Neither can answer for a domain."""
    db = _malware_db("feodo", "tor")
    domain = await enrich_domain("example.test", settings=settings_kratos, blocklist=db)
    assert domain.reputation_status == "not_checked"
    assert domain.feeds_checked == []
    assert "No malware feed that holds domains is loaded." in (domain.reputation_note or "")
    address = await enrich_ip(TIME_SERVER, settings=settings_kratos, blocklist=db)
    assert address.reputation_status == "not_listed"


@pytest.mark.asyncio
async def test_a_hash_is_checked_only_against_a_feed_that_holds_hashes(
    settings_kratos: Settings,
) -> None:
    urlhaus = await enrich_hash(
        SHA256, "sha256", settings=settings_kratos, blocklist=_malware_db("urlhaus")
    )
    assert urlhaus.reputation_status == "not_checked"
    assert urlhaus.feeds_checked == []
    threatfox = await enrich_hash(
        SHA256, "sha256", settings=settings_kratos, blocklist=_malware_db("urlhaus", "threatfox")
    )
    assert threatfox.reputation_status == "not_listed"
    assert threatfox.feeds_checked == ["threatfox"]


@pytest.mark.asyncio
async def test_the_operator_seed_list_alone_does_not_clear_an_indicator(
    settings_kratos: Settings,
) -> None:
    e = await enrich_ip(
        TIME_SERVER, settings=settings_kratos, blocklist=_malware_db("internal_seed")
    )
    assert e.reputation_status == "not_checked"
    assert e.feeds_checked == ["internal_seed"]


def test_every_configurable_feed_has_a_profile() -> None:
    """A feed with no profile would never count as checked."""
    from soc_ai.enrichment.blocklists import _LOADERS

    assert set(FEED_PROFILES) == set(_LOADERS)
    assert not FEED_PROFILES["tor"].malware
    assert not FEED_PROFILES["internal_seed"].malware


# ---------------------------------------------------------------------------
# The readers: templates, evidence, timeline
# ---------------------------------------------------------------------------


def _ctx(enrichments: dict[str, Any]) -> EnrichedAlertContext:
    return EnrichedAlertContext(
        alert=SoAlert(
            id="a1",
            rule_name="ET INFO NTP",
            severity_label="low",
            source_ip="10.0.0.1",
            destination_ip=TIME_SERVER,
            alert_action="allowed",
        ),
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


@pytest.mark.asyncio
async def test_the_templates_stand_down_with_only_the_tor_list(settings_kratos: Settings) -> None:
    e = await enrich_ip(TIME_SERVER, settings=settings_kratos, blocklist=_production_db())
    assert _blocklist_feeds_missing(_ctx({TIME_SERVER: e})) is True


@pytest.mark.asyncio
async def test_the_templates_keep_a_real_check(settings_kratos: Settings) -> None:
    """Negative control."""
    e = await enrich_ip(TIME_SERVER, settings=settings_kratos, blocklist=_malware_db("urlhaus"))
    assert _blocklist_feeds_missing(_ctx({TIME_SERVER: e})) is False


@pytest.mark.asyncio
async def test_the_coverage_bullet_fires_with_only_the_tor_list_and_its_path_resolves(
    settings_kratos: Settings,
) -> None:
    e = await enrich_ip(TIME_SERVER, settings=settings_kratos, blocklist=_production_db())
    ctx = _ctx({TIME_SERVER: e})
    gap = [b for b in _materialize_prefetch_evidence(ctx) if "blocklist coverage gap" in b]
    assert len(gap) == 1
    assert f"(path enrichments.{TIME_SERVER}.reputation_status)" in gap[0]
    # The cited path is in the bundle that the citation check reads.
    dumped = ctx.model_dump(mode="json")
    assert dumped["enrichments"][TIME_SERVER]["reputation_status"] == "not_checked"
    assert get_dotted(dumped["enrichments"][TIME_SERVER], "blocklist_sources") is None


@pytest.mark.asyncio
async def test_no_coverage_bullet_after_a_real_check(settings_kratos: Settings) -> None:
    """Negative control."""
    e = await enrich_ip(TIME_SERVER, settings=settings_kratos, blocklist=_malware_db("feodo"))
    bullets = _materialize_prefetch_evidence(_ctx({TIME_SERVER: e}))
    assert not [b for b in bullets if "blocklist coverage gap" in b]


@pytest.mark.asyncio
async def test_the_timeline_does_not_call_a_tor_only_miss_a_clean_miss(
    settings_kratos: Settings,
) -> None:
    e = await enrich_ip(TIME_SERVER, settings=settings_kratos, blocklist=_production_db())
    label = _tool_outcome(e.model_dump(mode="json"))
    assert label == "reputation not checked. No malware feed is loaded"
    assert _blocklist_unchecked({TIME_SERVER: e.model_dump(mode="json")}) is True


@pytest.mark.asyncio
async def test_the_timeline_reports_a_real_miss_and_a_real_hit(settings_kratos: Settings) -> None:
    """Negative control."""
    miss = await enrich_ip(TIME_SERVER, settings=settings_kratos, blocklist=_malware_db("feodo"))
    assert _tool_outcome(miss.model_dump(mode="json")) == "no blocklist/MISP match"
    hit = await enrich_ip(TOR_EXIT, settings=settings_kratos, blocklist=_production_db())
    assert _tool_outcome(hit.model_dump(mode="json")).startswith("flagged malicious")


# ---------------------------------------------------------------------------
# Records stored before the new shape
# ---------------------------------------------------------------------------


def _old_record(**over: Any) -> dict[str, Any]:
    """A t_enrich_ip result as the store holds it from before this change."""
    base: dict[str, Any] = {
        "indicator": TIME_SERVER,
        "indicator_type": "ip",
        "internal": False,
        "blocklist_hits": [],
        "blocklist_sources": ["tor"],
        "asn": None,
        "geoip": None,
        "cloud_provider": None,
        "misp_hits": [],
        "errors": [],
        "blocklist_checked": True,
    }
    base.update(over)
    return base


def test_an_old_stored_record_renders_as_it_did() -> None:
    assert _tool_outcome(_old_record()) == "no blocklist/MISP match"
    unloaded = _old_record(blocklist_sources=[], blocklist_checked=False)
    assert _tool_outcome(unloaded) == "no blocklist loaded. soc-ai checked nothing"
    assert _blocklist_unchecked({TIME_SERVER: unloaded}) is True
    assert _blocklist_unchecked({TIME_SERVER: _old_record()}) is False


def test_an_old_stored_record_still_validates_and_keeps_its_meaning() -> None:
    old = IndicatorEnrichment.model_validate(_old_record())
    assert old.reputation_status is None
    assert old.blocklist_checked is True
    unloaded = IndicatorEnrichment.model_validate(
        _old_record(blocklist_sources=[], blocklist_checked=False)
    )
    assert unloaded.blocklist_checked is False
    silent = IndicatorEnrichment(indicator=TIME_SERVER, indicator_type="ip")
    assert silent.blocklist_checked is None


@pytest.mark.asyncio
async def test_a_new_record_keeps_its_meaning_after_a_round_trip(
    settings_kratos: Settings,
) -> None:
    """A stored dump no longer holds the older names. The status must carry the meaning."""
    e = await enrich_ip(TIME_SERVER, settings=settings_kratos, blocklist=_production_db())
    back = IndicatorEnrichment.model_validate(e.model_dump(mode="json"))
    assert back.reputation_status == "not_checked"
    assert back.blocklist_checked is False
    assert back.feeds_checked == ["tor"]


# ---------------------------------------------------------------------------
# The prompt rule
# ---------------------------------------------------------------------------


def test_the_prompt_counts_a_miss_only_for_a_checked_malware_feed() -> None:
    prompt = build_synth_first_system_prompt()
    assert "`reputation_status: not_listed`" in prompt
    assert "`reputation_status: not_checked` is not evidence" in prompt
    assert "Only `feeds_matched` and" in prompt
    # The older rule counted a miss with one loaded feed as positive evidence.
    assert "blocklist_checked" not in prompt
    assert "blocklist_sources" not in prompt


# ---------------------------------------------------------------------------
# The doctor row
# ---------------------------------------------------------------------------


def _doctor_settings(settings: Settings, tmp_path: Any, files: list[str]) -> Settings:
    for name in files:
        (tmp_path / name).write_text("203.0.113.77\n", encoding="utf-8")
    settings.blocklist_data_dir = tmp_path
    settings.blocklist_sources = ["urlhaus", "threatfox", "feodo", "tor"]
    return settings


def test_the_doctor_row_states_that_no_malware_feed_is_on_disk(
    settings_kratos: Settings, tmp_path: Any
) -> None:
    from soc_ai.doctor import check_blocklists

    settings = _doctor_settings(settings_kratos, tmp_path, ["tor_exits.txt"])
    (row,) = check_blocklists(settings)
    assert row.status == "WARN"
    assert "never refreshed: urlhaus, threatfox, feodo" in row.detail
    assert "no malware feed is on disk, so each reputation result reads not_checked" in row.detail


def test_the_doctor_row_keeps_quiet_when_a_malware_feed_is_on_disk(
    settings_kratos: Settings, tmp_path: Any
) -> None:
    """Negative control."""
    from soc_ai.doctor import check_blocklists

    settings = _doctor_settings(settings_kratos, tmp_path, ["tor_exits.txt", "feodo.csv"])
    (row,) = check_blocklists(settings)
    assert row.status == "WARN"
    assert "no malware feed" not in row.detail


# ---------------------------------------------------------------------------
# Review of 2026-11-13: defects 1 and 13
# ---------------------------------------------------------------------------

MD5 = "44d88612fea8a8f36de82e1278abb02f"
SHA1 = "3395856ce81f2b7382dee72602f798b642f14140"


def _threatfox_dir(tmp_path: Any) -> Any:
    rows = {
        "1": [{"ioc_value": MD5, "ioc_type": "md5_hash", "tags": "eicar"}],
        "2": [{"ioc_value": SHA1, "ioc_type": "sha1_hash", "tags": "eicar"}],
        "3": [{"ioc_value": "a" * 64, "ioc_type": "sha256_hash", "tags": "x"}],
        "4": [{"ioc_value": "203.0.113.77:443", "ioc_type": "ip:port", "tags": "c2"}],
        "5": [{"ioc_value": "bad.example", "ioc_type": "domain", "tags": "c2"}],
    }
    import json

    (tmp_path / "threatfox.json").write_text(json.dumps(rows), encoding="utf-8")
    return tmp_path


@pytest.mark.asyncio
@pytest.mark.parametrize(("value", "algo"), [(MD5, "md5"), (SHA1, "sha1")])
async def test_a_hash_that_threatfox_lists_is_listed(
    settings_kratos: Settings, tmp_path: Any, value: str, algo: str
) -> None:
    """The loader kept SHA-256 rows only. The grid stores MD5 and SHA-1 for a Zeek file."""
    db = BlocklistDB.from_dir(_threatfox_dir(tmp_path), sources=["threatfox"])
    out = await enrich_hash(value, algo, settings=settings_kratos, blocklist=db)
    assert out.reputation_status == "listed"
    assert out.feeds_matched == ["threatfox"]


@pytest.mark.asyncio
async def test_a_miss_on_a_hash_type_that_a_feed_indexes_is_evidence(
    settings_kratos: Settings, tmp_path: Any
) -> None:
    """Negative control: ThreatFox now indexes MD5, so a different MD5 is a real miss."""
    db = BlocklistDB.from_dir(_threatfox_dir(tmp_path), sources=["threatfox"])
    out = await enrich_hash("0" * 32, "md5", settings=settings_kratos, blocklist=db)
    assert out.reputation_status == "not_listed"
    assert out.feeds_checked == ["threatfox"]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("feeds", "algo"),
    [(("urlhaus", "feodo", "tor"), "md5"), (("internal_seed",), "md5"), (("threatfox",), "sha512")],
)
async def test_a_hash_type_that_no_loaded_feed_indexes_is_not_checked(
    settings_kratos: Settings, feeds: tuple[str, ...], algo: str
) -> None:
    """A feed counts for an indicator only when its loader indexes that type."""
    out = await enrich_hash("0" * 32, algo, settings=settings_kratos, blocklist=_malware_db(*feeds))
    assert out.reputation_status == "not_checked"
    assert out.feeds_checked == []


def test_the_threatfox_profile_names_the_types_that_its_loader_indexes(tmp_path: Any) -> None:
    """The profile is a claim about the loader. This test holds the two together."""
    db = BlocklistDB.from_dir(_threatfox_dir(tmp_path), sources=["threatfox"])
    indexed = {
        hit.indicator_type
        for table in (db.ips, db.domains, db.hashes)
        for hits in table.values()
        for hit in hits
    }
    assert indexed == set(FEED_PROFILES["threatfox"].kinds)
    assert set(FEED_PROFILES["urlhaus"].kinds) == {"ip", "domain"}
    assert set(FEED_PROFILES["internal_seed"].kinds) == {"ip", "domain", "sha256"}


@pytest.mark.asyncio
async def test_a_miss_for_an_internal_address_is_not_checked(settings_kratos: Settings) -> None:
    """The feeds list public infrastructure. A miss says nothing about an internal address."""
    out = await enrich_ip(
        "10.0.0.7", settings=settings_kratos, blocklist=_malware_db("urlhaus", "feodo")
    )
    assert out.internal is True
    assert out.reputation_status == "not_checked"
    assert out.not_checked_reason == "internal_address"
    assert "internal address" in (out.reputation_note or "")


@pytest.mark.asyncio
async def test_an_internal_address_is_not_a_gap_in_the_feeds(settings_kratos: Settings) -> None:
    """Negative control: the readers of a feed gap do not fire for an internal address.

    Each alert names an internal address. If its status counted as a feed gap,
    each template would stand down, each run would carry the coverage line and
    each timeline row would say that nothing was checked.
    """
    db = _malware_db("urlhaus", "feodo")
    internal = await enrich_ip("10.0.0.7", settings=settings_kratos, blocklist=db)
    external = await enrich_ip(TIME_SERVER, settings=settings_kratos, blocklist=db)
    assert internal.blocklist_checked is None
    ctx = _ctx({"10.0.0.7": internal, TIME_SERVER: external})
    assert _blocklist_feeds_missing(ctx) is False
    assert not [b for b in _materialize_prefetch_evidence(ctx) if "coverage gap" in b]
    dumped = internal.model_dump(mode="json")
    assert _tool_outcome(dumped) == "internal address"
    assert _blocklist_unchecked({"10.0.0.7": dumped}) is False


@pytest.mark.asyncio
async def test_an_internal_address_with_no_malware_feed_is_a_gap(settings_kratos: Settings) -> None:
    """Negative control: with the Tor list alone the gap is real, for each address."""
    internal = await enrich_ip("10.0.0.7", settings=settings_kratos, blocklist=_production_db())
    assert internal.not_checked_reason == "no_feed"
    assert internal.blocklist_checked is False


@pytest.mark.asyncio
async def test_an_internal_address_that_a_feed_lists_is_still_listed(
    settings_kratos: Settings,
) -> None:
    """Negative control: the operator seed list names known-bad internal hosts."""
    db = _malware_db("internal_seed")
    db.ips["10.0.0.7"] = [
        BlocklistHit(indicator="10.0.0.7", indicator_type="ip", source="internal_seed", tags=())
    ]
    out = await enrich_ip("10.0.0.7", settings=settings_kratos, blocklist=db)
    assert out.reputation_status == "listed"
    assert out.feeds_matched == ["internal_seed"]


@pytest.mark.asyncio
async def test_a_lookup_that_failed_is_not_checked(settings_kratos: Settings) -> None:
    class _Broken(BlocklistDB):
        def lookup_ip(self, ip: str) -> list[Any]:
            raise RuntimeError("index corrupt")

    out = await enrich_ip(
        TIME_SERVER, settings=settings_kratos, blocklist=_Broken(loaded_sources=["urlhaus"])
    )
    assert any("blocklist lookup failed" in e for e in out.errors)
    assert out.reputation_status == "not_checked"
    assert out.not_checked_reason == "lookup_failed"
    assert out.feeds_checked == []
    assert "The lookup failed" in (out.reputation_note or "")
    label = _tool_outcome(out.model_dump(mode="json"))
    assert label == "reputation not checked. The lookup failed"


def _aged_db(days: float, *, hit: bool = False) -> BlocklistDB:
    from datetime import UTC, datetime, timedelta

    db = BlocklistDB(
        loaded_sources=["urlhaus"],
        file_mtimes={"urlhaus": datetime.now(UTC) - timedelta(days=days)},
    )
    if hit:
        db.ips[TIME_SERVER] = [
            BlocklistHit(
                indicator=TIME_SERVER, indicator_type="ip", source="abuse.ch URLhaus", tags=()
            )
        ]
    return db


@pytest.mark.asyncio
async def test_a_miss_on_a_stale_feed_is_not_checked(settings_kratos: Settings) -> None:
    """The feed file is older than blocklist_stale_threshold_days."""
    settings_kratos.blocklist_stale_threshold_days = 7
    out = await enrich_ip(TIME_SERVER, settings=settings_kratos, blocklist=_aged_db(30))
    assert out.reputation_status == "not_checked"
    assert out.feeds_checked == []
    assert out.feeds_stale == ["urlhaus"]
    assert out.not_checked_reason == "stale_feed"
    assert "The feed `urlhaus` is stale." in (out.reputation_note or "")
    label = _tool_outcome(out.model_dump(mode="json"))
    assert label == "reputation not checked. The feed file is stale"


@pytest.mark.asyncio
async def test_a_miss_on_a_fresh_feed_is_still_evidence(settings_kratos: Settings) -> None:
    """Negative control."""
    settings_kratos.blocklist_stale_threshold_days = 7
    out = await enrich_ip(TIME_SERVER, settings=settings_kratos, blocklist=_aged_db(1))
    assert out.reputation_status == "not_listed"
    assert out.feeds_checked == ["urlhaus"]
    assert out.feeds_stale == []


@pytest.mark.asyncio
async def test_a_hit_on_a_stale_feed_is_still_a_hit(settings_kratos: Settings) -> None:
    """Negative control: staleness must not hide a match."""
    settings_kratos.blocklist_stale_threshold_days = 7
    out = await enrich_ip(TIME_SERVER, settings=settings_kratos, blocklist=_aged_db(30, hit=True))
    assert out.reputation_status == "listed"
    assert out.feeds_matched == ["urlhaus"]


def test_the_doctor_row_warns_for_a_fresh_store_with_no_malware_feed(
    settings_kratos: Settings, tmp_path: Any
) -> None:
    """blocklist_sources is ["tor"] and the file is fresh. The row passed and said nothing."""
    from soc_ai.doctor import check_blocklists

    (tmp_path / "tor_exits.txt").write_text("203.0.113.77\n", encoding="utf-8")
    settings_kratos.blocklist_data_dir = tmp_path
    settings_kratos.blocklist_sources = ["tor"]
    (row,) = check_blocklists(settings_kratos)
    assert row.status == "WARN"
    assert "no malware feed is on disk, so each reputation result reads not_checked" in row.detail
    assert "ABUSE_CH_AUTH_KEY" in row.hint


def test_the_doctor_row_passes_for_a_fresh_store_with_a_malware_feed(
    settings_kratos: Settings, tmp_path: Any
) -> None:
    """Negative control."""
    from soc_ai.doctor import check_blocklists

    for name in ("tor_exits.txt", "feodo.csv"):
        (tmp_path / name).write_text("203.0.113.77\n", encoding="utf-8")
    settings_kratos.blocklist_data_dir = tmp_path
    settings_kratos.blocklist_sources = ["feodo", "tor"]
    (row,) = check_blocklists(settings_kratos)
    assert row.status == "PASS"


def test_the_doctor_row_states_when_each_malware_feed_is_stale(
    settings_kratos: Settings, tmp_path: Any
) -> None:
    """A stale malware feed gives not_checked, and the row says so."""
    import os
    import time

    from soc_ai.doctor import check_blocklists

    for name in ("tor_exits.txt", "feodo.csv"):
        (tmp_path / name).write_text("203.0.113.77\n", encoding="utf-8")
    old = time.time() - 40 * 86400
    os.utime(tmp_path / "feodo.csv", (old, old))
    settings_kratos.blocklist_data_dir = tmp_path
    settings_kratos.blocklist_sources = ["feodo", "tor"]
    settings_kratos.blocklist_stale_threshold_days = 7
    (row,) = check_blocklists(settings_kratos)
    assert row.status == "WARN"
    assert "no fresh malware feed is on disk" in row.detail

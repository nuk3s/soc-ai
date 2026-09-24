"""Catalogue-wide invariants for ``soc_ai/eval/synth_scenarios/*.yaml``.

These are properties of the CATALOGUE, not of any one scenario: they hold for
every file in the directory and keep holding as scenarios are added. Per-
scenario assertions live with the scenario that motivated them (see
``tests/test_synth_loader.py`` for e1's field-level pins).

The invariants exist because the catalogue is the instrument the product's
quality metric is measured with, and a broken instrument reports a product
defect that isn't there:

* **Prefix** — every event index under ``logs-synth-`` is what the synth
  pollution kill-switch keys on. One stray index and planted documents become
  invisible to cleanup and visible to production queries.
* **Typed parse** — a triage alert whose severity metadata does not land where
  ``SoAlert`` reads it parses with ``rule_metadata=None``, so a citation
  naming it can never resolve, capping confidence and turning a correct
  detection into a recorded miss (the 2026-08-26 fixture-shape finding).
* **Addressing** — the catalogue must not carry live-network identifiers, and
  every globally routable address has to be a deliberate, reviewed choice
  rather than a habit, because address CLASS decides tool visibility (see
  ``test_journey_cited_conn_events_clear_the_beacon_tool_floor``).
* **Measurable behaviour** — a scenario whose hunt journey turns on a
  behavioural sweep must plant enough RAW rows for that sweep to measure. A
  pre-aggregated summary document is invisible to a tool that aggregates raw
  events; ``m1-cobalt-strike-beacon`` shipped that way for months and reported
  a failure every run, and ``m2-dns-tunnel-exfil``/``b4-av-dns-reputation``
  repeated the same defect against the DNS-entropy sweep (one raw ``zeek.dns``
  row each, so ``t_dns_entropy_scan`` scanned zero parents for both).
"""

from __future__ import annotations

import ipaddress
import json
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from soc_ai.config import Settings
from soc_ai.eval.synth_loader import Scenario, load_all_scenarios, triage_scenarios
from soc_ai.eval.synth_render import render_scenario
from soc_ai.so_client.elastic import ElasticClient, EsSearchResult
from soc_ai.so_client.models import SoAlert
from soc_ai.tools.analytics import (
    _CV_MAX,
    _CV_PERIODIC,
    _ENTROPY_EXTREME_MIN,
    _ENTROPY_MIN,
    _QNAME_TERMS_SIZE,
    _QUERIES_MIN,
    _UNIQUE_SUBDOMAINS_MIN,
    _shannon_entropy_chars,
    _split_registrable,
    dns_entropy_scan,
)
from soc_ai.tools.pcap_decode import _compute_inter_arrival

REPO = Path(__file__).resolve().parents[1]
SCENARIOS_DIR = REPO / "soc_ai" / "eval" / "synth_scenarios"
RUN_TIME = datetime(2026, 8, 26, 14, 0, 0, tzinfo=UTC)

# Expected catalogue shape. Bump these deliberately when scenarios are added —
# an accidental drop (a file that stopped parsing, a scenario deleted in a
# merge) otherwise shows up as a silent recall change with no code behind it.
EXPECTED_TOTAL = 25
EXPECTED_ATTACKS = 17
EXPECTED_BENIGN = 8
EXPECTED_BY_TIER = {"easy": 6, "medium": 10, "hard": 9}

# The catalogue's internal-host convention.
INTERNAL_NET = ipaddress.ip_network("10.0.0.0/8")

# RFC 5737 documentation ranges — the default for external addresses.
DOCUMENTATION_NETS = tuple(
    ipaddress.ip_network(c) for c in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")
)

# Globally routable addresses are allowed ONLY with a reason, and the reason is
# always the same one: `soc_ai.tools.analytics` sweeps drop non-globally-
# routable destinations — server-side by CIDR and again client-side through
# `is_internal_ip`, which treats RFC 5737 documentation space as internal. A
# scenario whose detection path is t_beacon_profile or t_first_seen is
# INVISIBLE to it with a documentation address, however cleanly it renders.
# Scenarios that don't depend on those sweeps use documentation space.
ROUTABLE_ADDRESS_REASONS = {
    "104.18.42.69": "m1 beacon destination — must be reachable by t_beacon_profile",
    "151.101.65.67": "b1 benign beacon twin — same sweep must evaluate and clear it",
    "162.159.140.42": "h3 cloud-storage exfil destination",
    "162.243.103.246": "e1 Feodo blocklist entry — enrichment must resolve it",
    "185.220.101.182": "e3 Tor exit-list entry — enrichment must resolve it",
    "185.45.43.21": "m3 RAT controller",
    "193.42.39.117": "e2 URLhaus entry — enrichment must resolve it",
    "1.1.1.1": "public resolver (h3 DoT bypass, b7 browser DoH endpoint)",
    "45.9.148.99": "m5 mining pool — must be reachable by t_beacon_profile",
    "91.121.211.44": "m6 DoH C2 endpoint — must be reachable by t_beacon_profile",
}

# Fields whose string values are IP addresses worth auditing.
_IP_LIST_FIELDS = ("zeek.dns.answers", "zeek.files.tx_hosts", "zeek.files.rx_hosts")


@pytest.fixture(scope="module")
def scenarios() -> list[Scenario]:
    return triage_scenarios(load_all_scenarios(SCENARIOS_DIR))


@pytest.fixture(scope="module")
def rendered(scenarios: list[Scenario]) -> dict[str, list[tuple[str, dict[str, object], bool]]]:
    """scenario id -> [(index, body, is_triage_target), ...] via the REAL renderer."""
    return {
        s.id: [(d.index, d.body, d.is_triage_target) for d in render_scenario(s, run_time=RUN_TIME)]
        for s in scenarios
    }


def _addresses(body: dict[str, object]) -> set[str]:
    """Every value in an address-bearing field that IS an address.

    Non-address values are skipped rather than failing the scan: a DNS answer
    list legitimately carries non-IP RDATA (``m2-dns-tunnel-exfil``'s answers
    are base64 tunnel payload, which is the point of that scenario).
    """
    candidates: set[str] = set()
    for key, value in body.items():
        if isinstance(value, str) and (key.endswith(".ip") or key in _IP_LIST_FIELDS):
            candidates.add(value)
        elif isinstance(value, list) and key in _IP_LIST_FIELDS:
            candidates.update(v for v in value if isinstance(v, str))

    out: set[str] = set()
    for candidate in candidates:
        try:
            ipaddress.ip_address(candidate)
        except ValueError:
            continue
        out.add(candidate)
    return out


# ---------------------------------------------------------------------------
# Shape of the catalogue
# ---------------------------------------------------------------------------


def test_every_scenario_file_loads_through_the_real_loader() -> None:
    """Every ``*.yaml`` in the directory parses, and none was skipped.

    Deliberately NOT using the ``scenarios`` fixture, which is scoped to the
    triage population. This test is about files on disk, so it must see both
    populations or a broken spec_journey scenario would go unnoticed.
    """
    yaml_files = sorted(p.stem for p in SCENARIOS_DIR.glob("*.yaml"))
    assert yaml_files, "scenario catalogue is empty"
    everything = load_all_scenarios(SCENARIOS_DIR)
    assert sorted(s.id for s in everything) == yaml_files


def test_catalogue_counts_match_the_declared_shape(scenarios: list[Scenario]) -> None:
    attacks = [s for s in scenarios if s.ground_truth.verdict == "true_positive"]
    benign = [s for s in scenarios if s.ground_truth.verdict == "false_positive"]

    assert len(scenarios) == EXPECTED_TOTAL
    assert len(attacks) == EXPECTED_ATTACKS
    assert len(benign) == EXPECTED_BENIGN
    # Every scenario is one or the other: the scorer's precision arm needs a
    # clean two-class split, and a `needs_more_info` ground truth would sit in
    # neither the numerator nor the denominator of either metric.
    assert len(attacks) + len(benign) == len(scenarios)
    assert dict(Counter(s.tier for s in scenarios)) == EXPECTED_BY_TIER


def test_benign_stratum_spans_every_tier(scenarios: list[Scenario]) -> None:
    """Escalation precision has to be measurable at every difficulty, not just
    on the easy shapes — a system that only over-escalates on hard, ambiguous
    evidence is a different failure from one that pages on obvious updaters."""
    benign_tiers = {s.tier for s in scenarios if s.ground_truth.verdict == "false_positive"}
    assert benign_tiers == {"easy", "medium", "hard"}


def test_id_prefix_agrees_with_tier_and_verdict(scenarios: list[Scenario]) -> None:
    """The filename prefix is load-bearing: `b*` is the negative class and
    `e*`/`m*`/`h*` name the tier. A mismatch makes selectors lie."""
    prefix_tier = {"e": "easy", "m": "medium", "h": "hard"}
    for s in scenarios:
        head = s.id[0]
        if head == "b":
            assert s.ground_truth.verdict == "false_positive", (
                f"{s.id}: b* is the benign stratum but ground truth is {s.ground_truth.verdict!r}"
            )
        else:
            assert head in prefix_tier, f"{s.id}: unknown id prefix {head!r}"
            assert s.ground_truth.verdict == "true_positive", f"{s.id}: {head}* must be a TP"
            assert s.tier == prefix_tier[head], (
                f"{s.id}: id prefix says {prefix_tier[head]}, tier says {s.tier}"
            )


def test_benign_scenarios_declare_no_attack_and_close_benign(scenarios: list[Scenario]) -> None:
    for s in scenarios:
        if s.ground_truth.verdict != "false_positive":
            continue
        assert s.attack == [], f"{s.id}: a benign twin must not claim ATT&CK techniques"
        kinds = [a.kind for a in s.ground_truth.expected_actions]
        assert kinds == ["close_benign"], f"{s.id}: benign expected_actions are {kinds}"


def test_attack_scenarios_declare_techniques_and_an_escalating_action(
    scenarios: list[Scenario],
) -> None:
    for s in scenarios:
        if s.ground_truth.verdict != "true_positive":
            continue
        assert s.attack, f"{s.id}: a TP scenario must name at least one ATT&CK technique"
        kinds = {a.kind for a in s.ground_truth.expected_actions}
        assert kinds, f"{s.id}: a TP scenario must expect at least one action"
        assert "close_benign" not in kinds, f"{s.id}: a TP scenario must not expect close_benign"


def test_confidence_floors_sit_in_a_defensible_band(scenarios: list[Scenario]) -> None:
    """A floor above the evidence manufactures a permanent false negative, and
    a floor at zero makes the rubric vacuous. Easy-tier evidence supports a
    higher bar than hard-tier behavioural inference, so the ceiling is tiered."""
    ceiling = {"easy": 0.85, "medium": 0.80, "hard": 0.75}
    for s in scenarios:
        floor = s.ground_truth.confidence_min
        assert 0.5 <= floor <= ceiling[s.tier], (
            f"{s.id} ({s.tier}): confidence_min {floor} outside [0.5, {ceiling[s.tier]}]"
        )


# ---------------------------------------------------------------------------
# Synth pollution kill-switch
# ---------------------------------------------------------------------------


def test_every_event_index_carries_the_synth_prefix(scenarios: list[Scenario]) -> None:
    """The kill-switch that keeps planted documents out of production queries
    keys on this prefix, and cleanup deletes by it. One stray index leaves
    synthetic documents in a real index with nothing to find them by."""
    for s in scenarios:
        for event in s.events:
            assert event.index.startswith("logs-synth-"), (
                f"{s.id}/{event.index}: outside the logs-synth- prefix"
            )


def test_every_scenario_has_exactly_one_triage_target(scenarios: list[Scenario]) -> None:
    for s in scenarios:
        targets = [e for e in s.events if e.is_triage_target]
        assert len(targets) == 1, f"{s.id} has {len(targets)} triage targets, want 1"


def test_rendered_documents_carry_no_unsubstituted_placeholders(
    rendered: dict[str, list[tuple[str, dict[str, object], bool]]],
) -> None:
    for sid, docs in rendered.items():
        for index, body, _ in docs:
            for key, value in body.items():
                assert "{{" not in json.dumps(value), (
                    f"{sid}/{index}: unsubstituted placeholder in {key!r}: {value!r}"
                )


def test_supporting_events_join_the_triage_target_by_community_id(
    rendered: dict[str, list[tuple[str, dict[str, object], bool]]],
) -> None:
    """At least one supporting event must resolve ``{{ same_as_triage }}`` to
    the triage target's flow hash. Without a join the pivot from the alert into
    the corroborating evidence has nothing to follow, and the scenario is a
    bare alert wearing a story."""
    for sid, docs in rendered.items():
        triage_body = next(body for _, body, is_triage in docs if is_triage)
        cid = triage_body.get("network.community_id")
        assert isinstance(cid, str) and cid.startswith("1:"), (
            f"{sid}: triage target has no computed community_id ({cid!r})"
        )
        joined = [
            index
            for index, body, is_triage in docs
            if not is_triage and body.get("network.community_id") == cid
        ]
        assert joined, f"{sid}: no supporting event joins the triage target by community_id"


# ---------------------------------------------------------------------------
# The typed parse — a citation that cannot resolve caps confidence forever
# ---------------------------------------------------------------------------


def test_every_triage_alert_parses_to_populated_rule_metadata(
    rendered: dict[str, list[tuple[str, dict[str, object], bool]]],
) -> None:
    """Parsed exactly as the harness parses a live hit. ``rule_metadata=None``
    is the shape that produced the 2026-08-26 unresolved-citation cluster: the
    model can SEE the severity in the raw document and writes a citation for
    it, the typed path has nothing, the citation never resolves, coverage
    drops below 1.0, confidence is capped, and a correct detection is recorded
    as a miss."""
    for sid, docs in rendered.items():
        body = next(b for _, b, is_triage in docs if is_triage)
        alert = SoAlert.from_es_hit({"_id": f"synth-{sid}", "_source": body})

        assert alert.rule_metadata is not None, (
            f"{sid}: rule_metadata parsed as None — severity metadata is not "
            f"where SoAlert reads it (rule.metadata, single-element-list values)"
        )
        assert alert.rule_metadata.signature_severity, f"{sid}: signature_severity is empty"
        assert alert.classtype, (
            f"{sid}: classtype is None — SoAlert reads it from the EVE message "
            f"JSON as alert.category"
        )
        assert alert.rule_name, f"{sid}: rule.name did not parse"
        assert not alert.prefetch_parse_errors, f"{sid}: {alert.prefetch_parse_errors}"

        # The flattened top-level spellings are the unparseable shape this
        # invariant is about; they must not come back.
        assert "signature_severity" not in body, sid
        assert "classtype" not in body, sid


def test_triage_alerts_declare_a_severity_from_the_suricata_vocabulary(
    rendered: dict[str, list[tuple[str, dict[str, object], bool]]],
) -> None:
    allowed = {"Informational", "Minor", "Major", "Critical"}
    for sid, docs in rendered.items():
        body = next(b for _, b, is_triage in docs if is_triage)
        alert = SoAlert.from_es_hit({"_id": f"synth-{sid}", "_source": body})
        assert alert.rule_metadata is not None
        assert alert.rule_metadata.signature_severity in allowed, (
            f"{sid}: severity {alert.rule_metadata.signature_severity!r} is not a "
            f"Suricata signature_severity value"
        )


def test_no_rendered_document_leaks_the_expected_verdict(
    rendered: dict[str, list[tuple[str, dict[str, object], bool]]],
) -> None:
    """The agent under test can query these documents. The scenario id and
    version are the harness's join key and must ride along; the answer must
    not. ``synth.expected_verdict`` / ``synth.attack_technique`` imply the
    verdict directly."""
    for sid, docs in rendered.items():
        for index, body, _ in docs:
            for leaked in ("synth.expected_verdict", "synth.attack_technique"):
                assert leaked not in body, f"{sid}/{index}: {leaked} is an answer-key leak"


# ---------------------------------------------------------------------------
# Addressing — the publish gate, and tool visibility
# ---------------------------------------------------------------------------


def test_internal_addresses_follow_the_catalogue_convention(
    rendered: dict[str, list[tuple[str, dict[str, object], bool]]],
) -> None:
    """Internal hosts live in 10.0.0.0/8. Anything else private (192.168.x,
    172.16.x) reads as a real network someone pasted in.

    Note ``is_private`` is True for RFC 5737 documentation space as well —
    those ranges are in IANA's special-purpose registry — so they are excluded
    here and audited by the routable-address test instead."""
    for sid, docs in rendered.items():
        for index, body, _ in docs:
            for addr in _addresses(body):
                parsed = ipaddress.ip_address(addr)
                if any(parsed in net for net in DOCUMENTATION_NETS):
                    continue
                if parsed.is_private and not parsed.is_loopback:
                    assert parsed in INTERNAL_NET, (
                        f"{sid}/{index}: private address {addr} outside the "
                        f"catalogue's {INTERNAL_NET} convention"
                    )


def test_every_globally_routable_address_is_a_reviewed_exception(
    rendered: dict[str, list[tuple[str, dict[str, object], bool]]],
) -> None:
    """External addresses default to RFC 5737 documentation space. A globally
    routable one is allowed only when the scenario's detection path REQUIRES
    it, and then it has to be named here with the reason — because the choice
    is not cosmetic. `soc_ai.tools.analytics`'s beacon and novelty sweeps
    exclude non-globally-routable destinations, so a documentation address
    silently makes a scenario invisible to the tool it exists to exercise, and
    a routable one used out of habit puts an address someone else operates
    into a published fixture."""
    for sid, docs in rendered.items():
        for index, body, _ in docs:
            for addr in _addresses(body):
                parsed = ipaddress.ip_address(addr)
                if not parsed.is_global:
                    assert parsed.is_private or any(parsed in n for n in DOCUMENTATION_NETS), (
                        f"{sid}/{index}: {addr} is neither internal nor RFC 5737 "
                        f"documentation space"
                    )
                    continue
                assert addr in ROUTABLE_ADDRESS_REASONS, (
                    f"{sid}/{index}: {addr} is globally routable but not in "
                    f"ROUTABLE_ADDRESS_REASONS. Use RFC 5737 documentation space "
                    f"unless the scenario's detection path needs a routable "
                    f"destination — if it does, add it there with the reason."
                )


def test_catalogue_is_clean_against_the_publish_leak_gate() -> None:
    """The same scan the publish pipeline runs, over every rendered document.
    The patterns are parsed out of the mirror build script, so this test and
    the gate can never drift; on a public clone that script is absent and
    there is nothing to scan against."""
    if not (REPO / "scripts/build-public-mirror.sh").exists():
        pytest.skip("mirror build script not in this tree (public clone)")
    from scripts.demo.build_fixtures import scan_for_leaks

    for path in sorted(SCENARIOS_DIR.glob("*.yaml")):
        assert not scan_for_leaks(path.read_text(encoding="utf-8")), (
            f"{path.name}: publish leak gate matched"
        )


# ---------------------------------------------------------------------------
# Measurable behaviour — the m1 defect, pinned catalogue-wide
# ---------------------------------------------------------------------------


def test_journey_cited_conn_events_clear_the_beacon_tool_floor(
    scenarios: list[Scenario],
    rendered: dict[str, list[tuple[str, dict[str, object], bool]]],
) -> None:
    """A hunt journey that cites raw ``zeek.conn`` rows is asserting that a
    cadence sweep can measure them. ``t_beacon_profile`` aggregates RAW rows
    per src->dst pair and needs at least ``min_events`` (default 8) timestamps
    with an inter-arrival cv at or below ``_CV_MAX`` before the pair is a
    candidate at all. ``m1-cobalt-strike-beacon`` encoded its cadence as one
    pre-aggregated summary document plus a single raw row and was therefore
    invisible to the tool its journey depends on — for months, reporting a
    failure every run. This pins the floor for every scenario that makes the
    same claim, including ones not yet written.

    The destination must also be globally routable: the sweep drops
    non-globally-routable destinations server-side by CIDR and again
    client-side, so a documentation address reproduces the same invisibility
    by a different route.
    """
    min_events = 8  # t_beacon_profile's default `min_events`
    checked = 0
    for scenario in scenarios:
        journey = scenario.hunt_journey
        if journey is None or "logs-synth-zeek-conn" not in journey.expected_cited_event_ids:
            continue
        checked += 1

        pairs: dict[tuple[str, str], list[float]] = {}
        for index, body, _ in rendered[scenario.id]:
            if index != "logs-synth-zeek-conn" or body.get("event.dataset") != "zeek.conn":
                continue
            src, dst = body.get("source.ip"), body.get("destination.ip")
            ts = body.get("@timestamp")
            assert isinstance(src, str) and isinstance(dst, str) and isinstance(ts, str)
            pairs.setdefault((src, dst), []).append(datetime.fromisoformat(ts).timestamp())

        measurable = []
        for (src, dst), stamps in pairs.items():
            if len(stamps) < min_events:
                continue
            assert ipaddress.ip_address(dst).is_global, (
                f"{scenario.id}: destination {dst} is not globally routable, so "
                f"t_beacon_profile drops the pair before measuring it"
            )
            inter_arrival = _compute_inter_arrival(sorted(stamps))
            assert inter_arrival is not None and inter_arrival.mean_s > 0
            if inter_arrival.cv <= _CV_MAX:
                measurable.append((src, dst, len(stamps), inter_arrival.cv))

        assert measurable, (
            f"{scenario.id}: hunt_journey cites logs-synth-zeek-conn but no "
            f"src->dst pair clears t_beacon_profile's floor (>= {min_events} raw "
            f"rows, cv <= {_CV_MAX}); pairs seen: "
            f"{ {k: len(v) for k, v in pairs.items()} }"
        )
        # A cadence journey should land in the strong bucket, not scrape the
        # candidacy bar — "semi-regular" is a hint the agent is invited to
        # discard, so a journey resting on it is one jitter value from unwinnable.
        assert any(cv <= _CV_PERIODIC for *_, cv in measurable), (
            f"{scenario.id}: cadence measures as semi-regular only "
            f"({measurable}); t_beacon_profile calls a pair periodic at "
            f"cv <= {_CV_PERIODIC}"
        )

    assert checked >= 3, (
        f"expected several cadence-driven journeys to pin, found {checked} — "
        f"if journeys were removed, this test stopped protecting anything"
    )


def test_journeys_cite_only_indices_the_scenario_actually_renders(
    scenarios: list[Scenario],
    rendered: dict[str, list[tuple[str, dict[str, object], bool]]],
) -> None:
    """The loader checks cited ids against the scenario's declared events; this
    checks them against what actually RENDERED, which is what the journey
    scorer bridges to Elasticsearch ``_id``s. An unbridged id makes the
    journey unscoreable and reports a false failure."""
    for scenario in scenarios:
        if scenario.hunt_journey is None:
            continue
        present = {index for index, _, _ in rendered[scenario.id]}
        missing = [i for i in scenario.hunt_journey.expected_cited_event_ids if i not in present]
        assert not missing, f"{scenario.id}: journey cites unrendered id(s) {missing}"


def test_paired_benign_twins_plant_raw_rows_for_the_same_sweep(
    scenarios: list[Scenario],
    rendered: dict[str, list[tuple[str, dict[str, object], bool]]],
) -> None:
    """b7-browser-doh is m6-doh-c2-channel's negative control THROUGH the
    cadence sweep, which only works if the sweep actually evaluates it. If b7
    planted a single row, or an unroutable destination, it would come back
    "not flagged" for a reason that has nothing to do with its cadence — and a
    negative control that the instrument skips proves nothing about the
    instrument. Both sides must be measurable; only the statistic may differ.
    """
    by_id = {s.id: s for s in scenarios}
    assert {"m6-doh-c2-channel", "b7-browser-doh"} <= set(by_id)

    def measure(sid: str) -> tuple[int, float]:
        stamps = [
            datetime.fromisoformat(str(body["@timestamp"])).timestamp()
            for index, body, _ in rendered[sid]
            if index == "logs-synth-zeek-conn" and body.get("destination.port") == 443
        ]
        assert ipaddress.ip_address(
            str(
                next(
                    body["destination.ip"]
                    for index, body, _ in rendered[sid]
                    if index == "logs-synth-zeek-conn"
                )
            )
        ).is_global, f"{sid}: destination is not globally routable — the sweep would skip it"
        inter_arrival = _compute_inter_arrival(sorted(stamps))
        assert inter_arrival is not None
        return len(stamps), inter_arrival.cv

    attack_rows, attack_cv = measure("m6-doh-c2-channel")
    benign_rows, benign_cv = measure("b7-browser-doh")

    assert attack_rows >= 8 and benign_rows >= 8, (
        f"both sides must clear min_events=8 (attack {attack_rows}, benign {benign_rows})"
    )
    assert attack_cv <= _CV_PERIODIC, (
        f"m6 must measure as periodic to be flagged (cv {attack_cv:.3f} > {_CV_PERIODIC})"
    )
    assert benign_cv > _CV_MAX, (
        f"b7 must measure ABOVE the candidacy bar so the sweep clears it on "
        f"cadence rather than on address class (cv {benign_cv:.3f} <= {_CV_MAX})"
    )


# ---------------------------------------------------------------------------
# The DNS twins through the REAL entropy sweep — the m1 defect, third instance
# ---------------------------------------------------------------------------
#
# m2-dns-tunnel-exfil and b4-av-dns-reputation are the tunnel/reputation pair
# for `t_dns_entropy_scan` — the only scenarios whose story that sweep could
# ever measure. Both originally encoded their query volume as a pre-aggregated
# `zeek.dns_summary` document plus ONE raw `zeek.dns` row, while the sweep
# aggregates RAW rows and applies a `min_queries` floor (default 50, total
# queries per registrable parent) before a parent even counts as scanned: it
# returned `parents_scanned == 0` for both, rendering cleanly and measuring
# nothing. These tests drive the REAL tool over the rendered catalogue,
# reconstructing the qnames terms-agg response exactly as the tool's own ES
# query would produce it, so the numbers below are the tool's numbers.
#
# Note `t_dns_entropy_scan` does NOT exclude internal destinations (DNS
# resolvers ARE internal — see `_hunt_must_not(exclude_internal_dest=False)`
# in the tool), so unlike the beacon/first-seen twins these scenarios need no
# routable destination and no ROUTABLE_ADDRESS_REASONS entry.

M2_ID = "m2-dns-tunnel-exfil"
B4_ID = "b4-av-dns-reputation"
M2_PARENT = "update-cdn.click"
# The sweep's naive last-two-labels split resolves b4's
# `<hash>.filerep.avshield.example` qnames to parent `avshield.example` with
# `filerep` folded into the subdomain part — real tool behaviour, pinned here
# so nobody "fixes" a test to the story's three-label parent_domain.
B4_PARENT = "avshield.example"

RenderedDocs = list[tuple[str, dict[str, object], bool]]


def _dns_qnames_agg(docs: RenderedDocs) -> tuple[dict[str, Any], int]:
    """Rebuild the qnames terms-agg response the sweep's own query would get.

    Applies the tool's query semantics to the rendered documents: only raw
    ``event.dataset == "zeek.dns"`` rows participate (the pre-aggregated
    ``zeek.dns_summary`` documents are invisible to it — the defect class this
    section exists for), buckets are keyed by qname with ``doc_count`` equal
    to the row count, the terms agg caps at the tool's ``size`` with
    ``sum_other_doc_count`` carrying the overflow, and a ``top_hits`` sample
    rides along per bucket for citable ids. Returns ``(aggregations, total)``.
    """
    counts: Counter[str] = Counter()
    ids: dict[str, list[str]] = {}
    total = 0
    for index, body, _ in docs:
        if body.get("event.dataset") != "zeek.dns":
            continue
        qname = body.get("zeek.dns.query")
        assert isinstance(qname, str) and qname, f"{index}: raw zeek.dns row without a qname"
        total += 1
        counts[qname] += 1
        ids.setdefault(qname, []).append(f"{index}-{total}")

    ordered = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))
    dropped = sum(n for _, n in ordered[_QNAME_TERMS_SIZE:])
    buckets = [
        {
            "key": qname,
            "doc_count": n,
            "sample": {
                "hits": {
                    "total": {"value": n, "relation": "eq"},
                    "hits": [
                        {"_id": hit_id, "_source": {"zeek.dns.query": qname}}
                        for hit_id in ids[qname][:2]
                    ],
                }
            },
        }
        for qname, n in ordered[:_QNAME_TERMS_SIZE]
    ]
    aggs = {
        "qnames": {
            "doc_count_error_upper_bound": 0,
            "sum_other_doc_count": dropped,
            "buckets": buckets,
        }
    }
    return aggs, total


async def _run_dns_sweep(settings: Settings, docs: RenderedDocs) -> dict[str, Any]:
    """Run the REAL ``dns_entropy_scan`` against reconstructed rendered docs.

    Mocks only the ES transport (the ``ElasticClient.search`` wrapper), the
    same convention as ``tests/test_analytics_tools.py`` — the tool's own
    grouping, entropy math, floors and candidacy arms all execute for real.
    The single mocked result serves both the field-resolution probe (which
    reads ``total > 0``) and the aggregation query.
    """
    aggs, total = _dns_qnames_agg(docs)
    fake_es = AsyncMock()
    with patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=fake_es):
        client = ElasticClient(settings)
    result = EsSearchResult(total=total, took_ms=1, hits=[], aggregations=aggs)
    client.search = AsyncMock(return_value=result)  # type: ignore[method-assign]

    out = await dns_entropy_scan(elastic=client, settings=settings, include_synth=True)
    assert out.get("error") is not True, f"sweep errored: {out}"
    assert isinstance(out, dict)
    return out


def _raw_dns_rows(docs: RenderedDocs) -> list[dict[str, object]]:
    return [body for _, body, _ in docs if body.get("event.dataset") == "zeek.dns"]


async def test_dns_pair_is_visible_to_the_entropy_sweep(
    settings_kratos: Settings,
    rendered: dict[str, RenderedDocs],
) -> None:
    """The sweep must SCAN both sides of the pair before it can say anything.

    ``parents_scanned`` counts only parents whose raw-row volume cleared the
    ``min_queries`` floor — with the original one-raw-row encoding it was 0
    for both scenarios, so every clean render was measuring nothing."""
    for sid in (M2_ID, B4_ID):
        out = await _run_dns_sweep(settings_kratos, rendered[sid])
        floor = out["thresholds"]["min_queries_floor"]
        assert out["parents_scanned"] >= 1, (
            f"{sid}: parents_scanned == {out['parents_scanned']} — no parent's raw "
            f"zeek.dns volume cleared the min_queries floor ({floor}); the scenario "
            f"is invisible to t_dns_entropy_scan (the summary-doc-only encoding, "
            f"same defect class as the m1 beacon)"
        )


async def test_m2_tunnel_surfaces_from_its_raw_rows(
    settings_kratos: Settings,
    rendered: dict[str, RenderedDocs],
) -> None:
    """m2 must come back as a tunnel candidate, on the decisive-entropy arm.

    A planted slice cannot honestly carry the story's full 6,000-query volume,
    so the candidacy arm that must fire is the one built for exactly this
    case: ``entropy_mean >= _ENTROPY_EXTREME_MIN`` is decisive regardless of
    volume (a freshly-started tunnel has extreme entropy before it has
    volume). The raw rows must also carry the channel shape the verdict turns
    on: TXT/NULL-dominated qtypes and variable-length payload qnames."""
    out = await _run_dns_sweep(settings_kratos, rendered[M2_ID])
    items = {item["parent"]: item for item in out["items"]}
    assert M2_PARENT in items, (
        f"{M2_ID}: {M2_PARENT} is not a candidate (items: {sorted(items)}); the "
        f"tunnel the scenario narrates is invisible to the sweep it exists to feed"
    )
    item = items[M2_PARENT]
    assert item["entropy_mean"] >= _ENTROPY_EXTREME_MIN, (
        f"{M2_ID}: entropy_mean {item['entropy_mean']:.3f} is below the decisive "
        f"bar ({_ENTROPY_EXTREME_MIN}) — the only arm a slice-sized volume can clear"
    )
    assert item["queries"] >= out["thresholds"]["min_queries_floor"]
    assert item["subdomain_queries"] == item["queries"], (
        f"{M2_ID}: every tunnel query must carry an encoded subdomain "
        f"(apex volume contributes no entropy signal)"
    )
    assert item["sample_ids"], f"{M2_ID}: no citable sample ids — findings could not resolve"

    rows = _raw_dns_rows(rendered[M2_ID])
    qtypes = Counter(str(r.get("zeek.dns.qtype_name")) for r in rows)
    assert qtypes["TXT"] + qtypes["NULL"] > qtypes.get("A", 0), (
        f"{M2_ID}: qtype mix {dict(qtypes)} is not TXT/NULL-dominated — the "
        f"downstream data channel the story claims is missing from the rows"
    )
    qname_lengths = {len(str(r.get("zeek.dns.query"))) for r in rows}
    assert len(qname_lengths) >= 10, (
        f"{M2_ID}: only {len(qname_lengths)} distinct qname lengths — encoded "
        f"payload is variable-length; fixed-length rows would blur the b4 contrast"
    )


async def test_b4_reputation_twin_is_measured_and_cleared_on_channel_shape(
    settings_kratos: Settings,
    rendered: dict[str, RenderedDocs],
) -> None:
    """b4 must be scanned and NOT flagged — for the right reason.

    The twin was authored so entropy alone cannot separate it from the tunnel:
    hex hash subdomains ARE high-entropy, and this pins that property against
    the tool's own math (mean over the sweep's split subdomains sits at or
    above the candidacy entropy bar). What clears b4 at slice volume is the
    volume arms; what disposes it at verdict time is channel shape, which the
    raw rows must therefore actually carry: all-A qtypes (no downstream data
    channel), fixed-length hash qnames, and an answer space that collapses to
    a few loopback reputation codes (~nothing can be tunnelled back)."""
    out = await _run_dns_sweep(settings_kratos, rendered[B4_ID])
    assert out["parents_scanned"] == 1, (
        f"{B4_ID}: parents_scanned == {out['parents_scanned']}, want exactly 1 "
        f"({B4_PARENT} clearing the floor) — a negative control the instrument "
        f"skips proves nothing about the instrument"
    )
    flagged = {item["parent"] for item in out["items"]}
    assert B4_PARENT not in flagged, (
        f"{B4_ID}: {B4_PARENT} surfaced as a tunnel candidate {out['items']} — "
        f"if the benign twin flags identically the pair no longer discriminates"
    )

    rows = _raw_dns_rows(rendered[B4_ID])
    subs = []
    for row in rows:
        parent, sub = _split_registrable(str(row.get("zeek.dns.query")))
        assert parent == B4_PARENT
        assert sub
        subs.append(sub)

    # Entropy alone must NOT be what cleared it: the sweep-measured mean sits
    # in the high-entropy band (>= candidacy bar, < the decisive arm).
    entropy_mean = sum(_shannon_entropy_chars(s) for s in subs) / len(subs)
    assert entropy_mean >= _ENTROPY_MIN, (
        f"{B4_ID}: entropy_mean {entropy_mean:.3f} below {_ENTROPY_MIN} — the twin "
        f"only does its job if hash lookups measure as high-entropy as the alarm says"
    )
    assert entropy_mean < _ENTROPY_EXTREME_MIN, (
        f"{B4_ID}: entropy_mean {entropy_mean:.3f} reached the decisive arm "
        f"({_ENTROPY_EXTREME_MIN}) — the benign twin would flag on entropy alone"
    )
    # What actually clears it at slice volume: both volume arms.
    assert len(rows) < _QUERIES_MIN and len(set(subs)) < _UNIQUE_SUBDOMAINS_MIN

    # The discriminating channel shape, present in the rows themselves.
    qtypes = {str(r.get("zeek.dns.qtype_name")) for r in rows}
    assert qtypes == {"A"}, f"{B4_ID}: qtypes {qtypes} — reputation lookups are all-A"
    assert len({len(str(r.get("zeek.dns.query"))) for r in rows}) == 1, (
        f"{B4_ID}: qname lengths vary — a hash is fixed-length, encoded payload is not"
    )
    answers = {str(a) for r in rows for a in (r.get("zeek.dns.answers") or [])}
    assert answers and len(answers) <= 3, (
        f"{B4_ID}: {len(answers)} distinct answers — the reputation answer space "
        f"must collapse to a few codes (no return channel)"
    )
    assert all(ipaddress.ip_address(a).is_loopback for a in answers), (
        f"{B4_ID}: answers {sorted(answers)} are not loopback reputation codes"
    )


async def test_dns_twins_discriminate_within_one_sweep(
    settings_kratos: Settings,
    rendered: dict[str, RenderedDocs],
) -> None:
    """One sweep over both scenarios' documents: exactly the tunnel flags.

    This is the pair's whole purpose stated as a single measurement — both
    parents cleared the floor (both were EVALUATED), and only m2 came back a
    candidate. If b4 ever joins the items list, or m2 ever leaves it, the
    twins have stopped discriminating and the catalogue is measuring
    obedience to the alert text rather than behaviour."""
    out = await _run_dns_sweep(settings_kratos, rendered[M2_ID] + rendered[B4_ID])
    assert out["parents_scanned"] == 2, (
        f"parents_scanned == {out['parents_scanned']}, want both {M2_PARENT} and "
        f"{B4_PARENT} clearing the min_queries floor"
    )
    flagged = {item["parent"] for item in out["items"]}
    assert flagged == {M2_PARENT}, (
        f"flagged parents {sorted(flagged)}, want exactly {{{M2_PARENT!r}}} — the "
        f"attack/benign pair must discriminate inside a single measurement"
    )


# ---------------------------------------------------------------------------
# Sensor identity — host.name is a pivot key, observer.name is not
# ---------------------------------------------------------------------------
#
# Verified against the live grid: of 669,915 real ``suricata.alert``
# documents, ZERO carry a top-level ``host.name`` — Security Onion strips the
# shipper's ``host.*`` from network-sensor documents and the sensor identity
# rides ``observer.name``. The catalogue used to stamp
# ``host.name: so-sensor-1`` (and ``agent.name``) on every triage alert: a
# document shape that does not exist in reality, and one that welded all 25
# scenarios onto a single host key. The ``host.name`` prefetch pivot then
# returned the triage alerts of unrelated sibling scenarios —
# b3-rmm-admin-lateral was escalated to a false positive on two of them.

_NETWORK_SENSOR_PREFIXES = ("suricata.", "zeek.")


def _is_network_sensor_body(body: dict[str, object]) -> bool:
    dataset = str(body.get("event.dataset") or "")
    module = str(body.get("event.module") or "")
    return dataset.startswith(_NETWORK_SENSOR_PREFIXES) or module in {"suricata", "zeek"}


def test_network_sensor_events_carry_no_shipper_host_identity(
    rendered: dict[str, list[tuple[str, dict[str, object], bool]]],
) -> None:
    """No network-sensor document stamps a shipper identity into
    ``host.name``/``agent.name`` — real SO network-sensor docs carry neither,
    and a shared sensor literal is a cross-scenario pivot bridge."""
    for sid, docs in rendered.items():
        for index, body, _ in docs:
            if not _is_network_sensor_body(body):
                continue
            for forbidden in ("host.name", "agent.name"):
                assert forbidden not in body, (
                    f"{sid}/{index}: stamps {forbidden}={body.get(forbidden)!r}; "
                    f"real Security Onion network-sensor docs carry no shipper "
                    f"{forbidden} — the sensor identity belongs in observer.name"
                )


def test_triage_alerts_name_their_sensor_via_observer_name(
    rendered: dict[str, list[tuple[str, dict[str, object], bool]]],
) -> None:
    """The triage alert identifies its sensor where real SO documents do."""
    for sid, docs in rendered.items():
        body = next(b for _, b, is_triage in docs if is_triage)
        observer = body.get("observer.name")
        assert isinstance(observer, str) and observer, (
            f"{sid}: triage alert carries no observer.name — the sensor "
            f"identity belongs there (that is where Security Onion puts it)"
        )


def test_no_scenario_reuses_a_sensor_name_as_a_host_name(
    rendered: dict[str, list[tuple[str, dict[str, object], bool]]],
) -> None:
    """A name used anywhere as ``observer.name`` never doubles as a
    ``host.name`` — belt-and-braces for future endpoint-dataset scenarios,
    whose genuine ``host.name`` values are legitimate pivot keys."""
    sensor_names = {
        str(body["observer.name"])
        for docs in rendered.values()
        for _, body, _ in docs
        if body.get("observer.name")
    }
    assert sensor_names, "expected at least one observer.name in the catalogue"
    for sid, docs in rendered.items():
        for index, body, _ in docs:
            host = body.get("host.name")
            assert host not in sensor_names, (
                f"{sid}/{index}: uses sensor name {host!r} as host.name"
            )

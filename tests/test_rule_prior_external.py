"""The rule prior on an alert with one external address (safeguard 1, round prior-b).

Safeguard 1 used to hold back every alert with an external address. Now an
alert with one internal and one external address is covered when the external
address is known for the rule on that internal machine: two or more
model-backed false positives of the rule in the last 7 days had the same
internal address and an external address that matches it. A match is the same
address, the same network (IPv4 /24, IPv6 /64) or the same name of the external
end. Most tests here are negative controls on the path that a loose match
would miss.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any
from unittest.mock import AsyncMock, patch

from soc_ai.agent import rule_prior
from soc_ai.config import Settings
from soc_ai.so_client.elastic import EsSearchResult
from soc_ai.store import rule_prior as prior_store
from soc_ai.store.auth import utcnow
from soc_ai.store.models import EntityObservation, Investigation, InvestigationEvent, Lead
from soc_ai.webui import alerts_query as aq
from soc_ai.webui import autotriage as at

from tests.test_rule_prior import (
    DST,
    OUTSIDE,
    SRC,
    _decide,
    _decisions,
    _run,
    _settings,
    _store,
    _sweep,
    _target,
)

NEAR = "203.0.113.7"  # same /24 as OUTSIDE
FAR = "198.18.0.9"  # another external network
NAME = "updates.example.test"


async def _seed(
    maker: Any,
    *,
    internal: int = 3,
    external: list[tuple[str, str]] | None = None,
    contexts: dict[int, Any] | None = None,
    verdicts: dict[int, str] | None = None,
    start: float = 1.0,
) -> None:
    """``internal`` runs between two internal machines, then one run per
    (src, dst) pair in ``external``. ``contexts`` maps a run number to the
    payload of its stored alert context."""
    async with maker() as db:
        n = 0
        for _ in range(internal):
            db.add(_run(n, hours_ago=start + n, verdict=(verdicts or {}).get(n, "false_positive")))
            n += 1
        for src, dst in external or []:
            db.add(
                _run(
                    n,
                    hours_ago=start + n,
                    src_ip=src,
                    dest_ip=dst,
                    verdict=(verdicts or {}).get(n, "false_positive"),
                )
            )
            n += 1
        await db.commit()
        for run_n, payload in (contexts or {}).items():
            db.add(
                InvestigationEvent(
                    investigation_id=f"run{run_n:022d}",
                    sequence=2,
                    kind="enriched_alert_context",
                    payload=payload,
                )
            )
        await db.commit()


def _sni(*names: str) -> dict[str, Any]:
    return {"alert": {"id": "a"}, "typed_zeek": {"sni_servers": list(names)}}


# ── Covered ──────────────────────────────────────────────────────────────────


async def test_the_same_external_address_twice_is_known(settings_kratos: Settings) -> None:
    settings = _settings(settings_kratos)
    engine, maker = await _store(settings)
    await _seed(maker, external=[(SRC, OUTSIDE), (SRC, OUTSIDE)])
    out = await _decide(maker, settings, _target(dst_ip=OUTSIDE))
    # The direction does not change the match: the reply of the server matches too.
    back = await _decide(maker, settings, _target(src_ip=OUTSIDE, dst_ip=SRC))
    await engine.dispose()
    assert (out.applies, out.reason) == (True, "covered_known_external")
    assert (back.applies, back.reason) == (True, "covered_known_external")
    # The source is the newest run on this internal machine and this external end.
    assert out.source_id == f"run{3:022d}"
    assert out.would_verdict == "false_positive"
    assert out.runs_in_window == 5


async def test_the_same_network_is_known(settings_kratos: Settings) -> None:
    settings = _settings(settings_kratos)
    engine, maker = await _store(settings)
    await _seed(maker, external=[(SRC, NEAR), (SRC, NEAR)])
    v4 = await _decide(maker, settings, _target(dst_ip=OUTSIDE))
    other24 = await _decide(maker, settings, _target(dst_ip="203.0.114.7"))
    await engine.dispose()
    assert (v4.applies, v4.reason) == (True, "covered_known_external")
    assert (other24.applies, other24.reason) == (False, "external_endpoint_new")


async def test_the_same_ipv6_network_is_known(settings_kratos: Settings) -> None:
    settings = _settings(settings_kratos)
    engine, maker = await _store(settings)
    await _seed(maker, external=[(SRC, "2001:db8:1:2::5"), (SRC, "2001:db8:1:2::6")])
    v6 = await _decide(maker, settings, _target(dst_ip="2001:db8:1:2::99"))
    other64 = await _decide(maker, settings, _target(dst_ip="2001:db8:1:3::5"))
    await engine.dispose()
    assert (v6.applies, v6.reason) == (True, "covered_known_external")
    assert (other64.applies, other64.reason) == (False, "external_endpoint_new")


async def test_the_same_name_of_the_external_end_is_known(settings_kratos: Settings) -> None:
    settings = _settings(settings_kratos)
    engine, maker = await _store(settings)
    await _seed(
        maker,
        external=[(SRC, NEAR), (SRC, NEAR)],
        contexts={3: _sni(NAME), 4: {"alert": {"zeek_http_host": "Updates.Example.Test:8080"}}},
    )
    named = await _decide(maker, settings, _target(dst_ip=FAR, external_names=(NAME + ".",)))
    await engine.dispose()
    assert (named.applies, named.reason) == (True, "covered_known_external")


# ── Negative controls ────────────────────────────────────────────────────────


async def test_a_new_external_address_is_not_covered(settings_kratos: Settings) -> None:
    settings = _settings(settings_kratos)
    engine, maker = await _store(settings)
    await _seed(maker, external=[(SRC, NEAR), (SRC, NEAR)], contexts={3: _sni(NAME), 4: _sni(NAME)})
    # Another network, and no name on the alert.
    new = await _decide(maker, settings, _target(dst_ip=FAR))
    # Another name.
    other_name = await _decide(
        maker, settings, _target(dst_ip=FAR, external_names=("other.example.test",))
    )
    await engine.dispose()
    assert (new.applies, new.reason) == (False, "external_endpoint_new")
    assert (other_name.applies, other_name.reason) == (False, "external_endpoint_new")


async def test_one_earlier_false_positive_is_not_enough(settings_kratos: Settings) -> None:
    settings = _settings(settings_kratos)
    engine, maker = await _store(settings)
    await _seed(maker, internal=4, external=[(SRC, OUTSIDE)])
    decision = await _decide(maker, settings, _target(dst_ip=OUTSIDE))
    await engine.dispose()
    assert (decision.applies, decision.reason) == (False, "external_endpoint_new")


async def test_a_known_external_address_of_another_machine_does_not_count(
    settings_kratos: Settings,
) -> None:
    settings = _settings(settings_kratos)
    engine, maker = await _store(settings)
    await _seed(maker, external=[(DST, OUTSIDE), (DST, OUTSIDE)])
    decision = await _decide(maker, settings, _target(dst_ip=OUTSIDE))
    await engine.dispose()
    assert (decision.applies, decision.reason) == (False, "external_endpoint_new")


async def test_a_true_positive_of_the_rule_in_the_window_still_blocks(
    settings_kratos: Settings,
) -> None:
    settings = _settings(settings_kratos)
    engine, maker = await _store(settings)
    # The true positive is on another pair. It holds every alert of the rule.
    await _seed(
        maker,
        internal=3,
        external=[(SRC, OUTSIDE), (SRC, OUTSIDE), (SRC, OUTSIDE)],
        verdicts={0: "true_positive"},
    )
    decision = await _decide(maker, settings, _target(dst_ip=OUTSIDE))
    await engine.dispose()
    assert (decision.applies, decision.reason) == (False, "non_false_positive_in_window")


async def test_two_external_addresses_are_held_as_before(settings_kratos: Settings) -> None:
    settings = _settings(settings_kratos)
    engine, maker = await _store(settings)
    await _seed(maker, external=[(FAR, OUTSIDE), (FAR, OUTSIDE)])
    decision = await _decide(maker, settings, _target(src_ip=FAR, dst_ip=OUTSIDE))
    unreadable = await _decide(maker, settings, _target(dst_ip="not-an-address"))
    await engine.dispose()
    assert (decision.applies, decision.reason) == (False, "external_endpoint")
    assert (unreadable.applies, unreadable.reason) == (False, "external_endpoint")


async def test_an_old_match_outside_the_window_does_not_count(settings_kratos: Settings) -> None:
    settings = _settings(settings_kratos)
    engine, maker = await _store(settings)
    await _seed(maker, internal=5, external=[(SRC, OUTSIDE)])
    async with maker() as db:
        db.add(_run(40, hours_ago=24 * 8, dest_ip=OUTSIDE))
        await db.commit()
    decision = await _decide(maker, settings, _target(dst_ip=OUTSIDE))
    await engine.dispose()
    assert (decision.applies, decision.reason) == (False, "external_endpoint_new")


async def test_an_unreadable_name_gives_no_match(settings_kratos: Settings) -> None:
    """A name that is no host name, a broken context or a name on the wrong end."""
    settings = _settings(settings_kratos)
    engine, maker = await _store(settings)
    await _seed(
        maker,
        external=[(SRC, NEAR), (SRC, NEAR), (NEAR, SRC)],
        contexts={
            3: ["not", "a", "mapping"],
            4: {"alert": {"zeek_http_host": "-"}, "typed_zeek": {"sni_servers": "x.test"}},
            # The external end is the source of this flow. Its name names the
            # internal server, so it never counts.
            5: _sni(NAME),
        },
    )
    blank = await _decide(maker, settings, _target(dst_ip=FAR, external_names=("-",)))
    literal = await _decide(maker, settings, _target(dst_ip=FAR, external_names=(NEAR,)))
    named = await _decide(maker, settings, _target(dst_ip=FAR, external_names=(NAME,)))
    inbound = await _decide(
        maker, settings, _target(src_ip=FAR, dst_ip=SRC, external_names=(NAME,))
    )
    await engine.dispose()
    for decision in (blank, literal, named, inbound):
        assert (decision.applies, decision.reason) == (False, "external_endpoint_new")


async def test_a_store_error_fails_closed(settings_kratos: Settings) -> None:
    settings = _settings(settings_kratos)
    engine, maker = await _store(settings)
    await _seed(maker, external=[(SRC, NEAR), (SRC, NEAR)])

    async def broken(*_a: Any, **_kw: Any) -> Any:
        raise RuntimeError("the store is gone")

    with patch.object(prior_store, "stored_external_names", broken):
        named = await _decide(maker, settings, _target(dst_ip=FAR, external_names=(NAME,)))
    with patch.object(prior_store, "model_backed_runs", broken):
        runs = await _decide(maker, settings, _target(dst_ip=OUTSIDE))
    await engine.dispose()
    assert (named.applies, named.reason) == (False, "evaluation_failed")
    assert (runs.applies, runs.reason) == (False, "evaluation_failed")


# ── The sweep and the grid read ──────────────────────────────────────────────


async def test_shadow_still_runs_the_model_on_a_known_external_alert(
    settings_kratos: Settings,
) -> None:
    settings = _settings(settings_kratos)
    engine, maker = await _store(settings)
    await _seed(maker, external=[(SRC, OUTSIDE), (SRC, OUTSIDE)])
    calls = await _sweep(settings, maker, verdict="true_positive", draw=0.5, dst_ip=OUTSIDE)
    rows = await _decisions(maker)
    later = await _decide(maker, settings, _target(dst_ip=OUTSIDE))
    await engine.dispose()
    # Shadow: the model reads the alert. The disagreement suspends the rule.
    assert calls == ["ev-new"]
    assert (rows[0].applies, rows[0].reason, rows[0].agree) == (
        True,
        "covered_known_external",
        False,
    )
    assert (later.applies, later.reason) == (False, "suspended")


def test_the_planner_hands_the_names_of_the_alert_to_the_prior() -> None:
    target = at.Target(
        alert_es_id="a",
        rule_name="r",
        src_ip=SRC,
        dst_ip=OUTSIDE,
        severity="low",
        external_names=(NAME,),
    )
    assert at._prior_target(target).external_names == (NAME,)


async def test_the_grid_read_takes_the_names_of_the_alert_document(
    settings_kratos: Settings,
) -> None:
    elastic = AsyncMock()
    elastic.search.return_value = EsSearchResult(
        total=2,
        took_ms=1,
        aggregations=None,
        hits=[
            {
                "_id": "ev1",
                "_source": {
                    "@timestamp": "2026-06-12T06:41:00.000Z",
                    "source": {"ip": SRC},
                    "destination": {"ip": OUTSIDE},
                    "ssl": {"server_name": NAME},
                    "http": {"virtual_host": "web.example.test"},
                    "dns": {"query": {"name": "q.example.test"}},
                },
            },
            {"_id": "ev2", "_source": {"@timestamp": "2026-06-12T06:40:00.000Z"}},
        ],
    )
    events = await aq.fetch_group_events(elastic, settings_kratos, rule_name="r", time_range="24h")
    assert events[0].external_names == (NAME, "web.example.test", "q.example.test")
    assert events[1].external_names == ()
    assert rule_prior.EXTERNAL_ENDPOINT_NEW == "external_endpoint_new"


# ── P3: every other safeguard holds on the known external path ───────────────


async def _known(settings_kratos: Settings, **kw: Any) -> tuple[Settings, Any, Any]:
    """A store where SRC to OUTSIDE is known: five false positives, two on the pair."""
    settings = _settings(settings_kratos, **kw)
    engine, maker = await _store(settings)
    await _seed(maker, external=[(SRC, OUTSIDE), (SRC, OUTSIDE)])
    return settings, engine, maker


async def test_the_floor_of_five_runs_stays(settings_kratos: Settings) -> None:
    settings = _settings(settings_kratos)
    engine, maker = await _store(settings)
    await _seed(maker, internal=2, external=[(SRC, OUTSIDE), (SRC, OUTSIDE)])
    decision = await _decide(maker, settings, _target(dst_ip=OUTSIDE))
    await engine.dispose()
    assert (decision.applies, decision.reason) == (False, "too_few_runs")


async def test_the_lapse_and_the_critical_hold_stay(settings_kratos: Settings) -> None:
    settings = _settings(settings_kratos)
    engine, maker = await _store(settings)
    await _seed(maker, external=[(SRC, OUTSIDE), (SRC, OUTSIDE)], start=25.0)
    lapsed = await _decide(maker, settings, _target(dst_ip=OUTSIDE))
    critical = await _decide(maker, settings, _target(dst_ip=OUTSIDE, severity="critical"))
    await engine.dispose()
    assert (lapsed.applies, lapsed.reason) == (False, "lapsed")
    assert (critical.applies, critical.reason) == (False, "critical_severity")


async def test_a_lead_or_an_observation_on_either_end_holds(settings_kratos: Settings) -> None:
    settings, engine, maker = await _known(settings_kratos)
    async with maker() as db:
        db.add(Lead(status="open", entities_json=[["host", OUTSIDE]], kinds_json=["alert"]))
        await db.commit()
    with_lead = await _decide(maker, settings, _target(dst_ip=OUTSIDE))
    async with maker() as db:
        db.add(
            EntityObservation(
                entity_kind="host",
                entity_key=SRC,
                kind="alert",
                spec_id="alert",
                fingerprint="fp-ext",
                observed_at=utcnow() - timedelta(hours=1),
            )
        )
        await db.commit()
    with_observation = await _decide(maker, settings, _target(dst_ip=OUTSIDE, alert_es_id="ev-obs"))
    await engine.dispose()
    assert (with_lead.applies, with_lead.reason) == (False, "open_lead_or_fresh_observation")
    assert (with_observation.applies, with_observation.reason) == (
        False,
        "open_lead_or_fresh_observation",
    )


async def test_the_nomination_the_override_and_the_suspension_hold(
    settings_kratos: Settings,
) -> None:
    settings, engine, maker = await _known(settings_kratos)
    target = _target(dst_ip=OUTSIDE)
    other = await _decide(maker, settings, target, nominated=frozenset({"ET OTHER"}))
    blind = await _decide(maker, settings, target, nominated=None)
    async with maker() as db:
        row = await prior_store.record_decision(
            db,
            rule_name=target.rule_name,
            alert_es_id="old",
            mode="shadow",
            applies=True,
            reason="covered_known_external",
            sampled=False,
            would_verdict="false_positive",
        )
        await prior_store.settle_decision(
            db, row.id, investigation_id="x", real_verdict="true_positive"
        )
    suspended = await _decide(maker, settings, target)
    async with maker() as db:
        await prior_store.clear_suspension(db, target.rule_name, by="analyst")
        db.add(
            _run(
                90,
                hours_ago=24 * 40,
                report={"verdict": "false_positive", "resolution": {"resolved_via": "chat"}},
            )
        )
        await db.commit()
    override = await _decide(maker, settings, target)
    await engine.dispose()
    assert (other.applies, other.reason) == (False, "not_nominated")
    assert (blind.applies, blind.reason) == (False, "nomination_unavailable")
    assert (suspended.applies, suspended.reason) == (False, "suspended")
    assert (override.applies, override.reason) == (False, "analyst_override")


async def test_the_sample_still_picks_a_known_external_alert(settings_kratos: Settings) -> None:
    settings, engine, maker = await _known(settings_kratos)
    picked = await _decide(maker, settings, _target(dst_ip=OUTSIDE), draw=0.0)
    passed = await _decide(maker, settings, _target(dst_ip=OUTSIDE), draw=0.5)
    await engine.dispose()
    assert (picked.applies, picked.sampled) == (True, True)
    assert (passed.applies, passed.sampled) == (True, False)


async def test_live_mode_never_acknowledges_a_known_external_alert(
    settings_kratos: Settings,
) -> None:
    settings, engine, maker = await _known(settings_kratos, rule_prior_mode="live")
    calls = await _sweep(settings, maker, verdict="true_positive", draw=0.99, dst_ip=OUTSIDE)
    rows = await _decisions(maker)
    async with maker() as db:
        covered = await db.get(Investigation, rows[0].investigation_id)
    await engine.dispose()
    assert calls == []
    assert covered is not None
    report = covered.report or {}
    assert report["recommended_actions"] == []
    assert report["run_class_reason"] == "covered_known_external"
    assert "matching external address" in report["summary"]


def test_the_defaults_and_the_thresholds_stay() -> None:
    fields = Settings.model_fields
    assert fields["rule_prior_mode"].default == "shadow"
    assert fields["rule_prior_min_runs"].default == 5
    assert fields["rule_prior_sample_rate"].default == 0.02
    assert (rule_prior.WINDOW_DAYS, rule_prior.LAPSE_HOURS) == (7, 24)
    assert rule_prior.FRESH_OBSERVATION_HOURS == 24
    assert rule_prior.KNOWN_EXTERNAL_RUNS == 2


# ── P4: the record the owner reads after one week ────────────────────────────


async def test_the_stats_split_the_covers_and_the_disagreements(
    settings_kratos: Settings,
) -> None:
    settings = _settings(settings_kratos)
    engine, maker = await _store(settings)
    common = {"rule_name": "ET R", "mode": "shadow", "would_verdict": "false_positive"}

    async with maker() as db:

        async def decide(alert: str, reason: str, real: str | None, applies: bool = True) -> None:
            row = await prior_store.record_decision(
                db, alert_es_id=alert, applies=applies, reason=reason, sampled=False, **common
            )
            if real is not None:
                await prior_store.settle_decision(
                    db, row.id, investigation_id=alert, real_verdict=real
                )

        await decide("a", "covered", "false_positive")
        await decide("b", "covered", "true_positive")
        await decide("c", "covered_known_external", "false_positive")
        await decide("d", "covered_known_external", "false_positive")
        await decide("e", "covered_known_external", "true_positive")
        # A held alert is in no count, whatever its real verdict.
        await decide("f", "external_endpoint_new", "true_positive", applies=False)
        stats = (await prior_store.stats_by_rule(db, ["ET R"]))["ET R"]
    await engine.dispose()
    assert (stats.covered, stats.disagreements) == (5, 2)
    assert (stats.covered_internal, stats.disagreements_internal) == (2, 1)
    assert (stats.covered_known_external, stats.disagreements_known_external) == (3, 1)
    assert stats.last_reason == "external_endpoint_new"


def test_the_panel_route_carries_the_split(settings_kratos: Settings) -> None:
    import asyncio

    from soc_ai.webui.detection_tuning import NominationPage

    from tests.test_investigations_query import _client

    gen = _client(_settings(settings_kratos))
    client = next(gen)
    try:

        async def seed() -> None:
            async with client.app.state.db_sessionmaker() as db:
                await prior_store.record_decision(
                    db,
                    rule_name="ET R",
                    alert_es_id="a",
                    mode="shadow",
                    applies=True,
                    reason="covered_known_external",
                    sampled=False,
                    would_verdict="false_positive",
                )

        asyncio.run(seed())

        async def nominate_page(_state: Any) -> NominationPage:
            row = {
                "rule_name": "ET R",
                "alert_count": 9,
                "investigations": 9,
                "fp": 9,
                "tp": 0,
                "nmi": 0,
                "recommendation": "mute",
                "reason": "all false positive",
                "already_muted": False,
            }
            return NominationPage(nominations=[row], alert_total=9)

        with patch("soc_ai.webui.detection_tuning.nominate_page", nominate_page):
            row = client.get("/api/v1/detection-tuning").json()["nominations"][0]
    finally:
        gen.close()
    assert row["prior_covered"] == 1
    assert (row["prior_covered_internal"], row["prior_covered_known_external"]) == (0, 1)
    assert row["prior_disagreements_internal"] == 0
    assert row["prior_disagreements_known_external"] == 0

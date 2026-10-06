"""The learned group as the second peer source.

A host with a confident role reads its role, as before. A host without one
reads the learned group the estate model gave it, while the model is on and
its newest fit is measured and fresh. No ``ml`` extra is needed: the tests
write the fit and the groups straight into the store.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from soc_ai.config import Settings
from soc_ai.hunting import prior_sweep
from soc_ai.hunting.estate import LearnedPeers, peer_profiles, peer_source
from soc_ai.store import entity_profiles as ep
from soc_ai.store import estate_model as store
from soc_ai.store.db import make_engine, make_sessionmaker, run_migrations

SHA = "b" * 64
GROUP_ONE = [f"192.0.2.{n}" for n in range(1, 8)]
GROUP_TWO = [f"198.51.100.{n}" for n in range(1, 8)]
TARGET = "192.0.2.50"


def _now() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None, microsecond=0)


async def _seed(
    settings: Settings, *, state: str = store.STATE_MEASURED, age: timedelta = timedelta(hours=2)
) -> Any:
    engine = make_engine(settings)
    await run_migrations(engine)
    maker = make_sessionmaker(engine)
    at = _now() - age
    async with maker() as db:
        for key in [*GROUP_ONE, *GROUP_TWO, TARGET]:
            ports = {"443": {"count": 50, "first_seen": None, "last_seen": None}}
            if key in GROUP_ONE:
                ports["8443"] = {"count": 50}
            await ep.upsert_profile(
                db,
                entity_kind="host",
                entity_key=key,
                dimension="served_ports",
                shape="categorical",
                vector=ports,
                support_days=20,
                # The last member of group one is blind on this dimension.
                coverage="blind" if key == GROUP_ONE[-1] else "measured",
            )
        await store.record_fit(
            db,
            fitted_at=at,
            state=state,
            model_sha256=SHA,
            model_file="estate-b.json",
            groups_detail=[
                {"id": 1, "size": 8, "centroid": {"served_ports.members": 2.0}},
                {"id": 2, "size": 7, "centroid": {"served_ports.members": 1.0}},
            ],
        )
        rows = [store.GroupRow(k, 1, 0.1, 0.4) for k in [*GROUP_ONE, TARGET]]
        rows += [store.GroupRow(k, 2, 0.1, 0.4) for k in GROUP_TWO]
        rows.append(store.GroupRow("ws01", 2, 0.1, 0.4))
        await store.replace_groups(db, rows, model_sha256=SHA, fitted_at=at)
    return engine, maker


async def test_a_confident_role_comes_first(settings_kratos: Settings) -> None:
    engine, maker = await _seed(settings_kratos)
    async with maker() as db:
        source = await peer_source(
            db,
            entity_key=TARGET,
            role="server",
            confidence=1.0,
            learned=LearnedPeers(enabled=True),
        )
    await engine.dispose()
    assert source is not None
    assert (source.kind, source.label, source.role) == ("role", "server", "server")


async def test_a_host_with_no_role_reads_its_learned_group(settings_kratos: Settings) -> None:
    engine, maker = await _seed(settings_kratos)
    learned = LearnedPeers(enabled=True)
    async with maker() as db:
        guessed = await peer_source(
            db, entity_key=TARGET, role="server", confidence=0.5, learned=learned
        )
        source = await peer_source(
            db, entity_key=TARGET, role=None, confidence=0.0, learned=learned
        )
        assert source is not None
        rows = await peer_profiles(db, source, dimension="served_ports", learned=learned)
        named = await peer_source(
            db, entity_key="WS01.corp.example", role=None, confidence=0.0, learned=learned
        )
    await engine.dispose()
    # A role below the confidence gate is a guess. The learned group stands in.
    assert guessed is not None and guessed.kind == "learned"
    assert (source.kind, source.label, source.group_id) == ("learned", "learned group 1", 1)
    # The scorable members of the group, the target among them. The blind one is out.
    assert sorted(r.entity_key for r in rows) == sorted([*GROUP_ONE[:-1], TARGET])
    # A host name finds its group by the folded short name, as a role does.
    assert named is not None and named.group_id == 2


async def test_no_learned_group_when_the_model_is_off(settings_kratos: Settings) -> None:
    engine, maker = await _seed(settings_kratos)
    async with maker() as db:
        off = await peer_source(
            db, entity_key=TARGET, role=None, confidence=0.0, learned=LearnedPeers()
        )
        none = await peer_source(db, entity_key=TARGET, role=None, confidence=0.0, learned=None)
    await engine.dispose()
    assert off is None
    assert none is None


async def test_no_learned_group_from_a_drifted_or_stale_fit(settings_kratos: Settings) -> None:
    for state, age in (
        (store.STATE_DRIFTED, timedelta(hours=2)),
        (store.STATE_LEARNING, timedelta(hours=2)),
        (store.STATE_HELD, timedelta(hours=2)),
        (store.STATE_MEASURED, timedelta(hours=49)),
    ):
        engine, maker = await _seed(settings_kratos, state=state, age=age)
        async with maker() as db:
            source = await peer_source(
                db,
                entity_key=TARGET,
                role=None,
                confidence=0.0,
                learned=LearnedPeers(enabled=True),
            )
        await engine.dispose()
        assert source is None, (state, age)
        (settings_kratos.soc_ai_data_dir / "soc-ai.db").unlink()


async def test_the_sweep_reads_the_learned_group_as_the_peer_view(
    settings_kratos: Settings,
) -> None:
    """The one change in the prior sweep: its peer lookup asks the peer source."""
    engine, maker = await _seed(settings_kratos)
    on = prior_sweep._context_for(settings_kratos.model_copy(update={"estate_model_enabled": True}))
    off = prior_sweep._context_for(settings_kratos)
    async with maker() as db:
        view = await on.peer_view(
            db,
            role=None,
            confidence=0.0,
            dimension="served_ports",
            entity_key=TARGET,
            min_peers=5,
        )
        nothing = await off.peer_view(
            db,
            role=None,
            confidence=0.0,
            dimension="served_ports",
            entity_key=TARGET,
            min_peers=5,
        )
    await engine.dispose()
    assert nothing is None
    assert view is not None
    assert view.role == "learned group 1"
    # Six scorable peers: the seven of group one, less the blind one. The
    # target itself is not its own peer.
    assert view.peers == 6
    assert view.measurable
    assert view.held_by("8443") == 6
    assert view.trait("8443")

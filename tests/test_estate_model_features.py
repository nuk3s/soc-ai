"""Per-host behaviour vectors: the numbers the estate model reads, and their names.

Pure Python. These tests run with or without the ``ml`` extra.
"""

from __future__ import annotations

import math

import pytest
from soc_ai.config import Settings
from soc_ai.hunting.estate_model import features as ft
from soc_ai.store.db import make_engine, make_sessionmaker, run_migrations

from tests import estate_fixture as fx


def test_a_set_row_gives_its_member_count_and_its_documents_per_day() -> None:
    vector = {"22": {"count": 300}, "443": {"count": 600}}
    out = ft.reduce_row("served_ports", "measured", vector, support_days=30)
    assert out == {
        "plane.flow": 1.0,
        "served_ports.members": 2.0,
        "served_ports.per_day": 30.0,
    }


def test_a_learning_row_counts_and_a_blind_row_adds_nothing() -> None:
    """Learning describes what the host does. Blind describes what soc-ai cannot see."""
    vector = {"svchost.exe": {"count": 10}}
    assert ft.reduce_row("process_names", "learning", vector, support_days=2)["plane.process"] == 1
    assert ft.reduce_row("process_names", "blind", vector, support_days=2) == {}
    assert ft.reduce_row("process_names", "unmeasurable", vector, support_days=2) == {}


def test_the_active_hours_give_the_hours_and_the_night_share() -> None:
    vector = {"2": {"count": 30}, "9": {"count": 60}, "10": {"count": 10}, "x": {"count": 5}}
    out = ft.reduce_row("active_hours", "measured", vector, support_days=30)
    assert out["active_hours.hours"] == 3.0
    assert out["active_hours.night_share"] == pytest.approx(0.3)


def test_the_connection_rate_gives_one_median_per_cell() -> None:
    vector = fx._rate(50.0, 5.0, 2.0)
    out = ft.reduce_row("connection_rate", "measured", vector, support_days=30)
    assert out["connection_rate.work"] == 50.0
    assert out["connection_rate.off"] == 5.0
    assert out["connection_rate.weekend"] == 2.0


def test_one_vector_per_host_and_a_host_with_nothing_covered_is_blind() -> None:
    rows = [
        ("192.0.2.1", "served_ports", "measured", 30, None, None, {"22": {"count": 30}}),
        ("192.0.2.1", "dns_names", "learning", 3, None, None, {"a.example": {"count": 3}}),
        ("192.0.2.2", "process_names", "blind", 0, None, None, None),
    ]
    out = ft.vectors_from_rows(rows)
    assert [v.entity_key for v in out.vectors] == ["192.0.2.1"]
    assert out.blind == 1
    host = out.vectors[0]
    assert host.support_days == 30
    assert host.raw["plane.flow"] == 1.0
    assert host.raw["plane.dns"] == 1.0
    assert "plane.process" not in host.raw


def test_only_a_declared_role_enters_the_vector() -> None:
    """An inference at 0.9 is a belief. The one-hot names what an operator declared."""
    rows = [
        ("192.0.2.1", "served_ports", "measured", 30, "server", 1.0, {"22": {"count": 30}}),
        ("192.0.2.2", "served_ports", "measured", 30, "printer", 0.9, {"22": {"count": 30}}),
    ]
    vectors = ft.vectors_from_rows(rows).vectors
    names = [f.name for f in ft.feature_list(vectors)]
    assert "role.server" in names
    assert "role.printer" not in names
    raw, model = ft.matrix(vectors, ft.feature_list(vectors))
    column = names.index("role.server")
    assert [row[column] for row in raw] == [1.0, 0.0]
    assert [row[column] for row in model] == [1.0, 0.0]


def test_the_names_sit_beside_the_columns_in_a_fixed_order() -> None:
    hosts = fx.estate(planted=False)[:3]
    vectors = ft.vectors_from_rows(fx.rows_of(hosts)).vectors
    features = ft.feature_list(vectors)
    names = [f.name for f in features]
    assert names[:2] == ["peers_out.members", "peers_out.per_day"]
    assert names[-4:] == ["plane.flow", "plane.dns", "plane.process", "plane.logon"]
    assert len(names) == len(set(names))
    raw, model = ft.matrix(vectors, features)
    assert all(len(row) == len(names) for row in raw + model)
    # Counts and rates enter the model as log1p. Flags and hours as they are.
    members = names.index("peers_out.members")
    assert model[0][members] == pytest.approx(math.log1p(raw[0][members]))
    hours = names.index("active_hours.hours")
    assert model[0][hours] == raw[0][hours] == 10.0


def test_render_reads_as_an_analyst_reads() -> None:
    by_name = {f.name: f for f in ft.BASE_FEATURES}
    assert ft.render(by_name["served_ports.members"], 41.0) == "41"
    assert ft.render(by_name["served_ports.per_day"], 9000.0) == "9,000.0"
    assert ft.render(by_name["active_hours.night_share"], 0.42) == "42 %"
    assert ft.render(by_name["active_hours.hours"], 24.0) == "24 h"
    assert ft.render(by_name["plane.process"], 1.0) == "present"
    assert ft.render(by_name["plane.process"], 0.0) == "absent"


async def test_the_store_read_pages_and_matches_the_rows(settings_kratos: Settings) -> None:
    """A page smaller than one host's rows still folds every row into its host."""
    engine = make_engine(settings_kratos)
    await run_migrations(engine)
    maker = make_sessionmaker(engine)
    hosts = fx.estate(planted=False)[:12]
    async with maker() as db:
        db.add_all(fx.profile_models(hosts))
        await db.commit()
        paged = await ft.collect_vectors(db, page=7)
    await engine.dispose()
    expected = ft.vectors_from_rows(fx.rows_of(hosts))
    assert [v.entity_key for v in paged.vectors] == [v.entity_key for v in expected.vectors]
    for got, want in zip(paged.vectors, expected.vectors, strict=True):
        assert got.raw == pytest.approx(want.raw)
    assert paged.blind == expected.blind

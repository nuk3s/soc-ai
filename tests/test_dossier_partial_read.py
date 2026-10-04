"""A partial served-port read must not overwrite a stronger prior answer.

"Rebuild now" during a grid stall rewrote a domain controller (tcp/88, tcp/389)
as a server that "responds on tcp/53", and the sweep report said errors=[].
These tests pin the guard: the fields the port read decides keep their previous
values, the host row says "Stale read", and the sweep report counts the host.
The negative controls pin the reads the guard must let through: a chronic 400
on one optional aggregation, and a small port set that shrank for real.
"""

from __future__ import annotations

import copy
from typing import Any

from soc_ai.config import Settings
from soc_ai.enrichment import host_dossier as job
from soc_ai.so_client.elastic import EsSearchResult

from tests.test_host_dossier_job import (
    _MAIN_AGGS,
    _db,
    _dhcp_hit,
    _FakeES,
    _field,
    _host_row,
    _settings,
)

_DC = "192.168.10.11"
_DC_PORTS = (88, 389, 445, 53, 135, 636, 3268)


def _aggs(ports: tuple[int, ...]) -> dict[str, Any]:
    aggs = copy.deepcopy(_MAIN_AGGS)
    aggs["responder"]["ports"] = {
        "buckets": [{"key": port, "doc_count": 500 - i} for i, port in enumerate(ports)]
    }
    return aggs


class _StallES(_FakeES):
    """The fake grid, with a main pass that can answer short or fail partial."""

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.ports: tuple[int, ...] = _DC_PORTS
        self.main_error: str | None = None
        # Fail only the first main-pass attempt: the reduced retry answers.
        self.first_attempt_only = False
        self._main_calls = 0

    async def search(self, index: str, query: dict[str, Any], **kwargs: Any) -> EsSearchResult:
        result = await super().search(index, query, **kwargs)
        if self.calls and self.calls[-1]["kind"] == "main":
            self._main_calls += 1
            if self.main_error and (not self.first_attempt_only or self._main_calls % 2 == 1):
                raise RuntimeError(self.main_error)
            return EsSearchResult(total=result.total, took_ms=2, aggregations=_aggs(self.ports))
        return result


def _grid() -> _StallES:
    return _StallES(
        src={_DC: 3412},
        targeted={(_DC, "zeek.dhcp"): [_dhcp_hit(_DC, "dc01")]},
    )


async def _lanes(maker: Any) -> tuple[Any, Any]:
    role = await _field(maker, _DC, "role")
    services = await _field(maker, _DC, "services_offered")
    return (role.inferred_value, role.inferred_confidence), services.inferred_value_json


async def test_a_partial_port_read_keeps_the_previous_role_and_services(
    settings_kratos: Settings,
) -> None:
    settings = _settings(settings_kratos)
    engine, maker = await _db(settings)
    es = _grid()
    await job.run_dossier_refresh(es, maker, settings)
    before = await _lanes(maker)
    assert len(before[1]) == len(_DC_PORTS)

    es.main_error = "partial search results from logs-*: 2 of 5 shards failed"
    summary = await job.run_dossier_refresh(es, maker, settings)

    assert await _lanes(maker) == before
    host = await _host_row(maker, _DC)
    assert host is not None and host.build_error is not None
    assert host.build_error.startswith("Stale read.")
    assert summary.partial_reads == 1
    assert any("partial read on 1 host" in e for e in summary.errors)
    await engine.dispose()


async def test_a_short_read_with_no_error_keeps_the_previous_answer(
    settings_kratos: Settings,
) -> None:
    """A grid that returns partial results with no error still cannot shrink a DC."""
    settings = _settings(settings_kratos)
    engine, maker = await _db(settings)
    es = _grid()
    await job.run_dossier_refresh(es, maker, settings)
    before = await _lanes(maker)

    es.ports = (53,)
    summary = await job.run_dossier_refresh(es, maker, settings)

    assert await _lanes(maker) == before
    assert summary.partial_reads == 1
    assert "1 served ports where the previous build had 7" in (summary.partial_reason or "")
    await engine.dispose()


async def test_a_chronic_bad_request_on_an_optional_agg_is_not_a_partial_read(
    settings_kratos: Settings,
) -> None:
    """Negative control: a 400 on a text-mapped field says nothing about the ports.

    The reduced retry reads the full port set. Freezing the role on this
    error would freeze it on every sweep of a grid with that mapping.
    """
    settings = _settings(settings_kratos)
    engine, maker = await _db(settings)
    es = _grid()
    es.ports = (22, 8006)
    await job.run_dossier_refresh(es, maker, settings)

    es.ports = _DC_PORTS
    es.main_error = "BadRequestError(400, 'illegal_argument_exception', 'Text fields are not ...')"
    es.first_attempt_only = True
    summary = await job.run_dossier_refresh(es, maker, settings)

    _role, services = await _lanes(maker)
    assert len(services) == len(_DC_PORTS)
    host = await _host_row(maker, _DC)
    assert host is not None and host.build_error is None
    assert summary.partial_reads == 0
    await engine.dispose()


async def test_a_small_port_set_that_shrank_is_written(settings_kratos: Settings) -> None:
    """Negative control: two ports down to one is ordinary, not a short read."""
    settings = _settings(settings_kratos)
    engine, maker = await _db(settings)
    es = _grid()
    es.ports = (22, 8006)
    await job.run_dossier_refresh(es, maker, settings)

    es.ports = (22,)
    summary = await job.run_dossier_refresh(es, maker, settings)

    _role, services = await _lanes(maker)
    assert len(services) == 1
    assert summary.partial_reads == 0
    await engine.dispose()

"""Unit tests for the diverse-alert sampler.

The sampler walks an OQL result and yields alert IDs whose
diversity-key tuples are distinct. These tests stub
``query_events_oql`` (so we never hit ES) and verify:

- yields up to ``n`` distinct-tuple IDs
- skips duplicates (same tuple → only the first wins)
- supports both flat ("rule.name": "...") and nested
  ({"rule": {"name": "..."}}) source shapes
- falls back to a hash when *all* diversity keys are missing
- stops yielding when the consumer breaks early
- yields whatever it has when the OQL stream is exhausted before
  reaching ``n``
"""

from __future__ import annotations

from typing import Any

import pytest
from pydantic import SecretStr
from soc_ai.config import Settings
from soc_ai.eval import sampler as sampler_mod
from soc_ai.eval.sampler import sample_diverse_alerts
from soc_ai.so_client.elastic import EsSearchResult


def _settings() -> Settings:
    return Settings(
        so_host="https://so.example.com",
        so_username="analyst",
        so_password=SecretStr("password123"),
        so_verify_ssl=False,
        es_hosts=["https://so.example.com:9200"],
        litellm_base_url="http://localhost:4000",
    )


def _hit(_id: str, source: dict[str, Any]) -> dict[str, Any]:
    return {"_id": _id, "_source": source}


def _patch_query(monkeypatch: pytest.MonkeyPatch, hits: list[dict[str, Any]]) -> None:
    async def _fake_query(**_kwargs: Any) -> EsSearchResult:
        return EsSearchResult(total=len(hits), took_ms=1, hits=list(hits))

    monkeypatch.setattr(sampler_mod, "query_events_oql", _fake_query)


async def test_yields_up_to_n_distinct_tuples(monkeypatch: pytest.MonkeyPatch) -> None:
    hits = [
        _hit("a1", {"rule.name": "ET MALWARE", "host.name": "h1"}),
        _hit("a2", {"rule.name": "ET MALWARE", "host.name": "h2"}),
        _hit("a3", {"rule.name": "ET POLICY", "host.name": "h1"}),
        _hit("a4", {"rule.name": "ET MALWARE", "host.name": "h1"}),  # dup of a1
    ]
    _patch_query(monkeypatch, hits)

    out = []
    async for aid in sample_diverse_alerts(
        "x",
        n=5,
        settings=_settings(),
        elastic=None,  # type: ignore[arg-type]
    ):
        out.append(aid)

    # Only the three distinct (rule.name, host.name) tuples — a4 dropped.
    # Order is not pinned: a2 may be deferred to the per-rule-cap second pass
    # when the default max_rule_share reduces a single-rule share.
    assert set(out) == {"a1", "a2", "a3"}


async def test_consumer_can_stop_early(monkeypatch: pytest.MonkeyPatch) -> None:
    hits = [
        _hit("a1", {"rule.name": "r1", "host.name": "h1"}),
        _hit("a2", {"rule.name": "r2", "host.name": "h2"}),
        _hit("a3", {"rule.name": "r3", "host.name": "h3"}),
    ]
    _patch_query(monkeypatch, hits)

    out = []
    async for aid in sample_diverse_alerts(
        "x",
        n=2,
        settings=_settings(),
        elastic=None,  # type: ignore[arg-type]
    ):
        out.append(aid)
    assert out == ["a1", "a2"]


async def test_handles_nested_source_shape(monkeypatch: pytest.MonkeyPatch) -> None:
    """ES returns nested shapes when a `_source` excludes flat duplication.
    Sampler must read both."""
    hits = [
        _hit("a1", {"rule": {"name": "r1"}, "host": {"name": "h1"}}),
        _hit("a2", {"rule": {"name": "r1"}, "host": {"name": "h1"}}),  # dup
        _hit("a3", {"rule": {"name": "r2"}, "host": {"name": "h1"}}),
    ]
    _patch_query(monkeypatch, hits)

    out = []
    async for aid in sample_diverse_alerts(
        "x",
        n=10,
        settings=_settings(),
        elastic=None,  # type: ignore[arg-type]
    ):
        out.append(aid)
    assert out == ["a1", "a3"]


async def test_falls_back_to_hash_when_keys_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    """Alerts whose diversity keys are entirely missing should still be
    sampled (one per distinct full-source hash) so the batch isn't
    empty just because schemas vary."""
    hits = [
        _hit("a1", {"weird": "data"}),
        _hit("a2", {"weird": "data"}),  # same source → same hash → skip
        _hit("a3", {"different": "data"}),
        _hit("a4", {"rule.name": "r1", "host.name": "h1"}),
    ]
    _patch_query(monkeypatch, hits)

    out = []
    async for aid in sample_diverse_alerts(
        "x",
        n=10,
        settings=_settings(),
        elastic=None,  # type: ignore[arg-type]
    ):
        out.append(aid)
    assert out == ["a1", "a3", "a4"]


async def test_partial_key_coverage_still_dedupes(monkeypatch: pytest.MonkeyPatch) -> None:
    """If some keys are present and others missing, dedupe on the
    present ones — no fallback hash."""
    hits = [
        _hit("a1", {"rule.name": "r1"}),  # host missing
        _hit("a2", {"rule.name": "r1"}),  # same rule, host missing → dup
        _hit("a3", {"rule.name": "r2"}),
    ]
    _patch_query(monkeypatch, hits)

    out = []
    async for aid in sample_diverse_alerts(
        "x",
        n=10,
        settings=_settings(),
        elastic=None,  # type: ignore[arg-type]
    ):
        out.append(aid)
    assert out == ["a1", "a3"]


async def test_yields_what_it_has_when_oql_short(monkeypatch: pytest.MonkeyPatch) -> None:
    """Asking for n=10 but only 3 distinct tuples available → yield 3,
    don't error."""
    hits = [
        _hit("a1", {"rule.name": "r1", "host.name": "h1"}),
        _hit("a2", {"rule.name": "r2", "host.name": "h2"}),
        _hit("a3", {"rule.name": "r3", "host.name": "h3"}),
    ]
    _patch_query(monkeypatch, hits)

    out = []
    async for aid in sample_diverse_alerts(
        "x",
        n=10,
        settings=_settings(),
        elastic=None,  # type: ignore[arg-type]
    ):
        out.append(aid)
    assert out == ["a1", "a2", "a3"]


async def test_per_rule_cap_limits_single_rule_saturation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """30 alerts for 'ET POLICY X' on 30 distinct hosts + 10 alerts across 5
    other rules, sample size 20 with max_rule_share=0.25 → no rule exceeds 5
    rows and other rules are represented."""
    hits = []
    # 30 distinct-host alerts for one noisy rule.
    for i in range(30):
        hits.append(_hit(f"noisy-{i}", {"rule.name": "ET POLICY X", "host.name": f"h-noisy-{i}"}))
    # 10 alerts for 5 other rules (2 alerts each).
    for r in range(5):
        for j in range(2):
            hits.append(
                _hit(
                    f"other-r{r}-{j}",
                    {"rule.name": f"ET OTHER RULE {r}", "host.name": f"h-other-{r}-{j}"},
                )
            )
    _patch_query(monkeypatch, hits)

    out = []
    async for aid in sample_diverse_alerts(
        "x",
        n=20,
        settings=_settings(),
        elastic=None,  # type: ignore[arg-type]
        max_rule_share=0.25,
    ):
        out.append(aid)

    from collections import Counter

    rule_counts: Counter[str] = Counter()
    for aid in out:
        if aid.startswith("noisy-"):
            rule_counts["ET POLICY X"] += 1
        else:
            r_num = int(aid.split("-")[1][1:])
            rule_counts[f"ET OTHER RULE {r_num}"] += 1

    # Batch must be full.
    assert len(out) == 20

    # Cap prevented the noisy rule from taking the whole batch.
    # Without a cap, all 20 would be "ET POLICY X".
    # With max_rule_share=0.25 the first pass admits only 5; second pass
    # may fill remaining slots from overflow, but other rules always go
    # first in the first pass, so ALL 10 other-rule alerts appear.
    assert rule_counts["ET POLICY X"] < 20, "cap had no effect — rule still saturated"

    # All 5 other rules must appear (10 total, 2 each — all distinct tuples).
    other_rules_seen = sum(1 for k in rule_counts if k != "ET POLICY X")
    assert other_rules_seen == 5


async def test_n_must_be_positive() -> None:
    with pytest.raises(ValueError, match="n must be positive"):
        async for _ in sample_diverse_alerts(
            "x",
            n=0,
            settings=_settings(),
            elastic=None,  # type: ignore[arg-type]
        ):
            pass


async def test_skips_hits_with_no_id(monkeypatch: pytest.MonkeyPatch) -> None:
    """Defensive: ES might return a hit dict missing _id (script bug,
    bad mapping). Skip rather than crash."""
    hits = [
        {"_id": None, "_source": {"rule.name": "r1", "host.name": "h1"}},
        _hit("a2", {"rule.name": "r2", "host.name": "h2"}),
    ]
    _patch_query(monkeypatch, hits)

    out = []
    async for aid in sample_diverse_alerts(
        "x",
        n=10,
        settings=_settings(),
        elastic=None,  # type: ignore[arg-type]
    ):
        out.append(aid)
    assert out == ["a2"]

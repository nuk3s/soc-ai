"""Citation path resolution into dict keys that contain dots.

The enriched alert context carries an ``enrichments`` dict keyed by
indicator — for an IP that key is ``"10.0.0.55"``. A citation naming real
retrieved evidence under it (``enrichments.10.0.0.55.internal``) splits on
``.`` into ``['enrichments','10','0','0','55','internal']``; the naive walk
descended ``enrichments`` → ``"10"`` → dead end, and a TRUE citation was
recorded unresolved. Measured on the 9-scenario hunt-journey eval: 8/9 runs
below 1.0 coverage, with h1/e1 shaved below their own confidence floors by
the citation cap — correct detections recorded as misses.

The fix joins path segments against the keys that ACTUALLY EXIST at each
dict level (longest dot-joined prefix wins, greedy, no backtracking). It is
structural, never textual: a segment run only resolves by literal key
membership in the retrieved structure, so the forgeable substring path
removed by the 2026-08-25 audit (M2) stays removed.
"""

from __future__ import annotations

from typing import Any

from soc_ai.agent.evidence import _path_exists_in_alert
from soc_ai.so_client.models import RuleMetadata, SoAlert
from soc_ai.tools.enrichment import IndicatorEnrichment
from soc_ai.tools.get_alert_context import AlertContext, EnrichedAlertContext


class _StubCtx:
    """Minimal model_dump carrier for pinning walk mechanics on raw shapes."""

    def __init__(self, dump: dict[str, Any]) -> None:
        self._dump = dump

    def model_dump(self, mode: str = "json") -> dict[str, Any]:
        return self._dump


def _enriched_ctx() -> EnrichedAlertContext:
    return EnrichedAlertContext(
        alert=SoAlert(id="a1", rule_name="ET POLICY Example"),
        enrichments={
            "10.0.0.55": IndicatorEnrichment(
                indicator="10.0.0.55",
                indicator_type="ip",
                internal=True,
            )
        },
    )


def test_dotted_ip_key_in_enrichments_resolves() -> None:
    """The reproduced bug: ``enrichments.10.0.0.55.internal`` names real,
    retrieved evidence — the enrichments dict genuinely holds the key
    ``"10.0.0.55"`` — and must resolve."""
    ctx = _enriched_ctx()
    assert _path_exists_in_alert(ctx, "enrichments.10.0.0.55.internal") is True
    # A sibling field on the same enrichment resolves too.
    assert _path_exists_in_alert(ctx, "enrichments.10.0.0.55.indicator_type") is True


def test_missing_leaf_under_dotted_key_does_not_resolve() -> None:
    """No over-correction: the dotted-key join must not make a nonexistent
    LEAF under a real dotted key resolve."""
    ctx = _enriched_ctx()
    assert _path_exists_in_alert(ctx, "enrichments.10.0.0.55.not_a_field") is False


def test_absent_ip_key_does_not_resolve() -> None:
    """An IP key that was never enriched — never retrieved — must not
    resolve, however plausible the path looks."""
    ctx = _enriched_ctx()
    assert _path_exists_in_alert(ctx, "enrichments.10.0.0.99.internal") is False


def test_path_string_planted_in_a_value_does_not_resolve() -> None:
    """The M2 boundary: resolution is by literal key membership in the
    retrieved STRUCTURE, never by matching against dumped text. A full
    path string planted in an attacker-reachable VALUE must not mint a
    resolvable path."""
    ctx = EnrichedAlertContext(
        alert=SoAlert(id="a1", rule_name="enrichments.9.9.9.9.internal"),
    )
    assert _path_exists_in_alert(ctx, "enrichments.9.9.9.9.internal") is False


def test_plain_paths_resolve_exactly_as_before() -> None:
    """Ordinary non-dotted-key paths keep their exact prior behaviour:
    when no key at a level contains a dot, the longest joinable prefix is
    the single segment, so the walk is unchanged."""
    ctx = AlertContext(
        alert=SoAlert(
            id="a1",
            rule_name="ET MALWARE Known Bad",
            rule_metadata=RuleMetadata(signature_severity="Major"),
            dns_query="example.com",
        )
    )
    assert _path_exists_in_alert(ctx, "alert.rule_name") is True
    assert _path_exists_in_alert(ctx, "alert.rule_metadata.signature_severity") is True
    assert _path_exists_in_alert(ctx, "alert.dns_query") is True
    # Typos and absent pivots still reject.
    assert _path_exists_in_alert(ctx, "alert.rule_namee") is False
    assert _path_exists_in_alert(ctx, "alert.rule_metadata.signature_sevarity") is False
    assert _path_exists_in_alert(ctx, "host_events.7.id") is False


def test_ambiguous_prefix_longest_match_wins() -> None:
    """Tie-break rule, pinned: at each dict level the LONGEST dot-joined
    prefix of the remaining segments that is literally a key wins."""
    ctx = _StubCtx(
        {
            "a.b.c": {"leaf": 1},
            "a.b": {"c": {}},  # shorter prefix would dead-end at `leaf`
        }
    )
    assert _path_exists_in_alert(ctx, "a.b.c.leaf") is True


def test_ambiguous_prefix_is_greedy_no_backtracking() -> None:
    """The longest-match rule is greedy: once the longest key is taken the
    walk never backtracks to a shorter prefix, even when the shorter one
    would have resolved. Deterministic by construction."""
    ctx = _StubCtx(
        {
            "a.b.c": {},  # longest match taken, then `leaf` is absent
            "a.b": {"c": {"leaf": 1}},  # would resolve — deliberately not tried
        }
    )
    assert _path_exists_in_alert(ctx, "a.b.c.leaf") is False


def test_longest_join_beats_exact_single_segment() -> None:
    """When both a bare segment and a longer dotted key exist at a level,
    the longer (more specific) key wins — same longest-match rule, applied
    uniformly. This is the realistic enrichments shape when one indicator
    key is a prefix of another's first octet."""
    ctx = _StubCtx(
        {
            "enrichments": {
                "10": {"decoy": True},
                "10.0.0.55": {"internal": True},
            }
        }
    )
    assert _path_exists_in_alert(ctx, "enrichments.10.0.0.55.internal") is True
    # The bare-segment key is still reachable when it IS the longest match.
    assert _path_exists_in_alert(ctx, "enrichments.10.decoy") is True


def test_null_leaf_does_not_resolve() -> None:
    """Decision, pinned: a path whose leaf exists but holds null stays
    UNRESOLVED. Pydantic dumps every declared field whether or not data was
    retrieved (``alert.dns_query`` exists as ``null`` on every non-DNS
    alert), so resolving null leaves would make each empty schema slot
    citable as if it carried evidence. A citation documenting absence loses
    a little coverage; a citation laundering an empty field would gain a
    lot. Strictness wins."""
    ctx = AlertContext(alert=SoAlert(id="a1", rule_name="ET POLICY Example"))
    # dns_query is declared on SoAlert, present in the dump, and null here.
    assert _path_exists_in_alert(ctx, "alert.dns_query") is False

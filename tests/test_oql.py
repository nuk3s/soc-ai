"""Tests for :mod:`soc_ai.so_client.oql`.

The OQL pipeline is the trust boundary between LLM-generated queries and
Elasticsearch — these tests pin down the parser's accepted grammar, the
validator's whitelist and pipe-stage rules, and the translator's ES DSL output.
"""

from __future__ import annotations

import pytest
from soc_ai.errors import OqlValidationError
from soc_ai.so_client.oql import (
    _HARD_MAX_RESULTS,
    And,
    BareValue,
    Count,
    GroupBy,
    Head,
    MatchAll,
    Not,
    Or,
    QuotedValue,
    RangeValue,
    SortBy,
    Term,
    WildcardValue,
    ast_to_es_dsl,
    collect_filter_fields,
    filter_to_dsl,
    get_whitelist,
    parse_oql,
    validate_oql,
)

# =====================================================================
# Parser
# =====================================================================


def test_parse_simple_field_value() -> None:
    ast = parse_oql("event.module:zeek")
    assert ast.filter_ == Term(field="event.module", value=BareValue(text="zeek"))
    assert ast.pipes == ()


def test_parse_quoted_value() -> None:
    ast = parse_oql('rule.name:"ET MALWARE Suspicious User-Agent"')
    assert ast.filter_ == Term(
        field="rule.name", value=QuotedValue(text="ET MALWARE Suspicious User-Agent")
    )


def test_parse_quoted_value_with_escapes() -> None:
    ast = parse_oql(r'message:"hello \"world\""')
    assert ast.filter_ == Term(field="message", value=QuotedValue(text='hello "world"'))


def test_parse_wildcard_value() -> None:
    ast = parse_oql("rule.name:*MALWARE*")
    assert ast.filter_ == Term(field="rule.name", value=WildcardValue(pattern="*MALWARE*"))


def test_parse_range() -> None:
    ast = parse_oql("event.severity:[1 TO 100]")
    assert ast.filter_ == Term(field="event.severity", value=RangeValue(lo="1", hi="100"))


def test_parse_open_range_low() -> None:
    ast = parse_oql("destination.port:[* TO 1024]")
    assert ast.filter_ == Term(field="destination.port", value=RangeValue(lo="*", hi="1024"))


def test_parse_match_all() -> None:
    ast = parse_oql("*")
    assert ast.filter_ == MatchAll()


def test_parse_and() -> None:
    ast = parse_oql("event.module:zeek AND host.name:foo")
    assert isinstance(ast.filter_, And)
    assert len(ast.filter_.children) == 2


def test_parse_or() -> None:
    ast = parse_oql("event.module:zeek OR event.module:suricata")
    assert isinstance(ast.filter_, Or)
    assert len(ast.filter_.children) == 2


def test_parse_not() -> None:
    ast = parse_oql("NOT host.name:foo")
    assert isinstance(ast.filter_, Not)
    assert isinstance(ast.filter_.child, Term)


def test_parse_parens() -> None:
    ast = parse_oql("(event.module:zeek OR event.module:suricata) AND host.name:foo")
    assert isinstance(ast.filter_, And)
    # And children: [Or(...), Term(host.name, foo)]
    or_node = ast.filter_.children[0]
    term_node = ast.filter_.children[1]
    assert isinstance(or_node, Or)
    assert isinstance(term_node, Term)


def test_parse_precedence_not_binds_tightest() -> None:
    """NOT a AND b -> (NOT a) AND b, not NOT (a AND b)."""
    ast = parse_oql("NOT host.name:foo AND host.name:bar")
    assert isinstance(ast.filter_, And)
    assert isinstance(ast.filter_.children[0], Not)
    assert isinstance(ast.filter_.children[1], Term)


def test_parse_keywords_case_insensitive() -> None:
    ast = parse_oql("host.name:foo and host.name:bar")
    assert isinstance(ast.filter_, And)


def test_parse_pipe_groupby() -> None:
    ast = parse_oql("* | groupby host.name")
    assert ast.pipes == (GroupBy(fields=("host.name",)),)


def test_parse_pipe_groupby_multiple_fields() -> None:
    ast = parse_oql("* | groupby host.name, source.ip")
    assert ast.pipes == (GroupBy(fields=("host.name", "source.ip")),)


def test_parse_pipe_sortby_default_asc() -> None:
    ast = parse_oql("* | sortby @timestamp")
    assert ast.pipes == (SortBy(field="@timestamp", direction="asc"),)


def test_parse_pipe_sortby_desc() -> None:
    ast = parse_oql("* | sortby @timestamp desc")
    assert ast.pipes == (SortBy(field="@timestamp", direction="desc"),)


def test_parse_pipe_head_and_limit_synonyms() -> None:
    assert parse_oql("* | head 10").pipes == (Head(limit=10),)
    assert parse_oql("* | limit 10").pipes == (Head(limit=10),)


def test_parse_pipe_count() -> None:
    ast = parse_oql("event.kind:alert | count")
    assert ast.pipes == (Count(),)


def test_parse_full_pipeline() -> None:
    ast = parse_oql("event.kind:alert | groupby destination.ip | sortby count desc | head 10")
    assert len(ast.pipes) == 3
    assert isinstance(ast.pipes[0], GroupBy)
    assert isinstance(ast.pipes[1], SortBy)
    assert isinstance(ast.pipes[2], Head)


def test_parse_pipe_split_respects_quotes() -> None:
    """A `|` inside a quoted string must NOT be treated as a pipe separator."""
    ast = parse_oql('rule.name:"ET | MALWARE"')
    assert ast.pipes == ()
    assert ast.filter_ == Term(field="rule.name", value=QuotedValue(text="ET | MALWARE"))


def test_parse_pipe_split_respects_single_quotes() -> None:
    """A `|` inside a SINGLE-quoted string must NOT be treated as a pipe separator
    (the grammar accepts either quote style; the top-level splitter must track both
    so a single-quoted value can't smuggle a spurious stage break)."""
    ast = parse_oql("rule.name:'ET | MALWARE'")
    assert ast.pipes == ()
    assert ast.filter_ == Term(field="rule.name", value=QuotedValue(text="ET | MALWARE"))


def test_split_pipe_tracks_both_quote_styles() -> None:
    """A double quote inside a single-quoted string (and vice versa) is literal and
    does not toggle quote state, so an embedded `|` still doesn't split."""
    from soc_ai.so_client.oql import _split_pipe

    # `"` inside a single-quoted value is literal — the whole thing is one segment.
    assert _split_pipe("""rule.name:'a " | b'""") == ["""rule.name:'a " | b'"""]
    # A genuine top-level pipe still splits.
    assert _split_pipe("* | groupby source.ip") == ["* ", " groupby source.ip"]


def test_parse_empty_query_rejected() -> None:
    with pytest.raises(OqlValidationError, match="empty"):
        parse_oql("")
    with pytest.raises(OqlValidationError, match="empty"):
        parse_oql("   ")


def test_parse_garbage_rejected() -> None:
    with pytest.raises(OqlValidationError, match="parse"):
        parse_oql("this is not valid syntax")


def test_parse_recursion_error_becomes_oql_error(monkeypatch: pytest.MonkeyPatch) -> None:
    """A RecursionError from the parser (deeply-nested input) must surface as a
    clean OqlValidationError (400), never an unhandled RecursionError (500)."""
    from soc_ai.so_client import oql

    def _boom(_text: str) -> None:
        raise RecursionError("maximum recursion depth exceeded")

    monkeypatch.setattr(oql._PARSER, "parse", _boom)
    with pytest.raises(OqlValidationError):
        parse_oql("a:b")


def test_parse_unknown_pipe_stage_rejected() -> None:
    with pytest.raises(OqlValidationError, match="unknown pipe stage"):
        parse_oql("* | take 10")


def test_parse_unknown_pipe_stage_error_names_valid_stages() -> None:
    """U3: the unknown-stage error is returned verbatim to the LLM agent, so
    it must name the real pipe-stage surface (self-correcting error) and
    explicitly disclaim the `fields` projection stage the agents keep
    inventing."""
    with pytest.raises(OqlValidationError) as exc_info:
        parse_oql("event.kind:alert | fields rule.name, source.ip")
    msg = str(exc_info.value)
    assert "unknown pipe stage" in msg
    for stage in ("groupby", "sortby", "head", "count"):
        assert stage in msg, f"valid stage {stage!r} missing from error: {msg}"
    assert "fields" in msg and "projection" in msg


def test_parse_groupby_no_fields_rejected() -> None:
    with pytest.raises(OqlValidationError, match="groupby requires"):
        parse_oql("* | groupby   ,  ")


# =====================================================================
# Validator
# =====================================================================


def test_collect_fields_simple() -> None:
    ast = parse_oql("event.module:zeek AND host.name:foo")
    assert collect_filter_fields(ast.filter_) == {"event.module", "host.name"}


def test_collect_fields_match_all_empty() -> None:
    assert collect_filter_fields(MatchAll()) == set()


def test_validate_allowed_fields_pass() -> None:
    validate_oql(parse_oql("event.module:zeek AND host.name:foo"))


def test_validate_unknown_field_rejected() -> None:
    with pytest.raises(OqlValidationError, match="unknown or forbidden field"):
        validate_oql(parse_oql("totally_made_up:value"))


def test_validate_ecs_zeek_fields_allowed() -> None:
    """The ECS Zeek field names (what modern SO populates) pass the allowlist so
    the agent can OQL-query real fields."""
    wl = get_whitelist()
    for ecs_field in (
        "dns.query.name",
        "dns.resolved_ip",
        "dns.highest_registered_domain",
        "client.bytes",
        "server.bytes",
        "network.bytes",
        "connection.state",
        "connection.local.originator",
        "hash.ja3",
        "hash.ja3s",
        "ssl.server_name",
        "http.virtual_host",
        "user_agent.original",
        "file.hash.sha256",
    ):
        assert wl.is_allowed(ecs_field), f"{ecs_field} must be allowed"
    # and a real OQL query referencing an ECS field validates cleanly.
    validate_oql(parse_oql('client.bytes:[1000 TO *] AND ssl.server_name:"app.corp.acme.com"'))
    validate_oql(parse_oql('dns.query.name:"app.corp.acme.com" AND hash.ja3s:abc123'))


def test_validate_forbidden_field_rejected() -> None:
    with pytest.raises(OqlValidationError, match="forbidden"):
        validate_oql(parse_oql("_source:foo"))


def test_validate_groupby_unknown_field() -> None:
    ast = parse_oql("* | groupby fictional.field")
    with pytest.raises(OqlValidationError, match="groupby"):
        validate_oql(ast)


def test_validate_sortby_unknown_field() -> None:
    ast = parse_oql("* | sortby fictional.field")
    with pytest.raises(OqlValidationError, match="sortby"):
        validate_oql(ast)


def test_validate_leading_wildcard_rejected() -> None:
    """A leading ``*`` forces per-shard term-index scans — reject it."""
    with pytest.raises(OqlValidationError, match="leading-wildcard"):
        validate_oql(parse_oql("host.name:*foo"))


def test_validate_leading_wildcard_error_says_anchor_the_wildcard() -> None:
    """U3: the rejection is returned verbatim to the LLM agent, so it must
    say HOW to fix the pattern (anchor it: foo*, not *foo)."""
    with pytest.raises(OqlValidationError, match=r"anchor the wildcard \(write foo\*, not \*foo\)"):
        validate_oql(parse_oql("host.name:*foo"))


def test_validate_leading_question_wildcard_rejected() -> None:
    with pytest.raises(OqlValidationError, match="leading-wildcard"):
        validate_oql(parse_oql("host.name:?foo"))


def test_validate_bare_star_value_rejected() -> None:
    """A bare ``host.name:*`` (match-anything wildcard) is also rejected."""
    with pytest.raises(OqlValidationError, match="leading-wildcard"):
        validate_oql(parse_oql("host.name:*"))


def test_validate_trailing_wildcard_allowed() -> None:
    """Anchored-prefix wildcards (``foo*``, ``f*o``) stay allowed."""
    validate_oql(parse_oql("host.name:foo*"))
    validate_oql(parse_oql("host.name:f*o"))


def test_validate_leading_wildcard_nested_rejected() -> None:
    """The leading-wildcard guard recurses into AND/OR/NOT subtrees."""
    with pytest.raises(OqlValidationError, match="leading-wildcard"):
        validate_oql(parse_oql("event.module:zeek AND host.name:*evil"))


def test_validate_sortby_count_requires_groupby() -> None:
    ast = parse_oql("* | sortby count desc")
    with pytest.raises(OqlValidationError, match="sortby count requires"):
        validate_oql(ast)


def test_validate_sortby_count_after_groupby_ok() -> None:
    ast = parse_oql("* | groupby host.name | sortby count desc")
    validate_oql(ast)


def test_validate_head_over_max_rejected() -> None:
    ast = parse_oql("* | head 1000")
    with pytest.raises(OqlValidationError, match="exceeds max_results"):
        validate_oql(ast, max_results=100)


def test_validate_head_zero_rejected() -> None:
    ast = parse_oql("* | head 0")
    with pytest.raises(OqlValidationError, match="must be positive"):
        validate_oql(ast)


def test_validate_duplicate_groupby_rejected() -> None:
    ast = parse_oql("* | groupby host.name | groupby source.ip")
    with pytest.raises(OqlValidationError, match="groupby may not be repeated"):
        validate_oql(ast)


def test_validate_groupby_over_max_fields_rejected() -> None:
    """F46: unbounded groupby field count lets a query force deeply-nested
    per-shard terms aggregations — cap the pivot depth."""
    fields = ",".join(["host.name"] * 30)
    ast = parse_oql(f"* | groupby {fields} | head 10000")
    with pytest.raises(OqlValidationError, match="groupby supports at most"):
        validate_oql(ast, max_results=10000)


def test_validate_groupby_at_max_fields_allowed() -> None:
    ast = parse_oql("* | groupby host.name, source.ip, destination.ip, event.module")
    validate_oql(ast)


def test_validate_duplicate_sortby_rejected() -> None:
    ast = parse_oql("* | sortby @timestamp | sortby host.name")
    with pytest.raises(OqlValidationError, match="sortby may not be repeated"):
        validate_oql(ast)


def test_validate_duplicate_head_rejected() -> None:
    ast = parse_oql("* | head 5 | head 10")
    with pytest.raises(OqlValidationError, match="head may not be repeated"):
        validate_oql(ast)


def test_whitelist_loaded_with_expected_fields() -> None:
    wl = get_whitelist()
    # Spot-check the most important pivots.
    assert wl.is_allowed("network.community_id")
    assert wl.is_allowed("rule.name")
    assert wl.is_allowed("@timestamp")
    assert wl.is_allowed("zeek.conn.duration")
    # Forbidden / unknown.
    assert not wl.is_allowed("_source")
    assert not wl.is_allowed("fictional.field")


# =====================================================================
# Translator
# =====================================================================


def test_translate_match_all() -> None:
    assert filter_to_dsl(MatchAll()) == {"match_all": {}}


def test_translate_simple_term() -> None:
    dsl = filter_to_dsl(Term(field="host.name", value=BareValue(text="foo")))
    assert dsl == {"term": {"host.name": "foo"}}


def test_translate_quoted_term() -> None:
    dsl = filter_to_dsl(Term(field="rule.name", value=QuotedValue(text="ET MALWARE")))
    assert dsl == {"term": {"rule.name": "ET MALWARE"}}


def test_translate_wildcard_term() -> None:
    dsl = filter_to_dsl(Term(field="rule.name", value=WildcardValue(pattern="*MALWARE*")))
    assert dsl == {"wildcard": {"rule.name": {"value": "*MALWARE*"}}}


def test_translate_bare_value_with_wildcard_chars_becomes_wildcard() -> None:
    """A bare value containing `*` should still translate to a wildcard query."""
    dsl = filter_to_dsl(Term(field="rule.name", value=BareValue(text="*foo*")))
    assert dsl == {"wildcard": {"rule.name": {"value": "*foo*"}}}


def test_translate_range_closed() -> None:
    dsl = filter_to_dsl(Term(field="event.severity", value=RangeValue(lo="1", hi="100")))
    assert dsl == {"range": {"event.severity": {"gte": "1", "lte": "100"}}}


def test_translate_range_open_low() -> None:
    dsl = filter_to_dsl(Term(field="destination.port", value=RangeValue(lo="*", hi="1024")))
    assert dsl == {"range": {"destination.port": {"lte": "1024"}}}


def test_translate_range_open_high() -> None:
    dsl = filter_to_dsl(Term(field="bytes", value=RangeValue(lo="1024", hi="*")))
    assert dsl == {"range": {"bytes": {"gte": "1024"}}}


def test_translate_and() -> None:
    ast = parse_oql("event.module:zeek AND host.name:foo")
    dsl = filter_to_dsl(ast.filter_)
    assert "bool" in dsl
    assert "must" in dsl["bool"]
    assert len(dsl["bool"]["must"]) == 2


def test_translate_or() -> None:
    ast = parse_oql("event.module:zeek OR event.module:suricata")
    dsl = filter_to_dsl(ast.filter_)
    assert dsl["bool"]["minimum_should_match"] == 1
    assert len(dsl["bool"]["should"]) == 2


def test_translate_not() -> None:
    ast = parse_oql("NOT host.name:foo")
    dsl = filter_to_dsl(ast.filter_)
    assert "must_not" in dsl["bool"]


def test_full_translate_match_all_to_size() -> None:
    body = ast_to_es_dsl(parse_oql("*"), default_size=50)
    assert body["query"] == {"match_all": {}}
    assert body["size"] == 50


def test_full_translate_groupby_emits_aggs_and_size_zero() -> None:
    body = ast_to_es_dsl(parse_oql("* | groupby host.name"))
    assert body["size"] == 0
    assert "aggs" in body
    agg_root = next(iter(body["aggs"].values()))
    assert agg_root["terms"]["field"] == "host.name"


def test_full_translate_nested_groupby() -> None:
    body = ast_to_es_dsl(parse_oql("* | groupby host.name, source.ip"))
    outer = next(iter(body["aggs"].values()))
    assert outer["terms"]["field"] == "host.name"
    inner = next(iter(outer["aggs"].values()))
    assert inner["terms"]["field"] == "source.ip"


def test_full_translate_sortby_count_with_groupby_orders_buckets() -> None:
    body = ast_to_es_dsl(parse_oql("* | groupby host.name | sortby count desc"))
    agg_root = next(iter(body["aggs"].values()))
    assert agg_root["terms"]["order"] == {"_count": "desc"}


def test_full_translate_head_with_groupby_limits_buckets() -> None:
    body = ast_to_es_dsl(parse_oql("* | groupby host.name | head 5"))
    agg_root = next(iter(body["aggs"].values()))
    assert agg_root["terms"]["size"] == 5


def test_full_translate_head_with_nested_groupby_limits_all_levels() -> None:
    """F46: `head` must cap EVERY nested terms agg, not just the outermost —
    otherwise inner levels stay at the hardcoded default (25) regardless of
    what the caller asked for."""
    body = ast_to_es_dsl(parse_oql("* | groupby host.name, source.ip | head 5"))
    outer = next(iter(body["aggs"].values()))
    assert outer["terms"]["size"] == 5
    inner = next(iter(outer["aggs"].values()))
    assert inner["terms"]["size"] == 5


def test_full_translate_sortby_without_groupby_uses_sort() -> None:
    body = ast_to_es_dsl(parse_oql("* | sortby @timestamp desc"))
    assert body["sort"] == [{"@timestamp": {"order": "desc"}}]


def test_full_translate_head_without_groupby_uses_size() -> None:
    body = ast_to_es_dsl(parse_oql("* | head 25"))
    assert body["size"] == 25


def test_full_translate_count_emits_track_total_hits() -> None:
    """F72: `count` must NOT set `track_total_hits: True` — that forces ES to
    compute an exact total across every matching doc/shard with no cost
    ceiling. A bounded integer (the same hard cap `head` uses) still returns
    an exact count up to that many docs and a `gte` lower-bound beyond it,
    which EsSearchResult already renders as `total_is_lower_bound`."""
    body = ast_to_es_dsl(parse_oql("event.kind:alert | count"))
    assert body["size"] == 0
    assert body["track_total_hits"] == _HARD_MAX_RESULTS
    assert body["track_total_hits"] is not True

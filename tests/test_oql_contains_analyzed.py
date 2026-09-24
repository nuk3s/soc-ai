"""A contains query on a keyword field matched nothing and said so quietly.

``field:~value`` exists so substring intent has an expressible form, and it
compiles to an Elasticsearch ``match``. On an ANALYZED field that is right. On a
``keyword`` field the keyword analyzer emits the whole value as one token, so
``match`` degenerates into an exact full-value comparison and a substring query
returns zero.

``process.command_line`` is a keyword field, and it is the field Windows triage
asks about most. Measured on the range on 2026-09-07 over seven days, all four
counts taken in one aggregation so they share a snapshot:

    match on process.command_line ("nslookup.exe")            0
    match_phrase on process.command_line.text               405
    multi_match over both fields, phrase                     405
    the leading wildcard the validator refuses               405

Zero on the most important field in Windows triage is an absence a model reads
as innocence, and 405 documents were sitting behind it.

The substring search is not expensive here: Elastic's Windows and endpoint
integrations map ``process.command_line`` with an analyzed ``.text`` sibling, so
the answer already exists one field name away. ``:~`` now asks both, which costs
one extra clause and reaches the analyzed text wherever a grid maps it. Where a
grid does not, the query is exactly what it was before.
"""

from __future__ import annotations

import pytest
from soc_ai.errors import OqlValidationError
from soc_ai.so_client.oql import ast_to_es_dsl, parse_oql, validate_oql


def _query(oql: str) -> dict:
    ast = parse_oql(oql)
    validate_oql(ast)
    return ast_to_es_dsl(ast)["query"]


def test_a_quoted_contains_reaches_the_analyzed_sibling() -> None:
    """The phrase has to be asked of the analyzed field or it matches nothing."""
    q = _query('process.command_line:~"nslookup.exe"')
    assert q == {
        "multi_match": {
            "query": "nslookup.exe",
            "type": "phrase",
            "fields": ["process.command_line", "process.command_line.text"],
        }
    }


def test_a_bare_contains_reaches_the_analyzed_sibling() -> None:
    q = _query("message:~beacon")
    assert q == {
        "multi_match": {
            "query": "beacon",
            "fields": ["message", "message.text"],
        }
    }


def test_the_keyword_field_is_still_asked() -> None:
    """Negative control on the widening.

    Routing to ``.text`` ALONE would break every grid that maps the field as
    analyzed text with no sibling, and would silently answer a different
    question than the one the caller wrote. Both names go in the query, so the
    original field is never dropped.
    """
    q = _query('process.command_line:~"whoami"')
    assert q["multi_match"]["fields"][0] == "process.command_line"


def test_a_field_that_is_already_the_text_sibling_is_not_doubled() -> None:
    """No ``process.command_line.text.text``, which matches nothing anywhere."""
    q = _query('process.command_line.text:~"nslookup.exe"')
    assert q["multi_match"]["fields"] == ["process.command_line.text"]


def test_a_leading_wildcard_is_still_refused() -> None:
    """Negative control. The cheap path existing does not make the expensive one
    affordable: ``*foo*`` still scans every term in the inverted index per shard.
    The refusal is the honest answer, and it names the form that works."""
    with pytest.raises(OqlValidationError) as exc:
        _query("process.command_line:*nslookup*")
    assert "field:~value" in str(exc.value)


def test_an_anchored_wildcard_is_untouched() -> None:
    """``foo*`` is still a plain wildcard clause; only ``:~`` changed."""
    q = _query("process.command_line:nslookup*")
    assert q == {"wildcard": {"process.command_line": {"value": "nslookup*"}}}


def test_an_exact_term_is_untouched() -> None:
    q = _query("host.name:workstation-01")
    assert q == {"term": {"host.name": "workstation-01"}}


def test_the_derived_sibling_is_not_a_way_past_the_whitelist() -> None:
    """The sibling is derived from a field the validator already admitted.

    Validation runs on the field the caller wrote, so an unknown field is
    rejected before any sibling is minted; the set of names that can reach
    Elasticsearch stays the whitelist plus one fixed suffix per entry, not an
    open set.
    """
    with pytest.raises(OqlValidationError, match="unknown or forbidden field"):
        _query("attacker.controlled:~anything")

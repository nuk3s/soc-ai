"""OQL parser, validator, and Elasticsearch DSL translator.

OQL is the Security Onion query DSL: a Lucene-style boolean filter expression
followed by zero or more pipe stages (``groupby``, ``sortby``, ``head``,
``count``). Example::

    rule.name:"ET MALWARE Suspicious User-Agent" AND host.name:workstation-01
    | groupby source.ip
    | sortby count desc
    | head 10

This module is the **trust boundary** between LLM-generated query strings and
Elasticsearch. The pipeline is:

1. :func:`parse_oql` — split on top-level ``|``, parse the boolean filter with
   ``lark`` into a typed AST, parse pipe stages with regex.
2. :func:`validate_oql` — walk the AST, reject unknown fields against the
   :data:`FIELD_WHITELIST` and unsafe stage parameters.
3. :func:`ast_to_es_dsl` — translate the validated AST into an Elasticsearch
   search body (``query``, ``size``, ``sort``, ``aggs``, ``track_total_hits``).

Raw OQL never reaches Elasticsearch.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, assert_never

from lark import Lark, Token, Transformer, v_args
from lark.exceptions import LarkError

from soc_ai.errors import OqlValidationError

# =====================================================================
# Field whitelist
# =====================================================================

_FIELDS_PATH = Path(__file__).parent / "oql_fields.json"


@dataclass(frozen=True)
class FieldWhitelist:
    """Allowed field-name policy loaded from ``oql_fields.json``."""

    prefixes: frozenset[str]
    exact: frozenset[str]
    forbidden: frozenset[str]

    @classmethod
    def from_file(cls, path: Path = _FIELDS_PATH) -> FieldWhitelist:
        with path.open() as f:
            data = json.load(f)
        return cls(
            prefixes=frozenset(data.get("field_prefixes", [])),
            exact=frozenset(data.get("exact_fields", [])),
            forbidden=frozenset(data.get("forbidden_fields", [])),
        )

    def is_allowed(self, field_name: str) -> bool:
        """True iff ``field_name`` passes the whitelist policy."""
        if field_name in self.forbidden:
            return False
        if field_name in self.exact:
            return True
        for prefix in self.prefixes:
            if field_name == prefix or field_name.startswith(prefix + "."):
                return True
        return False


_WHITELIST: FieldWhitelist | None = None


def get_whitelist() -> FieldWhitelist:
    """Return the cached :class:`FieldWhitelist` (lazy-loaded)."""
    global _WHITELIST  # noqa: PLW0603
    if _WHITELIST is None:
        _WHITELIST = FieldWhitelist.from_file()
    return _WHITELIST


# =====================================================================
# AST
# =====================================================================


@dataclass(frozen=True)
class MatchAll:
    """``*`` - matches every document."""


@dataclass(frozen=True)
class BareValue:
    text: str


@dataclass(frozen=True)
class QuotedValue:
    text: str


@dataclass(frozen=True)
class WildcardValue:
    pattern: str


@dataclass(frozen=True)
class RangeValue:
    """Inclusive range. ``"*"`` for either bound means open-ended on that side."""

    lo: str
    hi: str


Value = BareValue | QuotedValue | WildcardValue | RangeValue


@dataclass(frozen=True)
class Term:
    """A single ``field:value`` predicate."""

    field: str
    value: Value


@dataclass(frozen=True)
class And:
    children: tuple[FilterNode, ...]


@dataclass(frozen=True)
class Or:
    children: tuple[FilterNode, ...]


@dataclass(frozen=True)
class Not:
    child: FilterNode


FilterNode = MatchAll | Term | And | Or | Not


@dataclass(frozen=True)
class GroupBy:
    fields: tuple[str, ...]


@dataclass(frozen=True)
class SortBy:
    field: str
    direction: str  # "asc" | "desc"


@dataclass(frozen=True)
class Head:
    limit: int


@dataclass(frozen=True)
class Count:
    """Marker that the caller wants only a total count, not documents."""


PipeStage = GroupBy | SortBy | Head | Count


@dataclass(frozen=True)
class OqlAst:
    """Top-level OQL syntax tree: filter expression + ordered pipe stages."""

    filter_: FilterNode
    pipes: tuple[PipeStage, ...] = ()


# =====================================================================
# Parser
# =====================================================================

_GRAMMAR = r"""
?start: or_expr

?or_expr: and_expr (_OR and_expr)*
?and_expr: not_expr (_AND not_expr)*
?not_expr: _NOT atom -> not_expr
         | atom

?atom: _STAR -> match_all
     | "(" or_expr ")"
     | term

term: FIELD ":" field_value

?field_value: range_value
            | quoted_value
            | wildcard_value
            | bare_value

range_value: "[" range_term _TO range_term "]"
?range_term: quoted_value | bare_value | star_value
star_value: _STAR

quoted_value: ESCAPED_STRING
wildcard_value: WILDCARD_TOKEN
bare_value: BARE_TOKEN

_OR: "OR"i
_AND: "AND"i
_NOT: "NOT"i
_TO: "TO"i
_STAR: "*"

FIELD: /(?!(?i:OR|AND|NOT|TO)\b)[@a-zA-Z_][@a-zA-Z0-9_.\-]*/
WILDCARD_TOKEN: /[a-zA-Z0-9_.\-:\/+]*[*?][a-zA-Z0-9_.\-:\/*?+]*/
BARE_TOKEN: /[a-zA-Z0-9_.\-:\/+]+/

ESCAPED_STRING: /"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'/

%import common.WS
%ignore WS
"""

_PARSER = Lark(_GRAMMAR, parser="lalr", maybe_placeholders=False)


class _AstTransformer(Transformer):  # type: ignore[type-arg]
    """Convert the lark parse tree into our typed AST nodes."""

    @v_args(inline=True)
    def match_all(self) -> MatchAll:  # called with no children (_STAR filtered)
        return MatchAll()

    @v_args(inline=True)
    def quoted_value(self, s: Token) -> QuotedValue:
        text = str(s)
        # Strip outer quotes (either ' or "); un-escape simple sequences.
        if (text.startswith('"') and text.endswith('"')) or (
            text.startswith("'") and text.endswith("'")
        ):
            text = text[1:-1]
        text = text.replace('\\"', '"').replace("\\'", "'").replace("\\\\", "\\")
        return QuotedValue(text=text)

    @v_args(inline=True)
    def wildcard_value(self, s: Token) -> WildcardValue:
        return WildcardValue(pattern=str(s))

    @v_args(inline=True)
    def bare_value(self, s: Token) -> BareValue:
        return BareValue(text=str(s))

    @v_args(inline=True)
    def star_value(self) -> BareValue:
        return BareValue(text="*")

    @v_args(inline=True)
    def range_value(self, lo: Value, hi: Value) -> RangeValue:
        return RangeValue(lo=_value_text_for_range(lo), hi=_value_text_for_range(hi))

    @v_args(inline=True)
    def term(self, field_token: Token, value: Value) -> Term:
        return Term(field=str(field_token), value=value)

    def or_expr(self, children: list[FilterNode]) -> Or:
        return Or(children=tuple(children))

    def and_expr(self, children: list[FilterNode]) -> And:
        return And(children=tuple(children))

    @v_args(inline=True)
    def not_expr(self, child: FilterNode) -> Not:
        return Not(child=child)


def _value_text_for_range(v: Value) -> str:
    """Range bounds must collapse to a string."""
    if isinstance(v, BareValue | QuotedValue):
        return v.text
    raise OqlValidationError(
        f"range bound must be bare or quoted, got {type(v).__name__}",
    )


# Pipe-stage regexes.
_GROUPBY_RE = re.compile(r"^groupby\s+([@\w.,\s\-]+)$")
_SORTBY_RE = re.compile(r"^sortby\s+([@\w.\-]+)\s*(asc|desc)?$", re.IGNORECASE)
_HEAD_RE = re.compile(r"^(?:head|limit)\s+(\d+)$", re.IGNORECASE)
_COUNT_RE = re.compile(r"^count$", re.IGNORECASE)


def _parse_pipe_stage(text: str) -> PipeStage:
    text = text.strip()
    if not text:
        raise OqlValidationError("empty pipe stage")
    if m := _GROUPBY_RE.match(text):
        fields = tuple(f.strip() for f in m.group(1).split(",") if f.strip())
        if not fields:
            raise OqlValidationError("groupby requires at least one field", fragment=text)
        return GroupBy(fields=fields)
    if m := _SORTBY_RE.match(text):
        direction = (m.group(2) or "asc").lower()
        return SortBy(field=m.group(1), direction=direction)
    if m := _HEAD_RE.match(text):
        return Head(limit=int(m.group(1)))
    if _COUNT_RE.match(text):
        return Count()
    raise OqlValidationError(f"unknown pipe stage: {text!r}", fragment=text)


def parse_oql(query: str) -> OqlAst:
    """Parse a full OQL query string into an :class:`OqlAst`.

    Raises :class:`soc_ai.errors.OqlValidationError` on any parse failure.
    The returned AST is structurally valid but **not yet validated** -
    callers must invoke :func:`validate_oql` before passing to ES.

    Tolerates LLM over-escaping: if the parser rejects the filter and the
    input contains ``\\"`` or ``\\'`` (a JSON-style escape that survived past
    the OpenAI tool-call argument decode), we try once more with those
    sequences collapsed.
    """
    if not query or not query.strip():
        raise OqlValidationError("empty query")

    parts = _split_pipe(query)
    filter_text = parts[0].strip()

    if filter_text in ("", "*"):
        filter_ast: FilterNode = MatchAll()
    else:
        filter_ast = _parse_filter_with_fallback(filter_text)

    pipes = tuple(_parse_pipe_stage(p) for p in parts[1:])
    return OqlAst(filter_=filter_ast, pipes=pipes)


def _parse_filter_with_fallback(filter_text: str) -> FilterNode:
    try:
        tree = _PARSER.parse(filter_text)
        return _AstTransformer().transform(tree)  # type: ignore[no-any-return]
    except LarkError as primary_err:
        # Recover from over-escaping (LLM tool-arg quirk): JSON layer escapes
        # `"` once, model emits another backslash, leaving literal `\"` in the
        # decoded string. Strip those and retry.
        if r"\"" in filter_text or r"\'" in filter_text:
            cleaned = filter_text.replace(r"\"", '"').replace(r"\'", "'")
            try:
                tree = _PARSER.parse(cleaned)
                return _AstTransformer().transform(tree)  # type: ignore[no-any-return]
            except LarkError:
                pass
        raise OqlValidationError(
            f"failed to parse filter: {primary_err}",
            fragment=filter_text,
        ) from primary_err
    except RecursionError as rec_err:
        # Deeply-nested input blows the parser's recursion limit; surface it as a
        # clean 400 bad_oql rather than an unhandled 500.
        raise OqlValidationError(
            "filter too deeply nested to parse",
            fragment=filter_text,
        ) from rec_err


def _split_pipe(query: str) -> list[str]:
    """Split on ``|`` at the top level (i.e. not inside double quotes)."""
    parts: list[str] = []
    buf: list[str] = []
    in_quote = False
    escape = False
    for ch in query:
        if escape:
            buf.append(ch)
            escape = False
            continue
        if ch == "\\":
            buf.append(ch)
            escape = True
            continue
        if ch == '"':
            in_quote = not in_quote
            buf.append(ch)
            continue
        if ch == "|" and not in_quote:
            parts.append("".join(buf))
            buf = []
            continue
        buf.append(ch)
    parts.append("".join(buf))
    return parts


# =====================================================================
# Validator
# =====================================================================


def collect_filter_fields(node: FilterNode) -> set[str]:
    """Return every field name referenced by the filter expression."""
    if isinstance(node, MatchAll):
        return set()
    if isinstance(node, Term):
        return {node.field}
    if isinstance(node, And | Or):
        out: set[str] = set()
        for child in node.children:
            out.update(collect_filter_fields(child))
        return out
    if isinstance(node, Not):
        return collect_filter_fields(node.child)
    assert_never(node)


def _term_wildcard_pattern(value: Value) -> str | None:
    """Return the literal wildcard pattern a term emits, or ``None``.

    Mirrors the DSL translation in :func:`_term_to_dsl`: an explicit
    :class:`WildcardValue`, or a bare/quoted value whose text contains ``*``/``?``,
    becomes an ES ``wildcard`` clause. Everything else is a plain ``term``.
    """
    if isinstance(value, WildcardValue):
        return value.pattern
    if isinstance(value, QuotedValue | BareValue) and ("*" in value.text or "?" in value.text):
        return value.text
    return None


def collect_wildcard_patterns(node: FilterNode) -> list[str]:
    """Return every wildcard pattern emitted by terms in the filter expression."""
    if isinstance(node, MatchAll):
        return []
    if isinstance(node, Term):
        pat = _term_wildcard_pattern(node.value)
        return [pat] if pat is not None else []
    if isinstance(node, And | Or):
        out: list[str] = []
        for child in node.children:
            out.extend(collect_wildcard_patterns(child))
        return out
    if isinstance(node, Not):
        return collect_wildcard_patterns(node.child)
    assert_never(node)


_HARD_MAX_RESULTS: int = 10_000


def validate_oql(ast: OqlAst, *, max_results: int = 100) -> None:
    """Run safety checks on a parsed AST.

    Raises :class:`OqlValidationError` if any field is unknown/forbidden, any
    pipe stage parameter is unsafe, or ``head`` requests more rows than
    ``max_results`` (capped at ``10_000`` regardless of caller intent).
    """
    wl = get_whitelist()

    for field_name in collect_filter_fields(ast.filter_):
        if not wl.is_allowed(field_name):
            raise OqlValidationError(
                f"unknown or forbidden field: {field_name!r}",
                fragment=field_name,
            )

    # Reject leading-wildcard patterns (``*foo``, ``?foo``, or a bare ``*``).
    # A wildcard anchored at the start forces ES to scan every term in the
    # field's inverted index per shard — unbounded fan-out that can saturate
    # the grid. Trailing/internal wildcards (``foo*``, ``f*o``) stay allowed.
    for pattern in collect_wildcard_patterns(ast.filter_):
        if pattern[:1] in ("*", "?"):
            raise OqlValidationError(
                f"leading-wildcard patterns are too expensive; anchor the prefix: {pattern!r}",
                fragment=pattern,
            )

    effective_cap = min(max_results, _HARD_MAX_RESULTS)
    seen_groupby = False
    seen_sortby = False
    seen_head = False

    for stage in ast.pipes:
        if isinstance(stage, GroupBy):
            if seen_groupby:
                raise OqlValidationError("groupby may not be repeated")
            seen_groupby = True
            for field_name in stage.fields:
                if not wl.is_allowed(field_name):
                    raise OqlValidationError(
                        f"unknown or forbidden field in groupby: {field_name!r}",
                        fragment=field_name,
                    )
        elif isinstance(stage, SortBy):
            if seen_sortby:
                raise OqlValidationError("sortby may not be repeated")
            seen_sortby = True
            # Allow `count` as a sort key when there's a groupby (sorts buckets
            # by document count). Otherwise it must be a real field.
            if stage.field == "count":
                if not seen_groupby:
                    raise OqlValidationError(
                        "sortby count requires a preceding groupby",
                        fragment="count",
                    )
            elif not wl.is_allowed(stage.field):
                raise OqlValidationError(
                    f"unknown or forbidden field in sortby: {stage.field!r}",
                    fragment=stage.field,
                )
            if stage.direction not in {"asc", "desc"}:
                raise OqlValidationError(
                    f"sort direction must be asc or desc, got {stage.direction!r}",
                )
        elif isinstance(stage, Head):
            if seen_head:
                raise OqlValidationError("head may not be repeated")
            seen_head = True
            if stage.limit <= 0:
                raise OqlValidationError(
                    f"head limit must be positive: {stage.limit}",
                    fragment=str(stage.limit),
                )
            if stage.limit > effective_cap:
                raise OqlValidationError(
                    f"head limit {stage.limit} exceeds max_results={effective_cap}",
                    fragment=str(stage.limit),
                )


# =====================================================================
# Translator
# =====================================================================


def filter_to_dsl(node: FilterNode) -> dict[str, Any]:
    """Translate a filter AST node to an Elasticsearch query clause."""
    if isinstance(node, MatchAll):
        return {"match_all": {}}
    if isinstance(node, Term):
        return _term_to_dsl(node.field, node.value)
    if isinstance(node, And):
        return {"bool": {"must": [filter_to_dsl(c) for c in node.children]}}
    if isinstance(node, Or):
        return {
            "bool": {
                "should": [filter_to_dsl(c) for c in node.children],
                "minimum_should_match": 1,
            }
        }
    if isinstance(node, Not):
        return {"bool": {"must_not": [filter_to_dsl(node.child)]}}
    assert_never(node)


def _term_to_dsl(field_name: str, value: Value) -> dict[str, Any]:
    if isinstance(value, RangeValue):
        body: dict[str, Any] = {}
        if value.lo != "*":
            body["gte"] = value.lo
        if value.hi != "*":
            body["lte"] = value.hi
        return {"range": {field_name: body}}
    if isinstance(value, WildcardValue):
        return {"wildcard": {field_name: {"value": value.pattern}}}
    if isinstance(value, QuotedValue | BareValue):
        text = value.text
        if "*" in text or "?" in text:
            return {"wildcard": {field_name: {"value": text}}}
        return {"term": {field_name: text}}
    assert_never(value)


def ast_to_es_dsl(ast: OqlAst, *, default_size: int = 100) -> dict[str, Any]:
    """Translate an :class:`OqlAst` to an Elasticsearch search body.

    Returned keys: ``query``, ``size``, optionally ``sort``, ``aggs``,
    ``track_total_hits``. Caller wires them into ``ElasticClient.search``.
    """
    body: dict[str, Any] = {
        "query": filter_to_dsl(ast.filter_),
        "size": default_size,
    }

    has_groupby = False

    for stage in ast.pipes:
        if isinstance(stage, GroupBy):
            body["aggs"] = _build_terms_aggs(stage.fields)
            body["size"] = 0  # groupby returns aggs, not hits
            has_groupby = True
        elif isinstance(stage, SortBy):
            if stage.field == "count" and has_groupby:
                # Sorting buckets by doc_count
                _attach_bucket_sort(body["aggs"], stage.direction)
            else:
                body["sort"] = [{stage.field: {"order": stage.direction}}]
        elif isinstance(stage, Head):
            if has_groupby:
                _attach_bucket_size(body["aggs"], stage.limit)
            else:
                body["size"] = stage.limit
        elif isinstance(stage, Count):
            body["size"] = 0
            body["track_total_hits"] = True

    return body


def _build_terms_aggs(fields: tuple[str, ...], *, size: int = 25) -> dict[str, Any]:
    """Build a (possibly nested) terms aggregation for groupby fields."""
    if not fields:
        return {}
    head_name = "by_" + _safe_agg_name(fields[0])
    agg: dict[str, Any] = {head_name: {"terms": {"field": fields[0], "size": size}}}
    if len(fields) > 1:
        agg[head_name]["aggs"] = _build_terms_aggs(fields[1:], size=size)
    return agg


def _attach_bucket_sort(aggs: dict[str, Any], direction: str) -> None:
    """Apply a doc-count sort to the outermost terms aggregation."""
    for agg_body in aggs.values():
        if "terms" in agg_body:
            agg_body["terms"]["order"] = {"_count": direction}
            return


def _attach_bucket_size(aggs: dict[str, Any], limit: int) -> None:
    """Limit the outermost terms aggregation to the top-N buckets."""
    for agg_body in aggs.values():
        if "terms" in agg_body:
            agg_body["terms"]["size"] = limit
            return


def _safe_agg_name(s: str) -> str:
    return s.replace(".", "_").replace("-", "_").replace("@", "")

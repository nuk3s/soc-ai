"""Every ``_build_time_filter`` call site must take the clause, not the pair.

``_build_time_filter`` returns ``(range_clause, window_descriptor)``. The
descriptor exists so a count is reported next to the span it was counted over.
The cost of that second element is that dropping the whole tuple into a ``bool``
filter list is valid Python, and ES then rejects the body.

mypy cannot see it: the query bodies are built as ``dict[str, Any]`` literals,
so the filter list is ``Any`` and the tuple type is erased on the way in. Three
of the seven call sites made exactly this mistake in one change, and only one of
the three had a test that happened to compare the whole filter list.

So the guard is static: parse the tree and require that every call either
subscripts the result or unpacks it into two names.
"""

from __future__ import annotations

import ast
from pathlib import Path

_SRC = Path(__file__).resolve().parent.parent / "soc_ai"
_NAME = "_build_time_filter"


def _calls(tree: ast.AST) -> list[ast.Call]:
    return [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and (
            (isinstance(node.func, ast.Name) and node.func.id == _NAME)
            or (isinstance(node.func, ast.Attribute) and node.func.attr == _NAME)
        )
    ]


def _consumed_whole(tree: ast.AST) -> list[ast.Call]:
    """Calls whose result is used as-is rather than indexed or unpacked."""
    indexed = {
        id(node.value)
        for node in ast.walk(tree)
        if isinstance(node, ast.Subscript) and isinstance(node.value, ast.Call)
    }
    unpacked = {
        id(node.value)
        for node in ast.walk(tree)
        if isinstance(node, ast.Assign)
        and isinstance(node.value, ast.Call)
        and any(isinstance(t, ast.Tuple) for t in node.targets)
    }
    return [c for c in _calls(tree) if id(c) not in indexed and id(c) not in unpacked]


def test_no_call_site_uses_the_pair_as_a_filter_clause() -> None:
    offenders: list[str] = []
    seen = 0
    for path in sorted(_SRC.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        seen += len(_calls(tree))
        offenders.extend(
            f"{path.relative_to(_SRC.parent)}:{call.lineno}" for call in _consumed_whole(tree)
        )

    assert seen > 0, f"{_NAME} not found; was it renamed? Update this guard."
    assert not offenders, (
        f"{_NAME} returns (clause, descriptor). These call sites use the whole "
        f"pair, which lands a tuple in an ES filter list: {offenders}"
    )

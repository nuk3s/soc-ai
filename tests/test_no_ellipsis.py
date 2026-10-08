"""Ellipsis gate: no backend string ends in "..." or carries "…".

The owner banned the ellipsis on 2026-10-07: "'...' is officially forbidden,
there are a bunch of places where this is present that essentially kills UI
and hides information." A cut with an ellipsis hid the rest of a title, a
reason or an error, and the full text was often nowhere. The console wraps a
long line, so the backend sends the whole text. A progress line reads
"Searching" with no trailing dots.

The scan mirrors ``tests/test_prose_style.py``. It parses every
``soc_ai/**/*.py`` file and reads the string constants. A constant fails when
it ends in "..." or "…" after trailing whitespace goes, or when it carries "…"
anywhere. An f-string fails when its last literal part ends that way, or when
any literal part carries "…".

Documentation is out of scope. A docstring and any other bare string
statement, such as an attribute docstring on a settings field, never reaches a
person at run time, so the scan skips them. Python's ``...`` (Ellipsis) is code.

``ALLOWLIST`` holds the model prompts that keep a "…" placeholder. A person
does not read them in the console, and a change to their wording needs a model
eval. Each entry names a file and a snippet of the constant, with the reason.
An entry that matches nothing fails the gate, so the list only shrinks.
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
BACKEND_GLOB = "soc_ai/**/*.py"
ELLIPSIS = "…"
THREE_DOTS = "..."

# "path:snippet" -> the reason the constant keeps its "…". The snippet is a
# part of the constant's text that names it.
ALLOWLIST: dict[str, str] = {
    "soc_ai/agent/chat_agent.py:a hostname such as `DESKTOP-…`": (
        "Chat agent system prompt. The model reads the placeholder. A change needs a chat eval."
    ),
    "soc_ai/agent/prompts.py:`… | sortby @timestamp desc`": (
        "OQL pipe-stage addendum in the triage and hunt prompts. The model reads the placeholder."
    ),
    "soc_ai/eval/prompt.py:result at sequence 7 returned …": (
        "Eval rubric prompt to the Oracle judge. The eval baseline was graded on this wording."
    ),
    "soc_ai/oracle/client.py:(IP_01, HOST_02, USER_03, …)": (
        "Oracle tool-loop system prompt. The Oracle reads the label list placeholder."
    ),
    "soc_ai/oracle/sanitize.py:(IP_01, HOST_02, USER_03, …)": (
        "Tool rejection message that only the Oracle reads inside its tool loop."
    ),
}


def _bare_string_ids(tree: ast.AST) -> set[int]:
    """Ids of the string constants that stand alone as a statement.

    A docstring is one. An attribute docstring under a field is another. No
    such string is a value at run time.
    """
    ids: set[int] = set()
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Expr)
            and isinstance(node.value, ast.Constant)
            and isinstance(node.value.value, str)
        ):
            ids.add(id(node.value))
    return ids


def _ends_badly(text: str) -> bool:
    tail = text.rstrip()
    return tail.endswith(THREE_DOTS) or tail.endswith(ELLIPSIS)


def _fstring_text(node: ast.JoinedStr) -> str:
    """The literal text of an f-string, with "{}" for each replacement field."""
    return "".join(
        part.value if isinstance(part, ast.Constant) and isinstance(part.value, str) else "{}"
        for part in node.values
    )


def find_ellipses(source: str, filename: str = "<source>") -> list[tuple[int, str]]:
    """(line, text) for each string in ``source`` that the ban covers."""
    tree = ast.parse(source, filename=filename)
    skip = _bare_string_ids(tree)
    fstring_parts: set[int] = set()
    found: list[tuple[int, str]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.JoinedStr):
            continue
        parts = [p for p in node.values if isinstance(p, ast.Constant)]
        fstring_parts.update(id(p) for p in parts)
        last = node.values[-1] if node.values else None
        trailing = (
            isinstance(last, ast.Constant)
            and isinstance(last.value, str)
            and _ends_badly(last.value)
        )
        inside = any(isinstance(p.value, str) and ELLIPSIS in p.value for p in parts)
        if trailing or inside:
            found.append((node.lineno, _fstring_text(node)))
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Constant)
            and isinstance(node.value, str)
            and id(node) not in skip
            and id(node) not in fstring_parts
            and (_ends_badly(node.value) or ELLIPSIS in node.value)
        ):
            found.append((node.lineno, node.value))
    return sorted(found)


def scan() -> dict[str, list[tuple[int, str]]]:
    """Offending strings per backend file, keyed by the repository-relative path."""
    out: dict[str, list[tuple[int, str]]] = {}
    for path in sorted(REPO_ROOT.glob(BACKEND_GLOB)):
        if not path.is_file():
            continue
        hits = find_ellipses(path.read_text(encoding="utf-8"), filename=str(path))
        if hits:
            out[path.relative_to(REPO_ROOT).as_posix()] = hits
    return out


def _allowed_key(path: str, text: str) -> str | None:
    for key in ALLOWLIST:
        key_path, _, snippet = key.partition(":")
        if key_path == path and snippet in text:
            return key
    return None


def _show(text: str) -> str:
    flat = " ".join(text.split())
    return flat if len(flat) <= 100 else f"{flat[:100]} [{len(flat) - 100} more characters]"


def test_no_backend_string_ends_in_an_ellipsis() -> None:
    offenders = [
        f"  {path}:{line}: {_show(text)!r}"
        for path, hits in scan().items()
        for line, text in hits
        if _allowed_key(path, text) is None
    ]
    assert not offenders, (
        "These strings end in '...' or carry '…'. The owner banned the ellipsis. "
        "Send the whole text, and drop the dots from a progress line.\n" + "\n".join(offenders)
    )


def test_every_allowlist_entry_still_matches_a_string() -> None:
    used = {
        key
        for path, hits in scan().items()
        for _line, text in hits
        if (key := _allowed_key(path, text)) is not None
    }
    stale = sorted(set(ALLOWLIST) - used)
    assert not stale, f"These allowlist entries match nothing. Remove them: {stale}"


def test_the_checker_catches_a_trailing_ellipsis_in_a_string_and_an_fstring() -> None:
    """Negative control: plant each shape the gate exists to catch."""
    source = 'x = "Loading..."\ny = f"{a}…"\nz = "one … two"\nw = f"{a}…[{b}]"\n'
    found = find_ellipses(source)
    assert [line for line, _text in found] == [1, 2, 3, 4], found


def test_the_checker_leaves_code_and_documentation_alone() -> None:
    """Negative control: Ellipsis as code and a docstring are not text a person reads."""
    source = (
        "def f(): ...\n"
        "def g():\n"
        '    """Wait for the grid..."""\n'
        "class Settings:\n"
        "    limit: int = 3\n"
        '    """The count of retries..."""\n'
        'ok = f"{a} of {b} done"\n'
        'mid = "a...b is a range"\n'
    )
    assert find_ellipses(source) == []


if __name__ == "__main__":
    for file, rows in scan().items():
        for row_line, row_text in rows:
            mark = "allowed" if _allowed_key(file, row_text) else "OFFENDER"
            print(f"{mark} {file}:{row_line}: {_show(row_text)!r}")
    sys.exit(0)
